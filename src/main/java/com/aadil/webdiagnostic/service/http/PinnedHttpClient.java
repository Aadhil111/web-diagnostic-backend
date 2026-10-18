package com.aadil.webdiagnostic.service.http;

import com.aadil.webdiagnostic.config.DiagnosticProperties;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * A deliberately tiny HTTP/1.1 client that connects ONLY to the addresses it is handed.
 *
 * <p>Why not {@code java.net.http.HttpClient}: it resolves the hostname itself, at connect time, with
 * no way to substitute an address. Between our SSRF check and its lookup a hostile DNS server could
 * answer differently (DNS rebinding) and send the request to 169.254.169.254 or an internal host. Here the
 * caller resolves the name once, validates every address, and passes the approved list in; this class
 * opens the socket to those {@link InetAddress} objects directly, so nothing is looked up again.
 *
 * <p>HTTPS stays correct: the TLS layer is created over our socket with the real hostname, so SNI is
 * sent and the certificate chain AND hostname are verified ({@code "HTTPS"} endpoint identification)
 * against the name, not the IP.
 *
 * <p>Only what the diagnostic needs: one request, status line and headers, then the socket is closed.
 * The body is never read. Everything is bounded: header size, header count, connect time and total
 * time to receive the headers.
 */
final class PinnedHttpClient {

    /** Status, headers (lower-case names) and the time it took to get them. */
    record Response(int statusCode, String httpVersion, Map<String, List<String>> headers, long elapsedMs) {

        String header(String name) {
            List<String> values = headers.get(name.toLowerCase(Locale.ROOT));
            return values == null || values.isEmpty() ? null : values.get(0);
        }
    }

    private static final int MAX_ADDRESSES_TRIED = 3;
    private static final int MAX_HEADER_BYTES = 32 * 1024;
    private static final int MAX_INTERIM_RESPONSES = 5;

    private final DiagnosticProperties props;

    PinnedHttpClient(DiagnosticProperties props) {
        this.props = props;
    }

    /**
     * @param addresses already validated addresses for {@code uri.getHost()}; the socket goes to one of these
     */
    Response send(URI uri, List<InetAddress> addresses, String method) throws IOException {

        if (addresses.isEmpty()) {
            throw new IOException("No address to connect to");
        }
        String host = uri.getHost();
        boolean https = "https".equalsIgnoreCase(uri.getScheme());
        int port = uri.getPort() != -1 ? uri.getPort() : (https ? 443 : 80);
        byte[] request = buildRequest(uri, host, port, https, method);

        long start = System.nanoTime();
        Socket socket = connect(addresses, port, start);
        try {
            long deadline = start + TimeUnit.MILLISECONDS.toNanos(
                    props.connectTimeoutMillis() + props.readTimeoutMillis());

            if (https) {
                socket = secure(socket, host, port, deadline);
            }
            socket.getOutputStream().write(request);
            socket.getOutputStream().flush();

            return readHeaders(socket, deadline, start);
        } finally {
            closeQuietly(socket);   // the body is never read
        }
    }

    // ------------------------------------------------------------------ connection

    private Socket connect(List<InetAddress> addresses, int port, long startNanos) throws IOException {
        long connectDeadline = startNanos + TimeUnit.MILLISECONDS.toNanos(props.connectTimeoutMillis());
        IOException failure = null;
        int tries = Math.min(addresses.size(), MAX_ADDRESSES_TRIED);

        for (int i = 0; i < tries; i++) {
            long remainingMs = TimeUnit.NANOSECONDS.toMillis(connectDeadline - System.nanoTime());
            if (remainingMs <= 0) {
                break;
            }
            // Share the time that is left between the addresses still to try. Without this, a first address
            // that silently drops packets (often IPv6) would use up the whole budget and the working
            // one would never be tried. A single address still gets all the time.
            int attemptMs = (int) Math.max(1, remainingMs / (tries - i));
            Socket socket = new Socket();
            try {
                // An InetSocketAddress built from an InetAddress is never re-resolved.
                socket.connect(new InetSocketAddress(addresses.get(i), port), attemptMs);
                socket.setTcpNoDelay(true);
                return socket;
            } catch (IOException e) {
                closeQuietly(socket);
                failure = e;
            }
        }
        throw failure != null ? failure : new SocketTimeoutException("Connect timed out");
    }

    private Socket secure(Socket plain, String host, int port, long deadline) throws IOException {
        String name = stripBrackets(host);
        SSLSocket tls = (SSLSocket) ((SSLSocketFactory) SSLSocketFactory.getDefault())
                .createSocket(plain, name, port, true);   // true: closing the TLS socket closes ours
        try {
            SSLParameters parameters = tls.getSSLParameters();
            parameters.setEndpointIdentificationAlgorithm("HTTPS");   // verify the certificate against the HOSTNAME
            tls.setSSLParameters(parameters);
            tls.setSoTimeout(remainingMillis(deadline));
            tls.startHandshake();
            return tls;
        } catch (IOException | RuntimeException e) {
            closeQuietly(tls);
            throw e;
        }
    }

    // ------------------------------------------------------------------ request / response

    private byte[] buildRequest(URI uri, String host, int port, boolean https, String method) throws IOException {
        String path = uri.getRawPath() == null || uri.getRawPath().isEmpty() ? "/" : uri.getRawPath();
        if (uri.getRawQuery() != null) {
            path += "?" + uri.getRawQuery();
        }
        boolean defaultPort = uri.getPort() == -1 || port == (https ? 443 : 80);
        String hostHeader = defaultPort ? host : host + ":" + port;

        // URI parsing already forbids control characters; this is a second, explicit guard against header injection.
        for (String part : new String[]{path, hostHeader, props.userAgent()}) {
            if (part.indexOf('\r') >= 0 || part.indexOf('\n') >= 0) {
                throw new IOException("Refusing to send a request containing line breaks");
            }
        }

        StringBuilder sb = new StringBuilder()
                .append(method).append(' ').append(path).append(" HTTP/1.1\r\n")
                .append("Host: ").append(hostHeader).append("\r\n")
                .append("User-Agent: ").append(props.userAgent()).append("\r\n")
                .append("Accept: */*\r\n")
                // Ask for compression so the site tells us whether it supports it. We never read a body.
                .append("Accept-Encoding: gzip, deflate, br\r\n")
                .append("Connection: close\r\n");
        if ("GET".equals(method)) {
            // If a server ignores us closing the socket, it still only has one byte to send.
            sb.append("Range: bytes=0-0\r\n");
        }
        sb.append("\r\n");
        return sb.toString().getBytes(StandardCharsets.ISO_8859_1);
    }

    private Response readHeaders(Socket socket, long deadline, long startNanos) throws IOException {
        InputStream in = socket.getInputStream();

        for (int interim = 0; interim <= MAX_INTERIM_RESPONSES; interim++) {
            String block = readHeaderBlock(socket, in, deadline);
            String[] lines = block.split("\r\n");

            String[] status = lines[0].split(" ", 3);
            if (status.length < 2 || !status[0].startsWith("HTTP/")) {
                throw new IOException("Malformed HTTP response");
            }
            int code;
            try {
                code = Integer.parseInt(status[1].trim());
            } catch (NumberFormatException e) {
                throw new IOException("Malformed HTTP response");
            }
            if (code >= 100 && code < 200 && code != 101) {
                continue;   // 100 Continue / 103 Early Hints: the real answer follows
            }

            Map<String, List<String>> headers = new LinkedHashMap<>();
            for (int i = 1; i < lines.length; i++) {
                int colon = lines[i].indexOf(':');
                if (colon <= 0) {
                    continue;   // obsolete folded line or noise
                }
                String name = lines[i].substring(0, colon).trim().toLowerCase(Locale.ROOT);
                headers.computeIfAbsent(name, k -> new ArrayList<>()).add(lines[i].substring(colon + 1).trim());
            }
            long elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startNanos);
            return new Response(code, versionName(status[0]), headers, elapsedMs);
        }
        throw new IOException("Too many interim responses");
    }

    /** Reads up to and including the blank line that ends a header block, never more than the size cap. */
    private String readHeaderBlock(Socket socket, InputStream in, long deadline) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream(512);
        int matched = 0;   // how much of "\r\n\r\n" we have just seen

        while (matched < 4) {
            socket.setSoTimeout(remainingMillis(deadline));
            int b = in.read();
            if (b < 0) {
                throw new IOException("Connection closed before the response headers were complete");
            }
            if (buffer.size() >= MAX_HEADER_BYTES) {
                throw new IOException("Response headers are too large");
            }
            buffer.write(b);
            if (b == (matched % 2 == 0 ? '\r' : '\n')) {
                matched++;
            } else {
                matched = b == '\r' ? 1 : 0;
            }
        }
        String text = buffer.toString(StandardCharsets.ISO_8859_1);
        return text.substring(0, text.length() - 4);
    }

    // ------------------------------------------------------------------ helpers

    /** Milliseconds left until the deadline, as a socket timeout (0 would mean "wait forever", so never 0). */
    private static int remainingMillis(long deadlineNanos) throws SocketTimeoutException {
        long remaining = TimeUnit.NANOSECONDS.toMillis(deadlineNanos - System.nanoTime());
        if (remaining <= 0) {
            throw new SocketTimeoutException("Timed out waiting for the response");
        }
        return (int) Math.min(remaining, Integer.MAX_VALUE);
    }

    private static String versionName(String statusToken) {
        return statusToken.replace("HTTP/", "HTTP_").replace('.', '_');   // HTTP/1.1 -> HTTP_1_1
    }

    private static String stripBrackets(String host) {
        return host.startsWith("[") && host.endsWith("]") ? host.substring(1, host.length() - 1) : host;
    }

    private static void closeQuietly(Socket socket) {
        try {
            socket.close();
        } catch (IOException ignored) {
            // nothing useful to do
        }
    }
}
