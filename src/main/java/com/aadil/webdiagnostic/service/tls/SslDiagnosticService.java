package com.aadil.webdiagnostic.service.tls;

import com.aadil.webdiagnostic.config.DiagnosticProperties;
import com.aadil.webdiagnostic.model.CheckStatus;
import com.aadil.webdiagnostic.model.SslDiagnosticResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import java.io.IOException;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.UnknownHostException;
import java.security.SecureRandom;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;

/**
 * Opens one connection to the site and reports two things: whether its certificate is
 * trustworthy, and how long the TCP connect and the TLS handshake took.
 *
 * <p>Two deliberate choices:
 * <ul>
 *   <li>A raw SSLSocket, not HttpsURLConnection: no HTTP request is sent, SNI is set explicitly,
 *       and hostname verification is turned on on purpose with
 *       {@code setEndpointIdentificationAlgorithm("HTTPS")} - an SSLSocket does NOT verify the
 *       hostname by default.</li>
 *   <li>We connect to the IP address the SSRF guard already approved, not to the hostname.
 *       Resolving the name a second time would let a hostile DNS server answer "public address"
 *       during the check and "192.168.0.1" a moment later (DNS rebinding). The hostname is carried
 *       along with the address so SNI and certificate verification still work normally.</li>
 * </ul>
 */
@Service
public class SslDiagnosticService {

    private static final Logger log = LoggerFactory.getLogger(SslDiagnosticService.class);

    private static final int MAX_ADDRESSES_TRIED = 3;

    private final DiagnosticProperties props;

    public SslDiagnosticService(DiagnosticProperties props) {
        this.props = props;
    }

    private record CertificateSnapshot(
            String subject, String issuer, Instant validFrom, Instant validUntil,
            Long daysUntilExpiry, Boolean selfSigned, String tlsVersion, String cipherSuite) {
    }

    /** Carries the timings back out of a socket attempt regardless of how it ended. */
    private static final class Stopwatch {
        Long tcpConnectMs;
        Long tlsHandshakeMs;
    }

    /**
     * @param addresses the addresses the SSRF guard already approved for this host.
     *                  The first one is the address we connect to.
     */
    public ConnectionProbe probe(URI uri, List<InetAddress> addresses) {

        String host = uri.getHost();

        if (addresses == null || addresses.isEmpty()) {
            // Never fall back to connecting by hostname: that would be a second, unvalidated DNS lookup.
            return ConnectionProbe.notChecked("No approved address to connect to");
        }

        // A host can publish several addresses (typically IPv6 + IPv4). If the first one cannot be
        // connected to at all, try the next, as a browser would, instead of reporting a failure
        // that the site's other address would not have had. Bounded so a dead host stays quick.
        ConnectionProbe result = null;
        int tries = Math.min(addresses.size(), MAX_ADDRESSES_TRIED);
        for (int i = 0; i < tries; i++) {
            result = probeAddress(uri, pin(host, List.of(addresses.get(i))));
            if (result.tcpConnectMs() != null || Thread.currentThread().isInterrupted()) {
                break;   // connected (whatever TLS then said), or we were cancelled
            }
        }
        return result;
    }

    private ConnectionProbe probeAddress(URI uri, InetAddress pinned) {

        String host = uri.getHost();

        if (!"https".equalsIgnoreCase(uri.getScheme())) {
            // No certificate to check, but the connect time is still worth reporting.
            int plainPort = uri.getPort() == -1 ? 80 : uri.getPort();
            return new ConnectionProbe(SslDiagnosticResult.notHttps(), tcpConnectMs(pinned, plainPort), null);
        }

        int port = uri.getPort() == -1 ? 443 : uri.getPort();
        Stopwatch watch = new Stopwatch();

        try (SSLSocket socket = openSocket(SSLContext.getDefault(), pinned, host, port, true, watch)) {

            long handshakeStart = System.nanoTime();
            socket.startHandshake();
            watch.tlsHandshakeMs = millisSince(handshakeStart);

            // Reaching here means the chain validated AND the hostname matched.
            SSLSession session = socket.getSession();
            X509Certificate certificate = (X509Certificate) session.getPeerCertificates()[0];

            CheckStatus validity = CheckStatus.VALID;
            String message = "Certificate is valid, trusted, and matches the hostname";

            try {
                certificate.checkValidity();
            } catch (CertificateExpiredException e) {
                validity = CheckStatus.INVALID;
                message = "Certificate has expired";
            } catch (CertificateNotYetValidException e) {
                validity = CheckStatus.INVALID;
                message = "Certificate is not yet valid";
            }

            SslDiagnosticResult ssl = new SslDiagnosticResult(
                    true, true,
                    validity, CheckStatus.VALID, CheckStatus.VALID,
                    certificate.getSubjectX500Principal().getName(),
                    certificate.getIssuerX500Principal().getName(),
                    certificate.getNotBefore().toInstant(),
                    certificate.getNotAfter().toInstant(),
                    daysUntil(certificate.getNotAfter()),
                    isSelfSigned(certificate),
                    session.getProtocol(),
                    session.getCipherSuite(),
                    message);

            return new ConnectionProbe(ssl, watch.tcpConnectMs, watch.tlsHandshakeMs);

        } catch (SSLHandshakeException e) {
            return withTimings(classifyHandshakeFailure(e, pinned, host, port), watch);

        } catch (SSLPeerUnverifiedException e) {
            return withTimings(withSnapshot(
                    CheckStatus.NOT_CHECKED, CheckStatus.INVALID, CheckStatus.NOT_CHECKED,
                    "Server certificate could not be verified", pinned, host, port), watch);

        } catch (SocketTimeoutException e) {
            return withTimings(SslDiagnosticResult.notChecked("Connection to the HTTPS server timed out"), watch);

        } catch (ConnectException e) {
            return withTimings(SslDiagnosticResult.notChecked("Could not connect to port " + port), watch);

        } catch (UnknownHostException e) {
            return withTimings(SslDiagnosticResult.notChecked("Host could not be resolved"), watch);

        } catch (IOException e) {
            return withTimings(SslDiagnosticResult.notChecked("TLS check failed: " + rootMessage(e)), watch);

        } catch (Exception e) {
            log.warn("Unexpected TLS failure for {}:{}", host, port, e);
            return withTimings(SslDiagnosticResult.notChecked("TLS check failed: " + rootMessage(e)), watch);
        }
    }

    // ---------------------------------------------------------------- addressing

    /**
     * Keeps the hostname attached to the approved IP. {@code InetAddress.getByAddress(host, bytes)}
     * builds an address that will NOT be re-resolved, while still reporting the hostname to SNI
     * and to certificate verification.
     */
    private InetAddress pin(String host, List<InetAddress> addresses) {
        if (addresses == null || addresses.isEmpty()) {
            return null;
        }
        InetAddress first = addresses.get(0);
        try {
            return InetAddress.getByAddress(host, first.getAddress());
        } catch (UnknownHostException e) {
            return first; // cannot happen for a raw byte address, but never let this break the check
        }
    }

    private Long tcpConnectMs(InetAddress pinned, int port) {
        if (pinned == null) {
            return null;
        }
        long start = System.nanoTime();
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(pinned, port), props.connectTimeoutMillis());
            return millisSince(start);
        } catch (IOException e) {
            return null; // the HTTP check reports the failure; timing simply isn't available
        }
    }

    // ---------------------------------------------------------------- sockets

    private SSLSocket openSocket(SSLContext context, InetAddress pinned, String host, int port,
                                 boolean verifyHostname, Stopwatch watch) throws IOException {

        SSLSocket socket = (SSLSocket) context.getSocketFactory().createSocket();
        boolean configured = false;
        try {
            long connectStart = System.nanoTime();
            if (pinned == null) {
                throw new IOException("No approved address to connect to");   // never resolve the hostname again
            }
            socket.connect(new InetSocketAddress(pinned, port), props.connectTimeoutMillis());
            watch.tcpConnectMs = millisSince(connectStart);

            socket.setSoTimeout(props.readTimeoutMillis());

            SSLParameters parameters = socket.getSSLParameters();
            try {
                parameters.setServerNames(List.of(new SNIHostName(host)));
            } catch (IllegalArgumentException ignored) {
                // host is an IP literal - SNI does not apply
            }
            parameters.setEndpointIdentificationAlgorithm(verifyHostname ? "HTTPS" : null);
            socket.setSSLParameters(parameters);

            configured = true;
            return socket;
        } finally {
            if (!configured) {
                socket.close();
            }
        }
    }

    // ------------------------------------------------------------ failure path

    private ConnectionProbe withTimings(SslDiagnosticResult ssl, Stopwatch watch) {
        return new ConnectionProbe(ssl, watch.tcpConnectMs, watch.tlsHandshakeMs);
    }

    private SslDiagnosticResult classifyHandshakeFailure(SSLHandshakeException exception,
                                                         InetAddress pinned, String host, int port) {

        CheckStatus validity = CheckStatus.NOT_CHECKED;
        CheckStatus trust = CheckStatus.NOT_CHECKED;
        CheckStatus hostname = CheckStatus.NOT_CHECKED;
        String message = null;

        // Two passes on purpose: the JDK nests CertificateExpiredException INSIDE a
        // CertPathValidatorException, so a single outer-to-inner pass would call an expired
        // certificate "not trusted".
        for (Throwable current = exception; current != null; current = current.getCause()) {
            if (current instanceof CertificateExpiredException) {
                validity = CheckStatus.INVALID;
                message = "Certificate has expired";
                break;
            }
            if (current instanceof CertificateNotYetValidException) {
                validity = CheckStatus.INVALID;
                message = "Certificate is not yet valid";
                break;
            }
        }
        if (message == null) {
            for (Throwable current = exception; current != null; current = current.getCause()) {
                if (current instanceof CertPathValidatorException
                        || current instanceof CertPathBuilderException) {
                    trust = CheckStatus.INVALID;
                    message = "Certificate chain is not trusted";
                    break;
                }
            }
        }

        if (message == null) {
            String text = chainMessage(exception).toLowerCase(Locale.ROOT);
            if (containsAny(text, "no subject alternative", "hostname", "host name",
                    "no name matching", "doesn't match", "does not match")) {
                hostname = CheckStatus.INVALID;
                message = "Hostname does not match the certificate";
            } else {
                message = "TLS handshake failed: " + rootMessage(exception);
            }
        }

        return withSnapshot(validity, trust, hostname, message, pinned, host, port);
    }

    /**
     * Attaches certificate metadata to a failed verdict so the user can still see who
     * issued the bad certificate and when it expired. The verdict above is already
     * decided - this connection never influences it.
     */
    private SslDiagnosticResult withSnapshot(CheckStatus validity, CheckStatus trust,
                                             CheckStatus hostname, String message,
                                             InetAddress pinned, String host, int port) {

        CertificateSnapshot snapshot = props.inspectUntrustedCertificates() ? peek(pinned, host, port) : null;

        if (snapshot == null) {
            return new SslDiagnosticResult(true, true, validity, trust, hostname,
                    null, null, null, null, null, null, null, null, message);
        }

        return new SslDiagnosticResult(true, true, validity, trust, hostname,
                snapshot.subject(), snapshot.issuer(),
                snapshot.validFrom(), snapshot.validUntil(), snapshot.daysUntilExpiry(),
                snapshot.selfSigned(), snapshot.tlsVersion(), snapshot.cipherSuite(),
                message);
    }

    private CertificateSnapshot peek(InetAddress pinned, String host, int port) {
        Stopwatch unused = new Stopwatch();
        try (SSLSocket socket = openSocket(permissiveContext(), pinned, host, port, false, unused)) {
            socket.startHandshake();

            SSLSession session = socket.getSession();
            X509Certificate certificate = (X509Certificate) session.getPeerCertificates()[0];

            return new CertificateSnapshot(
                    certificate.getSubjectX500Principal().getName(),
                    certificate.getIssuerX500Principal().getName(),
                    certificate.getNotBefore().toInstant(),
                    certificate.getNotAfter().toInstant(),
                    daysUntil(certificate.getNotAfter()),
                    isSelfSigned(certificate),
                    session.getProtocol(),
                    session.getCipherSuite());

        } catch (Exception e) {
            log.debug("Could not read certificate metadata from {}:{}", host, port, e);
            return null;
        }
    }

    /**
     * Metadata-only TLS context. Used exclusively by peek() AFTER a trust decision has
     * already been made and recorded. Never use this context for anything else.
     */
    private SSLContext permissiveContext() throws Exception {
        TrustManager[] trustManagers = {
                new X509ExtendedTrustManager() {
                    @Override public void checkClientTrusted(X509Certificate[] c, String a) { }
                    @Override public void checkClientTrusted(X509Certificate[] c, String a, Socket s) { }
                    @Override public void checkClientTrusted(X509Certificate[] c, String a, SSLEngine e) { }
                    @Override public void checkServerTrusted(X509Certificate[] c, String a) { }
                    @Override public void checkServerTrusted(X509Certificate[] c, String a, Socket s) { }
                    @Override public void checkServerTrusted(X509Certificate[] c, String a, SSLEngine e) { }
                    @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                }
        };

        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, trustManagers, new SecureRandom());
        return context;
    }

    // ---------------------------------------------------------------- helpers

    private long millisSince(long startNanos) {
        return TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startNanos);
    }

    private Long daysUntil(Date notAfter) {
        return Duration.between(Instant.now(), notAfter.toInstant()).toDays();
    }

    private Boolean isSelfSigned(X509Certificate certificate) {
        return certificate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal());
    }

    private String chainMessage(Throwable exception) {
        StringBuilder builder = new StringBuilder();
        for (Throwable current = exception; current != null; current = current.getCause()) {
            if (current.getMessage() != null) {
                builder.append(current.getMessage()).append(' ');
            }
        }
        return builder.toString();
    }

    private boolean containsAny(String text, String... values) {
        for (String value : values) {
            if (text.contains(value)) {
                return true;
            }
        }
        return false;
    }

    private String rootMessage(Throwable exception) {
        Throwable current = exception;
        while (current.getCause() != null) {
            current = current.getCause();
        }
        return current.getMessage() != null ? current.getMessage() : current.getClass().getSimpleName();
    }
}
