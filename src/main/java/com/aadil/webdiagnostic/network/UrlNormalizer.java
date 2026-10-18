package com.aadil.webdiagnostic.network;

import com.aadil.webdiagnostic.config.DiagnosticProperties;
import com.aadil.webdiagnostic.exception.InvalidTargetException;
import org.springframework.stereotype.Component;

import java.net.IDN;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Turns whatever the user typed into a canonical absolute URI, or rejects it loudly.
 * "google.com" -> "https://google.com/"   "münchen.de" -> "https://xn--mnchen-3ya.de/"
 *
 * Privacy: the query string and fragment are dropped (they often carry tokens, e.g. password-reset links).
 * Set diagnostic.keep-query-string=true on your own deployment if you need to diagnose a specific query.
 */
@Component
public class UrlNormalizer {

    private static final Pattern HAS_SCHEME = Pattern.compile("^[a-zA-Z][a-zA-Z0-9+.\\-]*://");
    private static final int MAX_LENGTH = 2048;

    private final DiagnosticProperties props;

    public UrlNormalizer(DiagnosticProperties props) {
        this.props = props;
    }

    public URI normalize(String raw) {
        if (raw == null || raw.isBlank()) {
            throw new InvalidTargetException("A 'url' parameter is required");
        }

        String candidate = raw.trim();

        if (candidate.length() > MAX_LENGTH) {
            throw new InvalidTargetException("URL is too long");
        }
        if (!HAS_SCHEME.matcher(candidate).find()) {
            candidate = "https://" + candidate;
        }
        candidate = hostToAscii(candidate);

        URI parsed;
        try {
            parsed = new URI(candidate).parseServerAuthority();
        } catch (URISyntaxException e) {
            throw new InvalidTargetException("Malformed URL");
        }

        if (parsed.getHost() == null || parsed.getHost().isBlank()) {
            throw new InvalidTargetException("URL does not contain a hostname");
        }
        if (parsed.getUserInfo() != null) {
            // Credentials in a URL are a classic SSRF/parser-confusion vector.
            throw new InvalidTargetException("URLs containing credentials are not supported");
        }

        // Raw (still percent-encoded) path and query: decoding and re-encoding would turn %2F into "/"
        // and silently test a different URL than the one the user typed.
        String path = (parsed.getRawPath() == null || parsed.getRawPath().isEmpty()) ? "/" : encodeNonAscii(parsed.getRawPath());
        String query = props.keepQueryString() && parsed.getRawQuery() != null ? encodeNonAscii(parsed.getRawQuery()) : null;

        StringBuilder canonical = new StringBuilder()
                .append(parsed.getScheme().toLowerCase(Locale.ROOT))
                .append("://")
                .append(parsed.getHost().toLowerCase(Locale.ROOT));
        if (parsed.getPort() != -1) {
            canonical.append(':').append(parsed.getPort());
        }
        canonical.append(path);
        if (query != null) {
            canonical.append('?').append(query);
        }
        // fragments are never sent to the server, so none is appended

        try {
            return new URI(canonical.toString());
        } catch (URISyntaxException e) {
            throw new InvalidTargetException("Malformed URL");
        }
    }

    /**
     * Percent-encodes every non-ASCII character as UTF-8, exactly as a browser does. java.net.URI accepts such
     * characters, but an HTTP request line must be ASCII: sent raw, a path like /wiki/日本 would reach the
     * server as Latin-1 bytes or '?' and the wrong page would be tested. Existing %XX escapes are untouched.
     */
    private static String encodeNonAscii(String raw) {
        if (raw.chars().allMatch(c -> c < 128)) {
            return raw;
        }
        StringBuilder out = new StringBuilder(raw.length() + 16);
        raw.codePoints().forEach(cp -> {
            if (cp < 128) {
                out.append((char) cp);
            } else {
                for (byte b : new String(Character.toChars(cp)).getBytes(StandardCharsets.UTF_8)) {
                    out.append('%').append(String.format("%02X", b & 0xFF));
                }
            }
        });
        return out.toString();
    }

    /**
     * java.net.URI cannot parse non-ASCII hostnames, so convert them to punycode first.
     * Input that also contains credentials ('@') is left alone and fails parsing as before.
     */
    private String hostToAscii(String candidate) {
        int start = candidate.indexOf("://") + 3;
        int end = start;
        while (end < candidate.length() && "/?#".indexOf(candidate.charAt(end)) < 0) {
            end++;
        }
        String authority = candidate.substring(start, end);

        boolean isAscii = authority.chars().allMatch(c -> c < 128);
        if (isAscii || authority.contains("@")) {
            return candidate;
        }
        try {
            return candidate.substring(0, start) + IDN.toASCII(authority) + candidate.substring(end);
        } catch (IllegalArgumentException e) {
            throw new InvalidTargetException("Malformed URL");
        }
    }
}
