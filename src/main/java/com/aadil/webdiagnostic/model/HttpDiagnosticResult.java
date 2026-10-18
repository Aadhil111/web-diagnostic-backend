package com.aadil.webdiagnostic.model;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * What the website answered, measured from our server. These are facts only - no verdicts.
 *
 * @param checked        false when the check was skipped (for example, DNS failed first)
 * @param reachable      true when the site answered at all, whatever the status code was
 * @param statusCode     status of the FINAL response after following redirects
 * @param responseTimeMs the final request only: request sent -> response headers received. Includes
 *                       connection setup (TCP/TLS) when a new connection had to be opened. A body is
 *                       never downloaded. Retries and earlier redirect hops are NOT included.
 * @param totalTimeMs    every redirect hop together
 * @param finalUrl       host and path of the final response (query strings are never reported)
 * @param httpVersion    the protocol of the response status line; always HTTP/1.1 ("HTTP_1_1"), see PinnedHttpClient
 * @param headers        a small allow-list of response headers from the final response, keyed by
 *                       lower-case name. Set-Cookie is deliberately never included.
 */
public record HttpDiagnosticResult(
        String url,
        boolean checked,
        boolean reachable,
        Integer statusCode,
        Long responseTimeMs,
        Long totalTimeMs,
        String finalUrl,
        String httpVersion,
        String contentEncoding,
        Long contentLength,
        String message,
        Map<String, String> headers) {

    public HttpDiagnosticResult {
        headers = headers == null ? null : Collections.unmodifiableMap(new LinkedHashMap<>(headers));
    }

    /** We tried and nothing answered. */
    public static HttpDiagnosticResult unreachable(String url, String message) {
        return new HttpDiagnosticResult(url, true, false, null, null, null, null,
                null, null, null, message, null);
    }

    /** We did not try (for example, DNS failed first). */
    public static HttpDiagnosticResult notChecked(String url, String reason) {
        return new HttpDiagnosticResult(url, false, false, null, null, null, null,
                null, null, null, reason, null);
    }
}
