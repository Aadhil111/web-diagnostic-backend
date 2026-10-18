package com.aadil.webdiagnostic.model;

/**
 * Where the time went, measured from our server. Separates a slow name lookup from a slow
 * handshake from a slow application.
 *
 * <p>Any field is null when that phase did not apply or could not be measured (for example
 * {@code tlsHandshakeMs} on a plain http:// site).
 *
 * @param dnsMs          looking up the domain name
 * @param tcpConnectMs   opening a TCP connection (taken from the TLS probe's own connection)
 * @param tlsHandshakeMs completing the TLS handshake (same connection)
 * @param httpResponseMs final HTTP request: sent -> response headers received. This is a separate
 *                       connection from the two above, so it includes its own connection setup
 *                       when the connection was new. See {@link HttpDiagnosticResult}.
 * @param totalMs        the whole diagnostic, including every redirect hop
 */
public record TimingBreakdown(
        Long dnsMs,
        Long tcpConnectMs,
        Long tlsHandshakeMs,
        Long httpResponseMs,
        Long totalMs) {
}
