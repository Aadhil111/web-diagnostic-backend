package com.aadil.webdiagnostic.model;

import java.time.Instant;

/**
 * The complete response of one diagnostic run. Every section is a measurement from our server.
 *
 * @param url normalised URL that was actually tested
 */
public record DiagnosticResult(
        String url,
        Instant checkedAt,
        long durationMs,
        DnsDiagnosticResult dns,
        HttpDiagnosticResult http,
        SslDiagnosticResult ssl,
        RedirectDiagnosticResult redirect,
        TimingBreakdown timing) {
}
