package com.aadil.webdiagnostic.model;

import java.time.Instant;

/**
 * Result of the TLS check, from OUR server.
 *
 * @param https  false when the URL is plain http:// (there is no certificate to check)
 * @param checked whether a TLS handshake was attempted and completed far enough to judge
 */
public record SslDiagnosticResult(
        boolean https,
        boolean checked,
        CheckStatus certificateValidity,
        CheckStatus certificateTrust,
        CheckStatus hostnameMatch,
        String subject,
        String issuer,
        Instant validFrom,
        Instant validUntil,
        Long daysUntilExpiry,
        Boolean selfSigned,
        String tlsVersion,
        String cipherSuite,
        String message) {

    public static SslDiagnosticResult notHttps() {
        return new SslDiagnosticResult(false, false,
                CheckStatus.NOT_CHECKED, CheckStatus.NOT_CHECKED, CheckStatus.NOT_CHECKED,
                null, null, null, null, null, null, null, null,
                "Website is not using HTTPS");
    }

    public static SslDiagnosticResult notChecked(String reason) {
        return new SslDiagnosticResult(true, false,
                CheckStatus.NOT_CHECKED, CheckStatus.NOT_CHECKED, CheckStatus.NOT_CHECKED,
                null, null, null, null, null, null, null, null, reason);
    }
}
