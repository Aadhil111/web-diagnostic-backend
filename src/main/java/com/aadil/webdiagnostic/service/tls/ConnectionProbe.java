package com.aadil.webdiagnostic.service.tls;

import com.aadil.webdiagnostic.model.SslDiagnosticResult;

/**
 * What one connection to the site told us: the certificate verdict, plus how long the
 * connection phases took. The timings come from the same socket as the TLS check,
 * so measuring them costs no extra connection.
 */
public record ConnectionProbe(SslDiagnosticResult ssl, Long tcpConnectMs, Long tlsHandshakeMs) {

    public static ConnectionProbe notChecked(String reason) {
        return new ConnectionProbe(SslDiagnosticResult.notChecked(reason), null, null);
    }
}
