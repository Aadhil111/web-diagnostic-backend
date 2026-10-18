package com.aadil.webdiagnostic.model;

import java.util.List;

public record DnsDiagnosticResult(
        String domain,
        boolean resolved,
        List<String> ipAddresses,
        Long resolutionTimeMs,
        String message) {

    public static DnsDiagnosticResult resolved(String domain, List<String> ips, long elapsedMs) {
        return new DnsDiagnosticResult(domain, true, List.copyOf(ips), elapsedMs,
                "Domain resolved to " + ips.size() + " address(es)");
    }

    public static DnsDiagnosticResult failed(String domain, String message) {
        return new DnsDiagnosticResult(domain, false, List.of(), null, message);
    }
}
