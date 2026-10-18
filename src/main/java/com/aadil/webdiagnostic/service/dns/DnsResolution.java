package com.aadil.webdiagnostic.service.dns;

import com.aadil.webdiagnostic.model.DnsDiagnosticResult;

import java.net.InetAddress;
import java.util.List;

/** The DNS report plus the raw addresses, so the rest of the pipeline doesn't re-resolve. */
public record DnsResolution(DnsDiagnosticResult result, List<InetAddress> addresses) {
}
