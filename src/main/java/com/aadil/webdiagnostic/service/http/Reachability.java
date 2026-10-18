package com.aadil.webdiagnostic.service.http;

import com.aadil.webdiagnostic.model.HttpDiagnosticResult;
import com.aadil.webdiagnostic.model.RedirectDiagnosticResult;

/**
 * The output of one walk of the redirect chain: what the site finally answered, and how we got there.
 * Both come from the SAME set of requests - see {@link ReachabilityService}.
 */
public record Reachability(HttpDiagnosticResult http, RedirectDiagnosticResult redirect) {

    public static Reachability notChecked(String url, String reason) {
        return new Reachability(
                HttpDiagnosticResult.notChecked(url, reason),
                RedirectDiagnosticResult.notChecked(reason));
    }
}
