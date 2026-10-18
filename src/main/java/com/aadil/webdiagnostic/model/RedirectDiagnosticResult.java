package com.aadil.webdiagnostic.model;

import java.util.List;

/**
 * The redirect chain, hop by hop.
 *
 * @param redirected  true when at least one hop redirected
 * @param count       number of redirecting hops (3xx with a Location header)
 * @param truncated   the chain was longer than {@code diagnostic.max-redirects}
 * @param blockedHop  the chain pointed at an address we refuse to probe (private / link-local).
 *                    Usually means an open redirect or a misconfigured internal rewrite.
 * @param chain       every response we saw, in order; the last one is the final response
 */
public record RedirectDiagnosticResult(
        boolean checked,
        boolean redirected,
        int count,
        boolean loopDetected,
        boolean truncated,
        boolean blockedHop,
        String finalUrl,
        List<RedirectHop> chain,
        String message) {

    public RedirectDiagnosticResult {
        chain = chain == null ? List.of() : List.copyOf(chain);
    }

    public static RedirectDiagnosticResult of(List<RedirectHop> chain, String finalUrl,
                                              boolean loopDetected, boolean truncated, boolean blockedHop) {
        int redirects = countRedirects(chain);

        String message;
        if (loopDetected) {
            message = "Redirect loop detected";
        } else if (truncated) {
            message = "Redirect chain exceeded the maximum number of hops";
        } else if (blockedHop) {
            message = "Redirect chain pointed at an address that is not safe to follow";
        } else if (redirects == 0) {
            message = "No redirects";
        } else {
            message = "Followed " + redirects + " redirect(s)";
        }

        return new RedirectDiagnosticResult(true, redirects > 0, redirects,
                loopDetected, truncated, blockedHop, finalUrl, chain, message);
    }

    /** The chain broke partway through (network error), so what we have is partial. */
    public static RedirectDiagnosticResult incomplete(List<RedirectHop> chain, String finalUrl, String message) {
        int redirects = countRedirects(chain);
        return new RedirectDiagnosticResult(true, redirects > 0, redirects,
                false, false, false, finalUrl, chain, message);
    }

    public static RedirectDiagnosticResult notChecked(String reason) {
        return new RedirectDiagnosticResult(false, false, 0, false, false, false, null, List.of(), reason);
    }

    /** A 3xx without a Location header (e.g. 304) is not a redirect we can follow. */
    private static int countRedirects(List<RedirectHop> chain) {
        return (int) chain.stream()
                .filter(hop -> hop.statusCode() != null
                        && hop.statusCode() >= 300 && hop.statusCode() < 400
                        && hop.location() != null)
                .count();
    }
}
