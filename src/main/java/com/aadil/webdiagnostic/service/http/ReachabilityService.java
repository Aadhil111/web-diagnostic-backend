package com.aadil.webdiagnostic.service.http;

import com.aadil.webdiagnostic.config.DiagnosticProperties;
import com.aadil.webdiagnostic.exception.BlockedTargetException;
import com.aadil.webdiagnostic.exception.InvalidTargetException;
import com.aadil.webdiagnostic.exception.ServiceBusyException;
import com.aadil.webdiagnostic.model.HttpDiagnosticResult;
import com.aadil.webdiagnostic.model.RedirectDiagnosticResult;
import com.aadil.webdiagnostic.model.RedirectHop;
import com.aadil.webdiagnostic.network.HostResolver;
import com.aadil.webdiagnostic.network.UrlGuard;
import org.springframework.stereotype.Service;

import javax.net.ssl.SSLException;
import java.io.IOException;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.NoRouteToHostException;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * Walks the site's redirect chain ONCE and reports both things we need from it:
 * whether the site answers (HTTP), and what the chain looks like (redirects).
 *
 * <ul>
 *   <li>Redirects are followed by hand, so every hop passes the SSRF guard. A client that follows
 *       redirects on its own would happily be sent to http://169.254.169.254/ (the cloud metadata service).</li>
 *   <li>Every hop is resolved ONCE, validated, and then connected to by those exact addresses
 *       ({@link PinnedHttpClient}). The first hop reuses the addresses the pipeline already approved.
 *       No second DNS lookup exists for a hostile server to answer differently (DNS rebinding).</li>
 *   <li>Response bodies are never downloaded: the socket is closed as soon as the headers arrive.
 *       That gives an honest time-to-headers and a 2 GB file costs nothing.</li>
 *   <li>Only the first request is retried. A single failed connection is not proof a site is down,
 *       but a later hop failing is a fact about the chain.</li>
 * </ul>
 */
@Service
public class ReachabilityService {

    /** The only response headers we keep. An allow-list on purpose: nothing sensitive is ever copied out. */
    private static final List<String> REPORTED_HEADERS = List.of(
            "server", "content-type", "content-length", "content-encoding", "vary",
            "cache-control", "etag", "last-modified", "age", "alt-svc", "cf-mitigated",
            "strict-transport-security", "content-security-policy",
            "x-content-type-options", "x-frame-options", "referrer-policy", "permissions-policy");

    private static final int MAX_HEADER_VALUE_CHARS = 300;

    private final DiagnosticProperties props;
    private final UrlGuard urlGuard;
    private final HostResolver resolver;
    private final PinnedHttpClient client;

    public ReachabilityService(DiagnosticProperties props, UrlGuard urlGuard, HostResolver resolver) {
        this.props = props;
        this.urlGuard = urlGuard;
        this.resolver = resolver;
        this.client = new PinnedHttpClient(props);
    }

    /**
     * @param startAddresses the already validated addresses of {@code start}'s host; the first request
     *                       connects to exactly these
     */
    public Reachability probe(URI start, List<InetAddress> startAddresses) {

        long begin = System.nanoTime();

        List<RedirectHop> chain = new ArrayList<>();
        Set<String> visited = new LinkedHashSet<>();

        URI current = start;
        List<InetAddress> currentAddresses = startAddresses;
        URI lastAnswered = null;
        Answer last = null;

        boolean loopDetected = false;
        boolean truncated = false;
        boolean blockedHop = false;
        String chainFailure = null;

        for (int hop = 0; ; hop++) {

            if (!visited.add(current.toString())) {
                loopDetected = true;
                break;
            }

            Attempt attempt;
            try {
                attempt = requestHop(current, currentAddresses, hop == 0);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return Reachability.notChecked(start.toString(), "Check was interrupted");
            }

            if (attempt.failure() != null) {
                if (hop == 0) {
                    // Nothing answered at all.
                    return new Reachability(
                            HttpDiagnosticResult.unreachable(start.toString(),
                                    describe(attempt.failure()) + attemptSuffix(attempt.attempts())),
                            RedirectDiagnosticResult.notChecked("Skipped because the site did not answer"));
                }
                // The site answered, then a later hop broke. Keep what we learned.
                chainFailure = "Redirect chain could not be completed: " + describe(attempt.failure());
                break;
            }

            last = attempt.answer();
            lastAnswered = current;
            PinnedHttpClient.Response response = last.response();

            Optional<URI> next = redirectTarget(current, response);
            chain.add(new RedirectHop(withoutQuery(current.toString()), response.statusCode(),
                    withoutQuery(response.header("location"))));

            if (next.isEmpty()) {
                break;
            }
            if (hop >= props.maxRedirects()) {
                truncated = true;
                break;
            }

            // Resolve and validate the next hop ONCE; the connection will use exactly these addresses.
            Approval approval = approve(next.get());
            if (approval.blocked()) {
                blockedHop = true;
                break;
            }
            if (approval.failure() != null) {
                chainFailure = "Redirect chain could not be completed: " + approval.failure();
                break;
            }
            current = next.get();
            currentAddresses = approval.addresses();
        }

        return assemble(start, lastAnswered, last, millisSince(begin),
                chain, loopDetected, truncated, blockedHop, chainFailure);
    }

    // ------------------------------------------------------------------ assembly

    private Reachability assemble(URI start, URI lastAnswered, Answer last, long totalMs,
                                  List<RedirectHop> chain, boolean loopDetected, boolean truncated,
                                  boolean blockedHop, String chainFailure) {

        PinnedHttpClient.Response response = last.response();
        String finalUrl = withoutQuery(lastAnswered.toString());

        HttpDiagnosticResult http = new HttpDiagnosticResult(
                start.toString(),
                true,
                true,
                response.statusCode(),
                last.elapsedMs(),
                totalMs,
                finalUrl,
                response.httpVersion(),
                response.header("content-encoding"),
                contentLength(response),
                "Server responded with HTTP " + response.statusCode(),
                reportedHeaders(response));

        RedirectDiagnosticResult redirect = chainFailure != null
                ? RedirectDiagnosticResult.incomplete(chain, finalUrl, chainFailure)
                : RedirectDiagnosticResult.of(chain, finalUrl, loopDetected, truncated, blockedHop);

        return new Reachability(http, redirect);
    }

    // ------------------------------------------------------------------ redirect hop approval

    /** Outcome of vetting a redirect target: usable addresses, or why it must not be followed. */
    private record Approval(List<InetAddress> addresses, boolean blocked, String failure) {
        static Approval approved(List<InetAddress> addresses) {
            return new Approval(addresses, false, null);
        }

        static Approval refused() {
            return new Approval(null, true, null);
        }

        static Approval failed(String reason) {
            return new Approval(null, false, reason);
        }
    }

    /**
     * A redirect we refuse to follow still proves the site answered, so it is reported, not treated as an error.
     * The addresses returned here are the ones the next request connects to.
     */
    private Approval approve(URI target) {
        try {
            urlGuard.validateSyntax(target);
            List<InetAddress> addresses = resolver.resolve(target.getHost(), props.dnsTimeout());
            urlGuard.validateAddresses(target.getHost(), addresses);
            return Approval.approved(addresses);
        } catch (InvalidTargetException | BlockedTargetException e) {
            return Approval.refused();
        } catch (UnknownHostException e) {
            return Approval.failed("Redirect target could not be resolved");
        } catch (SocketTimeoutException e) {
            return Approval.failed("Redirect target lookup timed out");
        } catch (ServiceBusyException e) {
            return Approval.failed("Service was too busy to look up the redirect target");
        }
    }

    // ------------------------------------------------------------------ requests and retry

    /** One response, and how long that single request took (headers received). */
    private record Answer(PinnedHttpClient.Response response, long elapsedMs) {
    }

    /** One hop's outcome: either an answer, or the failure that ended it, plus how many tries it took. */
    private record Attempt(Answer answer, int attempts, IOException failure) {
    }

    /**
     * Sends one hop, retrying a transient failure when {@code allowRetry} is set.
     *
     * <p>A dropped packet, a load balancer rotating a backend or a server restarting mid-deploy all
     * look exactly like an outage and clear within a second, so one retry removes most false
     * "unreachable" results. Deterministic failures (bad certificate) are not retried: the second
     * attempt would fail identically and only add latency.
     */
    private Attempt requestHop(URI uri, List<InetAddress> addresses, boolean allowRetry) throws InterruptedException {

        int maxAttempts = allowRetry ? props.connectionAttempts() : 1;
        IOException last = null;

        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            try {
                return new Attempt(headWithGetFallback(uri, addresses), attempt, null);
            } catch (IOException e) {
                last = e;
                if (attempt == maxAttempts || !isWorthRetrying(e)) {
                    return new Attempt(null, attempt, e);
                }
                Thread.sleep(props.retryDelay().toMillis());
            }
        }
        return new Attempt(null, maxAttempts, last);
    }

    /** Deny-list, not allow-list: transient faults are a wide range of IOExceptions; the deterministic one is easy to name. */
    private boolean isWorthRetrying(IOException e) {
        for (Throwable t = e; t != null; t = t.getCause()) {
            if (t instanceof SSLException) {
                return false;
            }
        }
        return true;
    }

    private String attemptSuffix(int attempts) {
        return attempts > 1 ? " (failed on " + attempts + " separate attempts)" : "";
    }

    private Answer headWithGetFallback(URI uri, List<InetAddress> addresses) throws IOException {
        PinnedHttpClient.Response response = client.send(uri, addresses, "HEAD");
        // Plenty of servers reject HEAD; fall back to GET before calling the site broken.
        if (response.statusCode() == 405 || response.statusCode() == 501) {
            response = client.send(uri, addresses, "GET");
        }
        return new Answer(response, response.elapsedMs());
    }

    // ------------------------------------------------------------------ redirects

    /** The next URL if this response is a redirect with a usable Location header. */
    private Optional<URI> redirectTarget(URI current, PinnedHttpClient.Response response) {
        int status = response.statusCode();
        if (status < 300 || status >= 400) {
            return Optional.empty();
        }
        String location = response.header("location");
        if (location == null) {
            return Optional.empty();
        }
        try {
            URI target = current.resolve(location);
            return target.getHost() == null ? Optional.empty() : Optional.of(target);
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
    }

    // ------------------------------------------------------------------ headers and helpers

    private Map<String, String> reportedHeaders(PinnedHttpClient.Response response) {
        Map<String, String> reported = new LinkedHashMap<>();
        for (String name : REPORTED_HEADERS) {
            String value = response.header(name);
            if (value != null) {
                reported.put(name, truncate(value));
            }
        }
        return reported;
    }

    /** A server can send a garbage Content-Length; that must not break the whole check. */
    private Long contentLength(PinnedHttpClient.Response response) {
        String value = response.header("content-length");
        if (value == null) {
            return null;
        }
        try {
            return Long.valueOf(value.trim());
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private String truncate(String value) {
        return value.length() <= MAX_HEADER_VALUE_CHARS
                ? value
                : value.substring(0, MAX_HEADER_VALUE_CHARS) + "...";
    }

    private long millisSince(long startNanos) {
        return TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startNanos);
    }

    /**
     * Host and path only - the query string is dropped. A sign-in redirect carries exactly the kind
     * of parameter (session handles, continue URLs) that must never be echoed back or logged.
     */
    private static String withoutQuery(String url) {
        if (url == null) {
            return null;
        }
        int cut = url.indexOf('?');
        String trimmed = cut < 0 ? url : url.substring(0, cut);
        int fragment = trimmed.indexOf('#');
        return fragment < 0 ? trimmed : trimmed.substring(0, fragment);
    }

    /** Plain wording for the failure, with no stack traces. */
    private String describe(IOException e) {
        if (e instanceof SocketTimeoutException) {
            return "Request timed out";
        }
        if (e instanceof ConnectException || e instanceof NoRouteToHostException) {
            return "Connection refused or unreachable";
        }
        if (e instanceof SSLException) {
            return "TLS connection failed: " + rootMessage(e);
        }
        return "Connection failed: " + rootMessage(e);
    }

    private String rootMessage(Throwable t) {
        Throwable current = t;
        while (current.getCause() != null) {
            current = current.getCause();
        }
        return current.getMessage() != null ? current.getMessage() : current.getClass().getSimpleName();
    }
}
