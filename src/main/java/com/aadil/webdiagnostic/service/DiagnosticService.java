package com.aadil.webdiagnostic.service;

import com.aadil.webdiagnostic.config.DiagnosticProperties;
import com.aadil.webdiagnostic.exception.ServiceBusyException;
import com.aadil.webdiagnostic.model.DiagnosticResult;
import com.aadil.webdiagnostic.model.DnsDiagnosticResult;
import com.aadil.webdiagnostic.model.HttpDiagnosticResult;
import com.aadil.webdiagnostic.model.RedirectDiagnosticResult;
import com.aadil.webdiagnostic.model.SslDiagnosticResult;
import com.aadil.webdiagnostic.model.TimingBreakdown;
import com.aadil.webdiagnostic.network.UrlGuard;
import com.aadil.webdiagnostic.network.UrlNormalizer;
import com.aadil.webdiagnostic.service.dns.DnsDiagnosticService;
import com.aadil.webdiagnostic.service.dns.DnsResolution;
import com.aadil.webdiagnostic.service.http.Reachability;
import com.aadil.webdiagnostic.service.http.ReachabilityService;
import com.aadil.webdiagnostic.service.tls.ConnectionProbe;
import com.aadil.webdiagnostic.service.tls.SslDiagnosticService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Supplier;

/**
 * The pipeline, top to bottom:
 * <ol>
 *   <li>normalise the URL and check its syntax (400 on failure)</li>
 *   <li>resolve DNS once, then check every address against the SSRF guard (403 on failure)</li>
 *   <li>run two branches in parallel, both connecting only to the approved addresses: the HTTP + redirect
 *       walk, and the TLS + connection-timing probe</li>
 * </ol>
 *
 * <p>The whole thing is bounded by {@code diagnostic.overall-timeout}. A branch that runs past the
 * deadline is cancelled <em>with interruption</em>, so a hung site cannot keep a socket and a
 * concurrency permit alive after the caller already has an answer.
 *
 * <p>There is deliberately no result cache: a diagnostic is a statement about a website <em>right
 * now</em>. The rate limit and the concurrency cap bound the cost instead.
 */
@Service
public class DiagnosticService {

    private static final Logger log = LoggerFactory.getLogger(DiagnosticService.class);

    private static final String TIMED_OUT = "Check did not finish in time";

    private final UrlNormalizer urlNormalizer;
    private final UrlGuard urlGuard;
    private final DnsDiagnosticService dnsService;
    private final ReachabilityService reachabilityService;
    private final SslDiagnosticService sslService;
    private final ExecutorService executor;
    private final DiagnosticProperties props;

    /** Caps how many diagnostics run at once, so a burst of traffic can't exhaust threads or sockets. */
    private final Semaphore inFlight;

    public DiagnosticService(UrlNormalizer urlNormalizer,
                             UrlGuard urlGuard,
                             DnsDiagnosticService dnsService,
                             ReachabilityService reachabilityService,
                             SslDiagnosticService sslService,
                             ExecutorService diagnosticExecutor,
                             DiagnosticProperties props) {
        this.urlNormalizer = urlNormalizer;
        this.urlGuard = urlGuard;
        this.dnsService = dnsService;
        this.reachabilityService = reachabilityService;
        this.sslService = sslService;
        this.executor = diagnosticExecutor;
        this.props = props;
        this.inFlight = new Semaphore(props.maxConcurrentDiagnostics());
    }

    public DiagnosticResult diagnose(String rawUrl) {

        URI uri = urlNormalizer.normalize(rawUrl);   // InvalidTargetException -> 400
        urlGuard.validateSyntax(uri);                // InvalidTargetException -> 400

        if (!inFlight.tryAcquire()) {
            throw new ServiceBusyException();        // -> 503
        }
        try {
            return run(uri);
        } finally {
            inFlight.release();
        }
    }

    private DiagnosticResult run(URI uri) {

        long start = System.nanoTime();
        long deadline = start + props.overallTimeout().toNanos();
        String host = uri.getHost();

        // Log the host only: paths can carry private tokens, and this is someone's browsing activity.
        log.info("Running diagnostic for host {}", host);

        // DNS first: it gates everything else and gives the SSRF guard its addresses. The lookup is
        // bounded by HostResolver (timeout, plus a cap on lookups that are still stuck), not by a Future.
        Duration dnsBudget = Duration.ofNanos(Math.max(0, deadline - System.nanoTime()));
        DnsResolution dns = dnsService.resolve(host, min(dnsBudget, props.dnsTimeout()));

        Reachability reach;
        ConnectionProbe probe;

        if (!dns.result().resolved()) {
            String reason = "Skipped because DNS resolution failed";
            reach = Reachability.notChecked(uri.toString(), reason);
            probe = skippedProbe(uri, reason);
        } else {
            urlGuard.validateAddresses(host, dns.addresses());   // BlockedTargetException -> 403

            // Both branches connect to exactly the addresses approved above; nothing is resolved a second time.
            Future<Reachability> reachFuture = executor.submit(() -> reachabilityService.probe(uri, dns.addresses()));
            Future<ConnectionProbe> probeFuture = executor.submit(() -> sslService.probe(uri, dns.addresses()));

            reach = await(reachFuture, deadline, () -> Reachability.notChecked(uri.toString(), TIMED_OUT));
            probe = await(probeFuture, deadline, () -> skippedProbe(uri, TIMED_OUT));
        }

        DnsDiagnosticResult dnsResult = dns.result();
        HttpDiagnosticResult http = reach.http();
        RedirectDiagnosticResult redirect = reach.redirect();
        SslDiagnosticResult ssl = probe.ssl();

        long totalMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);

        TimingBreakdown timing = new TimingBreakdown(
                dnsResult.resolutionTimeMs(), probe.tcpConnectMs(), probe.tlsHandshakeMs(),
                http.responseTimeMs(), totalMs);

        return new DiagnosticResult(uri.toString(), Instant.now(), totalMs,
                dnsResult, http, ssl, redirect, timing);
    }

    /**
     * Waits for a branch until the shared deadline. On timeout the task is cancelled
     * <em>with interruption</em>, which really does unblock a virtual thread sitting in a socket read.
     */
    private static <T> T await(Future<T> future, long deadlineNanos, Supplier<T> fallback) {
        try {
            if (future.isDone()) {
                return future.get();                       // finished already: never throw a result away
            }
            long remaining = deadlineNanos - System.nanoTime();
            if (remaining > 0) {
                return future.get(remaining, TimeUnit.NANOSECONDS);
            }
        } catch (TimeoutException e) {
            // fall through to the deadline handling below
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            future.cancel(true);
            return fallback.get();
        } catch (ExecutionException | CancellationException e) {
            log.warn("A diagnostic check did not complete: {}", e.toString());
            return fallback.get();
        }

        // Deadline passed. cancel() returns false if the task completed in the instant since we
        // looked; in that case its result is still valid, so keep it.
        if (!future.cancel(true) && future.state() == Future.State.SUCCESS) {
            return future.resultNow();
        }
        return fallback.get();
    }

    /**
     * The TLS section for a check that did not run. A plain http:// URL has no certificate to check,
     * so it must keep reporting "not using HTTPS" instead of claiming an HTTPS check was skipped.
     */
    private static ConnectionProbe skippedProbe(URI uri, String reason) {
        if ("https".equalsIgnoreCase(uri.getScheme())) {
            return ConnectionProbe.notChecked(reason);
        }
        return new ConnectionProbe(SslDiagnosticResult.notHttps(), null, null);
    }

    private static Duration min(Duration a, Duration b) {
        return a.compareTo(b) <= 0 ? a : b;
    }
}
