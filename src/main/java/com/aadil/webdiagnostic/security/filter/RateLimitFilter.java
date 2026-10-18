package com.aadil.webdiagnostic.security.filter;

import com.aadil.webdiagnostic.config.DiagnosticProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Fixed-window per-client rate limit. Without this the endpoint is a free scanning proxy
 * that anyone can point at anything.
 *
 * <p>The health check is exempt: a load balancer polling /api/v1/health every few seconds
 * would otherwise burn the whole budget for its own source address and start getting 429s,
 * which looks exactly like an outage.
 *
 * <p>Not a Spring bean on purpose: {@code SecurityConfig} creates it and places it in the security filter
 * chain. A bean of type Filter would ALSO be auto-registered in the servlet container and run twice.
 */
public class RateLimitFilter extends OncePerRequestFilter {

    private static final long WINDOW_MS = 60_000L;
    private static final int MAX_TRACKED_CLIENTS = 10_000;

    private static final Set<String> EXEMPT_PATHS = Set.of("/api/v1/health");

    private final Map<String, Window> windows = new ConcurrentHashMap<>();
    private final int limit;

    public RateLimitFilter(DiagnosticProperties props) {
        this.limit = props.rateLimitPerMinute();
    }

    /** One window per client. The counter is atomic, so concurrent requests can't slip past the limit. */
    private static final class Window {
        final long startMs;
        final AtomicInteger used = new AtomicInteger();

        Window(long startMs) {
            this.startMs = startMs;
        }
    }

    private record Decision(boolean allowed, int remaining, long resetAtMs) {
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return !path.startsWith("/api/") || EXEMPT_PATHS.contains(path);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {

        Decision decision = consume(clientKey(request));

        // Always tell the client where it stands, so a well-behaved extension can back off
        // before it gets refused. These are exposed to the browser in SecurityConfig.
        response.setHeader("X-RateLimit-Limit", String.valueOf(limit));
        response.setHeader("X-RateLimit-Remaining", String.valueOf(decision.remaining()));
        response.setHeader("X-RateLimit-Reset", String.valueOf(decision.resetAtMs() / 1000L));

        if (decision.allowed()) {
            chain.doFilter(request, response);
            return;
        }

        long retryAfterSeconds = Math.max(1, (decision.resetAtMs() - System.currentTimeMillis()) / 1000L);

        response.setStatus(429);
        response.setHeader(HttpHeaders.RETRY_AFTER, String.valueOf(retryAfterSeconds));
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        // Same shape as every other error (see ApiError / GlobalExceptionHandler).
        response.getWriter().write(
                "{\"timestamp\":\"" + Instant.now() + "\",\"status\":429,\"error\":\"RATE_LIMITED\","
                        + "\"message\":\"Too many requests. Limit is " + limit + " per minute.\"}");
    }

    private Decision consume(String key) {
        long now = System.currentTimeMillis();
        evictIfCrowded(now);

        while (true) {
            Window current = windows.get(key);

            if (current == null) {
                Window fresh = new Window(now);
                Window raced = windows.putIfAbsent(key, fresh);
                if (raced != null) {
                    continue;                       // another thread created it first; use theirs
                }
                current = fresh;

            } else if (now - current.startMs >= WINDOW_MS) {
                Window fresh = new Window(now);
                if (!windows.replace(key, current, fresh)) {
                    continue;                       // another thread already rolled the window
                }
                current = fresh;
            }

            int used = current.used.incrementAndGet();
            return new Decision(used <= limit, Math.max(0, limit - used), current.startMs + WINDOW_MS);
        }
    }

    /** Stops the map growing without bound when the service is scanned from many addresses. */
    private void evictIfCrowded(long now) {
        if (windows.size() > MAX_TRACKED_CLIENTS) {
            windows.entrySet().removeIf(e -> now - e.getValue().startMs >= WINDOW_MS);
        }
    }

    /**
     * The connection's address. In the prod profile Tomcat's RemoteIpValve (see application.yml,
     * server.tomcat.remoteip) has already replaced it with the real client address taken from
     * the trusted proxy's X-Forwarded-For. Never read X-Forwarded-For by hand here: any client
     * can spoof it to dodge the limit.
     */
    private String clientKey(HttpServletRequest request) {
        return request.getRemoteAddr();
    }
}
