package com.aadil.webdiagnostic.network;

import com.aadil.webdiagnostic.config.DiagnosticProperties;
import com.aadil.webdiagnostic.exception.ServiceBusyException;
import org.springframework.stereotype.Component;

import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * The only place that performs DNS lookups.
 *
 * <p>{@code InetAddress.getAllByName} is a blocking native call: it cannot be interrupted, so
 * cancelling the Future that wraps it does not stop it. Left unbounded, a flood of requests for names
 * whose DNS servers never answer would pile up stuck threads. So:
 * <ul>
 *   <li>every lookup holds a permit, and the permit is released by the lookup itself, when it really
 *       finishes - not when the caller gives up. A timed-out lookup therefore keeps counting against
 *       the cap until it has actually ended;</li>
 *   <li>when no permit is free the request is refused with {@link ServiceBusyException} (HTTP 503)
 *       instead of queueing more work behind stuck lookups.</li>
 * </ul>
 */
@Component
public class HostResolver implements AutoCloseable {

    private final Semaphore permits;
    /**
     * Platform daemon threads on purpose: a native lookup pins a virtual thread's carrier anyway.
     * The pool can never grow past the number of permits, so it is bounded without a queue.
     */
    private final ExecutorService executor = Executors.newCachedThreadPool(runnable -> {
        Thread thread = new Thread(runnable, "dns-lookup");
        thread.setDaemon(true);
        return thread;
    });

    public HostResolver(DiagnosticProperties props) {
        this.permits = new Semaphore(props.maxConcurrentDnsLookups());
    }

    /**
     * @throws UnknownHostException   the name does not exist
     * @throws SocketTimeoutException the lookup did not finish within {@code timeout}
     * @throws ServiceBusyException   too many lookups are already in flight (including stuck ones)
     */
    public List<InetAddress> resolve(String host, Duration timeout) throws UnknownHostException, SocketTimeoutException {
        if (!permits.tryAcquire()) {
            throw new ServiceBusyException();
        }
        // Exactly one party gives the slot back: the lookup task when it really ends, or - if the task
        // was cancelled before it ever started and so can never run its own cleanup - the caller.
        AtomicBoolean slotHandled = new AtomicBoolean();
        Future<InetAddress[]> future;
        try {
            future = executor.submit(() -> {
                boolean callerAlreadyReleased = slotHandled.getAndSet(true);
                try {
                    return InetAddress.getAllByName(host);
                } finally {
                    if (!callerAlreadyReleased) {
                        permits.release();   // released when the lookup truly ends, not when the caller stops waiting
                    }
                }
            });
        } catch (RuntimeException e) {
            permits.release();               // the task never started, so it can't release its own permit
            throw e;
        }

        try {
            return List.of(future.get(Math.max(1, timeout.toMillis()), TimeUnit.MILLISECONDS));
        } catch (TimeoutException e) {
            abandon(future, slotHandled);
            throw new SocketTimeoutException("DNS lookup timed out");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            abandon(future, slotHandled);
            throw new SocketTimeoutException("DNS lookup was interrupted");
        } catch (ExecutionException e) {
            if (e.getCause() instanceof UnknownHostException unknown) {
                throw unknown;
            }
            UnknownHostException wrapped = new UnknownHostException(host);
            wrapped.initCause(e.getCause());
            throw wrapped;
        }
    }

    /**
     * Stops waiting for a lookup. A lookup that is already running keeps its slot until it finishes
     * (it cannot be interrupted); one that never started gives its slot back here.
     */
    private void abandon(Future<?> future, AtomicBoolean slotHandled) {
        future.cancel(true);
        if (!slotHandled.getAndSet(true)) {
            permits.release();
        }
    }

    @Override
    public void close() {
        executor.shutdownNow();
    }
}
