package com.aadil.webdiagnostic.service.dns;

import com.aadil.webdiagnostic.model.DnsDiagnosticResult;
import com.aadil.webdiagnostic.network.HostResolver;
import org.springframework.stereotype.Service;

import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeUnit;

@Service
public class DnsDiagnosticService {

    private final HostResolver resolver;

    public DnsDiagnosticService(HostResolver resolver) {
        this.resolver = resolver;
    }

    /**
     * @param timeout how long to wait for the lookup; a stuck lookup is bounded by {@link HostResolver}
     * @throws com.aadil.webdiagnostic.exception.ServiceBusyException when too many lookups are in flight
     */
    public DnsResolution resolve(String host, Duration timeout) {
        long start = System.nanoTime();
        try {
            List<InetAddress> addresses = resolver.resolve(host, timeout);
            long elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);

            List<String> ips = addresses.stream()
                    .map(InetAddress::getHostAddress)
                    .distinct()
                    .toList();

            return new DnsResolution(DnsDiagnosticResult.resolved(host, ips, elapsedMs), addresses);

        } catch (SocketTimeoutException e) {
            return new DnsResolution(DnsDiagnosticResult.failed(host, "DNS lookup timed out"), List.of());
        } catch (UnknownHostException e) {
            return new DnsResolution(DnsDiagnosticResult.failed(host, "Domain name could not be resolved"), List.of());
        }
    }
}
