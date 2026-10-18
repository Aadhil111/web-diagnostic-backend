package com.aadil.webdiagnostic.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/** Everything tunable lives under {@code diagnostic.*} in application.yml. Missing values get safe defaults. */
@ConfigurationProperties(prefix = "diagnostic")
public record DiagnosticProperties(
        Duration connectTimeout,
        Duration readTimeout,
        Duration overallTimeout,
        Duration dnsTimeout,
        Integer maxRedirects,
        String userAgent,
        Set<Integer> allowedPorts,
        Boolean allowPrivateAddresses,
        Boolean inspectUntrustedCertificates,
        Integer connectionAttempts,
        Duration retryDelay,
        Integer rateLimitPerMinute,
        Integer maxConcurrentDiagnostics,
        Integer maxConcurrentDnsLookups,
        Boolean keepQueryString,
        Cors cors
) {

    /**
     * Which web origins may call the API from a browser.
     *
     * @param extensionIds   Chrome extension ids (32 letters a-p); each becomes {@code chrome-extension://<id>}.
     *                       Required in the prod profile; with none configured no origin is allowed.
     * @param allowedOrigins exact web origins (scheme + host [+ port], no path, no wildcard) of a website
     *                       frontend, e.g. {@code https://diagnose.example.com}. Optional.
     * @param allowAnyExtension development only: allow EVERY {@code chrome-extension://*} origin, so an unpacked
     *                       extension works without copying its id (the id differs per machine/path).
     *                       The dev profile turns it on; the prod profile refuses to start with it.
     * @param allowLocalhost also allow {@code http://localhost:*} and {@code http://127.0.0.1:*}.
     *                       Development only: the dev profile turns it on, the default is off.
     */
    public record Cors(List<String> extensionIds, List<String> allowedOrigins, Boolean allowLocalhost,
                       Boolean allowAnyExtension) {

        private static final Pattern EXTENSION_ID = Pattern.compile("[a-p]{32}");
        private static final Pattern WEB_ORIGIN = Pattern.compile("https?://[A-Za-z0-9.\\-]+(:\\d{1,5})?");

        public Cors {
            extensionIds = extensionIds == null ? List.of() : extensionIds.stream()
                    .map(String::trim)
                    .filter(id -> !id.isEmpty())
                    .toList();
            for (String id : extensionIds) {
                if (!EXTENSION_ID.matcher(id).matches()) {
                    throw new IllegalArgumentException(
                            "diagnostic.cors.extension-ids: '" + id + "' is not a Chrome extension id (32 letters a-p)");
                }
            }
            allowedOrigins = allowedOrigins == null ? List.of() : allowedOrigins.stream()
                    .map(String::trim)
                    .filter(origin -> !origin.isEmpty())
                    .toList();
            for (String origin : allowedOrigins) {
                if (!WEB_ORIGIN.matcher(origin).matches()) {
                    throw new IllegalArgumentException(
                            "diagnostic.cors.allowed-origins: '" + origin + "' is not an origin "
                                    + "(use e.g. https://diagnose.example.com: no path, no trailing slash, no wildcard)");
                }
            }
            if (allowLocalhost == null) allowLocalhost = false;
            if (allowAnyExtension == null) allowAnyExtension = false;
        }

        /** The exact origin patterns handed to the CORS filter. */
        public List<String> allowedOriginPatterns() {
            List<String> origins = new java.util.ArrayList<>();
            for (String id : extensionIds) {
                origins.add("chrome-extension://" + id);
            }
            origins.addAll(allowedOrigins);
            if (allowAnyExtension) {
                origins.add("chrome-extension://*");
            }
            if (allowLocalhost) {
                origins.add("http://localhost:*");
                origins.add("http://127.0.0.1:*");
            }
            return List.copyOf(origins);
        }
    }

    public DiagnosticProperties {
        if (connectTimeout == null)                connectTimeout = Duration.ofSeconds(5);
        if (readTimeout == null)                   readTimeout = Duration.ofSeconds(10);
        if (overallTimeout == null)                overallTimeout = Duration.ofSeconds(20);
        if (dnsTimeout == null)                    dnsTimeout = Duration.ofSeconds(5);
        if (maxRedirects == null || maxRedirects <= 0) maxRedirects = 10;
        if (userAgent == null || userAgent.isBlank())  userAgent = "WebDiagnosticSystem/1.0";
        if (allowedPorts == null || allowedPorts.isEmpty()) allowedPorts = Set.of(80, 443, 8080, 8443);
        if (allowPrivateAddresses == null)         allowPrivateAddresses = false;
        if (inspectUntrustedCertificates == null)  inspectUntrustedCertificates = true;
        // Retries absorb a dropped packet; they are clamped so we never keep knocking on a shut door.
        if (connectionAttempts == null || connectionAttempts < 1) connectionAttempts = 2;
        if (connectionAttempts > 3)                connectionAttempts = 3;
        if (retryDelay == null || retryDelay.isNegative()) retryDelay = Duration.ofMillis(500);
        if (rateLimitPerMinute == null || rateLimitPerMinute <= 0) rateLimitPerMinute = 30;
        if (maxConcurrentDiagnostics == null || maxConcurrentDiagnostics <= 0) maxConcurrentDiagnostics = 50;
        if (maxConcurrentDnsLookups == null || maxConcurrentDnsLookups <= 0) maxConcurrentDnsLookups = 64;
        if (keepQueryString == null)               keepQueryString = false;
        if (cors == null)                          cors = new Cors(null, null, null, null);
    }

    public int connectTimeoutMillis() {
        return (int) connectTimeout.toMillis();
    }

    public int readTimeoutMillis() {
        return (int) readTimeout.toMillis();
    }
}
