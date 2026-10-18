# Web Diagnostic: backend

A small Spring Boot service that tests a website **from the server's side**. It is one of three independent repositories:

| Repository | What it is |
|---|---|
| **web-diagnostic-backend** (this one) | the API, plus the Docker Compose + Caddy deployment for the EC2 server |
| web-diagnostic-website | the static website; Caddy serves it from the same host as the API |
| web-diagnostic-extension | the Chrome extension; it calls the same API at the same address |

```
Browser ──https──> Caddy (https://<your-domain>) ──┬─ /api/*  ──> Spring Boot :8080 (internal network only)
Extension ─https──┘                                          └─ everything else ──> website files (web-diagnostic-website/public)
```

No frontend code lives here and no backend code lives in the frontends. Deployment guide: [DEPLOYMENT.md](DEPLOYMENT.md).

| Check | What you get |
|---|---|
| **DNS** | resolved or not, IP addresses, lookup time |
| **HTTP** | final status code, HTTP version, content encoding, a safe allow-list of response headers |
| **Redirects** | every hop (status + location), loop detection, hop limit, refused unsafe hops |
| **SSL/TLS** | certificate validity, trust, hostname match, issuer, expiry, TLS version, cipher |
| **Timing** | DNS, TCP connect, TLS handshake, HTTP response, total |

Java 21 · Spring Boot 4.1 · `spring-boot-starter-webmvc` + `-security` + `-validation` · no database, no cache.

## Run

```bash
mvn spring-boot:run -Dspring-boot.run.profiles=dev     # http://localhost:8080; dev allows localhost targets and origins
mvn clean package                                      # builds target/web-diagnostic-system-1.0.0.jar
java -jar target/web-diagnostic-system-1.0.0.jar --spring.profiles.active=dev
```

## API

`POST /api/v1/diagnostic` (preferred: the URL stays out of access logs)

```json
{ "url": "example.com" }
```

`url` is the only field; unknown fields are ignored. `GET /api/v1/diagnostic?url=...` does the same for local curl testing, but the production Caddyfile answers it with 405: the URL would end up in history and proxy logs, and a GET needs no CORS preflight, so any web page could make its visitors' browsers trigger scans.
`GET /api/v1/health` is a liveness ping and is exempt from rate limiting.

Abridged response:

```json
{
  "url": "https://example.com/",
  "checkedAt": "2026-10-14T09:30:00Z",
  "durationMs": 412,
  "dns":      { "domain": "example.com", "resolved": true, "ipAddresses": ["93.184.216.34"], "resolutionTimeMs": 24 },
  "http":     { "checked": true, "reachable": true, "statusCode": 200, "responseTimeMs": 183, "totalTimeMs": 183,
                "finalUrl": "https://example.com/", "httpVersion": "HTTP_1_1", "headers": { "server": "..." } },
  "redirect": { "checked": true, "redirected": false, "count": 0, "chain": [ { "url": "https://example.com/", "statusCode": 200 } ] },
  "ssl":      { "https": true, "checked": true, "certificateValidity": "VALID", "certificateTrust": "VALID",
                "hostnameMatch": "VALID", "daysUntilExpiry": 61, "tlsVersion": "TLSv1.3" },
  "timing":   { "dnsMs": 24, "tcpConnectMs": 10, "tlsHandshakeMs": 90, "httpResponseMs": 183, "totalMs": 412 }
}
```

Fields that do not apply are omitted (for example `tlsHandshakeMs` on a plain `http://` URL).

**How to read the timings.** `httpResponseMs` is the final request only (sent → response headers), measured on its
own connection, so it includes connection setup when that connection was new. `tcpConnectMs` and `tlsHandshakeMs`
come from a separate probe connection. Response bodies are never downloaded.

## Errors

Every error is `{ "timestamp", "status", "error", "message" }`.

| Status | `error` | When |
|---|---|---|
| 400 | `INVALID_URL` / `INVALID_REQUEST` / `MISSING_PARAMETER` / `INVALID_PARAMETER` | bad URL, scheme or port; missing or malformed body or parameter |
| 403 | `BLOCKED_TARGET` | host resolves to a private, loopback or link-local address |
| 404 / 405 / 415 | `NOT_FOUND` / `METHOD_NOT_ALLOWED` / `UNSUPPORTED_MEDIA_TYPE` | wrong path, method or content type |
| 429 | `RATE_LIMITED` | over the per-client limit (`Retry-After` is set) |
| 503 | `BUSY` | too many diagnostics at once (`Retry-After: 5`) |
| 500 | `INTERNAL_ERROR` | unexpected; details are logged, never returned |

## Security

- **Spring Security** supplies the filter chain, CORS and hardened response headers, and nothing else: no login, users, sessions, tokens or authorization rules. Every request is permitted; CSRF protection is off because there are no cookies or sessions (`allowCredentials` is false).
  Order: `RequestIdFilter` → CORS → `RateLimitFilter`. A browser preflight is answered by CORS and never spends rate-limit budget; a 429 still carries CORS headers so the extension can read it.
- **CORS** allows only `chrome-extension://<id>` for each id in `diagnostic.cors.extension-ids`, plus each exact web origin in `diagnostic.cors.allowed-origins`, plus `http://localhost:*` / `http://127.0.0.1:*` when `diagnostic.cors.allow-localhost` is true (the `dev` profile only). There are no wildcards in production. In the Compose deployment the website is served from the API's own origin (so its calls are same-origin and need no CORS); Compose still lists `https://<DOMAIN>` as an allowed origin and `EXTENSION_ID` as the allowed extension. The `prod` profile **refuses to start** without an extension id or an allowed origin, or with localhost, any-extension or private-address switches turned on.
- **DNS rebinding / IP pinning.** `HostResolver` resolves each hostname once, `UrlGuard` validates every address, and the connection goes to exactly those addresses: `PinnedHttpClient` (HTTP) and `SslDiagnosticService` (TLS probe) open sockets to the approved `InetAddress` objects, so there is no second lookup to rebind. HTTPS still sends SNI and verifies the certificate chain and the **hostname** (not the IP). Every redirect hop is resolved, validated and pinned the same way.
- **IP validation** (`AddressClassifier`): IPv4 special-use blocks (this-network, private, CGNAT, loopback, link-local, IETF/documentation/benchmarking, 6to4 relay, multicast, reserved, broadcast) and, for IPv6, only global unicast `2000::/3` minus special blocks. Addresses that wrap an IPv4 address (IPv4-mapped, NAT64, 6to4) are judged by the IPv4 address inside.
- **DNS lookups are bounded.** A native lookup cannot be interrupted, so each one holds a slot (`max-concurrent-dns-lookups`) until it really finishes; a timed-out lookup keeps its slot, and further lookups get 503 instead of piling up.
- **Overall timeout.** Branches that finish are always kept, even if they finish at the deadline; only branches still running at the deadline are cancelled (with interruption) and reported as "did not finish in time".
- **UrlNormalizer** turns input into one canonical URL (adds `https://`, punycode for international names), drops query string and fragment, keeps percent-encoding as sent, rejects credentials in URLs.
- **RateLimitFilter**: fixed window per client address; `X-RateLimit-*` headers on every response. It never trusts a client-sent `X-Forwarded-For`.
- **RequestIdFilter**: an `X-Request-Id` on every response and in every log line. URLs are never logged, only hosts.
- Also: a concurrency cap, an overall timeout, no body downloads, no cookies read or returned.
- **Caddy** (see `Caddyfile`) adds HTTPS with HSTS, a strict Content-Security-Policy for the website, an 8 KB request body limit on the API, and replaces any client-sent `X-Forwarded-For`.

**HTTP version.** The HTTP check speaks HTTP/1.1 (`httpVersion` is `HTTP_1_1`); it no longer reports `HTTP_2`, because the JDK's HTTP client cannot be given pre-approved addresses.

## Configuration (`application.yml`, prefix `diagnostic`)

| Key | Default | Meaning |
|---|---|---|
| `connect-timeout` / `read-timeout` / `overall-timeout` | 8s / 12s / 30s | connecting, waiting for response headers, whole diagnostic |
| `dns-timeout` | 5s | per DNS lookup (initial host and each redirect hop) |
| `max-redirects` | 10 | longer chains are reported as `truncated` |
| `allowed-ports` | 80, 443, 8080, 8443 | other ports are rejected |
| `allow-private-addresses` | false | `true` only in the `dev` profile; `prod` refuses to start with it |
| `inspect-untrusted-certificates` | true | still read issuer and expiry of a certificate that failed validation |
| `connection-attempts` / `retry-delay` | 2 / 500ms | retry of the first request only |
| `rate-limit-per-minute` | 30 | per client address |
| `max-concurrent-diagnostics` | 50 | above this: 503 |
| `max-concurrent-dns-lookups` | 64 | stuck lookups cannot exceed this; above it: 503 |
| `keep-query-string` | false | privacy: query strings often carry tokens |
| `cors.extension-ids` | none | Chrome extension ids (32 letters a-p). Set `DIAGNOSTIC_CORS_EXTENSION_IDS` (comma-separated). `prod` needs this or `allowed-origins` |
| `cors.allowed-origins` | none | Exact web origins, e.g. `https://your-domain.com` (no path/wildcard). Set `DIAGNOSTIC_CORS_ALLOWED_ORIGINS` (comma-separated) |
| `cors.allow-any-extension` | false | development only; the `dev` profile allows any `chrome-extension://*` so an unpacked extension works without its id; `prod` refuses it |
| `cors.allow-localhost` | false | development only; the `dev` profile enables it, `prod` refuses it |

Profiles: `dev` (private targets and localhost origins allowed, debug logs) and `prod` (reads the real client IP from `X-Forwarded-For`;
only enable behind a proxy you control that overwrites that header, with port 8080 unreachable from outside; requires an allowed origin or extension id).
The Docker image runs `prod` by default.

```bash
SPRING_PROFILES_ACTIVE=prod DIAGNOSTIC_CORS_EXTENSION_IDS=abcdefghijklmnopabcdefghijklmnop java -jar target/web-diagnostic-system-1.0.0.jar
```

## Layout

Base package: `com.aadil.webdiagnostic`. Request flow: `controller` → `service` → (`network` guard, `model` results), with `security.filter` in front and `exception` turning failures into JSON.

```
src/main/java/com/aadil/webdiagnostic/
├── WebDiagnosticSystemApplication.java
├── config/              DiagnosticProperties (diagnostic.* binding), ExecutorConfig
├── controller/          DiagnosticController (POST and GET /api/v1/diagnostic), HealthController (GET /api/v1/health)
├── dto/                 DiagnosticRequest (request body), ApiError (error body)
├── exception/           InvalidTarget / BlockedTarget / ServiceBusy exceptions, GlobalExceptionHandler
├── model/               result records: Diagnostic, Dns, Http, Redirect (+ RedirectHop), Ssl, TimingBreakdown, CheckStatus
├── network/             UrlNormalizer, UrlGuard, AddressClassifier, HostResolver     (what we may connect to: SSRF guard)
├── security/            SecurityConfig (filter chain + CORS)
│   └── filter/          RequestIdFilter, RateLimitFilter
└── service/             DiagnosticService (the pipeline)
    ├── dns/             DnsDiagnosticService, DnsResolution
    ├── http/            ReachabilityService (redirect walk), Reachability, PinnedHttpClient (package-private)
    └── tls/             SslDiagnosticService (TLS + connect timing), ConnectionProbe
```

Design notes:

- `PinnedHttpClient` is package-private on purpose: only `service.http` can open sockets to pre-approved addresses, so nothing else can bypass the SSRF guard.
- `service.*` sub-packages are one per check (DNS / HTTP+redirects / TLS); `DiagnosticService` is the only class that composes them.
- Filters are plain classes created by `SecurityConfig`, not beans, so they run exactly once, in a defined order.

Outside `src/`: `Dockerfile`, `docker-compose.yml` and `Caddyfile` (deployment), `.env.example` (settings for Compose).
