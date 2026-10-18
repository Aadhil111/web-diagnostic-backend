# Deployment guide: website + backend on one AWS EC2 instance

Docker Compose runs two containers: **Caddy** (automatic HTTPS, serves the website, proxies `/api/*`) and the **Spring Boot backend**.
The Chrome extension is published separately and calls the same address.

```
Internet ──443/80──> Caddy ── /api/*  ──(private Docker network)──> Spring Boot :8080
 (browser, extension) │    └─ everything else ──> website files (web-diagnostic-website/public, mounted read-only)
                      └─ gets and renews the TLS certificate; only Caddy is exposed
```

Everything below uses `https://<your-domain>` as the public address. Replace `<your-domain>` with your own domain name or subdomain (for example `diagnostic.example.com`).

## 0. What you need

- An AWS account.
- A **domain name** you control (a domain from any registrar, or a subdomain of one) and access to its DNS settings, which you need for step 2.
- The two server-side repositories: `web-diagnostic-backend` (this one) and `web-diagnostic-website`.
- Later, for the extension: its ID (step 8). The website works without it.

## 1. Launch the EC2 instance

| Setting | Value |
|---|---|
| AMI | Ubuntu Server 24.04 LTS |
| Type | **t3.small** (2 GB RAM) or larger. t3.micro (1 GB) can run the app, but building the image on it needs swap (step 3) or build the image elsewhere (section "Build the image on your own computer") |
| Storage | 20 GB gp3 |
| Key pair | create/download one, keep the `.pem` safe and out of Git |

**Security group (inbound):**

| Port | Protocol | Source |
|---|---|---|
| 22 | TCP | **My IP only** |
| 80 | TCP | 0.0.0.0/0 (certificate issuance and the http→https redirect) |
| 443 | TCP | 0.0.0.0/0 |
| 443 | UDP | 0.0.0.0/0 (optional, HTTP/3) |

Do **not** open 8080. The backend must only be reachable through Caddy.

**Instance metadata.** This service makes outbound requests to URLs that users give it. The app already refuses private and
link-local addresses, but also harden the instance so containers can never reach the AWS credentials endpoint. Under
*Advanced details* set **Metadata version = V2 only** and **Metadata response hop limit = 1**. For an existing instance:

```bash
aws ec2 modify-instance-metadata-options --instance-id i-XXXXXXXX \
  --http-tokens required --http-put-response-hop-limit 1 --http-endpoint enabled
```

Don't attach an IAM role unless you need one.

## 2. Elastic IP and DNS

1. EC2 → Elastic IPs → Allocate → Associate with your instance (otherwise the IP changes on restart, and your DNS record would point at a dead address).
2. In your domain's DNS settings, create an **A record** for `<your-domain>` pointing at the Elastic IP.
3. Wait until it resolves: `nslookup <your-domain>` (or `dig +short <your-domain>`) shows the Elastic IP.

Caddy can only get a certificate once this record points at the server.

## 3. Prepare the server

```bash
ssh -i your-key.pem ubuntu@<ELASTIC_IP>
```

Install Docker (official repository):

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker $USER
exit            # log out and back in so the group change applies
```

Check after logging back in: `docker --version && docker compose version`.

**Low memory (t3.micro / 1 GB):** add swap before building.

```bash
sudo fallocate -l 2G /swapfile && sudo chmod 600 /swapfile
sudo mkswap /swapfile && sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
```

## 4. Put both repositories on the server

They must sit **side by side** (Compose looks for `../web-diagnostic-website/public`):

```
~/web-diagnostic/
├── web-diagnostic-backend/
└── web-diagnostic-website/
```

With Git (add a deploy key or use HTTPS if the repositories are private):

```bash
mkdir -p ~/web-diagnostic && cd ~/web-diagnostic
git clone <URL-of-web-diagnostic-backend>
git clone <URL-of-web-diagnostic-website>
```

Or copy the ZIPs from your computer and unzip them there:

```bash
scp -i your-key.pem web-diagnostic-backend.zip web-diagnostic-website.zip ubuntu@<ELASTIC_IP>:~/
ssh -i your-key.pem ubuntu@<ELASTIC_IP> 'sudo apt-get install -y unzip && mkdir -p ~/web-diagnostic && cd ~/web-diagnostic && unzip -q ~/web-diagnostic-backend.zip && unzip -q ~/web-diagnostic-website.zip'
```

If the website folder lives elsewhere, set `WEBSITE_DIR` in `.env` (next step) to the absolute path of its `public` folder.

## 5. Configure

```bash
cd ~/web-diagnostic/web-diagnostic-backend
cp .env.example .env
nano .env
```

```
DOMAIN=<your-domain>
ACME_EMAIL=you@example.com
EXTENSION_ID=
```

Leave `EXTENSION_ID` empty for now. Also open `~/web-diagnostic/web-diagnostic-website/public/privacy.html` and replace
`REPLACE_WITH_CONTACT_EMAIL` with an address where people can reach you. The Chrome Web Store needs this policy.

## 6. Deploy

```bash
docker compose up -d --build
```

The first build takes a few minutes (Maven downloads dependencies). Then:

```bash
docker compose ps                 # both containers Up; backend "healthy"
docker compose logs -f backend    # look for "Started WebDiagnosticSystemApplication"
docker compose logs -f caddy      # look for "certificate obtained successfully"
```

## 7. Verify

Open `https://<your-domain>` in a browser, enter `example.com`, press **DIAGNOSE**. Or check the API from your own computer:

```bash
curl -i https://<your-domain>/api/v1/health                  # 200 {"status":"UP"}
curl -s -X POST https://<your-domain>/api/v1/diagnostic \
  -H "Content-Type: application/json" -d '{"url":"example.com"}'
```

## 8. Publish the Chrome extension and allow it

The extension calls `https://<your-domain>/api/v1/diagnostic`, and the backend only accepts the extension's own origin
(`chrome-extension://<id>`), so the backend needs its ID. The Chrome Web Store assigns the ID when you create the item, before it is published:

1. In `web-diagnostic-extension`, set `<your-domain>` in `platform.js` (`API_BASE_URL`) and `manifest.json` (`host_permissions`), then zip the extension files with `manifest.json` at the top level.
2. Upload that ZIP as a new item in the Chrome Web Store developer dashboard (see that repository's README). Copy the item's **ID**.
3. On the server, set it in `.env` and apply:

   ```bash
   cd ~/web-diagnostic/web-diagnostic-backend
   nano .env                     # EXTENSION_ID=<the 32-letter id>
   docker compose up -d          # recreates only the backend with the new setting
   ```
4. Submit the item for review.

An unpacked copy of the extension has a different ID than the Web Store item. To test both, list both, comma-separated:
`EXTENSION_ID=<store id>,<unpacked id>`.

## 9. Day-to-day operations

```bash
cd ~/web-diagnostic/web-diagnostic-backend
docker compose logs -f --tail=100 backend      # app logs
docker compose restart backend                  # restart one service
docker compose down                             # stop everything (certificates are kept in a volume)
```

**Update the website** (no restart needed; Caddy reads the files from disk):

```bash
cd ~/web-diagnostic/web-diagnostic-website && git pull        # or copy/unzip the new version over it
```

**Update the backend:**

```bash
cd ~/web-diagnostic/web-diagnostic-backend && git pull        # or copy/unzip the new version over it
docker compose up -d --build
docker image prune -f           # clean old images
```

**Rollback:** check out or copy the previous version and run `docker compose up -d --build` again.

The app is stateless, so there is nothing to back up except your `.env`. The `caddy_data` volume holds the certificates; if lost, Caddy simply requests new ones.

## Build the image on your own computer (alternative for small instances)

```bash
docker build -t web-diagnostic-backend:latest .
docker save web-diagnostic-backend:latest | gzip > wds-backend.tar.gz
scp -i your-key.pem wds-backend.tar.gz ubuntu@<ELASTIC_IP>:~/
```

On the server:

```bash
gunzip -c ~/wds-backend.tar.gz | docker load
cd ~/web-diagnostic/web-diagnostic-backend && docker compose up -d --no-build
```

(The server still needs this repository's `docker-compose.yml`, `Caddyfile` and `.env`, and the website repository next to it.)

## 10. Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| Caddy log: "challenge failed" / no certificate | The domain name doesn't point at the Elastic IP yet, or ports 80/443 are closed in the security group. Fix, then `docker compose restart caddy`. |
| `docker compose up` says "Set DOMAIN in .env" | `.env` is missing or in a different folder from `docker-compose.yml`. |
| `docker compose up` fails with "bind source path does not exist" | The website repository is not at `../web-diagnostic-website`. Put it there or set `WEBSITE_DIR` in `.env`. |
| Backend exits at startup: "is not a Chrome extension id" | `EXTENSION_ID` must be exactly 32 lowercase letters a–p (commas between several). |
| Website shows "Cannot reach the diagnostic server" | `docker compose ps` (backend healthy?) and `docker compose logs backend`. Caddy returns 503 for up to 10 s after the backend restarts. |
| Website shows "The server refused the request (HTTP 403)" | Open the site at exactly `https://<DOMAIN>` (no `www.`, no port); that is the origin the backend allows. |
| Extension shows "(HTTP 403)" | The ID in `EXTENSION_ID` doesn't match the installed extension (Web Store and unpacked IDs differ). Update `.env`, `docker compose up -d`. |
| Extension shows "has not been configured" | `API_BASE_URL` in the extension's `platform.js` still has the placeholder. Set it to `https://<your-domain>` (and the same in `host_permissions` in `manifest.json`), then reload the extension. |
| Build killed / "Killed" during Maven | Out of memory: add swap (step 3), use a bigger instance, or build locally. |
| Every user gets HTTP 429 together | The rate limit sees Caddy's address instead of clients'. Make sure 8080 is **not** published (`ports:`) and the app runs with the `prod` profile. |
| Let's Encrypt rate-limit errors | Repeated failed attempts: wait an hour, or fix DNS before retrying. |

## 11. Security notes

- Only 80/443 are public; SSH is limited to your IP.
- The backend runs as a non-root user with all Linux capabilities dropped, `no-new-privileges`, a memory limit and log rotation.
- `8080` is intentionally not published: the rate limiter trusts `X-Forwarded-For` from private addresses, and that is only safe when Caddy is the sole path in.
- Caddy's access log is off on purpose, so tested URLs are not written to disk.
- `GET /api/v1/diagnostic` is refused at Caddy (POST only); see the comment in `Caddyfile`. To allow it for scripts, delete the `@diagnosticGet` block and run `docker compose up -d` (or `docker compose restart caddy`).
- Keep the OS patched: `sudo apt-get update && sudo apt-get upgrade -y`, and rebuild periodically
  (`docker compose build --pull && docker compose up -d`) to pick up base-image fixes.
- Docker Compose is a good fit for one small instance. For several instances the in-memory rate limiter would need a shared store.
