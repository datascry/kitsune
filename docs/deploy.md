# Deploy — hosting the full stack with a real network edge

Run Kitsune's **edge + detector** on a VPS with a real domain so the edge captures genuine **TLS JA3/JA4,
HTTP/2 (JA4H), TCP/IP-OS, and QUIC/HTTP-3** fingerprints from real visitor connections. This is the Tier-3
unlock the [research radar](research-radar.md) points at: real traffic feeds `task grounding` (real-traffic
prevalence prior, IP-reputation, the live QUIC rule) and makes the vendor comparison non-IP-confounded.

## Resource requirements

The stack is light (Go edge + Python detector + SQLite); cost is TLS termination + fingerprint parsing.

| | vCPU | RAM | Disk | Notes |
|---|---|---|---|---|
| **Recommended** | 2 | **4 GB** | 40 GB SSD | comfortable build (`uv sync` + Go + images) + headroom; e.g. Hetzner CX22 (~€5/mo) |
| Minimum | 1–2 | 2 GB | 20 GB | runs fine; build is tighter (or build elsewhere and pull) |

OS: Ubuntu/Debian 22.04/24.04 with Docker + the compose plugin.

## The make-or-break networking rules

1. **Direct public IP — NO CDN/proxy in front.** A proxying CDN (Cloudflare orange-cloud, any L7 load
   balancer) re-terminates TLS and rewrites the connection, **destroying JA3/JA4, HTTP/2 and TCP
   fingerprints**. Point DNS `A`/`AAAA` straight at the VPS (if Cloudflare hosts DNS, set the record to
   grey-cloud / DNS-only).
2. **Raw-packet access** for TCP/IP fingerprinting — the edge runs an AF_PACKET SYN sniffer (`CAP_NET_RAW`,
   already set in the base compose) and needs to see the real client SYN, which the direct public IP gives.
3. **Open ports:** `443/tcp` (TLS+H2), `443/udp` (QUIC/H3), `80/tcp` (ACME HTTP-01 + renewal). Keep the
   detector internal (compose network only). Firewall everything else; SSH on 22.

## One-time setup

```sh
# 0. DNS: A (and AAAA) record for your.domain -> the VPS public IP, DNS-only (no CDN proxy).
# 1. Install Docker + compose plugin, then:
git clone https://github.com/datascry/kitsune && cd kitsune

# 2. Configure the domain + ACME email.
cat > .env <<EOF
KITSUNE_DOMAIN=your.domain
KITSUNE_ACME_EMAIL=you@example.com
# Recommended on a public host: gate the inspection endpoints (/session, /verdict, /scoreboard) and
# hide the API docs. Anything reaching /session can expose raw signals incl. client IPs, so set a token.
KITSUNE_ADMIN_TOKEN=$(head -c 24 /dev/urandom | base64)
EOF
# .env holds secrets — it's gitignored; never commit it.

# 3. Open the firewall (ufw example).
ufw allow 22/tcp && ufw allow 80/tcp && ufw allow 443/tcp && ufw allow 443/udp && ufw enable

# 4. Issue the initial Let's Encrypt cert (standalone on :80; one-shot, before bringing the stack up).
#    --entrypoint certbot is required: the prod overlay sets the certbot service's entrypoint to /bin/sh
#    for the renewal loop, so the one-shot issuance must point it back at the certbot binary.
docker compose -f docker-compose.yml -f docker-compose.prod.yml run --rm --service-ports \
  --entrypoint certbot certbot \
  certonly --standalone -d "$(grep KITSUNE_DOMAIN .env | cut -d= -f2)" \
  -m "$(grep KITSUNE_ACME_EMAIL .env | cut -d= -f2)" --agree-tos --no-eff-email
```

## Bring it up

```sh
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

The edge loads the real cert (`KITSUNE_TLS_CERT`/`KITSUNE_TLS_KEY` → `loadCert`), terminates TLS+H2 on 443,
advertises h3 (QUIC) via Alt-Svc on 443/udp, sniffs client SYNs for TCP/IP-OS, and reverse-proxies to the
detector, which serves the demo page and scores `/ingest`. A real browser visiting `https://your.domain`
is fingerprinted across every wire layer + JS and gets the live verdict.

## Verify

```sh
curl -sv https://your.domain/healthz 2>&1 | grep -E "SSL|HTTP/|subject"   # real cert, h2
docker compose -f docker-compose.yml -f docker-compose.prod.yml logs edge | grep "loaded keypair"
# from a real browser, load https://your.domain  -> verdict renders; QUIC after the first visit (Alt-Svc)
```

## GeoLite2 (optional — geo/ASN on the wire panel)

The wire panel shows each visitor their own IP. To also resolve **city / country / ASN**, drop MaxMind's
free **GeoLite2** databases into a `geoip/` dir next to the compose files (the prod overlay mounts it at
`/geoip` read-only and sets `KITSUNE_GEOIP_DIR=/geoip`). Without them the panel just omits geo — it's
purely additive.

```sh
# Requires a free MaxMind account + licence key (https://www.maxmind.com/en/geolite2/signup).
mkdir -p geoip && cd geoip
# Download GeoLite2-City and GeoLite2-ASN (the .mmdb files) with your licence key, e.g.:
#   curl -sL "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=YOUR_KEY&suffix=tar.gz" | tar xz --strip-components=1 --wildcards '*GeoLite2-City.mmdb'
#   curl -sL "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN&license_key=YOUR_KEY&suffix=tar.gz"  | tar xz --strip-components=1 --wildcards '*GeoLite2-ASN.mmdb'
cd .. && docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d detector   # picks up the DBs
```

- **Licence/attribution:** GeoLite2 is free but its licence **requires attribution** — the page footer
  already credits "GeoLite2 data created by MaxMind". The `.mmdb` files are **not committed** (size +
  licence); keep them in `geoip/` (gitignored) and refresh monthly (MaxMind updates them; stale data is
  the only failure mode, and it degrades to a slightly-wrong city, never a crash).

## IP-reputation lists (optional — fuller datacenter / proxy / VPN / Tor coverage)

The detector ships a thin committed **seed** of datacenter/proxy CIDRs baked into the image. To land the
**full** lists on the server, generate them with the refresher into an `iprep/` dir next to the compose
files (the prod overlay mounts it at `/iprep` read-only and sets `KITSUNE_IPREP_DIR=/iprep`). Absent or
empty, the detector falls back to the in-image seed per file — purely additive, never a crash.

```sh
# Generate the lists (Tor + AWS/GCP/Oracle/DigitalOcean/Cloudflare/Fastly + X4BNet, ~60k+ CIDRs). Run it
# inside a detector container so you don't need a local Python toolchain. The image runs through `uv run`
# (the package lives in a uv venv — bare `python` won't find it), and `--build` ensures the image carries
# the KITSUNE_IPREP_DIR support. IMPORTANT: write to a SEPARATE read-WRITE target (/out) — the detector
# service mounts ./iprep at /iprep READ-ONLY, so the refresher cannot write there directly. Both /out and
# the detector's /iprep point at the same host ./iprep dir.
mkdir -p iprep
docker compose -f docker-compose.yml -f docker-compose.prod.yml run --rm --build \
  -v "$PWD/iprep:/out" -e KITSUNE_IPREP_DIR=/out \
  detector uv run python -m kitsune_detector.ip_reputation_refresh
#   -> wrote /out/proxy_exit_cidrs.txt (…)   /out/datacenter_cidrs.txt (…)   (= host ./iprep/…)
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d detector   # reads ./iprep at /iprep:ro
```

- **Refresh monthly** (the lists drift): a cron that re-runs the generate step + restarts the detector.

  ```sh
  # /etc/cron.monthly/kitsune-iprep
  cd /path/to/kitsune && docker compose -f docker-compose.yml -f docker-compose.prod.yml run --rm \
    -v "$PWD/iprep:/out" -e KITSUNE_IPREP_DIR=/out \
    detector uv run python -m kitsune_detector.ip_reputation_refresh \
    && docker compose -f docker-compose.yml -f docker-compose.prod.yml restart detector
  ```

- **Data hygiene:** `iprep/` is gitignored — only de-identified CIDR aggregates land on disk, never raw
  traffic. The refresher enforces per-source floors, so a drifted/empty upstream fails loud rather than
  silently shrinking coverage.
- **GreyNoise actor enrichment (future, needs an API key):** richer per-IP `classification`/`actor` intel
  (radar X8) would wire into the same refresh step; not yet implemented (gated on a key + egress).

## Renewal

The `certbot` service renews every 12h. The edge loads the cert at **startup**, so after a renewal restart it
to pick up the new cert (a monthly cron is plenty):

```sh
# /etc/cron.monthly/kitsune-cert  (or a systemd timer)
cd /path/to/kitsune && docker compose -f docker-compose.yml -f docker-compose.prod.yml restart edge
```

(Zero-touch alternative for later: Go `autocert` in the edge — auto-renew + hot-reload, no restart — at the
cost of integrating the ACME TLS-ALPN challenge into the edge's custom TLS listener.)

## Continuous deployment (pull-based: GHCR + Watchtower)

Release-gated, no inbound CI→VPS access. On each **release** (release-please publishes it when its release
PR merges), `.github/workflows/build-push.yml` builds the `detector` + `edge` images and pushes them to
`ghcr.io/datascry/kitsune-{detector,edge}`. On the VPS, a **Watchtower** container polls GHCR and pulls +
restarts the new images in place — the whole CD loop is `release → build-push → Watchtower pull`.

One-time, on the VPS, switch to the pull-based stack (adds the deploy overlay):

```sh
C="docker compose -f docker-compose.yml -f docker-compose.prod.yml -f docker-compose.deploy.yml"
$C pull        # fetch the GHCR images (so up uses them instead of building)
$C up -d       # detector/edge now run the GHCR images; watchtower auto-updates them on every release
```

- **Image visibility:** make the two GHCR packages **public** (simplest — no pull auth), or keep them private
  and `docker login ghcr.io` on the VPS with a `read:packages` token.
- **State survives updates:** the `detector-data` (SQLite) and `letsencrypt` volumes persist, so a Watchtower
  restart loses nothing — and the edge restart also picks up a freshly renewed cert.
- **Scope:** Watchtower is label-scoped to `detector` + `edge` only (it won't touch certbot or itself).
- **Security note:** Watchtower mounts the Docker socket (root-equivalent) — acceptable on a single research
  box; on a hardened host use a socket-proxy or the SSH-deploy model instead.
- **Auto-update cadence:** every 5 min (`WATCHTOWER_POLL_INTERVAL`); deployments are gated to releases because
  only a release builds+pushes a new image tag.

## What it unlocks (Tier-3 grounding)

Once real traffic flows, run the grounding sweep over the captured sessions (see [grounding.md](grounding.md)):

```sh
docker compose ... exec detector sh -c 'ls /data'           # the persisted store
task grounding -- <exported captures> --expect legit         # FP gate on real users
task grounding -- <exported captures> --build-prior ...       # real-traffic prevalence prior
```

This is where the edge-only rules finally evaluate on real data: the QUIC `net.quic_*` /
`net.quic_unstable_within_session` rules go live (real Chrome QUIC over the trusted cert), IP-reputation
populates from real egress, and the prevalence prior becomes real-traffic-grounded.

## Security & data

- The edge runs as root for `CAP_NET_RAW` (a research-demo trade-off; tighten to non-root + `setcap` later).
- The detector port is never published — only 443 (tcp+udp) and 80 face the internet.
- **Set `KITSUNE_ADMIN_TOKEN`.** With it set, the inspection endpoints (`/session`, `/verdict`,
  `/scoreboard`) require an `Authorization: Bearer <token>` header and `/docs` + `/openapi.json` are
  hidden — so the public surface is just `/` (demo page) + `/ingest` + `/healthz`. Without it they are
  open (`/session` can return raw signals incl. client IPs), so don't run a public host without one.
- **Operator raw data stays on the host.** Only de-identified aggregates (a rebuilt prior, IP-rep counts,
  verdict reports) are safe to commit/share — never raw captures (see the standing data rule).
- This is the **blue (detector) side** — a legitimate public bot-detection demo. Evaders still target only
  this host + the `harness/allowlist.py` endpoints; never a third-party production site.
