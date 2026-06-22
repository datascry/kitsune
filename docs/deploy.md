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
EOF

# 3. Open the firewall (ufw example).
ufw allow 22/tcp && ufw allow 80/tcp && ufw allow 443/tcp && ufw allow 443/udp && ufw enable

# 4. Issue the initial Let's Encrypt cert (standalone on :80; one-shot, before bringing the stack up).
docker compose -f docker-compose.yml -f docker-compose.prod.yml run --rm --service-ports certbot \
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

## Renewal

The `certbot` service renews every 12h. The edge loads the cert at **startup**, so after a renewal restart it
to pick up the new cert (a monthly cron is plenty):

```sh
# /etc/cron.monthly/kitsune-cert  (or a systemd timer)
cd /path/to/kitsune && docker compose -f docker-compose.yml -f docker-compose.prod.yml restart edge
```

(Zero-touch alternative for later: Go `autocert` in the edge — auto-renew + hot-reload, no restart — at the
cost of integrating the ACME TLS-ALPN challenge into the edge's custom TLS listener.)

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
- **Operator raw data stays on the host.** Only de-identified aggregates (a rebuilt prior, IP-rep counts,
  verdict reports) are safe to commit/share — never raw captures (see the standing data rule).
- This is the **blue (detector) side** — a legitimate public bot-detection demo. Evaders still target only
  this host + the `harness/allowlist.py` endpoints; never a third-party production site.
