# hosted-demo plan — running the full ruleset live against a visitor

> **Archived (2026-06-26) — delivered/historical.** The hosted-demo plan was realized; kept for the Tier-3 opt-in-capture rationale. The live deploy runbook is now [`../deploy.md`](../deploy.md).

> **Status: implemented and live at [kitsune.id](https://kitsune.id/).** This plan is now realized — the
> full edge + detector stack is hosted publicly (runbook: [`deploy.md`](../deploy.md)). The standalone
> **GitHub Pages live page has been retired**: the detector now serves the authoritative full demo page
> itself (`detector/.../demo.py`), which posts to the real `/ingest` and returns the cross-layer verdict
> correlated with the edge's wire fingerprints. The client-side-only `collector/src/livepage/` bundle is
> kept as a local self-test tool (see [`../collector/README.md`](../../collector/README.md)). The historical
> plan below is preserved for context.

The (now-retired) GitHub Pages live page evaluated the **client-evaluable**
browser/behavioral subset of the ruleset against the visitor's own browser, entirely client-side
(currently ~86 of the 113 non-retired rules at v0.70.0 — the split is computed at render time from the
`clientEvaluable` flag, not hardcoded). The remaining **edge-only rules** (~27) a browser cannot resolve:
it cannot observe its own TLS/JA3/JA4, HTTP/2 (Akamai) fingerprint, QUIC/HTTP-3 ClientHello, TCP/IP
(p0f) kernel, or its IP reputation — those are read from the *raw connection* by Kitsune's Go edge. To
run the **full** verdict (incl. the cross-layer incoherence that is Kitsune's thesis) against a real
visitor, the edge + detector must be **hosted publicly**. This is a deployment, not a static page. This
doc is the plan; it is not yet greenlit.

**Why this matters beyond a demo — it is the Tier-3 calibration path.** Kitsune's precision gate is
trusted-but-verified calibration (`docs/prevalence-model.md`, `harness/README.md`): currently **Tier-1**
(browserforge generated fingerprints, a single source) corroborated by **Tier-2** (real headless
Chromium/Firefox/WebKit captures). The open gap is **Tier-3 — real *desktop* traffic** from real devices,
which is what gates promotion of the experimental environment-tell and biomech rules (e.g.
`bh.power_law_violation`) toward convicting weight. A hosted demo with an explicit opt-in capture is the
project's stated route to that Tier-3 corpus — so this plan is also the calibration-data plan, not just a
showcase.

## Why Pages can't do it

GitHub Pages serves static files only. The network-layer signals require a server that:

1. terminates (or transparently inspects) the **raw TLS ClientHello** to compute JA3/JA4 — standard
   reverse proxies and CDNs strip this before your app sees it;
2. reads the **HTTP/2 SETTINGS/WINDOW_UPDATE/PRIORITY** frame order (the Akamai fingerprint) and the
   **TCP SYN** options (p0f) off the wire;
3. advertises **HTTP/3** (`Alt-Svc`) and captures the **QUIC Initial** to fingerprint the QUIC hello;
4. attributes all of the above to the same session as the in-browser collector POST, then runs the
   coherence engine to score cross-layer contradictions.

The edge already does 1–4 (see [`edge/`](../edge) and [`architecture.md`](../architecture.md)); the work is
hosting it reachably and safely.

## Architecture (reuse, don't rebuild)

```
visitor ──TLS/H2/QUIC──▶  edge (Go)  ──signals──▶ detector (Python) ──verdict──┐
        ◀── demo page ───  serves /  + mints ks_sid                            │
        ──browser/behavioral signals (collector) ──▶ /ingest ─────────────────┘
                                          page polls /session/<id> → renders full verdict
```

- **edge**: public host, real cert, ports 443 (TCP/H1/H2) + 443/udp (QUIC/H3). Mints `ks_sid`, forwards
  network signals to the detector. Serves the demo page (or the Pages page calls it cross-origin).
- **detector**: private (only the edge reaches it); holds the coherence engine + session store.
- **page**: the *same* `livepage/` bundle, with one change — when an edge base URL is configured, POST the
  collected signals to `/ingest` and poll `/session/<id>` for the joined network+browser verdict, instead
  of evaluating only the client subset. The client-only path stays as the no-edge fallback.

## Host options

| Option | JA3/H2/QUIC capture | Effort | ~Cost | Notes |
|---|---|---|---|---|
| **Single small VM** (Fly.io / Hetzner / DO), edge with raw-socket access | ✅ full | medium | ~$5–10/mo | Recommended. The edge needs the unproxied socket; a VM gives it. QUIC needs 443/udp open. |
| Cloud Run / Fly Machines (container) | ⚠️ H2 yes; JA3/QUIC depends on the LB passthrough | medium | usage-based | Many managed LBs terminate TLS → JA3 lost. Verify raw-ClientHello passthrough before committing. |
| Behind Cloudflare/CDN | ❌ JA3/TCP stripped | low | low | Defeats the purpose — the CDN does the fingerprinting, not us. |

**Recommendation:** a single small VM running `docker-compose` (edge + detector), DNS A/AAAA →
`demo.<domain>`, a real cert (the edge already supports one; Let's Encrypt via a sidecar or baked-in).
This is the only option that reliably preserves JA3/JA4 + QUIC + TCP.

## Work breakdown

1. **Edge: public TLS + cert** — wire a real certificate (Let's Encrypt) into the edge listener; today it
   self-signs. Confirm `Alt-Svc` + QUIC listener bind on the public UDP port.
2. **Page: edge mode** — add an optional `KITSUNE_EDGE_BASE`; when set, the bundle POSTs signals to
   `/ingest` and polls `/session/<id>`, then renders the full verdict (network + reputation bars populate;
   cross-layer incoherence becomes meaningful). Keep client-only as the default/fallback.
3. **CORS / origin** — either serve the page *from the edge* (same-origin, simplest, `ks_sid` cookie just
   works) or allow the Pages origin to call the edge with credentials. Same-origin is strongly preferred.
4. **Deploy** — `docker-compose` on the VM (edge public, detector private); the `live_scoreboard.sh` stack
   is already most of this. Add a healthcheck + restart policy + log rotation.
5. **Abuse / cost guards** — the `/ingest` endpoint is public: rate-limit per IP, cap session store size
   + TTL, drop oversized payloads. The edge already validates contracts; add a request cap.
6. **Tier-3 opt-in capture** — the calibration payoff. Behind an explicit, off-by-default consent toggle,
   persist the *real-device* fingerprint + behavioral signals (not raw IPs) into the calibration corpus
   format `browserforge_corpus.py --from-dir` already consumes (it loads "real-captured fingerprint JSONs"
   as Tier-2/Tier-3 profiles). This turns demo traffic into the real-desktop second source that gates
   promoting the experimental environment-tell and biomech rules. Consent + retention must be explicit
   (see below); a visitor who only wants the verdict is never captured.

## Security & ethics

- **Ethics gate is unchanged.** This hosts *Kitsune's own* detector for visitors to test *their own*
  browser. It does not target any third party — consistent with the allow-list rule in `CLAUDE.md` and
  `harness/.../allowlist.py`. Evaders still may only point at this endpoint or the approved test sites.
- **Privacy:** the hosted path means the visitor's signals (incl. a WebRTC-leaked public IP and a
  fingerprint hash) reach our server. The client-only Pages page keeps everything local. The hosted demo
  must carry a clear notice and retain nothing beyond the session TTL. Don't log raw IPs longer than needed.
  The **Tier-3 opt-in capture** (work item 6) is a separate, stricter consent than running the verdict:
  it is off by default, stores only the de-identified fingerprint/behavioral profile (never raw IPs), and
  has its own stated retention. Capturing calibration data without that explicit opt-in is out of bounds.
- **Exposure:** a public edge with raw-socket parsing is attack surface. The fuzz smokes (CI) cover the
  parsers; keep them green. Run the detector private.

## Decision needed before building

- Domain + host (which provider, who owns the VM/billing)?
- Same-origin (serve page from edge) vs Pages-origin + CORS? (recommend same-origin)
- Acceptable data-retention window for the hosted `/ingest`?
- Tier-3 capture: ship the opt-in calibration store with the first deploy, or run the demo verdict-only
  first and add capture once consent/retention copy is settled?

Until those are settled, the **client-only Pages page stands on its own** — it already matches the public
JS-only detection field (CreepJS/sannysoft) and is honest about what needs the edge.
