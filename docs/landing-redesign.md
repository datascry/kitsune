# Landing-page redesign — kitsune.id as the project's front door

> **Status: spec / awaiting build.** This is the agreed design for turning the detector-served page at
> [kitsune.id](https://kitsune.id/) from a bare demo into the **project's main landing page and a
> general-purpose fingerprint / antidetect tester** — a BrowserLeaks/CreepJS-class destination, with
> Kitsune's cross-layer incoherence thesis as the hook. Supersedes the served page shipped in the
> "forensic-inspector aesthetic" uplevel; complements [`deploy.md`](deploy.md).

## 1. Goals & positioning

- **Antidetect-first.** Lead copy, H1, and keywords target the antidetect/anti-bot audience ("is my
  stealth browser detectable", Camoufox / undetected-chromedriver / nodriver / multilogin users), with
  fingerprint-test and bot/headless-detection as the broader nets.
- **Genuinely useful standalone tool.** A visitor with no idea what Kitsune is should get real value:
  their fingerprint, their wire (TLS/JA4/TCP) layer, their connection, a verdict, and a clear
  explanation — without reading docs.
- **The thesis is the differentiator.** Other testers show signals; Kitsune shows **incoherence across
  layers**. Every section should reinforce: browser claims vs. feature-prediction vs. wire-inferred OS.
- **SEO is a first-class requirement.** This is the front door; it must rank.

### Non-goals (v1)
- Uniqueness / "1 in N" entropy — **deferred to Tier-3** (the prevalence prior is single-source; an
  honest population entropy needs real traffic).
- Accounts, history, saved scans.
- A separate marketing site / blog CMS (doc pages cover fresh-content needs).

## 2. Information architecture

| Route | Content | Source | Priority |
|---|---|---|---|
| `/` | Landing + **live fingerprint/antidetect test** | the inspector (this spec §4) | core |
| `/matrix` | Evader × detection results ("which antidetect tools get caught") | `docs/matrix.md` | v1 |
| `/evasions` | Evasion-technique catalog | `docs/evasion-catalog.md` | v1 |
| `/detections` | Every detection rule + the signal it exploits | `docs/detection-catalog.md` | v1 |
| `/how-it-works` | The cross-layer incoherence thesis, the layers | `docs/architecture.md` | v1 |
| `/research` | Findings / landscape | `docs/findings.md` (+ `landscape.md`) | v1 |
| `/robots.txt`, `/sitemap.xml`, `/og.png`, favicon set | SEO/crawl infra | generated | v1 |

**Kept internal (NOT published):** `red-team-roadmap.md`, `research-radar.md` (planning/queue).

A persistent top **nav** (Test · Matrix · Evasions · Detections · How it works · Research · GitHub)
appears on every page; the forensic CSS shell is shared across all routes.

## 3. Backend: new / changed endpoints (detector)

The detector serves the HTML and the JSON API behind the edge. New surface:

- **`GET /inspect/{session_id}`** — the **cookie-scoped** wire+verdict view the live page reads. Returns a
  de-identified-to-others-but-full-to-owner view: only succeeds when the request's `ks_sid` cookie matches
  `{session_id}` (you can only inspect your own session). Body: the edge wire fingerprints (JA3, JA4,
  TCP + `tcp_kernel` OS guess, QUIC observations, HTTP/2), the client **IP + GeoLite2 geo/ASN** (§5), the
  per-layer contradictions, and the composite fingerprint IDs (§6). `/session/{id}` stays **admin-gated**
  (it returns *raw* signals for any session); `/inspect` is the public, owner-scoped projection.
- **`GET /robots.txt`**, **`GET /sitemap.xml`** — crawl infra (list the public routes; allow all).
- **`GET /og.png`** (+ favicon set, `site.webmanifest`) — static brand assets (§9).
- **Doc routes** (`/matrix`, `/evasions`, `/detections`, `/how-it-works`, `/research`) — runtime
  markdown→themed HTML (§8).

Public surface after this: `/`, `/ingest`, `/inspect/{own}`, `/healthz`, the doc routes, crawl/brand
assets. Admin-gated (`KITSUNE_ADMIN_TOKEN`): `/session`, `/verdict`, `/scoreboard`, `/docs`.

## 4. The landing + live test page (`/`)

Server-rendered shell with real crawlable copy; the live results **hydrate into** the shell after JS.

Top → bottom:

1. **Hero** — H1 (antidetect-first), one-paragraph value prop (crawlable), the **composite Fingerprint
   ID** + the **verdict stamp** (label · bot-likelihood · incoherence). The fingerprint.com "here's your
   ID and are-you-a-bot" moment, above the fold.
2. **Cross-layer coherence banner** (the thesis) — *claimed UA* vs *feature-predicted browser* vs
   *wire-inferred OS (TCP/JA4)* → match / **mismatch**, colour-coded.
3. **Per-layer score bars** — Network · Browser · Behavioral · Reputation (anchor-linked to §detections).
4. **Network / wire layer** — JA3, JA4, TCP/IP-OS, QUIC ("captured on your next visit" until the 2nd hit
   via Alt-Svc), HTTP/2, **your IP + geo/ASN + reputation class**, each with a correlation note
   ("JA4 → Chrome ✓ matches UA" / "✗ JA4 says Firefox"). Fed by `/inspect`.
5. **Browser fingerprint surfaces** — BrowserLeaks-style grid: canvas / WebGL / audio / fonts / screen /
   … → value + per-surface hash + tamper status.
6. **Predicted browser** — UA-independent feature prediction.
7. **Detections, broken out by layer** (§7).
8. **Behavioral biometrics** — **text box only** (the 1–4 dot buttons are removed); live mouse/keystroke
   readout + re-score.
9. **Copy / share result.**
10. **FAQ** (crawlable, also `FAQPage` JSON-LD) — "What is a browser fingerprint?", "Can antidetect
    browsers beat fingerprinting?", "What is JA4/TLS fingerprinting?", "Is my browser detectable as a
    bot?", etc. Doubles as user help + SEO.

### Reuse note
The livepage (`collector/src/livepage/render.ts`/`predict.ts`) already produces §2/§5(browser)/§6 client
side. We **port that render/predict logic inline into `demo.py`** (the served page can't import the
collector across the contract boundary — same established pattern as the inlined CSS). The new work is the
wire layer (§4 net) + composite IDs (§6) + the layer-grouped detections (§7) + the SEO shell.

## 5. Wire layer + GeoLite2

- The edge already forwards `ja3`, `ja4`, `tcp`, `tcp_kernel`, `quic_observed`, `quic_no_grease`,
  `quic_no_pq_keyshare`, and HTTP/2 — correlated by `ks_sid`. `/inspect` projects these.
- **GeoLite2** (MaxMind, free, **attribution required**): bundle the City + ASN DBs so `/inspect` returns
  city/country + ASN/org for the client IP. Adds a ~60–70 MB dataset + a refresh path (monthly). License
  attribution shown in the footer / `/inspect` payload. The DB is **not committed** (size + license) —
  fetched at image build or mounted as a volume; documented in `deploy.md`.
- **Privacy**: the IP/geo is shown **only to the owner** of the session (cookie-scoped). Raw captures
  still never leave the host; only de-identified aggregates are shared (standing data rule).

## 6. Fingerprint IDs

Two IDs, to both match other testers and show the cross-layer story:

- **Browser FP hash** — stable hash over the client surfaces (canvas/WebGL/audio/fonts/screen/etc.),
  comparable to fingerprint.com's visitorID / CreepJS. Computed client-side (extends the existing
  per-surface FNV-1a hashing).
- **Full-stack ID** — browser FP ⊕ wire FP (JA4 + TCP-OS), computed server-side in `/inspect`. The
  Kitsune-unique identifier that folds in the layers a pure-JS tester can't see.

Show both, with honest stability caveats (canvas varies by GPU/driver; wire FP is stable per client
stack).

## 7. Detections layout (live page)

Mirror the thesis, not a flat table:

- **Group by signal layer**: Network · Browser · Behavioral · Reputation (aligned with the §3 score bars;
  bars anchor-link to their group).
- **Within a layer, fired first, split by role**: convicting (coherence / automation / artifact — these
  make a `bot`) visually distinct from corroborating (environment / behavioral / reputation / prevalence).
- **Unfired = collapsible "N checks passed"** per layer (the breadth flex; collapsed by default).
- **"Adjusted for your browser"** bucket retained — rules that fired but are expected for the real
  browser/form-factor and excluded from the verdict (honesty signal; already in the livepage render).
- The **Network group renders directly under the wire values** (§4) so `net.*` contradictions sit beside
  the JA3/JA4/TCP that produced them.

## 8. Doc pages — rendering

Runtime **markdown → themed HTML** in the detector: each doc route reads its `.md`, converts to HTML,
wraps it in the shared shell (forensic CSS, nav, footer) with **per-page SEO meta + JSON-LD**, and serves.

- Adds a markdown dependency to the detector (e.g. `markdown-it-py`/`markdown`); render is cached.
- **The published docs must be copied into the detector image** (the Dockerfile context/COPY must include
  the `docs/` subset) — current images don't ship docs.
- `/matrix` and `/detections` stay fresh because `task catalog` / the scoreboard regenerate their `.md` on
  every release; a later v2 can render them straight from `registry.yaml` + the live scoreboard for
  real-time data.

## 9. SEO + brand assets

- **Head/meta**: keyword-honest `<title>` + meta description per page, canonical link, `theme-color`,
  viewport (present).
- **Open Graph + Twitter card**: title/description/image(`/og.png`)/url/type — per page.
- **Structured data (JSON-LD)**: `WebApplication`/`SoftwareApplication` site-wide + `FAQPage` on `/`.
- **Crawlable content**: real `<h1>`/`<h2>`, intro + per-layer explanatory copy + FAQ all in the
  server-rendered HTML *before* JS; results hydrate in.
- **`/robots.txt` + `/sitemap.xml`**.
- **Performance**: inline CSS retained; **`defer`** the big collector script so content paints first.
- **Favicon + brand**: derive from the fox-fire vermilion mark → `favicon.svg`, `favicon.ico`,
  `apple-touch-icon.png`, `site.webmanifest`, `/og.png`.
- **CSP-safe**: the page keeps `img-src 'none'` (it powers the `csp_bypassed` probe), so **all page
  graphics are CSS/SVG — no body `<img>`**. Favicon/OG are `<link>`/`<meta>` only (scrapers fetch them;
  the page never image-loads them), so they don't trip the probe.

## 10. Constraints & risks

- **Component boundary**: detector can't import the collector; the rich render/predict logic is **ported
  inline** into `demo.py` (duplicates `livepage/` — accepted, like the CSS; the livepage stays the local
  self-test). Worth a future shared-bundle build only if drift becomes painful.
- **CSP probe preservation**: any graphic added as a body `<img>` would silently break `br.csp_bypassed` —
  enforce CSS/SVG-only in review.
- **Docs-in-image**: doc routes 404 if the image doesn't ship `docs/`; the build must COPY them.
- **GeoLite2**: license attribution mandatory; DB not committed; needs a refresh path.
- **QUIC second-visit**: the wire panel must degrade gracefully ("captured on your next visit").
- **Page weight**: the inline collector is large; `defer` + keep CSS inline; watch Lighthouse.

## 11. Phased build order (one PR per phase, CI-green, datascry-authored)

1. **SEO shell + brand + nav** — server-rendered crawlable shell, meta/OG/JSON-LD/FAQ, favicon set,
   `robots.txt`/`sitemap.xml`, `/og.png`, shared nav/footer. (No new data; immediate SEO win.)
2. **Live page render port** — port predict/coherence/surfaces/browser-FP-hash from `livepage/` into the
   served page; layer-grouped detections (§7); drop the dot buttons.
3. **Wire layer + `/inspect` + full-stack ID** — cookie-scoped `/inspect`, render §4, the full-stack ID.
4. **GeoLite2** — bundle + wire geo/ASN into `/inspect`; `deploy.md` + attribution.
5. **Doc pages** — markdown→themed routes for `/matrix`, `/evasions`, `/detections`, `/how-it-works`,
   `/research`; ship `docs/` in the image.

Each phase is independently shippable and redeploys via the existing path (`up -d --build detector`).
