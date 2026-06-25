# Kitsune — Catalog of Relevant Projects, Libraries & Sites

> **Purpose.** A curated, opinionated map of the prior art across both sides of the bot-vs-human
> arms race, organized by Kitsune component, with Milestone-0 stack recommendations. This is a
> research artifact to be read *before* building — it is not a dependency list.
>
> **Method.** Compiled 2026-06-17 from a 10-way parallel web sweep (GitHub, PyPI/npm/pkg.go.dev,
> arXiv/USENIX/ACM, vendor blogs, awesome-lists). Several projects surfaced independently in
> multiple sweeps — noted where relevant as a confidence signal.
>
> **Caveats.** Star counts are approximate (verify before quoting publicly). **Licenses must be
> re-verified before vendoring** — see the [License watch-list](#license-watch-list); several
> red-side tools are GPL/AGPL and must stay isolated from non-copyleft detector code.
>
> **Legend.** ⭐ = my top pick for that role · 🟢 **M0** = directly usable in Milestone 0 ·
> 🔬 = study/reference, not a dependency · 📄 = paper/writeup · 🎯 = ethics-approved test endpoint.
>
> **Stable section IDs.** §0–§14 are cited by number from elsewhere (e.g. `SECURITY.md` §14, the
> `collector` / `go-tls` READMEs). Treat the numbering as a stable contract — **do not renumber**;
> append new sections at the end instead.
>
> **Status (retrospective).** This is a pre-build Milestone-0 survey, kept for its prior-art map and
> license watch-list. Its §0 *stack recommendation* (a Node/TS detector) was **not** the path taken:
> Kitsune shipped a **Python detector + Python harness + Go edge + TypeScript collector** (see
> `docs/architecture.md`). Read §0 as the reasoning at the time, not current architecture; the
> project-by-project map in §1–§14 remains the useful, durable part. Star counts/licenses are as-surveyed
> (2026-06) — re-verify before quoting or vendoring.

---

## 0. TL;DR — Milestone-0 stack recommendation

The brief asks me to pick the detector/harness language "by best JA3/JA4 + HTTP/2-fingerprint
lib support, and say why." My recommendation:

### ⭐ Recommended: **Node/TypeScript detector + harness**, JA3/JA4 via `read-tls-client-hello`

| Concern | Pick | Why |
|---|---|---|
| **TLS fingerprint (JA3/JA4)** | [`httptoolkit/read-tls-client-hello`](https://github.com/httptoolkit/read-tls-client-hello) | Zero-dependency; parses the ClientHello off the Node socket *before* the handshake and hands you `.ja3` **and** `.ja4` per request. No proxy, no Go, no raw-packet capture. This is the single lowest-friction path to the M0 DoD ("reads JA3"). |
| **Browser FP + behavioral collection** | Custom TS client, porting checks from CreepJS / BotD / fp-collect | The collection client is JS regardless of backend language; keeping the backend in TS means one language across detector-client, detector-server, *and* the stealth evader (Node/Playwright). |
| **Detector scoring** | Node/TS service | Receives POSTed JS signals + reads TLS FP from the socket; emits the per-layer scoreboard. |
| **Stealth evader** | Node/Playwright (Camoufox via its Playwright API) | Already the seed stack; same language as detector. |

**Rationale for Node over Python at M0:** the heart of the browser layer is JS that runs in the
page, and the three best detector references (CreepJS, BotD, fp-collect/fpscanner) are all
JS/TS you can read and partially port. The stealth evader is also Node. One language for M0 =
less context-switching to hit the DoD fast. Go is deliberately deferred to **M2 (`go-tls`)**, which
is exactly where the brief wants the Go ramp — don't pull it forward.

**Deferred to M1+ (not needed for M0 DoD):**
- **HTTP/2 (Akamai) fingerprint** → add [`wi1dcard/fingerproxy`](https://github.com/wi1dcard/fingerproxy)
  (Go reverse proxy, injects `X-JA3`/`X-JA4`/`X-HTTP2-Fingerprint` headers). This also gives a
  cleaner long-term architecture if you later want a non-Node detector.
- **TCP/IP stack fingerprint** → [`pyp0f`](https://github.com/Nisitay/pyp0f) / [`passivetcp-rs`](https://github.com/biandratti/passivetcp-rs) (needs raw-socket/edge capture — heavier).

### Alternative: **Python detector** (choose this if you prefer Python for the ML/scoring side)
- TLS: [`ja4plus`](https://pypi.org/project/ja4plus/) (most complete pure-Python JA4+, but pcap/live-capture oriented) or front it with `fingerproxy` and just read headers.
- Trade-off: the browser-collection JS is still JS, so you lose the single-language advantage. Pick this only if the behavioral/reputation **scoring** is going to lean on Python ML libs sooner rather than later.

> **My call:** go Node/TS for M0 with `read-tls-client-hello`; introduce `fingerproxy` at M1 when
> you add the HTTP/2 layer; introduce Go at M2 for the `go-tls` evader. This sequences the
> language ramp to match the milestones instead of fighting them.

---

## 1. Network layer — TLS fingerprinting (JA3 / JA3S / JA4+)

| Project | Lang · License · Maint · ~Stars | Notes |
|---|---|---|
| ⭐🟢 **[httptoolkit/read-tls-client-hello](https://github.com/httptoolkit/read-tls-client-hello)** | JS/TS · Apache-2.0 · stale-but-stable · ~56★ | **M0 TLS pick.** Wrap `https.Server` with `trackClientHellos()`, read `socket.tlsClientHello.ja3/.ja4`. Zero deps. Last release 2022 but dependency-free and still works. |
| 🔬 **[FoxIO-LLC/ja4](https://github.com/FoxIO-LLC/ja4)** | Py/Rust/multi · BSD-3 (JA4) + FoxIO-1.1 (JA4S/H/X/T/L/SSH) · active · ~1.5k★ | **Read first — the spec source of truth.** JA4 is the TLS-1.3-robust successor to JA3 (sorts ciphers/extensions, defeating the permutation tricks that beat JA3). JA4H also fingerprints HTTP header order → useful for cross-layer coherence. ⚠️ Non-JA4 methods carry the FoxIO non-monetization license. |
| **[ja4plus (PyPI)](https://pypi.org/project/ja4plus/)** | Python · BSD-3 + FoxIO-1.1 · active · v0.6.0 | Most complete pure-Python JA4+ (all 10 methods, QUIC, pcap/live via Scapy). The Python-backend TLS pick if you go that route. |
| **[wi1dcard/fingerproxy](https://github.com/wi1dcard/fingerproxy)** | Go · Apache-2.0 · active · ~326★ | **M1 pick for HTTP/2.** Reverse proxy computing JA3 + JA4 + Akamai-h2, injected as headers → language-agnostic backend. Production-proven (~40M req/day). Surfaced in 3 separate sweeps. |
| **[dreadl0ck/ja3](https://github.com/dreadl0ck/ja3)** | Go · BSD-3 · active · ~155★ | Best pure-Go JA3+JA3S from pcap/live (~30× faster than the Python ref). JA3-only (no JA4). |
| **[psanford/tlsfingerprint](https://github.com/psanford/tlsfingerprint)** | Go · unknown · unknown | Cleanest Go primitive for *active* server-side JA3+JA4 if any sidecar goes Go. |
| **[gospider007/fp](https://github.com/gospider007/fp)** | Go · unknown · active | Dep-free Go lib extracting JA3/JA4/JA4H + HTTP/2 from connecting clients, with auto-cert mgmt. Good template for a self-hosted Kitsune test endpoint. |
| **[elpy1/tlsfp](https://github.com/elpy1/tlsfp)** | Python · MIT · active · ~38★ | Long-tail: minimal Python active-server JA3/JA4 reference, MIT (safe to lift logic). |
| **[phuslu/nginx-ssl-fingerprint](https://github.com/phuslu/nginx-ssl-fingerprint)** | C (nginx) · BSD-style · active | Edge alternative to fingerproxy if you front with nginx (JA3+JA4+h2 as nginx vars). |
| 🔬 **[salesforce/ja3](https://github.com/salesforce/ja3)** | Py/Zeek · BSD-3 · **archived May 2025** · ~3k★ | Historical JA3/JA3S ground truth. Use only for legacy compat + to *teach* JA3's extension-permutation weakness in /docs. Superseded by JA4. |
| **[jabedude/ja3-rs](https://github.com/jabedude/ja3-rs)** · **[pyja3](https://pypi.org/project/pyja3/)** | Rust / Python · BSD-3 · stale | JA3-only ports; reference only. |

**Verdict:** `read-tls-client-hello` for M0, `FoxIO-LLC/ja4` as the spec, `fingerproxy` when you add
HTTP/2. JA4 (not JA3) should be the detector's primary TLS signal; keep JA3 only as a teaching foil.

---

## 2. Network layer — HTTP/2, TCP/IP & stack fingerprinting

| Project | Lang · License · Maint | Notes |
|---|---|---|
| 📄 **[Akamai "Passive Fingerprinting of HTTP/2 Clients" (Black Hat EU 2017)](https://blackhat.com/docs/eu-17/materials/eu-17-Shuster-Passive-Fingerprinting-Of-HTTP2-Clients-wp.pdf)** | whitepaper | The canonical h2-fingerprint spec (SETTINGS \| WINDOW_UPDATE \| PRIORITY \| pseudo-header order). Required reading for the h2 layer on both sides. |
| 🔬 **[Xetera/nginx-http2-fingerprint](https://github.com/Xetera/nginx-http2-fingerprint)** | C/Lua · unknown · stale | Focused reference impl of the Akamai h2 fingerprint (vs fingerproxy which bundles it). Study the frame-parsing logic. |
| **[Nisitay/pyp0f](https://github.com/Nisitay/pyp0f)** | Python · MIT · stale | Pure-Python p0f v3 — TCP/IP stack OS guess to cross-check vs UA/TLS (Chrome ClientHello + Linux/Go TCP stack = incoherence). Embeds without spawning p0f. |
| **[biandratti/passivetcp-rs](https://github.com/biandratti/passivetcp-rs)** | Rust · MIT/Apache · active | Freshest maintained TCP fingerprinter (p0f-inspired), designed to embed in a service. |
| **[NikolaiT/zardaxt](https://github.com/NikolaiT/zardaxt)** | Python · MIT · stale · ~200★ | Modern passive TCP fingerprint server with an API — more deployable than raw p0f. |

**Verdict:** TCP/IP fingerprinting tooling is aging and needs raw-socket/edge capture a pure app-layer
detector can't easily get — treat as an M1+ "stretch" signal via `passivetcp-rs`. HTTP/2 is easy via
`fingerproxy`. The cross-layer incoherence here (TLS says Chrome, h2/TCP says Go) is exactly Kitsune's thesis.

---

## 3. Network layer — IP / ASN reputation data

| Source | License · Cost | Notes |
|---|---|---|
| ⭐ **[iptoasn.com](https://iptoasn.com/)** | open/free · self-host TSV | Zero-cost, hourly-updated IP→ASN→org. Map client IP → AS-org → datacenter heuristic (AWS/Hetzner/OVH/Vultr). Best fit for a self-contained lab with no paid API. |
| **[MaxMind GeoLite2-ASN + GeoIP2 Anonymous-IP](https://www.maxmind.com/en/geoip-anonymous-ip-database)** | GeoLite2 free / GeoIP2 commercial · MMDB | Free ASN tier for datacenter classification; paid Anonymous-IP adds residential-proxy detection (residential IP + datacenter TLS = suspicious). |
| **[IPinfo Lite / IP-to-ASN](https://ipinfo.io/developers/ip-to-asn-database)** | CC-BY-4.0 Lite / commercial Privacy · MMDB/CSV | Free Lite = full-accuracy country+ASN offline; paid tier flags VPN/proxy/Tor/hosting/Apple-Relay. |
| **[X4BNet/lists_vpn](https://github.com/X4BNet/lists_vpn)** | open · CIDR text · active | No-key VPN/datacenter CIDR lists — trivial CIDR matcher to supplement ASN heuristics. |

**Verdict:** reputation data is the *easiest* layer to cover for free — `iptoasn.com` + `GeoLite2-ASN`
gives offline datacenter classification with no API dependency, preserving the self-contained-arena ethics.

> **As shipped (superseding the M0 recommendation above).** Kitsune dropped the manual MaxMind
> GeoLite2/`iptoasn.com` path for a **keyless** offline pair: City + ASN come from **DB-IP Lite**
> (CC BY 4.0, no licence key), pulled by `detector/.../geo_refresh.py` (the `geo-refresh` compose
> companion) and read by `geo.py` as `dbip-city-lite.mmdb` / `dbip-asn-lite.mmdb`. DB-IP records share
> the GeoLite2 schema, so a manually-mounted `GeoLite2-City.mmdb` / `GeoLite2-ASN.mmdb` pair is still
> read as a filename fallback. This removes the MaxMind account/key step while keeping the lookup offline.

---

## 4. Browser-fingerprint layer — detection & collection

| Project | Lang · License · Maint · ~Stars | Notes |
|---|---|---|
| ⭐🟢🔬 **[abrahamjuliot/creepjs](https://github.com/abrahamjuliot/creepjs)** | JS/TS · MIT (name trademarked) · active · ~1.5k★ | **The single best match to Kitsune's core thesis.** Its "lies" engine detects that an API was *patched/spoofed* (prototype lies, getter overrides, worker-vs-main divergence) and produces a trust score from incoherence — exactly the detector-browser logic to emulate. Read/port the logic; don't reuse the name. |
| ⭐🟢 **[fingerprintjs/BotD](https://github.com/fingerprintjs/BotD)** | TS · MIT · active (stability mode) · ~1.5k★ | MIT, forkable, production checklist of automation tells (webdriver, headless, Electron, Selenium). Doubles as a harness oracle. |
| 🟢🔬 **[antoinevastel/fpscanner + fp-collect](https://github.com/antoinevastel/fpscanner)** | JS · MIT · recently revived · ~700/600★ | The exact **collect-client → server-side-rules** split Kitsune wants, from Castle's Head of Research. Forkable rule set for webdriver/headless/CDP tells. |
| 🔬 **[rebrowser/rebrowser-bot-detector](https://github.com/rebrowser/rebrowser-bot-detector)** | JS · MIT-ish · active | **Most current (2024-25) CDP/automation leak suite** (Runtime.enable leak, source-url, exposeFunction). Live demo at bot-detector.rebrowser.net. Use as detector ground truth + evader scoring. |
| 🔬 **[kaliiiiiiiiii/brotector](https://github.com/kaliiiiiiiiii/brotector)** | JS+Py · MIT · active · ~280★ | Aggressive recent vectors (input-event timing anomalies, injected-script signatures, can crash the driver). Great `test_cases` reference. |
| 🔬 **[fingerprintjs/fingerprintjs](https://github.com/fingerprintjs/fingerprintjs)** | TS · **MIT since v5.0** · active · ~25k★ | Reference for *how* to collect Canvas/WebGL/Audio/font entropy. ⚠️ Deliberately does NO bot detection — pair with BotD. (v4 was BSL; v5+ is MIT again.) |
| **[thumbmarkjs/thumbmarkjs](https://github.com/thumbmarkjs/thumbmarkjs)** | TS · MIT · active · ~1k★ | Leaner, actively-developed FingerprintJS alternative — diff against it to avoid over-fitting collectors to one library. |
| 🔬 **[apify/fingerprint-suite](https://github.com/apify/fingerprint-suite)** | TS · Apache-2.0 · active · ~700★ | **Dual-use:** the gold standard for what a *coherent* fingerprint looks like (Bayesian joint distribution of FP+headers) → train/validate the detector against it AND use it as a stealth source. ⚠️ Don't train the detector solely on the same generator the evader uses (data-leakage trap). |

**Key CDP-tell writeups (read these — the field moved in 2024-25):**
- 📄 **[How V8 Leaks Your Headless Browser's Identity (Sveba)](https://svebaa.github.io/personal/blog/cdp-fingerprinting/)** — the prototype-chain Proxy `ownKeys` trap: a synchronous, no-permission, deterministic `Runtime.enable` detector that survives the V8 change which broke the classic trick.
- 📄 **[Castle: why a classic CDP signal stopped working](https://blog.castle.io/why-a-classic-cdp-bot-detection-signal-suddenly-stopped-working-and-nobody-noticed/)** — the `Error.stack` getter trick silently *died* in 2024-25 V8. **Don't ship it.**
- 📄 **[DataDome: detecting puppeteer-stealth](https://datadome.co/bot-management-protection/detecting-headless-chrome-puppeteer-extra-plugin-stealth/)** — exact residual artifacts the stealth plugin leaves (broken `Function.prototype.toString`, inconsistent `navigator.plugins/permissions`).
- 📄 **[SicuraNext: Sec-Fetch & Client-Hints inconsistencies](https://blog.sicuranext.com/sec-fetch-and-client-hints-a-powerful-tool-against-automation/)** — which header pairs to cross-validate (`Sec-CH-UA-Platform` vs UA OS) for the CH↔UA↔TLS coherence check.

**Verdict:** CreepJS (incoherence/lie-scoring) + BotD (automation checklist) + fpscanner (collect→rules
split) are the three pillars. For CDP, implement the **Proxy `ownKeys` trap**, not the dead `Error.stack` trick.

---

## 5. Behavioral layer — detection, datasets & classifiers

| Project / Dataset | Type · License | Notes |
|---|---|---|
| ⭐🔬 **[chrisgdt/DELBOT-Mouse](https://github.com/chrisgdt/DELBOT-Mouse)** | TF.js + RandomForest · unknown · stale | Closest architectural analog to Kitsune's behavioral detector: in-browser TF.js human-vs-bot mouse classifier. |
| ⭐ **[margitantal68/sapimouse + SapiAgent](https://github.com/margitantal68/sapimouse)** | dataset + CNN/autoencoder · academic | **Dual-use gem:** SapiMouse (120 subjects) trains the detector's CNN; SapiAgent is a generative autoencoder evader that *beats* Bezier. Perfect adversarial pairing. |
| **[balabit/Mouse-Dynamics-Challenge](https://github.com/balabit/Mouse-Dynamics-Challenge)** | dataset · research | Canonical labeled real-human mouse trajectories (10 users) to contrast against generated evader paths. |
| **[BiDAlab/BeCAPTCHA-Mouse](https://github.com/BiDAlab/BeCAPTCHA-Mouse)** | benchmark · research | 15k trajectories with *graded* bot-realism labels → evaluate the detector on a difficulty spectrum. |
| **[CMU Keystroke Dynamics benchmark](https://www.cs.cmu.edu/~keystroke/)** | dataset · free-research | Standard hold-time/flight-time feature set for the keystroke classifier. ⚠️ Fixed-password setup — doesn't model free-text web typing well. |
| 🔬 **[ahlashkari/IMAPBotLyzer](https://github.com/ahlashkari/IMAPBotLyzer)** | Python · unknown | Combined mouse+keystroke feature-extraction + classical-ML classifier blueprint. |

**Verdict:** behavioral is Kitsune's **biggest learning delta and biggest white space** (see §11).
DELBOT-Mouse is the closest reference; SapiMouse/SapiAgent gives you both a detector baseline and a
state-of-the-art evader to beat. **Gaps:** scroll dynamics are under-served (no strong open dataset),
and almost nothing tackles *cross-channel coherence* (mouse persona ↔ typing persona ↔ TLS/UA).

---

## 6. Reputation / PoW / request-graph

| Project | Lang · License · Maint · ~Stars | Notes |
|---|---|---|
| ⭐🔬 **[WeebDataHoarder/go-away](https://github.com/WeebDataHoarder/go-away)** | Go · MIT · active · ~175★ | **The single most Kitsune-shaped existing project.** Already fuses network (JA3N/JA4, ASN/CIDR), browser (non-JS property probes, resource-load-order), and reputation (PoW, cookies) behind a CEL rule engine with PASS/CHALLENGE/DENY tiers. Study and out-design it. |
| ⭐ **[TecharoHQ/anubis](https://github.com/TecharoHQ/anubis)** | Go · MIT · active · ~20k★ | Cleanest embeddable PoW pattern (SHA-256 leading-zeros + signed-JWT cookie). Widely deployed → realistic evasion target. |
| **[tiagozip/cap](https://github.com/tiagozip/cap)** | JS · Apache-2.0 · active · ~5.2k★ | **Bridges reputation AND browser layers:** PoW + server-emitted JS "instrumentation" challenge proving a genuine browser — exactly the cross-layer coherence signal. ~20kB. |
| **[altcha-org/altcha](https://github.com/altcha-org/altcha)** | TS · MIT · active · ~2.5k★ | Memory-hard Argon2id/Scrypt PoW (resists GPU/ASIC brute-force) — matters when a Go/headless evader tries to solve cheaply. Clean HMAC-signed challenge format to copy. |
| **[mCaptcha/mCaptcha](https://github.com/mCaptcha/mCaptcha)** | Rust · AGPL-3.0 · active · ~3k★ | Load-*adaptive* difficulty + single-use expiring nonces (replay-resistant). Models "cost goes up under attack." ⚠️ AGPL. |
| **[crowdsecurity/crowdsec](https://github.com/crowdsecurity/crowdsec)** | Go · MIT · active · ~9k★ | Reference for the request-graph/rate-based + IP-reputation half: scenario detection → ban/captcha decision API. |
| **[umahmood/hashcash](https://github.com/umahmood/hashcash)** | Go · MIT · stale | The trivial PoW primitive — a few lines to mint/verify, so the *harness* can also solve it and measure evader cost. |
| 📄 **[Cloudflare Managed Challenge writeup](https://blog.cloudflare.com/end-cloudflare-captcha/)** | blog | The canonical escalation ladder (silent → non-interactive PoW/proof-of-space → interactive widget) = Kitsune's "escalate on incoherence" thesis in production. |
| 📄 **[Friendly Captcha: PoW design](https://friendlycaptcha.com/insights/proof-of-work-captcha/)** | blog | Two ideas to steal: many-small-puzzles (variance reduction) + PoW layered over a risk score, not alone. |
| 📄 **[Graph-Based Bot Detection for E-Commerce (arXiv 2601.22579)](https://arxiv.org/abs/2601.22579)** · **[Web Robot Detection (arXiv 1711.05098)](https://arxiv.org/pdf/1711.05098)** | papers | Request-graph feature design (incoherent navigation = bot signal). Open request-graph *code* is thin → Kitsune likely builds this layer itself. |

**Verdict:** `go-away` is the closest whole-detector analog to study; `anubis` is the cleanest PoW to
borrow; `cap` is notable for fusing PoW with a browser-coherence probe. Request-graph detection is mostly
academic — a build-it-yourself layer.

---

## 7. Evader — `stealth` (anti-detect browser automation)

| Project | Lang · License · Maint · ~Stars | Notes |
|---|---|---|
| ⭐🟢 **[daijro/camoufox](https://github.com/daijro/camoufox)** | C++/Py · MPL-2.0 · active · ~9.3k★ | **The seed stack & primary stealth evader.** Spoofs at the C++ engine level (below the JS API surface), defeating the toString/getter probes that injection-based tools fail. Pairs with BrowserForge. The reference for the coherence bar the detector must beat. |
| ⭐ **[Kaliiiiiiiiii-Vinyzu/patchright](https://github.com/Kaliiiiiiiiii-Vinyzu/patchright)** | TS/Py · Apache-2.0 · active · ~3.5k★ | Drop-in Playwright that patches CDP leaks (isolated ExecutionContexts → no `Runtime.enable` leak). Shows the red team how to neutralize the exact CDP signal the blue team probes. |
| **[rebrowser/rebrowser-patches](https://github.com/rebrowser/rebrowser-patches)** | JS · unknown · active · ~1.4k★ | Node-side surgical Puppeteer/Playwright patches; toggle-on/off design is a clean A/B model for the harness (leaky vs patched). |
| **[ultrafunkamsterdam/nodriver](https://github.com/ultrafunkamsterdam/nodriver)** | Python · AGPL/SSPL? · active | Successor to undetected-chromedriver; no-webdriver, selective-CDP architecture. ⚠️ Copyleft — verify before shipping. |
| 🔬 **[ultrafunkamsterdam/undetected-chromedriver](https://github.com/ultrafunkamsterdam/undetected-chromedriver)** | Python · GPL-3.0 · **stale ~2yr** · ~12k★ | Ideal **"should-be-caught" control**: patches webdriver/`cdc_` but NOT CDP/behavioral → detector catches the incoherence. |
| 🔬 **[berstend/puppeteer-extra-plugin-stealth](https://github.com/berstend/puppeteer-extra/tree/master/packages/puppeteer-extra-plugin-stealth)** | JS/TS · MIT · stale · ~7k★ repo | Canonical JS-injection evasion list = a **checklist of detector signals**. Each evasion is a detectable property override. |
| **[apify/fingerprint-suite](https://github.com/apify/fingerprint-suite)** · **[daijro/browserforge](https://github.com/daijro/browserforge)** | TS / Python · Apache-2.0 / unknown · active | Coherent FP+header generation (Bayesian network). BrowserForge is the engine Camoufox consumes. **Design lesson:** browserforge *deprecated* its JS injector in favor of Camoufox's C++ spoofing — injection is detectable. |
| **[tinyfish-io/tf-playwright-stealth](https://github.com/tinyfish-io/tf-playwright-stealth)** | Python · MIT-derived · active | Maintained Playwright-Python stealth fork — a "partially coherent" mid-tier evader if you stay Python. |
| 🔬 **[Mullvad Browser](https://mullvad.net/en/browser)** | C++ · MPL-2.0 · active | Opposite philosophy (RFP uniformity vs unique-realistic). **Insight:** a too-uniform/RFP'd fingerprint is *itself* an anomaly the detector can flag. |
| **[ZFC-Digital/puppeteer-real-browser](https://github.com/ZFC-Digital/puppeteer-real-browser)** | JS/TS · unknown · **EOL Feb 2026** | "Real browser + patches + Turnstile clicker" pattern. Maintenance dead — reference only. |
| 📄 **[The WASM Cloak (arXiv 2508.21219)](https://arxiv.org/html/2508.21219v1)** | paper | Academic backing that API/behavioral detection survives obfuscation while signature/feature detectors don't → supports Kitsune's incoherence-over-signatures design. |

**Natural evader difficulty ladder for the harness** (this fell out of the sweep and maps perfectly
to the incoherence thesis):

```
vanilla → puppeteer-extra / tf-playwright-stealth   (JS injection — partially coherent, detectable via probes)
        → patchright / rebrowser-patches             (CDP-clean)
        → Camoufox                                    (engine-level — most coherent)
```

**Verdict:** Camoufox (primary) + patchright (CDP companion) + BrowserForge (coherent FP gen). The
genre's whole trajectory — injection → CDP-patching → engine-level spoofing — *is* Kitsune's thesis in motion.

---

## 8. Evader — `agent` (LLM-driven browser agents — headline experiment)

| Project | Lang · License · Maint · ~Stars | Notes |
|---|---|---|
| ⭐🟢 **[browser-use/browser-use](https://github.com/browser-use/browser-use)** | Python · MIT · active · ~98k★ | **Primary self-hostable, model-agnostic agent** (wire to Claude). Drives via CDP + structured-DOM actions → leaves CDP + behavioral tells (no human input entropy). Its own maintainers now sell a *separate* behavioral layer — confirming the base agent does NOT defeat behavioral detection. The perfect demonstration of Kitsune's thesis. |
| ⭐ **[Anthropic Claude Computer Use (computer-use-demo)](https://github.com/anthropics/anthropic-quickstarts/tree/main/computer-use-demo)** | Python · MIT · active | **The one architecture that could plausibly beat the behavioral layer:** perceives screenshots, emits OS-level mouse/keyboard input (real cursor trajectories/timing) rather than CDP DOM injection. Native fit for the brief's Claude option. |
| **[OpenAI Operator / CUA](https://openai.com/index/computer-using-agent/)** | hosted · proprietary · active | Closed analog to Computer Use (same screenshot→click paradigm). Comparison/benchmark point, not self-hostable. |
| **[Skyvern-AI/skyvern](https://github.com/Skyvern-AI/skyvern)** | Python · AGPL-3.0 · active · ~20k★ | Vision-LLM + Playwright agent. Still executes via CDP → same tells unless paired with stealth. ⚠️ AGPL. |
| **[browserbase/stagehand](https://github.com/browserbase/stagehand)** | TS/Py · MIT · active | Best fit if the agent goes Node/TS. Hybrid NL+deterministic Playwright = reproducible harness runs. CDP-driven (tells present). |
| **[microsoft/playwright-mcp](https://github.com/microsoft/playwright-mcp)** | TS · Apache-2.0 · active | Lowest-friction way to make Claude itself a browser agent via MCP. Accessibility-tree driven → "scripted bot wearing an LLM hat" → excellent **naive-agent contrast** to Computer Use. |
| **[aws/nova-act](https://github.com/aws/nova-act)** | Python · research preview · active | Third major-lab CUA option; integrates Bedrock AgentCore Browser. Rounds out the agent comparison. |
| **[magnitudedev/browser-agent](https://github.com/magnitudedev/browser-agent)** | TS · unknown · active | Vision-first, "precise mouse/keyboard" execution — closer to the Computer-Use end. Worth testing if its input is more human-like than browser-use. |
| **[nottelabs/notte](https://github.com/nottelabs/notte)** · **[steel-dev/steel-browser](https://github.com/steel-dev/steel-browser)** | Py / TS · unknown / Apache-2.0 · active | "Agent + evasion infra" bundles (profiles, CAPTCHA handling). Study which layers they actually cover (usually network/FP, rarely behavioral entropy). Steel's org curates [awesome-web-agents](https://github.com/steel-dev/steel-browser). |
| 📄 **[WebVoyager (arXiv 2401.13919)](https://arxiv.org/abs/2401.13919)** | paper/benchmark | The de-facto agent success-rate benchmark; frames why vision/screenshot agents behave more human-like than DOM scripts. |
| 🔬 **[EmergenceAI/Agent-E](https://github.com/EmergenceAI/Agent-E)** · **[lavague-ai/LaVague](https://github.com/lavague-ai/LaVague)** | Python · MIT / Apache-2.0 · stale | Prior-art agents. LaVague compiles to Selenium → **ideal trivially-detectable baseline.** |

**The key experimental axis** (this is the headline finding): split agents into
**vision/computer-use** (Claude Computer Use, OpenAI CUA, Magnitude, Nova Act — OS-level input, more
human-like) vs **DOM/accessibility-driven** (Playwright-MCP, Stagehand, Skyvern, browser-use vanilla,
LaVague — CDP-driven, trip behavioral+CDP detectors). A paired **naive-vs-stealthy agent** comparison is
the natural design. **Surprise that validates the brief:** essentially *no* agent defeats behavioral
detection on its own — every vendor bolts on a separate stealth/behavioral layer. Behavioral coherence
is the hard, under-solved layer, which is exactly where the durable signal moves to intent/coordination.

---

## 9. Evader — `go-tls` (uTLS & ClientHello forging)

| Project | Lang · License · Maint · ~Stars | Notes |
|---|---|---|
| ⭐ **[refraction-networking/utls](https://github.com/refraction-networking/utls)** | Go · BSD-3 · active · ~5k★ | **The foundational primitive — everything wraps it.** `ClientHelloID` presets + `ClientHelloSpec` + `Fingerprinter` (replay a captured ClientHello byte-for-byte). Its own docs note "parroting is imperfect beyond the ClientHello" = exactly the h2/TCP incoherence the detector hunts. |
| ⭐ **[bogdanfinn/tls-client](https://github.com/bogdanfinn/tls-client)** | Go · BSD-4 · active · ~1.7k★ | Most batteries-included: utls + fhttp → fixes JA3 **and** HTTP/2 frame/header ordering. Ships C-library bindings for Node/Python reuse. Near drop-in for the go-tls module. |
| **[bogdanfinn/fhttp](https://github.com/bogdanfinn/fhttp)** | Go · BSD-4 · active | The h2-coherence layer (pseudo-header order, SETTINGS). Pair with utls to be coherent end-to-end, not just at the ClientHello. |
| **[Noooste/azuretls-client](https://github.com/Noooste/azuretls-client)** | Go · MIT · active | Strong alternative; adds **HTTP/3 (QUIC)** fingerprint support + accepts raw JA3 strings. |
| **[imroc/req](https://github.com/imroc/req)** | Go · MIT · active · ~4k★ | Lowest-friction: `ImpersonateChrome()` one-liners. Doubles as the vanilla baseline client. |
| **[enetx/surf](https://github.com/enetx/surf)** | Go · MIT? · active | Long-tail; tracks current browsers + **OS-platform diversity** → probe the CH↔UA↔TLS coherence check with mismatched OS. |
| **[lexiforest/curl-impersonate](https://github.com/lexiforest/curl-impersonate)** + **[curl_cffi](https://github.com/lexiforest/curl_cffi)** | C / Python · MIT · active · ~17k★ (orig) | **Gold-standard real-stack impersonation** (BoringSSL/NSS → byte-identical, *authentic* JA3/JA4, not a parrot). The toughest adversary + best oracle to test whether the detector can tell a parrot from the genuine browser stack. `curl_cffi` = Python harness driver. ⚠️ Original `lwthiker` fork is stale; use `lexiforest`. |
| **[0x676e67/wreq](https://github.com/0x676e67/wreq)** (formerly rquest) | Rust · Apache/MIT · active | Leading Rust option; controls TLS/h2 extensions directly via BoringSSL (closer to curl-impersonate's authenticity than utls parroting). |
| **[Danny-Dasilva/CycleTLS](https://github.com/Danny-Dasilva/CycleTLS)** | Go+JS/Py · **GPL-3.0** · active · ~1.6k★ | Cross-language bridge (drive a Go uTLS engine from Node/Python). ⚠️ GPL — keep isolated from non-GPL detector code. |

**Two evasion philosophies to test the detector against** (important design point):
1. **Parroting** (utls, tls-client, CycleTLS, req, surf, azuretls) — reconstructs a ClientHello in Go;
   fast/flexible but imperfect beyond the ClientHello.
2. **Real-stack impersonation** (curl-impersonate, curl_cffi, wreq) — byte-identical authentic handshakes;
   the hardest adversary and best oracle.

**Verdict:** `utls` (foundation) + `tls-client` (turnkey, keeps JA3+h2 coherent) for the Go ramp;
`curl-impersonate`/`curl_cffi` as the authenticity oracle. Target **JA4** on the blue side (it sorts
ciphers/extensions, neutralizing the shuffling tricks that beat JA3).

---

## 10. Behavioral evasion — human-input simulation (feeds `stealth` + `agent`)

| Project | Lang · License · Maint · ~Stars | Notes |
|---|---|---|
| ⭐ **[Xetera/ghost-cursor](https://github.com/Xetera/ghost-cursor)** | TS · MIT · active · ~1.5k★ | De-facto JS human-mouse sim (Bezier + Fitts's Law, overshoot/readjust). Slots into Node/Playwright evaders. Its predictable Bezier signature is also a detector training negative. |
| ⭐ **[riflosnake/HumanCursor](https://github.com/riflosnake/HumanCursor)** | Python · MIT · active · ~460★ | Python counterpart (Selenium + OS-level). |
| **[Lax3n/HumanTyping](https://github.com/Lax3n/HumanTyping)** | TS/JS · unknown · active | Most behaviorally-rich typing sim (Markov errors/corrections/fatigue) → defeats keystroke-dynamics. |
| **[sarperavci/human_mouse](https://github.com/sarperavci/human_mouse)** | Python · MIT · active | Bezier + spline smoothing (fewer curvature artifacts than plain Bezier). |
| **[WindMouse algorithm](https://ben.land/post/2021/04/25/windmouse-human-mouse-movement/)** | Py/JS · MIT · active ports | Gravity+wind model — a distinct curve family so the detector isn't overfit to Bezier-only bots. |
| **[patrikoss/pyclick](https://github.com/patrikoss/pyclick)** | Python · GPL-3.0 · stale | The canonical "Bezier bot" baseline academics compare against. ⚠️ GPL. |
| **[humanjs.dev](https://www.humanjs.dev/)** · **[humanization-playwright](https://github.com/saksham-personal/humanization-playwright)** · **[puppeteer-extra-plugin-human-typing](https://socket.dev/npm/package/puppeteer-extra-plugin-human-typing)** | JS/Py · unknown · mixed | Integrated persona-driven mouse+typing+scroll humanization layers. |

**Verdict:** ghost-cursor (JS) / HumanCursor (Python) for mouse, HumanTyping for keystrokes.
**Strategic insight:** nearly all popular evaders emit a *known, learnable* trajectory signature
(Bezier/physics), so a detector trained on Balabit/SapiMouse/BeCAPTCHA flags them — the real arms race
is generative models (SapiAgent) that close the gap.

---

## 11. Test endpoints (🎯 ethics-approved targets)

| Endpoint | Measures | Layer |
|---|---|---|
| 🎯 **[tls.peet.ws (TrackMe)](https://tls.peet.ws/)** — source: [wwhtrbbtt/TrackMe](https://github.com/wwhtrbbtt/TrackMe) | JA3/JA4/JA4R, Akamai-h2, PeetPrint, raw ClientHello — JSON API (`/api/all`) | **network** — the canonical TLS/h2 oracle; trivial to wire into the harness |
| 🎯 **[bot.sannysoft.com](https://bot.sannysoft.com/)** | webdriver, Chrome object, permissions, plugins, WebGL, broken-image | browser — quick smoke test (⚠️ 2019-era, weak; baseline not hard target) |
| 🎯 **[CreepJS demo](https://abrahamjuliot.github.io/creepjs)** | lie-detection, cross-signal incoherence, trust score | browser — the hardest open FP/incoherence target |
| 🎯 **[browserleaks.com](https://browserleaks.com/)** | per-vector: Canvas/WebGL/Audio/fonts/WebRTC-IP/TLS/Client-Hints | browser + network — isolate exactly which signal an evader leaks |
| 🎯 **[bot.incolumitas.com](https://bot.incolumitas.com/)** (Nikolai Tschacher) | classic + fresh Puppeteer/Playwright + behavioral checks | browser + behavioral — more modern/adversarial than sannysoft |
| 🎯 **[deviceandbrowserinfo.com](https://deviceandbrowserinfo.com/)** (Vastel, 2024) | IP/proxy + canvas + headers + `are_you_a_bot` — JSON API | network + browser + reputation, multi-layer with API |
| 🎯 **[browserscan.net](https://www.browserscan.net/)** | 50+ attrs incl. dedicated JA3/JA4 + h2 page + bot-detection + trust score | network + browser (one of few free cross-layer) |
| 🎯 **[pixelscan.net](https://pixelscan.net/)** | FP + proxy/IP consistency, timezone/locale-vs-geo incoherence | network↔browser coherence |
| 🎯 **[fingerprint.com demo/playground](https://demo.fingerprint.com/playground)** | full Pro signal set + bot-detection + bot-firewall (repeat-visitor) | reputation + scoreboard-UX reference |
| 🎯 **[amiunique.org](https://amiunique.org/)** · **[iphey.com](https://iphey.com/)** | per-attribute entropy/rarity (amiunique); trust verdict (iphey) | browser — principled signal weighting / coarse gate |

> **No public endpoint covers BEHAVIORAL or REPUTATION (request-graph) well** — that's a genuine gap
> and a differentiation opportunity for Kitsune's own detector.

---

## 12. Prior art — papers, "both sides" repos & vendor writeups

**The on-thesis academic anchors (cite these in /docs):**
- 📄 ⭐ **[FP-Inconsistent (Vastel et al., arXiv 2406.07647, ACM IMC 2025)](https://arxiv.org/abs/2406.07647)** — **the single most on-thesis paper.** Honey-site study vs 20 commercial "undetectable" bot services: evasive bots become self-inconsistent; spatial (attr-vs-attr) + temporal (attr-over-time) inconsistency rules cut evasion **~45-48%**. A direct blueprint for the coherence checks.
- 📄 **[FP-Scanner / FP-Stalker (Vastel, USENIX Sec 2018 / IEEE S&P 2018)](https://www.usenix.org/system/files/conference/usenixsecurity18/sec18-vastel.pdf)** — the academic lineage of incoherence-based detection + distinguishing natural FP drift from spoofing.

**The closest "both sides" artifact:**
- 🔬 ⭐ **[niespodd/browser-fingerprinting](https://github.com/niespodd/browser-fingerprinting)** — ~4k★ field guide cataloguing commercial anti-bot stacks (DataDome/PerimeterX/Kasada/Akamai) AND the evasion that beats each. The closest pre-existing analog to Kitsune's detector↔evader matrix; heavily inform /docs framing. (⚠️ stale, treat as a map.) Pair with **[scrapfly/Antibot-Detector](https://github.com/scrapfly/Antibot-Detector)** (identifies which vendor a page uses).

**Forward-looking AI-agent framing:**
- 📄 **[browser-use: "Browser agent bot detection is about to change"](https://browser-use.com/posts/bot-detection)** — red-side mirror of the incoherence thesis from the exact stack the agent evader targets.
- 📄 **[Castle: "From detection to trust"](https://blog.castle.io/from-detection-to-trust-the-evolving-challenge-of-ai-bot-authentication/)** — when a local agent inherits a real user's coherent fingerprint, FP alone fails → behavioral + reputation + cross-layer incoherence become the only tells. The forward-looking "trust" framing for /docs.
- 📄 **[DataDome: New Headless Chrome & the CDP Signal](https://datadome.co/threat-research/how-new-headless-chrome-the-cdp-signal-are-impacting-bot-detection/)** — modern headless Chrome now has a near-perfect FP, pushing detection toward CDP-presence + cross-layer incoherence.

---

## 13. Key strategic findings (cross-cutting)

1. **Kitsune's "incoherence across layers" thesis is empirically validated** — FP-Inconsistent (IMC
   2025) proves evasive bots become self-inconsistent and that inconsistency rules cut evasion ~45-48%.
   This is your strongest citation and design north-star.
2. **The white space is real and specific.** Almost nobody ships *detection + evasion together* with a
   *per-layer scoreboard* and an *AI-agent focus*. `go-away` is the closest detector; `niespodd` is the
   closest doc. None combine all three. **That's Kitsune's contribution.**
3. **The field moved in 2024-25 — beware stale tutorials.** The classic `Error.stack` CDP trick is dead
   (V8 change); use the Proxy `ownKeys` trap. FingerprintJS relicensed to MIT at v5. Modern headless
   Chrome has a near-perfect FP, so detection shifted to CDP-presence + incoherence, not single-leak hunting.
4. **No agent beats the behavioral layer alone.** Every agent vendor bolts on a separate stealth layer —
   confirming the brief's premise that the durable signal moves to behavioral coherence / intent / coordination.
5. **TLS forging only fixes the ClientHello.** uTLS parrots don't align h2/TCP/CH by default → the
   cross-layer incoherence (Chrome TLS + Go h2 + Linux TCP + datacenter ASN) is precisely the detector's edge.
6. **Two under-served detector layers = your biggest learning delta:** behavioral (no good open
   scroll dataset; cross-channel coherence untouched) and request-graph reputation (mostly academic).

---

## 14. License watch-list (verify before vendoring)

| Tier | Projects | Action |
|---|---|---|
| **Copyleft (GPL/AGPL/SSPL)** — isolate from detector code | CycleTLS (GPL-3.0), undetected-chromedriver (GPL-3.0), pyclick (GPL-3.0), pow-bot-deterrent (GPL-3.0), mCaptcha (AGPL-3.0), Skyvern (AGPL-3.0), nodriver (AGPL/SSPL?) | Keep in `/evaders` red-side subtrees; never import into detector; or use as external processes only. |
| **FoxIO License 1.1** — non-monetization | JA4S/JA4H/JA4X/JA4T/JA4L/JA4SSH (the non-`JA4` methods) | Fine for a research/portfolio lab; **not** for any commercialized version. Plain JA4 (TLS client) is BSD-3. |
| **Trademark** | CreepJS name | Read/port the logic; **don't rebrand** anything "CreepJS". |
| **Unverified** | rebrowser-patches, browserforge, tf-playwright-stealth, puppeteer-real-browser, several agent repos, gospider007/fp, surf, wreq | Confirm `LICENSE` before adding as a dependency. |
| **Permissive (safe)** | read-tls-client-hello (Apache), BotD (MIT), fpscanner (MIT), Camoufox (MPL-2.0), patchright (Apache), utls (BSD-3), tls-client (BSD-4), anubis (MIT), go-away (MIT), fingerprint-suite (Apache), browser-use (MIT), ghost-cursor (MIT) | OK to depend on; respect attribution. |

---

*Next step per the build plan: confirm the M0 architecture (this catalog's §0 stack pick + the
JS-collection signal list drawn from CreepJS/BotD/fpscanner + the behavioral capture approach + the
scoreboard format), then scaffold Milestone 0 to its DoD.*
