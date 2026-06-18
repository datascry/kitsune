# landscape — Kitsune vs. the bot-detection field

A survey of well-known bot-detection projects, test sites, and libraries, and an honest comparison of
Kitsune's current detections (v0.46.0, 93 rules) against what they do. Grounded in current sources
(2025–2026), not just the codebase.

## Who's out there

**Commercial anti-bot (proprietary, ML-scored):**
[Cloudflare Bot Management](https://scrapfly.io/blog/posts/how-to-bypass-anti-bot-protection),
[DataDome](https://scrapfly.io/blog/posts/how-to-bypass-datadome-anti-scraping),
Akamai Bot Manager, HUMAN Security (ex-PerimeterX), [Kasada](https://tendem.ai/blog/how-anti-bot-systems-work-scrape-anyway),
Imperva. Common stack: TLS (JA3/JA4) + HTTP/2 SETTINGS + JS fingerprint + **behavioral ML** + **IP
reputation** → a per-customer ML *trust score*. Differentiators: DataDome's 2025 **intent-based** analysis;
Kasada's client-side **cryptographic proof-of-work** challenge; Cloudflare default-blocking AI scrapers
(Jul 2025).

**Open-source detection / fingerprint test sites (the technique reference):**
[CreepJS](https://github.com/abrahamjuliot/creepjs) (the gold-standard *lie* detector — cross-checks
fingerprint consistency), [bot.sannysoft.com](https://bot.sannysoft.com) (quick Selenium/Puppeteer
artifacts), [BrowserLeaks](https://browserleaks.com) (per-surface leaks: canvas/WebGL/WebRTC/fonts/TLS/CH),
[incolumitas bot test](https://bot.incolumitas.com/) (notable for **passive + behavioral** signals),
FingerprintJS **BotD** (OSS bot library), [niespodd/browser-fingerprinting](https://github.com/niespodd/browser-fingerprinting)
(anti-bot-system analysis + countermeasures), AmIUnique/uniqueness.

## Technique-by-technique comparison

Legend: ✅ covered · 🟢 ahead of most public tools · ⚠️ partial / no data · ❌ gap

| Technique | Field | Kitsune |
|---|---|---|
| TLS JA3 / JA4 | DataDome, Akamai, Cloudflare | ✅ `ja3`, `ja4`, `ja4_browser_hint`, `ja4_os_hint` |
| TLS GREASE coherence | rare | 🟢 `net.tls_grease_vs_ua` |
| TLS post-quantum key share | almost none | 🟢 `net.tls_pq_keyshare_vs_ua` (catches template lag; live-validated vs uTLS) |
| HTTP/2 Akamai fingerprint | DataDome, Akamai | ✅ `h2`, `h2_browser_hint`, `h2_settings_hint` |
| HTTP/2 unknown-engine coherence | rare | 🟢 `net.h2_unknown_vs_ua` |
| HTTP/2 DoS attribution (rapid-reset, CONTINUATION flood) | infra/WAF only | 🟢 `h2_rapid_reset`, `h2_continuation_flood` |
| TCP/IP OS fingerprint (p0f-style) | rare client-side | 🟢 `tcp_kernel`, `net.tcp_os_vs_ua` |
| Client Hints (UA-CH) coherence | some | 🟢 platform/browser/version/mobile/**GREASE-brand** — unusually complete |
| Canvas / WebGL / Audio fingerprint + lie detection | CreepJS, all | ✅ `canvas_lie`, `canvas_noise`, `webgl_*`, `audio_*` |
| WebGPU coherence | emerging | 🟢 `br.webgpu_*` |
| Font enumeration / metrics | CreepJS, browserleaks | ✅ incl. Camoufox-specific artifacts |
| navigator / webdriver / CDP artifacts | sannysoft, all | ✅ `webdriver`, `cdp_runtime_enabled`, `cdc_artifacts`, `csp_bypassed` |
| WebRTC IP leak | browserleaks, HUMAN | ✅ `webrtc_public_ip`, cross-linked to proxy IP |
| Cross-layer **coherence** ("lies") | CreepJS (JS-only) | 🟢 the whole engine — and across TLS↔H2↔TCP↔JS, not just JS |
| **Coordination / fleet** detection | HUMAN (collective); most: none | 🟢 JA4-cluster + JS-divergence paradox + **fp-collision** + proxy topology |
| Mouse / keystroke dynamics | DataDome, Kasada, HUMAN (ML) | ⚠️ thresholds + new **biomechanics** features (power law, sub-movements); no ML yet |
| CDP-injection mechanism tell (coalesced events) | rare | 🟢 `bh.synthetic_no_coalesced` |
| IP reputation / ASN / datacenter / proxy-exit | **all commercial** (backbone) | ⚠️ rules exist (`rep.datacenter_asn`, `rep.known_proxy_exit`) but **no data feed** |
| Scroll / touch / intent sequences | DataDome 2025, Kasada | ❌ collector doesn't capture scroll/intent |
| ML trust-score / per-customer models | all commercial | ❌ Kitsune is rules-as-data (by design — explainable), no ML model |
| Active challenge (CAPTCHA / **proof-of-work**) | reCAPTCHA, hCaptcha, Turnstile, Kasada | ❌ Kitsune is **passive** — no challenge-response |
| QUIC / HTTP-3 fingerprint | emerging (Akamai) | ❌ edge is HTTP/2-only |
| Known-fingerprint DB (match vs known bots) | commercial scale | ❌ no large reference corpus |
| Mobile app / SDK attestation | HUMAN, DataDome SDKs | ❌ web-only |

## Where Kitsune leads

1. **Cross-layer incoherence as the primary signal.** The field scores per-layer signals and feeds an ML
   trust score; Kitsune flags *contradictions across* TLS, HTTP/2, TCP/IP, client-hints, and JS — explicit,
   explainable rules-as-data. CreepJS does this for the JS layer only; Kitsune generalizes it down the stack.
2. **Coordination / fleet detection.** Catching a *cloned-profile* (fp-collision) or *randomizing*
   (JS-divergence paradox) fleet by its shared TLS identity is something most commercial tools — which score
   each session in isolation — do not do explicitly. This is the durable bots/DDoS signal.
3. **Cutting-edge network tells** almost no public tool has: TLS **post-quantum** key-share lag, GREASE
   coherence, HTTP/2 **unknown-engine**, HTTP/2 **DoS attribution**, p0f-style TCP/IP OS coherence.
4. **Explainability.** Every verdict cites the exact rules + evidence; no black-box score.

## Honest gaps (prioritized)

1. **IP reputation / ASN / proxy-exit data** — the commercial backbone. Kitsune has the *rules* but no data
   feed (needs a GeoIP/ASN DB + a datacenter/proxy-exit list). Highest-leverage gap; bounded by data access,
   not research.
2. **Behavioral ML + scroll/intent.** Kitsune just gained real biomechanics *features* (the power law,
   sub-movements — see `docs/behavioral-data.md`); the field uses trained ML over richer signals (scroll,
   click cadence, intent sequences). Next: calibrate the biomech features on real human data, add scroll
   capture.
3. **QUIC / HTTP-3 fingerprinting** — a genuinely new transport layer the edge doesn't speak yet.
4. **Active proof-of-work challenge** — Kitsune is passive by design; a Kasada-style PoW gate is an option
   for the volumetric tier, but a different posture (challenge vs observe).
5. **Scale / known-fingerprint corpus** — commercial tools match against millions of known bot fingerprints;
   Kitsune relies on coherence + coordination instead of a reference DB (a deliberate, but real, trade-off).

**Summary.** Against the *public* detection field, Kitsune matches or exceeds the per-session fingerprint and
TLS/H2 stack, leads on cross-layer coherence + coordination + several cutting-edge network tells, and is
behind the *commercial* field mainly where they have proprietary assets Kitsune lacks by nature: IP-reputation
data, trained behavioral ML, and active challenges. The lab's thesis — incoherence across layers + coordination
— is genuinely differentiated; the gaps are data/infra, not detection ideas.
