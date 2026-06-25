# landscape — Kitsune vs. the bot-detection field

> Broad field survey incl. commercial anti-bot — for the in-browser-page gap analysis see
> [detection-landscape.md](detection-landscape.md).

A survey of well-known bot-detection projects, test sites, and libraries, and an honest comparison of
Kitsune's current detections against what they do. For the live per-rule inventory (counts, status,
versions) see the generated [`docs/detection-catalog.md`](detection-catalog.md) and
[`docs/scoreboard.md`](scoreboard.md); `ruleset_version` lives at the head of
`contracts/rules/registry.yaml`. Grounded in current sources (2025–2026), not just the codebase.

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
| WebGL renderer ↔ GPU-capability coherence | almost none | 🟢 `br.webgl_renderer_caps_mismatch` (renderer string vs `MAX_TEXTURE_SIZE` — catches source-level forks) |
| WebGPU coherence | emerging | 🟢 `br.webgpu_*` |
| Font enumeration / metrics | CreepJS, browserleaks | ✅ incl. Camoufox-specific artifacts |
| navigator / webdriver / CDP artifacts | sannysoft, all | ✅ `webdriver`, `cdp_runtime_enabled`, `cdc_artifacts`, `csp_bypassed` |
| WebRTC IP leak | browserleaks, HUMAN | ✅ `webrtc_public_ip`, cross-linked to proxy IP |
| Cross-layer **coherence** ("lies") | CreepJS (JS-only) | 🟢 the whole engine — and across TLS↔H2↔TCP↔JS, not just JS |
| **Coordination / fleet** detection | HUMAN (collective); most: none | 🟢 JA4-cluster + JS-divergence paradox + **fp-collision** + proxy topology |
| Mouse / keystroke dynamics | DataDome, Kasada, HUMAN (ML) | ✅ thresholds + **biomechanics** two-source corroborated on Balabit + SapiMouse (`bh.power_law_violation`, threshold tightened 0.1→0.05); no ML model |
| CDP-injection mechanism tell (coalesced events) | rare | 🟢 `bh.synthetic_no_coalesced` |
| IP reputation / ASN / datacenter / proxy-exit | **all commercial** (backbone) | ✅ live CIDR classifier (`ip_reputation.py`): `rep.datacenter_asn` + `rep.known_proxy_exit` active; keyless **DB-IP Lite** City+ASN geo (CC BY 4.0, no licence key) |
| QUIC / HTTP-3 fingerprint | emerging (Akamai) | 🟢 RFC 9001 Initial decrypt + capture; `net.quic_grease_vs_ua` live (few public tools do QUIC) |
| Within-session / temporal coherence (invariant field rotated, or must-vary field static) | rare | 🟢 JA4 / IP / HTTP-2 / UA rotation + `net.tls_ext_order_static_within_session` (Chromium that didn't permute its ClientHello extension order) |
| Web Bot Auth (RFC 9421 signed-agent) verify | Cloudflare (edge-live 2026) | 🟢 `net.web_bot_auth_invalid` convicts a forged/replayed signature; a valid signer is allow-listed (`Label.verified`) |
| Mouse / keystroke dynamics (touch) | DataDome 2025, Kasada | ✅ `bh.touch_uniform_velocity` (swipe velocity-CV floor, grounded on BrainRun) + `bh.mobile_keystroke_interval_floor` |
| Scroll / intent sequences | DataDome 2025, Kasada | ⚠️ touch swipes covered; collector still doesn't capture scroll/intent |
| ML trust-score / per-customer models | all commercial | ❌ Kitsune is rules-as-data (by design — explainable), no ML model |
| Active challenge (CAPTCHA / **proof-of-work**) | reCAPTCHA, hCaptcha, Turnstile, Kasada | ❌ Kitsune is **passive** — no challenge-response |
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
   coherence, HTTP/2 **unknown-engine**, HTTP/2 **DoS attribution**, p0f-style TCP/IP OS coherence, and
   **QUIC/HTTP-3 ClientHello** fingerprinting (RFC 9001 Initial decrypt) with a QUIC-GREASE tell.
4. **Explainability.** Every verdict cites the exact rules + evidence; no black-box score.

## Gaps closed since the first survey

- **IP reputation** — now live: a stdlib CIDR classifier (`ip_reputation.py`) feeds `rep.datacenter_asn`
  and `rep.known_proxy_exit` (active) from curated cloud/Tor/VPN lists (`docs/ip-reputation-data.md`).
- **Behavioral biomechanics** — two-source corroborated: calibrated on Balabit, then independently
  re-measured on **SapiMouse** (120 subjects, a different rig/era) with the shipped extractor; both agree
  real aimed motion obeys the power law far above the floor, so the threshold was tightened 0.1→0.05 at
  zero recall cost (`bh.power_law_violation`, `docs/behavioral-data.md`). Honest scope: a well-crafted
  humanizer still passes (caught by the mechanism tell), so this raises the floor, not the ceiling.
- **Mobile behavioral** — touch/keystroke floors grounded on public CC-licensed corpora:
  `bh.touch_uniform_velocity` (swipe velocity-CV, BrainRun 161,780 swipes) and
  `bh.mobile_keystroke_interval_floor` (Aalto mobile typing); see `docs/mobile-biomech-grounding.md`.
- **WebGL renderer ↔ caps** — `br.webgl_renderer_caps_mismatch` (G18) reads the GPU's actual
  `MAX_TEXTURE_SIZE` and convicts a high-end renderer string over a backend whose caps betray the lie —
  closing the source-level-fork gap the string-only WebGL checks miss.
- **Web Bot Auth** — `net.web_bot_auth_invalid` (G25) verifies an RFC 9421 / Ed25519 signed-agent
  identity at the edge (`edge/internal/webbotauth`) and convicts only a definitive forgery/replay; a valid
  signer is allow-listed via the new `Label.verified` outcome (`scoring.verified_agent`).
- **Within-session temporal coherence** — the network-invariant family now includes
  `net.tls_ext_order_static_within_session` (a Chromium-JA4 session that repeated a single ClientHello
  extension order instead of permuting per connection), alongside JA4/IP/HTTP-2/UA rotation.
- **Keyless geo** — geo enrichment now reads a keyless **DB-IP Lite** City+ASN MMDB pair
  (`dbip-city-lite.mmdb` / `dbip-asn-lite.mmdb`, CC BY 4.0), pulled by `geo_refresh.py` — replacing the
  manual MaxMind GeoLite2 path (GeoLite2 kept as a filename fallback).
- **QUIC / HTTP-3** — built across three validated cores (decrypt → capture → coherence);
  `net.quic_grease_vs_ua` validated live (`docs/findings.md`, "QUIC / HTTP-3 fingerprinting").

## Honest gaps that remain (prioritized)

1. **ML trust-score + scroll/intent sequences** — the field trains per-customer ML over richer behavioral
   signals; Kitsune is rules-as-data by design (explainable). Mobile touch dynamics are now covered
   (`bh.touch_uniform_velocity`); scroll/intent sequence capture remains the open behavioral gap.
2. **Active proof-of-work challenge** — Kitsune is passive by design; a Kasada-style PoW gate is an option
   for the volumetric tier, but a different posture (challenge vs observe).
3. **Scale / known-fingerprint corpus** — commercial tools match against millions of known bot fingerprints;
   Kitsune relies on coherence + coordination instead of a reference DB (a deliberate, but real, trade-off).
4. **Mobile app / SDK attestation** — Kitsune is web-only.

**Summary.** Against the *public* detection field, Kitsune matches or exceeds the per-session fingerprint and
TLS/H2/QUIC stack, and leads on cross-layer coherence + coordination + several cutting-edge network tells.
The IP-reputation, behavioral-biomechanics, and QUIC gaps from the first survey are now closed; what remains
versus the *commercial* field is proprietary by nature — trained behavioral ML over scroll/intent, active
proof-of-work challenges, and a million-fingerprint reference corpus. The lab's thesis — incoherence across
layers + coordination — is genuinely differentiated; the remaining gaps are posture/scale, not detection ideas.

## 2026 landscape recheck — the thesis is current, no missed technique

*(rule inventory: [`docs/detection-catalog.md`](detection-catalog.md) / [`docs/scoreboard.md`](scoreboard.md); `ruleset_version` at the head of `contracts/rules/registry.yaml`.)*

Re-surveyed the public 2026 anti-detect field to confirm Kitsune is not behind the cutting edge. The field's
state of the art maps directly onto what is already built or documented — no new attack technique surfaced
that the threat model (see docs/evasion-catalog.md "Coverage envelope") does not already address:

- **"Consistency checking" across UA / TLS / device is described as THE industry detection approach** — i.e.
  the field has converged on exactly Kitsune's cross-layer-incoherence thesis (a Chrome UA over a Python-TLS
  signature is flagged before any interaction). Kitsune leads here (`net.tls_vs_ua_browser`, `tcp_os_vs_ua`,
  `ch_ua_version_vs_ua`, the h2/QUIC tells).
- **SOTA stealth "works directly with native interfaces, leaves no automation-library traces"** — this is the
  Proxy-over-native technique white-boxed in fingerprint-injector, whose artifact-layer ceiling is documented.
  An industry **~53% evasion rate against commercial anti-bot** corroborates that the per-session ceiling is
  real field-wide, not a Kitsune limitation — and that the durable answer is coordination + a real-traffic
  prevalence prior, exactly the (external-data-bound) frontiers.
- **"Outdated browser versions stand out"** — version *incoherence* and stale templates are already covered
  (`net.ch_ua_version_vs_ua`, `br.ch_he_version_vs_ua`, `engine_feature_vs_ua`, PQ-keyshare lag). The only
  uncovered case — a *uniformly* stale-but-consistent version — is a corroborating prevalence/recency tell
  needing a maintained current-version reference; per the saturation guidance it is deliberately not built as
  a marginal environment tell (and is subsumed by a real-traffic prevalence prior when one exists).

Net: the 2026 SOTA confirms the thesis and the threat model are current; the residual frontier is unchanged
and external-data-bound. Sources: browserless.io, hcaptcha.com, scrapfly.io, scrapingbee.com (2026).
