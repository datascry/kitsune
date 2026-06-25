# Research radar — the detection⇄evasion loop's intake queue

This file is the durable queue of the **research-fed red⇄blue loop**: external papers/tools/techniques for
bot detection & evasion, each mapped to a Kitsune seam, tagged **groundable-in-sandbox** vs
**external-data-bound**, and tracked from `lead → grounded` (or `→ external queue`). It is fed by periodic
deep-research passes and drained by the adversarial pump. The `groundable?` column *is* the "evaluate
evasions against real-world testing" judgement: it records whether a technique can be tested with the local
lab (Docker, headless+headful browsers, synthetic traffic) or needs data the lab cannot self-generate.

## The loop cycle

Each iteration runs **locally, on demand** (the full toolchain — `uv`, `go-task`, Docker for the edge Go
tests — only exists in a local session; no cloud routine). Drive a cycle by asking Claude to "run a
research-loop cycle", or with `/loop` inside a session. The steps:

1. **Scan** — deep-research for new detection/evasion work since the last cycle; append new rows below
   (seam-tagged, cited, groundability assessed). Dedup against what Kitsune already covers.
2. **Pick** — take the highest-value **groundable** lead not yet `done`.
3. **Pump** — run one red⇄blue rung: red writes/confirms the evasion **EVADES** the current detector;
   blue builds the **grounded** detection; verify it **CONVICTS** the evader **and** passes the FP gates
   (`task calibrate` / `calibrate-intoli` / `coordination-eval`) + `task ci`.
4. **Record** — flip the row's status, update `task scoreboard`, commit (as `datascry`). Route
   external-data-bound items to the queue with the exact real data they need.

## Methodology guardrails (do not skip)

- **Grounding discipline (the standing constraint).** Never ship an ungrounded convicting rule. A rung needs
  a faithful red-team positive **and** a zero-FP sweep. External-data-bound items wait — they do not become
  speculative rules.
- **Lab-classifier deltas ≠ production-detector deltas.** Evasion papers (e.g. DMTG mouse synthesis) report
  reductions against the authors' *own* white-box classifiers. Treat such numbers as lower bounds; ground a
  red-team evasion by whether it trips Kitsune's *actual* tells, not by the paper's headline %.
- **Packet-length-sequence detections do not transfer to the wild (Rosetta, USENIX Sec 2023).** TCP
  reliability (retransmit/segmentation/MSS) makes length sequences network-path-dependent. Do NOT build a
  flow-length-sequence detection in-lab expecting it to hold in production — order/direction features are
  more robust, but flow-statistics detection is fundamentally external-data-bound here.

---

## Groundable leads (in-sandbox pump candidates)

| # | seam | technique / signal | evasion / tool | source | status |
|---|---|---|---|---|---|
| G1 | coherence (spatial) | **Cross-attribute inconsistency within one fingerprint** — e.g. a device class (UA/model) paired with a screen resolution/DPR that device never ships, an iPhone with an impossible screen geometry. FP-Inconsistent's *spatial* rules cut DataDome evasion 48% / BotD 45%. | anti-detect browsers that spoof attributes independently (browserforge/fingerprint-injector mix fields) | FP-Inconsistent, ACM **IMC 2025** (DOI 10.1145/3730567.3732919; arXiv 2406.07647) | **done** → `br.mobile_no_touch` (phone/tablet UA + maxTouchPoints 0; device-DB-free, FP-safe). Screen-geometry coherence needs a real-device resolution DB → see X5. |
| G2 | red-team / behavioral | **GAN/diffusion mouse-trajectory synthesis** as a faithful evader to pressure-test the behavioral floor + the coalesced-sample terminus. | DMTG (diffusion, arXiv 2410.18233), BeCAPTCHA-Mouse GAN, SapiAgent | DMTG; BeCAPTCHA-Mouse (Pattern Recognition 2022) | **validated** — the convicting tell (`bh.synthetic_no_coalesced` / `br.coalesced_untrusted`) is STRUCTURAL (getCoalescedEvents length + isTrusted), so trajectory SHAPE quality is orthogonal: a DMTG path injected via CDP still has `coalescedMax<=1` → caught. Already grounded (stealth `KS_BEHAVE`); escape is real XTEST/uinput (privilege-gated terminus). DMTG validates Kitsune's structural-over-shape bet. No new rule. |
| G3 | behavioral | **Keystroke-dynamics detection** (timing + key-identity); cGAN can synthesize evasions. | cGAN keystroke synthesis (arXiv 2212.08445) | IFIP SEC 2024 (DOI 10.1007/978-3-031-65175-5_30) | **not groundable** — keystroke timing is jitter-unsound across instances (no clone/structural channel, unlike mouse coalesced; memory-confirmed). `bh.keystroke_entropy_floor` stays corroborating; cGAN defeats shape/timing and there is no structural keystroke analog of coalesced sampling. |
| G6 | coherence (mobile) | **Mobile GPU-family ↔ OS coherence** — real mobile GPUs surface as enumerable WebGL renderer strings (Qualcomm **Adreno**, ARM **Mali** ⟹ Android; **"Apple GPU"** ⟹ Apple iOS/macOS). An Android UA with renderer "Apple GPU", or an iPhone UA with "Adreno"/"Mali", is a clean cross-layer incoherence — the mobile extension of `webgl_os_vs_ua` (which today only knows desktop Direct3D/Metal/Mesa). | a desktop-faking-mobile that fakes a mobile renderer to dodge `webgl_software` but mismatches the GPU family | Castle.io WebGL-renderer fingerprinting (mobile GPU enumeration), mobile-research pass 2026-06-21 | **resolved — no new rule.** Probed (confirm-EVADES-first): the **Apple-GPU** half is ALREADY caught — `_webgl_os` maps `Apple`→macOS, so an Android UA + "Apple GPU" already fires `webgl_os_vs_ua`. The **Adreno/Mali→Android** half is **FP-UNSAFE**: real **Windows-on-ARM (Snapdragon) ships Adreno** and **ChromeOS ships Mali** (both verified to currently — correctly — not fire), so mapping them to Android would FP on real devices → that direction is external (needs a device-class disambiguator, see X5). The only FP-safe sliver (Adreno/Mali under an Apple UA) is redundant — a Chromium-faking-iPhone already trips `apple_ua_nonwebkit`/`safari_ua_no_webkit_api`/`mobile_no_touch`. |
| G5 | environment (mobile) | **WebView / in-app-browser surface** — the `wv` UA token (durable through Android 16 UA reduction; standalone Chrome lacks it) + per-app IAB tokens (`FB_IAB`/`FBAN`) + the `X-Requested-With` package header (Android WebView). | host app overrides UA via `setUserAgentString` (all UA signals spoofable) | Android Devs Blog (Dec 2024); Tiwari et al. arXiv 2208.01968; mobiforge | **lead (weak/corroborating)** — WebView is ALSO the dominant *legit* mobile surface (in-app browsers), so presence is NOT convicting; only a non-UA-vs-UA mismatch (`X-Requested-With` present but UA omits `wv`) is a tell, and that's niche + needs real app traffic → mostly X7 |
| G4 | network (JA4+) | **JA4+ suite coverage audit.** | uTLS/curl-impersonate pin JA4; JA4T harder (real stack) | FoxIO JA4 (github.com/FoxIO-LLC/ja4), JA4T blog (blog.foxio.io/ja4t-tcp-fingerprinting) | **covered** — JA4 (ja4a/b/c) + JA4H (`net.h2_header_order_vs_ua`) present; JA4T's detection value = TCP-OS coherence (`tcp_kernel` SYN fp + `net.tcp_os_vs_ua`); JA4L (latency/hop-distance) marginal for bot-detection + latency-external; JA4S is server-side (N/A for a client detector). No groundable gap. |
| G7 | coherence (network ⇄ UA) | **FCrDNS declared-crawler verification** — a UA declaring a known crawler (Googlebot/Bingbot/Applebot/…) whose connecting IP fails forward-confirmed reverse DNS (no PTR, PTR under no official suffix, or no forward-confirm) is an impersonator. FCrDNS is the crawlers' OWN documented verification method, so a real crawler always confirms; transient DNS errors abstain (FP-safe). | a non-crawler IP wearing a crawler UA (fake-Googlebot scrapers — a common allow-list bypass) | GreyNoise GNQL gap analysis (`actor` + `metadata.rdns_validated` facets); Google/Bing crawler-verification docs | **done (experimental)** → edge `fingerprint.VerifyCrawler` emits `network.fake_declared_crawler` → `net.fake_declared_crawler` (coherence, convicting, w0.8). Unit-grounded (confirm / impersonator / NXDOMAIN / abstain) + a stub-resolver prepare test + a detector conviction test. EXPERIMENTAL until a live resolver grounds it in deployment (edge ships net.DefaultResolver; the FP-safe-by-construction logic mirrors the crawlers' own method). Adjacent to (not core to) the real-browser-coherence thesis — targets the declared-crawler-spoof abuse case. |
| G8 | artifact (input) | **screenX/screenY ↔ clientX/clientY pointer-coordinate coherence** — a real pointer event's `screenX/screenY` equals `clientX/clientY` plus the window's screen offset (and `screen` bounds); a CDP/`Input.dispatchMouseEvent`-injected event or a MouseEvent-Patcher shim commonly sets `screenX===clientX` or `0`, an impossible geometry. The collector today captures only `clientX/clientY` — a NET-NEW surface. | Bablosoft **MouseEvent-Patcher** (screenX/screenY spoof), CDP `Input.dispatchMouseEvent` synthetic events | TheGP/untidetect-tools (MouseEvent-Patcher); CDP Input domain | **grounded, deferred (marginal value).** Live-confirmed (Playwright 1.48): a CDP `page.mouse.move` event has `screenX===clientX && screenY===clientY` AND `isTrusted===true` — so it is ORTHOGONAL to the coalesced/untrusted tells (a genuinely new CDP-mouse-injection surface). FP-safe form: fire only when `screen.height - innerHeight > 50` (a real WINDOWED browser always has top chrome → `screenY>clientY`; fullscreen and headless both have `innerHeight≈screen.height` → gated out). BUT the value is low: (1) corroborating-only (chromeless-popup FP rules out convicting), (2) headless — the common bot — is gated out, (3) the headful frontier it would corroborate (camoufox-headful/patchright-headful) is ALREADY `suspicious`, so it changes no label. A full collector+rule+catalog/matrix cascade for a marginal corroborating tell. DEFER until headful-CDP-injection is a priority or it can convict; the grounding is captured here so the loop need not re-derive it. |
| G9 | automation (CDP) | **rebrowser-bot-detector coverage audit** — its checks (Runtime.enable leak, `dummyFn`/exposeFunction binding leak, sourceURL leak, useless-main-world exec). `br.cdp_runtime_enabled` covers the Runtime.enable leak; verify the binding/sourceURL leaks are covered or add them. | rebrowser-patches / patchright (the leaks they specifically fix) | TheGP/untidetect-tools (rebrowser-bot-detector, brotector) | **partial — audited + 1 leak closed.** Mapped all 10 rebrowser tests: COVERED — runtimeEnableLeak (`cdp_runtime_enabled`), navigatorWebdriver (`webdriver_present`), bypassCsp (`csp_bypassed`), headless UA. CLOSED this tick — exposeFunction/binding leak: live-grounded that real Playwright (1.48, via addInitScript) exposes `window.__playwright__binding__` while NONE of the previously-listed automation globals were present (vanilla Playwright was EVADING the `automation_globals` surface); added it to both collectors → trips the existing `br.automation_globals` (no new rule). `__pwInitScripts` is NOT in current Playwright (ungrounded — not added). REMAINING (low value / FP-risk): sourceUrlLeak (puppeteer-specific, `__puppeteer_evaluation_script__` already listed), viewport 800x600/1280x720 (FP-risky), Chrome-for-Testing UA (niche). |
| G10 | behavioral (mobile FP fix) | **Gate the mouse-biomech floors off real touch devices** — power-law/straightness/velocity-CV/coalesced-absent are mouse-calibrated and false-positive on a real phone swipe (caps at suspicious, not bot, but still a precision hit). Emit `browser.is_mobile` (UA mobile token AND maxTouchPoints>0) and drop the mouse-motion floors in applicability when set (keep trace_replay — device-agnostic). | n/a (a precision/FP fix, not an evasion) | mobile-vs-desktop behavioral analysis 2026-06-23 | **done** → collector emits `browser.is_mobile` (mobile UA token AND maxTouchPoints>0); `applicability._MOBILE_BIOMECH_NA` drops `bh.input_entropy_floor` / `power_law_violation` / `path_too_straight` / `uniform_velocity` / `synthetic_no_coalesced` for a mobile session (trace_replay + keystroke floor stay). Tests: desktop fires the floors, mobile drops them, mobile still convicts on trace_replay. |
| G11 | behavioral (AI agent) | **Teleport-click — a click with no preceding pointer trajectory.** FP-Agent's #1 discriminative signal: ALL tested AI agents (Operator/Atlas, Claude-for-Chrome, Comet, Manus, Browser-Use, Skyvern) exhibit ZERO continuous mouse movement — a single mousemove→immediate click, or none. Today Kitsune's biomech needs motion to score; a teleport leaves none. | LLM browser agents (CDP/vision-driven, all teleport to targets) | FP-Agent (arXiv 2605.01247); see docs/adversary-emulation-roadmap.md | **done** → `bh.click_without_trajectory` (behavioral/corroborating, experimental, w0.5): a trusted, mouse-origin (detail≥1) click with ZERO total pointer movement, gated to non-touch (maxTouchPoints==0). EVADES-first GROUNDED: a CDP `Input.dispatchMouseEvent` click fired a trusted detail=1 click with 0 mousemove/pointermove, vs 6 for a real move+click. Emitted by demo.py (authoritative) + livepage probes.ts; engine test. Residual FP = a desktop user with a pre-positioned cursor clicking without moving (rare) → corroborating-only + experimental, can't convict alone. |
| G12 | behavioral (AI agent) | **LLM think-time cadence** — agents run a perceive→reason→act loop at ~3–8 s/step (LLM inference + render); humans act in sub-second bursts. A multi-second deliberation gap then a burst of action is an intrinsic LLM-agent temporal signature. FP-Agent did NOT measure this (they did within-action timing) → novel, open signal. | any LLM-in-the-loop agent | architecture paper (arXiv 2511.19477, "6.8 s/step"); FP-Agent gap | **lead (groundable, novel)** → `bh.action_cadence_deliberative`: inter-action intervals clustered at LLM-inference latency. Durable — an agent can't shed deliberation rhythm without giving up its speed. Ground with AGENT_THINKTIME. |
| G13 | behavioral (AI agent) | **Keystroke inter-key floor** — agents type at 1–5 ms inter-key (Browser-Use 5.31 ms, Manus 1.39 ms) vs humans 100+ ms; renderer buffering leaks the real timing even when delays are added. | LLM agents (keystroke-modality) | FP-Agent (typing-behavior features) | **done** → `bh.keystroke_interval_floor` (median inter-key < 30 ms, behavioral/corroborating, w0.55). EVADES-first GROUNDED: a Playwright `delay:0` fast-type measured entropy **0.766** (ABOVE the 0.15 entropy floor → evades `bh.keystroke_entropy_floor`) but median inter-key **0.9 ms** → caught. Emitted by all three collectors (demo.py authoritative + collect.ts + livepage probes.ts via `keystrokeIntervalMedian`); engine + unit tests; live end-to-end grounding through the real detector: the fast-type session fires the rule (entropy floor silent), a human-paced 140 ms session does NOT (FP-safe). Orthogonal to the entropy floor by construction. |
| G14 | behavioral (AI agent) | **Scroll-teleport** — 0 ms zero-duration `scrollIntoView` jumps (DOM agents) or multi-burst viewport exploration (vision agents) vs human smooth continuous scroll. NEW capture surface (Kitsune does not record scroll today). | DOM/vision agents | FP-Agent (scroll-behavior features) | **lead (groundable, new surface)** → `bh.scroll_teleport`; needs a scroll-event collector capture. |
| G15 | behavioral (AI agent) | **Paste/programmatic input** — a form field value that changes with NO per-key events (Atlas/ChatGPT/Comet paste; Claude change-event-only). | LLM agents (paste-modality) | FP-Agent (typing-modality) | **lead (groundable)** → `bh.input_via_paste`: value-change with zero keystroke events. |
| G16 | network (DDoS L7) | **Slow-HTTP attacks** (slowloris / slow-POST / slow-read) — exhaust the connection table by HOLDING connections with partial requests / tiny windows. A DIFFERENT mechanism from the frame-floods Kitsune already catches; the edge's H2FrameScanner won't see it (it needs connection-duration/incompleteness accounting). | slowhttptest, Torshammer, slowloris | DDoS deep-dive 2026; see docs/adversary-emulation-roadmap.md | **in progress — detection core built.** Edge serves h2 + http/1.1 with a 15s `ReadTimeout` (it *survives* slowloris but emits no signal; the h1 path isn't byte-tee'd like h2). Built `fingerprint.SlowLorisScanner` (observe-only, mirrors H2FrameScanner): times request-header arrival, fires `SlowRequest` when the header block is still incomplete (no CRLFCRLF) past an age budget with only a trickle of bytes — distinct from latency (delays the whole burst, not its completion) and oversized headers (byte-budget excludes them). 6 deterministic injected-clock tests; gofmt/vet/edge-suite green. The H2 slow-header analogue is already `ContinuationFlood`. **Next tick: wire into the h1 conn read path + a timer for held connections (slowloris conns are sessionless — no completed request → no ks_sid), emit `network.slow_http_attack` → rule `net.slow_http_attack`, ground with a slowhttptest-style client.** |
| G17 | network (DDoS ⇄ coordination) | **L7-flood-as-coordination** — an application-layer HTTP flood from a botnet looks like N clients per-connection; the DDoS signature is the AGGREGATE (lockstep timing + shared JA4/fingerprint across the flood sources). That IS Kitsune's coordination scorer. The bot↔DDoS convergence: a fleet can't hide, scraping or flooding. | coordinated HTTP floods (MHDDoS-class fleets) | DDoS deep-dive 2026 | **lead (groundable, Kitsune-unique)** → wire the coordination scorer as the L7-flood attributor (lockstep + fp/JA4 collision); ground with an httpflood FLEET evader tier. Highest-leverage DDoS angle. |
| G18 | coherence (GPU) | **WebGL/WebGPU capability ↔ renderer-string coherence** — source-level forks repaint the `UNMASKED_RENDERER`/adapter-vendor STRING but leave the real silicon's `getShaderPrecisionFormat`, `MAX_TEXTURE_SIZE`/max-varying-vectors, and the WebGPU `limits`(~40 correlated numbers)+`features` set keyed to the actual GPU. A renderer string whose capability profile belongs to a different GPU is a within-fingerprint incoherence. Kitsune has the WebGPU **vendor-family** hook (`webgpu_vendor_vs_webgl`) but reads no capability values. Live instance: CloakBrowser #294 (string claims RTX 5090, caps are RTX 3060). DrawnApart timed-GPU is the timing complement (you can fake the string, not the execution-unit throughput). | CloakBrowser/BotBrowser/fingerprint-chromium (seed-spoof the string); any source-level fork | botbrowser.io/en/blog/webgpu-fingerprinting; github.com/CloakHQ/CloakBrowser/issues/294; prescience-data/dark-knowledge (DrawnApart); topics fan-out 2026-06-24 | **lead — grounded recon done; threshold is capture-profile-bound.** EVADES-first confirmed by code audit: the collectors capture only the WebGL renderer STRING + worker divergence + getParameter-tamper and the WebGPU vendor-FAMILY (`webgpu_vendor_mismatch`/`webgpu_webgl_mismatch`) — NO capability values, so any renderer-string spoof that keeps the family consistent passes every current WebGL/WebGPU rule. Captured the in-sandbox **software baseline** (headless Chrome = SwiftShader): renderer self-labels `ANGLE (… SwiftShader …)`, `MAX_TEXTURE_SIZE=8192`, `MAX_VARYING_VECTORS=31`, shader precision HIGH_FLOAT `[127,127,23]`, WebGPU absent. **The FP-safe convicting core = "renderer string claims real HARDWARE but caps are SOFTWARE-class"** (the headless-on-a-GPU-less-server bot that spoofs its renderer to a real GPU keeps SwiftShader caps). Honest SwiftShader self-labels in the string → excluded → no FP. BUT setting the FP-safe THRESHOLD (which caps separate software from real hardware, FP-safe across mobile/old GPUs) needs a real-hardware caps corpus — this sandbox has ONLY SwiftShader + no WebGPU. So G18 is partly **capture-profile-bound** (needs the `real-browser-capture-profiles` run on real GPUs), not purely self-contained. Next in-sandbox step: add the caps-capture instrumentation (additive, no rule) so a capture-profile run lands the reference; THEN ship `br.webgl_caps_vs_renderer`. |
| G19 | behavioral (compute-class) | **Timed-compute / PoW ↔ declared-hardware coherence** — a lightweight client-side timed-compute (PoW) challenge's solve speed implies a compute class; cross-check against `hardwareConcurrency`/`deviceMemory`/UA. Catches a datacenter solver posing as a low-end mobile. A temporal/compute axis static FP can't see. | non-browser/emulated solvers (Kasada KPSDK-class); datacenter scrapers spoofing a weak device | capjs.js.org (Cap GPU-resistant time-lock); lktop/kpsdk (Kasada); blog.send.win headless-detection guide; topics fan-out 2026-06-24 | **lead (groundable)** → ship a PoW probe in the collector, time it, cross vs declared hw. NB timing noise → likely corroborating (caps at suspicious) unless tightly bounded. |
| G20 | network (TLS) | **Post-quantum keyshare ↔ UA-version coherence** (`net.pq_keyshare_vs_ua`) — by 2026 ~57% of real browser ClientHellos carry an `X25519MLKEM768` hybrid keyshare (Chrome 124+, FF 132+, Apple Oct 2025), adding ~1088 B and pushing the CH past one TCP segment. Stale impersonation profiles omit it or mis-order `supported_groups`/`key_share` under a modern-Chrome UA — a contradiction that fires BEFORE the first HTTP byte. Sits right next to `net.h2_unknown_vs_ua`. | curl_cffi (old profiles), wreq/rquest, httpmorph (no PQ), anything pinned to a stale Chrome | scrapfly.io/blog/posts/post-quantum-tls-bot-detection; lexiforest/curl_cffi; arman-bd/httpmorph; topics fan-out 2026-06-24 | **ALREADY COVERED (fan-out duplicate).** The TLS path is SHIPPED: edge `reverseproxy.go` emits `network.tls_no_pq_keyshare` when `chromeUAExpectsPQ(ua)` (UA Chrome ≥131) and the ClientHello's `supported_groups` lacks X25519MLKEM768 (0x11EC) / X25519Kyber768Draft00 (0x6399) — see `fingerprint/keyshare.go::HasPostQuantumKeyShare` — wired to the active rule **`net.tls_pq_keyshare_vs_ua`**. The QUIC sibling (`net.quic_pq_keyshare_vs_ua`) was RETIRED (the QUIC ClientHello capture is infra-blocked: an MLKEM keyshare makes the hello multi-packet and the opportunistic capture misses the fragment → FP on real Chrome). The JS analog is `br.engine_feature_vs_ua`. The fan-out agents black-boxed the edge and missed all three. No new work. |
| G21 | coherence (environment) | **speechSynthesis voices ↔ OS** — `speechSynthesis.getVoices()` returns an OS-bundled, OS-specific voice set (Microsoft/Apple/Google families); an empty list under a Windows/macOS UA (headless Linux) or a voice set that mismatches the claimed OS is incoherent. Cheap, in-page. | headless Chromium claiming a desktop OS; anti-detect browser that forgets to spoof voices | scrapfly speech-synthesis-fingerprinting; scrapfly/Antibot-Detector; adryfish/fingerprint-chromium; topics fan-out 2026-06-24 | **ALREADY COVERED (fan-out duplicate).** Both halves are shipped: `br.voices_empty` (no TTS voices under a desktop UA — headless/container, environment, w0.5) and the active `br.voice_os_vs_ua` (coherence, w0.75: "Installed TTS voices imply an OS that contradicts the UA platform", reads `browser.voice_os_hint` vs `browser.ua_platform`). The fan-out agents black-boxed the registry and missed both. No new work. |
| G22 | coherence (hardware) | **WASM/SIMD CPU-microarchitecture ↔ claimed platform** — a WASM probe measuring NEON vs SSE/AVX availability / register width runs BELOW the JS shim every spoofer patches; cross-check the inferred CPU arch against the UA/WebGL/WebGPU platform story (e.g. WASM says Apple-ARM but UA/WebGL claim x86 Windows). Defeats engine-fork browsers that beat every JS-visible check. | engine-fork anti-detect browsers (Wayfern/BotBrowser); cross-arch emulation/VM hosting | TheGP/untidetect-tools; arxiv 2509.09950; scrappey WASM-fingerprinting; topics fan-out 2026-06-24 | **lead (groundable)** → Docker WASM probe + ARM-vs-x86 mismatch synthesis. NB heavy/noisy — calibrate FP carefully; likely corroborating. |
| G23 | network (TLS) | **uTLS preset coherence breaks** — (1) `HelloChrome_120` omits the `padding` extension real Chrome adds when the CH is <512 B → a single-packet length tell; (2) presets hardcode the AES cipher pref but randomize the ECH cipher → ~50 % outer-vs-inner ChaCha20/AES mismatch real Chrome never produces (CVE-2026-26995 / -27017). uTLS is already an evader fixture. | uTLS-based stealth clients pinned to a fixed `HelloChrome_*` preset | scrapfly PQ-TLS disclosure; topics fan-out 2026-06-24 | **lead (groundable)** → add ClientHello-length + ECH-cipher-vs-outer-cipher checks against the uTLS evader; convicting if the length/mismatch is structurally impossible for the claimed browser. |
| G24 | coherence (temporal) | **Client-timestamp ↔ server-clock coherence** — cross-check client-reported event timestamps against the detector's own ingest time AND the `performance.now()` time-origin; a replayed/synthetic sensor payload desyncs these (DataDome's own "fake-vs-real timestamp" check). The detector already holds both clocks. | replayed/forwarded sensor payloads; relay/token-replay clients | joekav/SlideCaptcha (DataDome); topics fan-out 2026-06-24 | **lead (groundable)** → clock-drift rule with an FP-safe band for legit NTP/skew. Adjacent to `bh.trace_replay_within_session` (replay on the temporal axis rather than the trace axis). |

## External-data-bound leads (queue — need real data the lab can't self-generate)

> **Turnkey path built:** `docs/grounding.md` + `task grounding -- <captures>` runs the full grounding
> sweep (per-session FP/recall + coordination + prevalence-prior rebuild) the moment an operator supplies
> real captures. Each X-item below maps to a capture + command in that runbook.


| # | seam | technique / signal | real data needed | source | status |
|---|---|---|---|---|---|
| X1 | proxy/tunnel | **Encapsulated-TLS-handshake fingerprinting** — fully passive; detects ALL proxy/tunnel stacks (shadowsocks/vmess/trojan/vless/httpt, TPR >70%) from nested-handshake size/timing/**direction**; padding doesn't defeat it (falls back to order+direction). | real proxy egress + large-scale ISP traffic (paper: 110M flows, TCP-only deployed) | Xue et al., **USENIX Sec 2024** (ensa.fi/papers/sec24-xue.pdf) | **external** — order/direction *insight* is mineable; QUIC/MASQUE transfer is an open question |
| X2 | residential proxy | **RESIP relayed/tunnel-flow classifier** — transformer, first 5 packets, payload-free: relayed 93%/93%, tunnel 91%/96%. | real RESIP node deployment + wild egress (3TB / 116M flows) | Huang et al., arXiv 2404.10610 (USTC+IU 2024) | **external** — the IP-reputation/proxy half Kitsune already flags as blocked |
| X3 | IP reputation | **CGNAT detection** to bound the `ip_rotation_within_session` confound + RESIP collateral. | real CGNAT/residential traffic | Cloudflare (blog.cloudflare.com/detecting-cgn-to-reduce-collateral-damage) | **external** — refines the documented CGNAT FP caveat |
| X4 | prevalence | **Real-traffic prevalence/IP-reputation prior** (the recurring Tier-3 gap). | hosted-demo opt-in / real-device matrix / real traffic | Resident Evil (RESIP study); Kitsune `build_prior_from_sessions` | **partially unblocked** — the IP-reputation half is now fed by the MIT X4BNet feed (wired into `ip_reputation_refresh`, see the real-data table below); the prevalence-prior half has a **turnkey adapter built** (`berke_corpus.py`) — it just needs the operator to accept the Berke Dataverse terms + download the CSV, then one command builds the aggregate prior |
| X6 | behavioral (mobile) | **Mobile touch/swipe biometrics** — extend the desktop mouse-biomech floors to touch swipes. | **human baseline NOW GROUNDED** (no longer fully external) | Touchalytics (arXiv 1207.6231), BeCAPTCHA (arXiv 2005.13655); **BrainRun (Zenodo 2598135, CC0)** | **SHIPPED (velocity floor) — see docs/mobile-biomech-grounding.md.** Analysed 161,780 real human swipes (BrainRun, CC0). **`bh.uniform_velocity` IS transferable → shipped as `bh.touch_uniform_velocity`** (median per-swipe touch velocity-CV < 0.15; human p1=0.235 → FP-safe with headroom). Collector captures swipes via touch events (touchstart/move/end) in demo.py + livepage; grounded end-to-end (constant-velocity replay CV≈0.005 fires; varied/natural swipe ≈0.24-0.6 stays silent — a naive jittery CDP swipe ≈ human p1 correctly does NOT fire). **`bh.path_too_straight` is NOT transferable** (human swipes inherently near-straight, median 0.993 — would FP >50%; the empirical proof behind G10's gate; stays gated). The labeled mobile-bot corpus stays external (none public — confirmed; the positive is self-generated). The 4 dataset searches are cataloged in the real-data table below. |
| X7 | environment (mobile) | **iOS WKWebView / in-app discriminator** — no durable CLIENT-side signal survived verification (the `Version/`-token-absence AND `window.webkit.messageHandlers` signals were both **refuted**); `X-Requested-With` (Android) reliability is post-2023-opt-in uncertain. | real in-app / WebView traffic across apps | research open-question 2026-06-21 | **external/open** — the largest unfilled real-mobile gap |
| X5 | coherence (spatial) | **Device-model ↔ screen-geometry coherence** — the DB-dependent half of G1 (an iPhone-15 UA with a resolution no iPhone-15 ships). Needs a real (device → screen res/DPR) mapping to be FP-safe; a hand-coded threshold FPs on foldables/edge devices. | real-device fingerprint DB (the FP-Inconsistent dataset is honey-site-derived, not released) | FP-Inconsistent, ACM IMC 2025 | **external** — split from G1 (the DB-free `mobile_no_touch` shipped) |
| X8 | IP reputation (actor) | **GreyNoise GNQL enrichment** — per-IP `classification` (malicious/suspicious/benign), `actor` (Shodan/Censys/GoogleBot), `tag`, `spoofable`, first/last-seen. Richer than the static CIDR lists Kitsune wires today: real actor/intent intel that would ground the currently-synthetic `rep.*` rules and complement the FCrDNS G7 check (confirming benign-crawler actors). | a GreyNoise API key + deploy-time egress (community tier rate-limited; GNQL is enterprise) | GreyNoise GNQL (docs.greynoise.io/docs/using-the-greynoise-query-language-gnql), gap analysis 2026-06-23 | **external** — the actor/reputation feed missing from the data-source table below; wire into `ip_reputation_refresh` at deploy when a key is available. |

## Real-data sources → grounding input (the "search for more real data" shopping list)

A vetted catalog of **actual downloadable datasets/feeds** mapped to the X-item each one unblocks, with
access + licence + the exact grounding command. Sourced via a deep-research pass (2026-06-21) and
fetchability/licence-verified in-sandbox. **Discipline:** never commit raw dataset rows — only de-identified
aggregates (a prior, a CIDR seed regenerated at deploy, counts). Licence claims are verified against the
source itself, not the aggregator's metadata (GitHub's licence detector missed X4BNet's README-embedded MIT).

| dataset / feed | unblocks | access | licence | fetchable now? | grounding input |
|---|---|---|---|---|---|
| **X4BNet/lists_vpn** `output/{vpn,datacenter}/ipv4.txt` | X4 (IP-rep) / X2,X3 corroboration | raw GitHub | **MIT** (README, covers the list data) — verified | ✅ HTTP 200 (vpn ~11k, dc ~42k) | **WIRED** → `ip_reputation_refresh` (proxy_exit += VPN, datacenter += hosting). Output uncommitted; run at deploy. |
| **Tor bulk exit list** | X4 (IP-rep) | check.torproject.org | public | ✅ (already wired) | `ip_reputation_refresh` proxy_exit (Tor slice) |
| **AWS `ip-ranges.json` + GCP `cloud.json`** | X4 (IP-rep) | publisher-authoritative | public | ✅ (already wired) | `ip_reputation_refresh` datacenter (cloud slice) |
| **FireHOL blocklist-ipsets** `firehol_proxies`/`firehol_anonymous` | X4 (broader proxy/anonymizer) | raw GitHub | **GPLv2 aggregate of mixed-licence upstreams** | ✅ HTTP 200 (~34MB) but **licence-gated** | candidate only — per-upstream vetting required before any redistribution (some components non-redistributable). Documented in `docs/ip-reputation-data.md`, NOT wired. |
| **Berke et al.** `github.com/aberke/fingerprinting-study` (PoPETs 2025) | X4 (prevalence prior) | browser-attrs file on **Harvard Dataverse** `doi.org/10.7910/DVN/0SGZFF` (repo MIT covers code only) | **research-use: no re-identification, no resharing** | ⚠ **gated** — only the no-browser-attrs survey CSV is in the repo; the 8,400-FP browser-attrs file needs accepting the Dataverse terms + download | **adapter BUILT** (`berke_corpus.py`): operator who accepted the terms runs `python -m kitsune_harness.berke_corpus <csv>` → committed **aggregate prior only** (frequency tables, never rows → satisfies no-resharing). Exact Kitsune attribute set (UA/screen/cores/unmasked-renderer). |
| **X4BNet datacenter** (above) | — | — | — | — | also a 2nd-source cross-check for the prevalence GPU/screen single-source factors |
| **Matomo `device-detector`** (regexes) | X5 (device↔geometry) partial | GitHub | **LGPL** | ✅ | device-model → class mapping; **no screen-resolution DB** (the FP-safe X5 half still needs a real device→res map) |
| **Resident Evil RESIP** (~6M IPs, rpaas.site) | X2/X3 (RESIP) | study artifact | study terms | gated | the RESIP IP set behind the residential-proxy-fleet signal |
| **GreyNoise GNQL** (per-IP actor/classification) | X8 (IP-rep actor) / G7 (benign-crawler actors) | api.greynoise.io | API key; community tier rate-limited, GNQL enterprise | ⚠ gated (needs key) | per-IP `classification`/`actor`/`tag`/`spoofable` → `ip_reputation_refresh` actor enrichment at deploy; aggregate/cache only, never commit raw |
| **Google/Bing crawler IP-range JSON** | G7 (FCrDNS — DNS-free CIDR path) | developers.google.com/static/crawling/ipranges/common-crawlers.json (+ special-crawlers); Bing equivalent | public (Google/MS authoritative) | ✅ public, daily, CIDR JSON | candidate → an authoritative CIDR feed for `net.fake_declared_crawler` (verify a declared crawler with NO DNS round-trip; resilient if DNS is slow/blocked). Edge-side consumer co-located with FCrDNS; not yet wired. |
| **Azure / Oracle / DigitalOcean / Cloudflare / Fastly ranges** | X4 (IP-rep datacenter) | Oracle `public_ip_ranges.json`, DO `digitalocean.com/geo/google.csv`, Cloudflare `/ips-v4`+`/ips-v6`, Fastly `api.fastly.com/public-ip-list`; Azure Service-Tags (rotating URL) | public | ✅ Oracle/DO/Cloudflare/Fastly stable; Azure rotates | **WIRED** (Oracle/DO/Cloudflare/Fastly → `ip_reputation_refresh` datacenter, per-source floors). Azure needs a discovery step for its rotating Service-Tags URL → candidate. |
| **Spamhaus DROP/EDROP + IPsum** | X4 (IP-rep proxy/abuse) | spamhaus.org/drop, github.com/stamparm/ipsum | DROP free-to-use; IPsum permissive (verify) | ✅ public, daily | candidate → thicken `proxy_exit` beyond Tor+X4BNet; licence-verify per source (cf. FireHOL caveat). |
| **FoxIO ja4db / peet.ws** (JA4 + Akamai H2 → client) | net.tls_vs_ua_browser / net.h2_vs_ua_browser precision | github.com/FoxIO-LLC/ja4 (ja4db), tls.peet.ws | varies (verify) | ✅ static lookup tables | candidate → expand the edge's tiny `ja4_hints.json` seed with more positively-identified clients (static table, no live traffic). |
| Hiding-in-the-Crowd (2M); Andriamilanto (4.15M) | prevalence (stats) | papers | — | ❌ stats-only (not downloadable) | reference distributions only — cannot rebuild a prior from them |
| **BrainRun** (Zenodo 2598135) | **X6 (mobile touch-biomech human baseline)** | Zenodo direct (gestures 265MB + sensors 3.2GB) | **CC0 1.0** (verified — derive+share aggregates freely) | ✅ **WIRED** | analysed → `docs/mobile-biomech-grounding.md` (161,780 human swipes: velocity-CV floor transferable, straightness not). The richest CC0 swipe baseline. |
| **MEU-Mobile KSD** (UCI 399) | X6 (mobile keystroke timing+pressure) | UCI direct (1.3MB) | **CC BY 4.0** | ✅ **ANALYZED** | 2,856 records → both keystroke floors VALIDATED FP-safe on mobile (inter-key p1 216ms ≫ 30ms floor; entropy p1 0.625 ≫ 0.15). See docs/mobile-biomech-grounding.md. |
| **Aalto ITE Typing** (Zenodo 12528163) | X6 (mobile keystroke floor, huge N) | Zenodo direct (7.3GB) | **CC BY 4.0** | ✅ **ANALYZED** | 42.3M keystrokes / 849,909 free-text mobile sessions → shipped `bh.mobile_keystroke_interval_floor` (<80ms, 0.018% FP). See docs/mobile-biomech-grounding.md. |
| **HuMIdb + BeCAPTCHA** (BiDAlab) | X6 (the only human-vs-bot mobile *positive*) | github.com/BiDAlab/HuMIdb — signed DUA, email atvs@uam.es | research-use, **no raw resharing** (aggregates after signing) | ⚠ gated | real human swipes + GAN/synthetic bot swipes+accel → the labeled positive; start the email request in parallel |
| **HMOG / WISDM / MotionSense** | X6 (motion-during-interaction baseline) | W&M / UCI 507 / GitHub | W&M-NC / **CC BY 4.0** / **MIT** | ✅/⚠ | accel/gyro envelopes for the emulator/motion-coherence angle (NB: device-motion *fingerprinting* was REFUTED — behavioral/coherence only) |

**Hardest-gap status:** X6 (mobile touch/keystroke biometrics) is **partially unblocked** — the *human baseline* is
now grounded from permissive CC0/CC-BY datasets (BrainRun wired; see `docs/mobile-biomech-grounding.md`), so the
velocity-uniformity floor is shippable on touch. What stays external is the **labeled mobile-bot positive** (no
public dataset exists — a 4-angle search confirmed it; self-generate via a synthetic-swipe red-team, as the
desktop side did) and **mobile/WebView** (X7). The Berke corpus (X4 prevalence) remains the other licence-gated unlock.

## Validations (research that confirms existing Kitsune work — do NOT rebuild)

- **Incoherence thesis** — FP-Inconsistent (IMC 2025) is the strongest external validation: cross-layer
  coherence is *the* convicting signal against evasive bots, not any single value. Kitsune's whole design.
- **Temporal inconsistency** = Kitsune's **within-session axis** (JA4/h2/IP/UA/fp/trace rotation) — already
  built and grounded. FP-Inconsistent's "same cookie changing an invariant" is exactly `*_within_session`.
- **Session-replay detection** = `bh.trace_replay_within_session` + coordination `trace_collision`. ReMouse
  (J. Cybersec. Privacy 2023) confirms intra-user variability makes a replayed path anomalous. NB the
  *inter*-user-similarity claim was **refuted** (0-3) — don't over-claim distinctness across users.
- **Engine-level spoof defeated by coherence, not property probes** — Camoufox's C++ patches read native;
  caught via TLS + cross-layer mismatch. Matches `privacy-browser-fp-surface` memory; keep mining coherence,
  not `[native code]` probes.
- **Commercial anti-bot does cross-layer coherence internally** — Akamai's deobfuscated `sensor_data` carries
  an explicit internal "coherence check" (var 115) + a sensor-quality score (OXDBXKXO/akamai-toolkit); it
  validates fields *against each other within one payload*, not in isolation. Independent confirmation of
  Kitsune's whole thesis — and suggests an architectural addition (a *within-payload* sensor-quality
  sub-scorer beneath the cross-layer engine). ThreatMetrix (ZacharyHampton/tmx-solver) ships the same shape:
  a self-report (`jso`/`jsb` declared OS/browser) ↔ observed (UA/WebGL/canvas/CH) matrix — most of which
  Kitsune already cross-checks. Its mouse biomech features (curviness/inflection/hesitancy) are a candidate
  behavioral second-source, but **external** (need a real corpus to calibrate, like SapiMouse).
- **"Browser-grade network, zero browser-runtime" is already covered** — the agent-fetch / azuretls-gateway
  pattern (a perfect `chrome-143` TLS+H2 fingerprint with NO JS ever executed) is exactly `network.browser_absent`
  (`detector._with_derived`: a network fingerprint with an empty browser layer). The topics fan-out surfaced
  it as "novel"; it is not — no new rule.

## Refuted leads — do NOT build (verification-killed)

- **Device-motion-sensor fingerprinting / coherence** — the "motion sensors fingerprint a phone 96-99%" and
  "sensors are permissionless, unlike camera/mic" claims did **not** survive 3-vote verification (1-2 / 0-3).
  Do not build a sensor-presence or motion-coherence rule on those grounds (it would be FP-prone).
- **iOS WKWebView client-side discriminators** — both "Safari has a `Version/` token a WKWebView lacks" and
  "`window.webkit.messageHandlers` is WebView-only" were **refuted** (0-3). No durable client signal → X7.
- **WebView privacy-sandbox / "259× more identifying" uniqueness** — refuted; not a basis for detection.

## Iteration log

- **2026-06-21 · iteration 1** — seeded from a deep-research pass (5 angles, 23 sources, 25 claims verified
  3-vote, 22 confirmed). Added G1–G4, X1–X4, 4 validations. Top groundable pick: **G1** (spatial
  cross-attribute coherence). Loop runs **local/manual** by design (no cloud routine — the edge pump needs
  local Docker/`go-task`); a cloud routine can be added later via `/schedule` once GitHub is connected.
- **2026-06-21 · iteration 2 (pump on G1)** — shipped `br.mobile_no_touch` (coherence, convicting): a
  phone/tablet UA (`Mobile`/iPhone/iPad token) with `maxTouchPoints == 0` is a desktop wearing a mobile UA.
  Device-DB-free + FP-safe (scoped off bare `Android`/TV). Grounded: convicts the mobile-spoof as the sole
  tell, silent on real iOS/Android (touch>0) and desktop; 0 FP on browserforge N=600; detector 260 + harness
  230 green; catalog/README/matrix regenerated. G1 spatial-screen-DB half split out to **X5** (external).
  Mirrored into the production livepage collector (`collector/src/livepage/probes.ts`, commit 3099fad) —
  emitted across demo.py (authoritative) + calibration mapper + livepage; collector CI green (Docker node).
- **2026-06-21 · iteration 3 (drain the groundable queue)** — ran G2/G3/G4: **G2 validated** (the coalesced
  terminus is structural/shape-independent, so DMTG-quality synthesis is already caught — no new rule);
  **G3 not groundable** (keystroke timing jitter-unsound, no structural channel); **G4 covered** (JA4/JA4H/
  JA4T-as-TCP-OS-coherence; JA4L marginal, JA4S N/A). **Groundable column is now DRY** — every remaining lead
  is external-data-bound (X1–X5: real proxy egress, real-device resolution DB, real-traffic prevalence). The
  loop reached the same wall as [[per-session-detection-saturated]]: the productive unlock is the GROUNDING
  HARNESS (hosted-demo opt-in / trusted-cert QUIC host / proxy egress), not more in-sandbox rules. Net result
  of the research-fed loop: 1 new grounded rule (`br.mobile_no_touch`, G1) + the rest validated/routed.
  Re-run the SCAN periodically — a genuinely new technique or tool re-opens the groundable column.
- **2026-06-21 · iteration 4 (mobile uplevel)** — Tier-1: grounded the mobile escalation ladder live (Android
  naive-spoof → `mobile_no_touch`; iOS-naive → `apple_ua_nonwebkit`+`safari_ua_no_webkit_api`+`mobile_no_touch`;
  fixed-touch → `pointer_touch_incoherent`; full-emulation → OS-leak), lighting 3 previously-unexercised rules
  via faithful evader modes (commits 350ffdb, 3ae9ac5). Tier-2: a mobile-targeted deep-research pass (6 angles,
  26 sources, 25 claims 3-vote-verified) added **G6** (mobile GPU↔OS coherence — top groundable), **G5**
  (WebView surface — weak/non-convicting), **X6** (mobile touch biometrics — external), **X7** (iOS WKWebView
  discriminator — open/external), and **killed the device-sensor lead** (refuted; saved an FP-prone build).
  Next groundable: **G6** (extend `_webgl_os` to mobile GPU families + a mismatched-renderer evader).
- **2026-06-21 · iteration 5 (G6 resolved — groundable column DRY)** — probed G6 (confirm-EVADES-first): the
  Apple-GPU half is already covered (`Apple`→macOS); the Adreno/Mali→Android half is FP-unsafe (real
  Windows-on-ARM Adreno + ChromeOS Mali) → external (X5-class); the FP-safe sliver is redundant with the
  iOS-spoof tells. **No new rule** (avoided a real-device FP), mirroring the `font_os_vs_ua`/`vendor_vs_ua`
  discipline. With G6 resolved, **every groundable lead (G1–G6) is now done/covered/validated/external and
  the whole gap queue (GAP-1–11) is cleared** — both queues exhausted. The loop's `next groundable` is empty;
  remaining radar items (X1–X7) are all external-data-bound and route to the grounding harness
  (`docs/grounding.md` / `task grounding`). External sourcing is the only way to refill the groundable column.
- **2026-06-21 · iteration 6 (real-data sourcing — X4 IP-rep half unblocked)** — ran the "search for more real
  data" pass: a deep-research sweep + in-sandbox fetchability/licence verification produced a vetted real-data
  shopping list (new **"Real-data sources → grounding input"** section), each dataset mapped to its X-item +
  access + licence + grounding command. **Grounded the one permissively-licensed, fetchable, in-sandbox asset:**
  wired **X4BNet/lists_vpn (MIT)** into `ip_reputation_refresh` — `proxy_exit` was Tor-only (a thin slice) and
  is now Tor + ~11k VPN CIDRs; `datacenter` was AWS/GCP-only and now adds ~42k hosting CIDRs. New `parse_cidr_list`
  + floor guards (`x4b_vpn`/`x4b_datacenter` ≥ 1000) + offline parser/drift tests; output stays uncommitted per
  the existing deploy-not-commit rule (detector 328 green, 99.34%). **Live-validated at scale** (in-memory, no
  committed output): a real refresh with the deploy-time floor guard active passes and grows the feeds from a
  thin seed to `proxy_exit` 1.2k → **12,231** CIDRs (~10×) and `datacenter` ~11.6k → **53,297** CIDRs (~4.6×),
  deduped; real AWS/Google IPs classify as datacenter, private LAN stays clean. **Verification catch:** GitHub's licence
  field reported X4BNet `null`, but its README carries full MIT text covering "the list itself" — confirmed at
  source before wiring (the standing don't-trust-single-source rule, applied to a licence). The other assets are
  licence-gated (Berke corpus → request research-use terms; FireHOL → per-upstream vetting) or stats-only; X6/X7
  still have no downloadable real dataset. Next external unlock: accept the Berke data terms → real prevalence prior.
- **2026-06-22 · iteration 7 (Berke prevalence-prior adapter — turnkey, awaiting operator download)** — pursued
  the X4 prevalence half. Investigation closed the loop to the session's start: the Berke browser-attributes file
  is **the same `survey-and-browser-attributes-data.csv` on Harvard Dataverse** (`doi.org/10.7910/DVN/0SGZFF`)
  behind the guestbook/WAF; the repo MIT licence covers code only, and the data carries research-use terms (no
  re-identification, **no resharing**). Only the no-attributes survey CSV is in the repo (useless for a prior).
  So I can't fetch it (the third-party-production line + I won't accept terms on the operator's behalf), but I
  **built the turnkey consumer**: `harness/berke_corpus.py` maps each Berke row into the detector's own
  `features_from_fingerprint` (zero bucketing duplication → prior stays in sync with the runtime scorer) and
  emits **only the aggregate prior** (frequency tables, never rows → honours no-resharing). Column names pinned
  from the published data dictionary + the repo's preprocessing notebook; offline-tested against synthetic rows
  in that schema (7 tests, 100% module cov, harness 240 green). The moment an operator accepts the terms and
  downloads the CSV: `uv run python -m kitsune_harness.berke_corpus <csv>` builds the real-traffic prior. This
  is the prevalence analog of iteration 6's IP-rep wiring — both halves of X4 now have turnkey consumers; only
  the operator-gated download remains.
- **2026-06-23 · GreyNoise GNQL capability-gap analysis** — mapped GreyNoise's GNQL telemetry against
  Kitsune. Verdict: **complementary, not overlapping** — GreyNoise is internet-wide IP/actor reputation,
  Kitsune is per-session cross-layer coherence; most GNQL facets map onto Kitsune's IP-reputation layer
  (already external-data-bound). Covered/equivalent: JA3/JA4/JA4H, JA4T↔`tcp_os` coherence, HTTP
  method/path/UA, the datacenter/VPN/Tor CIDR lists. Out of scope: HASSH/JA4SSH (SSH), CVE/callback_ips
  (vuln-scan/C2), internet-wide sensor generation (architectural). **Two real gaps surfaced:** (1) **G7
  FCrDNS declared-crawler verification** — a NEW *groundable* lead the iteration-3 "DRY" claim missed;
  BUILT this cycle (edge `fingerprint.VerifyCrawler` → `net.fake_declared_crawler`, experimental,
  FP-safe-by-construction, unit+detector grounded). (2) **X8 GreyNoise GNQL actor enrichment** — the
  per-IP actor/classification feed missing from the data-source table; queued (needs an API key at
  deploy). So the groundable column is no longer strictly dry — a new external telemetry source
  (GreyNoise) re-opened it, exactly as iteration 3 predicted ("a genuinely new technique re-opens it").
- **2026-06-23 · external-dataset sweep + cloud-range expansion** — catalogued four new public feeds in
  the data-source table: Google/Bing crawler IP-range JSON (G7 DNS-free path), additional cloud/CDN ranges,
  Spamhaus DROP/IPsum, and the FoxIO/peet.ws JA4 fingerprint DB. **WIRED #2**: `ip_reputation_refresh` now
  folds Oracle + DigitalOcean + Cloudflare + Fastly into the datacenter slice (stable official URLs, per-
  source floors, offline parser tests) on top of AWS+GCP+X4BNet — a ~60k-CIDR datacenter feed. Azure
  omitted (its Service-Tags JSON URL rotates weekly behind a portal redirect — needs a discovery step).
  The crawler-IP-range feed (the authoritative DNS-free consumer for `net.fake_declared_crawler`) and the
  JA4-DB hint-table expansion remain candidate (edge-side consumers).
- **2026-06-23 · arms-race loop tick 1 (gap-queue intake)** — mined TheGP/untidetect-tools,
  Everything-About-Captchas, Proxy-Providers-List + commercial anti-detect browsers (Multilogin/GoLogin/
  AdsPower/Dolphin-anty/Kameleo/Octo/BitBrowser/Linken Sphere/Bablosoft) + libraries. Cross-referenced vs
  current coverage. **Most commercial AD browsers hit the same canvas/WebGL/audio/font/WebRTC surfaces
  Kitsune already has coherence/artifact tells for** (the per-session floor), so they buy no new convict
  surface — EXCEPT specific features, now queued as **VERIFIED groundable gaps**: G8 (screenX/screenY
  coordinate coherence — a net-new surface; Bablosoft MouseEvent-Patcher), G9 (rebrowser-bot-detector
  coverage audit beyond cdp_runtime_enabled), G10 (mobile-behavioral FP gate). **New evaders for breadth**
  (caught by existing net tells, validate coverage): LightPanda (new lightweight engine class), got-scraping
  + CycleTLS (JS/Go TLS-impersonation HTTP clients) — none in the fleet. **Bablosoft PerfectCanvas**: naive
  (main-only) is already caught by `canvas_worker_vs_main`; a both-realm replay reaches the camoufox-class
  frontier (suspicious), not a new convict. **External-data-bound** (queue, not buildable): residential/
  mobile/ISP proxy detection + malware-fuelled RESIP (the Proxy-Providers-List categories → X2/X3/X8);
  CAPTCHA-solver traffic patterns (solver services are orthogonal to per-session FP detection). Loop closes
  G8→G10 + adds the breadth evaders on subsequent ticks.
- **2026-06-23 · arms-race loop tick 3 (closed G10 + missing-test audit)** — **G10 DONE** (mobile-biomech
  applicability gate, merged). **Missing-detection-test audit**: scored the full corpus vs the 100 active
  rules — 89 fire on a corpus evader, 11 do not (br.color_depth_anomaly, devicepixelratio_anomaly,
  languages_empty, mobile_no_touch, platform_empty, rfp_browser, screen_zero, voice_os_vs_ua,
  webgpu_vendor_vs_webgl, rep.datacenter_asn, rep.known_proxy_exit). **No missing-test gap**: all 11 already
  have engine-level firing tests (detector/tests/test_engine.py parametrised cases) + unit tests (rep.* in
  test_ip_reputation, rfp_browser in test_applicability). They are environment / degenerate-value / IP-rep
  tells the EVADER FLEET doesn't happen to trip (it isn't stripped/datacenter-hosted), which is expected —
  the corpus is the red-team ladder, not a coverage harness. No action; coverage is solid. **Next builds:**
  G9 (rebrowser-bot-detector leak audit — exposeFunction-binding + sourceURL leaks beyond cdp_runtime_enabled;
  groundable via a vanilla-Playwright positive vs patchright EVADES) and G8 (screen-coordinate coherence —
  net-new surface; build CORROBORATING + fullscreen-gated for FP-safety, since CDP Input.dispatchMouseEvent
  defaults screenX=clientX/screenY=clientY while a real windowed browser always has vertical chrome offset).
- **2026-06-23 · arms-race loop tick 5 (G8 grounded+deferred; SCAN — in-sandbox queue DRY)** — Grounded G8
  (CDP `page.mouse.move` → `screenX===clientX && screenY===clientY` with `isTrusted===true`, orthogonal to
  the coalesced tells) but DEFERRED it: corroborating-only + headless-gated + the headful frontier it'd
  corroborate is already `suspicious` → marginal value for a full collector/rule/matrix cascade (grounding
  captured in the G8 row so it isn't re-derived). External SCAN (2026 fingerprinting/bot-detection SOTA):
  every technique in active use — HTTP/2 settings fp, TLS+H2 matched against a known-browser DB, multi-signal
  "impossible combination" consistency checks, GPU-timing — maps to existing coverage (net.h2_*/JA4H,
  net.tls_vs_ua_browser, the coherence engine + prevalence); GPU-*timing* is jitter-unsound (like keystroke
  G3), not a coherence tell. No new groundable lead. **The in-sandbox groundable queue is DRY**: G10 + G9
  (binding leak) shipped; G8 grounded-but-marginal; everything remaining is external-data-bound (X1–X8:
  real proxy/RESIP egress, real-device DB, real-traffic prevalence, GreyNoise/crawler/JA4-DB feeds) or
  heavy coverage-breadth (LightPanda/got-scraping/CycleTLS evaders — same floors, no new convict surface).
  Per [[per-session-detection-saturated]], the loop has hit the saturation wall: future ticks should be
  SCAN-only (source genuinely-new external techniques) or wind down to a slower cadence — grinding marginal
  corroborating rules / redundant evaders is not worth the cost.
- **2026-06-23 · arms-race loop tick 6 (SCAN-only — queue still dry)** — Second consecutive dry scan, this
  time the EVASION-tooling angle (vs tick 5's detection-SOTA angle). Surfaced tools all map to existing
  coverage: patchright / playwright-stealth / puppeteer-extra-plugin-stealth (→ playwright-extra,
  stealth family), nodriver (→ evader). One genuinely new NAME — **SeleniumBase UC Mode** (Selenium +
  Cloudflare evasion + CDP-leak prevention + fingerprint patches) — but it is the same CDP-native-Selenium-
  with-stealth CLASS as the existing `undetected` / `selenium-driverless` evaders, so it buys NO new test
  surface (same per-session floor → caught by the same headless/CDP/coherence tells). The 2026 consensus
  itself restates Kitsune's thesis verbatim: "stealth only solves fingerprint-level detection, not IP
  reputation, TLS fingerprinting, or behavioral analysis" — i.e. the durable frontier is the external/wire/
  behavioral layers Kitsune already spans. No new groundable lead; in-sandbox queue remains DRY. The loop
  is in steady-state saturation — recommend winding the 4-min cadence down to SCAN-only weekly (or delete
  cron 2e89fb67; it auto-expires in ~7 days regardless).
- **2026-06-23 · commercial anti-detect browser coverage assessment (white-box + empirical)** — Evaluated
  the commercial class (Kameleo Chroma/Junglefox, Multilogin Mimic/Stalkfox, GoLogin Orbita, Octo, AdsPower
  SunBrowser, Dolphin{anty}). They are **engine-level (C++) Chromium/Firefox forks** — masking applied
  before any JS runs and consistent across main/worker/iframe realms — i.e. the **Camoufox class**, not the
  puppeteer-stealth class. White-box attempt on the OSS clone `itbrowser-net/undetectable-fingerprint-browser`:
  **dead end — it ships a prebuilt Windows .exe, no source** ("source uploaded gradually"); running an
  untrusted Windows binary in-sandbox is unsafe/infeasible. BUT the class is already characterized because
  **Camoufox (its OSS engine-level representative) is in the fleet**. Surface map vs coverage: canvas/WebGL/
  audio/fonts/timezone/languages — engine-level + **stable-per-profile** (real-device pool, not per-call
  noise) + all-realm → EVADES the JS-realm tells (`canvas_noise`, `*_worker_vs_main`, `fingerprint_unstable`)
  → reaches the documented `suspicious` frontier. TLS/JA4/HTTP-2 — they ARE real Chromium/Firefox → coherent
  → no tell (their strength). **The decisive convicting tell is the one their engine cannot reach: the
  kernel TCP/IP stack (`net.tcp_os_vs_ua` + `tcp_kernel` SYN fp).** EMPIRICAL PROOF in our own matrix:
  `camoufox-macos` (engine-level, spoofs OS→macOS on a Linux box) → **bot** via `net.tcp_os_vs_ua`;
  `camoufox-linux`/`camoufox-hardened` (engine-level, OS-coherent) → **suspicious**. Industry confirms (Google
  signup keys on the p0f TCP fingerprint as the decision point). So a multi-accounter running profiles that
  claim various OSes on one machine is convicted by `net.tcp_os_vs_ua` — the single highest-value tell vs this
  class, ALREADY shipped. The durable second axis is **coordination** (`fp_collision`/JA4-collision/
  `shared_real_ip`) — a fleet can't hide its shared infrastructure. **No new groundable convicting tell**: the
  OS-coherent engine-level browser is the saturation frontier (= Camoufox at suspicious); the convictable part
  (OS-spoof + coordination) is covered. The only residual path to convict an OS-coherent commercial browser is
  a Camoufox-class residual-leak hunt (frontier-by-definition) or external coordination data.
- **2026-06-24 · AI-agent + DDoS adversary frontiers (deep-dive intake)** — Two new groundable veins, the
  first non-saturated in-sandbox work in a while; full analysis in docs/adversary-emulation-roadmap.md.
  **AI agents** (FP-Agent arXiv 2605.01247 + architecture arXiv 2511.19477): the key finding INVERTS the
  worry — browser *fingerprints* have "limited discriminative power" for agents; the discriminator is
  BEHAVIORAL, strongest = mouse-trajectory. That is Kitsune's thesis exactly, and FP-Agent detects all 7
  agents where Cloudflare detects 1. Most agents (Browser-Use/Skyvern/Stagehand/Operator) drive via CDP →
  already caught by `cdp_runtime_enabled`/`__playwright__binding__`/coalesced. New groundable tells queued:
  G11 teleport-click (the #1 signal), G12 LLM think-time cadence (novel — FP-Agent didn't measure it), G13
  keystroke-interval floor, G14 scroll-teleport, G15 paste-input. Hard terminus = vision + real OS input
  (Computer Use): real trusted input beats the input-mechanic tells, but the COGNITIVE signature
  (think-time + teleport + no-exploratory-motion) survives — an LLM agent can't shed deliberation rhythm
  without losing its speed. **DDoS**: split is decisive — volumetric L3/4 (31 Tbps records) is an
  anycast/scrubbing infra problem, OUT of scope for a per-session detector. L7 is Kitsune's domain and
  already leads (H2FrameScanner: rapid-reset/CONTINUATION/control-flood — at the FRAME layer, below the
  request log where CONTINUATION hides). New L7 rungs: G16 slow-HTTP (clear gap, different mechanism), G17
  L7-flood-as-coordination (Kitsune-unique — an app-flood IS a coordination event). QUIC/HTTP-3 DoS =
  EXTERNAL/frontier (QUIC capture partly infra-blocked, ties to ADR-0005). Sequencing: G11 (teleport) +
  G16 (slow-HTTP) are the cleanest first bricks; G12 (think-time) + G17 (coordination-DDoS) are the
  highest-leverage/novel.
- **2026-06-24 · GitHub-topics fan-out scan (7 topics, 6 agents)** — fanned out research agents across
  `anti-detection` / `anti-detect` / `anti-bot` / `web-scraping` / `tls-fingerprint` / `antibot(s)`, deduped
  against the radar + the refuted/covered lists. **7 new GROUNDABLE leads** (the topic corpus re-opened the
  in-sandbox queue that was dry since tick 6): **G18** WebGL/WebGPU capability↔renderer-string coherence (the
  residual every source-level fork — CloakBrowser/BotBrowser — leaks; convergent across two independent
  agents; top pick), **G19** PoW/timed-compute↔declared-hardware-class, **G20** PQ-keyshare↔UA-version
  (`net.pq_keyshare_vs_ua`; convergent with the TLS agent), **G21** speechSynthesis-voices↔OS, **G22**
  WASM-CPU-arch↔platform, **G23** uTLS-preset CVE coherence breaks, **G24** client-timestamp↔server-clock.
  **Confirmed-covered (no new rule):** the "perfect TLS, zero JS-runtime" agent-fetch/azuretls case is
  already `network.browser_absent`; rebrowser/CDP-runtime-leak (re-surfaced by the scan) is the audited G9;
  maxTouchPoints↔UA is G1/G10. **Re-validated the thesis** (Akamai var-115 internal coherence check;
  ThreatMetrix self-report↔observed matrix) and routed ThreatMetrix biomech features + Akamai mobile MEMS-bias
  to external (real-corpus-bound). Sequencing: **G18** (GPU caps↔renderer) and **G20** (PQ keyshare) are the
  cleanest first bricks — both pure cross-layer incoherence, both fully in-sandbox-groundable by capturing
  real per-GPU caps tables / diffing impersonation-lib ClientHellos against the claimed UA.
- **2026-06-24 · /loop tick 1 (G18 grounding recon + G20 dedup)** — drained the top two topics-fan-out
  leads against the actual code (white-box, per [[white-box-anti-detect-source]]). **G20 was ALREADY
  SHIPPED** — the fan-out agents black-boxed the edge and re-proposed `net.tls_pq_keyshare_vs_ua` (edge
  `keyshare.go::HasPostQuantumKeyShare` + `tls_no_pq_keyshare`, UA-gated ≥Chrome 131; QUIC sibling retired
  as infra-blocked). Corrected the row to COVERED — no work. **G18 grounded-recon**: confirmed the EVADES
  surface (collectors read only the renderer STRING + WebGPU vendor-family, never capability values) and
  captured the in-sandbox SwiftShader software baseline (MAX_TEXTURE_SIZE 8192, MAX_VARYING_VECTORS 31,
  precision [127,127,23], WebGPU absent). Reframed G18 to its FP-safe core — *renderer string claims
  hardware but caps are software-class* — but the convicting THRESHOLD needs a real-hardware caps corpus
  (this sandbox has only SwiftShader), so G18 is partly capture-profile-bound. Next tick: either add the
  caps-capture instrumentation (additive) to prep a capture-profile run, or build a fully-self-contained
  lead (G24 timestamp↔clock is detector-only; G23 uTLS padding/ECH breaks are edge-local). Lesson: the
  fan-out leads must be white-boxed against the code before building — two of the top picks were already
  done or sandbox-bound.
- **2026-06-24 · /loop tick 3 (G13 SHIPPED — keystroke interval floor)** — first AI-agent (FP-Agent) rung
  grounded. EVADES-first proved the gap: a Playwright `delay:0` fast-type keeps entropy 0.766 (evades the
  0.15 entropy floor) while its median inter-key is 0.9 ms. Shipped `bh.keystroke_interval_floor` (median
  <30 ms, behavioral/corroborating) emitted by all three collectors via a shared `keystrokeIntervalMedian`;
  detector + collector CI green (376 detector / 73 collector); live end-to-end grounding confirms the rule
  fires on agent-speed typing and stays silent on a human-paced 140 ms session (FP-safe). Picked G13 over
  G11 (teleport-click) this tick because G11's zero-movement-click FPs on a stationary-cursor human (a
  corroborating-layer precision hit), whereas a <30 ms median keystroke has no human analog.
- **2026-06-24 · /loop tick 4 (G11 SHIPPED + G21 dedup)** — **G21 ALREADY COVERED** (`br.voices_empty` +
  active `br.voice_os_vs_ua`) — second fan-out duplicate after G20; corrected the row. **Shipped G11**
  (teleport-click, FP-Agent's #1 AI-agent signal): `bh.click_without_trajectory` — a trusted mouse-origin
  click (detail≥1) with ZERO total pointer movement, non-touch-gated. EVADES-first proved it: a CDP
  `Input.dispatchMouseEvent` click fired a trusted detail=1 click with 0 mousemove (vs 6 for a real
  move+click). Shipped behavioral/corroborating + experimental (residual FP = pre-positioned-cursor click,
  rare, can't convict alone). Emitted by demo.py (authoritative) + livepage probes.ts; engine + collector
  CI green. FP-reasoning that picked G11's strict form: a real mouse cursor entering/jittering the page
  emits mousemove first, so zero-TOTAL-movement-but-clicked is bot-specific (the earlier worry was about a
  weaker per-click gate). Two AI-agent rungs now shipped (G13 keystroke speed + G11 teleport-click); the
  remaining input rungs (G14 scroll-teleport, G15 paste) are FP-nuanced (scrollbar-drag / autofill).
- **2026-06-24 · /loop tick 5 (G16 detection core — slowloris scanner)** — pivoted off the FP-nuanced
  behavioral rungs (G12 reading-pause / G14 scrollbar-drag / G15 framework-value-set all FP on real users)
  to the clearest non-marginal gap: L7 slow-HTTP. Found the edge serves h2 **+ http/1.1** with a 15s
  ReadTimeout — it *survives* slowloris but emits no signal, and the h1 path (unlike h2's byte-tee'd
  countingConn) is unobserved. Built `fingerprint.SlowLorisScanner` (observe-only, deterministic,
  injected-clock): an incomplete request header (no CRLFCRLF) held past an age budget with only a trickle of
  bytes = the slowloris hold, separable from latency and oversized-header shapes. 6 tests; gofmt/vet/full
  edge suite green via Docker golang:1.26-alpine. Scoped to the detection CORE this tick — wiring (h1 conn
  wrapper + held-connection timer; these conns are sessionless) + a `net.slow_http_attack` rule + a
  slowhttptest grounding are next tick. First edge-layer / Go increment of this loop.
- **2026-06-24 · /loop tick 6 (G16 wiring is sessionless — loop wound down)** — confirmed the edge mints a
  session id ONLY inside `ServeHTTP`/`prepare(r,…)`, i.e. when a *complete* request reaches the handler. A
  slowloris connection never completes a request, so the entire request-driven signal pipeline has no path
  for it — wiring G16 needs a deliberate **connection-level** signal path (synthetic session ids for
  sessionless attacks, mint point, detector correlation). That is a design decision, not autonomous wiring.
  **Wound down the 4-min /loop (cron e459ff88 deleted).** Cleanly-autonomous-shippable queue is drained;
  what shipped this session: G11 (teleport-click), G13 (keystroke-interval floor), the live-panel surface
  maximization (~25 enumerated surfaces), the G16 slow-HTTP detection core, and G18-recon + G20/G21 dedups.
  **Remaining items are NOT autonomous-suitable** — each needs human-in-the-loop design or external data:
  G16-wiring (connection-level sessionless signal path) · G17 (coordination-DDoS wiring + fleet evader) ·
  G18-rule (real-GPU caps reference — capture-profile-bound) · G22 (real CPU corpus) · G12/G14/G15/G19/G23/
  G24 (FP-marginal on real users). Per [[per-session-detection-saturated]], grinding marginal rules is not
  worth it; resume with a deliberate design pass on G16-wiring or G17 when desired.

## Iteration log (continued)

- **2026-06-24 · X6 mobile touch-biomech — human baseline GROUNDED (4-angle dataset search + BrainRun analysis)**
  — fanned out 4 research agents (touch/swipe · mobile keystroke · motion-sensor · data-platform sweep) for
  real mobile behavioral-biometric data. All four independently converged on **BrainRun (Zenodo 2598135, CC0)**.
  Fetched it (CC0, 265MB) and analysed **161,780 real human swipes / 2,117 devices**: **`bh.uniform_velocity`
  is transferable to touch** (human velocity-CV p1=0.235 ≫ the 0.08 floor → FP-safe + headroom to ~0.15);
  **`bh.path_too_straight` is NOT** (human swipes inherently near-straight, median 0.993 → would FP >50%, the
  empirical proof behind G10's gate). Wrote `docs/mobile-biomech-grounding.md` (de-identified percentile
  aggregate only). Cataloged the permissive datasets (BrainRun/MEU-Mobile/Aalto-ITE CC0/CC-BY + HuMIdb gated).
  **Honest finding:** no public *labeled mobile-bot* corpus exists — the bot positive is self-generated
  (synthetic-swipe red-team). Remaining to ship: collector touch-trajectory capture (today `pts` is
  mousemove-only) + the synthetic-swipe positive. This moves X6 from fully-external to partially-unblocked.
- **2026-06-24 · X6 SHIPPED — mobile touch velocity-uniformity floor** — built on the BrainRun grounding:
  `bh.touch_uniform_velocity` (below 0.15 median per-swipe velocity-CV). Collector captures swipes via touch
  events (touchstart/touchmove/touchend — pointer events coalesce moves and drop pointerup for synthetic
  touch) in demo.py (authoritative) + livepage probes.ts; emits the median per-swipe CV. Grounded end-to-end
  through the real detector: a constant-velocity rAF replay (CV≈0.005) fires it, a varied/natural swipe
  (≈0.24-0.6) stays silent — and a *naive jittery CDP swipe* (CV≈0.24, ≈ the human 1st percentile) correctly
  does NOT fire, so the rule targets the too-perfect replay, not natural input. `path_too_straight` stays
  gated (proven un-transferable). 381 detector + 73 collector tests green; catalog/matrix regenerated. This
  is the first mobile-specific behavioral CONVICTION-layer tell (corroborating) — the rest of mobile
  behavioral detection (keystroke floor, trace_replay) was device-agnostic.
- **2026-06-24 · X6 mobile KEYSTROKE biomech grounded (MEU-Mobile, CC-BY)** — validated the device-agnostic
  keystroke floors (kept active on mobile by G10) against 2,856 real mobile keystroke records (MEU-Mobile
  KSD, UCI 399). Both are FP-safe on mobile with large margin: inter-key interval floor (30ms) vs human
  per-record median p1 **216ms** (~7×); entropy floor (0.15) vs human p1 **0.625** (~4×). No recalibration
  needed — the desktop floors are now grounded on mobile, not assumed. Displayed the inter-key-interval row
  (was scored-but-hidden). Gesture-typing (few keydowns, below the ≥4 gate) and autocomplete (single events)
  don't FP. Future headroom: a mobile-aware ~120ms interval floor would catch desktop-speed typing on a
  mobile session, but needs the free-text Aalto ITE set (7.3GB, CC-BY) to set safely — password data too narrow.
- **2026-06-24 · X6 mobile-aware keystroke floor SHIPPED (Aalto ITE, CC-BY, 42.3M keystrokes)** — pulled the
  7.3GB free-text set and analysed 849,909 real mobile typing sessions: per-session median inter-key p1=118ms;
  only **0.018%** of sessions median <80ms (vs 1.2% at 120ms). Shipped `bh.mobile_keystroke_interval_floor`
  (<80ms, mobile-gated, experimental) — catches a bot typing at DESKTOP speed (30-80ms) on a mobile session,
  the band the universal 30ms floor (G13) misses; self-gating (emitted only on mobile) so it never touches
  faster desktop typists. Grounded end-to-end: 55ms mobile typing fires it, 200ms (human) doesn't, 30ms floor
  stays silent at 55ms. Entropy floor re-confirmed FP-safe on free text (p1 0.699). Hold/dwell + flight time
  ungroundable from the processed log (one timestamp/press; raw with key-up is 65GB). Dataset deleted post-ship.

## Network / wire-layer surface audit (2026-06-25, 4-agent fan-out + industry-leader benchmark)

Grounded on the edge code first, then validated against Cloudflare / Akamai / DataDome / FingerprintJS /
GreyNoise / FoxIO JA4+ / peet.ws. **Verdict: at/near parity with the leaders on every *extractable* wire
signal + uniquely strong on the cross-layer incoherence thesis; the leaders' remaining edge is mostly DATA,
not signal.** Genuine un-extracted signals, mostly cheap (bytes the edge already captures):

| # | seam | gap | groundable? | note |
|---|---|---|---|---|
| N1 | network (TCP/IP) | **JA4T value-parsing**: MSS value + window-scale value + window/MSS ratio + p0f IP quirks (DF, IP-ID, ECN, ToS, SACK-perm, TCP-timestamps). Edge parses TTL+option-ORDER+window but discards the values. | **in-sandbox (cheapest)** — SYN bytes already captured; unlocks VPN/tunnel/mobile-from-MSS (wire proxy tell, no CIDR). **Corrects G4** ("JA4T covered" was wrong — values not captured). |
| N2 | network (TLS) | **Extension ORDER + GREASE placement** — JA4 sorts extensions; raw order captured as `tls_ext_order`. | ✅ CONVICTS (2026-06-25, within-session) — single-shot not viable (Chrome permutes per-conn), but that permutation IS the tell: `net.tls_ext_order_static_within_session` convicts a Chromium-JA4 session repeating ONE order across ≥2 conns. Red⇄blue grounded: go-tls KS_STATICEXT evader + tls_ext_order_test.go. |
| N3 | network (QUIC) | **QUIC transport_parameters (TLS ext 0x39)** — QUIC-stack fingerprint independent of inner TLS; raw order captured as `quic_transport_params`. | ⚠ EXTRACTED (display only) — conviction INFRA-BLOCKED (2026-06-25): same per-IP opportunistic QUIC-capture blocker that retired net.quic_*_vs_ua; revive when capture is per-connection w/ multi-packet reassembly. |
| N4 | network (HTTP/1.1) | **h1 header order + casing** + "refuses h2/h3 is itself a tell". We serve h1, fingerprint nothing. | **in-sandbox** — mirror JA4H order onto the h1 path. |
| N5 | network (TLS) | **CH micro-tells**: key_share share-vs-advertised, cert_compression list, padding/ECH presence (uTLS CVE family; extends G23). | ✅ SHIPPED 2026-06-25 (`tls_extras` signal + wire card, extract+display). Conviction NOT shippable: advertised==sent for all faithful clients → inert; advertised-side already = net.tls_pq_keyshare_vs_ua. |
| N6 | network (HTTP/3) | **H3 SETTINGS/QPACK fingerprint** (the h2-Akamai analog for h3). | **in-sandbox-ish** — edge runs an H3 server; frontier, no vendor ships it. |
| N7 | network (TLS/TCP) | **spoofable / handshake-completion** (GreyNoise) + **cipher-stunting / implausible-randomization-as-a-tell** (Akamai). | **in-sandbox** — cheap rules over data the edge sees. |
| NX | network (latency/IP) | JA4L latency-vs-geo (proxy-by-physics), JA4 prevalence ratios, ASN/named-proxy intel. | **external-data-bound** — RTT capture groundable, geo/prevalence conviction not. |
| N-OOS | — | JA4S / JA4X / JA4SSH / JARM — server-side / SSH / C2-infra hunting, not per-visitor web-bot. | out of scope. |

Sources: FoxIO JA4+ (blog.foxio.io/ja4t-tcp-fingerprinting, ja4+-network-fingerprinting); p0f v3 README; Fastly
Chrome-permutation; net4people #220; Scrapfly post-quantum-TLS + http2-http3-guide; BrowserLeaks /quic; QUIC
Hunter (PAM 2024, arXiv 2308.15841); Cloudflare ja4-signals + mitmengine; Akamai h2 fp (BH-EU-17); DataDome
TLS-fingerprinting; FingerprintJS osMismatch/VPN; GreyNoise GNQL; FP-Inconsistent IMC 2025.

**Cheapest highest-value first build: N1 (TCP/IP value-parsing → JA4T + p0f quirks)** — pure parsing of the
SYN already captured, no new infra, and it adds a wire-layer proxy/tunnel/mobile tell Kitsune only has via
CIDR lists today. Then N2 (TLS ext order) and N3 (QUIC transport params).

## Network-fingerprint grounding data (2026-06-25, 3-agent sourcing for N1-N7)

Datasets/ground-truth for grounding the wire-layer tells, license-verified on source. Discipline unchanged:
ship only de-identified aggregates / signature maps, never raw rows.

| source | grounds | access | licence | fetchable | use |
|---|---|---|---|---|---|
| **p0f v3 `p0f.fp`** | TCP SYN signature → OS + `[mtu]` MSS→link table | github.com/p0f/p0f `docs/p0f.fp` | **LGPL 2.1** | ✅ | JA4T/TCP-OS signature map + tunnel-MSS map, no raw traffic |
| **ValdikSS `p0f-mtu`** | MSS → VPN/tunnel type (WireGuard 1440/1420, OpenVPN ~1400/1369, PPPoE 1492, mobile 1280/1450, native 1460) | github.com/ValdikSS/p0f-mtu | **LGPL** | ✅ | grounds the N1 MSS→tunnel hint |
| **uTLS `u_parrots.go`** | exact per-browser ClientHello (cipher/ext ORDER, groups, sigalgs, key_share, GREASE) for ~40 Chrome/FF/Safari/Edge versions | github.com/refraction-networking/utls | **BSD-3** | ✅ | ground truth for N2 (ext order) + N5; "this JA4/order = Chrome 131" |
| **curl-impersonate `tests/signatures`** | per-browser TLS+h2 templates (2nd source vs uTLS) | github.com/lwthiker/curl-impersonate | **MIT** | ✅ | corroborates N2/N5 + h2 |
| **FoxIO ja4db** (`ja4db.com/api/read`, `ja4plus-mapping.csv`) | JA4/JA4H/JA4T → app/library/device/OS (+ malware col) | ja4db.com / repo | **BSD-3 (JA4-TLS part)**; JA4+ suite FoxIO-1.1 (non-monetization) | ⚠ (egress-gated; csv in repo ✅) | fingerprint→client map + prevalence |
| **QUIC Hunter** (`quic-hunter/libraries`, PAM 2024) | QUIC transport-param ORDER → 18 QUIC libs (quiche/ngtcp2/quic-go/cronet) | github.com/quic-hunter/libraries | no LICENSE → extract heuristics only | ⚠ | grounds N3 (QUIC transport params) |
| **Akamai h2 (BH-EU-17)** + lwthiker ts1 | h2 Akamai-fp + pseudo-header order per browser | blackhat.com / github.com/lwthiker/ts1 | cite / OSS | ✅ | grounds h2 + N4 reference values |
| **Satori `tcp.xml`** | TCP→OS 2nd source incl. IoT/printer/phone device class | github.com/xnih/satori | **GPLv2** | ✅ | corroborates p0f; device-class |
| Zardaxt | (TCP-OS) | github.com/NikolaiT/zardaxt | **proprietary — DO NOT use** | ❌ | reference only |

**Highest-value, ready now:** p0f.fp + ValdikSS p0f-mtu (LGPL) ground N1's JA4T-OS + MSS-tunnel with zero raw
traffic; uTLS u_parrots (BSD) + curl-impersonate (MIT) are the exact-byte browser templates that ground
N2 (extension order) and N5; QUIC Hunter encodes the N3 transport-param→stack logic.

- **2026-06-25 · N1 SHIPPED (TCP/IP value-parsing → JA4T + display)** — edge now parses MSS value,
  window-scale value, SACK-permitted, timestamps, DF, ECN, and the raw option kinds from the SYN it already
  captures; computes the FoxIO **JA4T** (`window_options_mss_scale`); stores+emits `network.ja4t`; `/inspect`
  + the live wire panel display **JA4T (TCP/IP)** with a derived MSS→tunnel hint. Pure parse of bytes already
  in hand; edge + detector tests green. No new convicting rule (MSS-tunnel is informational — legit VPN/mobile
  users have low MSS; the OS-coherence tell `net.tcp_os_vs_ua` already convicts). Next: N2 (TLS ext order), N3
  (QUIC transport params), N5 (CH micro-tells), N4 (h1 header order).
- **2026-06-25 · N2/N3/N4 SHIPPED (wire-fingerprint extraction + live display)** — continued the network
  surface buildout, each extract-on-edge → display-in-wire-panel: **N2** TLS extension + cipher ORDER
  (`tls_ext_order`/`tls_cipher_order`, GREASE→"g" — the raw order JA4 sorts away); **N3** QUIC transport
  parameters (`quic_transport_params`, ext-0x39 id order, GREASE 31N+27→"g" — the QUIC-stack tell no vendor
  ships); **N4** negotiated HTTP version (`http_version` — "downgrade to h1 is a dead evasion"). All shown in
  the wire panel + machine-readable `window.ksResult.wire`. Grounding templates recorded (uTLS/curl-impersonate
  for N2; QUIC Hunter for N3). Edge (6 pkgs) + detector tests green. **Deferred (documented, not built):** N4's
  raw h1 header ORDER + CASING needs teeing decrypted h1 bytes, which breaks the stdlib's `*tls.Conn` h2/ALPN
  detection — a dedicated custom h1 reader, out of scope for a safe increment. N5 (CH micro-tells:
  key_share-share-vs-advertised, cert_compression, padding/ECH) still queued. Convicting rules for N2-N4 (e.g.
  Chrome-impossible ext order, TP-stack-vs-UA) are follow-ups needing the per-browser template DBs + within-
  session order history; this wave is extraction + display (the "every fingerprint, shown" goal).
- **2026-06-25 · N5 SHIPPED (CH micro-tells extraction + live display)** — edge now parses the per-stack
  ClientHello surface JA4 sorts away: the **key_share groups actually SENT** (ext 0x33) vs merely advertised in
  `supported_groups`, the **certificate_compression** algorithms (ext 0x1b: zlib/brotli/zstd), and **ECH / ALPS
  / padding** presence. Surfaced as a `tls_extras` signal and a "TLS extras" wire-panel card (+ `/inspect`). The
  sharp tell it unlocks: real Chrome 131+ ships BOTH an X25519 and an X25519MLKEM768 key_share, whereas a pinned
  or pre-PQ template advertises the PQ group but sends only the X25519 share — `HasPQKeyShareSent()` reads the
  share, not the advertisement. Grounding templates: uTLS `u_parrots.go` + curl-impersonate signatures (exact
  per-browser key_share/cert-comp/ext bytes). Extraction + display only — the `key_share-advertised-not-sent`
  conviction needs the per-browser template DBs and is queued for the rules wave. Edge (6 pkgs) + detector (382
  tests, 97.22%) green. **This completes the N1-N5 wire-fingerprint extraction wave**; the remaining radar
  network rows are N4-raw-h1 (deferred: needs a custom h1 reader), N6 (H3 SETTINGS/QPACK), N7 (handshake-
  completion / cipher-stunting rules), and the convicting-rules follow-up wave.
- **2026-06-25 · Rules-wave conviction grounding pass (N2/N3/N5 → NO new convicting rule; saturation
  confirmed)** — investigated turning the N2/N3/N5 *extraction* signals into *convicting* coherence rules
  against the repo's grounding bar (real-browser NEGATIVE + live evader POSITIVE, FP-safe). Verdicts:
  - **N2 (TLS extension order) — NOT shippable (marginal + FP-risky).** The premise that "uTLS/curl-impersonate
    emit a fixed order" has DECAYED: both now SHUFFLE the ClientHello extension order PER CONNECTION (uTLS
    `ShuffleChromeTLSExtensions`, curl-impersonate verified — 6 distinct orders / 6 requests). So (a) a
    "static order = impostor" within-session rule has no honest positive (every real Chrome-faking tool
    permutes), and (b) a single-shot "order ∉ legal Chrome set" rule FPs on Chrome's own per-connection
    permutations. The only *unique* catch over the existing `net.tls_vs_ua_browser` (JA4 engine) +
    `net.tls_grease_vs_ua` (GREASE) would be a stack that GREASEs AND matches Chrome's cipher JA4 yet emits a
    non-Chrome order — which no faithful tool produces. Corrected the decayed premise in `edge/.../grease.go`.
    **SUPERSEDED (same day, see next entry):** the per-connection shuffle is itself the WITHIN-SESSION tell —
    built the faithful evader + grounded `net.tls_ext_order_static_within_session`.
  - **N5 (key_share advertised-but-not-sent) — NOT shippable (inert, no honest positive).** A faithful
    template SENDS what it ADVERTISES, so `HasPostQuantumKeyShare()` (advertised) == `HasPQKeyShareSent()`
    (sent) for every real client and every current evader; "advertised but not sent" is a pathological
    hand-broken state nothing in the fleet produces. An active rule on it would be an unexercised
    never-firing convicting rule (the anti-pattern). The advertised-side tell is already covered by
    `net.tls_pq_keyshare_vs_ua`. The `HasPQKeyShareSent()` extraction stays (cheap, future-proof).
  - **N3 (QUIC transport-param order vs claimed stack) — INFRA-BLOCKED.** Same blocker that RETIRED
    `net.quic_grease_vs_ua` / `net.quic_pq_keyshare_vs_ua`: the QUIC Initial capture is opportunistic and
    per-IP-attributed (`FingerprintByIP`), so it cannot be grounded FP-safe against a confirmed real-Chromium
    QUIC positive in-sandbox. REVIVE together with those rules when the QUIC capture is per-CONNECTION
    attributed with full multi-packet CRYPTO reassembly.
  Net: the conviction wave hits the documented per-session saturation — the extraction (N1-N5) was the right
  scope; the marginal order/micro-tell convictions are either redundant, inert, or infra-blocked. The one
  honest path to a NEW N2 positive is a faithful red-team evader that GREASEs + matches Chrome ciphers but
  pins a non-permuting order (a real anti-detect failure mode) — queued as a faithful-evader task, not a
  rule to arm speculatively.
- **2026-06-25 · N2 CONVICTS via red⇄blue — net.tls_ext_order_static_within_session (ruleset 0.74.50)** — took
  the honest path the grounding pass identified, and it reframed N2 from "not shippable" to a clean
  within-session conviction. KEY INSIGHT: the per-connection extension permutation that KILLED the single-shot
  rule is exactly what makes a WITHIN-SESSION rule FP-safe — a real Chromium (BoringSSL) emits a DIFFERENT
  `tls_ext_order` on every connection, so a Chromium-JA4 session that repeats ONE order across ≥2 connections
  cannot be a real Chrome. This is the FIFTH member of the within-session-invariant family (JA4 / h2 / IP / UA
  / now ext-order), and the INVERSE shape: the siblings convict on >1 distinct value (a fixed field rotated),
  this convicts on exactly 1 where a real client MUST vary. RED: `go-tls KS_STATICEXT` builds a Chrome-131
  hello ONCE (current ciphers, GREASE, PQ key share, extension SET) and replays it across 3 connections under
  one ks_sid (a faithful pinned-template move). BLUE: `detector ingest._annotate_ext_order_static` derives
  `tls_ext_order_static` over the pre-collapse per-connection history, gated to a Chromium `ja4_browser_hint`
  (Firefox/Safari don't permute → never convict); rule = `present`, weight 0.6, active. GROUNDED BOTH WAYS:
  in-process (deterministic, in CI) `edge tls_ext_order_test.go` proves (a) real Chrome (uTLS HelloChrome_131,
  the permuter) emits 3 DISTINCT orders → FP-safe negative, (b) a reused pinned current-Chrome spec emits a
  byte-IDENTICAL order while still GREASEing + carrying a PQ key share → the static order is the sole residual
  tell, (c) the hello's JA4 hints `chrome` so the gate opens; AND LIVE — the evader pins a STALE non-shuffling
  `HelloChrome_102` (GREASEs + Chrome ciphers → JA4 hints chrome, but no permutation) and the rebuilt
  edge→detector stack convicted it (label bot, score 0.996), captured as `corpus/sessions/go-tls-static-ext.json`
  and frozen by `test_lit_rule_captures`. The live run also CAUGHT A BUG the in-process test could not:
  reusing one `ClientHelloSpec` across full handshakes fails after conn 0 (consumed key shares) — so the evader
  uses a non-shuffling preset per connection instead. 5 detector ingest tests cover positive /
  permutation-negative / gate-off / single-conn / sticky. Edge + detector (388 tests, 97.25%) green.
  NON-REDUNDANT: JA4 sorts extensions, so a pinned-order template keeps one JA4_b and can hold h2/IP/UA fixed —
  every other tell stays silent while the un-permuted order is the only contradiction. Net: N2 is the first of
  the N-series extractions to become a CONVICTION (N3 still QUIC-infra-blocked; N5 still inert). The arms-race
  ladder gained a rung on BOTH sides.
- **2026-06-25 · Research SCAN cycle (mid-2025→mid-2026 sweep) — ONE new groundable lead (G25), else
  saturation confirmed** — fanned out across USENIX/NDSS/CCS/IMC/PETS + arXiv + industry (Cloudflare/FoxIO/
  DataDome/Fingerprint/GreyNoise), deduped against the coverage list AND this radar. Verdict: the in-sandbox
  frontier is near-saturated; the genuinely-novel remainder is external-data-bound — with exactly one
  self-contained exception worth grounding:
  - **G25 (NEW, GROUNDABLE) → `net.web_bot_auth_unsigned_claimed_agent`** (network/coherence, convicting).
    **Web Bot Auth** (IETF `draft-meunier-web-bot-auth-architecture`, chartered WG; Cloudflare edge-live
    2026-03) lets a legitimate agent (GPTBot/ClaudeBot/Operator/Perplexity/Google/CommonCrawl) cryptographically
    sign the request via RFC 9421 HTTP Message Signatures + Ed25519, attaching `Signature-Agent` /
    `Signature-Input` (`tag="web-bot-auth"`, `keyid`=JWK thumbprint, `created`/`expires`) / `Signature`; the
    verifier fetches the JWKS at `/.well-known/http-message-signatures-directory` ONCE, then validates OFFLINE.
    The Kitsune incoherence: a request whose UA/Client-Hints CLAIM a known agent identity but carry NO valid
    signature (missing headers / expired or future `created` / `keyid` not in the directory / failing
    verification) is an impostor — a cross-layer coherence tell next to `net.h2_header_order_vs_ua`; a VALID
    signature is a clean benign-actor allow-list (complements the FCrDNS check). GROUNDABLE in-sandbox: pure
    RFC 9421/Ed25519 header crypto — publish a test JWKS at a local well-known URL, a faithful signed-agent
    evader vs a "claims-ClaudeBot-but-unsigned" evader; no real traffic/proxy/device data. Lib:
    github.com/cloudflare/web-bot-auth. Cites: blog.cloudflare.com/web-bot-auth/;
    developers.cloudflare.com/bots/reference/bot-verification/web-bot-auth/. **This cycle's recommended PICK.**
  - **X9 (external) → PAT / PACT** (Apple Private Access Tokens; cross-vendor Private Access Control Tokens,
    Cloudflare+Chrome/Firefox/Edge/Shopify, 2026-06). Privacy-Pass human/device attestation without a CAPTCHA;
    detection-relevant inverse = absent/malformed token. EXTERNAL: needs the four-party attester+issuer infra
    to mint/validate real tokens. Cites: blog.cloudflare.com/private-attestation-token-device-posture/;
    datadome.co PAT analysis.
  - **X10 (external) → "Detecting Bot Detection" prevalence corpus** (arXiv 2606.14525) — 132 JS props in 3
    confidence tiers + honeypot-property probing; the SIGNALS are already covered, the value is a prevalence
    PRIOR for weight calibration (measurement data, not a new rule). Sibling to the Berke/Intoli calibration
    feeds.
  Confirms-coverage (not novel): FP-Inconsistent IMC 2025 final numbers (44.95–48.11% evasion cut at 96.84%
  TNR vs 20 commercial services — strongest external validation of the incoherence thesis); CloakBrowser /
  Wayfern / BotBrowser source-level Chromium forks (the G18 renderer-string-vs-stale-caps frontier);
  TLS-bad-bot ML (arXiv 2602.09606, JA4 already shipped); DataDome behavioral-biomech + Cloudflare v9 ML
  score. Net: SCAN done — queue is dry except G25; G25 is the one new in-sandbox rung (cryptographic
  claimed-identity-vs-proof coherence — dead-on the thesis), recommended as the next red⇄blue PUMP.
- **2026-06-25 · G25 SHIPPED — net.web_bot_auth_invalid (ruleset 0.74.51), red⇄blue grounded** — PUMPed the
  one new groundable lead from today's SCAN. KEY FP-SAFETY REFINEMENT vs the lead's "unsigned-claimed-agent"
  framing: convicting an UNSIGNED claimed-agent would FP on the many legit agents that don't sign yet (Web Bot
  Auth is new), so the rule instead convicts only a Web Bot Auth signature that is PRESENT and FAILS Ed25519
  verification against a key we HOLD (forged / tampered / wrong-@authority / replayed past expires). That is
  FP-safe by construction — a real signer always emits a valid, in-window signature for its own key — and is
  the cryptographic analog of net.fake_declared_crawler. An UNKNOWN keyid is unjudgeable and never convicts; a
  VALID signature emits the benign network.web_bot_auth_verified marker. BLUE: edge/internal/webbotauth
  reconstructs the RFC 9421 signature base ("@authority"[+"signature-agent"] + @signature-params) and verifies
  Ed25519; wired in proxy.prepare. RED: go-tls KS_WEBBOTAUTH — `valid` signs a fresh signature (→ verified,
  no fire), default replays the draft's own expired example (→ web_bot_auth_invalid, label bot). GROUNDED two
  ways: (1) in-process against the draft Appendix A.2.2 OFFICIAL Ed25519 test vector + the RFC 7638 thumbprint
  (edge webbotauth_test.go — the published signature verifies, tampered/expired/wrong-authority/unknown-key
  all handled correctly); (2) LIVE through the rebuilt edge→detector stack (replay convicts, valid verifies),
  frozen as corpus/sessions/go-tls-web-bot-auth.json in test_lit_rule_captures. Edge (7 pkgs) + detector (392)
  + harness (249) green. PRODUCTION wires the real agent directories (each agent's
  /.well-known/http-message-signatures-directory JWKS) — the lab seeds the RFC test key. The first detection
  built on a 2026 standard, and dead-on the incoherence thesis: claimed identity vs cryptographic proof.
- **2026-06-25 · G25 COMPLETED — verified-agent allow-list (Label.verified)** — closed the benign half of
  G25. A request that cryptographically PROVES its agent identity (a VALID Web Bot Auth signature →
  network.web_bot_auth_verified) is now ALLOW-LISTED as the new Label.verified, overriding the bot verdict its
  honest automation signals (no JS, non-browser HTTP/2) would otherwise earn — the whole point of the standard
  is to separate good bots from bad. scoring.verified_agent gates it (verified marker AND no web_bot_auth_invalid
  forgery tell); detector.score applies the override; the live page renders a jade "VERIFIED · allow-listed"
  stamp. HONEST SECURITY FRAMING (the evasion the allow-list enables): an allow-list is only as strong as the
  signing key's secrecy. The lab seeds the PUBLIC RFC 9421 test key, so in-sandbox ANY client can sign a valid
  signature and mint a 'verified' agent — the go-tls KS_WEBBOTAUTH=valid evader IS that bypass, and the page
  says so. Production trusts real agent directories whose private keys are secret. Grounded by test_scoring
  (verified_agent: allow-lists a valid sig, never a forgery) + test_detector (verified→Label.verified,
  forged→bot). Detector 394 green. The convicting net.web_bot_auth_invalid (forgery) + the verified allow-list
  are the two halves of the same RFC 9421 coherence check: claimed identity vs cryptographic proof, both ways.
