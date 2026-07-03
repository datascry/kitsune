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

**Status tags:** `lead` = sourced, not yet pumped · `validated` = analysed, no new rule (existing tell
already covers it) · `done` = shipped rule, grounded red⇄blue + FP-swept · `external` = routed to the
external-data-bound queue (needs real data the lab can't self-generate) · `resolved` = closed with no
rule (redundant / FP-unsafe / superseded by another rung). Shipped rows name their rule id inline.

| # | seam | technique / signal | evasion / tool | source | status |
|---|---|---|---|---|---|
| G1 | coherence (spatial) | **Cross-attribute inconsistency within one fingerprint** — e.g. a device class (UA/model) paired with a screen resolution/DPR that device never ships, an iPhone with an impossible screen geometry. FP-Inconsistent's *spatial* rules cut DataDome evasion 48% / BotD 45%. | anti-detect browsers that spoof attributes independently (browserforge/fingerprint-injector mix fields) | FP-Inconsistent, ACM **IMC 2025** (DOI 10.1145/3730567.3732919; arXiv 2406.07647) | **done** → `br.mobile_no_touch` (phone/tablet UA + maxTouchPoints 0; device-DB-free, FP-safe). Screen-geometry coherence needs a real-device resolution DB → see X5. |
| G2 | red-team / behavioral | **GAN/diffusion mouse-trajectory synthesis** as a faithful evader to pressure-test the behavioral floor + the coalesced-sample terminus. | DMTG (diffusion, arXiv 2410.18233), BeCAPTCHA-Mouse GAN, SapiAgent | DMTG; BeCAPTCHA-Mouse (Pattern Recognition 2022) | **validated** — the convicting tell (`bh.synthetic_no_coalesced` / `br.coalesced_untrusted`) is STRUCTURAL (getCoalescedEvents length + isTrusted), so trajectory SHAPE quality is orthogonal: a DMTG path injected via CDP still has `coalescedMax<=1` → caught. Already grounded (stealth `KS_BEHAVE`); escape is real XTEST/uinput (privilege-gated terminus). DMTG validates Kitsune's structural-over-shape bet. No new rule. **2026-06-28 — the terminus is BUILT (red uplevel):** stealth `KS_REAL_INPUT` drives the cursor via real X-server input (XTEST/xdotool, unprivileged under xvfb) instead of CDP/JS, so the browser COALESCES for real. GROUNDED live: 92 pointermoves, **max coalesced batch 12, isTrusted=true, ZERO JS tamper** → behavioral layer score **0, no behavioral contradictions** (beats `bh.synthetic_no_coalesced` + `bh.click_without_trajectory` + the biomech floors honestly). Decisive contrast: `HUMAN_MOUSE` (JS bezier via CDP) STILL trips `bh.synthetic_no_coalesced`; `KS_REAL_INPUT` does not. Per-node `KS_NODE_SEED` gives a fleet distinct trajectories (no trace_collision / template_similarity). The per-session behavioral layer is now a SOLVED red problem given OS-input access — the durable signal moves to coordination/cross-layer (the thesis), and the residual blue tells are automation/environment (container-bound: webdriver/CDP, webgl_software/voices/media → real-GPU/display, external). |
| G3 | behavioral | **Keystroke-dynamics detection** (timing + key-identity); cGAN can synthesize evasions. | cGAN keystroke synthesis (arXiv 2212.08445) | IFIP SEC 2024 (DOI 10.1007/978-3-031-65175-5_30) | **not groundable** — keystroke timing is jitter-unsound across instances (no clone/structural channel, unlike mouse coalesced; memory-confirmed). `bh.keystroke_entropy_floor` stays corroborating; cGAN defeats shape/timing and there is no structural keystroke analog of coalesced sampling. |
| G6 | coherence (mobile) | **Mobile GPU-family ↔ OS coherence** — real mobile GPUs surface as enumerable WebGL renderer strings (Qualcomm **Adreno**, ARM **Mali** ⟹ Android; **"Apple GPU"** ⟹ Apple iOS/macOS). An Android UA with renderer "Apple GPU", or an iPhone UA with "Adreno"/"Mali", is a clean cross-layer incoherence — the mobile extension of `webgl_os_vs_ua` (which today only knows desktop Direct3D/Metal/Mesa). | a desktop-faking-mobile that fakes a mobile renderer to dodge `webgl_software` but mismatches the GPU family | Castle.io WebGL-renderer fingerprinting (mobile GPU enumeration), mobile-research pass 2026-06-21 | **resolved — no new rule.** Probed (confirm-EVADES-first): the **Apple-GPU** half is ALREADY caught — `_webgl_os` maps `Apple`→macOS, so an Android UA + "Apple GPU" already fires `webgl_os_vs_ua`. The **Adreno/Mali→Android** half is **FP-UNSAFE**: real **Windows-on-ARM (Snapdragon) ships Adreno** and **ChromeOS ships Mali** (both verified to currently — correctly — not fire), so mapping them to Android would FP on real devices → that direction is external (needs a device-class disambiguator, see X5). The only FP-safe sliver (Adreno/Mali under an Apple UA) is redundant — a Chromium-faking-iPhone already trips `apple_ua_nonwebkit`/`safari_ua_no_webkit_api`/`mobile_no_touch`. |
| G5 | environment (mobile) | **WebView / in-app-browser surface** — the `wv` UA token (durable through Android 16 UA reduction; standalone Chrome lacks it) + per-app IAB tokens (`FB_IAB`/`FBAN`) + the `X-Requested-With` package header (Android WebView). | host app overrides UA via `setUserAgentString` (all UA signals spoofable) | Android Devs Blog (Dec 2024); Tiwari et al. arXiv 2208.01968; mobiforge | **lead (weak/corroborating)** — WebView is ALSO the dominant *legit* mobile surface (in-app browsers), so presence is NOT convicting; only a non-UA-vs-UA mismatch (`X-Requested-With` present but UA omits `wv`) is a tell, and that's niche + needs real app traffic → mostly X7 |
| G4 | network (JA4+) | **JA4+ suite coverage audit.** | uTLS/curl-impersonate pin JA4; JA4T harder (real stack) | FoxIO JA4 (github.com/FoxIO-LLC/ja4), JA4T blog (blog.foxio.io/ja4t-tcp-fingerprinting) | **covered** — JA4 (ja4a/b/c) + JA4H (`net.h2_header_order_vs_ua`) present; JA4T's detection value = TCP-OS coherence (`tcp_kernel` SYN fp + `net.tcp_os_vs_ua`); JA4L (latency/hop-distance) marginal for bot-detection + latency-external; JA4S is server-side (N/A for a client detector). No groundable gap. **Superseded by N1 (JA4T value-parsing):** the "JA4T covered" verdict was wrong — the edge parsed TTL/option-order/window but DISCARDED the values, so the FoxIO JA4T (`window_options_mss_scale`) was not actually computed. N1 corrected this and SHIPPED it (`network.ja4t` emitted + displayed); see the N rows below. |
| G7 | coherence (network ⇄ UA) | **FCrDNS declared-crawler verification** — a UA declaring a known crawler (Googlebot/Bingbot/Applebot/…) whose connecting IP fails forward-confirmed reverse DNS (no PTR, PTR under no official suffix, or no forward-confirm) is an impersonator. FCrDNS is the crawlers' OWN documented verification method, so a real crawler always confirms; transient DNS errors abstain (FP-safe). | a non-crawler IP wearing a crawler UA (fake-Googlebot scrapers — a common allow-list bypass) | GreyNoise GNQL gap analysis (`actor` + `metadata.rdns_validated` facets); Google/Bing crawler-verification docs | **done (experimental)** → edge `fingerprint.VerifyCrawler` emits `network.fake_declared_crawler` → `net.fake_declared_crawler` (coherence, convicting, w0.8). Unit-grounded (confirm / impersonator / NXDOMAIN / abstain) + a stub-resolver prepare test + a detector conviction test. EXPERIMENTAL until a live resolver grounds it in deployment (edge ships net.DefaultResolver; the FP-safe-by-construction logic mirrors the crawlers' own method). Adjacent to (not core to) the real-browser-coherence thesis — targets the declared-crawler-spoof abuse case. **2026-06-28: added a DNS-free CIDR path** — `CrawlerVerifier` checks Google/Bing's published official IP ranges (deploy-refreshed via `edge/cmd/crawler-refresh`) FIRST, falling back to FCrDNS; GROUNDED live (real Googlebot/bingbot confirm, impostor IPs convict with zero DNS). See the crawler-CIDR row in the data table. |
| G8 | artifact (input) | **screenX/screenY ↔ clientX/clientY pointer-coordinate coherence** — a real pointer event's `screenX/screenY` equals `clientX/clientY` plus the window's screen offset (and `screen` bounds); a CDP/`Input.dispatchMouseEvent`-injected event or a MouseEvent-Patcher shim commonly sets `screenX===clientX` or `0`, an impossible geometry. The collector today captures only `clientX/clientY` — a NET-NEW surface. | Bablosoft **MouseEvent-Patcher** (screenX/screenY spoof), CDP `Input.dispatchMouseEvent` synthetic events | TheGP/untidetect-tools (MouseEvent-Patcher); CDP Input domain | **grounded, deferred (marginal value).** Live-confirmed (Playwright 1.48): a CDP `page.mouse.move` event has `screenX===clientX && screenY===clientY` AND `isTrusted===true` — so it is ORTHOGONAL to the coalesced/untrusted tells (a genuinely new CDP-mouse-injection surface). FP-safe form: fire only when `screen.height - innerHeight > 50` (a real WINDOWED browser always has top chrome → `screenY>clientY`; fullscreen and headless both have `innerHeight≈screen.height` → gated out). BUT the value is low: (1) corroborating-only (chromeless-popup FP rules out convicting), (2) headless — the common bot — is gated out, (3) the headful frontier it would corroborate (camoufox-headful/patchright-headful) is ALREADY `suspicious`, so it changes no label. A full collector+rule+catalog/matrix cascade for a marginal corroborating tell. DEFER until headful-CDP-injection is a priority or it can convict; the grounding is captured here so the loop need not re-derive it. |
| G9 | automation (CDP) | **rebrowser-bot-detector coverage audit** — its checks (Runtime.enable leak, `dummyFn`/exposeFunction binding leak, sourceURL leak, useless-main-world exec). `br.cdp_runtime_enabled` covers the Runtime.enable leak; verify the binding/sourceURL leaks are covered or add them. | rebrowser-patches / patchright (the leaks they specifically fix) | TheGP/untidetect-tools (rebrowser-bot-detector, brotector) | **partial — audited + 1 leak closed.** Mapped all 10 rebrowser tests: COVERED — runtimeEnableLeak (`cdp_runtime_enabled`), navigatorWebdriver (`webdriver_present`), bypassCsp (`csp_bypassed`), headless UA. CLOSED this tick — exposeFunction/binding leak: live-grounded that real Playwright (1.48, via addInitScript) exposes `window.__playwright__binding__` while NONE of the previously-listed automation globals were present (vanilla Playwright was EVADING the `automation_globals` surface); added it to both collectors → trips the existing `br.automation_globals` (no new rule). `__pwInitScripts` is NOT in current Playwright (ungrounded — not added). REMAINING (low value / FP-risk): sourceUrlLeak (puppeteer-specific, `__puppeteer_evaluation_script__` already listed), viewport 800x600/1280x720 (FP-risky), Chrome-for-Testing UA (niche). |
| G10 | behavioral (mobile FP fix) | **Gate the mouse-biomech floors off real touch devices** — power-law/straightness/velocity-CV/coalesced-absent are mouse-calibrated and false-positive on a real phone swipe (caps at suspicious, not bot, but still a precision hit). Emit `browser.is_mobile` (UA mobile token AND maxTouchPoints>0) and drop the mouse-motion floors in applicability when set (keep trace_replay — device-agnostic). | n/a (a precision/FP fix, not an evasion) | mobile-vs-desktop behavioral analysis 2026-06-23 | **done** → collector emits `browser.is_mobile` (mobile UA token AND maxTouchPoints>0); `applicability._MOBILE_BIOMECH_NA` drops `bh.input_entropy_floor` / `power_law_violation` / `path_too_straight` / `uniform_velocity` / `synthetic_no_coalesced` for a mobile session (trace_replay + keystroke floor stay). Tests: desktop fires the floors, mobile drops them, mobile still convicts on trace_replay. |
| G11 | behavioral (AI agent) | **Teleport-click — a click with no preceding pointer trajectory.** FP-Agent's #1 discriminative signal: ALL tested AI agents (Operator/Atlas, Claude-for-Chrome, Comet, Manus, Browser-Use, Skyvern) exhibit ZERO continuous mouse movement — a single mousemove→immediate click, or none. Today Kitsune's biomech needs motion to score; a teleport leaves none. | LLM browser agents (CDP/vision-driven, all teleport to targets) | FP-Agent (arXiv 2605.01247); see docs/adversary-emulation-roadmap.md | **done** → `bh.click_without_trajectory` (behavioral/corroborating, experimental, w0.5): a trusted, mouse-origin (detail≥1) click with ZERO total pointer movement, gated to non-touch (maxTouchPoints==0). EVADES-first GROUNDED: a CDP `Input.dispatchMouseEvent` click fired a trusted detail=1 click with 0 mousemove/pointermove, vs 6 for a real move+click. Emitted by demo.py (authoritative) + livepage probes.ts; engine test. Residual FP = a desktop user with a pre-positioned cursor clicking without moving (rare) → corroborating-only + experimental, can't convict alone. |
| G12 | behavioral (AI agent) | **LLM think-time cadence** — agents run a perceive→reason→act loop at ~3–8 s/step (LLM inference + render); humans act in sub-second bursts. A multi-second deliberation gap then a burst of action is an intrinsic LLM-agent temporal signature. FP-Agent did NOT measure this (they did within-action timing) → novel, open signal. | any LLM-in-the-loop agent | architecture paper (arXiv 2511.19477, "6.8 s/step"); FP-Agent gap | **done** → `bh.action_cadence_deliberative` (behavioral/corroborating, experimental, w0.5). The collector builds a high-level action timeline (clicks + the start of each >1s typing burst) and emits the boolean when >=5 actions have a median interval in [2.5s,15s] AND CV < 0.35 (metronomic). Needed a LONG-HORIZON capture fix: the collectors posted once early (before a 25s cadence accumulates), so added a bounded one-shot re-post when the 5th action lands (demo.py + collect.ts). GROUNDED live (Playwright through the edge): a metronomic ~5s-cadence run FIRES; an irregular-gap human control does NOT. Calibrate-clean (0/800 — browserforge has no interaction timeline). The real `agent` evader (claude -p brain) exhibits this cadence intrinsically. Durable — an agent can't shed deliberation rhythm without giving up its speed. |
| G13 | behavioral (AI agent) | **Keystroke inter-key floor** — agents type at 1–5 ms inter-key (Browser-Use 5.31 ms, Manus 1.39 ms) vs humans 100+ ms; renderer buffering leaks the real timing even when delays are added. | LLM agents (keystroke-modality) | FP-Agent (typing-behavior features) | **done** → `bh.keystroke_interval_floor` (median inter-key < 30 ms, behavioral/corroborating, w0.55). EVADES-first GROUNDED: a Playwright `delay:0` fast-type measured entropy **0.766** (ABOVE the 0.15 entropy floor → evades `bh.keystroke_entropy_floor`) but median inter-key **0.9 ms** → caught. Emitted by all three collectors (demo.py authoritative + collect.ts + livepage probes.ts via `keystrokeIntervalMedian`); engine + unit tests; live end-to-end grounding through the real detector: the fast-type session fires the rule (entropy floor silent), a human-paced 140 ms session does NOT (FP-safe). Orthogonal to the entropy floor by construction. |
| G14 | behavioral (AI agent) | **Scroll-teleport** — 0 ms zero-duration `scrollIntoView` jumps (DOM agents) or multi-burst viewport exploration (vision agents) vs human smooth continuous scroll. NEW capture surface (Kitsune does not record scroll today). | DOM/vision agents | FP-Agent (scroll-behavior features) | **done** → `bh.scroll_teleport` (behavioral/corroborating, experimental, w0.5). Added a scroll-event capture surface to all three collectors (max single scroll-event delta + wheel count + scroll-key use); emits the boolean when a >=800px jump lands in one scroll event with ZERO wheel events, no scroll-key, on a non-touch session. GROUNDED live confirm-evades-first: a Playwright window.scrollTo(0,3000) FIRES; a mouse.wheel scroll (many small deltas) does NOT. Calibrate-clean (0/600 — browserforge has no scroll timeline). Residual FP (anchor-link jump / scrollbar drag) → corroborating, never convicts alone. Reuses the G12 one-shot re-post pattern (the scroll may land after the early post). |
| G15 | behavioral (AI agent) | **Paste/programmatic input** — a form field value that changes with NO per-key events (Atlas/ChatGPT/Comet paste; Claude change-event-only). | LLM agents (paste-modality) | FP-Agent (typing-modality) | **done** → `bh.input_via_paste` (behavioral/corroborating, experimental, w0.5). All three collectors track, per form field, a keydown / trusted paste / value-change (input/change); a CHANGED field that got neither keydown nor trusted paste is programmatic injection (paste / CDP insertText / fill() / .value set). Server-prefill excluded (fires no input/change during the session). GROUNDED live confirm-evades-first: Playwright page.fill() FIRES; page.type() (real keydowns) does NOT. Calibrate-clean (0/600). Residual FP = browser autofill → corroborating, never convicts alone. Reuses the G12 one-shot re-post. |
| G16 | network (DDoS L7) | **Slow-HTTP attacks** (slowloris / slow-POST / slow-read) — exhaust the connection table by HOLDING connections with partial requests / tiny windows. A DIFFERENT mechanism from the frame-floods Kitsune already catches; the edge's H2FrameScanner won't see it (it needs connection-duration/incompleteness accounting). | slowhttptest, Torshammer, slowloris | DDoS deep-dive 2026; see docs/adversary-emulation-roadmap.md | **in progress — detection core built.** Edge serves h2 + http/1.1 with a 15s `ReadTimeout` (it *survives* slowloris but emits no signal; the h1 path isn't byte-tee'd like h2). Built `fingerprint.SlowLorisScanner` (observe-only, mirrors H2FrameScanner): times request-header arrival, fires `SlowRequest` when the header block is still incomplete (no CRLFCRLF) past an age budget with only a trickle of bytes — distinct from latency (delays the whole burst, not its completion) and oversized headers (byte-budget excludes them). 6 deterministic injected-clock tests; gofmt/vet/edge-suite green. The H2 slow-header analogue is already `ContinuationFlood`. **done (wired + live-grounded).** The edge now runs its OWN accept loop (`edge/internal/proxy/h1serve.go`) because the stdlib `http.Server` reserves ALPN `http/1.1` from `TLSNextProto` (`validNextProto` returns false for it) — so a `serveH1` takeover via that map is silently ignored (the trap that cost the first wiring attempt). The loop dispatches h2→`serveH2`, everything else→`serveH1`, which wraps the decrypted conn in a `slowConn` that tees request-header bytes through the `SlowLorisScanner` and, on teardown of a connection held past the budget on an incomplete header, mints a SYNTHETIC session (slowloris conns are sessionless) carrying `network.slow_http_attack` + `observed_ip` → rule **`net.slow_http_attack`** (active, w0.9, automation). The `observed_ip` is what lets a slowloris FLEET fold into the G17 L7-flood attribution (`_has_dos_tell` already recognises `slow_http_attack`). Grounded LIVE: new evader **`evaders/slow-http`** (a fleet of ALPN-http/1.1 connections dribbling incomplete headers) → 4 held connections produced 4 detector sessions each firing `net.slow_http_attack`, verdict **bot 0.99**; normal h1 (200/1.1) and h2 (200/2) traffic unaffected. Edge suite (vet + all pkgs) + detector engine test green; catalog regenerated. |
| G17 | network (DDoS ⇄ coordination) | **L7-flood-as-coordination** — an application-layer HTTP flood from a botnet looks like N clients per-connection; the DDoS signature is the AGGREGATE (lockstep timing + shared JA4/fingerprint across the flood sources). That IS Kitsune's coordination scorer. The bot↔DDoS convergence: a fleet can't hide, scraping or flooding. | coordinated HTTP floods (MHDDoS-class fleets) | DDoS deep-dive 2026 | **done** → wired the coordination scorer (`harness/coordination.py`) as the L7-flood attributor: a new ambiguous **flood-shape** signal (`_FLOOD_MIN_ORIGINS=6` — a large lockstep cluster across many distinct origins) that convicts only when corroborated by a non-browser tool JA4, a **DoS tell** (`_has_dos_tell` — the G16/H2FrameScanner `h2_rapid_reset`/`continuation`/`control`/`madeyoureset` + forward-wired `slow_http_attack`), an automation tell, or datacenter/abuse IP-rep. `FleetVerdict.l7_flood` marks the attribution. Grounded red⇄blue: Skulk `httpflood` tier (8 no-JS tool sources, one flood-tool JA4, lockstep, distinct residential origins, NO per-node binding) → scenario `fleet-httpflood` convicts `fleet` on the tool JA4 ALONE (no datacenter flag needed), while the FP control `legit-flash-crowd` (6 real browsers, same aggregate shape, residential, no corroborator) caps at **candidate**. coordination-eval gate stays precision/recall **1.0**; harness+fleet ruff/mypy/pytest green. Highest-leverage DDoS angle, shipped. |
| G18 | coherence (GPU) | **WebGL/WebGPU capability ↔ renderer-string coherence** — source-level forks repaint the `UNMASKED_RENDERER`/adapter-vendor STRING but leave the real silicon's `getShaderPrecisionFormat`, `MAX_TEXTURE_SIZE`/max-varying-vectors, and the WebGPU `limits`(~40 correlated numbers)+`features` set keyed to the actual GPU. A renderer string whose capability profile belongs to a different GPU is a within-fingerprint incoherence. Kitsune has the WebGPU **vendor-family** hook (`webgpu_vendor_vs_webgl`) but reads no capability values. Live instance: CloakBrowser #294 (string claims RTX 5090, caps are RTX 3060). DrawnApart timed-GPU is the timing complement (you can fake the string, not the execution-unit throughput). | CloakBrowser/BotBrowser/fingerprint-chromium (seed-spoof the string); any source-level fork | botbrowser.io/en/blog/webgpu-fingerprinting; github.com/CloakHQ/CloakBrowser/issues/294; prescience-data/dark-knowledge (DrawnApart); topics fan-out 2026-06-24 | **done** → `br.webgl_renderer_caps_mismatch` (coherence, convicting). The collector now captures the capability fingerprint (`webgl_caps` + `webgl_max_texture`, main realm); the rule fires when the renderer string names a recent HIGH-END discrete GPU (RTX / Radeon RX 6000+ / Apple M-series / Intel Arc) yet `MAX_TEXTURE_SIZE < 16384` — below the floor every such GPU exposes. FP-safe by the high-end-string scoping: a real RTX/Apple-M/Arc is always >=16384 (never fires); an honest software renderer NAMES itself (SwiftShader/llvmpipe → caught by `webgl_software`) so its string never matches the high-end pattern; a real low-end/mobile GPU at 8192 has a low-end string, not 'RTX 4090', so it's out of scope. The only thing that trips it is a spoofed high-end renderer string over a backend (software or lesser GPU) whose caps betray the lie. GROUNDED on the captured SwiftShader baseline (`MAX_TEXTURE_SIZE=8192`) vs the universal >=16384 of recent hardware; browserforge calibration carries the renderer string but not the live caps probe, so promotion can't raise its legit flag rate. Increment 1 (caps capture + display + this software-vs-high-end tell); the broader renderer↔caps profile match across more GPU tiers is a follow-up still needing a real-GPU caps corpus (capture-profile-bound). |
| G19 | behavioral (compute-class) | **Timed-compute / PoW ↔ declared-hardware coherence** — a lightweight client-side timed-compute (PoW) challenge's solve speed implies a compute class; cross-check against `hardwareConcurrency`/`deviceMemory`/UA. Catches a datacenter solver posing as a low-end mobile. A temporal/compute axis static FP can't see. | non-browser/emulated solvers (Kasada KPSDK-class); datacenter scrapers spoofing a weak device | capjs.js.org (Cap GPU-resistant time-lock); lktop/kpsdk (Kasada); blog.send.win headless-detection guide; topics fan-out 2026-06-24 | **external-data-bound** (routed to queue 2026-06-28) → the discriminator (a solve-speed implying a compute class that CONTRADICTS the declared device) needs a per-device-class PoW-timing BASELINE the sandbox cannot self-generate: one host = no device diversity, and `performance.now()` is Spectre-coarsened. Without the real-device baseline a timing rule FPs on a throttled/slow real phone or a fast desktop. Ship the PoW probe once real-device timing baselines exist (the rule logic is clear; only the calibration is external). |
| G20 | network (TLS) | **Post-quantum keyshare ↔ UA-version coherence** (`net.pq_keyshare_vs_ua`) — by 2026 ~57% of real browser ClientHellos carry an `X25519MLKEM768` hybrid keyshare (Chrome 124+, FF 132+, Apple Oct 2025), adding ~1088 B and pushing the CH past one TCP segment. Stale impersonation profiles omit it or mis-order `supported_groups`/`key_share` under a modern-Chrome UA — a contradiction that fires BEFORE the first HTTP byte. Sits right next to `net.h2_unknown_vs_ua`. | curl_cffi (old profiles), wreq/rquest, httpmorph (no PQ), anything pinned to a stale Chrome | scrapfly.io/blog/posts/post-quantum-tls-bot-detection; lexiforest/curl_cffi; arman-bd/httpmorph; topics fan-out 2026-06-24 | **ALREADY COVERED (fan-out duplicate).** The TLS path is SHIPPED: edge `reverseproxy.go` emits `network.tls_no_pq_keyshare` when `chromeUAExpectsPQ(ua)` (UA Chrome ≥131) and the ClientHello's `supported_groups` lacks X25519MLKEM768 (0x11EC) / X25519Kyber768Draft00 (0x6399) — see `fingerprint/keyshare.go::HasPostQuantumKeyShare` — wired to the active rule **`net.tls_pq_keyshare_vs_ua`**. The QUIC sibling (`net.quic_pq_keyshare_vs_ua`) was RETIRED (the QUIC ClientHello capture is infra-blocked: an MLKEM keyshare makes the hello multi-packet and the opportunistic capture misses the fragment → FP on real Chrome). The JS analog is `br.engine_feature_vs_ua`. The fan-out agents black-boxed the edge and missed all three. No new work. |
| G21 | coherence (environment) | **speechSynthesis voices ↔ OS** — `speechSynthesis.getVoices()` returns an OS-bundled, OS-specific voice set (Microsoft/Apple/Google families); an empty list under a Windows/macOS UA (headless Linux) or a voice set that mismatches the claimed OS is incoherent. Cheap, in-page. | headless Chromium claiming a desktop OS; anti-detect browser that forgets to spoof voices | scrapfly speech-synthesis-fingerprinting; scrapfly/Antibot-Detector; adryfish/fingerprint-chromium; topics fan-out 2026-06-24 | **ALREADY COVERED (fan-out duplicate).** Both halves are shipped: `br.voices_empty` (no TTS voices under a desktop UA — headless/container, environment, w0.5) and the active `br.voice_os_vs_ua` (coherence, w0.75: "Installed TTS voices imply an OS that contradicts the UA platform", reads `browser.voice_os_hint` vs `browser.ua_platform`). The fan-out agents black-boxed the registry and missed both. No new work. |
| G22 | coherence (hardware) | **WASM/SIMD CPU-microarchitecture ↔ claimed platform** — a WASM probe measuring NEON vs SSE/AVX availability / register width runs BELOW the JS shim every spoofer patches; cross-check the inferred CPU arch against the UA/WebGL/WebGPU platform story (e.g. WASM says Apple-ARM but UA/WebGL claim x86 Windows). Defeats engine-fork browsers that beat every JS-visible check. | engine-fork anti-detect browsers (Wayfern/BotBrowser); cross-arch emulation/VM hosting | TheGP/untidetect-tools; arxiv 2509.09950; scrappey WASM-fingerprinting; topics fan-out 2026-06-24 | **external-data-bound / not in-sandbox-structural** (routed 2026-06-28) → WASM is deterministic across CPU arch BY SPEC: it cannot STRUCTURALLY reveal NEON-vs-SSE (the whole point of WASM portability). Only a timing micro-benchmark can infer arch, which is (a) noisy under Spectre timer-coarsening and (b) needs real-device per-arch baselines to set an FP-safe band — external. No clean in-sandbox structural rule exists; routed to the queue rather than ship a noisy timing heuristic. |
| G23 | network (TLS) | **uTLS preset coherence breaks** — (1) `HelloChrome_120` omits the `padding` extension real Chrome adds when the CH is <512 B → a single-packet length tell; (2) presets hardcode the AES cipher pref but randomize the ECH cipher → ~50 % outer-vs-inner ChaCha20/AES mismatch real Chrome never produces (CVE-2026-26995 / -27017). uTLS is already an evader fixture. | uTLS-based stealth clients pinned to a fixed `HelloChrome_*` preset | scrapfly PQ-TLS disclosure; topics fan-out 2026-06-24 | **covered + external residual** (routed 2026-06-28) → the STALE-preset case (the common uTLS evasion) is ALREADY SHIPPED as `net.tls_pq_keyshare_vs_ua` (G20): a HelloChrome pinned below Chrome 131 lacks X25519MLKEM768 and is convicted pre-HTTP. The residuals are external-data-bound + FP-risky: modern Chrome+PQ exceeds 512B so rarely pads (the padding tell barely applies), the padding/ECH bands need a real-Chrome TLS baseline to set FP-safely (cf. the v0.74.32/34 QUIC-capture retirements that FP'd real Chrome), and ECH inner-cipher inspection needs server-side ECH-decryption infra. Do not ship a patent-adjacent, FP-risky TLS rule ungrounded; routed to the queue. |
| G24 | coherence (temporal) | **Client-timestamp ↔ server-clock coherence** — cross-check client-reported event timestamps against the detector's own ingest time AND the `performance.now()` time-origin; a replayed/synthetic sensor payload desyncs these (DataDome's own "fake-vs-real timestamp" check). The detector already holds both clocks. | replayed/forwarded sensor payloads; relay/token-replay clients | joekav/SlideCaptcha (DataDome); topics fan-out 2026-06-24 | **external-data-bound** (routed 2026-06-28) → a client-vs-server clock drift is dominated by real users with badly-set clocks, so the FP-safe band needs a real-traffic clock-skew DISTRIBUTION the sandbox cannot self-generate (browserforge/Intoli carry no client clock). The synthetic-replay sub-case is already covered by `bh.trace_replay_within_session` (the trace axis). A convicting clock rule without real-skew calibration would FP every wrong-clock user; routed to the queue. |
| G26 | network (JA4 threat intel) | **JA4 → known-client enrichment as a coherence input** — the on-thesis slice of "JA4/JA3 threat intel." A blocklist of malware JA4s is the off-thesis bad-signal denylist Kitsune exists to beat (evadable by fingerprint rotation, FP-prone via JA4 collision); the VALUE is JA4→client identity used cross-layer. The lazy-scraper gap: `net.tls_vs_ua_browser` reads the JS `browser.ua_browser`, absent for a no-JS client, so a curl/Go/Python scraper spoofing a browser UA in the HTTP *header* over its default TLS stack evaded it. | curl / Go net/http / Python urllib / requests with a spoofed browser UA (the default-TLS + fake-UA lazy scraper); NOT the high-fidelity impersonators (curl-impersonate/uTLS emit a Chrome-identical JA4 — out of scope by design) | abuse.ch SSLBL (JA3 feed retired — skip JA3); ja4db.com (FoxIO community DB, free-use OK, cleanroom); self-generated from the evader fleet | **done** → `net.ja4_tool_vs_ua` (coherence, w0.75, active). Captured live tool JA4s through the edge (curl `t13d3012h2_1d37bd780c83`, Go `t13d131100_f57a46bbacb6`, Python `t13d171100_ab0a1bf427ad`); added a `Client` hint field → edge emits `network.ja4_client_hint` + a new `network.ua_header_browser` (UA family parsed edge-side, available for no-JS clients). Rule fires when both present (disjoint vocabularies → not_equal ≡ tool-JA4 wearing a browser UA). GROUNDED live confirm-evades-first: curl+Chrome-UA evaded (ja4_browser_hint=None) → now FIRES; curl+honest-UA + real browser do NOT. Calibrate clean (browserforge has no JA4 → 0 FP). External feed (full ja4db/threat import) stays queued — long-tail mappings need real traffic to FP-validate (JA4 collisions). |
| G25 | network (IPv6 origin unit) | **The "distinct source IP" unit is wrong for IPv6.** Every coordination binding (fp/trace/ticket collision, IP-spread) gates on ">= 2 DISTINCT observed IPs", and the rate gate keys per IP. On IPv6 the address is the wrong unit: a subscriber owns a whole /64 (often /56) and mints unlimited /128s for free (SLAAC + RFC 4941 privacy addresses rotate hourly). Raw /128 counting both **false-fires** (one real user's hourly privacy rotation looks like a multi-IP fleet) and is **evadable** (rate-limit bypass by spraying /128s; faking IP spread). JA4 itself is transport-agnostic — identical on v4/v6 — so the fix is purely the IP-keyed logic. | a fleet rotating /128s inside one /64 to bypass per-IP rate limits / fake spread; a real user's RFC 4941 rotation (the FP side) | IPv6 v4-vs-v6 JA4 analysis 2026-06-27 (in-session); RFC 4941 (privacy addrs); RFC 6177 (/56–/64 allocation) | **done** → `coordination._ip_origin` folds every observed_ip to its ORIGIN (IPv4 address / IPv6 /64) at every distinct-IP counting site (fp/trace/ticket collision, `_distinct_origins`, `_collision_clusters`); `arena/rate.go` `clientIP` keys per /64 origin (+ fixed the bracketed-IPv6 `net.SplitHostPort` parse the old `LastIndexByte(':')` mangled); Skulk `ipv6-rotate` strategy (cloned fleet spraying /128s across a few /64s). GROUNDED live: 6 /128s across 2 /64s → `fleet 1.00` with `distinct_observed_ips=2` (folded from 6 — the spray bought no spread, conviction held); 4 /128s within ONE /64 → `candidate 0.52`, `distinct_observed_ips=1`, no fp-collision (a single subscriber isn't a coordination fleet — the FP boundary, and without the fold those 4 would have read as 4 IPs → false `fleet`). Go + harness + fleet suites green. |

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
| **Google/Bing crawler IP-range JSON** | G7 (FCrDNS — DNS-free CIDR path) | `developers.google.com/static/search/apis/ipranges/googlebot.json`, `bing.com/toolbox/bingbot.json` | public (Google/MS authoritative) | ✅ live-parsed 2026-06-28: Googlebot 315 prefixes, bingbot 28 | **WIRED** → built the edge-side CIDR deploy-refresh: `edge/cmd/crawler-refresh` fetches both feeds into `KITSUNE_CRAWLER_CIDR_DIR` (floor-guarded google≥20/bing≥10); the edge loads them (`fingerprint.LoadCrawlerCIDR`) and `CrawlerVerifier.Verify` does the DNS-free CIDR check FIRST, falling back to FCrDNS when no feed covers the crawler (Applebot/Yandex/Baidu). Feeds ship EMPTY (a stale snapshot must never convict a new real crawler IP) → no mount = unchanged FCrDNS behaviour; a deploy refresh activates the DNS-free conviction. GROUNDED live (resolver nil): real Googlebot/bingbot IPs confirm, non-Google/non-Bing IPs wearing those UAs are convicted with zero DNS. This is the reusable edge-side CIDR-refresh mechanism (future edge CIDR feeds plug in the same way). |
| **Azure / Oracle / DigitalOcean / Cloudflare / Fastly ranges** | X4 (IP-rep datacenter) | Oracle `public_ip_ranges.json`, DO `digitalocean.com/geo/google.csv`, Cloudflare `/ips-v4`+`/ips-v6`, Fastly `api.fastly.com/public-ip-list`; Azure Service-Tags (rotating URL) | public | ✅ Oracle/DO/Cloudflare/Fastly stable; Azure rotates | **WIRED** (Oracle/DO/Cloudflare/Fastly → `ip_reputation_refresh` datacenter, per-source floors). Azure needs a discovery step for its rotating Service-Tags URL → candidate. |
| **Spamhaus DROP + IPsum** | NEW `is_abuse_listed` rep dimension | `spamhaus.org/drop/drop_v4.json`, `raw.githubusercontent.com/stamparm/ipsum/master/levels/4.txt` | **DROP free-to-use** (verified at source); **IPsum = Unlicense / public-domain** (verified at source) | ✅ public, daily (live-parsed 2026-06-28: DROP 1698 CIDRs, IPsum-L4 7140 IPs → 8837 abuse entries) | **WIRED** → a THIRD reputation list `abuse_cidrs.txt` (distinct from datacenter/proxy: hijacked/criminal netblocks + multiply-blocklisted IPs) → `reputation.is_abuse_listed` → rule `rep.abuse_listed` (corroborating) + the coordination corroborator `_has_ip_reputation_flag`. `ip_reputation_refresh` fetches both at deploy (output uncommitted, seed ships empty); floor-guarded (DROP≥200, IPsum≥500). Real-data parsers grounded; calibrate-clean (no IP in browserforge). |
| **FoxIO ja4db** `ja4plus-mapping.csv` (JA4 → client) | net.ja4_tool_vs_ua coverage + net.tls_vs_ua_browser precision | raw GitHub `FoxIO-LLC/ja4/main/ja4plus-mapping.csv` | **base JA4 = BSD-3-Clause, patent-free** (verified at source: "FoxIO does not have patent claims") — the `ja4` column is all Kitsune uses; JA4+ extension columns (License 1.1) are NOT used | ✅ HTTP 200 (35 ja4 rows, curated) | **WIRED** → expanded `ja4_hints.json` with 10 non-browser library prefixes (Python/Go/WinINET → `net.ja4_tool_vs_ua`) + 4 real browser no-SNI variants (Chromium/Firefox/Safari → `net.tls_vs_ua_browser`). KEY: C2 frameworks inherit their HTTP library's JA4 (Sliver=Go `t13d190900_9dc949149365`, Cobalt Strike=WinINET `t12d190800_d83cc789557e`), so the LIBRARY hint catches the beacon-wearing-a-browser-UA for free — threat intel the on-thesis way, no malware blocklist. No tool↔browser prefix collision; unit-grounded (the established ja4db-reference pattern). Malware-SPECIFIC JA4s (IcedID, SoftEther, bare Cobalt-Strike variants) NOT shipped — a blocklist needs real-traffic FP validation. |
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
- **Chained tool stacks are counterproductive, not a new frontier (2026-07-02, GROUNDED live).** Built the
  `evaders/chain-mitm` harness (a uTLS MITM front + a real browser proxying through it — the hazetunnel+camoufox
  / Ulixee-Hero shape) and drove the `stealth` evader through it vs. direct. Every chain config INCREASED
  detection: a matched-engine Chrome front adds `net.h2_unknown_vs_ua` (the Go-H2 seam; network 0.60→0.84), a
  mismatched Firefox front detonates FOUR tells at once (`net.tls_vs_ua_browser` + `net.tls_grease_vs_ua` +
  `net.tls_pq_keyshare_vs_ua` + `net.h2_unknown_vs_ua`; network →0.98). A real browser is already its own best
  network layer, so a forging front can only add the seam BETWEEN two tools — the thesis in miniature. The
  dominant conviction is always the browser layer (environment floor + automation), and even `FLOOR_SPOOF`
  (fakes voices/devices) stays `bot 0.996` (the spoof is caught by coherence). **No new rule** — the coherence
  matrix HELD against a real MITM chain. Single-session evasion is bounded by real hardware + a single coherent
  runtime (camoufox), NOT by tool-chaining; the frontier is environmental/behavioral (external), not integrative.
- **The single-session WALL, pinned (2026-07-02, GROUNDED live).** Drove the maximal COHERENT stack — camoufox
  (`KS_HARDENED` engine-spoof + `KS_LINUX` coherent OS + `KS_NOTOUCH`) with a clean behavioral layer — to
  **`suspicious` score 0.473, conviction_score 0.0, network 0.0**. Everything spoofable is solved: the network
  is a perfect real-Firefox wire (Gecko, no tells), camoufox speaks no CDP so there are ZERO automation
  convictions, and real XTEST input zeroes the behavioral layer (grounded separately on stealth: 95
  pointermoves, coalesced batch 8, `isTrusted` → `bh.synthetic_no_coalesced` silent, behavioral 0). The ENTIRE
  residual is four CORROBORATING environment-floor tells, each requiring real hardware: `br.webgl2_missing`
  (real GPU), `br.voices_empty` (real OS TTS), `br.media_devices_empty` (real audio/video), `br.webrtc_unavailable`
  (real network path). Faking them doesn't work — `FLOOR_SPOOF` (fakes voices+devices) stays `bot 0.996` because
  the spoof is caught by coherence. So the best single-session evader reaches `suspicious`-with-zero-convictions
  and is held there ONLY by the environment floor: the last mile is "run on real hardware," the economic bind —
  not any spoofable value, and not a cleverer tool chain. **The fusion is now BUILT + grounded in ONE runtime**
  (camoufox `KS_REAL_INPUT`: headful on Xvfb + XTEST input via xdotool): 92 pointermoves, coalesced batch 6,
  `isTrusted` → network 0.0 + behavioral 0.0 + conviction 0.0, `suspicious` 0.455, residual = exactly three
  environment-floor tells (`br.voices_empty` + `br.media_devices_empty` + `br.webrtc_unavailable`). The maximal
  coherent single-session stack is one engine on real hardware — not a chain.
- **CORRECTION (2026-07-02): the environment floor is PROVISIONABLE in a Docker container → `human`.** An
  earlier claim that the floor is a hard "real hardware" wall was WRONG. Adding a real environment to the
  camoufox container (`KS_PROVISION`: PulseAudio null-sink/source over an ANONYMOUS-auth unix socket so the
  root browser connects — the fix for the earlier `pulse-access` barrier — + speech-dispatcher/espeak voices;
  headful Xvfb already supplies WebGL) silenced `br.media_devices_empty` and `br.voices_empty` COHERENTLY (real
  native enumeration, not the JS fake coherence catches). The fully coherent + provisioned stack (camoufox
  HARDENED+LINUX+NOTOUCH + real XTEST input + provisioned audio/voices) scored **`human` 0.300, conviction 0.0,
  network 0, behavioral 0** — only `br.webrtc_unavailable` remained, and THAT is a STUN-egress limit of this
  sandbox (no outbound internet for a reflexive ICE candidate; Chromium gathered WebRTC in the SAME container,
  and a local STUN/coturn flips it), not a container impossibility. The deeper truth is better than the wall
  claim: a fully coherent + provisioned runtime IS a real desktop browser and CORRECTLY scores human — the
  detector isn't tricked, it declines to convict something with no incoherence left. The thesis holds (no
  conviction without incoherence); "become a real browser" is a provisioning task, achievable in a container,
  not a hardware wall. The JS-SPOOF vs PROVISION split still stands: spoofing the floor is caught (`FLOOR_SPOOF`
  → bot 0.996); provisioning it is coherent → human.
- **Provisioning extends to FLEETS — a diversified provisioned fleet evades coordination too (2026-07-02,
  GROUNDED live).** Ran a 3-node cloned-`KS_PROVISION` camoufox fleet through the detector + live coordination
  scorer. Each node scored `human 0.30`; the coordination verdict was **`candidate` (NOT `fleet`)** — "shared
  JA4 + JS divergence / IP spread but NO convicting coordination signal." A hypothesised "cloned-environment
  collision" was DISPROVEN as-is: camoufox already DIVERSIFIES the capturable per-node attributes — `fp_hash`
  3/3 distinct, `webgl_renderer` randomised per node (Intel HD / Intel HD / NVIDIA GTX 980), `hardware_concurrency`
  2/3, traces distinct/None — so no fp/trace collision; and the one genuinely-cloned resource (the identical
  espeak voice LIST + null-sink device labels across identical containers) is NOT captured as a coordination
  signal (`voice_os_hint`=None; there is no `voices_hash`). Distinct container IPs + no corroboration (clean
  camoufox, private IPs) → capped at candidate, indistinguishable from a real Firefox cohort. So provisioning
  lets a well-built fleet evade BOTH layers in-sandbox; the residual is the known EXTERNAL lever (IP reputation
  on real datacenter/proxy egress). **A `voices_hash` collision rung was considered and REJECTED as off-thesis.**
  The intuition (cluster on a shared TTS voice-set) fails the premise that makes every EXISTING collision key
  valid: `_fp_collision`/`_trace_collision` work because the value is HIGH-ENTROPY, so a collision across distinct
  IPs "cannot be organic (real machines each hash differently)." A voice set is LOW-ENTROPY — every user of the
  same OS+browser shares it — so a `voices_hash` collision IS organic (any two Windows users collide). That is a
  shared-VALUE signal, not an INCOHERENCE signal — exactly the "bad signal" the whole project exists to avoid.
  Corroboration-gating would hide the residential FP but not fix the category error (a datacenter VDI farm of
  identical real machines would still collide), and the corroborator (datacenter IP) IS already the real signal,
  making the rung redundant. Correct conclusion: a well-built provisioned + diversified fleet on distinct real IPs
  is genuinely indistinguishable from N real users — the coordination wall is EXTERNAL IP reputation, and there is
  no clean in-sandbox rung. Do NOT build a cloned-environment collision key; it is off-thesis.
- **Coherent OS spoofing is bounded by the TCP option ORDER — the one OS tell a browser can't forge
  (2026-07-02, GROUNDED live).** Ran camoufox `KS_MACOS` (a coherent macOS profile) on the Linux container:
  the browser story is spoofable (UA/platform/CH-UA/oscpu), but three things leak. (1) target-OS PHYSICAL
  markers: `br.macos_dpr1` (no Retina DPR) + `br.font_mac_internal` (real fonts aren't macOS system fonts) —
  macOS is a HARD target; Windows is more forgiving (generic DPR, Direct3D renderer, spoofable fonts). (2) the
  environment floor + behavioral — both provisionable (`KS_PROVISION` + `KS_REAL_INPUT`, proven above). (3) the
  WALL: **`net.tcp_os_vs_ua`** — `tcp_kernel=linux` (`ja4t=64240_2-4-8-1-3_1460_7`) vs the darwin UA. Verified
  the obvious evasion is DEAD: `ClassifyTCPOS` (edge `fingerprint/tcpip.go`) keys ONLY on the TCP option order
  (`mss,sack…`→linux, `mss,nop,ws,nop,nop,ts…`→darwin, `…,sack…`→windows), NOT the TTL — a `sysctl
  ip_default_ttl=128` mangle is explicitly defeated (grounded: TTL-128 curl still classified `linux`). The
  option order is set by the kernel TCP stack; a UA/navigator spoof can't touch it, and even the high-end
  network impersonators (uTLS/curl-impersonate) forge the TLS ClientHello but NOT the TCP SYN. GROUNDED that
  uTLS ALONE can't: the go-tls (uTLS) evader produced a forged Chrome JA4 (`t13d1516h2_…`) but `tcp_kernel`
  stayed `linux` with the IDENTICAL JA4T to plain curl (`64240_2-4-8-1-3_1460_7`) — uTLS is a TLS library that
  wraps a net.Conn AFTER the kernel has already opened the TCP connection and emitted the SYN, so it has no
  access to the SYN options. So coherent OS spoofing needs one of: run on the real target OS; tunnel through a
  VM/proxy whose EGRESS stack is the target OS; a **userspace TCP/IP stack** (gVisor netstack / raw sockets with
  NET_RAW) emitting the target's option order, with uTLS layered ON TOP for the TLS (uTLS accepts any net.Conn —
  the SYN forge is the userspace stack, not uTLS); or an edge behind a CDN/LB (which sees the balancer's SYN,
  not the client's — the deployment caveat that makes this tell direct-connection-only).
  Same pattern as the whole session: everything above the kernel is spoofable/provisionable; the kernel TCP
  stack is the durable OS fingerprint, and forging it means becoming (or tunnelling through) the real OS.
- **The SYN wall IS crossable — userspace TCP + uTLS forges the kernel, GROUNDED live (2026-07-02).** Built
  `evaders/os-spoof`: a hand-rolled happy-path userspace TCP stack over `AF_PACKET` (gopacket) that emits a
  caller-chosen SYN option order, with uTLS's Chrome ClientHello layered on top (uTLS accepts any net.Conn) and
  an HTTP/1.1 request, in a `NET_RAW`+`NET_ADMIN` container that drops the kernel's RSTs. Result: the forged
  Windows SYN (`64240_2-1-3-1-1-4_1460_8` = `mss,nop,ws,nop,nop,sack`) made the edge classify **`tcp_kernel=
  windows`**, matching the Windows UA, so **`net.tcp_os_vs_ua` went SILENT** — while the control (normal kernel
  TCP + same Windows UA) classified `tcp_kernel=linux` and the rule FIRED. So the precise answer to "can uTLS
  do it": uTLS ALONE can't (it runs over the kernel's TCP), but **uTLS + a userspace TCP stack** can — the SYN
  forge is the stack, not uTLS. The tool is a raw HTTP client so it still trips the no-browser tells
  (`net.no_js_execution`/`sec_fetch_vs_ua`/`accept_encoding_vs_ua`); a COHERENT full OS spoof routes a real
  browser (camoufox Windows profile + `KS_PROVISION`) THROUGH this stack so every layer tells one OS story. The
  blue residual moves DOWN a layer: from the SYN option order (now forgeable) to deeper TCP *behavior* (window
  dynamics, retransmit timers) that a happy-path userspace stack doesn't reproduce — a much harder fingerprint,
  and the natural next blue rung if the edge ever needs to catch a userspace-stack forger. Net: the OS-coherence
  wall is not absolute; it costs a userspace TCP stack + raw-socket privileges — real, but buildable, and now built.
  **Productized into coherent PROFILES (2026-07-02):** `os-spoof` now carries a profile registry (windows-chrome/
  windows-edge/macos-safari/macos-chrome/linux-firefox/ios-safari), each a coherent kernel SYN (option order +
  TTL + window) + matching uTLS hello + UA. `KS_PROFILE=<name>|random|list`; grounded that each forges its own
  `tcp_kernel` with `tcp_os_vs_ua` silent (windows `64240_2-1-3-1-1-4`, darwin `65535_2-1-3-1-1-8-4-0`, linux
  `64240_2-4-8-1-3`), and a 5-node `random` fleet morphed into a diverse multi-OS mix. So the fleet can present
  any OS shape at the kernel layer for free — reinforcing that the per-node fingerprint is fully forgeable and
  the durable blue signal is coordination behavior + IP reputation, not per-node OS coherence.
- **Proxy mode — a REAL browser rides the forged kernel; engine-agnostic (2026-07-02, GROUNDED).** `os-spoof`
  gained `KS_MODE=proxy`: a SOCKS5 front end over a CONCURRENT userspace stack (one manager demuxes many flows).
  Point any browser at it and every flow rides the forged kernel while the browser's own real TLS + JS run end
  to end. Grounded that it is NOT camoufox-only: a Chromium browser (stealth = the nodriver/zendriver/patchright
  family) through a `windows-chrome` proxy routed with the collector running and `tcp_kernel=windows`; camoufox
  (Firefox) through a `macos-firefox` proxy came through with `tcp_kernel=darwin` matching its macOS-Firefox UA
  and `net.tcp_os_vs_ua` SILENT. Each profile now carries an `Engine` (chromium/firefox/webkit) naming the
  coherent browser family. Residual: the happy-path TCP is robust enough for a Chromium page load but camoufox's
  collector POST didn't always land — a production node swaps the stack for gVisor `netstack` (the SYN-forge
  design is unchanged). **Blue rung (Rung B) assessed, not built:** the only durable counter to a userspace-stack
  forger is deeper TCP *behavior* (no-retransmit, static window, no delayed-ACK, non-incrementing timestamps),
  which needs extending the edge sniffer from SYN-only to FLOW-level tracking + real-traffic calibration to set
  FP-safe bands — external-data-bound, and a single-SYN heuristic (e.g. implausible timestamp) would be FP-prone
  / off-thesis (a fresh-booted machine has a small timestamp too). So the durable in-sandbox blue signal stays
  coordination + IP reputation; per-node TCP behavior is a hard, external-calibration-bound frontier, routed to the queue.
- **Real data (p0f) moved the SYN needle a notch — `net.tcp_syn_anomaly` SHIPPED, arms-race grounded (2026-07-02).**
  Sourced the p0f OS SYN fingerprint corpus (real data) and compared it to the os-spoof forger: the edge's
  `ClassifyTCPOS` keys ONLY on the option ORDER — the weakest part — while p0f shows the full tuple (window,
  wscale, quirks) is far richer. The forger's Windows (`64240`/ws8) and Linux (`64240`/ws7) tuples ARE realistic
  modern signatures, but its macOS SYN carried `wscale=6`, which NO real macOS/iOS emits (p0f: all ≤4). Built the
  value-vs-order coherence check `net.tcp_syn_anomaly` (edge `SYNValueAnomaly`: darwin-ordered SYN with wscale>5,
  a p0f-grounded FP-safe boundary), experimental, w0.5. GROUNDED LIVE: os-spoof `macos-safari` (wscale 6) → the
  rule FIRES (the option-order classifier + `net.tcp_os_vs_ua` had missed it); `windows-chrome`/`linux-firefox`
  → silent. RED counter-move: fixed the forger's macOS wscale 6→4 (p0f-faithful) → it now ESCAPES — the arms
  race, honestly demonstrated. So the p0f data DID move the detection needle (catches an order-copying forger the
  prefix classifier can't) but confirms it is an arms-race step, not a durable wall: a forger that copies the
  FULL real signature escapes. The Windows/Linux value-check needs modern real-traffic captures for FP-safe bands
  (p0f's window/scale are dated) → external queue. Net: per-node/kernel fingerprint is forgeable with real-data
  care; the durable break-through stays coordination + IP reputation + flow-level TCP behavior (all external).
- **Flow-level TCP behavior (Rung B) — `net.tcp_static_window` SHIPPED, the first blue tell BELOW the SYN
  (2026-07-02, GROUNDED live).** The os-spoof forger can forge the SYN (order + values) but not a real kernel's
  window-growth DYNAMICS: every OS auto-tunes its advertised receive window (it grows as the receiver buffers),
  while a happy-path userspace stack holds it constant. Extended the edge SYN sniffer to a FLOW-level
  `WindowTracker` (per source IP, the distinct receive-window values across its established segments) + emit
  `network.tcp_static_window` when a flow sent >=12 segments all advertising ONE window → rule
  `net.tcp_static_window` (automation, experimental, w0.4). GROUNDED LIVE: the tracker recorded the os-spoof
  userspace stack advertising ONE window value (64240) across its flow, while a real curl kernel advertised
  MULTIPLE (502, 533, … and growing) — the exact static-vs-dynamic split, live. This is the FIRST detection tell
  below the SYN — the layer no SYN/TLS/UA/kernel-order spoof (incl. os-spoof) reaches, because reproducing it
  needs reimplementing TCP auto-tuning, not just crafting a packet. EXPERIMENTAL: the >=12-segment floor is
  FP-conservative (a single small real flow can look near-static before its window grows; a minimal/embedded
  stack could be static), so FP-safe deployment (the floor, which real minimal stacks are static) needs
  real-traffic calibration — but the STRUCTURAL tell is grounded and it catches the userspace-stack-forger class
  (a browser routed through the os-spoof proxy accumulates far more than 12 static-window segments). Net: a real,
  grounded blue advance on the deepest layer — the forger's one structural residual, now detected.
- **The environment JOINT-manifold axis is NOT saturated — device↔screen coherence, X5 iOS half SHIPPED
  (2026-07-02, GROUNDED live).** The environment is a joint distribution, not a bag of attributes: real devices
  occupy a thin manifold (an iPhone-15 is ONE exact tuple of screen/DPR/GPU/cores/…). The detector today checks
  mostly per-attribute MARGINALS (`macos_dpr`, `screen_impossible`, `mobile_no_touch`, `pointer_touch`) + a few
  pairwise cross-checks; the full JOINT (device↔screen↔DPR↔GPU↔cores) is under-built — the non-saturated frontier
  a "coherent per-OS environment randomizer" (the red vision) targets. FOUND real data (Apple device-screen
  corpus: iosref.com/res, ios-resolution.com — 137 iPhones + 52 iPads; largest real iOS logical screen is iPad
  Pro 12.9\" at 1024x1366). Shipped the FP-safe slice of X5: `br.ios_screen_oversized` (collector: iOS UA +
  max(screen dim) > 1400 → forged; convicting, w0.7) — the joint-coherence RATCHET that forces a mobile spoof to
  get the SCREEN right too, not just touch (it catches the touch-faking iOS spoof that beats `mobile_no_touch`).
  GROUNDED LIVE, the exact marginal-vs-joint split: a real Chromium given an iPhone UA + a DESKTOP screen
  (1920x1080, a MARGINAL randomizer) FIRES it; the same UA + a REAL iPhone screen (393x852, a JOINT randomizer)
  is SILENT. So a coherent joint randomizer evades and a marginal one is caught — proving the vision's core claim
  AND the detection response: the frontier is the FULL per-OS joint manifold (desktop + mobile), gated on real
  device distributions (screen/DPR/GPU-family/cores per OS). Each new joint constraint (device↔screen shipped;
  next: screen↔DPR-for-OS, cores↔device-class, GPU-family↔model) ratchets the coherence bar up; the red vision
  and the blue frontier are the same manifold seen from two sides, both data-driven. NOT saturated — routed the
  full device-DB joint checks (the sub-1400 per-model set, desktop resolutions, DPR/cores/GPU joints) to the queue.
- **The RED half — a coherent per-OS device randomizer, BUILT + grounded (2026-07-02).** The vision's capability:
  `stealth` gained `KS_DEVICE=<name>|random|list` — sample a REAL device from Playwright's maintained registry
  and apply it NATIVELY (UA + Sec-CH-UA + screen + DPR + isMobile + hasTouch from ONE device, no JS patches → no
  realm-divergence tell). Scoped to chromium-engine devices (Android Chrome + desktop Chrome; iOS/WebKit devices
  self-defeat into `apple_ua_nonwebkit` on Blink, so those need a real WebKit runtime). GROUNDED LIVE: a
  `KS_DEVICE=random` fleet drew Pixel 5 / Nexus 10 / Nexus 7 (each launch distinct — a morphing device
  population), and EVERY sampled device showed device-coherence tells NONE (`mobile_no_touch` / `maxtouch_desktop`
  / `ios_screen_oversized` / `pointer_touch` / `screen_impossible` all silent) — on-manifold by construction. So
  the coherent joint randomizer evades the device-marginal checks a naive independent-attribute spoof trips: the
  red⇄blue axis is live and symmetric. Residual (unchanged, external): the environment FLOOR (webgl_software /
  voices / media — the container GPU/hardware) still fires; a fully-coherent morphing device = KS_DEVICE (spoofable
  joint) + KS_PROVISION (floor) + a WebKit runtime for the iOS slice. The manifold is the shared battlefield —
  red samples it, blue checks it, both gated on the same real per-OS device distributions. NOT saturated.
- **[LOOP R1] KS_DEVICE + KS_PROVISION composed in one Chromium tool — grounded, Chromium floor mapped
  (2026-07-02).** Ported the camoufox provisioner (PulseAudio null-sink/source over an anon socket +
  speech-dispatcher/espeak-ng) into the stealth image via a new `entrypoint.sh`, so `KS_DEVICE` (coherent device)
  and `KS_PROVISION` (real floor) compose in ONE run. GROUNDED LIVE, device+provision: DEVICE-coherence tells
  NONE (the sampled device stays on-manifold) and `br.media_devices_empty` CLEARED (Chromium enumerates the
  PulseAudio devices natively — provisioning works for Blink too). Residual, and honest: `br.voices_empty` still
  fires (headless Chrome does not enumerate speech-dispatcher voices even with `--enable-speech-dispatcher` — a
  headless-Chromium TTS limitation, not a provisioning gap) and `br.webgl_software` still fires (the Chromium
  software-GPU wall — no GPU in-sandbox, and a JS renderer spoof is caught by caps-coherence). BOTH residuals are
  exactly what camoufox (Firefox, engine-level renderer + native Gecko voice enumeration) clears to reach `human`
  — so the composition CONFIRMS the human morphing vehicle is camoufox+provision, while the stealth+KS_DEVICE node
  contributes coherent-device diversity. The morphing-HUMAN fleet = camoufox+provision (human floor, engine-level)
  × per-OS device coherence; the Chromium path is diversity, not human, until a real GPU/headful-TTS is present.
- **[LOOP B1] device↔DPR coherence — br.ios_dpr_incoherent SHIPPED, grounded (2026-07-02).** The DPR sibling of
  ios_screen_oversized on the same iOS manifold: iOS renders at a device-FIXED backing scale — every real
  iPhone/iPad reports window.devicePixelRatio of EXACTLY 2 or 3 (2 for iPad + SE/older; 3 for modern/Plus/mini —
  the 6-Plus and 12/13-mini downsample but REPORT integer 3; no fractional/1x iOS display). Collector emits
  ios_dpr_incoherent when an iOS UA's DPR ∉ {2,3} → rule br.ios_dpr_incoherent (coherence, convicting, w0.7),
  FP-safe by the Apple hardware bound and distinct from br.devicepixelratio_anomaly (finite-only). Added KS_DPR
  (deviceScaleFactor) to the stealth runner to red-verify. GROUNDED LIVE: iPhone UA at the container-default
  DPR 1 (KS_DPR unset) FIRES; the same UA at a real iOS DPR (KS_DPR=3) is SILENT. Together ios_screen_oversized
  (screen) + ios_dpr_incoherent (backing scale) force a coherent iOS spoof to get BOTH right — two rungs of the
  ratchet now on the iOS device manifold. Next blue rungs on this axis: device-class↔cores/memory (B2),
  GPU-family↔model (B3), the sub-1400 per-model iOS screen SET (B4).
- **[LOOP B4-slice] br.ios_screen_desktop_res — the sub-1400 desktop-res catch, grounded (2026-07-02).** Closes
  the gap under ios_screen_oversized's max>1400 bound: a desktop faking iOS with a SMALLER panel (1366x768,
  1280x720, 1280x1024) slips under the oversized threshold. Collector emits ios_screen_desktop_res when an iOS UA
  reports a screen in a curated set of common DESKTOP resolutions (both orientations), NONE of which any iPhone/
  iPad ships (verified against the Apple corpus; iPad geometries like 1024x768 EXCLUDED). FP-safe by construction
  (desktop-exclusive geometries). GROUNDED LIVE: iPhone UA + KS_SCREEN=1366x768 → ios_screen_desktop_res fires
  while ios_screen_oversized stays silent (1366<1400) — the new rung catches exactly what the old one missed; a
  real iPhone screen (393x852) → both silent. The iOS screen manifold is now a THREE-rung ratchet (oversized +
  desktop-res + DPR); a coherent iOS spoof must land ON a real geometry, not merely dodge the oversized bound.
- **[LOOP B2] br.devicememory_vs_engine — engine↔API-surface coherence via a THIRD Blink surface, grounded
  (2026-07-02).** navigator.deviceMemory is Blink-EXCLUSIVE (Firefox declined it for privacy; Safari/WebKit never
  shipped it). A UA whose engine token is firefox or safari while deviceMemory is DEFINED is a Blink engine
  wearing a non-Blink UA — the inverse of br.no_devicememory (Chromium UA MISSING it) and a THIRD independent
  Blink surface beyond apple_ua_nonwebkit (window.chrome/userAgentData) + the Gecko buildID check, so it still
  fires when a spoofer scrubs window.chrome + userAgentData and fakes buildID but forgets deviceMemory. FP-safe
  (no real Firefox/Safari has it); scoped to the firefox/safari UA engines. GROUNDED LIVE: a Chromium (stealth)
  given a Firefox UA fires devicememory_vs_engine (ua_engine=firefox + Blink deviceMemory present); under its
  native Chromium UA it does NOT. A new axis off the iOS-screen vein — one more surface a Chromium-faking-a-non-
  Blink-browser must scrub. Next: R2 (desktop-OS device tuples), B3 (GPU-family↔model), deeper TCP-behavior.
- **[LOOP R3] WebKit runtime path — the coherent iOS device, engine wall CROSSED (2026-07-02, grounded).** The
  missing rung: an iOS device is only coherent on a REAL WebKit engine (Blink-faking-iOS self-defeats). Added
  KS_ENGINE=webkit|firefox|chromium to the stealth runner (Playwright ships a real WebKit build) + scoped
  KS_DEVICE to the launched engine (webkit→iPhone/iPad) + a maxTouchPoints=5 init-fix for the headless-WebKit
  touch quirk (main-thread-only is safe: WorkerNavigator has no maxTouchPoints to diverge). GROUNDED LIVE:
  KS_ENGINE=webkit + KS_DEVICE='iPhone 15' → ALL iOS/engine tells SILENT (apple_ua_nonwebkit, devicememory_vs_
  engine, ios_screen_oversized/desktop_res/dpr_incoherent, mobile_no_touch) = a FULLY coherent iOS device;
  the Blink+iPhone-UA contrast trips apple_ua_nonwebkit + devicememory_vs_engine, proving WebKit crosses the
  engine wall those checks guard. The device-identity axis (engine+screen+DPR+touch) is now coherent for iOS —
  the R3 win. Residual, honest (7 tells, OTHER axes, each with its own tool): automation (webdriver_present /
  automation_globals → patchright), floor (media_devices_empty → KS_PROVISION), the Linux-container leak
  (font_os_vs_ua + navplatform_vs_ua → the WebKit host is Linux, needs engine-level font/platform spoofing or a
  real iOS host), network (tcp_os_vs_ua + tls_grease_vs_ua → route through the os-spoof ios-safari proxy). R3
  crosses the iOS device-identity wall and MAPS the coherent-full-stack-iOS frontier: font/platform + network.
- **[LOOP B5] br.android_phone_screen_oversized — first device-coherence check on the ANDROID manifold, grounded
  (2026-07-02).** The detector had ZERO Android device checks; this opens the axis. Scoped to the UA 'Mobile'
  token (Android Chrome OMITS it on tablets + Android TV/Auto, so this keys on PHONES + foldables only), whose
  logical screen is bounded — the largest current Android phone/foldable tops out ~1100 CSS px. An Android+Mobile
  UA with max(screen) > 1400 is a desktop faking an Android phone (Mobile UA over a 1920x1080 screen), the Android
  sibling of ios_screen_oversized. FP-safe by the hardware bound (no Android phone screen nears 1400; tablets/TV
  excluded by the Mobile-token gate). GROUNDED LIVE: Android Pixel Mobile UA + KS_SCREEN=1920x1080 fires; a
  coherent KS_DEVICE Pixel 5 is SILENT. (Impl note: the JS regex word-boundary \\b was mangled by the demo.py
  Python-string escaping on first cut — caught it LIVE when the naive case did not fire, switched to /Mobile/i;
  a reminder that the collector is JS-in-a-Python-string and backslash escapes double.) Mobile screen coherence
  now spans BOTH mobile OSes (iOS 3-rung + Android). Ladder: R1,B1,B4-slice,B2,R3,B5 — 6 rungs, 3 axes.
- **[LOOP B2b] br.devicememory_worker_divergence — realm coherence gap CLOSED, grounded (2026-07-02).** The
  general br.worker_divergence probed the Worker's ua/hardwareConcurrency/platform but NOT navigator.deviceMemory
  — yet WorkerNavigator.deviceMemory exists (Blink). So a main-thread-only deviceMemory patch (a spoofer inflating
  RAM or hiding a low-mem VM) survived every realm check. Added deviceMemory to the worker postMessage + a
  divergence rule (convicting, w0.8). A page init script (addInitScript / CDP addScriptToEvaluateOnNewDocument)
  does NOT run in Worker scope, so a main-only Object.defineProperty diverges. FP-safe via a 'u' sentinel (both
  realms undefined on Firefox/Safari compare EQUAL; a real Chromium reports one value in both → silent). GROUNDED
  LIVE with a red-verify hook (stealth KS_SPOOF_DM=0.25, main-only): devicememory_worker_divergence FIRES while
  the general worker_divergence stays FALSE — proving the gap was real; the un-patched browser is SILENT. The
  realm-coherence axis (languages/webgl/canvas/timezone worker-divergence) now covers deviceMemory too. 7 rungs.
- **[LOOP B-uad] br.uadata_worker_divergence — realm coherence for the CH-UA object, the #1 spoof surface,
  grounded (2026-07-02).** navigator.userAgentData (platform/mobile/brands) is THE target of OS-spoof tooling and
  is exposed in WorkerNavigator too (Blink) — but the general worker_divergence never probed it. A main-only
  Object.defineProperty(navigator,'userAgentData',…) (the standard OS-fake) never reaches Worker scope → diverges.
  Added platform|mobile to the worker probe + a divergence rule (convicting, w0.8), DOUBLE FP-guarded (the 'u'
  sentinel for Firefox/Safari both-absent + a wn.uad!=='u' gate so a browser whose worker lacks userAgentData
  never false-fires). GROUNDED LIVE (stealth KS_SPOOF_UADATA=Windows, main-only): uadata_worker_divergence FIRES
  — which also CONFIRMS the Chromium worker exposes userAgentData — while the general worker_divergence stays
  FALSE (the gap); the un-patched browser is SILENT. Realm coherence now covers the three Blink WorkerNavigator
  surfaces a main-only OS-spoof leaves un-synced: deviceMemory, userAgentData, plus the original ua/hw/platform.
  8 rungs, 4 axes. The realm axis catches the naive JS-patch OS-spoof at its root — the reason per-node OS faking
  needs engine-level (camoufox), not addInitScript.
- **[LOOP R3+] WebKit iOS through the os-spoof ios-safari proxy — kernel residual CLEARED, grounded
  (2026-07-02).** Composed the R3 WebKit iOS device with the os-spoof darwin-kernel proxy to attack the network
  residuals R3 surfaced. GROUNDED LIVE: WebKit iPhone 15 + KS_PROXY=socks5 to an ios-safari proxy →
  tcp_kernel=darwin, req_count=122 (the happy-path stack carried WebKit's FULL session — TLS + h2 + the
  collector's worker/fetch, more robustly than camoufox's earlier flaky POST), and net.tcp_os_vs_ua CLEARED
  (kernel now matches the iOS UA). Residual: net.tls_grease_vs_ua — proxy mode passes the browser's OWN TLS
  end-to-end, and Playwright's Linux WebKit ClientHello ≠ real iOS Safari's GREASE/JA4; clearing it needs a uTLS
  HelloIOS re-origination (the chain-mitm front), not the kernel forge. So the composed iOS node is now coherent
  at KERNEL + browser-engine + screen/DPR/touch; the single remaining network tell is the TLS fingerprint, the
  deepest full-stack-iOS residual. Updated the os-spoof README (WebKit driver now exists via KS_ENGINE=webkit).
  9 rungs. The full-stack coherent iOS node = WebKit engine (R3) + darwin kernel (os-spoof) + uTLS-iOS TLS (next).
- **[LOOP B-ns] br.ios_no_standalone — the check that BEATS R3, grounded (2026-07-02).** navigator.standalone is
  an iOS-Safari-SPECIFIC boolean (present on real iOS/iPadOS Safari through 2026 per MDN + Apple; undefined on
  desktop Safari, DESKTOP WebKit, Chrome, Firefox) — FINER than br.safari_ua_no_webkit_api (window.GestureEvent,
  which every desktop Safari + WebKit also has). An iPhone/iPad UA with navigator.standalone === undefined is not
  genuine iOS Safari. GROUNDED LIVE, the decisive contrast: the R3 KS_ENGINE=webkit iPhone 15 fires
  ios_no_standalone TRUE while safari_ua_no_webkit_api is FALSE — so it catches R3's DESKTOP-WebKit iOS node that
  GestureEvent + apple_ua_nonwebkit MISS (R3 is WebKit, just not iOS WebKit). The blue rung that beats the red
  rung two firings prior — the arms race closing on itself. EXPERIMENTAL (w0.4): iOS in-app WKWebViews also lack
  navigator.standalone and carry Safari-like UAs, so FP-safe promotion needs a UA app-token / clean-Version gate;
  the surface is sound (real full iOS Safari always defines it). 10 rungs. R3's iOS device is now coherent at
  engine+screen+DPR+touch+kernel but STILL falls to the iOS-Safari-specific JS surface — desktop WebKit ≠ iOS.
- **[LOOP R3++] synthesize navigator.standalone — evades B-ns, and reveals WHY (2026-07-02, grounded).** The red
  counter to B-ns: the WebKit iOS node (KS_ENGINE=webkit) now defines navigator.standalone=false (the faithful
  in-browser value) via addInitScript. GROUNDED LIVE: R3++ WebKit iPhone 15 → ALL iOS/tamper tells SILENT —
  ios_no_standalone CLEARED and NO new realm divergence (deviceMemory/userAgentData/worker divergence all quiet).
  THE INSIGHT: navigator.standalone is a main-window-ONLY surface (not in WorkerNavigator), so a main-only
  Object.defineProperty synthesises it with NOTHING to diverge against — unlike deviceMemory/userAgentData, which
  ARE in the worker and so catch a main-only patch. So the ARMS-RACE LESSON is now grounded on both sides:
  main-window-only surface checks (ios_no_standalone, GestureEvent) are SYNTHESISABLE and thus soft; the durable
  browser-coherence checks are the REALM-BACKED ones (br.*_worker_divergence) a JS patch cannot reach without
  also rewriting worker scope (→ br.worker_source_rewritten). B-ns correctly shipped experimental for exactly
  this reason. 11 rungs. The blue counter to R3++ must be realm-backed or unforgeable, not another window surface.
- **[LOOP attempt] delayed-ACK tell — NOT groundable in-sandbox, reverted honestly (2026-07-02).** Tried the
  deepest unforgeable layer (a JS spoof cannot touch TCP behaviour): a real kernel implements TCP delayed-ACK
  (RFC 1122, ~1 ACK per 2 segments) while a happy-path userspace stack ACKs every one. Built the tracker +
  edge wiring + unit tests, then hit TWO grounding walls and REVERTED rather than ship an ungrounded rule:
  (1) counting the edge's outgoing data segments is impossible here — AF_PACKET in this sandbox delivers ZERO
  PACKET_OUTGOING frames (grounded: a pkttype histogram was 100% PACKET_HOST); (2) the inbound-only pivot
  (measure bytes-acknowledged per ACK from the client's pure ACKs) didn't separate either: the real kernel on
  this docker bridge COALESCES ACKs heavily (grounded ~5893 bytes/ACK ≈ 4 MSS, not the textbook 2), and the
  os-spoof proxy PIGGYBACKS its ACKs on the data it relays (so it emits few pure ACKs to measure). The tell is
  real but needs a real NIC (PACKET_OUTGOING) + a faithful pure-1:1-acking client, neither available in-sandbox
  — like the QUIC member (ADR-0005), it is infra-bound. Recorded as the FIRST of the loop's "twice-in-a-row dry"
  stop condition; the ladder continues (this is a documented negative, not a shipped-broken rule). Lesson: the
  edge's packet view here is INBOUND-ONLY, so TCP-behaviour tells must be derivable from client→edge packets
  alone (net.tcp_static_window works because window auto-tuning IS inbound-visible; ACK cadence largely is not).
- **[LOOP R-mac] camoufox engine-level macOS spoof beats the realm-backed platform check + macos_dpr1 fix
  (2026-07-02, grounded).** The red side of the R3++ insight: JS-patch (addInitScript) can't fake navigator.platform
  without tripping worker_divergence, but an ENGINE-LEVEL browser can — camoufox's os='macos' spoofs platform in
  every realm. GROUNDED LIVE: camoufox KS_MACOS shows platform-realm tells [] (navplatform_vs_ua,
  ua_platform_vs_ch_platform, worker_divergence ALL silent) — the exact check R3++ (Chromium/WebKit JS-patch)
  cannot evade. It was still caught by br.macos_dpr1 (headless DPR 1, real macOS is Retina ≥2), so added an
  engine-level Retina DPR (config window.devicePixelRatio=2.0 on the macOS path) → GROUNDED: macos_dpr1 now
  CLEARS with no new tell. The camoufox macOS node is now coherent on platform (all realms) + DPR — the device-
  identity axis for macOS. Residual, the DURABLE macOS catch: br.font_mac_internal (camoufox's fonts.json ships
  49 dot-prefixed internal system fonts a real Mac HIDES — an engine-bundled-font leak the DPR/platform spoof
  can't fix), plus the floor (media/voices/webrtc → KS_PROVISION) and net.tcp_os_vs_ua (→ os-spoof macos proxy).
  So engine-level beats JS-patch on platform+DPR, but font_mac_internal is the macOS residual that even engine-
  level leaves. 12 grounded rungs. The arms race: JS-patch < engine-level < (engine-level + curated real fonts).
- **[LOOP R-font] curate camoufox's macOS fonts — evades font_mac_internal, macOS device-identity COMPLETE
  (2026-07-02, grounded).** The predicted next step from R-mac: strip the 49 dot-prefixed internal fonts
  (.Aqua Kana, .Apple Color Emoji UI, …) from camoufox's bundled fonts.json `mac` list (573→524 fonts) via a
  Dockerfile build step — a real Mac HIDES these from web content, so exposing them was the leak br.font_mac_internal
  keyed on. GROUNDED LIVE: camoufox KS_MACOS now shows font_mac_internal FALSE **and** font_os_vs_ua FALSE (the
  ~524 non-dot fonts keep the font-derived OS macOS-coherent) — the dot-leak closed without breaking OS coherence.
  The macOS DEVICE-IDENTITY axis is now FULLY coherent: platform (all realms, R-mac) + DPR (Retina, R-mac) +
  fonts (R-font). Remaining camoufox-macOS tells are ALL other axes: behavioral (bh.power_law/synthetic → KS_BEHAVE/
  KS_REAL_INPUT), floor (media/voices/webrtc → KS_PROVISION), webgl2_missing (camoufox headless GL), net.tcp_os_vs_ua
  (→ os-spoof macos proxy). BLUE consequence: br.font_mac_internal (present-dot-font check) is now EVADABLE by
  curation — the durable font tell must become a MISSING-expected-font or font-METRIC check, not a present-internal-
  font one. 13 grounded rungs. Next blue: a font tell a curated list can't satisfy (metric-based or expected-present).
- **[LOOP R-gl] KS_HEADFUL gives camoufox real WebGL2 — evades webgl2_missing, caps-mismatch is the durable catch
  (2026-07-02, grounded).** webgl2_missing is a camoufox-WIDE tell (grounded: the default linux profile trips it
  too, not just macOS) — headless camoufox has no GL context. RED: KS_HEADFUL runs camoufox on a virtual Xvfb
  display (real llvmpipe GL). GROUNDED LIVE (KS_MACOS + KS_HEADFUL): webgl2_missing CLEARED **and** webgl_software
  CLEARED (a real GL context, renderer spoofed to "Apple M1, or similar"). But a NEW tell fires:
  br.webgl_renderer_caps_mismatch — the "Apple M1" renderer STRING vs the llvmpipe CAPABILITY vector (MAX_TEXTURE_
  SIZE / limits / extensions). That is the durable GL catch: camoufox can spoof the renderer STRING and provide a
  real GL context, but cannot reproduce a real Apple GPU's capability numbers without an actual Apple GPU — the
  SAME "string-spoof < real-hardware" law as R-font (declared fonts) and net.tcp_static_window (SYN vs behaviour).
  The camoufox macOS node is now coherent on platform + DPR + fonts + WebGL2-presence + renderer-string; the GL
  CAPS are the residual the software renderer can't fake. Blue holds via a caps-vector check the string spoof
  can't satisfy. 14 grounded rungs. Pattern crystallised: every layer's durable tell is the one that measures the
  REAL substrate (caps, metrics, kernel behaviour), not the DECLARED string — string spoofs are always evadable.
- **[LOOP dry-1] two sound-negative findings — JA4T-collision rejected, GL-caps evasion infra-bound (2026-07-02).**
  A lean firing that produced two disciplined negatives rather than a padded rung (the quality bar: a rung must
  BEAT the last, not repeat a soft pattern). (1) COORDINATION: considered a JA4T-collision key to catch the
  morphing-device fleet (diverse browser fps, one shared os-spoof kernel) that _fp_collision misses — REJECTED as
  low-entropy: JA4T is OS-DETERMINED (window+options+scale) plus a near-universal MSS 1460 (any 1500-MTU network),
  so most same-OS users share it → it would fire on benign cohorts, the voices_hash trap. Consequence: the
  morphing fleet's shared kernel is NOT a coordination tell; the durable coordination signal stays IP-reputation +
  shared-origin (external), as established. (2) GL CAPS: probed evading webgl_renderer_caps_mismatch — camoufox
  ships a webgl_data.db with real per-GPU caps, but the evasion is infra-bound: headless has no GL context
  (webgl2_missing), headful leaks the real llvmpipe caps that override the DB spoof (caps_mismatch), and there is
  no real Apple GPU in-sandbox to satisfy either — so webgl_renderer_caps_mismatch holds durably here (like the
  delayed-ACK AF_PACKET block, it is an infra floor, not a detector gap). Rejected soft-surface padding
  (navigator.getBattery/connection-vs-engine: window-only, so a main-only delete evades with no realm to diverge —
  the R3++ soft-surface class, not worth a rung). Dry attempt #1 of a new streak; the loop continues.
- **[LOOP B4-full] br.ios_screen_offmanifold — the full iOS device-screen SET, dry streak RESET (2026-07-02,
  grounded).** Closed the last iOS-screen gap after dry-1: the three slices (oversized max>1400, desktop-res,
  DPR∉{2,3}) all pass a spoofer who picks a sub-1400, non-desktop, DPR-2/3 geometry that is simply NOT a real
  iPhone — e.g. 400x800. This keys on the SET of real iOS logical resolutions (portrait CSS px) from the Apple
  device corpus (iosref.com/res + ios-resolution.com); screen.width/height is device-fixed on iOS, so a portrait
  (min×max) normalisation covers both orientations. GROUNDED LIVE, the decisive contrast: iPhone UA + 400x800 @
  DPR3 fires ios_screen_offmanifold while oversized + desktop_res + dpr_incoherent ALL stay silent (it catches
  exactly what the slices miss); a real iPhone 15 393x852 is silent everywhere. EXPERIMENTAL (w0.4): a brand-new
  Apple model ships a resolution not yet in the maintained set → FP until refreshed, so it convicts only
  corroborated (the oversized/desktop-res slices stay the FP-safe hardware-bound frontline; this is the tight
  corroborating backstop). The iOS screen manifold is now a FOUR-rung ratchet — oversized, desktop-res, DPR, and
  the full set. 15 grounded rungs. Dry streak reset to 0. Data-grounded rungs still exist where real device
  corpora fill a manifold the hardware-bound slices can't.
- **[LOOP B-chua] net.ch_ua_on_safari_ua — Blink-faking-Safari at the HEADER layer, catches no-JS (2026-07-02,
  grounded).** Sec-CH-UA is Blink-EXCLUSIVE: Chromium sends it, Safari (macOS + iOS) has NEVER shipped Client
  Hints (WebKit declined the spec). So a request whose UA claims Safari while ANY Sec-CH-UA header is present is a
  Chromium engine wearing a Safari UA. The HEADER-layer twin of br.apple_ua_nonwebkit (JS window.chrome): because
  it lives on the HTTP request, it fires even for a NO-JS scraper (curl/Go copying a Safari UA behind a
  Client-Hints-emitting stack, or headless Chromium with JS off) that the JS check never sees. Distinct from
  net.ch_ua_vs_ua_browser (which needs the JS ua_browser to COMPARE) — this needs only the header's PRESENCE
  under a Safari UA. FP-safe (no real Safari/WKWebView emits Sec-CH-UA; scoped to a Safari-family UA). Convicting
  (w0.7). GROUNDED LIVE: a Chromium given an iPhone-Safari UA fires ch_ua_on_safari_ua; under its native Chrome UA
  it does not. A NETWORK-layer engine tell — moved off the saturated browser-JS layer onto the header layer, and
  it catches the no-JS class the JS engine-checks structurally cannot. 16 grounded rungs.
- **[LOOP R-chua] KS_STRIP_CHUA evades ch_ua_on_safari_ua — but the TLS/h2 SUBSTRATE holds (2026-07-02,
  grounded).** The red counter to B-chua: a Chromium faking Safari strips the Blink-only Sec-CH-UA* request
  headers (stealth context.route) so it emits none, like real Safari. GROUNDED LIVE: Safari UA + KS_STRIP_CHUA →
  ch_ua_browser=None, ch_ua_on_safari_ua CLEARED (vs FIRES without the strip). BUT the run is STILL `bot` —
  caught by the SUBSTRATE the header strip can't touch: net.tls_vs_ua_browser + net.h2_vs_ua_browser (the TLS
  ClientHello + HTTP/2 fingerprint reveal a Chromium engine under the Safari UA), plus the JS surfaces
  (apple_ua_nonwebkit, devicememory_vs_engine). So the arms race resolves EXACTLY on the R-gl law: ch_ua_on_safari_ua
  is a HEADER STRING (strippable → evaded), but the engine is ALSO written into the TLS/h2 WIRE FINGERPRINT
  (substrate → durable), which a header edit cannot reach. Crucially this holds for the NO-JS case too: even a
  curl/Go Chromium-stack scraper that strips Sec-CH-UA is still convicted by net.tls_vs_ua_browser / h2_vs_ua_browser.
  17 grounded rungs. The header check was worth shipping (it fires FIRST + cheaply, no TLS parse), and the
  substrate is the backstop — defence in depth, string-tell in front, substrate-tell behind.
- **[LOOP B-nc] generalised ch_ua_on_non_chromium_ua — closed the Firefox gap (2026-07-02, grounded).** A
  systematic emitted-but-unread signal audit (network + browser layers) confirmed the layers are near-saturated
  (http_version/http_user_agent are intentional corroborating values; QUIC infra-blocked; webgpu_* covered by
  webgpu_webgl_mismatch or FP-risky). The one real HOLE was self-inflicted: B-chua's ch_ua_on_safari_ua was
  Safari-ONLY, but Firefox ALSO never sends Sec-CH-UA (Mozilla declined Client Hints for privacy). So a
  Blink-faking-Firefox no-JS scraper slipped through. Broadened the edge check to non-Chromium (safari OR firefox)
  UAs and renamed the signal/rule to net.ch_ua_on_non_chromium_ua. GROUNDED LIVE: a Chromium given a FIREFOX UA now
  fires it (the closed gap); a Safari UA still fires; a native Chrome UA is silent. FP-safe (no real Safari/Firefox
  emits Sec-CH-UA). 18 grounded rungs. Audit takeaway: the network + browser signal layers are saturated — every
  emitted signal is read, corroborating-by-design, or infra-blocked; the remaining frontier is composition/fleet
  (R1) and the external-data floors (IP reputation, real-traffic calibration), as established.
- **[LOOP R1-capstone] the maximally-coherent per-node node grounded END-TO-END — 3-tell ceiling, one substrate
  wall (2026-07-02).** First full composition of the session's per-node work on ONE node: camoufox macOS (engine
  platform all-realms + Retina DPR + curated fonts, R-mac/R-font) + WebGL2 (real Xvfb llvmpipe GL) + provisioned
  floor + REAL coalesced input (KS_REAL_INPUT XTEST). GROUNDED LIVE, the ceiling is exactly THREE tells, and they
  categorise: (1) br.webgl_renderer_caps_mismatch = the ONLY hardware-SUBSTRATE wall (the 'Apple M1' renderer
  string is spoofed but the llvmpipe capability vector can't be — no real Apple GPU in-sandbox; the R-gl law);
  (2) br.webrtc_unavailable = provision/ICE infra; (3) net.tcp_os_vs_ua = kernel (os-spoof forges darwin, GROUNDED
  tcp_kernel=darwin through the macos-safari proxy, but the happy-path stack drops the larger collector POST →
  net.no_js_execution, so the browser coherence and the darwin kernel can't be shown on ONE session in-sandbox —
  an infra limit, not a detector gap). KS_REAL_INPUT cleared bh.synthetic_no_coalesced (real XTEST input yields
  coalesced pointer events; synthetic page.mouse.move does not). So the whole per-node ladder converges on ONE
  irreducible in-sandbox wall — the GL CAPS substrate (a real GPU) — with the rest provisionable/infra-bound. The
  per-node arms race is CONVERGED: the durable detector edge is the substrate the container can't fake (GPU caps),
  and beyond that it is the external floors (IP reputation, real egress). 18 grounded rungs + this capstone.
- **[LOOP dry-2a] webrtc_unavailable is INFRA-bound, not a provision gap (2026-07-02, honest negative).** Tried to
  reduce the R1 ceiling by fixing the webrtc tell (the provision comment claims KS_PROVISION clears it). GROUNDED
  it does NOT: plain camoufox KS_PROVISION (headless) fires br.webrtc_unavailable with webrtc_public_ip=None — and
  the collector's probe sets any=true on ANY ICE candidate (host/loopback/mDNS/srflx), so NONE arrived. Firefox in
  the sandbox container gathers ZERO ICE candidates: the STUN is unreachable (no srflx, expected) AND no host/
  loopback candidate forms either (a media.peerconnection.ice.loopback=True attempt did not help → REVERTED, not
  shipped ungrounded). So it is a container UDP/interface-enumeration block — an infra floor like the QUIC member
  (ADR-0005) and the delayed-ACK AF_PACKET wall, NOT a fixable provision pref in-sandbox. This SHARPENS the R1
  capstone: of the 3 ceiling tells, ONE is a hardware-substrate wall (GL caps / real GPU) and TWO are infra-bound
  (webrtc ICE gathering, kernel-forge-drops-the-POST) — NONE is a detector gap. The per-node detector holds
  completely; every residual is an environment/hardware floor the sandbox can't provision. Honest negative; a
  reduce-the-ceiling attempt that grounded the wall instead of moving it.
- **[LOOP CONCLUSION] in-sandbox arms-race ladder EXHAUSTED at convergence — 19 rungs, loop ended (2026-07-02,
  dry #2).** After the R1 capstone (per-node convergence) + the webrtc infra-negative (dry #1), this firing dug
  through FIVE more distinct axes for any new groundable rung and found each saturated, downstream, or
  external-bound: (1) COORDINATION — live-wired + tested (live_coordination), only real-proxy-egress stays
  external; the high-entropy collision keys (fp/trace/ticket) are taken and JA4T was rejected as low-entropy. (2)
  ARENA — a challenge-gate solver is downstream of the per-node coherence verdict (a browser-solver still hits the
  converged GL-caps wall; a no-JS solver still trips no_js_execution). (3) SIGNAL-OMISSION — a client can strip
  its own collector telemetry, but the NETWORK substrate (edge-observed TLS/h2/TCP) is un-fakeable + no_js_execution
  backstops a full strip. (4) WEB BOT AUTH — fully covered (invalid Ed25519 + nonce-replay + verified). (5) AUDIO
  worker-divergence — infeasible (OfflineAudioContext is not a worker realm). Two consecutive firings of thorough
  investigation yielded only infra floors + saturated axes → the loop's own twice-in-a-row-dry stop condition is
  MET; the cron loop is ended. THE GROUNDED VERDICT of the whole run: the per-node arms race CONVERGES on the
  network/hardware SUBSTRATE the sandbox cannot fake (TLS/h2 wire fingerprint, GL capability vector, TCP window
  auto-tuning, worker-realm coherence), with a single irreducible in-sandbox wall (GPU caps) and the durable
  frontier beyond it EXTERNAL-DATA-BOUND (IP reputation, real GPU/egress, real-scale coordination). Every string a
  client controls is spoofable; every substrate the edge measures holds. This loop shipped 19 grounded rungs +
  4 honest negatives across ~9 axes — the ladder is complete to its in-sandbox floor.
- **[LOOP REOPENED · MOBILE] Android coherent fingerprint is achievable — kernel/engine/TLS are NATIVE; font
  coherence SHIPPED (2026-07-02, grounded).** Reopened on the mobile axis. The grounded split: ANDROID is far
  closer to coherent than the converged desktop node because Android = Linux kernel + Blink engine + Chrome TLS,
  ALL native to the Linux/Chromium container — so net.tcp_os_vs_ua, apple_ua_nonwebkit, and tls_grease_vs_ua do
  NOT fire (no os-spoof, no WebKit needed). Grounded a KS_DEVICE='Pixel 5' + patchright device: residual 10 tells,
  of which only TWO were device-coherence (font_linux_leak + font_os_vs_ua — the container's desktop-Linux fonts
  under an Android UA). SHIPPED the fix: KS_ANDROID_FONTS masks the desktop-Linux SIGNATURE fonts (DejaVu/
  Liberation/croscore/Free/Ubuntu/Cantarell) via a fontconfig reject list, leaving only Noto (which Android also
  ships) — dropping the collector's font-OS probe below its 2-signature Linux threshold. GROUNDED LIVE: font_os_hint
  goes None and BOTH font tells clear; the residual is now automation (no_chrome_object/permissions → nodriver),
  floor (media/voices → KS_PROVISION; webgl_software → real GPU), headless (→ headful), behavioral (→ real input),
  and prevalence. The ONLY hard wall left is webgl_software — the SAME real-GPU wall as desktop, no mobile-specific
  wall. iOS remains harder (WebKit-on-Linux leaks navplatform=macOS + Linux fonts, needs os-spoof darwin + real
  Safari TLS). So: coherent ANDROID mobile is achievable to the desktop floor; coherent iOS needs a real WebKit/iOS
  runtime. Mobile axis reopened with a grounded rung.
- **[LOOP MOBILE B-model] net.ch_ua_mobile_no_model — the CH-layer catch for a desktop-faking-Android
  (2026-07-02, grounded).** A red attempt first: a window.chrome addInitScript shim to clear the Android
  no_chrome_object tell BROKE the collector (grounded: no-shim lands 2/2, shim fails 4/4 → a naive shim is fragile;
  no_chrome_object needs a native-window.chrome tool like nodriver, not a page shim) — reverted, then PIVOTED to a
  blue rung. The edge now advertises Accept-CH: Sec-CH-UA-Model; a REAL Android Chrome answers with its hardware
  model (e.g. Pixel 8) on the next request, but a DESKTOP Chromium — even KS_DEVICE emulating a Pixel UA — answers
  EMPTY, because the hint reads the REAL hardware not the spoofed UA (Playwright device emulation sets UA+viewport,
  not the model). So Sec-CH-UA-Mobile ?1 + present-but-empty Sec-CH-UA-Model = desktop faking Android at the CH
  layer → net.ch_ua_mobile_no_model (convicting, w0.6). A NETWORK tell that catches a NO-JS Android scraper too.
  GROUNDED LIVE: KS_DEVICE='Pixel 5' fires it (empty model); a desktop Chrome UA (?0) is out of scope. This
  catches EXACTLY last firing's font-coherent Android node — the mobile red⇄blue is live: KS_ANDROID_FONTS closed
  the font tell, and this opens a CH-layer one that the device emulation structurally can't fill. The RED counter
  is forging the Sec-CH-UA-Model header (route interception), which then must match the UA model string + the
  device screen — the mobile joint-coherence ratchet continues.
- **[LOOP MOBILE R-model] KS_FORGE_MODEL — forge Sec-CH-UA-Model to evade ch_ua_mobile_no_model, coherently
  (2026-07-02, grounded).** The red counter to B-model: route-interception injects Sec-CH-UA-Model set to the
  emulated device's model, parsed from the device UA (…Android 14; Pixel 5) …). GROUNDED LIVE: KS_DEVICE='Pixel 5'
  fires ch_ua_mobile_no_model; + KS_FORGE_MODEL it CLEARS. Crucially this is a COHERENT forge, not a bare bypass —
  the injected model 'Pixel 5' matches the device UA AND the KS_DEVICE screen/DPR, so it is on the real-Pixel
  manifold. So the mobile CH-layer is now spoofable (like every header string — the R-gl/R-chua law), and the
  DURABLE blue counter must be the JOINT: model ↔ UA-model-string ↔ screen/DPR — a device-model→screen DB (the
  Android analog of the iOS offmanifold, keyed by model). A mismatched forge (model 'Pixel 5' but a Galaxy screen)
  is what that DB check would catch; a coherent randomizer drawing model+screen+UA from ONE real Android device
  evades. Mobile red⇄blue now 2-for-2 (KS_ANDROID_FONTS / ch_ua_mobile_no_model / KS_FORGE_MODEL), each rung
  surfacing the next — exactly the joint-manifold dynamic the desktop ladder converged on, now on mobile.
- **[LOOP MOBILE B-jsmodel] br.mobile_no_js_model — the JS twin that catches the header forge (2026-07-02,
  grounded).** The blue counter to R-model: navigator.userAgentData.getHighEntropyValues(['model']) is a JS
  surface that a real Android Chrome fills with the device (Pixel 8) but a desktop Chromium returns EMPTY (reads
  real hardware) — even under KS_DEVICE emulation (sets UA+viewport+mobile, not the high-entropy model). So
  userAgentData.mobile + empty getHighEntropyValues().model = desktop faking Android. GROUNDED LIVE, the decisive
  contrast: KS_DEVICE='Pixel 5' fires BOTH mobile_no_js_model (JS) and ch_ua_mobile_no_model (header); + KS_FORGE_MODEL
  the HEADER check CLEARS but the JS check STILL FIRES — the route-interception forge patches the header, not the
  JS surface. So the model must be coherent across THREE surfaces: the Sec-CH-UA-Model HEADER, main-thread
  getHighEntropyValues, AND the WORKER (forging the JS via Object.defineProperty is caught by uadata_worker_divergence,
  userAgentData being in the worker realm). A desktop emulation can fill at most the header (route) or main-JS
  (defineProperty, caught by the worker); only a REAL Android device fills all three natively. The mobile CH-UA-Model
  joint is now a 3-surface ratchet — the same realm-backed durability the desktop realm rungs (deviceMemory/userAgentData
  worker-divergence) established, applied to the mobile model. Mobile red⇄blue: 4 rungs, tightly interlocked.
- **[LOOP MOBILE R-jsmodel] KS_FORGE_JS_MODEL — forge the JS model too, both model checks evaded (2026-07-02,
  grounded).** The red counter to B-jsmodel: an addInitScript override of NavigatorUAData.prototype.getHighEntropyValues
  (PROTOTYPE, not instance — an instance assignment did NOT take, the collector reads via the prototype) injects
  the device model into the resolved values. GROUNDED LIVE: KS_DEVICE='Pixel 5' + KS_FORGE_MODEL + KS_FORGE_JS_MODEL
  → BOTH mobile_no_js_model (JS) AND ch_ua_mobile_no_model (header) CLEAR. Critically uadata_worker_divergence does
  NOT catch it — that rule keys on userAgentData.platform|mobile, NOT the model. So the 3-surface ratchet has a
  HOLE: the model is currently forgeable on header (route) + main-JS (prototype override), with no live check on
  the model in the worker. The DURABLE blue counter (next rung) is a WORKER-realm model check: the worker's
  getHighEntropyValues returns the real EMPTY model, diverging from the forged main — a main-only prototype patch
  cannot reach the worker (→ br.worker_source_rewritten if it tries). Alternatively a getHighEntropyValues
  NATIVENESS check (the override's toString lacks [native code]) — but a Proxy can spoof that, so the worker-realm
  check is the robust one, consistent with the whole session's realm-backed-durability finding. 5 mobile rungs.
- **[LOOP MOBILE B-workermodel] br.uadata_model_worker_divergence — closes the model ratchet at the worker realm
  (2026-07-02, grounded).** The durable blue counter to R-jsmodel, exactly as predicted. Made the worker probe
  ASYNC and had it resolve navigator.userAgentData.getHighEntropyValues(['model']) — the Worker gets the REAL
  hardware model (empty on a desktop faking Android). A main-thread prototype override that forges the model never
  reaches Worker scope, so main (forged 'Pixel 5') and worker (real '') disagree → fires. GROUNDED LIVE, the
  decisive close: KS_DEVICE='Pixel 5' + KS_FORGE_MODEL + KS_FORGE_JS_MODEL (which clear BOTH the header and main-JS
  model checks) now trips uadata_model_worker_divergence; an un-forged Pixel (both realms empty) does NOT. The
  mobile CH-UA-Model is now a COMPLETE 3-surface ratchet — header (route-forgeable) + main-JS (prototype-forgeable)
  + WORKER (realm-backed, only a real device or a self-incriminating worker-source rewrite fills it). This mirrors
  the desktop deviceMemory/userAgentData worker-divergence rungs exactly: the durable edge is the WORKER REALM a
  main-thread patch cannot reach. Mobile red⇄blue: 6 tightly-interlocked rungs, the model joint now closed to its
  realm floor — a coherent Android spoof must present a REAL device's model across all three surfaces (which the
  KS_DEVICE emulation cannot), or fall to the worker check. The mobile axis is reproducing the desktop convergence.
- **[LOOP MOBILE B-modelscreen] br.android_model_screen_incoherent — the model↔screen joint (2026-07-02,
  grounded).** With the model pinned across 3 surfaces (B-workermodel), the fresh joint is model ↔ SCREEN: a
  claimed Android model names a handset whose logical screen is device-fixed. Seeded a per-model portrait-screen
  set from Playwright's maintained Android device registry (Pixel 2..7, Nexus, Galaxy SM-*; real device data) and
  the collector keys getHighEntropyValues().model against the actual screen. GROUNDED LIVE, the manifold contrast:
  KS_DEVICE='Pixel 5' + forged model 'Pixel 5' (screen 393x851 MATCHES) is SILENT; KS_DEVICE='Pixel 7' (412x915) +
  forged model 'Pixel 5' (expects 393x851) FIRES — model and screen drawn from DIFFERENT devices. The Android
  analog of br.ios_screen_offmanifold but keyed by the EXACT model (tighter than set-membership). EXPERIMENTAL
  (w0.5): fires only for a model in the maintained set with a mismatched screen (unknown/new models skip → FP-safe;
  set needs refresh). A COHERENT randomizer (model+screen+UA from ONE real device, as KS_DEVICE does) evades by
  construction — the manifold point: mobile coherence now REQUIRES drawing the whole tuple from one real device,
  exactly as the desktop device-manifold rungs established. 7 mobile rungs; the model joint is closed AND its
  screen-consistency is enforced. The remaining Android residual to the desktop floor is automation (native tool)
  + provision + webgl_software (real GPU) — no NEW mobile-specific coherence gap beyond the (real-device) manifold.
- **[LOOP MOBILE capstone] the Android node grounded end-to-end — the model ratchet + GPU are TWO hard walls
  (2026-07-02).** Composed the full Android node (KS_DEVICE=Pixel 5 + PATCHRIGHT + KS_ANDROID_FONTS + KS_PROVISION
  + the model forges) and read the residual: 9 tells, and the decisive finding is that MY OWN blue model ratchet
  CATCHES the red forge. The model forges clear the header + main-JS model checks but trip
  br.uadata_model_worker_divergence (KS_FORGE_JS_MODEL patches main-JS, not the worker) — the realm-backed check
  from the prior firing convicts the composed node. So mobile has TWO in-sandbox hard walls, not one: (1) the
  CH-UA-Model ratchet — a desktop CANNOT present a real device's model (empty → header/JS checks; forged → worker
  check; a real Android fills all three natively); (2) webgl_software (real GPU). The rest is tool/provision-fixable
  (automation → nodriver, voices → the Chromium-headless-TTS limit noted on desktop, ch_he_headless → headful,
  fingerprint_improbable → resolves as the others clear). So ANDROID is actually HARDER to fake coherently than
  desktop was: desktop converged on ONE wall (GPU); mobile has the GPU wall PLUS the model-ratchet wall (a
  session-built blue axis that a desktop-faking-Android cannot cross). A coherent Android fingerprint therefore
  requires a REAL Android device (real model + real GPU), not a Chromium emulation — the honest answer to
  "can we achieve coherent mobile fingerprints": Android in principle yes, but only on real hardware, and the
  detector now holds two independent walls. 7 mobile rungs + this capstone; the Android axis has converged.
- **[LOOP MOBILE R-iosfonts] KS_MOBILE_FONTS — generalise the font mask to iOS; iOS converges on 3 hard walls
  (2026-07-02, grounded).** The desktop-Linux font mask (KS_ANDROID_FONTS) is engine-agnostic — it works on the
  WebKit iOS node too. Generalised the flag to KS_MOBILE_FONTS (KS_ANDROID_FONTS kept as alias). GROUNDED LIVE:
  KS_ENGINE=webkit + KS_DEVICE='iPhone 15' + KS_MOBILE_FONTS → font_os_hint None, br.font_os_vs_ua CLEARED (the
  probe drops below its 2-signature Linux threshold on WebKit exactly as on Blink). But the iOS node's OTHER three
  residuals are HARD walls that do NOT clear in-sandbox: (1) br.navplatform_vs_ua — Playwright's WebKit reports
  navigator.platform='MacIntel' (desktop WebKit), not 'iPhone'; a JS patch is caught by worker_divergence (platform
  is in the worker probe) and Playwright can't engine-level spoof it; (2) net.tcp_os_vs_ua — iOS is darwin, the
  container is linux, needs the os-spoof darwin proxy (which drops the collector POST); (3) net.tls_grease_vs_ua —
  Playwright's Linux WebKit ClientHello ≠ real iOS Safari's, needs a uTLS-HelloIOS chain-mitm. So iOS has THREE
  hard in-sandbox walls (platform-realm, kernel, TLS) vs Android's TWO (model-ratchet, GPU) vs desktop's ONE (GPU)
  — a strict hierarchy: iOS is the hardest to fake coherently, and needs a REAL WebKit/iOS runtime, not a
  Linux-container stand-in. 8 mobile rungs; both mobile OSes converged, each on a distinct set of real-hardware
  walls the container cannot provision.
- **[LOOP MOBILE B-pointerhover] br.mobile_pointer_hover_desktop — pointer/hover realism, mobile-side (2026-07-02,
  grounded).** Dug past the "converged" call and found an untouched joint: the collector had hover_none_desktop
  (a DESKTOP claiming no-hover) and pointer_touch_incoherent (any-pointer coarse vs maxTouchPoints), but NOTHING
  for the mobile-side inverse — a mobile UA with a DESKTOP pointer surface. A real phone has PRIMARY (pointer:
  coarse) + (hover: none); a UA claiming Mobile/Android/iPhone whose (pointer: fine) or (hover: hover) matches is a
  desktop wearing a mobile UA without emulating the touch device (the lazy UA-only spoof — CDP setUserAgentOverride
  sets the string but not isMobile/hasTouch, so the CSS pointer surface still describes a mouse). GROUNDED LIVE:
  SPOOF_UA=<Pixel 5 mobile UA> with NO device emulation FIRES mobile_pointer_hover_desktop; KS_DEVICE='Pixel 5'
  (full emulation, pointer coarse + hover none) is SILENT. FP-safe by construction (every real phone has coarse
  pointer + no hover; a full device emulation sets both media). This catches a no-device mobile spoof the model/
  font/screen rungs miss (they need a real Chromium device or fire on emptiness) — a distinct entry point. 9 mobile
  rungs: the "converged" call was premature at the per-surface level — the pointer/hover surface was still open.
- **[LOOP MOBILE B-androiddpr] br.android_mobile_dpr1 — Android backing-scale realism (2026-07-02, grounded).**
  Continuing the per-surface sweep, found the DPR gap: the collector bounded iOS DPR (ios_dpr_incoherent, must be
  2/3) and macOS DPR (macos_dpr1), but had NO Android bound. A modern Android PHONE (a 'Mobile' token on a current
  Chrome) is high-density — DPR ∈ {1.5, 2, 2.625, 2.75, 3, 3.5, 4}, NEVER exactly 1 (the desktop default). So an
  Android 'Mobile' UA with devicePixelRatio === 1 is a desktop that set the screen/touch surfaces but not the
  backing scale. GROUNDED LIVE: SPOOF_UA=<Pixel 5 mobile UA> (no device, DPR 1) FIRES android_mobile_dpr1;
  KS_DEVICE='Pixel 5' (DPR 2.75) is SILENT. FP-safe: gated on the 'Mobile' token (phones, not low-density tablets/
  TV), every modern phone >= 1.5x. EXPERIMENTAL (w0.5). A distinct backing-scale entry point beside the pointer
  (B-pointerhover) and screen (android_phone_screen_oversized) surfaces. 10 mobile rungs — the per-surface sweep is
  paying out (pointer, then DPR), so the mobile axis is NOT yet dry; the UA-only/partial mobile spoof is now caught
  on pointer + DPR + screen + touch independently. Next sweep: orientation, and the codec/GPU mobile surfaces.
- **[LOOP MOBILE B-cores] br.mobile_cores_high — mobile core-count realism, and it catches the FULL emulation
  (2026-07-02, grounded).** First tried the platform surface — DEAD END: ch_platform is set coherently by the
  stealth UACH path, and ua_platform_vs_ch_platform already catches a raw Linux platform, so no gap. Pivoted to
  hardwareConcurrency and found a real one: the 12-core test host reports hardware_concurrency=12 for BOTH
  SPOOF_UA AND KS_DEVICE=Pixel — Playwright/CDP device emulation sets UA+screen+touch+DPR but does NOT spoof
  hardwareConcurrency (it reads the real host). A real phone (a 'Mobile' UA) exposes <= 8 web cores (mobile SoCs
  are octa-core at most, iOS A-series 6), so a 'Mobile' UA with hardwareConcurrency > 8 is a desktop. GROUNDED
  LIVE: KS_DEVICE='Pixel 5' on the 12-core host FIRES mobile_cores_high; a hw=2 spoof (WORKER_SPOOF) is SILENT
  (FP-safe at <= 8). UNLIKE the pointer/DPR rungs (which only catch the UA-only spoof), this catches the FULL
  Playwright Android emulation — a genuine residual the capstone missed, because the emulation leaks the host core
  count. FP-safe: gated on 'Mobile' (phones, not M-series iPads). EXPERIMENTAL (w0.5). The RED counter (spoof hw
  <= 8) is realm-backed: main-only trips worker_divergence, worker-scope trips worker_constructor_tampered — so a
  coherent low core count needs a real <= 8-core device (or a <= 8-core host), like the model ratchet. 11 mobile
  rungs; the sweep is still productive AND now reaching residuals the wall-level capstone under-counted.
- **[LOOP MOBILE R-headful] the HEADFUL Android node — automation solved, the irreducible floor exposed
  (2026-07-02, grounded).** Drove the Android node with the full composition: KS_DEVICE='Pixel 5' + PATCHRIGHT +
  HEADFUL + KS_MOBILE_FONTS + KS_PROVISION → residual collapses to SEVEN tells (from ~10). HEADFUL is the key: it
  cleared BOTH automation residuals the prior capstone still had — no_chrome_object (a HEADFUL patchright exposes
  window.chrome natively, so the fragile addInitScript shim that broke the collector was never needed) AND
  permissions_anomaly (headful has a real permission state), PLUS ch_he_headless (headless→headful) and the
  automation_globals/cdp/webdriver cluster (patchright), media_devices_empty (provision), and the font tells (mask).
  So RED ladder rungs (1) clear-automation and (2) compose-to-floor are DONE — via HEADFUL, not the shim. The
  IRREDUCIBLE Android floor is now exposed and every remaining tell is a real-hardware/real-device wall or a
  provisionable/behavioral floor: mobile_cores_high (the 12-core host — needs a <=8-core host), webgl2_missing
  (real GPU), the model ratchet (ch_ua_mobile_no_model + mobile_no_js_model — a real device or a worker-caught
  forge), voices_empty (the Chromium-headless-TTS limit, unchanged), tls_ext_order_static (a within-session TLS
  artifact), keystroke_entropy_floor (real input). VALIDATION: mobile_cores_high fires even on this MAX-composed
  node, confirming it is a genuine residual, not an artifact of a lazy config. So the Android node reaches the SAME
  provision/real-hardware floor as desktop — automation is fully solved — with mobile's extra model-ratchet + core
  walls on top. 12 mobile rungs; the Android node is now driven to its floor and every residual is characterised.
- **[LOOP MOBILE B-gpufamily] br.mobile_gpu_not_mobile — mobile GPU-family coherence, broader than webgl_software
  (2026-07-02, grounded).** The ladder's mobile GPU<->device rung. A phone/tablet renders WebGL on a MOBILE GPU:
  Adreno (Qualcomm), Mali/Immortalis (ARM), PowerVR, Apple GPU, Xclipse (Samsung), Tegra, VideoCore. A Mobile/
  Android/iPhone UA whose UNMASKED_RENDERER names none of these is a desktop faking mobile. The KEY over
  webgl_software: that rule fires ONLY on a software rasteriser (SwiftShader/llvmpipe); this ALSO convicts a
  scraper on a real DESKTOP GPU (NVIDIA/Radeon/discrete Intel) under a phone UA — which webgl_software misses
  because a hardware desktop GPU is not 'software'. GROUNDED LIVE, both cases: (1) KS_DEVICE='Pixel 5' (SwiftShader)
  fires it; (2) THE DISTINCTIVE CASE — SPOOF_UA=<Pixel UA> + FULL (renderer spoofed to 'NVIDIA GeForce RTX 3060')
  FIRES mobile_gpu_not_mobile while webgl_software stays SILENT — catching a desktop-GPU scraper the software check
  cannot. FP-safe (the family list covers shipping mobile GPUs; scoped to a present renderer). The RED counter
  (spoof the renderer to a mobile GPU) is main-only-caught by webgl_worker_divergence (the OffscreenCanvas Worker
  renderer), so a coherent mobile GPU needs REAL mobile silicon — realm-backed like the model/cores rungs.
  EXPERIMENTAL (w0.6). 13 mobile rungs; the sweep keeps finding distinct value — this one is not a UA-only-spoof
  catcher but a GPU-substrate check that convicts a real-hardware desktop scraper faking mobile.
- **[LOOP MOBILE — honest negative #1] CPU architecture is NOT groundably catchable (2026-07-02).** Investigated
  the Sec-CH-UA-Arch / getHighEntropyValues(['architecture']) surface as a host-substrate leak (like cores). It is
  NOT catchable, for a grounded reason: Chromium AUTO-DERIVES a coherent userAgentData (platform + architecture +
  mobile) from the context.userAgent STRING. Grounded: SPOOF_UA=<a Pixel Android UA> alone (no UACH override)
  reports ch_arch='arm' + ch_platform='Android' — the arch is 'arm', NOT the host 'x64', purely from the UA string.
  KS_DEVICE='Pixel 5' likewise reports arch='arm'. So (a) NO evader can produce a mobile-UA + desktop-arch session
  to ground the FP-safe check (mobile + arch=x86 → desktop); and (b) a real Android almost certainly reports 'arm'
  too (same derivation), so the alternative 'mobile + arch non-empty → bot' check would FALSE-FIRE on real Android
  (WebSearch: the UA-CH spec only says mobile MAY return empty arch — not a guarantee to build an FP-safe rule on).
  Shipping either would violate the ground-LIVE + FP-safe discipline, so nothing shipped. KEY INSIGHT (explains the
  platform dead-end too): Chromium's UA-string→UA-CH auto-derivation means the platform/arch/mobile CH surfaces are
  COHERENT for free even on a naive UA-only spoof — which is why the productive mobile leaks are the ones Chromium
  does NOT derive (hardwareConcurrency, the GPU renderer, the high-entropy MODEL) rather than the ones it does. This
  is the FIRST of the two-in-a-row dry firings the loop's stop-condition requires; the next firing must ALSO fail to
  find a groundable rung to end the mobile axis. 13 rungs stand.
- **[LOOP MOBILE — honest negative #2 → AXIS CLOSED] audio can't discriminate mobile from desktop; the mobile
  axis is at its groundable terminus (2026-07-02).** Genuine second attempt: the audio surface. DEAD END for a
  grounded engine-level reason — the collector's audio FP is OfflineAudioContext, PURE computation determined by
  the Blink engine, so it is IDENTICAL on Android and desktop Chromium (Android IS Blink); no audio_* signal fires
  on the Pixel node, and the real-time AudioContext.sampleRate is FP-risky (desktops vary 44100/48000) and
  provision-dependent. That is TWO consecutive dry firings (arch, audio), each with a genuine attempt and a
  grounded reason, so per the loop's own stop-condition the MOBILE AXIS IS CLOSED. Full remaining-surface map
  (why each is closed): platform/arch/bitness/platformVersion → Chromium AUTO-DERIVES them coherently from the UA
  string (coherent-for-free on any spoof); audio → engine-pure, identical Android/desktop Blink; deviceMemory →
  spec-capped at 8, not discriminating; orientation/codec → redundant with the screen/oversized rungs or
  build-dependent-corroborating; model↔GPU-family → subsumed by the worker GPU realm check + real-hardware
  coherence. The PRODUCTIVE leaks were exactly what Chromium does NOT derive and the engine does NOT fix: the
  host CPU cores, the GPU renderer, and the high-entropy model — all now caught. FINAL MOBILE LADDER (13 rungs):
  KS_ANDROID_FONTS/KS_MOBILE_FONTS (R, font coherence Android+iOS) · ch_ua_mobile_no_model (B, header model) ·
  KS_FORGE_MODEL (R, header forge) · mobile_no_js_model (B, main-JS model) · KS_FORGE_JS_MODEL (R, JS forge) ·
  uadata_model_worker_divergence (B, worker model — closes the 3-surface model ratchet) · android_model_screen_
  incoherent (B, model↔screen) · mobile_pointer_hover_desktop (B, pointer/hover) · android_mobile_dpr1 (B, backing
  scale) · mobile_cores_high (B, core count — catches the FULL emulation) · mobile_gpu_not_mobile (B, GPU family —
  broader than webgl_software) · R-headful (automation solved) · R-iosfonts (iOS convergence). THE ANSWER to 'can
  we achieve coherent mobile fingerprints': ANDROID reaches the desktop floor but with TWO extra in-sandbox walls
  (the CH-UA-Model 3-surface ratchet + the mobile core-count/GPU-family checks) — a coherent Android fingerprint
  needs REAL Android hardware (real model + <=8 cores + a mobile GPU), not a Chromium emulation; iOS is HARDER
  still (three walls: platform-realm + kernel + TLS, needs a real WebKit/iOS runtime). Mobile is STRICTLY harder
  to fake than desktop, iOS hardest — a clean hierarchy. Loop 8ac28e2e retired.
- **[LOOP MOBILE REOPENED — the two-dry close was PREMATURE] br.mobile_gpu_caps_mismatch — the mobile source-fork
  GPU tell (2026-07-02, grounded).** Challenged on "is this actually the floor?", re-audited the dismissals and
  found one that was REASONING, not grounding: the mobile GPU-caps surface. The existing webgl_renderer_caps_mismatch
  patterns ONLY desktop high-end GPUs (RTX/Radeon/Apple-M/Arc); there was NO mobile equivalent. A SOURCE-LEVEL FORK
  that patches the renderer string in BOTH realms to a high-end mobile GPU (e.g. 'Adreno 730') over a SwiftShader
  (8192) backend slips past EVERY existing GPU rung: mobile_gpu_not_mobile passes (Adreno IS a mobile family),
  webgl_software passes (not software), and the both-realm patch evades webgl_worker_divergence — yet MAX_TEXTURE_SIZE
  (real Adreno 6xx+/Mali-G7x+ = 16384) cannot be string-patched. GROUNDED LIVE: SPOOF_UA=<Pixel UA> + KS_RENDERER=
  'Adreno 730' over the 8192 backend FIRES mobile_gpu_caps_mismatch while mobile_gpu_not_mobile AND webgl_software
  BOTH stay silent — catching the fork none of the others see; KS_DEVICE='Pixel 5' (honest SwiftShader) does NOT fire
  it (correctly caught by mobile_gpu_not_mobile instead). FP-safe (real high-end mobile GPUs >=16384; lesser mobile
  GPUs carry lesser strings out of pattern). CONVICTING (w0.7). LESSON: this is the 4th premature-convergence call
  this session (after model↔screen, and the two-dry close) — the source-level-fork frontier (both-realm string spoofs
  vs unspoofable silicon/realm facts) is a live seam the per-surface sweep under-explored. 14 mobile rungs; axis
  REOPENED — the honest next targets are the OTHER both-realm-fork gaps (model↔GPU-family for a coherent-but-wrong
  mobile GPU; other WebGL caps beyond maxTexture; WebGPU adapter caps↔renderer). Loop re-armed.
- **[LOOP MOBILE B-modelgpu] br.android_model_gpu_incoherent — model↔GPU-family on the source-fork frontier
  (2026-07-02, grounded).** First of the reopened-axis frontier leads. Pixels have a DETERMINISTIC SoC per
  generation: Pixel 1-5 = Snapdragon (Adreno), Pixel 6+ = Google Tensor (ARM Mali/Immortalis). Since the model is
  already realm-ratcheted across 3 surfaces, a pinned Pixel model + a mobile GPU of the WRONG family for that
  generation is a source-fork that spoofed a COHERENT mobile GPU string (evading mobile_gpu_not_mobile — Mali IS a
  mobile GPU) but the wrong one for the claimed device. GROUNDED LIVE: KS_DEVICE='Pixel 5' + KS_FORGE_JS_MODEL=
  'Pixel 5' + KS_RENDERER='Mali-G78' (Pixel 5 is Adreno) FIRES android_model_gpu_incoherent while
  mobile_gpu_not_mobile stays SILENT; the same with KS_RENDERER='Adreno (TM) 620' (correct) does NOT fire it.
  FP-safe (scoped to Pixels — Google fixes the SoC per generation; fires only on a mobile GPU family the claimed
  Pixel never shipped). EXPERIMENTAL (w0.6). 15 mobile rungs. The source-fork frontier is real and productive —
  two rungs in (GPU-caps, model↔GPU) since the premature close was corrected; still-open: other WebGL caps (max
  viewport / uniform vectors / MSAA) vs the claimed GPU, WebGPU adapter caps↔renderer, and the model↔SoC extended
  to Samsung (region-ambiguous, needs an allowed-set). NOT closing cheaply.
- **[LOOP MOBILE B-modeldpr] br.android_model_dpr_incoherent — model↔DPR, an axis independent of model↔screen
  (2026-07-02, grounded).** First checked the deeper GPU-caps evasion (a fork spoofing MAX_TEXTURE_SIZE too): that
  gap is CLOSED — the worker probe sends the full caps digest and br.webgl_caps_worker_divergence (demo.py ~2622)
  catches a main-only caps spoof; the both-realm-consistent-caps case terminates at ACTUAL-GPU-RENDERING, which is
  external-data-bound (needs real-GPU render reference), a grounded boundary not a lazy dismissal. So took a clean
  device-manifold joint instead: model↔DPR. A Pixel model has a device-FIXED backing scale (Pixel 5 = 2.75, Pixel 7
  = 2.625, Pixel 4 = 3) — a SEPARATE axis from the CSS screen (physical = CSS*DPR), so a randomizer/fork can get the
  screen right yet the DPR wrong. GROUNDED LIVE: KS_DEVICE='Pixel 7' (DPR 2.625) + KS_FORGE_JS_MODEL='Pixel 5'
  (expects 2.75) FIRES; KS_DEVICE='Pixel 5' + 'Pixel 5' (2.75) SILENT. FP-safe (Pixel model→DPR from Playwright's
  deviceScaleFactor, the same corpus model↔screen trusts; > 0.02 tolerance). EXPERIMENTAL (w0.5; DPR map needs
  calibration as Pixels ship). HONEST NOTE: this is a device-manifold rung (incremental over model↔screen), NOT a
  source-fork-substrate rung like GPU-caps/model↔GPU — the pure-substrate GPU-caps surface is now defended to its
  in-sandbox terminus (realm divergence covered; actual-rendering is external-data). 16 mobile rungs. Still-open
  frontier: Samsung model↔GPU (region allowed-set), WebGPU adapter caps↔renderer WHEN an adapter is present, and
  the actual-GPU-rendering terminus if a real-GPU reference corpus becomes available.
- **[LOOP MOBILE hardening] mobile_gpu_caps_mismatch extended to the full cap TRIAD; WebGPU tested-dead
  (2026-07-02, grounded).** First TESTED (not reasoned) the WebGPU-adapter lead: DEAD — the container exposes NO
  WebGPU adapter headless OR headful (both report webgpu_no_adapter), so there is nothing to cross-check; grounded
  dead-end. Then closed a real both-realm-fork gap in the GPU-caps check: it keyed ONLY on MAX_TEXTURE_SIZE, so a
  fork that fakes JUST maxTexture (to 16384) in both realms evaded it AND webgl_caps_worker_divergence (the digests
  stay consistent across realms) while leaving MAX_RENDERBUFFER_SIZE / MAX_VIEWPORT_DIMS at the real 8192. Extended
  mobile_gpu_caps_mismatch to check the FULL triad (any of the three < 16384 for a high-end mobile GPU string).
  GROUNDED LIVE the distinctive case: KS_RENDERER='Adreno 730' + KS_FAKE_MAXTEX (added to the evader — patches
  MAX_TEXTURE_SIZE to 16384) reports webgl_max_texture=16384 (faked) yet STILL FIRES via the renderbuffer/viewport
  arm (rb 8192). A fork must now fake the ENTIRE limit vector consistently across BOTH realms to evade — which
  converges on the actual-rendering terminus (can't allocate a real 16384 surface on an 8192 backend). 16 rungs +
  this hardening. Distinguished grounded-dead-end (WebGPU: no adapter) from the closable gap (caps triad) and
  tested both — the discipline the premature close lacked.
- **[LOOP MOBILE B-alloc] br.webgl_maxtexture_unallocatable — the UNSPOOFABLE floor; my 'external-data terminus'
  claim was wrong (2026-07-02, grounded).** Last firing I called the actual-rendering terminus 'external-data-
  bound (needs a real-GPU corpus)'. TESTED that instead of accepting it — WRONG. getParameter(MAX_TEXTURE_SIZE) is
  a value a both-realm fork fakes to 16384, but gl.texImage2D validates against the REAL GL backend: a
  (claimedMax x 1) texture — 1 row, ~64KB, NO memory confound — succeeds on silicon that supports the dimension
  and FAILS (INVALID_VALUE) on SwiftShader (real 8192) claiming 16384. NO getParameter/caps patch in any realm
  repairs it — the allocation reaches the real driver. Needs NO external corpus (the earlier 'terminus needs
  real-GPU reference' was itself a reasoned dismissal that did not hold). Guarded against a getError patch: the
  probe first verifies getError is HONEST (a deliberately-invalid getParameter must raise INVALID_ENUM) before
  trusting the allocation error. GROUNDED LIVE: KS_RENDERER='Adreno 730' + KS_FAKE_MAXTEX (getParameter reports
  16384 over the real 8192 backend) FIRES webgl_maxtexture_unallocatable — the alloc fails though the cap READS
  16384; honest KS_DEVICE='Pixel 5' (claims + allocates 8192) does NOT fire. CONVICTING (w0.8). FP-safe: an honest
  device allocates its OWN claimed max; only claim > real fails. This is the hard floor: it forces the source-fork
  off cheap string/value spoofing and onto patching the ACTUAL rendering pipeline (invasive, breaks real WebGL,
  getError-guard catches the naive version). 17 mobile rungs. The lesson recurs — a 'terminus/floor' is only real
  once the reasoned dismissal behind it is itself tested; this is the THIRD time testing a dismissal broke it open.
- **[LOOP MOBILE R-bothrealm + CORRECTION] KS_RENDERER_WORKER (true both-realm fork) reveals the WebGL worker
  checks are INACTIVE in-sandbox; the substrate walls carry the defense (2026-07-02, grounded).** Built the TRUE
  source-level fork: KS_RENDERER_WORKER wraps Worker() to inject the renderer patch into WORKER scope too (fetches
  the collector's blob source via sync XHR, prepends the getParameter patch, re-blobs), so main AND worker report
  the same spoofed 'Adreno 730' — the both-realm string spoof that DEFEATS realm-divergence. Grounding it surfaced
  a CORRECTION of the prior firing: br.webgl_worker_divergence and br.webgl_caps_worker_divergence do NOT fire even
  on a MAIN-ONLY WebGL spoof — because OffscreenCanvas WebGL returns null in a Worker in this container (SwiftShader
  headless), so those two checks are INACTIVE in-sandbox. PROVEN the worker REALM itself works (KS_SPOOF_DM main-
  only → br.devicememory_worker_divergence FIRES), so it is specifically the WebGL-in-worker probe that is null, not
  the realm mechanism. So last firing's 'webgl_caps_worker_divergence closes the main-only maxTexture gap' was a
  REASONED claim that does NOT hold here — the main-only WebGL spoof is NOT caught by the (inactive) worker check;
  it is caught by the MAIN-realm substrate walls br.mobile_gpu_caps_mismatch (caps triad) + br.webgl_maxtexture_
  unallocatable (actual allocation), which need no worker. GROUNDED: with KS_RENDERER_WORKER (full both-realm
  renderer spoof) mobile_gpu_caps_mismatch STILL FIRES — the caps/allocation substrate walls are realm-independent
  and carry the entire mobile-GPU defense in this environment. So the source-fork's realm-evasion (the whole point
  of a both-realm fork) buys it NOTHING against the substrate walls, which are the true floor. 17 rungs + this
  RED capability & correction; the discipline caught my own prior over-claim.
- **[LOOP MOBILE B-uniforms] br.mobile_gpu_uniforms_software — closes the LOW-END-GPU evasion (2026-07-02,
  grounded).** Rather than accept the GPU surface as walled, TESTED a specific evasion: a fork claiming a LOW-END
  mobile GPU whose real caps match SwiftShader's. GROUNDED the gap — KS_RENDERER='Adreno 505' (real MAX_TEXTURE_SIZE
  8192, which coincides with a genuine low-end phone GPU) fires NONE of mobile_gpu_not_mobile / mobile_gpu_caps_
  mismatch / webgl_maxtexture_unallocatable / webgl_software — the texture-floor rungs all key on the 16384 HIGH-end
  floor, so a low-end claim slips through. But SwiftShader ALSO reports MAX_VERTEX/FRAGMENT_UNIFORM_VECTORS = 4096,
  a SOFTWARE value; real mobile GPUs report 256-1024 (Adreno on a Nexus 5 = 256, per Qualcomm's dev docs — WebSearch-
  verified for FP-safety). So a renderer naming ANY mobile GPU family with vertex/fragment uniform capacity > 2048
  is a software backend wearing a mobile-GPU name. GROUNDED LIVE: Adreno 505 over SwiftShader (vu/fu 4096) FIRES
  mobile_gpu_uniforms_software while ALL texture-floor rungs stay silent; honest KS_DEVICE='Pixel 5' (SwiftShader
  string, not a mobile family) does NOT fire it (caught by mobile_gpu_not_mobile instead). FP-safe (256-1024 band,
  wide margin to 2048; desktop 4096 carries a desktop string out of scope). EXPERIMENTAL (w0.6). The RED counter
  (spoof uniform caps DOWN) is the next unspoofable tell: an actual-shader-compile probe (a shader using > the
  claimed uniform count still links on the real 4096 backend) — the uniform analog of the maxTexture allocation
  probe. 18 mobile rungs. Testing the 'caps match = terminus' assumption found a real gap AND its closer.
- **[LOOP MOBILE B-uniformcompile] br.gpu_uniform_underreport — the uniform actual-compile probe closes the surface
  both ways (2026-07-02, grounded).** Built the RED counter to B-uniforms AND its blue closer in one rung. RED:
  extended KS_FAKE_VU to spoof MAX_VERTEX/FRAGMENT_UNIFORM_VECTORS DOWN to a mobile 256 — which evades the value
  check mobile_gpu_uniforms_software (256 <= 2048). BLUE: the actual-compile probe (the uniform analog of
  webgl_maxtexture_unallocatable) — getParameter only changes what JS READS, but the GL compiler ENFORCES the real
  backend, so the collector compiles+links a vertex shader USING (reported + 40) uniform vec4s: a real device
  (reported == enforced) rejects it; a spoofed-down claim over SwiftShader's real 4096 LINKS. GROUNDED LIVE, the
  clean both-ways closure: (leave vu/fu HIGH 4096) mobile_gpu_uniforms_software FIRES / compile probe silent
  (out of scope); (spoof vu/fu DOWN 256 via KS_FAKE_VU) mobile_gpu_uniforms_software SILENT / gpu_uniform_underreport
  FIRES (the 296-uniform shader links on the real 4096). Unspoofable by getParameter (the compiler reaches the real
  silicon); FP-safe (a real mobile GPU's reported == enforced, so the over-claim shader fails). CONVICTING (w0.8).
  19 mobile rungs. The uniform surface now mirrors the texture surface — a value floor + an actual-behaviour probe —
  and the two GPU actual-behaviour probes (texture allocation, uniform compile) are the hard unspoofable walls that
  force the source-fork off getParameter spoofing entirely and onto a real GPU.
- **[LOOP MOBILE — grounded negative] shader mediump PRECISION does not distinguish SwiftShader from mobile
  (2026-07-02).** Tested a DISTINCT GPU substrate (not caps): shader numerical precision. Premise — mobile GPUs
  use fp16 mediump (precision ~10) while software/desktop use fp32 (23). GROUNDED IT and the premise was WRONG:
  SwiftShader reports FRAGMENT mediump/highp = 10/23 — it advertises the REDUCED fp16-characteristic mediump (10),
  exactly like a real mobile GPU. So getShaderPrecisionFormat does NOT betray SwiftShader; the value check is a
  dead-end (reverted, nothing shipped). The actual-COMPUTATION variant (does mediump physically band? SwiftShader
  might compute fp32 despite reporting 10) is FP-RISKY and external-data-bound: modern high-end mobile GPUs (Adreno
  6xx+) also PROMOTE mediump to fp32, so 'mediump doesn't band -> not mobile' would false-fire on them, and I cannot
  ground that real-device FP-safety in-sandbox. So precision is a grounded dead-end for a shippable rung. NOTE: not
  a full frontier-dry — other leads remain untested (MSAA if WebGL2 is present, deterministic-SoC model↔GPU for
  OnePlus/Samsung-by-suffix, the cores actual-parallelism). One surface tested and closed; the discipline (test the
  premise) again overturned it — this time to a dead-end rather than a rung, which is the honest other half of the
  same rule.
- **[LOOP MOBILE B-modelos] br.android_model_os_predates — model↔OS-version release-date coherence (2026-07-02,
  grounded).** A NEW axis, not GPU/screen/DPR: a device physically CANNOT run an Android OLDER than the one it
  SHIPPED with (Pixel 2=8, 3=9, 4=10, 5=11, 6=12, 7=13, 8/9=14). First GROUNDED that platformVersion is usable
  (unlike the empty model): getHighEntropyValues(['platformVersion']) is the real OS major, Chromium-derived from
  the Android UA (KS_DEVICE='Pixel 5' -> 11, 'Nexus 5' -> 6.0). The model is already pinned by the 3-surface
  ratchet, so a pinned Pixel with platformVersion BELOW its launch is a randomizer/fork that paired a real model
  with an impossible OS. GROUNDED LIVE: KS_DEVICE='Nexus 5' (platformVersion 6.0) + KS_FORGE_JS_MODEL='Pixel 5'
  (launch 11) FIRES (6 < 11); KS_DEVICE='Pixel 5' + 'Pixel 5' (11) SILENT (11 >= 11). FP-safe (a device runs
  launch-or-newer; scoped to Pixels' deterministic launch dates); EXPERIMENTAL (w0.6; custom-ROM-older-Android the
  vanishing confound). 20 mobile rungs. The device-manifold now constrains a fork on FOUR independent axes — screen,
  DPR, GPU-family AND OS-version — each drawn from ONE real device; a coherent Android spoof must satisfy all four
  plus the unspoofable GPU substrate probes. After a precision dead-end, a clean new-axis rung — the frontier still
  yields when tested.
- **[LOOP MOBILE — grounded negative] cores actual-parallelism is not viable in a CPU-quota environment
  (2026-07-02).** Tested the one distinct-substrate lead I had dismissed as 'noisy' (the CPU analog of the GPU
  actual-behaviour probes): measure real parallelism via 16-worker throughput and catch a both-realm
  hardwareConcurrency spoof. GROUNDED it — the measurement is CONSISTENT (est 4.8/4.8/4.7 across runs, NOT noisy)
  but reads ~4.8 while hardwareConcurrency reports 12: the Docker container is CPU-QUOTA-limited to ~5 effective
  cores. So measured parallelism reflects the CPU QUOTA / scheduling, NOT the core count, and ~4.8 is squarely
  mobile-plausible. A real phone under load/throttling ALSO measures below its core count, so 'measured < claimed'
  cannot separate a spoof from a throttled real device (FP-unsafe), and 'measured > claimed' never fires in a
  quota-limited env. GROUNDED DEAD-END — not from noise (it was stable) but from the measurement proxying quota not
  cores. Reverted, nothing shipped. This was the last distinct-substrate lead; the remaining are incremental
  (MSAA/WebGL2 caps, model↔OS upper bound) or FP-risky (non-Pixel model↔GPU: the Samsung suffix→SoC convention
  BROKE with the S23 all-Snapdragon line, so it is not deterministic). 20 rungs stand. NOT a full frontier-dry yet
  (the incremental leads remain groundable), but the DISTINCT-substrate frontier is now tested to its floor: GPU
  (actual-behaviour probes) is the one unspoofable-substrate axis that grounds cleanly in-sandbox; cores does not.
- **[LOOP MOBILE B-modelos-upper] br.android_model_os_exceeds — the OTHER bound of the model↔OS window
  (2026-07-02, grounded).** The UPPER bound to match B-modelos's lower: a device cannot run an Android NEWER than
  its LAST update. Pixels 2-5 are EOL with a FIXED last version (3 years of updates pre-Pixel-8: Pixel 2->11, 3->12,
  4->13, 5->14 — these never advance). A pinned EOL Pixel with platformVersion ABOVE its last release is a fork
  pairing an OLD model with an impossible-for-it NEW OS — the case the launch lower-bound misses. GROUNDED LIVE:
  KS_DEVICE='Pixel 7' (newer Android) + KS_FORGE_JS_MODEL='Pixel 2' (last OS 11) FIRES; Pixel 5 on Android 11
  (window 11-14) SILENT. FP-safe (an EOL device's max OS is manufacturer-fixed; scoped to Pixels 2-5, 6+ excluded
  as still-supported). EXPERIMENTAL (w0.6). The model↔OS window is now closed BOTH sides — a coherent Android
  device's OS must lie within its model's real support window. HONEST framing: this is the same AXIS as B-modelos
  (incremental), but closes a distinct case (old-model+new-OS) the lower bound missed — a real gap, not a
  reasoned-away one. 21 rungs. The frontier is now: distinct-substrate tested-to-floor (GPU clean, cores/precision/
  WebGPU dead), device-manifold closed on 5 axes (screen/DPR/GPU/OS-low/OS-high), remaining leads incremental or
  FP-risky (non-Pixel model↔GPU). Approaching a genuine boundary, but each closure is still grounded, not assumed.
- **[LOOP MOBILE B-contacts] br.android_no_contacts_api — a FRESH axis: mobile-only web-platform APIs
  (2026-07-02, grounded).** Right when the frontier looked like it was down to incremental manifold bounds, TESTING
  a new angle opened a whole fresh surface: mobile-ONLY web platform APIs. navigator.contacts (ContactsManager /
  Contact Picker API) is present on Android Chrome 80+ but UNDEFINED on desktop Chrome (WebSearch-confirmed:
  developer.chrome.com's support test is 'contacts' in navigator && 'ContactsManager' in window, false on desktop).
  GROUNDED both ends: the container reports contacts=false for BOTH a desktop UA AND the emulated KS_DEVICE=Pixel 5
  — device emulation does NOT add it (a platform capability, not toggled by isMobile). So a non-WebView Android
  Chrome Mobile UA lacking navigator.contacts is a desktop faking Android — and, like mobile_cores_high, it catches
  the FULL Playwright emulation, not just a UA-only spoof. GROUNDED LIVE: KS_DEVICE='Pixel 5' FIRES; a desktop UA is
  out of scope. FP-safe (real Android Chrome >= 80 has it; WebView 'wv' excluded). Also grounded which candidates
  are NOT usable: getInstalledRelatedApps + ondeviceorientationabsolute are present on desktop too (not Android-
  only); DeviceMotionEvent.requestPermission is iOS-only. 22 rungs. IMPORTANT: the 'thinning frontier' read was
  itself premature — the web-API-presence axis is fresh and likely has MORE members (each mobile-only API a real
  device exposes that the emulation cannot). The lesson holds one more time: testing a new angle beat the
  boundary-instinct."
- **[LOOP MOBILE — grounded negative] the web-API axis is essentially a SINGLE clean member (2026-07-02).** Swept
  the mobile-only-API axis I opened with B-contacts for the more members I predicted. TESTED three candidates
  (grounded in the container + WebSearch): NDEFReader (Web NFC) — present only on Android with NFC HARDWARE, so it
  false-fires on budget/non-NFC real phones (FP-risky, skip); navigator.virtualKeyboard — GROUNDED present on the
  DESKTOP container too (vkbd=true), so NOT Android-only (unusable); BarcodeDetector — Play-Services-gated on
  Android AND present on macOS desktop (FP-risky + not mobile-exclusive, skip). So navigator.contacts appears to be
  the ONE clean member (a software picker present on ALL Android Chrome, no hardware gate, absent on every desktop)
  — my 'likely MORE members' read last firing was over-optimistic. Honest correction: the fresh axis is real but
  NARROW. Nothing shipped; grounded which candidates are not FP-safe so they are not re-tried. This is a grounded
  negative (contacts was the last rung, so not a two-in-a-row dry). Remaining untested: a mobile API with
  UNSPOOFABLE behaviour (not just presence — presence is a shallow spoof), and the coherent-generator RED capstone
  (compose all spoofs, ground that the GPU substrate wall still holds). 22 rungs stand."
- **[LOOP MOBILE — SOURCE-FORK TERMINUS grounded] the maximally-coherent JS fork is caught on many independent
  axes, and its own both-realm MECHANISM is self-incriminating (2026-07-02).** Composed the most coherent JS
  source-fork the toolkit can build: KS_DEVICE=Pixel 5 + KS_FORGE_MODEL (header) + KS_FORGE_JS_MODEL (main-JS) +
  KS_RENDERER='Adreno 620' (the Pixel 5's REAL GPU) + KS_RENDERER_WORKER (both-realm renderer) + KS_MOBILE_FONTS +
  patchright. GROUNDED the residual — three findings: (1) THE FUNDAMENTAL WALLS hold: mobile_gpu_caps_mismatch +
  mobile_gpu_uniforms_software (the real SwiftShader silicon can't be a real Adreno — the binary-fork-proof floor),
  android_no_contacts_api + mobile_cores_high (the Playwright emulation can't provide the mobile API / hide the
  host cores). (2) THE JS BOTH-REALM MECHANISM IS SELF-INCRIMINATING — a finding I had UNDER-appreciated: the
  getParameter string override trips br.webgl_getparameter_tampered (nativeness), and the Worker-WRAPPING used to
  reach the worker realm trips br.worker_constructor_tampered + br.worker_source_rewritten. So a JS-injection fork
  cannot even REACH the both-realm state cleanly — the mechanism to patch the worker is itself detected. (3) So the
  'both-realm string spoof defeats realm-divergence' premise holds only for a BINARY source-fork (CloakBrowser-class,
  patching the engine in C++, no JS Worker-wrapping) — and THAT is exactly what the GPU substrate actual-behaviour
  probes (allocation, uniform-compile) are built to catch, because a binary fork still runs on the real silicon it
  has. TERMINUS: a JS fork is caught by the tamper checks; a binary fork evades those but is caught by the GPU
  substrate (needs real mobile silicon); the emulation is caught by contacts/cores. There is no in-sandbox path to
  a coherent Android fingerprint — grounded, not asserted. 22 rungs + this terminus grounding."
- **[LOOP MOBILE FP-FIX] mobile_gpu_caps_mismatch narrowed to CONFIDENTLY-16384 GPUs — testing my OWN premise
  found an FP risk (2026-07-02, grounded).** Turned the discipline on a SHIPPED rung. mobile_gpu_caps_mismatch
  fired on any /Adreno [6-8]xx/ with maxTexture < 16384, on the ASSUMPTION that all Adreno 6xx are 16384. TESTED
  that: WebSearch could NOT confirm mid-range Adreno 6xx (610/618/619/620) are 16384 — they may be 8192, and
  MAX_TEXTURE_SIZE is driver-variant per the sources. So a REAL Pixel 5 (Adreno 620, if 8192) would have
  FALSE-FIRED this convicting rule — a real FP on real mid-range Android phones. FIX: narrowed the pattern to GPUs
  CONFIDENTLY 16384 (Adreno 7xx/8xx flagship; Mali-G76-79 + G710-719; Immortalis), excluding the ambiguous
  mid-range. GROUNDED LIVE: Adreno 730 (flagship) still FIRES; Adreno 620 (Pixel 5's real GPU) is now SILENT — and
  the excluded case is fully backstopped by mobile_gpu_uniforms_software (SwiftShader's vu 4096 fires under ANY
  mobile GPU string), which STILL FIRES, so ZERO net coverage lost while the FP risk is removed. This is the
  discipline's most important application: the same 'test the premise, don't assume' rule that OPENED surfaces and
  CLOSED dead-ends also CATCHES a latent false-positive in my own work — an unverified 16384 assumption that would
  have convicted real hardware. 23 rungs (this one a correctness fix, which beats the last by making the ruleset
  trustworthy, not just broader)."
- **[LOOP MOBILE FP-AUDIT] audited the other value-based GPU/manifold rungs for the same unverified-constant class
  (2026-07-02).** Followed the caps-fix by turning the same lens on the sibling checks. Findings, grounded: (1)
  mobile_gpu_uniforms_software (vu/fu > 2048) rests on the SAME kind of assumption (mobile vu <= 1024) — the
  Nexus-5 data point (256) + GLES-3.0 spec-min 256 + mobile GPUs' register constraint give ~2x margin to 2048, but
  a MODERN-FLAGSHIP's exact vu is unverified in-sandbox (WebSearch could not pin it). Rather than assume, ADDED an
  explicit calibration caveat + named its FP-SAFE BACKSTOP: br.gpu_uniform_underreport (the compile probe assumes
  NO constant), and its w0.6 keeps the value-arm corroborating not solely-convicting. (2) android_mobile_dpr1
  (DPR===1) ALREADY carried its caveat (mdpi extinct on modern-Chrome hardware) — honest as shipped. (3)
  mobile_cores_high (>8) is FP-safe for modern (mobile SoCs are octa-core max; old deca-core don't run current
  Chrome). KEY ARCHITECTURAL FINDING: the FP-safety is already correctly LAYERED — the ACTUAL-BEHAVIOUR probes
  (webgl_maxtexture_unallocatable, gpu_uniform_underreport) that assume NO constant carry the CONVICTING weight
  (w0.8), while the VALUE-heuristic checks (caps/uniforms, w0.6-0.7) that rely on real-mobile-GPU constants are the
  corroborating layer. So the one genuinely-unsafe constant (16384) was the caps bug (fixed); the rest are margined
  heuristics backstopped by the constant-free probes. 23 rungs + this audit: the ruleset's FP-safety architecture
  is sound and now explicitly documented — value-heuristics corroborate, actual-behaviour probes convict."
- **[LOOP MOBILE — grounded frontier-dry #1] WebGL2 caps yield no new in-sandbox discriminator (2026-07-02).**
  A genuine frontier attempt on the 'other WebGL caps' lead, TESTED not reasoned: grounded the container's (SwiftShader)
  WebGL2 caps — MAX_SAMPLES=4 (matches mobile's standard 4x MSAA), MAX_3D_TEXTURE_SIZE=2048 + MAX_ARRAY_TEXTURE_
  LAYERS=2048 (match mobile), MAX_VERTEX_UNIFORM_BLOCKS=14 (matches), MAX_FRAGMENT_UNIFORM_COMPONENTS=16384 (= 4096
  vectors, the SAME software-uniform signal br.mobile_gpu_uniforms_software already catches). SwiftShader mimics
  mobile on EVERY discriminating WebGL2 cap. The one direction that COULD catch the residual desktop-GPU fork
  (mobile GPU string + MAX_SAMPLES > 4, since desktop GPUs are 8/16x) is BOTH ungroundable in-sandbox (SwiftShader
  is 4, no real desktop GPU to test) AND FP-uncertain (mobile MSAA ceiling unverified — the same unverified-constant
  trap the caps fix just corrected). Nothing shipped. This is a GENUINE frontier-dry: the distinct in-sandbox
  surfaces are built, and the remaining residual (a real-desktop-GPU fork claiming a matching-caps mobile GPU) is
  EXTERNAL-DATA-BOUND (needs an actual-rendering reference corpus or a real desktop GPU), not a reasoned dismissal.
  23 rungs stand. HONEST STATUS: this is frontier-dry #1. If the next genuine attempt is also dry, that is the
  EARNED close — reached after exhaustively testing the GPU-substrate/manifold/web-API/realm surfaces, with the
  residuals grounded as external-data-bound, NOT the premature reasoned-close of before."
- **[LOOP MOBILE — frontier-dry #2 → AXIS CLOSED (EARNED)] emoji-color renders on the container; the in-sandbox
  frontier is exhausted (2026-07-02).** Second consecutive GENUINE grounded attempt: color-emoji rendering (every
  modern mobile OS renders emoji in color — an OS-invariant, reference-free angle). GROUNDED: the container renders
  color emoji (colored 580/600, with AND without the font mask — it ships Noto Color Emoji), exactly like a real
  mobile device AND like every modern desktop (Segoe/Apple/Noto Color Emoji are universal now), so 'monochrome
  emoji' is not a clean mobile discriminator and the positive is ungroundable in-sandbox; the emoji GLYPH-SHAPE
  angle (Android vs iOS vs Noto) needs a reference corpus — EXTERNAL-DATA, like the desktop-GPU-fork residual.
  TWO-IN-A-ROW grounded frontier-dry (WebGL2 caps, then emoji), so per the loop's OWN stop-condition the mobile
  axis is CLOSED — and this time it is EARNED, the categorical opposite of the premature close: that one was a
  REASONED dismissal (GPU-caps 'done' without testing, which the challenge overturned); this is ~20 firings of
  EXHAUSTIVE GROUNDED testing across every in-sandbox surface (GPU substrate value+actual-behaviour, device
  manifold on 5 axes, the 3-surface model ratchet, fonts, pointer/DPR/cores, web-API presence, realm-divergence,
  the source-fork terminus) with the residuals GROUNDED as external-data-bound (a real-desktop-GPU fork with
  matching caps; per-device rendering/emoji glyph references; real iOS/WebKit hardware), NOT reasoned away.
  FINAL: 25 mobile rungs (23 detections + 2 grounded-terminus/audit findings — actually 23 shipped rungs: fonts,
  ch_ua_mobile_no_model, mobile_no_js_model, uadata_model_worker_divergence, model↔screen/DPR/GPU/OS-low/OS-high,
  pointer_hover, mobile_cores_high, gpu_not_mobile, gpu_caps_mismatch [FP-fixed], maxtexture_unallocatable,
  uniforms_software, uniform_underreport, contacts, + the KS_MOBILE_FONTS/FORGE/RENDERER red capabilities). The
  answer stands, hardened: NO in-sandbox path to a coherent Android fingerprint; a JS fork is self-incriminating
  (tamper checks), a binary fork is caught by the GPU actual-behaviour substrate (real silicon), the emulation by
  cores/contacts. Loop 49807012 retired at the EARNED terminus."
- **[POST-CLOSE FP-VALIDATION] the mobile rungs run against REAL browserforge mobile fingerprints — found + fixed
  a second latent FP; the coherence rules validated FP-safe (2026-07-03).** User picked 'validate FP-safety' over
  shipping/new-axis. browserforge samples REAL mobile fingerprints (Android + iPhone) WITH the high-entropy model,
  platformVersion, GPU renderer, screen, DPR, cores — complete data to test every model↔X + GPU + cores + DPR rung.
  Ran ~800 coherent-only mobile fingerprints (dropping browserforge's UA/platform-incoherent cross-samples) through
  each rule's logic. FINDINGS: (1) FOUND A REAL FP — mobile_cores_high (> 8) FALSE-FIRED on real 9-core Android
  (grounded distribution: Android hardwareConcurrency = 8 dominant + a 9-tail ~1.4% + a lone 12; iPhone 4). FIXED
  to > 9 (still catches the 12-core host leak; clears real 8-9-core phones). This is the SECOND latent FP the
  discipline caught (after the Adreno-620 caps assumption) — both were unverified-constant assumptions the REAL
  DATA refuted, which is exactly why this validation pass mattered. (2) VALIDATED FP-SAFE: the coherence rungs
  (model↔screen/DPR/GPU/OS, mobile_gpu_not_mobile) fire ONLY on browserforge's cross-sampled model↔hardware combos
  (Pixel 8+Adreno, Pixel 5+wrong-screen, Pixel 8+Android-10) — genuinely incoherent, NOT real devices, so they are
  WORKING CORRECTLY, not FPing. (3) CONFIRMED two prior findings against real data: real Android userAgentData.
  architecture is '' (empty — the arch dead-end was right) and real mobile DPR is 2-3.5 never 1 (android_mobile_dpr1
  fires only on cross-samples). (4) The GPU-caps NARROWING was validated: real mid-range mobile GPUs in the corpus
  are Mali-G68/Adreno 610/506 — EXACTLY the ones the FP-fix excluded from the 16384 pattern. So the mobile detector
  is now REAL-DATA-CALIBRATED: two FPs found+fixed, coherence rungs confirmed to fire only on genuine incoherence.
  The validation was the right call — a detector that convicts real phones is worse than a smaller one, and it
  caught a real one."
- **[POST-CLOSE — second-source corroboration: NOT available in-sandbox for mobile] (2026-07-03).** The standing
  constraint ("never act on a single-source false-positive; corroborate") led me to the second generator, fpgen
  (Scrapfly). GROUNDED: fpgen is DESKTOP-ONLY (300/300 desktop; its os.name schema rejects 'android') — it carries
  the real WebGL caps browserforge lacks (params['3379']=MAX_TEXTURE_SIZE) but generates no mobile fingerprints,
  so it CANNOT corroborate the mobile FP-findings. browserforge is the SOLE real-mobile-fingerprint source
  in-sandbox. CONSEQUENCES, reasoned: (1) the mobile_cores_high 8->9 fix STANDS — raising a threshold is a
  CONSERVATIVE FP-REDUCTION (it only removes convictions, never adds them), so it is safe even single-source. (2)
  The mobile rungs correctly STAY experimental — promoting experimental->active makes a rule CONVICT more, which is
  'acting on a single-source FP-safe number', and the constraint wants a second source first. So promotion is
  EXTERNAL-DATA-BOUND: it needs a second real-mobile source (real-device captures, or a mobile-capable generator),
  the same boundary the axis-close identified. The mobile suite is thus real-data-CALIBRATED (browserforge, 2 FPs
  fixed) and FP-safe, but stays experimental-weighted pending a corroborating mobile corpus — the honest terminus
  for in-sandbox FP-validation."
- **Environmental evasions split spoof vs provision — and the floor never convicts (2026-07-02).** Can the
  environment floor itself be evaded? Two paths, and only one is coherent: (1) SPOOF the values in JS (fake
  `getVoices()`/`enumerateDevices()`/renderer string) — CAUGHT by coherence (`FLOOR_SPOOF` fakes voices+devices
  and still scores `bot 0.996`: a JS-faked value is incoherent with own-property/`voice_os_vs_ua`/caps-mismatch/
  native-invariant checks). (2) PROVISION the real thing (install a TTS engine, a virtual audio/video device, a
  GPU, a STUN-reachable path) so the browser enumerates real values NATIVELY — coherent, silent, but genuine
  systems work: a `KS_PROVISION` attempt (pulseaudio null-sink + speech-dispatcher/espeak in the camoufox
  container) hit real barriers — system-mode PulseAudio denies a root-only container (`pulse-access` group),
  speech-dispatcher's socket needs a real user session. That difficulty IS the point: provisioning = "become a
  real desktop," the economic bind made concrete (reverted the non-working scaffold; the finding is the
  barrier). Crucially the environment-floor tells are CORROBORATING (0.5-0.6, **conviction 0**) BY DESIGN — real
  privacy browsers (WebRTC off), VMs (no GPU/audio), RFP all trip them, so the detector can't convict without
  massive FPs. So a coherent stack is already `suspicious`-with-zero-convictions regardless; the floor only gates
  `suspicious → clean`, and clearing it means running on (or fully provisioning) a real environment — not a
  spoof, not a cleverer tool. The lab thesis holds: no conviction without incoherence, and a real-enough
  environment has none. The durable single-session signal was never the environment floor — it is coherence.

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
- **2026-06-26 · G18 SHIPPED — br.webgl_renderer_caps_mismatch, red⇄blue grounded** — closed the GPU
  renderer-string↔capability rung the 2026-06-24 recon left capture-profile-bound. KEY FP-SAFETY MOVE: rather
  than wait on a full real-GPU caps corpus (still external), shipped the FP-safe-by-construction CORE — the
  collector captures the capability fingerprint (`webgl_caps` + `webgl_max_texture`, main realm) and the rule
  convicts only when the renderer string names a recent HIGH-END discrete GPU (RTX / Radeon RX 6000+ / Apple
  M-series / Intel Arc) yet `MAX_TEXTURE_SIZE < 16384`, below the floor every such GPU exposes. That is FP-safe
  three ways: a real high-end GPU is always >=16384 (never fires); an honest software renderer names itself
  (SwiftShader/llvmpipe → already caught by `webgl_software`) so it never matches the high-end string; a real
  low-end/mobile GPU at 8192 carries a low-end string, not 'RTX 4090', so it's out of scope. The only thing
  that trips it is a source-level fork (CloakBrowser/Wayfern/BotBrowser) that repaints `UNMASKED_RENDERER` to a
  high-end string in BOTH realms — defeating `webgl_worker_vs_main` — over a backend whose silicon can't back
  the claim. GROUNDED on the captured in-sandbox SwiftShader baseline (`MAX_TEXTURE_SIZE=8192`, live) vs the
  universal >=16384 of recent hardware; RED = the renderer-spoof evader (high-end string over SwiftShader)
  fires, every real-browser capture (honest string ↔ caps) stays silent. browserforge calibration carries the
  renderer string but not the live caps probe, so promotion can't raise its legit flag rate. Increment 1 (caps
  capture + display + the software-vs-high-end tell); the broader renderer↔caps profile match across more GPU
  tiers stays a follow-up needing the `real-browser-capture-profiles` run on real GPUs (capture-profile-bound).

- **2026-06-26 · /loop tick — G26 SHIPPED — net.h2_madeyoureset (CVE-2025-8671), red⇄blue grounded.** Drained
  the 12-lane fan-out's RECOMMENDED NEXT PUMP. KEY PROPERTY: MadeYouReset coerces server-side stream resets with
  MALFORMED control frames and sends NO client RST_STREAM, so it slips past the rapid-reset rung (CVE-2023-44487,
  which keys on client RST). BLUE: extended `H2FrameScanner` (the same client-byte tee that powers rapid-reset /
  CONTINUATION / control-flood) to buffer + inspect the WINDOW_UPDATE (4-byte increment) and PRIORITY (5-byte
  dependency) payloads it previously skipped, counting three RFC-9113 coercion primitives — zero-increment
  WINDOW_UPDATE, mis-sized PRIORITY (FRAME_SIZE_ERROR), self-dependent PRIORITY (PROTOCOL_ERROR) — none of which
  a conformant browser ever emits; `MadeYouReset()` fires at a floor of 10 → `network.h2_madeyoureset` →
  `net.h2_madeyoureset` (automation, w0.9). RED: `go-tls KS_MADEYOURESET` forges a Chrome ClientHello (uTLS),
  then on the raw h2 connection floods 60 self-dependent PRIORITY frames BEFORE the real request (so the edge's
  in-order tee has counted them by the time the request's handler emits the signal), with zero client RST.
  Self-dependency is the chosen live primitive because Go's h2 server treats it as a STREAM error (connection
  survives, so the request still mints a session); the scanner's unit tests cover all three primitives + chunk
  boundaries. GROUNDED BOTH WAYS: in-process (`edge h2frames_test.go` — the three primitives count, legit
  WINDOW_UPDATE/PRIORITY stay at zero, rapid-reset stays quiet) AND LIVE through the rebuilt edge→detector stack
  (label bot, score 1.0, `net.h2_madeyoureset` fires while `net.h2_rapid_reset` is SILENT — proving it closes the
  exact evaded gap), frozen as `corpus/sessions/go-tls-madeyoureset.json` + `test_madeyoureset_evades_rapid_reset`
  + the `test_lit_rule_captures` guard. Edge + detector + harness (258, 97.13%) + go-tls evader all green; catalog
  / matrix / README regenerated. Deferred: the half-closed HEADERS/DATA + window-overflow primitives need
  per-stream state tracking (the 3 frame-level primitives already close the rapid-reset evasion). Next groundable
  from the fan-out batch: G27 (GREASE-ECH AEAD, CVE-2026-27017), G30 (HTTP/2-Bomb, CVE-2026-49975), G28
  (deviceMemory spec-invariant), G32 (WBA nonce-replay).

- **2026-06-26 · /loop tick — G32 SHIPPED — net.web_bot_auth_nonce_replay (CVE n/a; RFC 9421 / WBA draft),
  red⇄blue grounded.** Took the second fan-out pick, the cleanest extension of the shipped G25 (it reuses the
  same crypto + grounds via the same network evader, no browser). THE GAP: the G25 forgery check
  (`net.web_bot_auth_invalid`) only catches a signature that FAILS verification or is past its expires window —
  it structurally MISSES a captured-and-replayed signature that is GENUINE and still in-window. RFC 9421 makes a
  Web Bot Auth nonce single-use per validity window, so a real signer never repeats one; the reuse IS the tell.
  BLUE: `edge/internal/webbotauth.ReplayStore` records the (keyid, nonce) of every VALID signature (self-evicting
  at the signature's own expiry so the set stays bounded) and fires `network.web_bot_auth_nonce_replay` on an
  in-window reuse; wired through `prepare` on the TCP/h2 path; `detector.scoring.verified_agent` now withholds the
  verified allow-list when this rule fires (alongside `web_bot_auth_invalid`), so a replayed verified-agent
  request convicts instead of riding the allow-list. RED: `go-tls KS_WEBBOTAUTH=replay` signs ONE genuine,
  in-window RFC 9421 signature carrying a fixed nonce and presents it TWICE under one ks_sid. GROUNDED live
  through the rebuilt edge→detector stack: the session carries BOTH `web_bot_auth_verified` (req 1) AND
  `web_bot_auth_nonce_replay` (req 2) yet labels **bot** (score 0.985) — the verified marker did NOT save the
  replay, the precise scoring interaction G32 demanded. Frozen as `corpus/sessions/go-tls-web-bot-auth-replay.json`
  + `test_web_bot_auth_replay_is_not_allow_listed` + the `test_lit_rule_captures` guard; unit-tested ReplayStore
  (fresh/blank/expired/per-keyid). FP-safe by construction. Edge + detector (425, 95.84%) + harness (260) +
  go-tls evader all green; catalog/matrix/README/scoreboard regenerated. The two-rung pair G25+G32 now covers
  both ways a Web Bot Auth identity can be abused: a forged/expired signature, and a captured-then-replayed
  genuine one. Remaining fan-out CVE rungs: G27 (GREASE-ECH AEAD — needs a uTLS <1.8.1 pin), G30 (HTTP/2-Bomb).

## Detection/evasion surface fan-out (2026-06-25, 12-lane research radar · 54 agents)

A breadth+depth fan-out across every Kitsune seam (TLS/QUIC, HTTP/2-3, TCP/IP, browser-coherence,
behavioral-biomech, AI-agents, coordination-fleet, DDoS-L7, 2026-standards, vendor-research, anti-detect
tools, mobile/WebView), each lane deep-scanned then **adversarially verified** per lead (novel? groundable
in-sandbox? FP-safe-by-construction?). 41 verified leads → **11 new groundable rows + 11 external**. Verdict:
**NOT saturated** — the strongest groundable batch since the per-session-saturated note; four are
safe-by-construction convicting rungs anchored to dated 2025-2026 CVEs/drafts, wired through existing edge
infra. (Existing G1-G25/N1-N7/X1-X8 deduped out.)

### New groundable leads (in-sandbox pump candidates)

| # | seam | technique / signal | evasion / tool | source | status |
|---|---|---|---|---|---|
| G26 | http2 (DDoS L7) | **MadeYouReset (CVE-2025-8671)** — client COERCES server RST via RFC-9113 PROTOCOL_ERROR primitives (WINDOW_UPDATE 0, PRIORITY len≠5 / self-dependent) while NEVER sending its own RST_STREAM → evades the client-RST rapid-reset rung. Extend `H2FrameScanner` (client bytes already tee'd) to parse the WINDOW_UPDATE/PRIORITY payloads → `network.h2_madeyoureset` → `net.h2_madeyoureset` (automation, w0.9). FP-safe (spec violations no browser emits). | go-tls KS_MADEYOURESET (fires each primitive, no client RST) | CERT/CC VU#767506; Imperva MadeYouReset; CVE-2025-8671 (2025-08-13) | **done** → `net.h2_madeyoureset` (ruleset 0.74.52). Scanner now parses WINDOW_UPDATE (zero-increment) + PRIORITY (mis-sized / self-dependent) prefixes; floor 10. RED `go-tls KS_MADEYOURESET` floods self-dependent PRIORITY (Go's h2 server treats it as a stream error → connection survives → request still mints a session) with ZERO client RST. GROUNDED live (edge→detector): label bot, `net.h2_madeyoureset` fires while `net.h2_rapid_reset` stays QUIET — frozen as `corpus/sessions/go-tls-madeyoureset.json` + `test_madeyoureset_evades_rapid_reset`. The half-closed HEADERS/DATA + window-overflow primitives need stream-state tracking → deferred (the 3 frame-level primitives close the gap). |
| G27 | tls | **GREASE-ECH HPKE-AEAD vs outer-AEAD (CVE-2026-27017)** — real Chrome gates BOTH outer AEAD pref and GREASE-ECH HPKE aead_id on the same AES-NI bit; uTLS<1.8.1 picks the ECH AEAD randomly → ~50% emit impossible AES-outer + ChaCha20-ECH. Extend `extECH` (0xfe0d) parse to read kdf_id+aead_id; convict Chrome-claim AND AES-first-outer AND ECH-aead==ChaCha20. Both fields cleartext. | uTLS Chrome parrots <1.8.1 (go-tls/primp/curl-impersonate) w/ ECH GREASE | GHSA-7m29-f4hw-g2vx / CVE-2026-27017; utls 1.8.1 changelog; RFC 9849 | **lead (groundable, high).** Positive: pinned vulnerable parrot fires on ~50% of handshakes. Negative: real Chrome + patched 1.8.1 lock the two AEADs. |
| G28 | browser-coherence | **navigator.deviceMemory spec-invariant** — Chromium clamps to {0.25,0.5,1,2,4,8}; any >8 / non-pow2, or the Chromium-only API PRESENT under Gecko/WebKit UA, is impossible. (A) `br.devicememory_out_of_set` (Chromium-UA-gated), (B) `br.devicememory_on_non_chromium`. Deterministic, not rarity. | browserforge/GoLogin/Octo profile mixers leaking host RAM (16/32); non-Chromium-UA spoof leaking the API | Castle.io deviceMemory deep-dive (2025); W3C Device Memory clamp | **lead (groundable, high).** Forward `browser.device_memory_value`; positive: override=16/=3 under Chrome UA, or native value under FF UA. Negative: real Chrome/Edge/Brave (legal set) + real FF/WebKit (absent). |
| G29 | http2 | **RFC 9218 priority-scheme vs engine** — Chrome 105+ sends ZERO standalone PRIORITY frames (uses PRIORITY_UPDATE / `priority:` header); a Chromium-classified h2 stack emitting legacy PRIORITY frames is a non-Chrome stack (Go x/net/http2, stale uTLS) in Chrome's clothes. ASYMMETRIC/engine-keyed (not version) → `net.h2_priority_scheme_vs_engine`. | curl-impersonate / surf / go-tls KS_H2PRIORITY (legacy PRIORITY under Chrome UA) | RFC 9218; Chromium I2S priority header; Scrapfly h2/h3 FP (2025-26) | **lead (groundable, high).** Crosses h2-frame ↔ JA4/pseudo-order engine identity; gates off FF/Safari/unknown. |
| G30 | http2 (DDoS L7) | **HTTP/2 Bomb (CVE-2026-49975)** — JOINT per-stream: HPACK ref-amplification (thousands of 1-byte indexed refs, cookie-crumb-split bypasses field caps) AND zero-window slowloris hold. Convict only on the joint (huge-bookkeeping-per-decoded-byte AND zero-window drip); neither half alone malicious → `network.h2_memory_bomb`. | scripted Go h2 client (off h2-rapid-reset/main.go) | Calif "HTTP/2 Bomb"; CVE-2026-49975 (Apache/nginx/Envoy/Pingora) | **lead (groundable, high).** Half-only controls prove each half alone does NOT convict (safe-by-construction joint). |
| G31 | http2 | **HPACK encoding-choice fingerprint** (Huffman-always + never-indexed) — wire-byte layer below JA4H; Chrome Huffman-encodes everything, libraries differ. Raw HPACK byte-walker on first HEADERS → `network.hpack_encoder_hint`; ASYMMETRIC `net.hpack_engine_vs_ua` (corroborating). EXCLUDE dynamic-table sizing (stateful, FP-unsafe). | go-tls/http2-naive faking Chrome order via hpack.NewEncoder; Python h2; nghttp2 | Sendwin 2026 FP guide; RFC 7541 §5.2/§6.2.3 | **lead (groundable, med) — needs-threshold-data.** Pin the invariant set from real captures (request-type-invariant per the v0.74.29 fetch/XHR lesson) before convicting weight. |
| G32 | standards | **Web Bot Auth nonce-replay** — RFC 9421 nonce must be unique in the validity window; an in-window replay verifies cleanly (reaches the verified allow-list) — the expiry arm of G25 structurally misses it. Per-keyid seen-nonce set → `net.web_bot_auth_nonce_replay` (convicts; withholds `web_bot_auth_verified`). | credential-capture/replay of a verified agent's signed request; go-tls KS_WEBBOTAUTH in-window same-nonce mode | draft-meunier-web-bot-auth-architecture-05 §4.2.2; Cloudflare secure-agentic-commerce | **done** → `net.web_bot_auth_nonce_replay` (ruleset 0.74.53). edge `webbotauth.ReplayStore` records (keyid, nonce) of every VALID signature (self-evicting at the signature's expiry) → fires on an in-window nonce reuse; `scoring.verified_agent` now withholds the allow-list on it (alongside `web_bot_auth_invalid`). RED `go-tls KS_WEBBOTAUTH=replay` presents ONE genuine in-window signed request TWICE under one ks_sid. GROUNDED live (edge→detector): the capture carries BOTH `web_bot_auth_verified` (req 1) AND `web_bot_auth_nonce_replay` (req 2), yet labels **bot** — the verified marker did NOT save the replay. Frozen as `corpus/sessions/go-tls-web-bot-auth-replay.json` + `test_web_bot_auth_replay_is_not_allow_listed`. FP-safe by construction (nonces are single-use; a blank nonce never convicts). |
| G33 | browser-coherence | **Closed-shadow-root CDP-pierce honeypot** — plant a target inside `attachShadow({mode:'closed'})` (root ref in closure only); CDP frameworks reach it via DOM.pierce, page JS cannot → control-plane vs content-plane DOM incoherence. `br.closed_shadow_pierce`. | patchright ("interact in closed shadow roots"), rebrowser, nodriver/zendriver; vanilla Playwright/Selenium CANNOT (negative) | patchright README; "Piercing the Shadow Root Using CDP"; Playwright #23047 | **lead (groundable, med).** FP-hardening is load-bearing: a11y-tree (screen reader) + password-manager negative must be clean before convicting; else experimental. |
| G34 | http2 | **SETTINGS INITIAL_WINDOW_SIZE library-default** — Chrome=6291456, Go/Python h2 default 65535 (~96×). Asymmetric library-default form only (NOT exact-value, NOT settings 3/5 omission — poisoned) → `net.h2_window_vs_engine` (w~0.6, coherence). Value already captured. | stale curl-impersonate/uTLS; Go/Python clients leaking default window under Chrome UA | Scrapfly h2/h3 guide; Sendwin 2026 | **lead (groundable, med) — needs-threshold-data.** Re-pull the Chrome window each cycle (Intoli/browserforge-loop style); never hardcode the trigger. |
| G35 | ai-agent | **Visibility-vs-trusted-input** — CDP agents deliver isTrusted input with `visibilityState==='hidden'` (background tabs, multi-tab fleets). `behavioral.input_while_hidden` CORROBORATING + gated. | Operator/Browser-Use/Skyvern parallel tabs; CDP evader BG_TAB_INPUT | Browserbase foreground-tab tracking (2026); CDP Input semantics | **lead (groundable, med) — needs-threshold-data.** NOT FP-safe as pitched: Document-PiP (Chrome 116+) fires isTrusted while hidden → PiP gate + persistence debounce load-bearing; measure residual rate. |
| G36 | browser-coherence | **deviceMemory × cores × form-factor impossible-corner** — Corner A (convicting): mobile UA AND hardware_concurrency>16 (no phone exposes >16). Corner B (corroborating, guarded): deviceMemory≤1 AND cores≥16. DROP the deviceMemory=8+huge-cores corner (real workstation, Chrome clamps to 8 → FP-unsafe). | browserforge/GoLogin mixers with independent RAM/core pools; mobile-UA-on-desktop | Castle deviceMemory deep-dive (2025) | **lead (groundable, med) — needs-threshold-data.** Reuses G28's `device_memory_value`; high-end-workstation + real-mobile negatives set the ceilings. |

### New external-data-bound leads (queue)

| # | seam | technique | real data needed | source |
|---|---|---|---|---|
| X11 | http3 | H3 GREASE-frame/SETTINGS vs same client's TLS-GREASE cross-layer coherence | browser-trusted cert + real completed QUIC/H3 session (H3 control SETTINGS exchanged post-completion) | net4people; QUIC FP research |
| X12 | tcp/proxy | Handshake-RTT misalignment (TCP-RTT vs TLS-RTT vs app-RTT) as TCP-terminating-proxy tell | real-WAN path latency asymmetry (in-lab tc-netem delta is fabricated) | proxy-detection-by-physics |
| X13 | tls (fleet) | Shared/warmed TLS session-ticket (PSK) reuse across multiple source IPs | real multi-IP roaming/CGNAT/dual-stack prevalence to set the threshold | TLS resumption fleet analysis |
| X14 | tcp/proxy | OpenVPN mssfix MSS-residue tunnel-cipher leak (1369/1338 class) | real-WAN path-MTU/encapsulation (loopback MTU is an artifact) | OpenVPN mssfix |
| X15 | behavioral | Pointer inter-arrival quantized to USB polling grid (8ms@125Hz/1ms@1000Hz lattice) | real-human-on-real-hardware HID-timing corpus (headful injects synthetic timing) | USB polling fingerprint |
| X16 | behavioral | Fitts submovement microstructure (corrective ballistic sub-movements absent) | per-click target geometry capture + real-human approach corpus | Fitts/minimum-jerk |
| X17 | ddos | DoLLM carpet-bombing / low-and-wide L7 spread under per-host threshold | many distinct real victim IPs/subnets + real per-host rate prevalence | DoLLM |
| X18 | standards | Signature-Agent vs keyid directory-origin coherence (card-signature impersonation) | published authoritative card-signature test vectors (registry-01 App. A is TODO) | Web Bot Auth registry |
| X19 | standards | Agentic-commerce payment-tag coherence (Visa TAP / Mastercard Agent Pay WBA tag) | live payment-network directory egress + agent enrollment for the real key | agent-payment auth |
| X20 | standards | PACT / Private Access Tokens personhood presence-vs-proof (blind-RSA Privacy Pass) | real secure-enclave attestation chain + Issuer egress + double-spend prevalence | PACT / Privacy Pass |
| X21 | browser-coherence | Wasm↔JS call-latency ratio as engine/OS coherence | real-prevalence threshold across µarch / JIT tiering / load+thermal / VM | Wasm-JIT timing |

- **2026-06-25 · 12-lane research-radar fan-out (54 agents) — queue RE-ENRICHED, +11 groundable +11 external.**
  A breadth+depth SCAN across every seam with adversarial per-lead verification (novel? in-sandbox-groundable?
  FP-safe-by-construction?) surfaced **G26-G36** (groundable) and **X11-X21** (external); see the dated section
  above. NOT saturated — four safe-by-construction convicting rungs anchored to dated 2025-2026 CVEs/drafts and
  wired through existing edge infra: **G26 MadeYouReset (CVE-2025-8671)**, **G27 GREASE-ECH AEAD
  (CVE-2026-27017)**, **G30 HTTP/2-Bomb (CVE-2026-49975)**, **G32 WBA nonce-replay**. RECOMMENDED NEXT PUMP =
  **G26**: smallest zero-FP-by-construction brick (six RFC-9113 protocol-error primitives no browser emits →
  single-frame conviction, no threshold data), reuses the client byte-stream `H2FrameScanner` already tees, and
  uniquely VALIDATES the evasion ladder — it is explicitly engineered to evade the rapid-reset rung Kitsune
  ships, so grounding it proves `net.h2_madeyoureset` fires while `net.h2_rapid_reset` stays quiet. Beats every
  pending lead (N6 infra-blocked, G16 wiring-stuck, G12/G14/G15 FP-nuanced on real users, N1/N4/N7 lower-leverage
  than a 2025-CVE conviction with a live evasion story). The behavioral/coordination/RTT/RESIP frontier stays
  external (X11-X21: H3-GREASE coherence, handshake-RTT proxy tells, TLS-PSK fleet reuse, USB-polling mouse
  lattice, Fitts submovements, DoLLM carpet-bombing, PACT/Private Access Tokens, Wasm/JS latency-ratio).
- **2026-07-01 · pump on G17 — L7-flood-as-coordination SHIPPED (the bot⇄DDoS convergence).** Wired the
  coordination scorer (`harness/coordination.py`) as the L7-flood attributor, the strategy's highest-leverage
  DDoS angle and the one detection nobody else frames (a flood and a scraping fleet are the SAME aggregate
  coordination signal). New ambiguous **flood-shape** signal: a large cluster (`_FLOOD_MIN_ORIGINS=6`) in
  timing lockstep across many distinct origins — the aggregate signature of an application-layer flood, which a
  pure HTTP flood produces with NO per-node binding (no cloned fp / replayed trace / shared ticket — it runs no
  browser), so exact-match collision finds nothing. It convicts only when corroborated (the flash-crowd FP
  gate): a non-browser tool JA4, a **DoS tell** (`_has_dos_tell` — the G16/H2FrameScanner floods +
  forward-wired `slow_http_attack`, connecting the edge DoS scanners to the coordination layer), an automation
  tell, or datacenter/abuse IP-rep. Grounded red⇄blue: Skulk gained an **`httpflood`** tier (8 no-JS tool
  sources, one flood-tool JA4, lockstep, distinct RESIDENTIAL origins) → new scenario **`fleet-httpflood`**
  convicts `fleet` on the tool JA4 ALONE (no datacenter flag — proving the coordination attributor catches a
  flood even on clean residential infra), while the FP control **`legit-flash-crowd`** (6 real browsers, same
  aggregate shape, residential, no corroborator) caps at **candidate**. `FleetVerdict.l7_flood` marks the
  attribution. coordination-eval gate holds precision/recall **1.0** (368 harness tests); fleet 23 tests, both
  ruff/mypy clean. This is the economic-asymmetry thesis in practice: a coordinated flood cannot shed its
  aggregate any more than a fleet can — it can hide per-connection but not the synchrony across its sources.
- **2026-07-01 · pump on G16 — slow-HTTP (slowloris) wired + live-grounded, and its driver.** Closed the
  last DDoS-shaped gap: the `SlowLorisScanner` (long built + unit-tested) is now wired end to end. The trap
  that stalled the prior attempt: the stdlib `http.Server` RESERVES ALPN `http/1.1` from `TLSNextProto`
  (`validNextProto` returns false for `http/1.1` and `""`), so a `serveH1` handler registered there is
  silently never called — a normal request still 200s (via the built-in h1 path) so it *looks* wired but the
  scanner never sees a byte. Fix: the edge runs its OWN accept loop (`h1serve.go serveConns`/`dispatchConn`)
  that handshakes each conn and dispatches by ALPN — h2→`serveH2` (unchanged), else→`serveH1`, which tees the
  decrypted request-header bytes through the `SlowLorisScanner` on a `slowConn` and, when a connection is torn
  down still-incomplete past the 10s/8KiB budget, mints a synthetic session carrying `network.slow_http_attack`
  + `observed_ip` → active rule **`net.slow_http_attack`** (w0.9). New evader **`evaders/slow-http`** grounds
  it live: 4 held ALPN-http/1.1 connections → 4 detector sessions each firing the rule, verdict **bot 0.99**;
  h1 (200/1.1) + h2 (200/2) unaffected. Unit tests for the pure pieces (`slowConn` tee, single-conn listener,
  `connIP`) + a real-TLS integration test (normal-serve + slowloris-emit); detector engine test extended;
  catalog regenerated. The `observed_ip` on each held connection is the G16→G17 bridge: a slowloris FLEET
  folds into the L7-flood attribution via `_has_dos_tell` (which already lists `slow_http_attack`).

## Arena defenses & evasions frontier (2026-06-26 research scan)

A frontier scan for the self-hosted arena's arms race (defenses to model, evasions to expect). Groundable
= buildable against our OWN gates in-sandbox; external = needs real attestation/traffic/paid models.

### Defense frontier

| # | technique | status in the wild | arena fit |
|---|---|---|---|
| AD1 | **Puzzles are dying → invisible signal-based** (PoW + behavioral + device intelligence) | the 2026 consensus (Turnstile, Friendly Captcha, Fingerprint) | **already modelled** — the `managed` ladder = silent coherence → PoW step-up |
| AD2 | **Behavioral biometrics** as the durable interactive layer (drag speed/accel/jitter, full trajectory server-scored) | GeeTest Adaptive, Cloudflare heuristics | **modelled** — slider + rotate score the trajectory (velocity-CV); = Kitsune's `uniform_velocity` thesis |
| AD3 | **PACT / Private Access (Control) Tokens** — anonymous proof-of-PERSONHOOD tokens; skip the challenge for token-carriers | Cloudflare + Chrome/Edge/Firefox, **launched 2026-06** (Privacy Pass family) | **LEAD (groundable + external)** — the token-verify mechanism is groundable like Web Bot Auth; the real secure-enclave attestation (Apple PAT) is external. Complements shipped **G25 Web Bot Auth** (good-bot half) with the **human-personhood half** |
| AD4 | **Anti-LLM-solver CAPTCHA** + defensive eval | COGNITION (arXiv 2512.02318), NGCaptcha (arXiv 2512.16223) | external/research — the durable answer is coherence, not a harder puzzle |

### Evasion frontier

| # | technique | status in the wild | arena fit |
|---|---|---|---|
| AE1 | **Multimodal-LLM solvers** (GPT-4V/Claude vision) solve visual CAPTCHAs zero-shot ~96% on new types | Oedipus (CCS 2025), agentic-VLM "Are CAPTCHAs still bot-hard?" | the **text + image-select** gates fall to a VLM; our heuristic CV already does image-select, a VLM/OCR does text |
| AE2 | **Behavioral trajectory synthesis** (Sigmoid/Softmax/ReLu/Tanh sim functions) | ~96% GeeTest, ~98% Netease | **shown** — `arena-solver` beats slider/rotate by synthesizing a variable-velocity trajectory |
| AE3 | **HF OCR / CAPTCHA-solver models** (leverage, don't train) | mature | **the missing evader half** — beats the distorted-text gate the Go heuristic solver can't |

### HF models to leverage (for the text-gate OCR evasion, against our OWN gate)

- **`anuashok/ocr-captcha-v3`** — TrOCR fine-tuned on captchas, **CER ≈ 0.014** (~98.6% per-char). Best off-the-shelf fit.
- **`DunnBC22/trocr-base-printed_captcha_ocr`** — TrOCR fine-tuned for captcha text.
- **`microsoft/trocr-base-printed`** — general transformer OCR (baseline).
- **`keras-io/ocr-for-captcha`** — classic CRNN+CTC captcha OCR.
- Dataset for training our own: a ~1.8M synthetic-captcha set on HF.

### The meta-finding (confirms the thesis)

The whole frontier says the **puzzle layer is dead** — every gate (PoW, slider, image, text) falls to scripting /
synthesis / CV / VLM-OCR, and the industry is moving to **behavioral + cryptographic attestation**. That is exactly
Kitsune's bet: the arena proves a solved challenge ≠ a human, and **coherence + attestation** is the durable layer.

### Next builds (arms race)

- **Evasion:** a Python `arena-solver-ocr` using a HF TrOCR-captcha model to beat the text gate (own gate only) →
  completes the solver; honest (the text gate's real-OCR barrier falls to a real OCR model, and the detector still
  convicts the no-JS client).
- **Defense (lead AD3):** model **PACT / Private Access Tokens** as a personhood-token arena gate — the human half of
  the Web Bot Auth coherence check Kitsune already ships.

### Arena arms-race update (2026-06-26 — built from the frontier scan)

- **AE3 OCR — confirmed, 6/6.** The off-the-shelf HF model `anuashok/ocr-captcha-v3` reads the arena's
  distorted-text gate **6/6** with no fine-tune (~20-26s/solve on CPU — the cost asymmetry; the text gate is the
  most expensive to evade, yet it falls). `evaders/arena-solver-ocr`. The detector still convicts the no-JS client.
- **AD3 PACT — modelled (gate built).** `arena/pact.go` + `/arena/pact[/verify]`: a self-hosted issuer mints an
  anonymous Ed25519 proof-of-personhood token (single-use, expiring); a valid token **skips** the challenge — the
  Private Access Token behaviour, the human-personhood twin of the shipped Web Bot Auth good-bot identity. Honest
  caveat (as with Web Bot Auth): the issuer mints freely in-sandbox, so any client can skip — the documented
  bypass — and the detector convicts a no-JS one regardless. Real PACT issuers gate on device attestation (external).
- **Net:** every arena gate now falls to the appropriate evader (markup / CV / trajectory synthesis / OCR), and
  every defense (managed ladder, behavioral trajectory, PACT/Web-Bot-Auth attestation) is modelled — the arms race
  is demonstrated end-to-end, both sides, confirming the thesis: coherence + attestation, not the challenge, is durable.

### Difficulty levels — per-gate cost dial (2026-06-26)

Added **easy / medium / hard** to every gate with a real difficulty axis (`arena/levels.go`), framed honestly as a
**cost dial, not a security dial**: harder = more work (more PoW bits/memory, heavier text distortion, tighter fit,
a richer required trajectory), never a better bot/human discriminator. The behavioural gates (slider/rotate) hold
the **velocity-CV human-detection floor CONSTANT** across levels — difficulty tightens tolerance + asks for a
richer (but still human-reachable) trajectory, so a harder level never false-positives a real person. honeypot and
pact have no axis (binary). Threaded through the detector relay (`?level=`, whitelisted) + a per-gate
easy/medium/hard selector on each gate page; the detector convicts at **every** level (the point).

**Evader re-verification, live at each level** (the standing rule — solvers must keep pace or the break is recorded):

| gate | easy | medium | hard | evasion |
|---|---|---|---|---|
| hashcash PoW | ✅ 12b/15ms | ✅ 15b/58ms | ✅ 18b/545ms | SHA-256 solver — clean cost gradient |
| many-small PoW | ✅ | ✅ | ✅ 24×12b | per-sub solver |
| memory-hard PoW | 4MB | 8MB | 16MB | reference Argon2id solver (costly by design; not in-browser) |
| math | ✅ | ✅ | ✅ | **solver upgraded** `+` → `+/−/×` (the re-verification caught the break) |
| honeypot | ✅ | — | — | binary (leave trap empty) |
| image-select (CV) | ✅ | ✅ | ✅ | radial-signature classifier survives heavy tile noise |
| slider (synth) | ✅ | ✅ | ✅ | variable-velocity trajectory hits tol=4 + 12-pt/300ms bar |
| rotate (synth) | ✅ | ✅ | ✅ | variable-rate drag |
| text (OCR) | ✅ 4/4 | ✅ 3/4 | ✅ 3/4 (6 confusable chars + heavy noise) | TrOCR `anuashok/ocr-captcha-v3` |

**Text-OCR breaking-point finding (live sweep, 4 rounds/level):** the off-the-shelf TrOCR model reads the text gate
at **every** level — even hard (6 confusable chars + dense noise + strong warp) at 3/4. The misses were NOT the
distortion winning: every one was the model appending a stray `/` (`'KEP7B/'`, `'1AXIV0/'`), and the answer charset
is known alphanumeric — so the solver now strips non-`[A-Z0-9]`, recovering those misses (unit-tested
`test_solve_text_strips_spurious_separator`). The honest lesson reinforces the thesis: heavier text distortion buys
the gate only a marginal, recoverable cost — it does not stop OCR. The Go `arena-solver` keeps pace at every level
except text (the OCR solver's job); PoW shows a clean cost gradient (12→18 bits, 15→545 ms). **Difficulty raises the
bill; the detector's coherence verdict is unchanged at every tier — a cost dial, not a discriminator.**

### Captcha hardening pass (2026-06-26) — text noise, emoji image-select, checkbox

Driven by a captcha-library + public-image-source research pass (Bursztein WOOT'14: **segmentation, not
recognition, is the bottleneck**; licence-verified image sources). Three changes:

- **Text gate — anti-segmentation noise** (`arena/raster.go`): the old render was almost all anti-recognition;
  added the research's top moves, level-scaled — **negative kerning / glyph overlap** (the #1 anti-segmentation
  technique), **2D sine warp** (H+V), **curved Bézier interference lines** through the glyphs, **per-glyph colour
  variation** (beats single-threshold binarization), denser grey-varied speckle. Hard now renders 6 confusable
  overlapping warped chars; easy stays a clean 4-char read.
- **Image-select — real emoji glyphs** (`arena/emoji.go`, Noto Emoji **OFL 1.1**, vendored `assets/`): replaced the
  4 synthetic shapes (circle/square/triangle/star) with categorised emoji tiles ("select every animal/food/vehicle").
  RED RE-VERIFY: the `arena-solver` radial-signature classifier (`classifyTilePNG`) **now FAILS image-select live** —
  emoji glyphs have no clean contour, so the heuristic CV breaks. This is the intended needle-move: the gate now
  forces a real CV/VLM solver (the documented frontier), not a shape heuristic. Licence-clean (OFL, no per-image
  attribution; OFL.txt bundled). Traps avoided per the research: CIFAR (no licence), ImageNet/Tiny-ImageNet
  (non-commercial), Unsplash/Pexels (proprietary), OpenMoji (CC BY-SA ShareAlike). Quick, Draw! (CC BY 4.0) is the
  queued richer second source ("emoji now, doodles later").
- **Checkbox gate** — the iconic reCAPTCHA-v2 / Turnstile "click to confirm you are human" checkbox on the managed
  mechanism (click → coherence check → pass-on-click or PoW step-up).

Net: text + image-select are now genuinely CV-hard (OCR and real-CV/VLM respectively), the heuristic `arena-solver`
is held to math/honeypot/slider/rotate, and the detector still convicts the no-JS client at every gate and level.

## Coordination — fleet axis live-grounded end-to-end (2026-06-27)

The cross-session/fleet axis — the durable answer to "you can beat any single layer, but not coherence across
all of them at fleet scale" — was scorer-built + offline-graded + live-consumer-unit-tested, but never proven
against a **real detector** ingesting a real fleet. Closed that: `harness/tools/fleet_coordination_demo.py`
POSTs a coordinated fleet through the live detector's `/ingest` (it correlates + stores them), then
`coordination-live` pulls them back over `/scoreboard` + `/session` and grades. Live result (`task
coordination-fleet-demo`), three clusters:

- **fp-collision arm → `fleet` 1.00** — one cloned high-entropy `fp_hash` across 3 distinct source IPs + an
  automation tell (the cloned-profile bot fleet).
- **trace-collision arm → `fleet` 1.00** — one replayed pointer `trace_hash` across 3 distinct IPs (unambiguous).
- **paradox-only control → `candidate` 0.97** — JS divergence under one JA4 from ONE IP, no convicting signal:
  correctly NOT convicted (a real diverse cohort on one browser build produces this shape — the gate's honesty).

Frozen as `corpus/fleet-live/` (the real detector-served sessions) + `test_fleet_coordination_grounding`
(score_corpus → both arms `fleet`, paradox `candidate`) for CI. This proves the whole contract path —
`/ingest` → correlate → store → `/scoreboard`/`/session` → live grading → conviction — works end-to-end. The
one remaining external input is unchanged: **real residential-proxy egress** for *authentic* distinct source
IPs (here distinct `observed_ip` signals stand in for it); the conviction LOGIC (every convicting signal needs
≥2 distinct IPs) is now live-grounded. This is the load-bearing demonstration of the incoherence thesis at
fleet scale: a fleet must randomize JS (→ the TLS/JS paradox) or clone one profile (→ the fp/trace collision)
— it cannot do neither, and the collision is a property of the cluster no per-session spoof can hide.

### Coordination — authentic real-evader fleet re-grounded LIVE (2026-06-27, ruleset 0.74.52)

Beyond the synthetic /ingest-path demo: ran the AUTHENTIC fleet path on the current stack — 3 concurrent real
stealth-browser containers (`fleet_capture.sh`, `task coordination-fleet-capture`) through the live edge,
each holding a GENUINELY distinct container IP (172.22.0.4/5/6 — the in-sandbox analog of proxy egress, not an
injected `observed_ip`). All three produced the SAME deterministic high-entropy `fp_hash` (`bf779223`, one
cloned anti-detect profile) → graded **`fleet` 1.00** via fp-collision across 3 distinct REAL IPs, severity
HIGH (198 requests). This closes the "distinct IPs stand in" caveat with authentic traffic: the fp collision
is real (3 actual browser instances hashing identically) and the distinct sources are real. Refreshed
`corpus/fleet-cloned/cn{1,2,3}.json` to these current-ruleset captures (the `test_real_cloned_*` regression
still convicts). The fleet axis is now maximally grounded in-sandbox; the only remaining input is real
residential-proxy egress (the `PROXIES=` turnkey path in `fleet_capture.sh`), which is external by nature.

### Coordination — template-similarity rung closes the fuzzy-trace gap (2026-06-27, G37)

The `fuzzy` adversary (Skulk) was the open coordination frontier: jitter the fingerprint AND the pointer trace
per node so every `fp_hash`/`trace_hash` differs → the EXACT collision rules (`fp_collision`, `trace_collision`)
find nothing and the cluster caps at `candidate`. But a real fuzzing fleet draws all N "different" traces from
**one humanizer model** (a Bézier/GAN mouse generator), so they cluster in motion-feature space far tighter than
N distinct humans do. Built the rung that exploits that — **template-similarity clustering**:

- **Signal:** a normalized, jitter-stable `behavioral.trace_descriptor` (6-D motion vector: power-law exponent +
  fit, sub-movement rate, pause ratio, velocity CV, straightness — `harness/biomech.trace_descriptor`), the
  similarity analog of `trace_hash`. The collector emits it from the same pointer stream.
- **Blue (`coordination._template_similarity`):** among cluster members spanning ≥2 distinct IPs, the MEDIAN
  pairwise descriptor distance below the human floor `_TEMPLATE_EPSILON = 0.10` is one model sampled per node.
  **AMBIGUOUS / corroboration-gated** like `fp_collision` (a tight cluster could be one real person across their
  own sessions), so it convicts only with an automation tell or IP-reputation flag; needs ≥3 members (a 2-IP
  pair could be one human on home+mobile).
- **Floor grounded, not picked:** `harness/template_calibration` measures one-humanizer median ≈ 0.05–0.07 vs
  the tightest distinct-human cohort ≈ 0.166 in-sandbox (synthetic Bézier reaches through the SHIPPED
  extractor), with SapiMouse (120 real subjects) as the local second source (`task template-calibrate`) — the
  same two-source discipline as the biomech power-law floor.
- **Red (Skulk `similarity`):** the evolved adversary, profiled — distinct `fp_hash`/`trace_hash` per node but a
  one-humanizer descriptor family, on datacenter egress (the corroborator). **GROUNDED live** (skulk → real
  detector `/ingest` → `coordination-live`): `skulk run similarity` → **`fleet` 1.00** ("traces cluster below
  the human floor, median 0.059 ≤ 0.1, across 3 distinct IPs — exact-match found nothing"); `skulk run fuzzy`
  (no descriptor profiled) → still `candidate` 0.47, the contrast proving the rung closed exactly the humanizer
  gap and nothing more. Scenarios hold precision/recall at 100% (`fleet-template-similarity` convicts,
  `legit-distinct-traces` caps at candidate).

### Coordination — JA4-rotating fuzzy fleet: a measured FP boundary, not a new similarity key (2026-06-27)

The next shape after `similarity`: a fleet that **rotates its JA4 per node** (uTLS-randomized / mixed builds —
each node a singleton JA4-prefix cluster, never graded) AND fuzzes fp/trace. The tempting fix — run
template-similarity as a *primary, corpus-wide* clustering key (not just within a JA4 cluster) — was
**measured and rejected as FP-unsafe** before building. Using the shipped descriptor + a realistic kNN clusterer
(`template_calibration`): a one-humanizer fleet's tightest cluster sits at median ≈ 0.06, but a population of
**distinct** humans always contains a *coincidentally tighter* subset, and that false-cluster floor **drops as
the corpus grows** (worst-case coincidental-k median: 0.046 at M=40 → 0.031 at M=200, *below* the real fleet at
every size k=4–6). Without a binding to constrain the candidate set first, cherry-picking the tightest subset of
a large distinct-human population manufactures false fleets. **So descriptor similarity is a within-cluster
CORROBORATOR, never a primary cross-corpus key** — the within-JA4 rung is FP-safe precisely *because* JA4 binds
the candidates first.

The faithful catch: a JA4-rotating fuzzy fleet is convicted only when an **unambiguous binding survives the
rotation** — here a shared WebRTC origin (recovered by `_collision_clusters`), with template-similarity
corroborating inside the recovered cluster. **GROUNDED live** (`skulk run fuzzy-rotate` → real detector): graded
**`fleet` 1.00** via `shared_real_ip` "3 proxy IPs front one real IP (WebRTC)" + "traces cluster below the human
floor, median 0.054" — despite a distinct JA4, fp, AND trace_hash per node. The FP-safe boundary is locked: the
**same fleet with NO surviving binding** (rotated JA4 + fuzzed fp/trace + no shared origin) grades **0 clusters**
— correctly left ungraded, not forced (`test_pure_cross_ja4_fuzzy_fleet_is_not_clustered`).

- **Groundable, done:** the `fuzzy-rotate` Skulk strategy + the surviving-origin catch + template corroboration.
- **External-data-bound (queued):** a fleet that rotates JA4, fuzzes fp/trace, AND leaks *no* binding is
  indistinguishable from coincidentally-similar distinct humans in-sandbox. Convicting it FP-safely needs a
  **production-scale real diverse-trace population** to calibrate the false-cluster floor at the corpus + cluster
  size where the margin is real — data the lab can't self-generate (SapiMouse's 120 subjects bound the *within*-
  cluster floor, not the corpus-wide cherry-pick floor).
- **Next groundable rung:** a `ticket-reuse` binding (a reused TLS session ticket / PSK shared across the
  rotated-JA4 nodes — another invariant that survives rotation, an exact collision key like the WebRTC origin),
  which needs the Go edge to capture + forward the resumption-ticket identity.

### Coordination — TLS-ticket-reuse binding (the edge-captured rung that survives JA4 rotation) (2026-06-27)

Built the next binding flagged above: a fleet that rotates its JA4 AND fuzzes fp/trace can still be bound by a
**reused TLS-resumption ticket** — a fleet that resumes ONE TLS session across its nodes (to skip full
handshakes) presents the same ticket from every node. A resumption ticket (TLS 1.3 `pre_shared_key` identity /
TLS 1.2 `session_ticket`) is **client-specific session material the server issued to one client**, so the same
ticket id arriving from distinct source IPs is one TLS identity shared across machines — a binding JA4 rotation
and fp/trace fuzzing cannot touch.

- **Edge (Go):** `clienthello.go` now parses `pre_shared_key` (0x29 — first PskIdentity, ignoring the per-
  connection `obfuscated_ticket_age` so the id is stable) and `session_ticket` (0x23 — non-empty body only; an
  empty body is a resumption *request*, not a presented ticket). `tls_extras.TLSTicketID()` hashes the opaque
  ticket to a fixed-width, secret-free id; the edge forwards it as `network.tls_ticket_id`. Go-tested (parse,
  stability, empty-ticket-is-not-an-id, distinct-tickets-differ).
- **Blue:** `tls_ticket_id` joins `_COLLISION_KEYS` (recovers the fleet across rotated JA4) + `_shared_ticket`
  in `score_cluster`. **AMBIGUOUS / corroboration-gated** like `fp_collision`: a single ROAMING user can resume
  from a second IP (home → mobile) and some servers permit ticket reuse, so it convicts only with an automation
  tell / IP-reputation flag; a clean roaming user on residential IPs caps at candidate.
- **Red (`ticket-reuse` Skulk strategy):** rotated JA4 + fuzzed fp/trace + one shared `tls_ticket_id`, on
  datacenter egress. **GROUNDED live** (`skulk run ticket-reuse` → real detector): graded **`fleet` 1.00** —
  cluster recovered by "reused TLS session ticket", `shared_ticket` fires, datacenter corroborates — despite a
  distinct JA4/fp/trace per node. Scenarios at 100% precision/recall: `fleet-ticket-reuse` convicts,
  `legit-roaming-ticket` (one user, 2 residential IPs, sequential) caps at candidate.

The JA4-rotating fleet now has **two** edge-captured surviving-binding catches (shared WebRTC origin, reused TLS
ticket); a fleet that rotates JA4, fuzzes fp/trace, AND leaks neither binding remains the external-data-bound
case above (needs a production-scale real-trace population for the corpus-wide similarity floor). Next: a
`staggered` timing strategy (defeat the lockstep window — corroborating-only, so lower-value).

### Browser-coherence — WebGL caps worker-vs-main (the hardened cross-realm GPU tell) (2026-06-27, G37b)

`br.webgl_worker_vs_main` (existing, experimental) compares the WebGL renderer STRING across the main realm and
a Worker OffscreenCanvas — but that is ONE value a spoofer can cheaply patch into Worker scope to defeat it.
Built the hardened complement: `br.webgl_caps_worker_vs_main` compares the high-entropy **capability VECTOR**
(MAX_TEXTURE_SIZE, MAX_RENDERBUFFER_SIZE, MAX_VIEWPORT_DIMS, the uniform/varying/attrib limits,
MAX_COMBINED_TEXTURE_IMAGE_UNITS, supported-extension count) across the same two realms. One physical GPU yields
one limit set, so a real browser matches; a main-realm WebGL fake that matched the renderer string but did not
reproduce the whole limit vector inside the Worker diverges here.

- **Collector:** `demo.py` (authoritative) + `livepage/probes.ts` now compute a `glCapsDigest` in the main
  realm and an identical digest inside the Worker OffscreenCanvas, and emit `browser.webgl_caps_worker_divergence`
  when they differ. Rule: `br.webgl_caps_worker_vs_main` (coherence, weight 0.6, reads the divergence signal).
- **GROUNDED headful, both directions (real browsers, through edge→detector):**
  - **FP-safe:** a real (SwiftShader) Chromium reports an identical caps digest in both realms → signal ABSENT,
    rule does NOT fire (labelled bot only for its Playwright automation tells, not this rule).
  - **Positive, clean:** a capture that fakes MAX_TEXTURE_SIZE in the MAIN realm only (renderer left untouched)
    → renderer MATCHES across realms (`br.webgl_worker_vs_main` stays quiet) but the caps digest diverges →
    `br.webgl_caps_worker_vs_main` fires. This is exactly the case the renderer-string check misses by
    construction. Frozen as `corpus/sessions/webgl-caps-worker-spoof.json` +
    `test_lit_rule_captures[webgl-caps-worker-spoof]`; the grounding capture is `harness/tools/webgl_caps_spoof_capture.mjs`.
- **EXPERIMENTAL** on the same caveat as the renderer sibling: grounded only on software rendering here (no real
  GPU in-sandbox). A real-hardware browser whose Worker OffscreenCanvas software-falls-back could diverge
  legitimately, so it stays experimental (for review) until validated against a Tier-3 real-GPU device — that
  real-GPU validation is the external-data-bound follow-up.

### Coordination — staggered-timing strategy: lockstep is corroborating-only (2026-06-27)

Closed the last Skulk roadmap strategy. A `staggered` fleet spreads its arrivals over time (beyond the engine's
120s lockstep window) to look like organic traffic rather than a synchronized burst. The lesson it grounds:
the lockstep tell is **corroborating-only**, never load-bearing for conviction. Skulk's `staggered` strategy is
a cloned-profile fleet (one fp + automation across distinct IPs) with arrivals 300s apart; the runner stamps
each member's `observed_at` at base + offset, and the detector derives `first_seen` from it (`min(observed_at)`),
so the stagger is real. GROUNDED live (`skulk run staggered` → real detector): graded **`fleet` 1.00** with
evidence "arrivals spread over 600s — no lockstep" (rate 0.3/min, not the 360/min of a lockstep burst), yet the
fp-collision + automation binding convicts unchanged. Scenario `fleet-staggered` (arrivals 10min apart) holds
precision/recall at 100%. Timing-stagger is a weak evasion: it costs only the lockstep bonus, not the verdict.

### Validation — audit of active convicting rules with no live capture (2026-06-27)

Swept all 86 active convicting (coherence/automation/artifact) rules against every committed corpus capture: 83
fire on at least one, 3 had NO corpus positive — the "unexercised active rules need live positives" liability
(an active CONVICTING rule that has never been shown to fire on a real capture). Triaged by in-sandbox
groundability:

- **`br.mobile_no_touch` → GROUNDED (closed).** A real headful Chromium with an iPhone UA but maxTouchPoints=0
  (`harness/tools/mobile_no_touch_capture.mjs`) trips it through edge→detector — the classic desktop-faking-mobile
  spoof (CDP UA override without touch emulation). Frozen as `corpus/sessions/mobile-no-touch.json` +
  `test_lit_rule_captures`. It had only a synthetic-fingerprint grounding before; this closes the real-capture gap.
- **`br.voice_os_vs_ua` → external-data-bound.** Needs real OS speech-synthesis voices to derive `voice_os_hint`;
  the in-sandbox container Chromium has NONE (it fires `br.voices_empty`), so the voice→OS coherence can't be
  exercised here. Needs a real-OS browser with a populated TTS voice list.
- **`br.webgpu_vendor_vs_webgl` → external-data-bound.** Needs a functional WebGPU adapter to read the adapter
  vendor; the container reports `webgpu_no_adapter` (navigator.gpu present but requestAdapter() → null under
  headless SwiftShader), so there is no adapter vendor to contradict the WebGL one. Needs a real-GPU device.

Net: the in-sandbox-groundable share of the unexercised set is now lit; the remaining two join the Tier-3
real-GPU / real-OS queue alongside the WebGL-worker rules.

### Red-team — managed fleet orchestration + zendriver-docker investigation (2026-06-27)

Built the orchestration layer the authentic fleet path lacked. `fleet_capture.sh` runs N copies of ONE image
and silently drops any node that flakes; `kitsune_harness.fleet_manager` is the stateful, self-healing upgrade:
a declarative `FleetPlan` of **heterogeneous** nodes (mix camoufox + zendriver + …), each with its own env
(KS_UACH/KS_LINUX/…) and **per-node egress proxy**, launched concurrently with **per-node retry** (a transient
Chrome-sandbox flake re-runs instead of shrinking the fleet — observed live), then every minted session is
pulled and graded as one coordination cluster, with a per-node health report. Ethics-gated in code: the target
is checked against the harness allow-list FIRST (`assert_allowed`) — owned edge/detector/arena only, no botnet.
Docker + the detector fetch are injected, so the orchestration (retry, concurrency, health, grading) is unit-
tested without containers; the real-Docker launch is `# pragma: no cover`. **GROUNDED live** (`task
coordination-fleet-manage`): 3 zendriver workers → 3/3 sessions → graded **`fleet` 1.00** (deterministic
cloned-profile fp-collision across distinct container IPs). Note the worker↔manager detector split: workers get
the network name `detector:8080`, the off-network manager fetches the host port `localhost:8099`.

**zendriver-docker investigation** (github.com/cdpdriver/zendriver-docker): a SINGLE-INSTANCE template on
`swayvnc-chrome` (Sway/Wayland + VNC on :5910, `RENDER_GROUP_GID` for GPU). It handles the Chrome sandbox via a
containerized Wayland session (not `--no-sandbox`) and is **GPU-accelerated** — but has no pooling, proxy, or
session management, so it is NOT a fleet manager (the orchestration above is the complementary piece). The
genuinely useful lead: its **host-GPU passthrough** (`RENDER_GROUP_GID` + Wayland) is a concrete path to ground
the Tier-3 real-GPU rules (`br.webgl_caps_worker_vs_main`, `br.webgpu_vendor_vs_webgl`) — a real GPU adapter
inside the worker would finally exercise the worker-OffscreenCanvas-vs-main caps comparison on real hardware.
Filed as the worker-image option for the real-GPU queue (needs a GPU host).

### Red-team — bake the evasion ladder into the fleet manager (2026-06-27)

The managed fleet manager could run any evader image+env, but the operator had to know image tags and KS_*
flags. Built the structured **evasion registry** (`kitsune_harness.evasions`) the generated evasion-catalog
always implied — each fleet-relevant evasion as a named `Evasion(name, image, env, family, summary)`: the
Camoufox family (default/linux/macos/hardened/behave/headful/touch), the Chromium-CDP class
(zendriver{,-uach,-uach-behave}/nodriver/pydoll/undetected/selenium-driverless), the stealth/brave/playwright-extra
browsers, and the vanilla control. The fleet manager now composes from NAMED evasions: `evasion_node("camoufox-linux")`
resolves the registry entry, and the CLI takes `--evasion <name>` (repeat for a MIXED fleet) + `--list-evasions`.
GROUNDED live: `--evasion zendriver-uach --n 3` → 3 real workers labelled `zendriver-uach-{0,1,2}` → graded
`fleet` 1.00 (cloned-profile fp-collision). The registry is the long-pending authored source the evasion-catalog
can eventually generate from; the stealth tool's single-session artifact modes (electron-leak/canvas-lie/…) stay
lit via the per-rule captures, not fleet nodes, so only the stealth BASE mode is registered.

### Red-team — declarative engagement plans for the fleet manager (2026-06-27)

Made the managed fleet shareable + reusable for engagements: a **declarative plan file** (YAML/JSON) defines a
whole multi-evasion fleet — `kitsune_harness.fleet_manager.load_plan(path)` / `plan_from_obj(obj)` parse a spec
whose `nodes` are `{evasion|image, replicas?, proxy?, env?}` into a `FleetPlan` (replicas expand to labelled
nodes, env overlays the evasion's, the allow-list still gates the target). CLI: `--plan engagement.yaml`. Two
worked templates ship in `harness/examples/`: `engagement-cloned-residential.yaml` (one cloned hardened profile
fanned across residential proxies — the account-fraud/credential-stuffing shape that convicts on fp-collision)
and `engagement-mixed-randomizer.yaml` (a heterogeneous camoufox+zendriver+nodriver fleet — the multi-accounting
shape that correctly caps at `candidate` until corroborated). GROUNDED live: a 3-node zendriver plan via `--plan`
→ 3/3 sessions → graded `fleet` 1.00. The plans are the version-controllable, reviewable engagement artifact the
"reusable for education + active engagements" goal wanted.

### Red-team — structured engagement report (the red⇄blue finding) (2026-06-27)

A fleet run now produces a reviewable, diffable **finding**, not just stdout. `fleet_manager.report_dict(report)`
emits a structured JSON engagement report — per-node health (status/attempts/proxy/session), the coordination
verdict (label/score/severity/binding/evidence), and the top-line **outcome**: `caught` (the defense convicted
the fleet), `evaded` (the fleet ran but the defense did not convict — the honest boundary), or `inconclusive`
(too few sessions to cluster), with a one-line assessment naming the convicting binding (fp_collision /
trace_collision / shared_origin / ticket_reuse / template_similarity). CLI: `--report engagement.json`.
GROUNDED end-to-end live on Kitsune: `--evasion zendriver-uach --n 3 --report engagement.json` → 3/3 sessions →
`{"outcome": "caught", "assessment": "the 3-node fleet … was CAUGHT — graded \`fleet\` 1.00 via fp_collision", …}`.
This is the deliverable an engagement produces: plan in → finding out.

### Red-team — behavioral task scripts for fleet workers (2026-06-27)

A fleet worker that only navigates and mints sends ZERO input — no realistic interaction. Added a behavioral
task DSL (`kitsune_harness.tasks`): a `BehavioralTask` is a declarative list of single-action steps
(`{move:[x,y]}` / `{click:[x,y]}` / `{scroll:dy}` / `{type:"…"}` / `{wait:ms}`) with named presets (`idle-cursor`,
`browse`, `scrape-scroll`, `form-fill`). A plan node's `task:` (a preset name or inline steps) serializes to the
`KS_TASK` env via the fleet manager; a TASK-AWARE evader replays it through trusted CDP input. Generalized
zendriver's hardcoded `_human_mouse` into a `_run_task` CDP executor (move/click/scroll/type/wait, each step
best-effort so a flaky action never loses the session). GROUNDED end-to-end live on Kitsune: `--task browse` →
the session carries pointer_event_count=21, submovement_count=6, mouse_entropy=0.64 (real interaction features),
versus a navigate-and-mint node where the behavioral signals are ABSENT (zero input). CLI `--task <preset>` +
example `harness/examples/engagement-scraper-fleet.yaml` (a zendriver fleet running `scrape-scroll`). Caveat:
the DSL + plumbing are universal but execution needs a task-aware evader (today zendriver); others ignore
`KS_TASK` harmlessly. The behavioral analog of the engagement plan: a fleet now models a real flow, not just
navigate-and-mint.

### Red-team — behavioral task DSL portable to a second backend (camoufox) (2026-06-27)

Extended the behavioral task executor to a SECOND evader, proving the DSL is portable across automation
backends. camoufox (Firefox engine, sync Playwright — not CDP) now reads the same `KS_TASK` script and replays
it via `page.mouse.move/click/wheel` + `page.keyboard.type` (the Gecko twin of zendriver's CDP `_run_task`,
each step best-effort). GROUNDED live on Kitsune: `--evasion camoufox-linux --task browse` → the session carries
pointer_event_count=27, submovement_count=8, mouse_entropy=0.43 — real interaction features from the Playwright
backend, the same DSL zendriver runs via CDP. The harness owns the DSL; each evader owns its execution; two
backends (Chromium-CDP + Firefox-Playwright) now prove the portability. `engagement-scraper-fleet.yaml` updated
to a mixed cross-backend task fleet. Task-aware evaders today: zendriver, camoufox.

### Red-team — multi-wave campaigns (an engagement as a timeline) (2026-06-27)

The top layer of the adversary-emulation tool: a `CampaignPlan` is a SEQUENCE of named fleet waves (recon →
coordinated attack → …), each a full managed fleet run in sequence and graded in ISOLATION (run_fleet grades
only the sessions each wave minted, so a recon wave does not pollute the attack wave's coordination cluster even
though both hit the same detector store). `campaign_from_obj` / `load_campaign` parse a `{name, waves:[…]}` spec
where campaign-level edge/detector/retries are inherited by every wave; `run_campaign` executes them; the
`campaign_report_dict` aggregates which waves the defense caught vs evaded with a top-line assessment. CLI
`--campaign campaign.yaml` (+ `--report`). Example `harness/examples/campaign-account-takeover.yaml` (a quiet
recon wave, then a cloned-hardened credential-stuffing fleet running a form-fill task). GROUNDED end-to-end live
on Kitsune: a 2-wave campaign → recon INCONCLUSIVE (baseline), attack-fleet CAUGHT `fleet` 1.00 → "the defense
CAUGHT 1/2 wave(s): attack-fleet". The full adversary-emulation arc: campaign timeline → mixed named-evasion
fleets with per-node proxy + behavioral tasks (cross-backend) → self-healing capture → coordination grade →
aggregated red⇄blue finding.

### Red-team — adversary archetype catalog (named personas) (2026-06-27)

Answered "do we have a variety of adversary archetypes": built a structured catalog (`kitsune_harness.archetypes`)
of named personas, each packaging a fleet SHAPE (evasions + replicas + behavioral task) + the threat class + the
coordination binding it exhibits + a rate/scale profile. Five today: `credential-stuffer` (cloned hardened
camoufox + form-fill → fp_collision, caught), `scalper` (cloned checkout burst → fp_collision), `scraper`
(cloned crawler + scrape-scroll → fp_collision), `sybil-farmer` (DIVERSE evasions, no shared binding → candidate
— the honest evading shape), `proxy-botnet` (diverse behind one origin → shared_origin, needs real proxy
egress). `archetype_plan(name)` resolves a persona to a runnable FleetPlan; CLI `--archetype <name>` +
`--list-archetypes`. GROUNDED live on Kitsune: `--archetype scraper` → 3-node zendriver fleet running
scrape-scroll → graded `fleet` 1.00 via fp_collision, outcome "caught". The catalog spans the ladder honestly:
4 personas are caught (fp_collision / shared_origin), the deliberately-diversified sybil-farmer evades to
candidate. NB the `rate` field is an informational scale/RPS hint — ACTIVE RPS scoping (probing the target's
throttle/challenge thresholds in a recon wave) is the distinct rate dimension this sets up but does not yet
drive; the recon wave today is a fingerprint/coordination baseline, not rate reconnaissance.

### Red-team — RPS scoping (the recon RATE dimension) (2026-06-27)

Closed the recon rate gap. The fleet manager scoped a target's fingerprint/coordination posture but never its
RATE posture. `kitsune_harness.rps_scout` is the recon rate probe: `scout_rps(url, rates=…)` ramps a short,
bounded probe through ascending target RPS against an ALLOW-LISTED url (ethics-gated by `assert_allowed`),
classifies each request (ok / throttled 429 / blocked 403,503 / challenged — a PoW/CAPTCHA/rate-limit gate
marker in the body) + latency percentiles, and reports the BUDGET (the highest clean RPS before the knee) and
what degraded (throttled/blocked/challenged/latency). It stops ramping at the first knee — a bounded recon
probe, NOT a flood. CLI `python -m kitsune_harness.rps_scout <url>` / `task scope-rps`; HTTP + the pacing sleep
are injected so the ramp/budget/knee logic is unit-tested without a network. GROUNDED live on Kitsune: ramped
1→100 RPS against the detector /healthz → all clean (latency flat ~2ms), budget 100 rps, knee none (an honest
finding: no rate limit on healthz up to 100 RPS). The knee paths (throttle/blocked/challenge/saturation) are
unit-grounded. This is the recon rate dimension an archetype's `rate` profile now has a tool to measure against.

### Red-team/blue — RPS-gated arena + RPS recon as a campaign wave (2026-06-27)

Built the rate-based challenge gate the RPS scout needed and wired RPS scoping into the recon phase. BLUE: a new
arena gate `GET /arena/rate` (arena/rate.go) — a per-client token-bucket rate limiter (the documented CDN/WAF
mechanism), 200 under the per-level RPS budget and 429 above it, with the difficulty cost dial (easy 50 / medium
20 / hard 5 rps). The detector relays it (`/arena/rate`, forwarding X-Forwarded-For so the budget is per real
origin) so it's on the unified origin like the other gates. RED/recon: a campaign wave can now be a `scout:`
(RPS recon) instead of `nodes:` (fleet) — run_campaign ramps RPS against the gate and reports the budget + knee,
so the recon phase LITERALLY includes RPS scoping. GROUNDED end-to-end live on Kitsune: rps_scout vs the hard
gate → budget 5 rps, knee throttled (the gate's exact threshold); and a 2-wave campaign → recon-rps RPS-SCOPE
(budget 5 rps, throttled) + attack-fleet CAUGHT `fleet` 1.00. Example campaign-account-takeover.yaml updated so
its recon-rps wave scopes the rate budget before the credential-stuffing fleet. Go vet/gofmt clean + arena tests;
detector relay tested; harness 346 pass. This closes the "does recon include RPS scoping" gap with a real gate
to scope against.

### Red-team/blue — archetype validation harness (the catalog as a tested contract) (2026-06-27)

Answered "can we create arena tests for the adversary archetypes": yes — built a validation harness that runs
EVERY archetype's real fleet against the live detector and checks the actual coordination outcome matches the
catalog's declared `expected`, turning each persona from documentation into a tested contract.
`validate_archetypes()` + CLI `--validate-archetypes` / `task archetype-validate`; archetypes whose binding is
external-data-bound (proxy-botnet → shared_origin needs real proxy egress) are reported `skipped`. Running it
live IMMEDIATELY caught two fidelity bugs in the catalog:

1. **credential-stuffer used camoufox-hardened** — but camoufox RANDOMIZES its fingerprint per launch, so a
   camoufox fleet has distinct fps (no fp_collision) → it graded `candidate`, not the cataloged `caught`. Fixed
   to a deterministic-fingerprint Chromium clone (zendriver, which is also task-aware so the form-fill replays).
2. **sybil-farmer mixed camoufox + zendriver + nodriver** — but zendriver and nodriver are BOTH Chromium and
   render identically, so those two COLLIDED on fp → graded `caught`, not the cataloged `candidate`. Fixed to a
   camoufox-only fleet: per-launch randomization gives genuinely distinct fps → no collision → `candidate`.

After the corrections the live validation is 5/5. The lesson (now a CI structural test): fp_collision needs ONE
deterministic Chromium clone (never camoufox); a diverse/sybil fleet gets its fp-diversity from camoufox's
per-launch randomization, NOT from mixing Chromium tools (which collide). The archetype `expected` is now
grounded against reality, and a future catalog/scoring change that breaks a persona's outcome is caught by
`task archetype-validate`. harness 347 pass.

### Red-team — review-farmer archetype: the behavioral (trace_collision) binding (2026-06-27)

Broadened the archetype catalog to a NEW coordination binding. All caught personas convicted on fp_collision
(a cloned fingerprint); none exercised the BEHAVIORAL binding. Added `review-farmer` (engagement/review fraud):
camoufox ×3 — each randomizes its fingerprint per launch (DISTINCT fps, no fp_collision) — but a pinned
`KS_TASK_SEED` makes every node replay the IDENTICAL canned humanized trace → one shared trace_hash across
distinct IPs → trace_collision convicts (two real users never trace the same path). Mechanism: the task
executors (zendriver CDP + camoufox Playwright) now seed their RNG from KS_TASK_SEED, so the per-instance jitter
is identical fleet-wide — a real canned-replay, not byte-faked. GROUNDED live: `--archetype review-farmer` →
`fleet` 1.00 via trace_collision ("identical pointer trace across 3 distinct source IPs — replayed canned
trajectory"). The catalog now spans four bindings (fp_collision ×3 / trace_collision / none / shared_origin),
all live-validated 6/6 by `task archetype-validate`. ArchetypeNode gained an `env` field (carries the seed).

### Analysis — coordinating a fleet without correlation: the evasion frontier (2026-06-27)

Synthesized the coordination red⇄blue into docs/coordination-evasion.md (the answer to "how to coordinate a
large fleet without fleet correlation"). To evade conviction a fleet must remove EVERY binding a real cohort
can't produce — diverse fps (no fp_collision/template_similarity), distinct JA4 (and survive cross-JA4 recovery),
distinct behavioral models (no trace_collision/template_similarity), distinct residential origin (no shared_origin
/ticket/datacenter rep). GROUNDED: the maximal in-sandbox version (sybil-farmer, camoufox ×3, diverse fps +
distinct traces + distinct IPs) evades to `candidate` 1.00 — its only shared signal is the JA4 cipher prefix
(one build, ambiguous) + corroborating-only paradox/IP-spread/lockstep. What still convicts it is external-data-
bound: IP reputation (real datacenter/proxy egress), different real browser BUILDS (drop the JA4 prefix), and
real-distinct-hardware fps (survive template_similarity). The bind/thesis: doing all of it at scale reconstructs
N genuinely independent real users at N× cost — coordination detection forces the fleet to cost as much as N
real users, which is why the residual is an economic / external-data frontier, not in-sandbox-solvable (it is
saturated in-sandbox).

### Red-team — distinct-builds lever + fragmentation reporting (2026-06-27)

Built the lever that drops the last shared signal of a diversified fleet (the JA4 cipher prefix = one build):
put nodes on different engines/builds so the fleet spans multiple JA4 prefixes and no single cluster binds it.
The engagement report now surfaces this — FleetReport holds ALL graded clusters (not just the top); report_dict
adds `fragmented` + a per-cluster breakdown, and the outcome is CAUGHT iff ANY cluster convicts. GROUNDED live: a
mixed-engine fleet (camoufox ×2 + zendriver ×2) FRAGMENTED into two JA4 clusters (Firefox + Chrome), both
`candidate` → fully evaded — the JA4 prefix no longer binds the fleet. In-sandbox LIMIT: only a few engine
families exist and a same-engine deterministic-fp sub-fleet still collides; full per-node distinct builds needs
uTLS (non-browser Go tools) or many real builds — Skulk's fuzzy-rotate models it synthetically, and the cross-JA4
`_collision_clusters` recovery still catches it if any binding leaks. Also surfaced a fidelity note: a small
Chromium-clone sub-fleet did NOT always fp-collide (zendriver fp has some run-to-run variance), so a 2-node
clone is less reliably caught than a 3+-node one. docs/coordination-evasion.md updated with the grounded result.

## FoxIO JA4+ suite — leverage scan (2026-06-27)

Scanned github.com/FoxIO-LLC/ja4 for anything not already covered. Result: Kitsune already implements the
JA4+ value, independently — and is AHEAD on the headline use-case.

**Already covered (independent Kitsune implementations):**
- JA4 (TLS client) — `edge/fingerprint/ja4.go` (the JA4 TLS-client spec is BSD-3 open; our code is our own).
- JA4H (HTTP client) — h2 header-order / `net.h2_header_order_vs_ua`.
- JA4T-equivalent (TCP client OS) — `edge/tcpfp` (p0f-style) + the `net.tls_os_vs_tcp_os` coherence rule.
- QUIC/H3 ClientHello fingerprint.
- **The JA4+ cross-validation THESIS itself** — JA4+'s headline ("detect spoofed fingerprints by comparing
  JA4/JA4S/JA4H/JA4T consistency") IS Kitsune's coherence engine, and the JA4+ README explicitly does NOT detail
  the cross-layer algorithms Kitsune already ships (tls-vs-tcp OS, JA4H-vs-UA, accept-lang-vs-nav-lang, …).

**Out of scope (not web-bot detection):** JA4S (server hello), JA4X (X.509 cert), JA4SSH, JA4D/JA4D6 (DHCP),
JA4TScan (active port scan), JA4L*S* (server→client latency).

**The one genuinely-new leverageable concept — JA4L (client latency / light-distance):** measure the handshake
RTT, derive the max physical distance light could travel in that RTT, and flag when the IP's CLAIMED geo (we
already have `detector/geo.py`, City+ASN MMDB) is FARTHER than light-speed allows → a proxy/VPN tell that needs
NO IP reputation (the residential-proxy frontier). Pairs perfectly with our existing geo. The one real blocker is
**external-data grounding**: in-sandbox all traffic is localhost (RTT ~0, no distance), so a live positive needs a
real distant client behind a proxy. On licensing — FoxIO License 1.1 **permits free / non-commercial / research
use** (only monetized / OEM products need the commercial + patent licence), so a free public lab like Kitsune may
use the method; we still implement cleanroom (from the published concept, under our own name, never vendoring their
code) as we do for base JA4. VERDICT: record the RTT-vs-geo light-distance COHERENCE idea as an external-data-bound
lead; do NOT ship an ungrounded rule now (the bar is grounding, not licensing).

**Marginal:** JA4's a_b_c locality lets you cluster by `a_c` (drop the cipher hash) to catch a CIPHER-only
randomizing fleet — but no real tool randomizes ciphers-but-not-extensions, and full JA4 rotation is already
caught by the cross-JA4 `_collision_clusters` recovery. Not worth a build.

### Network — IPv6 origin unit: detection + evasion (G25, 2026-06-27)

"What are the implications of JA4 fingerprinting on IPv4 vs IPv6?" → **JA4 is transport-agnostic** (the TLS
ClientHello is identical over v4 and v6, so JA4/JA4H/JA4T-equiv all carry over unchanged). The real implication
is one layer down: **the per-IP defenses break on IPv6.** Every coordination binding gates on ">= 2 DISTINCT
observed IPs" and the arena rate gate keys per IP — but on IPv6 the *address* is the wrong unit. A subscriber is
handed a whole **/64** (often a /56) and a host mints unlimited **/128s** for free (SLAAC + RFC 4941 privacy
addresses rotate hourly). Counting raw /128s is both a **false positive** (one real user's hourly privacy
rotation looks like a multi-IP fleet) and an **evasion** (rate-limit bypass + faked IP spread by spraying /128s
inside one /64). Cleanroom: this is plain networking (a /64 prefix mask), zero FoxIO IP involved.

Built (detection + evasion together):
- **`coordination._ip_origin(ip)`** folds every source IP to its ORIGIN — IPv4 address, IPv6 /64 (`ipaddress`) —
  applied at every distinct-IP counting site: `_fp_collision`, `_trace_collision`, `_shared_ticket`,
  `_template_similarity`, the new `_distinct_origins` (IP-spread / proxy-fleet scoring), and `_collision_clusters`.
  "Distinct source IPs" now means distinct origins everywhere.
- **`arena/rate.go` `clientIP`** keys the token bucket per /64 origin (`ipOrigin`), and the rewrite fixes the
  bracketed-IPv6 `RemoteAddr` parse the old `LastIndexByte(':')` mangled (now `net.SplitHostPort` + `net.ParseIP`).
- **Skulk `ipv6-rotate`** strategy: a cloned fleet spraying distinct /128s across a FEW real /64s — models the
  "use IPv6 to fake spread for free" attacker. Skulk's self-grader folds to /64 too (`grade._origin`).

GROUNDED live against the running detector (`live_coordination.score_live`):
- 6 /128s across **2 /64s** → `fleet 1.00`, `distinct_observed_ips=2` (folded from 6 — the /128 spray bought no
  apparent spread) → fp-collision convicts across the 2 origins. The evasion buys nothing; real spread still costs
  genuinely distinct /64 subscriptions.
- 4 /128s within **ONE /64** → `candidate 0.52`, `distinct_observed_ips=1`, no fp-collision — a single subscriber
  rotating privacy addresses is not a coordination fleet (the FP boundary; without the fold those 4 would have
  read as 4 IPs → false `fleet`).

Tests: harness `test_coordination` (cloned across distinct /64s convicts; /128 rotation within one /64 folds to one
origin; `_ip_origin` unit), fleet `test_skulk` (the spray folds + the one-/64 FP boundary), arena `rate_test`
(bracketed-IPv6 keying, /128-rotation throttled). Go + harness + fleet suites green; see
[`docs/coordination-evasion.md`](coordination-evasion.md) §IPv6.

### Network — JA4 threat intel: the no-JS lazy-scraper tell (G26, 2026-06-28)

"Can we leverage JA3/JA4 threat intel?" → the honest answer is the on-thesis *slice*, not a blocklist. A
denylist of known-bad JA4 hashes is the canonical bad-signal Kitsune exists to beat (trivially evaded by the
fingerprint rotation the lab already models, FP-prone via JA4 collision). The value is JA4 used as a
**client-identity coherence input** — the lab already does this for browser engines (`ja4_hints.json` →
`net.tls_vs_ua_browser`/`net.tls_os_vs_tcp_os`) and for IP reputation (curated CIDR feed → the coordination
corroborator). **Skip JA3 entirely**: MD5-era, unstable under TLS 1.3 + GREASE, abuse.ch retired its JA3 feed.

The gap closed: `net.tls_vs_ua_browser` reads the JS `browser.ua_browser`, which a no-JS client never sends, so
a curl/Go/Python scraper that spoofs a browser UA in the HTTP *header* over its default TLS stack evaded it
(GROUNDED baseline: curl with a Chrome UA → `ja4_browser_hint=None` → the rule was unevaluable). Built the no-JS
complement, entirely from self-generated ground truth (no external feed, license-clean):

- Captured the real tool JA4s by running each client through the live edge: curl `t13d3012h2_1d37bd780c83`,
  Go net/http `t13d131100_f57a46bbacb6`, Python urllib `t13d171100_ab0a1bf427ad`.
- Added a `Client` field to the edge hint (`hints.go`) — mutually exclusive with `Browser` (a JA4 is a browser
  engine OR a known automation stack). The edge emits `network.ja4_client_hint` (`signal.go`) and a new
  `network.ua_header_browser` (`reverseproxy.go::uaHeaderBrowser`, the UA family parsed edge-side — the operand
  that exists for a no-JS client, unlike the JS `browser.ua_browser`).
- Rule `net.ja4_tool_vs_ua` (coherence, w0.75, active): `not_equal` over the two. Disjoint vocabularies
  (tool name vs browser name) → it fires iff BOTH are present, i.e. a known automation-tool TLS handshake
  wearing a browser User-Agent.

GROUNDED live end-to-end (ruleset 0.74.53): curl+Chrome-UA, which EVADED before, now FIRES; honest curl+`curl/8.x`
does NOT (ua_header_browser withheld); Go+Chrome-UA also classified (`go-http`). FP-safe: a real browser's JA4
sets a browser hint never a client hint (unit-tested); `task calibrate` 500 browserforge profiles → **bot 0%**,
`net.ja4_tool_vs_ua` never fires (browserforge carries no JA4). Honest scope: this catches the LAZY scraper
(default-library fingerprint); the high-fidelity impersonators (curl-impersonate/uTLS) emit a Chrome-identical
JA4 and are out of scope by construction — exactly what cross-layer coherence BEYOND JA4 is for. The external
full-feed import (ja4db.com / vendor threat intel) stays queued: the long tail (malware C2, exotic libs) needs
real traffic to FP-validate, and ja4db use is free but must be cleanroomed.

### Coordination — known-automation-tool JA4 as a corroborator (G26 follow-on, 2026-06-28)

The corroboration twin of the no-JS scraper rule. The coordination conviction gate elevates an AMBIGUOUS binding
(fp-collision / JA4_c divergence / template-similarity / reused TLS ticket) to a `fleet` only when corroborated —
previously by an unambiguous binding, a per-session JS automation tell, or a datacenter/proxy IP-reputation flag.
A NO-JS automation-tool fleet (curl/Go/Python scrapers) fell through that gate: it runs no JavaScript (no
webdriver/CDP tell) and can sit on CLEAN residential IPs (no IP-rep flag), yet still shares a network-layer
ambiguous binding — a reused TLS-resumption ticket, or divergent JA4_c. Such a cluster capped at `candidate`
even though its handshake is provably non-browser.

Added `coordination._has_known_automation_ja4` — a 4th corroborator that fires when any cluster member carries
`network.ja4_client_hint` (the edge's JA4→tool classification from G26). It is the network-layer twin of the JS
automation tell: a non-browser TLS handshake IS proof the client is automation, so an ambiguous binding shared
across a tool-JA4 cluster convicts without needing a JS tell or a datacenter flag. FP-safe: it only ELEVATES an
existing ambiguous binding (a tool-JA4 cluster with no binding stays candidate), and a real diverse cohort runs
browsers (a browser hint, never a client hint).

Skulk gains `tool-fleet` (a no-JS tool fleet bound by a reused ticket on residential IPs, ja4_client set,
no automation/datacenter) and FleetMember a `ja4_client` field (emits ja4_client_hint). GROUNDED live: the
tool-fleet → `fleet 1.00` corroborated explicitly by the tool-JA4; the IDENTICAL ticket-reuse shape WITHOUT the
tool-JA4 (a roaming-user-like residential cohort) stays `candidate` — the corroborator is exactly what flips it.
harness + fleet suites green; README/matrix/scoreboard regenerated.

### Behavioral — LLM think-time cadence: a novel temporal AI-agent tell (G12, 2026-06-28)

The AI-agent vein's fourth rung (after G11 teleport-click, G13 keystroke-interval-floor). An LLM browser agent
runs a perceive→reason→act loop bottlenecked on model inference (~3-8s/step), so its HIGH-LEVEL actions (clicks +
typing bursts) arrive at a metronomic multi-second cadence; a human is bursty (sub-second within a task,
irregular gaps between). FP-Agent measured within-action timing but NOT this inter-action rhythm → a novel, open
signal. Durable: an agent cannot shed its deliberation rhythm without giving up the reasoning that is its whole
advantage.

Built `bh.action_cadence_deliberative` (behavioral/corroborating, experimental, w0.5) across all three collectors
(demo.py authoritative + collect.ts + livepage probes.ts) plus a shared `actionCadenceDeliberative` in
`collector/behavioral.ts`. The collector builds a high-level action timeline (click timestamps + the start of each
>1s typing burst) and emits the boolean when >=5 actions have a median interval in [2.5s, 15s] AND a coefficient
of variation < 0.35 (metronomic).

A LONG-HORIZON capture fix was required and is the reusable lesson: the collectors posted once EARLY (the demo
rescore fires at >=12 pointer samples, ~1-2s in; collect.ts at delayMs=4s), long before a ~25s click cadence
accumulates — so the signal could never post. Added a bounded ONE-SHOT re-post that fires when the 5th high-level
action lands (demo.py `ksMaybeCadence`; collect.ts `cadencePosted`), capturing accumulated long-horizon behavior
without spamming /ingest. Any future multi-second-horizon behavioral signal can reuse this.

GROUNDED live confirm-evades-first (Playwright through the live edge→detector spine, `kitsune-stealth` + xvfb): a
metronomic ~5s-cadence run (6 clicks, ±jitter) → `action_cadence_deliberative=true`, rule FIRES; an irregular-gap
human control (0.15-3.5s gaps) → does NOT (CV well above 0.35). Unit-grounded too: 5 vitest cases on the cadence
function (metronomic→true, bursty→false, <5 actions→false, sub-second-metronomic→false, typing-burst folding) +
2 collect-signal cases + a detector engine fires-case. FP-safe: behavioral category is corroborating (never
convicts alone — the residual FP is a methodical human at a steady pace); calibrate-clean (0/800 browserforge,
no interaction timeline). The real `agent` evader (claude -p brain) exhibits this cadence intrinsically — a
faithful adversary the rule now reads.

### Behavioral — scroll-teleport: programmatic scroll as an AI-agent tell (G14, 2026-06-28)

The AI-agent vein's 5th rung. A DOM browser agent jumps the viewport with scrollIntoView()/scrollTo() — an
instant programmatic scroll, never the incremental wheel/trackpad scroll a human produces. Added a NEW scroll
capture surface to all three collectors (demo.py authoritative + collect.ts + livepage probes.ts): the max single
scroll-event delta, the wheel-event count, and whether a scroll-causing keydown fired. `bh.scroll_teleport`
(behavioral/corroborating, experimental, w0.5) emits when a >=800px jump lands in ONE scroll event with ZERO
wheel events, no scroll-key (PageDown/Space/arrows excluded), on a non-touch session (finger-scroll fires no
wheel but is real input). 800px is far above a wheel notch (~100px) or a trackpad swipe per event. The pure
threshold lives in `collector/behavioral.ts::isScrollTeleport` (unit-tested 5 ways); the demo/livepage capture
mirrors it inline.

GROUNDED live confirm-evades-first (Playwright through the edge, kitsune-stealth + xvfb): window.scrollTo(0,3000)
→ `scroll_teleport=true`, rule FIRES; a mouse.wheel scroll (20 notches, many small deltas, wheelCount>0) → does
NOT. Reuses the G12 one-shot re-post (the scroll can land after the early post). FP-safe: behavioral category is
corroborating (never convicts alone); the residual FP is a human clicking an in-page anchor link (instant jump,
no wheel) or dragging the scrollbar; calibrate-clean (0/600 browserforge — no scroll timeline).

### Behavioral — programmatic form input: paste/insertText/fill as an AI-agent tell (G15, 2026-06-28)

The AI-agent vein's 6th rung. LLM browser agents populate a form field via paste (Atlas/ChatGPT/Comet), CDP
Input.insertText, Playwright fill(), or a direct .value set + dispatched input/change — the value appears with NO
keydown on that field and no TRUSTED paste event. A human types (keydowns on the field) or pastes (a trusted
ClipboardEvent). All three collectors (demo.py authoritative + collect.ts + livepage probes.ts) track, per form
field, whether it received a keydown, a trusted paste, and a value change (input/change); a CHANGED field that got
neither keydown nor trusted paste is programmatic injection. `bh.input_via_paste` (behavioral/corroborating,
experimental, w0.5).

Server-prefill is excluded by construction (a pre-populated value fires no input/change during the session).
GROUNDED live confirm-evades-first (Playwright through the edge): page.fill('#ks-bio-text', …) (sets .value +
dispatches input, no keydown) → `input_via_paste=true`, rule FIRES; page.type() (a real keydown per char) → does
NOT. Reuses the G12 one-shot re-post (the fill can land after the early post). FP-safe: behavioral category is
corroborating (never convicts alone); the residual FP is browser autofill (fills without keystroke/paste);
calibrate-clean (0/600 browserforge — no input-interaction timeline).

This completes the in-sandbox AI-agent behavioral set (G11 teleport-click, G12 think-time cadence, G13 keystroke
floor, G14 scroll-teleport, G15 programmatic input) — five orthogonal tells that together convict the real
`agent` evader on the behavioral layer it cannot fully humanize without a real-input-synthesis pipeline (the
phase-4 frontier, external).

### Triage — the remaining groundable-tagged leads are external-data-bound (2026-06-28)

After the AI-agent behavioral set (G11-G15) shipped, the four remaining `lead (groundable)` rows were
re-examined against the guardrail (never ship an ungrounded convicting rule; route external-data-bound items to
the queue). None is cleanly in-sandbox-groundable as an FP-safe rule:

- **G19 (PoW-timing ↔ declared hardware)** — the discriminator is a per-device-class timing baseline; the sandbox
  is one host (no device diversity) and `performance.now()` is Spectre-coarsened → external.
- **G22 (WASM/SIMD arch ↔ platform)** — WASM is deterministic across arch BY SPEC (no structural arch tell); only
  noisy timing micro-benchmarks remain, needing real-device per-arch baselines → external / not structural.
- **G23 (uTLS preset breaks)** — the common stale-preset case is ALREADY shipped (`net.tls_pq_keyshare_vs_ua`,
  G20); the padding/ECH residuals need a real-Chrome TLS baseline (FP-risky, cf. the QUIC-capture retirements)
  and ECH-decryption infra → covered + external residual.
- **G24 (client ↔ server clock)** — convicting drift is swamped by real users' wrong clocks; an FP-safe band needs
  a real-traffic skew distribution (calibration carries no client clock); the replay sub-case is already covered
  by `bh.trace_replay_within_session` → external.

**The in-sandbox groundable G-queue is now DRY.** Every remaining detection lead is bound to data the lab cannot
self-generate (real-device timing/arch baselines, real-Chrome TLS baselines, real-traffic clock skew) — the same
external-data frontier the coordination half hit (real IP reputation, real-GPU, residential egress). The next
detection gains require either real traffic/devices or a fresh SCAN of new research.

### SCAN — 2026-06-28 (post AI-agent-set): no new clean in-sandbox groundable lead

Focused research scan after G11-G15 shipped and the groundable G-queue went dry.

- **"Known By Their Actions: Fingerprinting LLM Browser Agents via UI Traces" (arXiv 2605.14786)** — 41
  client-side UI-trace features; the paper's headline is that **timing features (inter-event intervals,
  time-to-first-action) DOMINATE agent identification**, with action-based features (structural-key ratio, click
  position) as the recovery fallback when timing is jittered. This directly **validates the G11-G15 set** — and
  specifically G12 (action-cadence) as the dominant tell, and G13/G11/G14/G15 as the action-axis fallbacks.
  Verdict: VALIDATION, no new rule. Its remaining features (link-click ratio, clicks-in-top-quarter, scroll
  reversals, popstate-nav fraction, IEI second-vs-first-half trend) are ML-DISTRIBUTIONAL — they need a trained
  classifier over aggregate human telemetry, not the FP-safe single-signal threshold/coherence rules Kitsune
  ships; forcing them into thresholds would FP (e.g. structural-key ratio FPs on a human Tab/Enter-ing a form,
  time-to-first-action FPs on a reader). Out of architecture, not out of scope.
- **Nyasa / vendor "constellation" signals** (mouse-stillness >70%, sub-20ms keystroke bursts, near-zero keystroke
  variance) — the keystroke-burst/variance signals are already shipped (`bh.keystroke_interval_floor` G13,
  `bh.keystroke_entropy_floor`). Mouse-stillness (parked cursor) is FP-prone in isolation (a human reading parks
  the cursor for long stretches) and overlaps the shipped cursor-movement set (`click_without_trajectory`,
  mouse_entropy, pointer_event_count) — marginal, not built (the "grind a marginal tell" the saturation note
  warns against).
- **Red side** — residential/mobile-CGNAT proxies (highest IP trust, share real-user pools), stealth-tool churn
  (puppeteer-extra-stealth deprecated Feb 2026 → nodriver / SeleniumBase UC / patchright, all already in the
  evader ladder). Nothing new + groundable; the proxy/IP-trust frontier remains external-data-bound (the
  coordination half's known queue).

**Outcome: the in-sandbox groundable detection queue is DRY and the SCAN adds no new clean lead.** The dominant
new-research signal (agent timing/cadence) is already shipped; everything else is ML-distributional, FP-soft, or
external-data-bound (real-device baselines, real-traffic IP-trust/clock-skew). Further detection gains now require
real traffic/devices, a trained behavioral classifier (an architecture change), or the next research cycle.

### External data leveraged — ja4db expands the JA4 hint table (2026-06-28)

"Check for external data we can leverage" → the standout immediately-usable source was **FoxIO ja4db**
(`ja4plus-mapping.csv`), a public JA4→client table. Licence verified AT SOURCE: the base JA4 fingerprint (the
only column Kitsune uses) is **BSD-3-Clause and explicitly patent-free** ("FoxIO does not have patent claims");
the JA4+ extension columns (License 1.1, monetization-restricted) are NOT used. It is a static lookup table — no
live traffic, no PII — so it slots straight into the `ja4_hints.json` machinery shipped for `net.ja4_tool_vs_ua`
(#179) and `net.tls_vs_ua_browser`.

Leveraged (curated, not bulk-dumped — the same discipline as the IP-CIDR seeds): +10 non-browser library prefixes
(Python ×3, GoLang ×5, GoLang-webhooks, WinINET) as `client` hints, +4 real browser no-SNI variants
(Chromium/Firefox/Safari) as `browser` hints. The hint table went 11→25 entries.

The on-thesis threat-intel win: **C2 frameworks inherit their HTTP library's JA4** — Sliver (Go) shares
`t13d190900_9dc949149365`, Cobalt Strike (WinINET) shares `t12d190800_d83cc789557e` — so classifying the LIBRARY
makes `net.ja4_tool_vs_ua` catch a Sliver/Cobalt-Strike beacon wearing a browser UA FOR FREE, with no malware
blocklist (which would be off-thesis + need real-traffic FP validation). The malware-SPECIFIC JA4s in ja4db
(IcedID, SoftEther, bare Cobalt-Strike non-library variants) were deliberately NOT shipped for that reason.
Verified no tool↔browser a+b-prefix collision; unit-grounded (hintdb_test, the established ja4db-reference
pattern — the existing real Safari/Firefox seed entries came from this same source and were never re-captured
live). Edge suite green.

**Other external sources checked, status unchanged:** Google/Bing crawler IP-range JSON (public, daily CIDR —
candidate for a DNS-free `net.fake_declared_crawler` path, G7); Spamhaus DROP / IPsum (proxy/abuse IP-rep,
licence-verify per source); Azure Service-Tags (rotating-URL discovery step). All real-device / real-traffic /
real-GPU baselines (G18 Tier-3, G19, G22, X5 device-screen DB, X4 prevalence Berke corpus) remain gated on an
operator download or real egress — the genuine external frontier, with adapters already built (`grounding.md`).

### External data leveraged — Spamhaus DROP + IPsum → abuse IP reputation (2026-06-28)

Second external-data wire from the "check for external data" pass. Two public abuse/threat IP feeds, both
licence-verified AT SOURCE: **Spamhaus DROP** (`drop_v4.json`, hijacked / criminal-leased netblocks, free-to-use)
and **IPsum level-4** (`levels/4.txt`, IPs on ≥4 independent blocklists, **Unlicense / public-domain**). These are
an ABUSE reputation dimension distinct from the existing datacenter (rep.datacenter_asn) and proxy/VPN
(rep.known_proxy_exit) ones — an IP connecting FROM a hijacked netblock or a multiply-blocklisted address is
bot/abuse infrastructure, not a clean residential eyeball.

Wired end-to-end, following the X4BNet pattern: `IPReputation.classify` now returns a 3-tuple (added the `abuse`
list + index); the detector emits `reputation.is_abuse_listed`; new rule `rep.abuse_listed` (reputation/
corroborating, w0.5); the coordination corroborator `_has_ip_reputation_flag` now also fires on abuse-listed
(an abuse IP corroborates an ambiguous coordination binding as a bot fleet, exactly like datacenter/proxy);
`ip_reputation_refresh` fetches both at deploy into `abuse_cidrs.txt` (uncommitted; committed seed ships empty,
as the proxy-exit seed does — abuse IPs are dynamic), floor-guarded (DROP≥200, IPsum≥500) so a source URL/format
drift fails loud instead of silently emptying the list.

GROUNDED: real-data parsers run against LIVE production data (2026-06-28: Spamhaus DROP 1698 CIDRs, IPsum-L4 7140
IPs → 8837 normalized abuse entries, both well above floors); unit-grounded (classify 3rd flag, refresh parsers +
floor-drift guard, detector emission, engine rule fires, coordination corroboration); FP-safe like every rep.*
rule — corroborating-only (never convicts alone) and browserforge/Intoli calibration carry no IP, so it cannot
raise the legit flag rate. detector 444 / harness 354 green.

**Remaining fetchable-but-unwired public CIDR feeds** (next-tier candidates, all in the data table): Google/Bing
crawler IP-range JSON (a DNS-free `net.fake_declared_crawler` path — deferred: an embedded snapshot goes stale and
FPs new real crawler IPs, so it needs an edge-side deploy refresh, which the edge lacks today); Azure Service-Tags
(rotating-URL discovery step). The real-device/GPU/traffic baselines stay operator-gated (adapters built).

### Infra — edge-side CIDR deploy-refresh + DNS-free crawler verification (G7, 2026-06-28)

Built the reusable EDGE-side CIDR deploy-refresh the lab lacked (the detector had `ip_reputation_refresh`; the
edge had no equivalent), and used it to wire the Google/Bing crawler IP-range feeds conviction-grade for G7.

- `edge/internal/fingerprint/crawlercidr.go`: `CrawlerCIDR` loads per-feed prefixes from `KITSUNE_CRAWLER_CIDR_DIR`
  (`google.json`/`bing.json`, the `{"prefixes":[{"ipv4Prefix"|"ipv6Prefix"}]}` shape); `CrawlerVerifier.Verify`
  runs the DNS-free CIDR check first and falls back to FCrDNS when no feed covers the crawler.
- `crawlercidr_refresh.go` + `edge/cmd/crawler-refresh`: fetch both published feeds at deploy, floor-guarded
  (google≥20 / bing≥10) so a URL/format drift fails loud instead of shipping an empty (= everyone-passes) feed.
- Wired into the proxy: the crawler block now calls `crawler.Verify` (CIDR-then-DNS); `NewReverseProxy` loads the
  feeds from the env. Feeds ship EMPTY so out-of-the-box behaviour is unchanged FCrDNS — the staleness FP that
  blocked this earlier is gone because an empty/absent feed ABSTAINS (never convicts on a CIDR miss); only a
  freshly-refreshed feed activates the DNS-free conviction, which Google/Bing's own contract guarantees FP-safe
  (a real crawler is always within the published ranges).

GROUNDED live (resolver nil → proves DNS-free): live feeds parsed (Googlebot 315 prefixes, bingbot 28); real
Googlebot 66.249.66.1 + bingbot 157.55.39.1 → confirmed; 203.0.113.7 (Googlebot UA) + 8.8.8.8 (bingbot UA) →
convicted, zero DNS. Edge suite green; gofmt clean. The mechanism generalizes — any future edge CIDR feed
(e.g. an Azure-Service-Tags discovery, additional crawler feeds) plugs into the same loader+refresh pattern.

### Red uplevel — real OS-level input (XTEST) beats the behavioral layer honestly (G2, 2026-06-28)

The behavioral conviction is STRUCTURAL, not shape-based: `bh.synthetic_no_coalesced` (getCoalescedEvents length)
+ isTrusted come from the hardware input pipeline, which no JS/CDP path produces honestly. The red fleet had only
JS-level humanisation — `HUMAN_MOUSE` (bezier shape via `page.mouse.move` → discrete events), `COALESCE_SPOOF`/
`COALESCE_PROXY` (a JS fabrication of getCoalescedEvents, defeatable by coherence/native-invariant checks), and
`REPLAY_TRACE` (canned, caught by trace_collision). None produces genuine hardware-originated motion.

Built stealth `KS_REAL_INPUT`: drives the cursor via real X-server input (XTEST through `xdotool`, added to the
image; unprivileged under xvfb) along a per-node bezier sent as fine sub-frame bursts (SUB points ~2ms apart,
~13ms between bursts) so the browser coalesces them for real. No `page.mouse`, no JS — the events are genuinely
hardware-originated.

GROUNDED live through the edge (HEADFUL=1 under xvfb): a passive in-page probe measured **92 pointermoves, max
coalesced batch 12, isTrusted=true** — real coalescing, zero JS tamper. The detector graded the **behavioral
layer 0 with NO behavioral contradictions** (`bh.synthetic_no_coalesced`, `bh.click_without_trajectory`, and the
biomech floors all silent). Decisive contrast on the same stack: `HUMAN_MOUSE` (JS bezier via CDP) STILL trips
`bh.synthetic_no_coalesced`; `KS_REAL_INPUT` does not. `KS_NODE_SEED` seeds a per-node distinct trajectory, so a
real-input FLEET spreads (no trace_collision / template_similarity) — the coordination-layer half.

The honest terminus: **given OS-input access, the per-session behavioral layer is a solved red problem** — real
input is structurally indistinguishable from a human's, so the durable signal is coordination / cross-layer
coherence (the thesis), not per-session behavior. The browser KS_REAL_INPUT ran was still caught — but only on
AUTOMATION (naive Playwright: webdriver/CDP) and ENVIRONMENT (headless-container: webgl_software/voices/media)
tells, which are orthogonal axes (the former addressed by the stealth patches, the latter real-GPU/display-bound,
external). Pairing KS_REAL_INPUT with the fingerprint stealth modes leaves only the container-environment frontier.

### Red fleet — KS_REAL_INPUT wired into the fleet manager (2026-06-28)

Wired the behavioral humaniser into the fleet so it composes as a coordinated fleet: registered the `real-input`
evasion (stealth image, KS_REAL_INPUT + HEADFUL), made the stealth image self-wrap xvfb on HEADFUL (so the fleet
manager launches it with a plain docker run — NB exec'ing xvfb-run as PID 1 hangs under Chromium's process tree,
so it stays a child of PID 1), and the plan builders now inject a per-replica `KS_NODE_SEED` so each node draws a
DISTINCT trajectory.

GROUNDED live (2 nodes, seeds 0/1, through the edge): each posted real input (93/95 pointermoves, coalesced ~11,
isTrusted) and the coordination scorer graded the cluster with **trace_collision=None and template_radius=None** —
the real-input fleet's BEHAVIORAL bindings do not fire (distinct seeds → distinct paths → no trace_collision /
template_similarity). The residual conviction was **fp_collision** (the stealth image's shared Chromium
fingerprint), NOT behavior — confirming the axis split: real-input gives behavioral fleet-safety; fingerprint
diversity still needs camoufox (the sybil-farmer). The **maximal in-sandbox evader is therefore camoufox
fp-diversity × real-input behavior** — a fleet that leaks NO pairwise binding (distinct fp, distinct trace,
distinct-enough descriptors, clean behavior), which the pairwise-binding coordination scorer structurally cannot
catch. That is exactly the fleet the population/aggregate detector (axis A, next) must close.

### Blue uplevel — axis A: population/aggregate coordination (the campaign detector) (2026-06-28)

The per-cluster scorer (score_corpus) convicts on a PAIRWISE binding a real cohort cannot produce (cloned fp,
replayed trace, shared origin, reused ticket, template-tight traces). The maximal in-sandbox evader removes every
one — distinct fp/trace per node, descriptors tuned just ABOVE the hard template floor, no shared origin/ticket,
clean residential IPs — and lands as singletons (Part 1's real-input + camoufox fp-diversity fleet). Axis A lifts
the coherence thesis from the session to the COHORT: even with no single hard binding, a coordinated campaign is
correlated IN AGGREGATE across several INDEPENDENT weak dimensions; a real diverse population (even a flash crowd,
tight on build+time only) is not.

`coordination.score_campaigns` builds a multi-dimensional similarity graph over the whole corpus — an edge links
two sessions similar on >= 2 independent soft dimensions (ja4_prefix, descriptor ≤0.15 soft eps, lockstep ≤120s,
shared origin-reputation class, shared prevalence-tail) — finds connected communities, and grades one a `campaign`
when it spans >= 2 origins and is dense (>= half its pairs) on >= 3 INDEPENDENT dimensions (a flash crowd, dense
on ≤2, is only a `candidate`). Posture: CANDIDATE-grade intelligence — the RELATIVE multi-dimensional structure is
groundable in-sandbox; the ABSOLUTE thresholds (an organic population's density) are external-data-bound, so it
surfaces a campaign for operator review, not an auto-conviction.

Red counterpart: Skulk `diffuse-campaign` (the maximal evader — shared build + lockstep + a humanizer tuned just
above the floor, distinct fp/trace/IP, clean IPs). GROUNDED live end-to-end: the per-binding score_corpus graded
it **candidate 0.52** (fp_collision/trace/template all None — no pairwise binding), while axis A
(score_campaigns_live) graded it **campaign 0.84**, dense on ja4_prefix + descriptor + lockstep across 4 origins.
Offline tests pin the FP boundary: a diverse cohort (distinct builds, spread traces, spread arrivals) forms no
community; a flash crowd (shared build + lockstep, real spread traces) is only a `candidate`, not a `campaign`.

This closes the red⇄blue arc of the coordination uplevel: Part 1 built the maximal evader (camoufox fp-diversity ×
real-input behaviour, no pairwise binding); Part 2 built the detector that catches it (aggregate multi-dimensional
density). The residual frontier stays external: to evade axis A too, a fleet must break the AGGREGATE correlation —
genuinely distinct builds (distinct JA4), genuinely distinct hardware fps (out of the prevalence tail), and
non-lockstep organic arrival — i.e. become N independent real users, the economic bind, now proven on both axes.

### Blue — axis A productionized: blocking candidate-gen + windowed streaming (2026-06-28)

Axis A (`score_campaigns`) was O(n^2) all-pairs — fine offline, not at fleet scale. Productionized it without
changing the verdicts:
- **Blocking candidate generation** (`_campaign_candidate_pairs`): two sessions can only form an edge if they
  share >= 2 soft dimensions, and every such pair co-occurs in an EXACT blocking bucket — the JA4 cipher prefix
  or a time window (lockstep, paired across adjacent buckets). So only within-bucket pairs are verified, a
  candidate SUPERSET of the true edges → IDENTICAL campaigns for any cohort that shares a build or arrives
  co-timed (the realistic case + every fixture). Documented blind spot: a pair correlated ONLY on
  rep/prevalence/descriptor with distinct builds AND spread arrivals (caught by the offline exact path). A flood
  bucket over a cap is down-sampled with a LOGGED drop (never silent). GROUNDED: a 5-node campaign buried in 800
  organic sessions (distinct builds, arrivals > 2 windows apart) generates < n candidate pairs (vs n(n-1)/2) and
  is still found — sub-quadratic at scale, identical result.
- **Windowed streaming** (`replay_campaigns`): feeds the corpus in arrival order through a sliding window,
  re-scoring incrementally and emitting a campaign alert the first time each community forms (a growing campaign
  does not re-fire) — the online analog of `replay_stream`, bounding memory + per-step cost. GROUNDED: a lockstep
  campaign emits exactly one alert; an organic stream none.

This makes axis A deploy-grade (the #2 next-step). The remaining axis-A work is external-data-bound: the absolute
organic-density thresholds that would turn `campaign` from candidate-grade into convicting need real traffic.

### Red fleet — Objective work-sharding: driving a coordinated fleet at a goal (2026-06-28)

The task/archetype layer gave every worker the SAME action script (same typed text, same clicks) — unrealistic
and itself a coordination tell. Added an `Objective` abstraction (`objectives.py`): a named goal + a WORK SET
(one dict of fields per item) + a TASK TEMPLATE with `{field}` placeholders. `Objective.compile(n)` round-robin-
shards the work across n workers and fills the template per item, yielding one DISTINCT
:class:`BehavioralTask` per worker. The fleet manager's plan builder takes `objective:` on a node entry and drops
each worker's compiled task into its `KS_TASK` (alongside its distinct `KS_NODE_SEED`), so the fleet pursues one
goal with DISTRIBUTED, non-identical work — cred-stuffer worker i tries credential batch i, etc.

Shipped objectives: `credential-stuffing` and `account-creation` (sharded SYNTHETIC identities — `example.test`,
no real auth — typed into the lab's OWN form; the same allow-list scope the archetype catalog enforces). ETHICS
is explicit in code: these MODEL an adversary's objective against Kitsune's own form/gate to measure whether
coordination detection catches the fleet; no third-party target, no real credential.

GROUNDED: unit tests prove the work set is sharded disjointly + completely and each worker compiles a distinct
filled task (worker 0 → creds[0::n], etc.); plan tests prove the objective node expands to per-worker distinct
`KS_TASK` + seeds covering the whole set. Live: a zendriver worker ran its compiled objective task end-to-end
(typed its shard `user0@example.test`/`user3…`, mode `zendriver-uach-task`, session posted) — the
objective→shard→per-worker-task→execute loop, the existing KS_TASK executor unchanged. harness 365 green.

This completes the coordinated-fleet picture: a fleet that is fingerprint-diverse (camoufox), behaviorally real
(KS_REAL_INPUT), behaviorally diverse (per-node seed), AND productively pursuing a goal with distributed work
(Objective) — the full adversary, against which the coordination scorer + axis A campaign detector are measured.

### Showcase — the coordination red⇄blue escalation ladder, end-to-end (2026-06-28)

`harness/tools/adversary_showcase.py` (task `adversary-showcase`) demonstrates the whole coordination picture in
one reproducible run: it emits four canonical fleet shapes to a live detector and grades each through BOTH
scorers (per-binding `score_corpus` + aggregate `score_campaigns`/axis A). Grounded output:

```
  fleet shape        per-binding (score_corpus)   axis A (score_campaigns)
  cloned             FLEET (fp_collision+auto)    candidate
  trace-replay       FLEET (trace_collision)      candidate
  diffuse-campaign   CANDIDATE (evades)           CAMPAIGN (caught)
  diversified        — (evades)                   — (evades) → the frontier
```

The ladder: pairwise bindings fall first (cloned/replay → FLEET); a build-rotating-but-tuned humanizer evades
them yet axis A catches the aggregate correlation (diffuse-campaign → CAMPAIGN — the axis-A payoff); only a fully
diversified fleet (distinct build/fp/trace, spread descriptors, spread arrivals) evades BOTH.

Confirmed with a REAL evader, not just the synthetic shapes: the assembled fleet — camoufox (per-launch fp
diversity) + a sharded `credential-stuffing` Objective + per-node humanised behaviour, run live (3 nodes) — graded
**per-binding CANDIDATE, axis A no-campaign**: it evades both axes in-sandbox. That is the `diversified` row with a
real adversary, and it is the thesis made concrete: the fully-diversified real fleet is indistinguishable from a
diverse cohort here, so the conviction that closes it is external-data-bound (a real-traffic organic baseline for
axis A's absolute thresholds, real IP reputation, real-hardware fps). To evade both is to be N independent real
users — the economic bind, now demonstrated on both detection axes against a real, goal-driven, diversified fleet.

### Red — reducing correlation / increasing diversity: the lever map + the stagger lever (2026-06-28)

"How do we reduce correlation and increase diversity" → each axis-A dimension has a red lever that breaks it:

| axis-A dimension | lever | in-sandbox |
|---|---|---|
| ja4_prefix | distinct builds/engines per node (Chromium/Firefox/WebKit, version spread, per-node uTLS) | partial (few real engines) |
| descriptor | distinct behavioral MODELS per node — descriptors spread ABOVE the 0.15 soft eps (not one tuned humanizer) | yes (KS_NODE_SEED) |
| lockstep | STAGGER/drip arrivals beyond the 120s window | **now built** |
| origin_reputation | clean residential/mobile egress (no datacenter/proxy/abuse) | external |
| prevalence_tail | real-hardware fingerprints (out of the generated-fp tail) | external |

Each lever removes one dimension; axis A needs >=2 shared dims to form a community and >=3 dense to convict, so
dropping below those is the goal. Built the missing in-sandbox lever — **stagger**: `FleetPlan.stagger_seconds`
delays each node's launch so arrivals SPREAD instead of lockstep (drips the fleet; >120s drops the per-binding
lockstep corroboration AND axis A's lockstep dimension + its time-block candidate generation). Unit-tested
(elapsed >= (n-1)*stagger; all nodes still run).

Measured effect, grounded in the showcase (also hardened: deterministic component-offset descriptors at exactly
d*sqrt(2) instead of boundary-jittered, and grading isolated to the shape's own sessions so it is store-state-
independent): adding a `diffuse-staggered` row — identical to diffuse-campaign but spread in time —

```
  diffuse-campaign    per-binding CANDIDATE   axis A CAMPAIGN     (ja4 + descriptor + lockstep)
  diffuse-staggered   per-binding CANDIDATE   axis A CANDIDATE    (stagger drops lockstep -> 2 dims)
  diversified         per-binding —           axis A —            (distinct builds too -> evades both)
```

So the stagger lever alone downgrades CAMPAIGN -> CANDIDATE; stacking distinct-builds + spread-descriptors on top
reaches the `diversified` evades-both frontier. The maximal in-sandbox diversification (stagger + distinct builds
+ distinct behaviour) evades both axes; the LAST two levers (clean residential egress, real-hardware fps) are
external-data-bound — i.e. fully reducing correlation = becoming N independent real users, the economic bind.

- **[COORDINATION LOOP — rung 1: descriptor-dispersion is a GROUNDED DEAD-END] (2026-07-03).** The `fuzzy` fleet
  (jitters fp+trace per instance, descriptors tuned just above the template floor) evades template_similarity's
  MEDIAN test and scores `candidate`. Hypothesised blue counter: a cohort DISPERSION signal — the SPREAD (std, or
  coefficient of variation) of pairwise descriptor distances, which should be implausibly narrow for a one-model
  cluster vs wide for diverse humans, and is baseline-free (calibrated on the SapiMouse human distribution, no
  absolute traffic baseline). GROUNDED it before building: a one-humanizer fleet with enough jitter to clear the
  0.10 floor (j≈9-12) reaches median 0.17-0.18 AND CV 0.54-0.61 — both OVERLAPPING distinct-human cohorts (median
  0.17-0.25, CV 0.29-0.64). No clean separator: pushing jitter to spread the descriptors past the floor also
  spreads the dispersion into the human range. So the descriptor-structure approach to the fuzzy frontier is DEAD
  in-sandbox — confirming (not refuting) the map's verdict that a fully-diversified fleet's conviction is
  external-data-bound (IP reputation). The discipline worked: grounded the hypothesis, it failed, shipped nothing.
  Next rungs to test (NOT descriptor dispersion): new Axis-A soft dimensions that need no absolute baseline;
  within-cohort structure a one-tool fleet can't shed without becoming genuinely N-independent.
- **[COORDINATION LOOP — rung 2: SCHEDULED-STAGGER regularity — a NEW baseline-free Axis-A timing dim (SHIPPED)]
  (2026-07-03).** The diffuse-staggered fleet shares ja4 + descriptor (2 pairwise dims) but defeats the LOCKSTEP
  co-arrival dim by spreading in time -> only a `candidate`. GROUNDED: a cohort's inter-arrival coefficient of
  variation cleanly separates a SCHEDULED fleet (regular gaps, CV 0.08-0.15) from independent users (a Poisson
  process, exponential gaps, CV 0.5-1.16) — and it is BASELINE-FREE because CV=1 is INTRINSIC to independent
  arrivals, not a population statistic. Built `_arrival_regularity` + wired it into score_campaigns as the
  `scheduled` timing signal: when a community is NOT lockstep-dense but its arrivals are regular (CV <= 0.35, >= 5
  members), the TIMING layer counts ONCE (no double-count) -> the scheduled-stagger fleet reaches 3 independent
  dims (ja4 + descriptor + scheduled) -> `campaign`. FP-SAFE by construction: `scheduled` only UPGRADES a
  community that already formed on 2 PAIRWISE dims (ja4 + a clustered-descriptor humanizer) — a legit regular
  cohort (scheduled corporate sync) has diverse HUMAN descriptors, so the descriptor dim denies it and no
  2-pairwise-dim community even forms. GROUNDED LIVE: new test_axis_a_scheduled_stagger_caught (staggered every
  300s -> campaign via `scheduled`, lockstep silent) convicts; test_axis_a_regular_legit_cohort_not_a_campaign
  (regular + human traces) stays clean; coordination precision==1.0 preserved (370 harness tests green). Residual:
  a Poisson-STAGGERED fleet (random gaps, CV~1) still evades — but then its timing IS indistinguishable from
  independent users, the genuine external wall. SECONDARY grounded-negative this rung: CLOCK-SKEW COLLISION (a
  co-hosted fleet sharing one OS clock's TCP-timestamp skew across proxied IPs) is a genuinely NEW binding idea,
  distinct from the rejected G24 clock-COHERENCE (which needed a skew DISTRIBUTION) — but un-groundable in-sandbox:
  the edge captures no TCP timestamps, and every sandbox session shares the ONE sandbox clock, so distinct-host
  skews cannot be produced to test it; FP-safety of a continuous fuzzy-match also needs real-traffic precision
  calibration. External-data-bound.
- **[COORDINATION LOOP — rung 3: RED-verify the scheduled dim + ground the evasion boundary (SHIPPED)]
  (2026-07-03).** Completed rung 2's red<->blue. RED: added the Skulk `diffuse-scheduled` strategy — a diffuse
  fleet (no pairwise binding, distinct fp/trace/IP, one build, clean) whose members carry REGULAR `offset_seconds`
  (300s cadence past the 120s lockstep window). GROUNDED it produces the scheduled shape (constant gaps, 6 distinct
  fp/trace, one ja4) and that axis A now flags it `campaign` via the `scheduled` timing dim. BOUNDARY: added
  test_axis_a_poisson_stagger_evades — the SAME diffuse fleet with POISSON-random gaps (exponential inter-arrivals,
  CV~1) correctly stays a 2-dim `candidate`, because its timing IS statistically that of N independent users. So
  the scheduled-stagger rung is precisely bounded: it convicts a fixed-schedule fleet, and the residual (a
  Poisson-randomised stagger) is the GENUINE external wall — a fleet whose arrival process is indistinguishable
  from independent users cannot be convicted on timing, which is the economic bind (full timing-diversification =
  actually being N independent users). Fleet + harness suites green (24 + 371), coordination precision==1.0
  preserved, README strategy table updated. The scheduled/Poisson pair is now the crisp red<->blue frontier line on
  the timing axis.
- **[COORDINATION LOOP — rung 4: uniform-stagger regularity generalization is a GROUNDED DEAD-END] (2026-07-03).**
  Tried to broaden the timing catch beyond fixed schedules to a UNIFORM/mild stagger (the jitter a naive scheduler
  adds), using a cohort-size-scaled CV ceiling ``1 - C/sqrt(n)`` calibrated below the bootstrapped Poisson CV
  1st-percentile (which rises with n: 0.24@6, 0.58@20, 0.70@40, 0.78@80). GROUNDED before shipping: a uniform
  stagger's EMPIRICAL inter-arrival CV is ~0.58-0.67 at n=40 — which sits BETWEEN an FP-safe ceiling (0.60) and the
  Poisson p1 (0.70), so the margin to catch it while staying below the Poisson tail is razor-thin and fragile
  (uniform and Poisson-lower-tail OVERLAP). Only a NEAR-PERFECT schedule (CV ~ 0.20, rung 2) is cleanly separable
  from independent arrivals; a merely-uniform stagger is not. REVERTED the generalization, kept rung 2's clean
  fixed 0.35 threshold. Shipped only a regression test (test_axis_a_poisson_stagger_evades_at_scale) documenting
  that the wall holds at scale. A distributional test (gap SKEWNESS: exponential ~2 vs uniform ~0, or a KS-fit)
  MIGHT separate uniform from Poisson better than CV, but it needs a 3rd moment (noisy) for a marginal payoff
  (catches only naive uniform-staggerers; a true Poisson evader wins either way) — noted, not pursued. This is the
  coordination axis's first DRY firing after two shipped rungs: the timing axis's groundable win is the
  regular-schedule catch, and the residual (any stagger whose arrival process approaches Poisson) is the genuine
  external wall.
- **[COORDINATION LOOP — rung 5: axis-A corroboration on per-session bot tells (SHIPPED)]** (2026-07-03). A
  DIFFERENT angle after the timing axis: score_campaigns had NO corroboration — it only counted soft dims, so a
  diffuse fleet at exactly 2 dims (ja4 + descriptor, Poisson timing) stayed a `candidate` even when a member
  carried a per-session automation tell, AND axis B also capped it at candidate (no convicting fp/trace/ticket
  binding to reach 0.60 — the tell there is only a corroborator). So a Poisson-staggered diffuse fleet WITH a
  browser-automation slip evaded BOTH axes. GROUNDED the gap live (2-dim + webdriver -> axis A `candidate`, axis B
  no fleet-binding), then wired the axis-A analog of score_cluster's conviction gate: a 2-dim community lifts to
  `campaign` when `_has_automation_tell` (webdriver/CDP/headless/injection) OR `_has_known_automation_ja4` (curl/Go/
  Python non-browser stack) fires — an INDEPENDENT browser-automation layer, baseline-free (in-sandbox bot signals,
  explicitly NOT IP reputation). FP-SAFE by construction: a legit cohort never BOTH forms a 2-dim community (human
  descriptors spread past the eps; distinct real builds shed ja4) AND carries an automation tell / tool JA4.
  GROUNDED LIVE: test_axis_a_two_dim_candidate_with_automation_tell_convicts (2-dim + webdriver -> campaign via the
  new `automation` dim); test_axis_a_clean_two_dim_fleet_stays_candidate (the SAME fleet clean stays candidate —
  the frontier holds); full harness green (374), coordination precision==1.0 preserved. This convicts a coordinated
  BOT campaign (the members are per-session-flagged bots; the rung upgrades the COHORT verdict from N-independent-
  bots to one campaign — attribution), NOT the fully-clean real-browser frontier fleet, which stays the external
  wall. Two shipped rungs (2, 5) + one red-verify (3) + two dead-ends (1, 4) — the loop is NOT dry: rung 5 found a
  real groundable gap on a non-timing angle.
- **[COORDINATION LOOP — rung 6: red-verify rung 5, grounded END-TO-END LIVE (SHIPPED)]** (2026-07-03). Added the
  Skulk `diffuse-automated` strategy — the sloppy-but-diversified bot: a diffuse fleet (distinct fp/trace/IP, one
  build) POISSON-staggered (only 2 soft dims — evades lockstep AND the scheduled tell) that LEAKS a per-session
  automation tell (webdriver). This is the red counterpart to rung 5's corroboration. GROUNDED FULLY LIVE for the
  first time on the coordination axis: `skulk run diffuse-automated` -> POST to the live detector's /ingest -> the
  detector correlated 6 sessions (shared ja4 confirmed, webdriver tell on all, 6 distinct staggered first_seen —
  the Poisson offsets flowed through as the runner stamps observed_at=base+offset and the detector sets
  first_seen=min(timestamps)) -> `score_campaigns_live` returned `campaign | [ja4_prefix, descriptor, automation]`
  over the 6 members. So the rung-5 `automation` dim does the work on the REAL wire path, not just a constructed
  corpus. RED<->BLUE line: `diffuse-automated` -> campaign (the slip converts it); a fully-clean diffuse fleet
  (no tell) -> candidate (the real-browser frontier holds). Fleet suite green (25), test_skulk asserts the shape,
  README strategy table updated. NOTE the plumbing win: skulk is pure-stdlib so it emits via PYTHONPATH in a bare
  network container; the harness score needs its venv (uv sync in-container). The end-to-end path (Skulk -> edge/
  detector -> live_coordination scorer) is now exercised, not just the offline scorer.
