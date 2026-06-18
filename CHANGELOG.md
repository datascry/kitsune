# Changelog

All notable changes to Kitsune are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Releases are cut automatically from
[Conventional Commits](https://www.conventionalcommits.org/) via release-please.

## [Unreleased]

### Added

- **Canvas-farbling detection + Brave evaluated** (ruleset 0.26.0) — `br.canvas_noise` covers the last
  anti-fingerprinting *philosophy* (farbling: per-session canvas/audio noise). It is **reference-free**:
  fill a canvas with a solid colour and read it back — a real browser returns the exact colour, a
  farbling browser perturbs pixels. Validated live by building a **Brave** evader (the last major
  browser): Brave trips `canvas_noise` (its canvas farbling), while stealth/camoufox read the fill back
  exactly (no false positive). `audio_noise` does not fire on Brave — its audio farbling is per-session
  *deterministic*, so the canvas invariant is what exposes it. Weight 0.5 (`suspicious`): a human on Brave
  is a privacy-tool signal (elevated risk), not a bot conviction. **All five evasion philosophies are now
  covered with validated detections** (coherent-spoof, CDP-stealth, scripted/no-JS, RFP, farbling).
- **resistFingerprinting (Tor/Mullvad) detection** (ruleset 0.25.0) — `br.rfp_browser`, covering the last
  anti-fingerprinting *philosophy* (RFP evades by making all users identical, the opposite of Camoufox's
  coherent uniqueness). From the Tor design doc: RFP forces UTC, letterboxes the window to 200×100
  multiples, and clamps `hardwareConcurrency` to 2. Each trait alone is common (a UK user, a round window,
  a 2-core VM), so the collector requires the **conjunction** — confirmed no false positive on real
  evaders (their windows aren't letterboxed). Calibrated as `suspicious` (weight 0.4), *not* a `bot`
  conviction: RFP identifies a privacy browser = elevated risk, and Tor users are often human — it
  corroborates with automation/coordination rather than convicting alone.
- **undetected-chromedriver evaluated** — the most popular anti-detect tool (only its successor nodriver
  had been tested). **Finding:** UC has evolved to defeat the SOTA `Runtime.enable` leak
  (`cdp_runtime_enabled` does not fire) and patches `navigator.webdriver` — so the *entire* popular tool
  ecosystem (UC, nodriver, patchright, rebrowser) has converged on closing the CDP-automation tells; only
  naive plain Playwright still trips `Runtime.enable` (3 corpus evaders). UC's profile mirrors nodriver
  exactly (`automation:2`, `environment:3`) and it stays `bot` 0.999 on the headless-environment floor
  (`webgl_software`, `voices_empty`, `media_devices_empty`, `headless_ua`, `chrome_runtime_missing`).
  New `undetected` evader + corpus session.
- **HTTP-layer Sec-Fetch coherence** (ruleset 0.24.0) — `net.sec_fetch_vs_ua`: every modern browser sends
  `Sec-Fetch-Site`/`Sec-Fetch-Mode` on requests, but a scripted HTTP client faking a browser UA over
  httpx/curl (the volumetric-DDoS case) omits them. The edge emits `network.sec_fetch_missing` when a
  browser-claiming UA lacks the headers — a tell on the *HTTP* layer, independent of TLS and JS. Added a
  `KS_UA` mode to the vanilla evader to validate: vanilla faking a Chrome UA now scores `bot` on *both*
  `net.no_js_execution` and `net.sec_fetch_vs_ua`; real Chromium (which sends Sec-Fetch) does not trip it.
- **Engine error-message coherence** (ruleset 0.24.0) — `br.error_engine_vs_ua`, the deepest engine tell.
  V8/SpiderMonkey/JSC produce distinct `TypeError` messages for the same fault (V8 "Cannot read
  properties of…", SpiderMonkey "can't access property…", JSC "… is not an object"). The engine's *own
  message generator* is far harder to spoof than `navigator.vendor` or `Error.captureStackTrace`.
  **Validated:** fires on `spoof-ua` (V8 engine + Firefox UA) but not on `stealth-naive` (V8 + Chrome UA)
  or `camoufox` (real SpiderMonkey + Firefox UA) — engine-spoofers caught, real browsers cleared.
- **WebGPU coherence** (ruleset 0.23.0) — `br.webgpu_webgl_vs`, the emerging GPU fingerprint vector
  (2024-25). Explored reality-first: headless Chromium has `navigator.gpu` but no adapter; Firefox/Camoufox
  lack WebGPU entirely — both too common to flag alone. The clean tell is cross-vector: a WebGL renderer
  claiming a *hardware* GPU while WebGPU exposes *no real adapter* means the renderer was spoofed (a real
  GPU drives both). **Validated:** fires on `full-stealth` (fakes its WebGL renderer to "NVIDIA RTX 3060"
  while headless) but not on `stealth-naive` (honest SwiftShader) or VM/VDI (honest software WebGL) — it
  catches the spoof below the WebGL layer with no false positive. Its headful counterpart
  `br.webgpu_vendor_vs_webgl` covers the real-hardware case: a real GPU's WebGPU adapter family must match
  the WebGL renderer, so a faked renderer on real hardware is exposed by the WebGPU vendor — the detection
  for the frontier headful-real-hardware spoofer (unit-tested; needs a GPU-equipped target to fire live).
- **Scripted / non-browser client detection** (ruleset 0.22.0) — `net.no_js_execution`: a session with a
  network/TLS fingerprint but an *empty browser layer* loaded the challenge page yet never executed the JS
  collector — a scripted HTTP client (httpx/curl), the volumetric-DDoS majority. Emitted as a score-time
  derived cross-layer signal (`network.browser_absent`, not persisted), so the registry rule and the
  incoherence amplifier handle it like any other tell. **Closes the last recall gap:** `vanilla` (httpx),
  which previously scored `human`, now scores `bot` 0.90. Humans are unaffected (they have a browser
  layer) — every evader is now `bot`, every human `human`.
- **Deep engine-API coherence** (ruleset 0.21.0) — `br.engine_stack_vs_ua`: `Error.captureStackTrace` is
  a V8 (Chromium) API absent in Firefox/Safari, so a UA claiming Chrome without it — or Firefox *with* it
  — is an engine spoof deeper than `navigator.vendor` (which JS-stealth patches, while the `Error` API it
  often misses). **Validated both ways:** fires on `spoof-ua` (Chromium engine + Firefox UA), does not
  trip real Chromium or Firefox. Near-zero false positives.
- **Timezone-consistency detection** (ruleset 0.21.0) — `br.timezone_inconsistent` (CreepJS "timezone
  lie"): a real browser derives both the IANA `timeZone` and the numeric `getTimezoneOffset()` from the
  OS, so they always agree; a spoof that sets one but not the other (or forces UTC over a real offset) is
  self-inconsistent. A coherence tell with near-zero false-positive surface — confirmed live that real
  browser engines (Camoufox, Playwright Chromium) do not trip it. Catches naive timezone spoofers.
- **Precision suite — legitimate humans must not be flagged** (`tests/test_precision.py`). A panel of
  fully-coherent human profiles (Win/Mac/Linux × Chrome/Firefox, plus a touch laptop and an
  external-monitor Mac) must all score `human`. It surfaced two real false positives that recall testing
  never would.

### Changed

- **False-positive mitigations** (from the precision suite). Retired `br.maxtouch_desktop` — it flagged
  ordinary Windows 2-in-1 touch laptops, and the sound `br.pointer_touch_incoherent` (CSS-vs-JS touch
  disagreement) supersedes it. Cut `br.macos_dpr1` 0.4 → 0.3 (desktop Mac on a 1080p external monitor) and
  `br.webgl_software` 0.6 → 0.3 (corporate VM/VDI software rendering) below the suspicious threshold, so
  neither flags a human alone — both now only corroborate inside a cluster of tells. The emergent rule:
  *environment tells must corroborate, not convict* (each has an innocent lone explanation; the combination
  is decisive). Recall unaffected — every evader still scores `bot` (Camoufox 0.99, all chromium 1.00).

### Added (continued)

- **Online coordination detector (`FleetTracker`).** Streaming fleet detection: `observe(name, session)`
  ingests sessions one at a time (arrival order), re-scores only the affected JA4-prefix cluster, and
  returns a verdict exactly when a cluster *newly* crosses the `fleet` threshold or escalates severity —
  edge-triggered, alerting once rather than on every confirming member. This is how a production bots/DDoS
  detector works (incremental clustering + threshold alerting) versus the offline `score_corpus` snapshot.
  `replay_stream` / `render_stream` (and `--stream`) replay a corpus in `first_seen` order; on the
  residential-proxy fleet it alerts on the second arrival — the instant the paradox is observable.
- **Sliding-window aging** (`FleetTracker(window_seconds=W)`) — count only cluster members within `W`
  seconds of the latest arrival, ageing out the rest: detect a *burst*, not slow accumulation of unrelated
  same-browser users into a false fleet. Two paradox nodes 10s apart alert; the same two 10 minutes apart
  never coexist and do not. State resets when a burst ages out, so a fresh burst re-alerts. 100% covered.
- **Fleet threat-severity (DDoS triage).** The coordination verdict now reports `request_volume`,
  `arrival_rate_per_min`, and a `severity` tier (`moderate`/`high`/`critical`) derived from scale and
  rate — *separate* from the confidence `score` (a confirmed fleet maxes the score whether it is 3 nodes
  or 3,000; severity distinguishes a curiosity from an active attack). Surfaced in the rendered report.
- **Residential-proxy fleet detection (coordination, the bots/DDoS frontier).** Two IP-topology signals
  in `harness/coordination.py`: (1) *residential-proxy pattern* — a confirmed spoofing fleet (JS paradox
  or JA4_c divergence) also spread across many distinct `observed_ip` values, so the IP diversity that
  defeats per-IP/ASN rules instead reveals a distributed botnet; (2) *same-origin behind proxies* —
  diverse proxy IPs but one shared `webrtc_public_ip`, cross-linking the WebRTC signal with the fleet
  view. A synthetic residential-proxy Camoufox fleet (distinct exit IPs, one real origin) scores `fleet`
  1.00 on all six coordination signals (`docs/coordination-proxy.md`). 100% covered.
- **Keystroke-dynamics capture — last dead rule closed.** A signal-emission audit found one rule whose
  signal the collector never produced: `bh.keystroke_entropy_floor` (read `behavioral.keystroke_entropy`).
  The collector now captures keydown timing and emits the normalized inter-key interval entropy, and the
  stealth evader types a phrase to exercise it. **Result:** unlike the mouse thresholds, this one bites —
  naive fixed-delay typing collapses to ~0 entropy and **fires** (`stealth-naive` `behavioral:1`), while
  variable human-like timing (0.975 vs the 0.15 floor) evades. **Every rule's signal is now emittable —
  zero dead rules.**
- **Max-stealth chromium evader (`MAX_STEALTH=1`)** — the kitchen sink (patchright + a coherent
  Linux-Chrome UA + human-mouse motion), the chromium analog of `camoufox-hardened`. Every evasion layer
  works (UA removes `headless_ua`, human-mouse zeroes behavioral, patchright closes `Runtime.enable` +
  `webdriver`), yet it is still `bot` on the environment floor (`automation:4` + `environment:6`). The
  capstone: maximal stealth on *both* engines converges on the headless environment as the irreducible
  floor, with coordination beneath it — documented in `docs/findings.md`.
- **HTTP/2 fingerprint core** (`edge/internal/fingerprint/h2.go`) — the Akamai-style h2 fingerprint
  (`SETTINGS | WINDOW_UPDATE | PRIORITY | pseudo-header-order`) plus an engine classifier keyed on the
  version-stable pseudo-header order (Chromium `m,a,s,p`, Firefox `m,p,a,s`, Safari `m,s,p,a`), and a
  `signal.FromH2` emitter for `h2` + `h2_browser_hint`. Go unit-tested with documented real-browser
  fingerprints. The detector's `net.h2_vs_ua_browser` / `net.h2_vs_tls_browser` coherence rules already
  consume `h2_browser_hint`, so the detection is ready; live capture needs the edge to sniff H2 frames
  post-TLS (a multi-turn change — H2 is currently disabled on the edge so the ClientHello ConnContext
  reaches handlers). This lands the tested fingerprint core ahead of that wiring.
- **Human-mouse behavioral evader (`HUMAN_MOUSE=1`)** — synthesizes realistic motion (Bézier curve,
  ease-in-out velocity, micro-jitter, variable inter-event timing) to red-team the behavioral layer.
  Finding: the motion thresholds (`path_too_straight`, `uniform_velocity`, `input_entropy_floor`) catch
  only *degenerate* input — even the naive sine-wave path already clears them; the human generator clears
  them wider (entropy 0.87, straightness 0.29, velocity CV 1.01). Behavioral is trivially evaded and is
  the first layer to fall — the `human-mouse` evader zeroes the behavioral column yet is still `bot` on
  automation + environment. Reinforces that the durable signals are environment and coordination.
- **nodriver re-evaluated against the full ruleset** — its "minimal CDP footprint" claim **holds against
  the SOTA detection**: it trips neither `cdp_runtime_enabled` (`Runtime.enable`) nor `webdriver`
  (`automation:2`, the lowest of all CDP tools), yet is still `bot` on the environment floor plus a
  `HeadlessChrome` UA and missing `window.chrome.runtime`. Completes the CDP-tool gradient
  (plain 6 → rebrowser 5 → patchright 4 → nodriver 2 automation tells).

### Fixed

- **Collector timing regression** — the v0.19 WebRTC probe (1500ms) plus the audio/enumerate probes had
  pushed the collector's send past short fixed-wait evaders (nodriver's 3s), yielding empty captures. Cut
  the WebRTC gather window to 700ms (local candidates arrive in ~200ms; STUN does not resolve in the lab
  anyway) and gave nodriver a 4s margin. Camoufox's `webrtc_unavailable` is unaffected (it blocks WebRTC
  outright, so no candidates regardless of the window).

### Added (continued)

- **Cross-layer network-identity rule** (ruleset 0.20.0) — `net.webrtc_ip_vs_observed`: the edge now emits
  the observed connection IP (`network.observed_ip`), and the rule fires when it disagrees with the
  WebRTC STUN public IP the collector reported (`browser.webrtc_public_ip`) — the canonical proxied-bot
  tell (HTTP via a residential proxy, real IP leaked over WebRTC), central to bots/DDoS. This is the first
  rule correlating a signal the *edge* observed at the network layer with one the *browser* reported — the
  cross-layer thesis in its purest form. Needs a real proxy scenario to trigger live; unit-tested both
  ways (fires on mismatch, not on a direct connection). Edge change covered by Go tests.
- **Hardened-Camoufox evader (`KS_HARDENED=1`)** — red-teams the detector with its own findings: applies
  Camoufox config (`os="windows"` to drop the macOS-only tells, `block_webrtc=False`) to fix the
  spoof-specific tells Kitsune discovered, and measures what survives. Result: hardening cuts Camoufox's
  spoof-specific catches from three to one (Windows pin removes `macos_dpr1` + `font_mac_internal`), but
  it stays `bot` 0.93. Two tells are **not config-fixable**: `webgl_renderer_artifact` (every renderer in
  Camoufox's `webgl_data.db` carries the `", or similar"` suffix — baked into the shipped data) and
  `webrtc_unavailable` (`block_webrtc=False` did not restore it). New `camoufox-hardened` corpus session.
- **WebRTC ICE probe** (ruleset 0.19.0) — the missing network-identity vector (central to bots/DDoS).
  `br.webrtc_unavailable` (artifact): a real browser always gathers ICE candidates; **Camoufox disables
  WebRTC** to prevent the IP leak — confirmed live, it fires on Camoufox but NOT on stock headless Firefox
  (which keeps WebRTC in the same container), so it is a spoof tell, not a headless one, and it survives a
  headful deployment. A macOS-draw Camoufox now has three spoof-specific catches (`macos_dpr1` +
  `font_mac_internal` + `webrtc_unavailable`) independent of the environment floor. The STUN-reflexive
  public IP (`webrtc_public_ip`) is also collected, for future cross-layer correlation against the request
  IP (the proxied-bot tell) — leaving the evader a no-win: keep WebRTC and leak the real IP, or disable it
  and trip this rule.
- **`rebrowser-patches` evaluated** — added a `REBROWSER=1` mode to the stealth evader
  (`rebrowser-playwright@1.48.2`). Result: it closes exactly the `Runtime.enable` leak (so
  `br.cdp_runtime_enabled` correctly does not fire — validating both the rule and rebrowser's claim) but
  leaves `webdriver` / headless-UA / `window.chrome` unpatched. The three CDP tools now form a measured
  gradient of automation-tell coverage (plain 6 → rebrowser 5 → patchright 4), all still `bot` on the
  headless `environment` floor. New `rebrowser` corpus session and `docs/findings.md` comparison.
- **`Runtime.enable` CDP-leak detection wired** — the `br.cdp_runtime_enabled` rule existed but the
  collector never emitted its signal (a gap). Implemented the detection (log an `Error` with a `stack`
  getter that fires only when a CDP client serializes it — the current #1 headless-Chromium tell, 2024-25
  research). Validated: plain Playwright (`stealth-naive`) fires it; `patchright` (which patches
  `Runtime.enable`) does not — the detector now *quantifies* patchright's CDP patches (`automation:6` vs
  `4`), though both remain caught by the headless `environment` tells. Fixed the `stealth`/`patchright`
  evader image (unpinned patchright pulled a Chromium-revision mismatch; now installs the matching browser).
- **Codec-support coherence** (ruleset 0.18.0, experimental) — `br.codec_os_incoherent`: from the
  Camoufox cast map, `audioCodecs`/`videoCodecs` are unspoofed, so a non-Linux UA that cannot play
  proprietary H.264/AAC (codecs a real Windows/macOS has via the OS) would betray the real container.
  **Did not fire** on this Camoufox — the Playwright base image bundles the codecs, so its support is
  coherent. Kept as coverage of a known detection class (catches a codec-less Linux deployment).
- **Font construction-artifact detection** (ruleset 0.17.0) — from Camoufox's `fonts.json` (its fixed
  per-OS font lists). `br.font_mac_internal` (artifact): Camoufox bundles 49 dot-prefixed macOS system
  fonts (`.Aqua Kana`, …) and exposes them to `measureText`, which a real Mac never does — **confirmed
  live** on its macOS draws; works headful (no display needed). With `macos_dpr1` a macOS-draw Camoufox
  now has two spoof-specific catches independent of the headless-environment tells (`bot` 0.976).
  `br.font_linux_leak` (coherence, experimental): Arimo/Cousine/Tinos under a non-Linux UA — did not fire
  (Camoufox's font spoofing is complete) but still catches naive non-font-spoofing tools.
- **Detection-class taxonomy + no-spoof baseline control.** Added a `category` to every rule (and to each
  verdict `Contradiction`): `coherence` / `artifact` (genuine anti-detect catches) vs `environment` /
  `automation` / `behavioral` / `reputation`. Validated it against a **control group** — stock Playwright
  Firefox (`KS_BASELINE=1`, Camoufox's engine with no spoofing) through the same pipeline: it fires only
  `automation` + `environment` tells (zero coherence), proving those are headless-environment signals, not
  spoofing detection. Camoufox additionally trips `coherence`/`artifact` tells — the real catches. New
  `report.render_categories` view (in `docs/matrix.md`), `camoufox`/`baseline-firefox` corpus sessions,
  and a `docs/findings.md` section. Contracts (`coherence-rule`, `verdict`) gain the optional `category`.
- **More white-box, source-driven detection** (ruleset 0.16.0) — continuing to read the `camoufox`
  source. `br.macos_dpr1`: Camoufox pins `devicePixelRatio` to 1.0 (its cast map: "any value other than
  1.0 is suspicious") but a modern Mac is Retina (dPR 2) — **confirmed live**, fires on exactly the
  launches where Camoufox draws macOS, not Windows. `br.adblock_present` (experimental): Camoufox bundles
  uBlock Origin as a default addon (`addons.py`/`utils.py`), detected via an ad-bait element — weak alone
  (humans run adblockers) and not validated in our short sessions, but a documented default.
- **White-box, source-driven detection** (ruleset 0.15.0) — read the open-source `camoufox` package to
  drive detections precisely instead of black-box probing. From `browserforge.yml` (its spoof cast map):
  `multimediaDevices` is unsupported → `br.media_devices_empty` (enumerateDevices() empty in a container;
  a real desktop always has a default audio endpoint) — **fires on both headless and headful Camoufox**,
  raising them to `bot` 0.86 / 0.955. From the same source: Camoufox does not farble audio, so
  `br.audio_noise` (per-render AudioContext perturbation) is reserved for farbling browsers; `br.audio_missing`
  flags a stripped audio stack. Confirmed `webgl_data.db` stores every renderer with a `", or similar"`
  suffix, so `br.webgl_renderer_artifact` catches every Camoufox WebGL fingerprint by construction.
- **Headful Camoufox evaluation + renderer-artifact counter** (ruleset 0.14.0) — added a headful mode to
  the Camoufox evader (`KS_HEADFUL=1` → virtual Xvfb display) to test whether the per-session capability
  tells are real spoofing flaws or headless-container artifacts. **Finding:** headful Camoufox gains a
  software WebGL2 context (so `webgl2_missing` closes — it *was* a headless artifact) but its spoofed
  renderer string is the placeholder `"Intel(R) HD Graphics 400, or similar"`. New rule
  `br.webgl_renderer_artifact` catches that implementation flaw in Camoufox's own WebGL spoofer; headful
  Camoufox is caught at `bot` 0.90 (renderer artifact + `voices_empty`, which persists headful). New
  tracked corpus session `camoufox-headful`.
- **Speech-synthesis voice coherence** (ruleset 0.13.0) — `br.voices_empty` (no TTS voices: a headless
  container has no speech stack, a real desktop ships OS voices) and `br.voice_os_vs_ua` (voice set
  implies an OS contradicting the UA platform). **Result:** cracks a single coherent Camoufox instance —
  it returns zero voices, so combined with `webgl2_missing` the per-session verdict rises from
  `suspicious` 0.40 to **`bot` 0.70**. The engine-level spoof that once evaded every per-session rule is
  now caught per-session, via OS *capabilities* (GPU, TTS) a container cannot fake.
- **Cross-API device/media coherence** (ruleset 0.12.0) — five CreepJS/fingerprintjs rules comparing the
  CSS `matchMedia` view of the device against the JS-API view: `br.screen_avail_invalid`,
  `br.color_depth_anomaly`, `br.devicepixelratio_anomaly`, `br.hover_none_desktop`,
  `br.pointer_touch_incoherent`. Catch tools that patch one surface but not both. **Finding:** Camoufox
  keeps both views coherent, so it is not caught by these (documented in `docs/findings.md`).
- **JA4_c coordination signal** — the fleet detector now keys on the JA4 *cipher-suite prefix* (JA4_a +
  JA4_b) and grades **JA4_c (extensions/sig-alg) divergence** as a coordination tell. **Finding:**
  Camoufox randomizes JA4_c per launch, so the full JA4 is not fleet-stable — but since JA4 sorts
  extensions to defeat order-shuffling, a varying JA4_c betrays per-launch TLS manipulation. The live
  Camoufox fleet is now caught (`fleet`) via JA4_c divergence even when its JS traits collide by chance.
- **Faster single-Camoufox capture** — `KS_FAST=1` (event-driven, behavioral layer omitted so skipped
  input isn't mis-scored) and `KS_REPEAT=N` (N captures from one browser launch, amortizing the ~10s
  cold-start). The corpus fast-rescore (~0.3s, no browser) remains the path for rule-only changes.

### Fixed

- **CI lint enforcement** — the `harness` CI job was missing `ruff format --check` (the `detector` job
  had it), so harness format drift went uncaught; added it. Bumped both Python components' ruff
  `line-length` to 120 (matching the established style, incl. the mandated 2-line headers) and brought
  detector + harness fully green on `ruff check`, `ruff format`, and `mypy`. demo.py (embedded JS/HTML
  template) carries a scoped `E501` per-file-ignore.

### Added (continued)

- **Coordination scoring** (`harness/coordination.py`) — grades a JA4 cluster into a graded fleet
  verdict (`fleet`/`candidate`/`benign`) on three independent signals: the **TLS-identical-but-JS-
  divergent paradox** (a real same-build cohort shares its JS identity too, but an anti-detect fleet
  randomizes JS per instance while sharing one TLS handshake), **timing lockstep** (members arriving
  within a 2-minute window are synchronized, unlike organic same-JA4 users), and **volume**. Live
  Camoufox fleet scores `fleet` 1.00. 100% covered.
- **Frontier runner** (`scripts/frontier.sh`) — fast, frontier-only loop that exercises *only* the
  evaders that still beat per-session detection (Camoufox single + a Camoufox fleet), instead of
  re-detecting the known-caught fleet every iteration. The full sweep (`live_scoreboard.sh`) becomes
  the sparse regression tier.

- **Font-OS fingerprint** (`br.font_os_vs_ua`, ruleset 0.11.0) — the collector classifies the host OS
  from OS-signature font availability (Segoe UI/Calibri → Windows, Menlo → macOS, DejaVu → Linux) and
  flags it against the claimed UA platform. Catches chromium tools that spoof the UA but not the host
  font stack. **Finding:** Camoufox spoofs Canvas font metrics at the engine level, so it defeats this
  probe (the measured font OS coherently matches its claimed OS) — documented in `docs/findings.md`.
- **`docs/findings.md`** — empirical arms-race ladder: what each anti-detect tool leaks, why Camoufox is
  the per-session frontier, and why coordination is the durable bots/DDoS signal.

### Changed

- **Frontier crack** — `br.webgl2_missing` (v0.10.0) now flags live single-instance Camoufox
  (`suspicious` 0.40): headless Camoufox exposes no WebGL2 context where real Firefox does. The
  engine-level anti-detect browser that previously evaded all per-session rules now leaks one.
- **`liveboard`** — a crashed/empty evader output file is skipped instead of aborting the whole
  scoreboard render (was a `json.loads("")` fatal).

### Added (earlier)

- **Architecture & contracts.** Session-correlation design (`docs/architecture.md`) and the
  language-agnostic JSON-Schema contracts (`Signal`/`Session`/`Verdict`/`CoherenceRule`) plus the
  initial 10-rule coherence registry.
- **detector** (Python) — session correlation, the data-driven coherence engine, transparent
  noisy-or scoring with cross-layer amplification, SQLite store, and a FastAPI `/ingest` boundary.
  100% test coverage.
- **harness** (Python) — scenario runner + reproducible per-layer scoreboard (Markdown/JSON) with
  the ethics allow-list enforced in code. 100% test coverage.
- **edge** (Go) — raw ClientHello parser → JA3/JA4, session correlation, and signal forwarding.
- **collector** (TypeScript) — in-browser fingerprint + behavioral signal collection over an
  abstracted `BrowserEnv`. 100% test coverage of the pure logic.
- **Repo standards** — 2-line machine-scannable file headers (enforced), MADR ADRs, security
  posture (SECURITY.md, gitleaks, pinned actions, SBOM), supply-chain (Dependabot, license gate),
  community templates, and conventional-commit linting.
- **Live pipeline** — transparent TLS peek-proxy in the edge (captures the raw ClientHello, mints
  `ks_sid`, forwards JA3/JA4 signals), a real `vanilla` evader, and `docker-compose` wiring
  detector + edge + vanilla. Verified end-to-end (`session_id` threads socket → verdict).
- **`go-tls` evader** — uTLS-based Chrome/Firefox TLS fingerprint forging.
- **JA4 live network scoring** — detector `GET /session/{id}` to inspect captured signals; the edge's
  JA4 hint DB seeded with **real captured fingerprints** (go-tls Chrome, httpx), so the network layer
  recognises clients live (`ja4_browser_hint`/`ja4_os_hint` populate). (Browser-session network
  capture through the peek-proxy is a known follow-up — see `edge/README.md`.)
- **`stealth` evader (live)** — drives a real Chromium through the edge via Playwright (in the
  Playwright Docker image); the detector serves an in-page collector. Verified red-vs-blue result:
  naive automation scores `bot` (0.985, webdriver + headless tells), the stealth variant scores
  `human`.
- **`agent` evader (live)** — LLM-driven browser agent using `claude -p` as the reasoning engine
  (brain on host, Chromium in the Playwright container over CDP). Verified result: the agent beats
  the network + browser/fingerprint layers but is caught by the **behavioral** layer
  (`bot`, 0.80) — the thesis, demonstrated.
- **Coherence registry v0.2.0 → v0.3.0** — added HTTP/2-vs-TLS, headless-UA, keystroke-entropy, and
  proxy/Tor-exit rules (v0.2.0); then **deeper behavioral shape features** — mouse-path straightness
  and velocity coefficient-of-variation (collector + live demo page) with `bh.path_too_straight` and
  `bh.uniform_velocity` rules (v0.3.0), the start of the real behavioral frontier.
- **Cross-layer incoherence, demonstrated live** — a `spoof-ua` evader (real Chrome TLS + a lying
  Firefox UA) passes every single-layer check yet is caught solely by `net.tls_vs_ua_browser`
  (network 0.70 · browser 0.70 · incoherence 0.70 · bot). The thesis, proven with a real browser.
- **Unified live scoreboard** — `harness.live`/`liveboard` fold every evader's live verdict into one
  dated board; `scripts/live_scoreboard.sh` runs the whole fleet against the running stack and writes
  `docs/scoreboard.md` (vanilla → stealth → agent in one table).
- **docs/catalog.md** — opinionated catalog of ~70 relevant projects across the arms race.

[Unreleased]: https://github.com/datascry/kitsune/commits/main
