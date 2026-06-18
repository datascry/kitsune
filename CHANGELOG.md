# Changelog

All notable changes to Kitsune are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Releases are cut automatically from
[Conventional Commits](https://www.conventionalcommits.org/) via release-please.

## [Unreleased]

### Added

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
