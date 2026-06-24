# detection-catalog — every detection rule Kitsune leverages, plus the open frontiers

This catalog has two parts: a **complete, auto-generated registry of every rule** in the ruleset (below,
regenerated from `contracts/rules/registry.yaml` by `task catalog` so it never drifts), followed by the
curated **gap analysis and frontier log** — what is built, what is saturated, and what is blocked on external
data. Start with the registry for "what does Kitsune detect today"; read the prose for "what's next and why."

<!-- GENERATED:rules:start -->
## Complete rule registry

> Every detection rule Kitsune leverages — **generated** from `contracts/rules/registry.yaml` (ruleset `0.74.49`); regenerate with `task catalog`, do not edit by hand. **137 rules**: 100 active · 31 experimental · 6 retired; 90 convicting (coherence/automation/artifact — only these can convict a `bot`; environment/behavioral/reputation/prevalence corroborate only).

### network layer (31)

| rule | category | predicate | wt | status | what it catches |
|---|---|---|---|---|---|
| `net.accept_encoding_vs_ua` | coherence✦ | present | 0.6 | active | UA claims a modern browser but Accept-Encoding omits Brotli (scripted client) |
| `net.accept_lang_vs_navigator` | coherence✦ | not_equal | 0.55 | active | HTTP Accept-Language contradicts the JS navigator.languages locale |
| `net.ch_platform_header_vs_ua` | coherence✦ | not_equal | 0.6 | active | HTTP Sec-CH-UA-Platform contradicts the JS UA platform |
| `net.ch_ua_mobile_vs_ua` | coherence✦ | present | 0.6 | active | Sec-CH-UA-Mobile form factor contradicts the UA's mobile-ness |
| `net.ch_ua_version_vs_ua` | coherence✦ | present | 0.6 | active | Sec-CH-UA brand version disagrees with the UA-string Chrome version |
| `net.ch_ua_vs_ua_browser` | coherence✦ | not_equal | 0.6 | active | HTTP Sec-CH-UA brand contradicts the JS UA browser |
| `net.datacenter_origin_proxied` | coherence✦ | present | 0.8 | active | WebRTC reveals a datacenter machine hidden behind a non-datacenter connection |
| `net.fake_declared_crawler` | coherence✦ | present | 0.8 | experimental | A UA declaring a known crawler (Googlebot/Bingbot/…) whose IP fails forward-confirmed reverse DNS |
| `net.h2_header_order_vs_ua` | coherence✦ | present | 0.6 | active | Chromium UA but the HTTP/2 regular-header order is not chromium-shaped (JA4H) |
| `net.h2_settings_vs_order` | coherence✦ | not_equal | 0.6 | active | HTTP/2 SETTINGS-profile engine contradicts the pseudo-header-order engine |
| `net.h2_unknown_vs_ua` | coherence✦ | present | 0.6 | active | Modern-browser UA but the HTTP/2 stack matches no known browser engine |
| `net.h2_unstable_within_session` | coherence✦ | present | 0.7 | active | HTTP/2 fingerprint (SETTINGS preface) changed within one session |
| `net.h2_vs_tls_browser` | coherence✦ | not_equal | 0.55 | active | HTTP/2 fingerprint browser contradicts the TLS (JA4) browser |
| `net.h2_vs_ua_browser` | coherence✦ | not_equal_browser | 0.6 | active | HTTP/2 (Akamai) fingerprint contradicts User-Agent browser |
| `net.ip_rotation_within_session` | coherence✦ | present | 0.7 | active | One session egressed from many distinct IPs (rotating proxy pool) |
| `net.ja4_unstable_within_session` | coherence✦ | present | 0.8 | active | TLS engine (JA4_b cipher identity) changed within one session |
| `net.no_js_execution` | coherence✦ | present | 0.6 | active | Page request with a TLS fingerprint but no browser layer (no JS ran — scripted client) |
| `net.quic_grease_vs_ua` | coherence | present | 0.6 | retired | GREASEing-engine UA (Chromium/Safari) but the QUIC ClientHello has no GREASE |
| `net.quic_pq_keyshare_vs_ua` | coherence | present | 0.5 | retired | Current-Chrome UA but the QUIC ClientHello offers no post-quantum key share |
| `net.sec_fetch_vs_ua` | coherence✦ | present | 0.7 | active | UA claims a modern browser but the request omits Sec-Fetch metadata headers |
| `net.tcp_os_vs_ua` | coherence✦ | not_equal | 0.7 | active | TCP/IP-stack OS kernel contradicts the OS the User-Agent claims |
| `net.tls_grease_vs_ua` | coherence✦ | present | 0.6 | active | UA claims a GREASEing-engine browser (Chromium/Safari) but the TLS ClientHello has no GREASE |
| `net.tls_os_vs_tcp_os` | coherence✦ | not_equal | 0.6 | experimental | JA4-implied OS contradicts TCP/IP-implied OS |
| `net.tls_pq_keyshare_vs_ua` | coherence✦ | present | 0.5 | experimental | UA claims current Chrome but the TLS handshake offers no post-quantum key share |
| `net.tls_vs_ua_browser` | coherence✦ | not_equal_browser | 0.7 | active | JA4 browser family contradicts User-Agent browser |
| `net.ua_rotation_within_session` | coherence✦ | present | 0.7 | active | One session sent multiple distinct User-Agent strings (mid-session UA rotation) |
| `net.h2_continuation_flood` | automation✦ | present | 0.9 | active | HTTP/2 CONTINUATION flood (CVE-2024-27316) on this connection |
| `net.h2_control_flood` | automation✦ | present | 0.9 | active | HTTP/2 control-frame flood (SETTINGS/PING — CVE-2019-9515/9512) |
| `net.h2_rapid_reset` | automation✦ | present | 0.9 | active | HTTP/2 rapid-reset flood (CVE-2023-44487) on this connection |
| `net.ch_ua_no_grease_brand` | artifact✦ | present | 0.6 | active | Chromium Sec-CH-UA brand list omits the GREASE brand (hardcoded header) |
| `net.webrtc_ip_vs_observed` | reputation | not_equal | 0.85 | experimental | WebRTC-revealed public IP contradicts the observed connection IP (proxied bot) |

### browser layer (108)

| rule | category | predicate | wt | status | what it catches |
|---|---|---|---|---|---|
| `br.apple_ua_nonwebkit` | coherence✦ | present | 0.75 | active | A UA claiming Apple WebKit (Safari / any iOS browser) exposes a Blink-only structural API |
| `br.canvas_worker_vs_main` | coherence✦ | present | 0.6 | experimental | Canvas pixel hash differs between the main thread and a Worker OffscreenCanvas |
| `br.ch_he_version_vs_ua` | coherence✦ | present | 0.6 | experimental | UA-CH high-entropy Chrome version contradicts the UA-string version |
| `br.engine_feature_vs_ua` | coherence✦ | present | 0.65 | active | JS engine lacks an API its claimed Chrome version shipped — stale template |
| `br.engine_stack_vs_ua` | coherence✦ | present | 0.7 | active | JS-engine stack API (Error.stackTraceLimit = V8) contradicts the UA engine |
| `br.error_engine_vs_ua` | coherence✦ | present | 0.75 | active | JS-engine error-message format contradicts the UA engine |
| `br.fingerprint_unstable_within_session` | coherence✦ | present | 0.7 | active | One session presented divergent hardware-invariant browser fingerprints (re-randomising anti-detect browser) |
| `br.firefox_ua_nongecko` | coherence✦ | present | 0.7 | active | A UA claiming Firefox lacks navigator.buildID — a Gecko-only surface, so it is not Gecko |
| `br.font_os_vs_ua` | coherence✦ | not_equal | 0.75 | active | Installed fonts imply an OS that contradicts the UA platform |
| `br.language_vs_languages` | coherence✦ | present | 0.6 | active | navigator.language disagrees with navigator.languages[0] (spec-invariant violation) |
| `br.languages_worker_vs_main` | coherence✦ | present | 0.6 | experimental | navigator.languages differs between the main thread and a Web Worker |
| `br.math_engine_vs_ua` | coherence | present | 0.7 | retired | JS Math float precision implies an engine that contradicts the UA |
| `br.mobile_no_touch` | coherence✦ | present | 0.7 | active | Phone/tablet UA reports no touch capability (maxTouchPoints 0) |
| `br.navplatform_vs_ua` | coherence✦ | not_equal | 0.7 | active | navigator.platform implies an OS that contradicts the UA platform |
| `br.oscpu_vs_ua` | coherence✦ | not_equal | 0.7 | active | navigator.oscpu implies an OS that contradicts the UA platform |
| `br.pointer_touch_incoherent` | coherence✦ | present | 0.7 | active | CSS coarse-pointer and navigator.maxTouchPoints disagree on touch |
| `br.productsub_vs_ua` | coherence✦ | not_equal | 0.7 | active | navigator.productSub render engine contradicts the UA |
| `br.safari_ua_no_webkit_api` | coherence✦ | present | 0.7 | active | A UA claiming Safari lacks window.GestureEvent — a WebKit-only surface, so it is not WebKit |
| `br.timezone_inconsistent` | coherence✦ | present | 0.6 | active | IANA timeZone and getTimezoneOffset() disagree (a real browser derives both from the OS) |
| `br.timezone_offset_vs_intl` | coherence✦ | present | 0.65 | active | getTimezoneOffset disagrees with the Intl IANA timezone's actual offset |
| `br.timezone_worker_vs_main` | coherence✦ | present | 0.7 | active | Timezone differs between the main thread and a Web Worker |
| `br.ua_platform_vs_ch_platform` | coherence✦ | not_equal | 0.7 | active | navigator/UA platform contradicts Sec-CH-UA-Platform |
| `br.vendor_vs_ua` | coherence✦ | not_equal | 0.7 | active | navigator.vendor implies an engine that contradicts the UA |
| `br.voice_os_vs_ua` | coherence✦ | not_equal | 0.75 | active | Installed TTS voices imply an OS that contradicts the UA platform |
| `br.webgl_os_vs_ua` | coherence✦ | not_equal | 0.7 | active | WebGL renderer implies an OS that contradicts the UA platform |
| `br.webgl_worker_vs_main` | coherence✦ | present | 0.6 | experimental | WebGL GPU renderer differs between the main thread and a Worker OffscreenCanvas |
| `br.webgpu_vendor_vs_webgl` | coherence✦ | present | 0.75 | active | WebGPU adapter GPU family contradicts the WebGL renderer (spoofed renderer on real hardware) |
| `net.accept_encoding_vs_ua` | coherence✦ | present | 0.6 | active | UA claims a modern browser but Accept-Encoding omits Brotli (scripted client) |
| `net.accept_lang_vs_navigator` | coherence✦ | not_equal | 0.55 | active | HTTP Accept-Language contradicts the JS navigator.languages locale |
| `net.ch_platform_header_vs_ua` | coherence✦ | not_equal | 0.6 | active | HTTP Sec-CH-UA-Platform contradicts the JS UA platform |
| `net.ch_ua_mobile_vs_ua` | coherence✦ | present | 0.6 | active | Sec-CH-UA-Mobile form factor contradicts the UA's mobile-ness |
| `net.ch_ua_version_vs_ua` | coherence✦ | present | 0.6 | active | Sec-CH-UA brand version disagrees with the UA-string Chrome version |
| `net.ch_ua_vs_ua_browser` | coherence✦ | not_equal | 0.6 | active | HTTP Sec-CH-UA brand contradicts the JS UA browser |
| `net.datacenter_origin_proxied` | coherence✦ | present | 0.8 | active | WebRTC reveals a datacenter machine hidden behind a non-datacenter connection |
| `net.h2_vs_ua_browser` | coherence✦ | not_equal_browser | 0.6 | active | HTTP/2 (Akamai) fingerprint contradicts User-Agent browser |
| `net.no_js_execution` | coherence✦ | present | 0.6 | active | Page request with a TLS fingerprint but no browser layer (no JS ran — scripted client) |
| `net.quic_grease_vs_ua` | coherence | present | 0.6 | retired | GREASEing-engine UA (Chromium/Safari) but the QUIC ClientHello has no GREASE |
| `net.quic_pq_keyshare_vs_ua` | coherence | present | 0.5 | retired | Current-Chrome UA but the QUIC ClientHello offers no post-quantum key share |
| `net.sec_fetch_vs_ua` | coherence✦ | present | 0.7 | active | UA claims a modern browser but the request omits Sec-Fetch metadata headers |
| `net.tls_grease_vs_ua` | coherence✦ | present | 0.6 | active | UA claims a GREASEing-engine browser (Chromium/Safari) but the TLS ClientHello has no GREASE |
| `net.tls_pq_keyshare_vs_ua` | coherence✦ | present | 0.5 | experimental | UA claims current Chrome but the TLS handshake offers no post-quantum key share |
| `net.tls_vs_ua_browser` | coherence✦ | not_equal_browser | 0.7 | active | JA4 browser family contradicts User-Agent browser |
| `br.automation_globals` | automation✦ | present | 0.6 | active | Automation-framework global or webdriver DOM attribute present |
| `br.canvas_lie` | automation✦ | present | 0.7 | active | Canvas/WebGL API tampering detected (getter override) |
| `br.cdc_artifacts` | automation✦ | present | 0.85 | active | Selenium / chromedriver automation artifacts in window/document |
| `br.cdp_runtime_enabled` | automation✦ | present | 0.85 | active | CDP Runtime.enable detected (prototype-chain Proxy ownKeys trap) |
| `br.ch_he_headless` | automation✦ | present | 0.85 | active | UA-Client-Hints high-entropy brand list reveals HeadlessChrome |
| `br.chrome_runtime_missing` | automation | present | 0.6 | retired | window.chrome present but chrome.runtime missing |
| `br.csp_bypassed` | automation✦ | present | 0.6 | active | Page CSP not enforced (setBypassCSP — an automation context, never a real browser) |
| `br.electron_process` | automation✦ | present | 0.85 | active | Renderer exposes a Node process object — Electron / automation runtime |
| `br.headless_ua` | automation✦ | present | 0.85 | active | User-Agent advertises a headless browser |
| `br.honeypot_interaction` | automation✦ | present | 0.85 | active | Interacted with a honeypot bait element a human cannot reach (off-screen + aria-hidden + tabindex -1) |
| `br.iframe_divergence` | automation✦ | present | 0.8 | active | navigator differs between the main document and an iframe |
| `br.nav_property_spoofed` | automation✦ | present | 0.6 | active | A prototype-inherited navigator property (pdfViewerEnabled/mimeTypes) is an own property |
| `br.no_chrome_object` | automation✦ | present | 0.7 | active | Chrome User-Agent but window.chrome is absent |
| `br.notification_denied` | automation | present | 0.4 | retired | Notification.permission is denied by default (headless Chrome) |
| `br.notification_getter_tampered` | automation✦ | present | 0.75 | active | Notification.permission getter is non-native (faked to beat the notification floor) |
| `br.permissions_anomaly` | automation✦ | present | 0.7 | active | Notification.permission contradicts the Permissions API state |
| `br.plugins_spoofed` | automation✦ | present | 0.6 | active | navigator.plugins is an own property (patched via defineProperty) |
| `br.tostring_tampered` | automation✦ | present | 0.8 | active | A native function's toString no longer reads [native code] |
| `br.webdriver_getter_tampered` | automation✦ | present | 0.85 | active | Navigator.prototype.webdriver getter is non-native (prototype patch) |
| `br.webdriver_present` | automation✦ | present | 0.9 | active | navigator.webdriver is true |
| `br.webdriver_spoofed` | automation✦ | present | 0.8 | active | navigator.webdriver is an own property (patched via defineProperty) |
| `br.webgl_getparameter_tampered` | automation✦ | present | 0.8 | active | WebGLRenderingContext.getParameter is overridden (non-native toString) |
| `br.worker_divergence` | automation✦ | present | 0.8 | active | navigator differs between the main thread and a Web Worker |
| `br.audio_noise` | artifact✦ | present | 0.6 | active | AudioContext fingerprint differs across identical renders (per-render perturbation) |
| `br.brave_spoofed` | artifact✦ | present | 0.7 | active | navigator.brave is present but faked (isBrave is not a native function) |
| `br.canvas_geometry_noise` | artifact✦ | present | 0.6 | active | Canvas path geometry is non-deterministic (isPointInPath farbling, e.g. JShelter) |
| `br.canvas_noise` | artifact✦ | present | 0.5 | active | Solid-fill canvas reads back perturbed (engine-level farbling, e.g. Brave) |
| `br.coalesced_untrusted` | artifact✦ | present | 0.7 | active | A coalesced pointer batch contains an untrusted (constructor-built) event — fabricated coalescing |
| `br.domrect_invariant` | artifact✦ | present | 0.55 | active | getBoundingClientRect is non-deterministic or disagrees with getClientRects — geometry shim |
| `br.font_mac_internal` | artifact✦ | present | 0.7 | experimental | macOS internal dot-prefixed system fonts are web-measurable (never on a real Mac) |
| `br.measuretext_offscreen_vs` | artifact✦ | present | 0.6 | active | Canvas measureText differs between main and OffscreenCanvas — main-thread font hook |
| `br.native_invariant_violated` | artifact✦ | present | 0.7 | active | A built-in method claims native but violates native-function invariants |
| `br.readback_noise` | artifact✦ | present | 0.4 | experimental | AudioBuffer getChannelData and copyFromChannel disagree — readback noise shim |
| `br.screen_impossible` | artifact✦ | present | 0.5 | active | Available screen area exceeds the physical screen (impossible geometry) |
| `br.webgl_renderer_artifact` | artifact✦ | present | 0.8 | active | WebGL renderer string is an anti-detect spoofing placeholder, not a real driver |
| `br.worker_constructor_tampered` | artifact✦ | present | 0.75 | active | Web Worker / OffscreenCanvas constructor is not native (worker-realm spoof injection) |
| `br.worker_source_rewritten` | artifact✦ | present | 0.75 | active | Web Worker ran from a different source than the page passed (worker-scope spoof injection) |
| `br.adblock_present` | environment | present | 0.3 | experimental | A content blocker hides the ad bait element (Camoufox default-bundles uBlock Origin) |
| `br.audio_missing` | environment | present | 0.5 | experimental | No OfflineAudioContext (audio stack absent) |
| `br.codec_os_incoherent` | environment | present | 0.65 | experimental | Non-Linux UA cannot play H.264/AAC (proprietary codecs a real Windows/macOS has via OS) |
| `br.color_depth_anomaly` | environment | present | 0.5 | active | screen.colorDepth is not a real-display value (24/30/32) |
| `br.devicepixelratio_anomaly` | environment | present | 0.5 | active | window.devicePixelRatio is not a positive finite number |
| `br.font_linux_leak` | environment | present | 0.7 | experimental | Linux metric-compatible fonts (Arimo/Cousine/Tinos) present under a non-Linux UA |
| `br.hover_none_desktop` | environment | present | 0.6 | active | Non-mobile UA reports no hover capability (CSS hover:none) |
| `br.languages_empty` | environment | present | 0.6 | active | navigator.languages is empty |
| `br.low_hardware_concurrency` | environment | below_threshold | 0.5 | experimental | navigator.hardwareConcurrency implausibly low |
| `br.macos_dpr1` | environment | present | 0.3 | experimental | macOS UA but devicePixelRatio is 1.0 (a modern Mac is Retina, dPR 2) |
| `br.media_devices_empty` | environment | present | 0.55 | active | navigator.mediaDevices.enumerateDevices() is empty (no audio/video hardware) |
| `br.mimetypes_empty` | environment | present | 0.5 | experimental | navigator.mimeTypes is empty |
| `br.no_connection` | environment | present | 0.5 | active | Chromium UA but navigator.connection is absent |
| `br.no_devicememory` | environment | present | 0.5 | experimental | Chromium UA but navigator.deviceMemory is undefined |
| `br.no_pdfviewer` | environment | present | 0.5 | experimental | Chromium UA but pdfViewerEnabled is false |
| `br.no_plugins` | environment | below_threshold | 0.4 | experimental | Desktop browser reports zero plugins |
| `br.platform_empty` | environment | present | 0.6 | active | navigator.platform is empty |
| `br.rfp_browser` | environment | present | 0.4 | active | resistFingerprinting signature (UTC + letterboxed window + 2-core, all at once) |
| `br.screen_avail_invalid` | environment | present | 0.7 | active | screen.availWidth/Height exceeds the physical screen size |
| `br.screen_zero` | environment | present | 0.7 | active | Screen or outer window dimensions are zero |
| `br.voices_empty` | environment | present | 0.5 | experimental | No speech-synthesis voices (headless/container — a real desktop has OS TTS) |
| `br.webgl2_missing` | environment | present | 0.4 | experimental | WebGL2 unsupported (headless software rendering) |
| `br.webgl_not_angle` | environment | present | 0.55 | experimental | Chromium UA but the WebGL renderer is not ANGLE-wrapped — renderer spoof |
| `br.webgl_software` | environment | present | 0.3 | active | WebGL renderer is software (SwiftShader / llvmpipe / Mesa) — headless tell |
| `br.webgpu_webgl_vs` | environment | present | 0.7 | active | WebGL renderer claims a hardware GPU but WebGPU exposes no real adapter (spoofed renderer) |
| `br.webrtc_unavailable` | environment | present | 0.6 | active | WebRTC gathers no ICE candidates (disabled/blocked) |
| `br.fingerprint_improbable` | prevalence | present | 0.25 | experimental | Fingerprint joint (platform/gpu/screen/colour/cores) is improbable under the real-traffic prior |
| `net.webrtc_ip_vs_observed` | reputation | not_equal | 0.85 | experimental | WebRTC-revealed public IP contradicts the observed connection IP (proxied bot) |
| `br.maxtouch_desktop` | — | present | 0.5 | retired | maxTouchPoints > 0 on a desktop User-Agent |

### behavioral layer (11)

| rule | category | predicate | wt | status | what it catches |
|---|---|---|---|---|---|
| `bh.trace_replay_within_session` | coherence✦ | present | 0.65 | active | One session replayed an identical pointer trajectory across page loads (record-and-replay bot) |
| `bh.click_without_trajectory` | behavioral | present | 0.5 | experimental | Trusted mouse click with no pointer trajectory in the session (teleport-click) |
| `bh.input_entropy_floor` | behavioral | below_threshold | 0.6 | experimental | Mouse-movement entropy below the human floor |
| `bh.keystroke_entropy_floor` | behavioral | below_threshold | 0.55 | experimental | Keystroke timing entropy below the human floor |
| `bh.keystroke_interval_floor` | behavioral | below_threshold | 0.55 | experimental | Median inter-keystroke interval below the human cadence floor |
| `bh.no_input_before_action` | behavioral | below_threshold | 0.5 | experimental | Action (submit/nav) with zero pointer events |
| `bh.path_too_straight` | behavioral | above_threshold | 0.55 | active | Mouse path is unnaturally straight (start->end ~= total length) |
| `bh.power_law_violation` | behavioral | below_threshold | 0.55 | experimental | Mouse motion violates the 2/3 power law (speed independent of curvature — synthetic path) |
| `bh.synthetic_no_coalesced` | behavioral | present | 0.45 | active | Long pointer stream never coalesces (CDP-injected input, not hardware) |
| `bh.touch_uniform_velocity` | behavioral | below_threshold | 0.5 | experimental | Touch-swipe velocity too uniform for a human finger (mobile) |
| `bh.uniform_velocity` | behavioral | below_threshold | 0.55 | active | Mouse moves at near-constant speed (low velocity CV) |

### reputation layer (4)

| rule | category | predicate | wt | status | what it catches |
|---|---|---|---|---|---|
| `net.datacenter_origin_proxied` | coherence✦ | present | 0.8 | active | WebRTC reveals a datacenter machine hidden behind a non-datacenter connection |
| `rep.datacenter_asn` | reputation | present | 0.5 | active | Source IP belongs to a datacenter / hosting ASN |
| `rep.known_proxy_exit` | reputation | present | 0.5 | active | Source IP is a known VPN / proxy / Tor exit |
| `rep.webrtc_origin_datacenter` | reputation | present | 0.6 | active | WebRTC-leaked real origin IP belongs to a datacenter / hosting ASN |

_✦ = a convicting category (can push a session to `bot`); all others corroborate only._

<!-- GENERATED:rules:end -->

## Provenance of the gap analysis

A subagent fleet enumerated bot-detection techniques across CreepJS, FingerprintJS/BotD, stealth-plugin
inverses, DataDome/Kasada/Cloudflare/Akamai/HUMAN, fingerprint surfaces, live production-JS reverse
engineering, and network/transport research, then gap-analyzed every technique against Kitsune's ruleset.

**Result: ~56 techniques already covered, 24 genuine gaps.** Coherence + automation are
near-saturated; the gaps cluster in deeper fingerprint-content checks, automation invariants, and a few
network refinements. Prioritize **FP-safe** gaps (the calibration showed adding FP-prone environment
tells is what flags real browsers) — i.e. low-fp coherence/automation/artifact gaps over medium-fp ones.

> **Per-session saturation, measured (v0.73.1, 2026-06-19).** Scoring all 40 **real captured** evader
> sessions (`corpus/sessions/`, the live-stack second source — not browserforge) through the current
> ruleset: **every evader scores `bot`**, including the top-tier stealth tools (`max-stealth`,
> `full-stealth`, `patchright`, `selenium-driverless`, `camoufox-hardened`, `zendriver`, `nodriver`,
> `rebrowser`, `undetected`). There is **no escaping evader** to build a new per-session detection against.
> The remaining catalog gaps below are either un-groundable in this sandbox (need a real GPU / real device /
> headful — `canvas_hash_engine_vs_ua`, `emoji_os_vs_ua`, `webgpu_limits`), confirmed-defeated
> (`h_order_vs_ua`), or FP-prone environment tells that only corroborate. Net: per-session convicting
> coverage is **saturated**; the live frontiers (real-residential-proxy harness, Tier-3 real-device matrix,
> real-hardware-headful) are blocked by sandbox limits. Iterations now harden the structural frontiers
> (prevalence prior, coordination gate) and the calibration's trustworthiness instead of grinding marginal
> tells. The detection matrix (`matrix.md`) is regenerated from these captures against the current ruleset;
> the latest refresh added the 2 newest rules with **no catch-count regression** on any existing rule.

## Prioritized gaps

| suggested rule | priority | fp-risk | effort | technique |
|---|---|---|---|---|
| `br.canvas_hash_engine_vs_ua` | high | medium | medium | Canvas hash vs engine baseline — Hash toDataURL vs Blink/Gecko/WebKit/SwiftShader baselines. |
| `net.h_order_vs_ua` | ✅ DONE | medium | medium | JA4H header order & casing — On-wire header order/casing is per-stack; browser UA over non-browser order is a tell. SHIPPED as `net.h2_header_order_vs_ua` (active v0.74.13, two-source corroborated). |
| `bh.interact_without_focus` | ❌ DEAD | medium | easy | document.hasFocus coherence — Interaction (pointer/keystroke/submit) while document.hasFocus() false is incoherent. DEAD: grounded out — document.hasFocus() is `true` in headless Chromium (identical to headful), so there is no signal and the rule cannot fire in our context. |
| `br.readback_noise` | ✅ DONE | low | easy | getImageData/audio readback-noise — getImageData and getChannelData-vs-copyFromChannel must round-trip identical bytes; diverg SHIPPED (active; live-validated via audio-readback-spoof). |
| `br.native_invariant_violated` | ✅ DONE | low | medium | Native prototype-lie suite — Illegal-invocation throw, non-constructability, ownKeys=length,name, prototype-in-fn false SHIPPED (active; native-spoof evader). |
| `br.electron_process` | ✅ DONE | low | easy | Electron process leak — Electron exposes a Node process object in the renderer; a real browser never does. SHIPPED (active). **v0.74.22: first live positive** — the new stealth `ELECTRON_LEAK=1` evader leaks `process.versions.electron`/`process.type='renderer'` and trips it; plain `STEALTH=1` + the real headful captures do not (FP-safe). No longer unexercised. |
| `br.measuretext_os_vs_ua` | medium | medium | medium | measureText OS signature — measureText metrics encode OS renderer; main vs OffscreenCanvas divergence; Camoufox spoof |
| `br.emoji_os_vs_ua` | medium | medium | medium | Emoji glyph vs OS — Emoji raster hash + tofu-vs-glyph maps to OS/version; Windows UA with Noto emoji is incohe |
| `br.isolated_world` | medium | medium | hard | Isolated-world execution tell — Main-world sentinel unreachable from isolated-world automation (selenium-driverless/patchr |
| `br.stack_tool_marker` | ❌ DEAD | low | easy | Error.stack tool-marker leak — Error().stack leaks pptr/puppeteer/playwright/_evaluation_script__ markers. DEAD: the collector runs as the page's own inline script, so its Error().stack is clean regardless of automation — cannot fire in our context. |
| `br.domrect_invariant` | ✅ DONE | low | medium | DOMRect transform geometry — getClientRects on transformed/zero-size elements; per-engine sub-pixel + invariant checks. SHIPPED (active). |
| `bh.honeypot_interaction` | ✅ DONE | low | medium | Honeypot bait interaction — Hidden bait element/field; automation that touches/fills it trips. Very low FP. SHIPPED as `br.honeypot_interaction` (automation) v0.74.11. |
| `net.ja4t_vs_ua` | ❌ REDUNDANT / ungroundable | low | medium | JA4T active TCP fingerprint — TCP window/options-order/MSS/wscale. RESOLVED (2026-06-19, not worth building): JA4T encodes the **OS TCP stack** (a browser uses the OS's stack), and the edge already parses the SYN (`ParseSYN`) and derives OS coherence via `ClassifyTCPOS` → `net.tcp_os_vs_ua`. So JA4T-vs-UA is the SAME SYN-derived OS-coherence signal we already ship, just a different encoding — redundant. AND ungroundable: FoxIO's `ja4plus-mapping.csv` ja4t column is EMPTY for Chrome/Firefox/Safari (JA4T is OS/path-specific, not a stable browser baseline), so there is no second source to ground per-browser JA4T against. |
| `br.timer_resolution_vm` | low | high | medium | performance.now VM timing — VM/headless timer resolution/jitter + micro-benchmark distinguish virtualized hosts. |
| `net.tls_raw_value_anomaly` | low | medium | medium | JA4_r raw value anomaly — Raw cipher/ext hex values vs claimed-browser profile; catches a value the hashed JA4 hides |
| `br.webgpu_limits_incoherent` | low | medium | medium | WebGPU limits/features bucket — adapter.limits/features bucket must match the GPU class; stock limits on a high-end vendor |
| `br.hw_memory_implausible` | low | medium | easy | hwc/deviceMemory plausibility — Default/round/implausible hwc+deviceMemory pairings signal VMs. |
| `br.storage_quota_anomaly` | low | medium | easy | Storage quota disk leak — storage.estimate quota ~60% of disk; containers report small/round; identical across sessi |
| `br.gamut_vs_gpu` | low | medium | easy | color-gamut/HDR vs GPU — P3/HDR display claim while software-rendering (SwiftShader) is suspicious. |
| `br.battery_anomaly` | ❌ REDUNDANT / medium-FP | — | — | Battery API stub/presence — `navigator.getBattery` is Chromium-only (Firefox removed it v52/2017, Safari never had it). RESOLVED 2026-06-20 (not worth building): the FP-safe direction (non-Chromium engine faking a Chromium UA, or Chromium faking Firefox → getBattery present under a Firefox UA) is **already covered** — a Chromium-faking-Firefox is caught by `br.firefox_ua_nongecko` (Firefox UA with no Gecko-only `navigator.buildID`), the superior already-shipped positive-surface tell. The only NON-redundant direction ("Chrome UA + getBattery ABSENT") is **FP-prone**: Brave removed getBattery and privacy users block it, so it would false-fire on real Brave/privacy Chromium. No collector probe for getBattery exists either. Net: no FP-safe non-redundant coverage to add. |
| `br.sensor_vs_formfactor` | low | medium | medium | Sensor presence vs form factor — DeviceMotion/Sensor presence must match mobile-ness; mobile UA with no motion, or static s |
| `br.broken_image_dims` | ❌ DEAD | medium | easy | Broken-image dimensions — Headless renders a broken img at 0x0; real Chrome ~16x16. DEAD: grounded out — a broken <img> is 0x0 in headless AND headful Chromium, so there is no signal to mismatch. |
| `rep.ja4_traffic_shape` | low | medium | hard | JA4 aggregate traffic-shape — Per-JA4 browser_ratio/h2h3_ratio/quantile vs genuine same-JA4 baseline flags spoofed fps. |
| `br.antidetect_tool_hash` | low | low | medium | Anti-detect extension hash — Hash patched prototype-method source to name CanvasBlocker/JShelter/puppeteer-extra. |
| `br.chrome_runtime_authenticity` | ❌ SUPERSEDED (v0.74.28) | — | — | RESOLVED by grounding against real Chrome. A real non-automated Chrome 149 (CDP-launched, `webdriver=false`) has `window.chrome` but **`chrome.runtime` is `undefined` on a normal page** — modern Chrome removed it from non-extension contexts (~v106). So "authenticity" has no baseline (the API is absent), and `br.chrome_runtime_missing` was RETIRED (it convicted EVERY real Chrome — a presence-check FP, not a buildable gap). Catching a chrome.runtime-faking tool now means catching a tool that ADDS an API real Chrome lacks — the inverse, and only if the fake's shape is distinguishable, which is its own ungrounded surface. See `corpus/calibration/headful/chrome-stable.json` + [[real-browser-capture-profiles]]. |

## Open frontiers — what external data unblocks each (operator menu, 2026-06-20)

Per-session detection is **saturated** and every real-browser FP a sandbox can surface is fixed (11 fixes,
v0.74.26–0.74.35; all runnable engine families clean — see [[real-browser-capture-profiles]]). The last three
were found by **reading the emitter** — auditing how each convicting rule's read-signal is produced, then asking
what real-user state yields the same signal: the prevalence GPU `other` bucket false-flagged real Firefox/Mullvad
(v0.74.33), `net.quic_pq_keyshare_vs_ua` rode the same broken QUIC capture as the retired `quic_grease`
(v0.74.34), and `br.notification_denied` fired on real "block notifications" users (v0.74.35, superseded by the
FP-safe `permissions_anomaly`). All 11 are now pinned by CI regression guards against accidental un-retirement and
real-capture re-flagging. Every genuinely
unbuilt gap above is now classified, and each converges on ONE external data source the sandbox cannot generate.
This is the operator's menu — provide a source, unlock the detections:

| provide this data source | unlocks |
|---|---|
| **Real residential/datacenter proxy egress** (real exit IPs, not container 172.x) | the coordination `rep.*` + proxy-topology signals (plumbing built + tested, `task fleet_capture`); catches the per-session EVADES mimics (zendriver/patchright/camoufox-headful) when they fleet behind proxies |
| **A real-traffic fingerprint prior** (hosted-demo opt-in or a real-device matrix — NO public dataset of sufficient scale/fields is fetchable; checked 2026-06-20) | a TRUE second prevalence prior to replace the single-source browserforge `gpu` factor (fpgen agrees but is same-family, not ground truth); `build_prior_from_sessions` is ready |
| **A real GPU host** (non-software-rendering, real WebGL/WebGPU) | `br.canvas_hash_engine_vs_ua`, `br.webgpu_limits_incoherent`, `br.gamut_vs_gpu` — all need a real-GPU baseline to ground without FP |
| **Real Windows / macOS / Safari browsers** (sandbox is Linux-only) | `br.measuretext_os_vs_ua`, `br.emoji_os_vs_ua` (OS-font baselines); resolves the Playwright-WebKit-≠-real-Safari `net.*` artifacts; cross-OS FP grounding |

The remaining unbuilt gaps without an external blocker are FP-prone (`br.timer_resolution_vm`, `br.hw_memory_implausible`,
`br.storage_quota_anomaly`), redundant with shipped OS-coherence rules (`br.emoji_os_vs_ua` overlaps `net.tcp_os_vs_ua`
for direct connections; `net.ja4t_vs_ua`), or dead — i.e. NOT worth building per the standing "don't grind marginal
tells at saturation" constraint. The honest state: in-sandbox detection advancement is exhausted; genuine new
coverage needs one of the four data sources above.

## Build order (precision-first) — COMPLETE

The original precision-first build order is now fully resolved: `br.readback_noise`, `br.electron_process`,
`br.native_invariant_violated`, and `net.h_order_vs_ua` (as `net.h2_header_order_vs_ua`) all **shipped active**;
`br.stack_tool_marker` is **DEAD** in our context (the collector is the page's own inline script, so its
`Error().stack` is clean regardless of automation). The low-FP/high-priority queue is exhausted.

### Live-coverage audit — unexercised active convicting rules (the constraint-#6 worklist)

Saturation means few NEW rules, so the productive precision work shifts to **proving every active convicting
rule actually fires in our context** (constraint #6: never ship a rule that can't fire here). A systematic
audit (2026-06-19) scored all 53 committed captures through the detector: **15 of 73 active convicting rules
fire on zero committed captures.** Of those, 4 had ALSO no detector unit test — the weakest-validated rules,
the genuine liabilities. Each read-signal IS producible by the collector/edge (none are dead), so each is
lightable by a faithful evader (the electron-leak / stale-engine pattern):

| rule | category | status | how to light |
|---|---|---|---|
| `br.engine_feature_vs_ua` | coherence | ✅ **lit v0.74.22** (stealth `STALE_ENGINE=1`) | claim Chrome ≥121 UA, remove `Promise.withResolvers` |
| `br.electron_process` | automation | ✅ lit v0.74.22 (stealth `ELECTRON_LEAK=1`) | leak Node `process` into the renderer |
| `br.measuretext_offscreen_vs` | artifact | ✅ **lit v0.74.22** (stealth `MEASURETEXT_SPOOF=1`) | farble main-thread `measureText` only (offscreen stays real → divergence) |
| `br.canvas_lie` | automation | ✅ **lit v0.74.22** (stealth `CANVAS_LIE=1`) | override `HTMLCanvasElement.prototype.toDataURL` with a non-native fn (toString lacks `[native code]`) |
| `br.domrect_invariant` | artifact | ✅ **lit v0.74.22** (stealth `DOMRECT_SPOOF=1`) | per-call DOMRect noise shim breaks the getBoundingClientRect determinism invariant |
| `br.cdc_artifacts` | automation | ✅ **lit v0.74.32** (stealth `CDC_LEAK=1`) | inject the canonical un-patched-chromedriver `$cdc_asdjflasutopfhvcZLmcfl_*` globals onto `document` |
| `br.font_os_vs_ua` | coherence | ✅ **lit v0.74.32** (stealth `FONT_OS_LEAK=1`) | Windows UA while the real Linux host fonts (DejaVu/Noto baked into the image) leak through |
| `br.csp_bypassed` | automation | ✅ **lit v0.74.32** (stealth `CSP_BYPASS=1`) | context `bypassCSP:true` swallows the served `img-src 'none'` violation a real browser fires |
| `br.audio_noise` | artifact | ✅ **lit v0.74.32** (stealth `AUDIO_NOISE=1`) | perturb `AudioBuffer.getChannelData` per-call so two identical OfflineAudioContext renders diverge |
| `br.screen_impossible` | artifact | ✅ **lit v0.74.32** (stealth `SCREEN_IMPOSSIBLE=1`) | spoof `Screen.prototype` so avail > physical (impossible geometry) |
| `net.h2_control_flood` | automation | ✅ **lit v0.74.32** (h2-rapid-reset `KS_MODE=controlflood`) | spam 150 SETTINGS+PING frames → edge ControlFrameFlood (>=100) |
| `net.h2_settings_vs_order` | coherence | ✅ **lit v0.74.32** (h2-rapid-reset `KS_MODE=settingssplit`) | Chromium SETTINGS profile + Firefox pseudo-header order (half-spoofed stack) |
| `br.font_mac_internal` | artifact (experimental) | ✅ **lit v0.74.35** (camoufox `KS_MACOS=1`) | pin Camoufox to a macOS profile — its bundled `fonts.json` `mac` list exposes 49 dot-prefixed internal fonts (`.Aqua Kana`, `.Apple Color Emoji UI`) a real Mac hides from web enumeration (white-box grounded against the tool's own source; 0 browserforge FPs incl. its macOS fingerprints) |
| `br.voice_os_vs_ua`, `br.webgpu_vendor_vs_webgl` | coherence | ⛔ hardware-blocked, un-groundable in-sandbox | needs real OS TTS voices / a real GPU (headless `getVoices()`=0; software WebGPU vendor is unrecognised by `gpuFam()`) — see [[unexercised-active-rules-need-live-positives]] |

Reproduce the audit: score `corpus/sessions/*.json` through `Detector().score()` and diff the fired rule_ids
against the active-convicting set. **The no-test/no-capture liability class is EMPTY** (v0.74.22) and the
**fire-on-zero-captures liability is now down to 2 hardware-blocked rules** (v0.74.32). The v0.74.22 set of 5
(electron-leak, stale-engine, measuretext-spoof, canvas-lie, domrect-spoof) was extended across v0.74.32 with
**7 more live captures** (cdc-leak, font-os-leak, csp-bypass, audio-noise, screen-impossible, h2-control-flood,
h2-settings-split) — each run LIVE through the edge→detector and frozen as a committed `corpus/sessions`
fixture guarded by `test_lit_rule_captures.py` (each capture must still trip its target rule and verdict bot).
This dropped fire-on-zero-captures 15 → 9 → **2**. The 2 remaining (`br.voice_os_vs_ua`,
`br.webgpu_vendor_vs_webgl`) are blocked on real audio/GPU hardware the sandbox cannot provide, and faking the
signal would be a strawman — they keep their unit tests (logic proven) and are left un-lit by design.

**Producer-side complement of the audit (2026-06-20): every emitted signal is consumed or context-only — no
collector work produces a missed FP-safe convicting opportunity.** Constraint #6 checks the CONSUMER side (no
rule reads a never-produced signal). The inverse is the producer side: diff the signals the collector/edge
EMIT (`demo.py` `S(...)` + edge `Network(...)` + `probes.ts` `put(...)`, 141 kinds) against the signals rules
`reads:`. The 18 emitted-but-unread signals are ALL legitimately non-convicting: coordination inputs
(`fp_hash`/`trace_hash`/`ja4`, consumed harness-side), prevalence-prior inputs
(`screen_resolution`/`webgl_renderer`/`webgl_vendor`, plus `color_depth` deliberately DROPPED as a
single-source FP), applicability/context (`is_brave`, `brand`), derived-hint raws (`ja3`/`h2`/`quic_observed`
feed the `*_hint` signals rules actually read — or, for QUIC, the retired rules), and environmental WebGPU
context (`webgpu_absent`/`webgpu_no_adapter` — a GPU-less machine, FP-prone to convict, correctly unused;
`webgpu_vendor`/`webgpu_fallback` feed the derived `webgpu_*_mismatch`). So the collector↔ruleset mapping is
complete in BOTH directions: no convicting rule is unproducible, and no emitted signal is an un-built FP-safe
convicting tell. Reproduce: regex the emitters vs the registry `reads:` and classify the difference.

Beyond the active set, the audit also lit one **experimental** convicting rule, `br.font_mac_internal`
(v0.74.35, camoufox `KS_MACOS=1`): a faithful white-box capture grounded against Camoufox's own bundled
`fonts.json` rather than a synthesized signal. The other two never-fired experimental net rules were probed
this round (2026-06-20) and are **both external-resource-blocked in-sandbox, NOT quick captures** (the prior
"groundable" note was optimistic — corrected here after a live producer test):
- `net.webrtc_ip_vs_observed` ⛔ **STUN-blocked.** `webrtc_public_ip` is set only from a `typ srflx` STUN
  candidate; a live Chromium probe in-sandbox gathers host candidates but **no srflx** (STUN UDP egress is
  blocked, while TCP egress works), so the signal never populates and the rule cannot fire. Faking the srflx IP
  would be a strawman. Same external-network-blocked class as `voice_os`.
- `net.tls_os_vs_tcp_os` ⛔ **no producer (inert by design).** `tcp_os_hint` needs raw-packet capture
  (CAP_NET_RAW/AF_PACKET) the userspace edge lacks; the registry comment confirms it is the only active rule
  with no producer and **explicitly defers arming it** until a capture sidecar lands AND `tcp_os_hint` is
  FP-grounded on real browsers (it is a convicting coherence rule — cf. the quic retirements). Not force-lit.

**Per-session validation is complete; the lit-capture campaign is now fully exhausted in-sandbox** — every
convicting rule (active + experimental) either has a live positive OR is provably external-resource-blocked
(real GPU / real audio / STUN UDP egress / a raw-packet-capture sidecar), each with the evidence recorded
above. Future iterations pivot
to the structural frontiers, both confirmed external-data-bound: the prevalence second prior needs real-device
gpu/cores data, and the coordination shape-signals (`fp_collision` via fleet-cloned, `trace_collision` via
fleet-replay, `shared_real_ip` via fleet-proxy) are already grounded END-TO-END on real concurrent-container
captures (distinct docker IPs) — only the IP-reputation half (`rep.*`) needs real residential-proxy egress.
**v0.74.32: `trace_collision` grounded on a real fleet** (corpus/fleet-replay rt1/2/3, stealth
`REPLAY_TRACE=1`): three instances inject one RECORDED pointer path via synthetic mousemove events, so the
collector hashes an IDENTICAL `trace_hash` across 3 distinct IPs → `fleet`. **Lesson (the reverted
keystroke_collision):** a clone-collision hash is only sound over an EXACTLY-REPRODUCIBLE value — render output
(`fp_hash`) or integer coordinates (`trace_hash`) — never over TIMING; a keystroke/scroll *timing* hash varies
run-to-run under ms-scheduler jitter (empirically: 3 concurrent containers → 3 distinct keystroke_hashes but 1
shared trace_hash), so it cannot ground and was removed. Before any new `*_collision`, run the same evader from
>= 2 concurrent containers and confirm the hash is byte-identical. The experimental rules re-validate live as of v0.74.32
(`br.readback_noise` fires via stealth `AUDIO_READBACK_SPOOF=1`; `net.h2_header_order_vs_ua`, now active, stays
guarded by its 3 committed non-Chrome-h2 captures). Deployed detector == committed ruleset 0.74.32 (no stale deploy).

### Producer-vs-reader audit — no dead rules (whole ruleset, 2026-06-19)

The live-coverage audit above asks "does each convicting rule *fire*?"; this complementary one asks the
prior question "can each rule fire *at all* — is its read-signal produced anywhere?" — across **all 91 active
rules** (not just convicting), every layer. For each rule's `reads`, confirm the signal is emitted by a
producer: the collector (`demo.py` `S("browser"|"behavioral", …)`), the edge (Go, network layer), or detector
enrichment (`ip_reputation` for `reputation.*`). **Result: all 96 distinct read-signals are produced — zero
dead rules** (a rule reading a signal nothing emits can never fire — a constraint-#6 violation; there are
none). The reverse check (collector signals **no** rule reads) found 13, all accounted for and intentional:
coordination inputs (`fp_hash`, `trace_hash`), prevalence inputs (`screen_resolution`, `webgl_renderer`,
`color_depth`), an applicability input (`is_brave`), informational session-record fields (`webgl_vendor`,
`webgpu_*` — the convicting `webgpu_*_mismatch` is derived from these in-collector), and the **documented
latent biomech** signals (`pause_ratio`, `submovement_count` — emitted, no rule yet, by design). No dead
collection to remove. Reproduce: diff registry `reads` against `S("…")` emissions in `demo.py` + edge Go +
`ip_reputation`.

**Per-session convicting detection is SATURATED.** The remaining table rows are either shipped (✅), grounded-
out dead-ends (❌: `interact_without_focus` — `document.hasFocus()` is `true` in headless too;
`broken_image_dims` — 0×0 in headless and headful alike), medium-FP environment tells that need a real-device
corpus to calibrate (`canvas_hash_engine_vs_ua`, `measuretext_os`, `emoji_os`, `gamut_vs_gpu`, `hw_memory`,
`storage_quota`, `battery_anomaly`, `sensor_vs_formfactor`), or blocked on inputs the sandbox cannot produce
(`ja4t_vs_ua`/`tls_raw_value` need an edge-side JA4T/JA4_r build; `webgpu_limits` needs a real GPU;
`ja4_traffic_shape`/`rep.*` IP-reputation need a real residential-proxy source; the prevalence model's
gpu/colour/cores factors need a Tier-3 real-device matrix to corroborate browserforge).

One **new convicting gap** was surfaced (2026-06-19) by the headful-patchright red-team work and is the
clearest per-session frontier, but it too is Tier-3-blocked: `br.chrome_runtime_authenticity`. The current
`br.chrome_runtime_missing` is presence-only and is the *sole deterministic* browser-layer catch for headful
patchright; faking `window.chrome.runtime` clears it (FLOOR_SPOOF already does). The fix — an authenticity
check — cannot be FP-safely grounded in-sandbox (no real non-Playwright Chrome to observe a genuine
`chrome.runtime`), so it is deferred to a Tier-3 real-Chrome capture rather than shipped ungrounded.

The productive frontier has shifted to **red-team-driven validation** (build the evader that exercises a
known-good rule, ground the real-browser negative) — which cleared the "Evaded" rule queue and surfaced the
engine-identity family — and to **periodic live re-validation + scoreboard/matrix refresh** (see
docs/calibration.md). New marginal per-session tells are deliberately NOT pursued at saturation.

### Frontier activation runbook — the turnkey infra is built; supply the data, run the command

The structural-frontier consumption infrastructure is built and tested, so each frontier is now
**data-only-blocked** (no further code needed — supply the external data the sandbox can't generate and
run the command). The one entry point:

| frontier | what to supply | command (already built + tested) |
|---|---|---|
| **Prevalence — independent prior** (fixes browserforge same-source blindness) | real-traffic SESSION captures (a hosted-demo opt-in yields these; shape = `corpus/sessions/*.json`) | `cd harness && uv run python -m kitsune_harness.browserforge_corpus --build-prior-from-sessions <dir>` (or `--build-prior-from-dir` for raw fingerprint dicts). Detector then loads the new prior automatically. See docs/prevalence-model.md. |
| **Live proxy / coordination harness** (activates `rep.*` + proxy-topology signals) | real residential/datacenter proxy endpoints | `IMAGE=… N=… PROXIES="socks5://p1,socks5://p2,…" OUT=corpus/fleet-proxy harness/tools/fleet_capture.sh` then grade with `kitsune_harness.coordination`. Refresh CIDR seeds first: `python -m kitsune_detector.ip_reputation_refresh`. **Egress plumbing PROVEN** (2026-06-19, docs/coordination-proxy.md): a local stand-in showed `KS_PROXY` moves the edge's `observed_ip` to the proxy's egress, so a real proxy → an ASN-classifiable IP → `rep.datacenter_asn`/`rep.known_proxy_exit` fire. The refresh path is drift-guarded + live-validated (11.6k DC + 1.2k Tor CIDRs). |
| **`net.webrtc_ip_vs_observed`** (the WebRTC real-IP-behind-proxy leak — part of the proxy frontier) | real proxy endpoints **AND a real browser** | Needs *both*: the proxy (above) + a real browser, because the srflx leak needs real STUN reachability. Diagnosed 2026-06-19 (docs/coordination-proxy.md): headless Chromium's WebRTC `srflx` gathering ignores `--host-resolver-rules`, so a local-STUN stand-in can't drive it; rule logic is unit-tested (`test_engine`), only the live collector→signal path is blocked. |
| **`br.chrome_runtime_authenticity`** (the one per-session gap) | a real (non-Playwright) **Chrome** capture, to ground authentic `window.chrome.runtime` | NOT turnkey yet — needs a real-Chrome session through the collector first, THEN add a `chrome.runtime`-shape probe + the FP-safe authenticity rule (grounded against that capture). The capture path (collector + `/session`) exists; the probe+rule are a small follow-up once real-Chrome data lands. |

So two of the three are pure data drops; the third needs a real-Chrome capture before its (small) probe+rule
can be written FP-safely. Nothing here is buildable further in-sandbox without that external data.

### Saturation is PROVEN, not asserted — the emitted-vs-consumed audit (2026-06-19)

Saturation was re-confirmed systematically rather than by inspection: diff every signal the collector
**emits** against every signal a rule **consumes**.

```sh
# emitted kinds (collector): the S("<layer>","<kind>",…) calls in detector/src/kitsune_detector/demo.py
grep -rhoE 'S\("(network|browser|behavioral|reputation)",[[:space:]]*"[a-z_0-9]+"' \
  detector/src/kitsune_detector/demo.py | grep -oE '"[a-z_0-9]+"[[:space:]]*$' | tr -d '" ' | sort -u
# consumed kinds (rules): the reads: lists in contracts/rules/registry.yaml
grep -oE '(network|browser|behavioral|reputation)\.[a-z_0-9]+' contracts/rules/registry.yaml \
  | sed -E 's/^[a-z]+\.//' | sort -u
```

Of 112 emitted kinds, **all but 12 feed a rule directly**, and every one of those 12 is accounted for —
none is an unbuilt **convicting** (coherence/automation/artifact) gap:

- **Raw-value inputs to the structural models, by design** (not direct rule predicates): `fp_hash` +
  `trace_hash` (coordination collision signals), `color_depth` + `screen_resolution` + `webgl_renderer`
  (prevalence factors / `webgl_os_hint` derivation), `webgl_vendor` + `webgpu_vendor`.
- **WebGPU-absence environment tells** (`webgpu_absent`/`webgpu_fallback`/`webgpu_no_adapter`): environment
  tier — corroborating only, and the convicting WebGPU coherence (`webgpu_*_mismatch`) is already ruled.
- **Dead collection — two behavioural metrics** (`pause_ratio`, `submovement_count`): collected but read by
  no rule. They are *behavioural*, hence corroborating-only/FP-prone, so wiring them would be a marginal
  non-convicting tell — deliberately NOT built at saturation. Flagged here as a latent corroborating option
  (or remove from the collector) for a future biomech pass, not a detection gap.

So there is provably **no unconsumed signal that could become a convicting per-session rule** — the gate is
saturated against the current collection surface. New convicting coverage now requires either a new
collector signal (new attack surface) or the structural frontiers (prevalence second prior; live proxy
coordination), both of which are external-data-blocked as noted above.

### Privacy-browser FP surface — a real-Brave grounding (2026-06-19)

Privacy/hardened browsers (Brave, Tor, Mullvad, LibreWolf) deliberately **farble or block** canvas / audio /
WebGL by default — exactly the footprint a naive bot blocker produces. That surface is invisible to every
calibration source we have (browserforge / fpgen / Intoli / SapiMouse all model *normal* browsers), so "does
a real privacy browser's farbling convict it?" was an **assumption**, not grounded — the risk a real
Mullvad/Tor user raises. Grounded it against a **real Brave** (default Shields) through the live collector
(`corpus/calibration/privacy/brave.json`, the corpus's first privacy-browser fixture):

- `canvas_noise=true`, `audio_readback_noise=true` — Brave really does farble both — yet **`br.canvas_lie`
  does NOT fire**: Brave's farbling is **engine-level**, so `toDataURL` stays NATIVE (`[native code]`). The
  convicting `automation` rule keys on a non-native getter *override* (a JS blocker / bot), which an
  engine-level privacy browser never presents. This is the coherence thesis working: same *signal* (perturbed
  canvas), different *mechanism* (native engine vs JS lie) → only the lie convicts.
- `is_brave=true` → `br.audio_noise` / `br.readback_noise` dropped by `detector.applicability`, so the
  by-design audio farble does not convict either.
- The capture's `bot` label comes **only** from the Playwright driver's automation tells (`webdriver`,
  `chrome_runtime_missing`) + the headless container's environment tells — never from a privacy feature.

Locked by `test_calibration_methodology.test_real_brave_farbling_does_not_trip_the_canvas_or_audio_spoof_rules`
(grounding, not a rule change → no ruleset bump).

### Gecko-RFP grounding — a real Mullvad Browser exposes a true FP (v0.74.26, 2026-06-19)

The Gecko-RFP gap is now **closed** — and it was NOT a no-op like Brave. Real **Mullvad Browser 15.0.16**
(Firefox 140 + resistFingerprinting) was driven through the live collector via **geckodriver + xvfb**
(disproving the prior "Playwright can't drive Gecko-RFP → external-data-bound" note: geckodriver *can*, given
`page_load_strategy=eager`, TRR off so the docker hostname resolves, and reading `ks_sid` from
`document.cookie` since the cert-override blocks Selenium's cookie API). Fixture:
`corpus/calibration/privacy/mullvad.json`. Findings:

- **A real FP, unlike Brave.** Mullvad's RFP trips three CONVICTING rules by design: `br.canvas_noise`
  (artifact), `br.canvas_geometry_noise` (artifact — its "deterministic in every real engine" claim is FALSE
  for RFP, which perturbs `isPointInPath`), and `br.canvas_worker_vs_main` (coherence — RFP's per-call canvas
  noise diverges main vs Worker). Stock non-RFP Firefox trips none, so these are RFP-on artifacts.
- **Root cause: `rfp_browser` never identified Mullvad.** Its conjunction required `hardwareConcurrency <= 2`,
  but modern Tor/Mullvad NO LONGER clamp cores (real Mullvad reports **4**). So the privacy-browser
  applicability drops never applied. **Fix:** the reliable, RFP-exclusive leg is the WebGL UNMASKED
  vendor+renderer both being literally `"Mozilla"`; the predicate is now `rfpGL && (rfpUTC || rfpBox ||
  rfpCores)` (the letterbox check is timing-flaky — RFP letterboxes *after* the collector's early run — so it
  can't be required). `_PRIVACY_FARBLING` extended to drop the geometry/worker canvas rules too. Grounded:
  re-captured Mullvad now sets `rfp_browser=true` and the three rules drop. Locked by
  `test_real_mullvad_rfp_farbling_does_not_trip_the_canvas_spoof_rules`.

### ✅ FIXED (v0.74.27): `br.engine_stack_vs_ua` false-fired on modern Firefox 122+

The Mullvad capture surfaced a SECOND, broader FP — convicting and **not** privacy-specific. `engine_stack_vs_ua`
treated `Error.captureStackTrace` as V8/JSC-only ("Firefox WITH it = spoof"), but **Firefox added
`Error.captureStackTrace` natively in v122 (Jan 2024)**, so the `firefox && hasV8Stack` arm fired on **every
modern real Firefox / Tor / Mullvad** (coherence, w=0.7 → convicts). Our committed Firefox captures missed it
because Playwright's Firefox is Juggler-patched and camoufox pins an older build (both report it `undefined`).
**Grounded + fixed:** captured **stock Firefox 152** via geckodriver (`corpus/calibration/headful/firefox-stock.json`)
— it reports `Error.captureStackTrace === "function"` (confirming Firefox-wide, not Mullvad-specific) AND
`Error.stackTraceLimit === undefined`, whereas Chromium reports `stackTraceLimit === "number"` (10). So the
discriminator switched to `Error.stackTraceLimit`, which stays V8-exclusive: it fixes the FP while PRESERVING
both spoof directions. Verified end-to-end: stock Firefox 152 + a re-captured Mullvad now trip no
`engine_stack` (zero browser-layer coherence/artifact fires on stock FF), while a real Chromium-faking-Firefox
spoof STILL trips it (and `firefox_ua_nongecko`). Locked by
`test_calibration_methodology.test_real_stock_firefox_152_no_browser_coherence_or_artifact_fp`.

### ✅ RETIRED (v0.74.28): `br.chrome_runtime_missing` convicted every real Chrome — and a saturation finding

Captured the most common real browser for the first time: **real Google Chrome 149**, both via Playwright
(`channel:chrome`) and — decisively — **manually launched + CDP-attached** so `navigator.webdriver === false`
(a genuine non-automated human-Chrome baseline, `corpus/calibration/headful/chrome-stable.json`). Result:
`window.chrome` is present (`loadTimes`/`csi`/`app`) but **`chrome.runtime` is `undefined`** on a normal page.
Chrome removed `chrome.runtime` from non-extension page contexts (~v106), so the rule's premise ("window.chrome
without runtime = headless/stealth") decayed: it now fires identically on real Chrome and convicts (automation,
w=0.6) **every real Chrome user**. A non-automated real Chrome scored **bot** on it alone. Retired
(`status: retired`), grounded, locked by `test_real_nonautomated_chrome_trips_no_browser_layer_conviction`.

**Honest consequence — a saturation marker, not hidden:** retiring it dropped the `zendriver` evader from
**bot → suspicious**. Why: a well-configured zendriver hides `webdriver` (false), emits no headless-UA / CDC /
CDP tell — its *only* convicting signal was `chrome_runtime_missing`, the **same** signal real Chrome emits. So
the rule only ever "caught" zendriver by also convicting all real Chrome; that is not a valid detection. Per
the prime directive (a real browser must not trip a convicting rule) the FP wins. **This is the per-session
saturation frontier made concrete:** a perfect-mimic anti-detect Chrome (real fingerprint, webdriver hidden) is
now indistinguishable from real Chrome on per-session JS signals. Catching it requires a signal real Chrome does
NOT share — the **structural frontiers** (network-layer TLS/h2 deviation outside the container confound;
coordination/prevalence), not another per-session tell.

### ✅ FIXED (v0.74.29): `net.h2_header_order_vs_ua` false-fired on real Chrome's fetch() requests

The `net.h2_header_order_vs_ua` fire on the real-Chrome capture was NOT a container artifact — a real coherence
FP. The edge's `HeaderOrderBrowser` keyed on `sec-ch-ua` before `user-agent`, which holds only for the document
NAVIGATION. Real Chrome 149's fetch()/XHR requests (the collector's own POST to `/ingest`) interleave the
Sec-CH-UA trio AROUND user-agent
(`content-length,sec-ch-ua-platform,user-agent,sec-ch-ua,content-type,sec-ch-ua-mobile,accept`), so the edge
fingerprinting that request convicted a real Chrome. Fixed: `HeaderOrderBrowser` now keys on the PRESENCE of the
full Sec-CH-UA trio (request-type-invariant; a naive non-browser stack omits it). Re-validated LIVE — real
Chrome 149 now has ZERO convicting fires across all layers; `webkit-ua-spoof` (real WebKit + Chrome UA, no trio)
still trips it (no detection loss); partial-trio cases unit-tested in edge `h2_test.go`.

### ✅ FIXED (v0.74.30): `net.tls_vs_ua_browser` + `net.h2_vs_ua_browser` convicted real Microsoft Edge

First capture of **real Microsoft Edge 149** (`corpus/calibration/headful/msedge.json`) — the 2nd–3rd most common
desktop browser — surfaced a coherence FP. Edge is built on Chromium, so its TLS/HTTP-2 stack is **identical to
Chrome's** (`ja4_browser_hint=chrome`, `h2_browser_hint=chrome`), but `ua_browser=edge`. The two cross-layer
browser-coherence rules used `predicate: not_equal`, so `chrome != edge` convicted every real Edge. Fixed with a
new **`not_equal_browser`** predicate that collapses the Chromium family (edge/brave/opera/vivaldi/samsung →
chrome) to its engine before comparing: a Chromium-engine UA matches the `chrome` network hint (no fire) while a
CROSS-ENGINE pairing still fires. Re-validated LIVE — real Edge 149 now has zero coherence/artifact fires;
`webkit-ua-spoof` (WebKit TLS + Chrome UA) and `spoof-ua`/`ios-ua-spoof` (Chrome TLS + Firefox/Safari UA) still
fire (no detection loss). Unit-tested in `test_predicates.test_not_equal_browser`; locked by
`test_real_edge_chromium_family_not_a_tls_or_h2_browser_contradiction`.

### Open data gap (remaining)

LibreWolf is the next privacy/Gecko source; fetchable via the geckodriver path proven here (Tor/Mullvad/stock
Firefox all captured), no longer external-data-bound. `br.chrome_runtime_authenticity` (authenticate a PRESENT
chrome.runtime's shape — a stealth tool that INJECTS a fake one) is the salvage of the retired rule, but needs
the rare present-case grounded first.

## Shipped from this catalog

- ✅ `br.safari_ua_no_webkit_api (ACTIVE v0.74.18 — completes the engine-identity family. window.GestureEvent is a WebKit-ONLY global (every desktop + iOS Safari since Safari 5; Blink and Gecko have none). A Safari UA without it is a non-WebKit faker — the negative-surface complement to apple_ua_nonwebkit (which keys on Blink APIs PRESENT), robust to a spoof that DELETES window.chrome/userAgentData to beat that rule. GROUNDED on the real-browser second source (live Playwright WebKit GestureEvent="function" vs Chromium/Firefox undefined); real headful WebKit does NOT fire, the ios-ua-spoof evader (Chromium under an iPhone Safari UA) does. FP-safe: every real Safari has GestureEvent. The three engine-identity tells now cover all three: chromium↔engine_stack, gecko↔firefox_ua_nongecko (buildID), webkit↔this (GestureEvent) + apple_ua_nonwebkit (Blink-present).)`
- ✅ `br.firefox_ua_nongecko (ACTIVE v0.74.17 — the Gecko analog of apple_ua_nonwebkit. navigator.buildID is a Gecko-ONLY surface (every real Firefox/Tor/Mullvad/fork exposes it, release builds frozen to "20181001000000"; Blink and WebKit have none). A Firefox UA without buildID is a non-Gecko engine faking Firefox. STRUCTURAL positive-surface tell, complementary to engine_stack_vs_ua: a spoof that deletes Error.captureStackTrace to beat engine_stack still cannot synthesise a real Gecko buildID. GROUNDED on the real-browser second source (live Playwright Firefox buildID="20181001000000" vs Chromium undefined) + the real-Gecko firefox-os-spoof evader does NOT fire (it IS Gecko); the spoof-ua evader (Chromium under a Firefox UA) does. FP-safe: every real Gecko has buildID → never fires on real Firefox.)`
- ✅ `br.honeypot_interaction (ACTIVE — the classic honeypot, the catalog's bh.honeypot_interaction gap. The collector injects an off-screen, aria-hidden, tabIndex=-1 bait link + input a human literally cannot reach; a click on the bait or a value in the bait input is a programmatic DOM-enumeration interaction → automation. FP-safe: fires ONLY on a definitive hit, never on absence; grounded against clean headful Chromium AND Firefox (no fire). Fires in-context via the stealth HONEYPOT=1 form-spammer evader.)`
- ✅ `net.h2_header_order_vs_ua (ACTIVE v0.74.13 — promoted from experimental after two independent non-Chrome h2 stacks corroborated: httpx/h2 (http2-naive) and curl/nghttp2 (curl-http2), both faking a Chrome UA with a non-Chrome regular-header order. Real Chrome + all 40+ Chrome impersonators emit the Sec-CH-UA-first order → never fire. Catches the naive h2 scraper that fakes Chrome without replicating its on-wire order.)`
- ✅ `br.readback_noise`
- ✅ `br.electron_process`
- ✅ `br.native_invariant_violated`
- ✅ `br.domrect_invariant`
- ✅ `br.measuretext_offscreen_vs`
- ✅ `br.fingerprint_improbable (prevalence model — the structural frontier)`
- ✅ `br.webgl_worker_vs_main (experimental — GPU analog of worker_divergence; fires live on full-stealth + native-spoof; pending Tier-3 real-GPU FP validation)`
- ✅ `br.canvas_worker_vs_main (experimental — canvas analog; a Worker OffscreenCanvas hash vs main; fires live on canvas-spoof; pending Tier-3 real-GPU FP validation)`
- ✅ `br.timezone_worker_vs_main (ACTIVE — geo-spoof analog; main vs Worker timezone; FP-safe (process-level, legit CDP override propagates to workers); fires live on tz-spoof)`
- ✅ `br.languages_worker_vs_main (experimental — language half of the geo-spoof pair; main vs Worker navigator.languages; fires live on lang-spoof; experimental NOT active because a legit CDP locale override does not propagate to workers, so it needs Tier-3 legit-divergence-rate validation)`
- ✅ `br.worker_constructor_tampered (ACTIVE — the escalation guard for the whole realm-coherence family; window.Worker/OffscreenCanvas must be native; fires live on worker-wrap, which defeats worker_divergence by injecting the spoof into worker scope but cannot keep the Worker constructor native)`
- ✅ `br.timezone_offset_vs_intl (ACTIVE — internal timezone coherence; getTimezoneOffset must match the Intl IANA zone's actual offset; self-contained, no worker/IP-geo; FP-safe (real + legit CDP override both coherent); fires live on naive-tz-spoof and the wrong-season tz-spoof)`
- ✅ `br.canvas_geometry_noise (ACTIVE — canvas GEOMETRY farbling, the JShelter white-box tell from evasion-catalog; isPointInPath is an exact GPU-independent hit-test, deterministic in every real engine; 120 trials on a deep-interior + far-exterior point catch a ~5%-flip farbler at ~99.8%; FP-safe (missing API never fires, only a definitive verdict counts) — zero FP across browserforge calibration; distinct from canvas_noise/Brave readback farbling)`
- ✅ `br.apple_ua_nonwebkit (ACTIVE — iOS/Safari engine lock; Apple mandates WebKit for Safari AND every iOS browser (Chrome=CriOS, Firefox=FxiOS, Brave, DuckDuckGo, Onion all wrap system WebKit), so a UA claiming Apple WebKit that exposes a Blink-only structural API — window.chrome, navigator.userAgentData, or V8 Error.captureStackTrace — is a Chromium host faking an iOS/Safari UA. STRUCTURAL positive-API tell (survives error-message/float spoofing that error_engine/math_engine rely on). Catches the common mobile-Safari-UA spoof on headless Chromium. **v0.74.9: narrowed to TWO arms** — the Error.captureStackTrace arm was dropped after a live headful WebKit capture (corpus/calibration/headful/) proved JSC ships captureStackTrace since Safari 16.4, i.e. the arm convicted real Safari 16.4+/iOS users; window.chrome / userAgentData remain genuinely Blink-only so the spoof catch is preserved — see docs/calibration.md "Tier-2")`

_Skipped: `br.stack_tool_marker` — the collector runs as the page's own inline script, so its Error().stack is clean regardless of automation (can't fire here)._

## Live-page browser discrimination (white-box identification)

The live page predicts the **real** browser from feature detection (`collector/src/livepage/predict.ts`),
independent of the spoofable UA, and names it: **Brave** (`navigator.brave`), **Chrome / Edge / Opera /
Samsung Internet** (UA-CH brands + `window.chrome`), **Firefox** (Gecko: `-moz-appearance` / `buildID` /
`mozInnerScreenX`), **Safari** (WebKit), and the **Tor / Mullvad Browser** family (Gecko + the
resistFingerprinting conjunction: UTC timezone + a 200×100-letterboxed window + ≤2 cores — the same
signature the detector's `br.rfp_browser` ships and calibrates, so a vanilla Firefox is not mislabeled).

**Mobile + privacy browsers** are named with the same honesty about what features *can* prove:
- **iOS** — Apple forbids non-WebKit engines, so Safari, Chrome (CriOS), Firefox (FxiOS), Brave, DuckDuckGo,
  and Onion Browser all run the *same* system WebKit. The engine cannot separate them, so the page reports
  `iOS browser (WebKit)` and says so — and the detector's convicting `br.apple_ua_nonwebkit` fires on any UA
  that claims iOS/Safari while exposing a Blink-only API (a Chromium host faking an iOS UA).
- **Android** — `Brave`/`Opera`/`Edge`/`Chrome` carry an `(Android)` tag; a Blink engine with no vendor tell
  is named `Chromium (Android)` (Vivaldi/Yandex/UC/DuckDuckGo-Android suppress their brand — not guessed);
  Gecko is `Firefox / GeckoView (Android)` (Firefox/Focus/Fennec share the engine), and the RFP-Gecko variant
  is `Tor Browser / Mull (Android)`.

**Honest limit:** Tor Browser and Mullvad Browser are *intentionally identical* at the JS layer (they share
one anonymity set), so they are not JS-separable — only the **network layer** (a Tor exit-IP via
`rep.*`/IP reputation) tells them apart. The prediction surfaces this in its evidence rather than guessing.

**Per-browser FP suppression (the point of the prediction).** `notApplicable(ruleId, prediction)` excludes
a tell that is *expected* for the identified browser so it cannot convict a real user:
- platform-coherence (`navplatform/webgl/oscpu_vs_ua`) on **mobile** (Android's `Linux` platform is genuine);
- Chromium-only capability tells (`no_chrome_object`, `no_connection`, …) on **non-blink** engines;
- **Brave's by-design farbling** (`canvas_noise`, `audio_noise`) when the browser is positively **Brave**
  (the definitive `navigator.brave` global) — Brave's default Shields perturb the canvas/audio readback, so a
  real Brave user (~70M of them) would otherwise noisy-or two *artifact* (convicting) tells to `bot`. A
  Chrome-claiming farbler with no `navigator.brave` (an anti-detect tool) still convicts.

> **Detector-side parity (done, v0.73.3).** The same Brave farbling FP existed server-side; the detector now
> has its own per-browser N/A (`detector.applicability`, the analog of the live page's `predict.notApplicable`).
> The collector emits `browser.is_brave` (from `navigator.brave`); `Detector.score` drops the Brave-expected
> farbling artifacts (`canvas_noise`, `audio_noise`) before scoring when the session is Brave, so a real Brave
> user is not convicted. A Chrome-claiming farbler with no `navigator.brave` still convicts, and a Brave-faking
> bot is still caught by its automation tells, so it cannot help a bot escape. Calibration is unchanged
> (browserforge never emits `is_brave`, so the filter is a no-op there).
