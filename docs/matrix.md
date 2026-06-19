# Kitsune detection matrix — 118 rules vs 47 evaders

_46/47 evaders caught (`bot`). Generated from the committed captures._

## Per-evader verdict — score and the convicting tells that caught each evader

| Evader | verdict | score | fired | convicting tells |
|---|---|---|---:|---|
| `audio-readback-spoof` | bot | 1.00 | 15/118 | `br.cdp_runtime_enabled`, `br.headless_ua`, `br.ch_he_headless` +5 |
| `baseline-firefox` | bot | 1.00 | 6/118 | `br.webdriver_present` |
| `brave-fake` | bot | 1.00 | 15/118 | `br.cdp_runtime_enabled`, `br.headless_ua`, `br.ch_he_headless` +5 |
| `brave` | bot | 1.00 | 10/118 | `br.webdriver_present`, `br.headless_ua`, `br.chrome_runtime_missing` +1 |
| `camoufox-hardened` | bot | 0.98 | 5/118 | `br.pointer_touch_incoherent` |
| `camoufox-headful` | suspicious | 0.95 | 4/118 | — |
| `camoufox` | bot | 1.00 | 3/118 | `net.tcp_os_vs_ua`, `net.no_js_execution`, `net.tls_grease_vs_ua` |
| `canvas-geometry-spoof` | bot | 1.00 | 15/118 | `br.cdp_runtime_enabled`, `br.headless_ua`, `br.ch_he_headless` +5 |
| `canvas-spoof` | bot | 1.00 | 17/118 | `br.cdp_runtime_enabled`, `br.headless_ua`, `br.ch_he_headless` +7 |
| `ch-ua-hardcoded` | bot | 1.00 | 6/118 | `net.tcp_os_vs_ua`, `net.no_js_execution`, `net.sec_fetch_vs_ua` +3 |
| `chrome-clone-1` | bot | 1.00 | 14/118 | `br.webdriver_present`, `br.cdp_runtime_enabled`, `br.headless_ua` +3 |
| `chrome-clone-2` | bot | 1.00 | 14/118 | `br.webdriver_present`, `br.cdp_runtime_enabled`, `br.headless_ua` +3 |
| `curl-impersonate` | bot | 0.90 | 1/118 | `net.no_js_execution` |
| `floor-spoof` | bot | 1.00 | 8/118 | `br.tostring_tampered`, `br.nav_property_spoofed`, `br.webdriver_getter_tampered` +1 |
| `full-stealth` | bot | 1.00 | 17/118 | `br.cdp_runtime_enabled`, `net.ch_ua_version_vs_ua`, `br.ch_he_headless` +8 |
| `go-tls` | bot | 0.99 | 3/118 | `net.h2_unknown_vs_ua`, `net.no_js_execution`, `net.tls_pq_keyshare_vs_ua` |
| `h2-continuation-flood` | bot | 0.99 | 2/118 | `net.h2_continuation_flood`, `net.no_js_execution` |
| `h2-rapid-reset` | bot | 0.99 | 2/118 | `net.h2_rapid_reset`, `net.no_js_execution` |
| `honeypot` | bot | 1.00 | 16/118 | `br.webdriver_present`, `br.cdp_runtime_enabled`, `br.honeypot_interaction` +5 |
| `human-mouse` | bot | 1.00 | 14/118 | `br.webdriver_present`, `br.cdp_runtime_enabled`, `br.headless_ua` +4 |
| `iframe-spoof` | bot | 1.00 | 23/118 | `br.ua_platform_vs_ch_platform`, `br.cdp_runtime_enabled`, `net.ch_platform_header_vs_ua` +10 |
| `ios-ua-spoof` | bot | 1.00 | 22/118 | `net.h2_vs_ua_browser`, `br.ua_platform_vs_ch_platform`, `net.ch_ua_vs_ua_browser` +11 |
| `lang-list-spoof` | bot | 1.00 | 15/118 | `br.cdp_runtime_enabled`, `br.headless_ua`, `br.ch_he_headless` +5 |
| `lang-spoof` | bot | 1.00 | 15/118 | `br.cdp_runtime_enabled`, `br.headless_ua`, `br.ch_he_headless` +5 |
| `linear-bot` | bot | 1.00 | 18/118 | `br.webdriver_present`, `br.cdp_runtime_enabled`, `br.headless_ua` +4 |
| `max-stealth` | bot | 1.00 | 11/118 | `br.webdriver_spoofed`, `br.permissions_anomaly`, `br.no_chrome_object` +1 |
| `naive-tz-spoof` | bot | 1.00 | 17/118 | `br.cdp_runtime_enabled`, `br.headless_ua`, `br.ch_he_headless` +7 |
| `native-spoof` | bot | 1.00 | 17/118 | `br.native_invariant_violated`, `br.cdp_runtime_enabled`, `br.headless_ua` +7 |
| `nodriver` | bot | 1.00 | 9/118 | `net.quic_grease_vs_ua`, `br.headless_ua`, `br.chrome_runtime_missing` |
| `os-spoof` | bot | 1.00 | 17/118 | `br.cdp_runtime_enabled`, `net.ch_ua_version_vs_ua`, `net.tcp_os_vs_ua` +6 |
| `patchright` | bot | 1.00 | 11/118 | `br.headless_ua`, `br.ch_he_headless`, `br.permissions_anomaly` +2 |
| `primp` | bot | 0.97 | 2/118 | `net.tcp_os_vs_ua`, `net.no_js_execution` |
| `pydoll` | bot | 1.00 | 8/118 | `br.headless_ua`, `br.chrome_runtime_missing` |
| `quic-no-grease` | bot | 1.00 | 5/118 | `net.quic_grease_vs_ua`, `net.no_js_execution`, `net.sec_fetch_vs_ua` +2 |
| `rebrowser` | bot | 1.00 | 11/118 | `br.webdriver_present`, `br.headless_ua`, `br.permissions_anomaly` +2 |
| `renderer-spoof` | bot | 1.00 | 19/118 | `br.cdp_runtime_enabled`, `br.headless_ua`, `br.ch_he_headless` +7 |
| `selenium-driverless` | bot | 1.00 | 8/118 | `br.headless_ua`, `br.chrome_runtime_missing` |
| `spoof-ua` | bot | 1.00 | 16/118 | `net.h2_vs_ua_browser`, `net.ch_ua_vs_ua_browser`, `br.ch_he_headless` +7 |
| `stealth-naive` | bot | 1.00 | 14/118 | `br.webdriver_present`, `br.cdp_runtime_enabled`, `br.headless_ua` +4 |
| `stealth-patched` | bot | 1.00 | 21/118 | `br.cdp_runtime_enabled`, `net.ch_ua_version_vs_ua`, `net.tcp_os_vs_ua` +8 |
| `tls-stale-template` | bot | 1.00 | 6/118 | `net.tcp_os_vs_ua`, `net.no_js_execution`, `net.sec_fetch_vs_ua` +3 |
| `tz-spoof` | bot | 1.00 | 17/118 | `br.cdp_runtime_enabled`, `br.headless_ua`, `br.ch_he_headless` +7 |
| `undetected` | bot | 1.00 | 8/118 | `br.headless_ua`, `br.chrome_runtime_missing` |
| `vanilla` | bot | 1.00 | 5/118 | `net.tcp_os_vs_ua`, `net.no_js_execution`, `net.sec_fetch_vs_ua` +2 |
| `worker-spoof` | bot | 1.00 | 15/118 | `br.cdp_runtime_enabled`, `br.headless_ua`, `br.ch_he_headless` +5 |
| `worker-wrap` | bot | 1.00 | 15/118 | `br.cdp_runtime_enabled`, `br.headless_ua`, `br.ch_he_headless` +5 |
| `zendriver` | bot | 1.00 | 8/118 | `br.chrome_runtime_missing` |

## Per-rule coverage — 81/118 rules catch ≥1 evader (rest in Gaps)

| Detector | layer | category | catches |
|---|---|---|---:|
| `br.media_devices_empty` | browser | environment | 36 |
| `br.voices_empty` | browser | environment | 36 |
| `br.webgl_software` | browser | environment | 31 |
| `br.mimetypes_empty` | browser | environment | 27 |
| `br.no_plugins` | browser | environment | 27 |
| `br.notification_denied` | browser | automation | 27 |
| `br.permissions_anomaly` | browser | automation | 27 |
| `br.headless_ua` | browser | automation | 25 |
| `br.no_pdfviewer` | browser | environment | 25 |
| `br.no_chrome_object` | browser | automation | 24 |
| `br.cdp_runtime_enabled` | browser | automation | 22 |
| `br.ch_he_headless` | browser | automation | 22 |
| `bh.keystroke_entropy_floor` | behavioral | behavioral | 19 |
| `br.webdriver_getter_tampered` | browser | automation | 15 |
| `bh.input_entropy_floor` | behavioral | behavioral | 10 |
| `net.no_js_execution` | network,browser | coherence | 10 |
| `bh.no_input_before_action` | behavioral | behavioral | 9 |
| `br.webdriver_present` | browser | automation | 9 |
| `net.tcp_os_vs_ua` | network | coherence | 8 |
| `br.chrome_runtime_missing` | browser | automation | 6 |
| `br.webgl_os_vs_ua` | browser | coherence | 6 |
| `br.hover_none_desktop` | browser | environment | 5 |
| `br.webdriver_spoofed` | browser | automation | 5 |
| `net.tls_grease_vs_ua` | network,browser | coherence | 5 |
| `bh.synthetic_no_coalesced` | behavioral | behavioral | 4 |
| `br.codec_os_incoherent` | browser | environment | 4 |
| `br.fingerprint_improbable` | browser | prevalence | 4 |
| `br.font_linux_leak` | browser | environment | 4 |
| `br.navplatform_vs_ua` | browser | coherence | 4 |
| `net.accept_encoding_vs_ua` | network,browser | coherence | 4 |
| `net.sec_fetch_vs_ua` | network,browser | coherence | 4 |
| `br.ch_he_version_vs_ua` | browser | coherence | 3 |
| `br.webgl2_missing` | browser | environment | 3 |
| `br.webgl_worker_vs_main` | browser | coherence | 3 |
| `br.webgpu_webgl_vs` | browser | environment | 3 |
| `br.webrtc_unavailable` | browser | environment | 3 |
| `net.ch_ua_version_vs_ua` | network,browser | coherence | 3 |
| `br.canvas_noise` | browser | artifact | 2 |
| `br.error_engine_vs_ua` | browser | coherence | 2 |
| `br.timezone_inconsistent` | browser | coherence | 2 |
| `br.timezone_offset_vs_intl` | browser | coherence | 2 |
| `br.timezone_worker_vs_main` | browser | coherence | 2 |
| `br.tostring_tampered` | browser | automation | 2 |
| `br.ua_platform_vs_ch_platform` | browser | coherence | 2 |
| `br.vendor_vs_ua` | browser | coherence | 2 |
| `br.webgl_getparameter_tampered` | browser | automation | 2 |
| `br.worker_divergence` | browser | automation | 2 |
| `net.ch_ua_vs_ua_browser` | network,browser | coherence | 2 |
| `net.h2_vs_ua_browser` | network,browser | coherence | 2 |
| `net.quic_grease_vs_ua` | network,browser | coherence | 2 |
| `net.tls_pq_keyshare_vs_ua` | network,browser | coherence | 2 |
| `bh.path_too_straight` | behavioral | behavioral | 1 |
| `bh.power_law_violation` | behavioral | behavioral | 1 |
| `bh.uniform_velocity` | behavioral | behavioral | 1 |
| `br.apple_ua_nonwebkit` | browser | coherence | 1 |
| `br.brave_spoofed` | browser | artifact | 1 |
| `br.canvas_geometry_noise` | browser | artifact | 1 |
| `br.canvas_worker_vs_main` | browser | coherence | 1 |
| `br.engine_stack_vs_ua` | browser | coherence | 1 |
| `br.honeypot_interaction` | browser | automation | 1 |
| `br.iframe_divergence` | browser | automation | 1 |
| `br.language_vs_languages` | browser | coherence | 1 |
| `br.languages_worker_vs_main` | browser | coherence | 1 |
| `br.macos_dpr1` | browser | environment | 1 |
| `br.native_invariant_violated` | browser | artifact | 1 |
| `br.nav_property_spoofed` | browser | automation | 1 |
| `br.no_connection` | browser | environment | 1 |
| `br.notification_getter_tampered` | browser | automation | 1 |
| `br.plugins_spoofed` | browser | automation | 1 |
| `br.pointer_touch_incoherent` | browser | coherence | 1 |
| `br.productsub_vs_ua` | browser | coherence | 1 |
| `br.readback_noise` | browser | artifact | 1 |
| `br.webgl_not_angle` | browser | environment | 1 |
| `br.webgl_renderer_artifact` | browser | artifact | 1 |
| `br.worker_constructor_tampered` | browser | artifact | 1 |
| `net.ch_platform_header_vs_ua` | network,browser | coherence | 1 |
| `net.ch_ua_mobile_vs_ua` | network,browser | coherence | 1 |
| `net.ch_ua_no_grease_brand` | network | artifact | 1 |
| `net.h2_continuation_flood` | network | automation | 1 |
| `net.h2_rapid_reset` | network | automation | 1 |
| `net.h2_unknown_vs_ua` | network | coherence | 1 |

## Detection class — coherence/artifact = spoofing caught; environment/automation = headless too

| Evader | verdict | coherence | artifact | automation | environment | behavioral | reputation |
|---|---|---|---|---|---|---|---|
| `audio-readback-spoof` | bot | 0 | 1 | 7 | 6 | 1 | 0 |
| `baseline-firefox` | bot | 0 | 0 | 1 | 5 | 0 | 0 |
| `brave-fake` | bot | 0 | 1 | 7 | 6 | 1 | 0 |
| `brave` | bot | 0 | 1 | 3 | 4 | 2 | 0 |
| `camoufox-hardened` | bot | 1 | 0 | 0 | 4 | 0 | 0 |
| `camoufox-headful` | suspicious | 0 | 0 | 0 | 4 | 0 | 0 |
| `camoufox` | bot | 3 | 0 | 0 | 0 | 0 | 0 |
| `canvas-geometry-spoof` | bot | 0 | 1 | 7 | 6 | 1 | 0 |
| `canvas-spoof` | bot | 1 | 1 | 8 | 6 | 1 | 0 |
| `ch-ua-hardcoded` | bot | 5 | 1 | 0 | 0 | 0 | 0 |
| `chrome-clone-1` | bot | 0 | 0 | 6 | 6 | 2 | 0 |
| `chrome-clone-2` | bot | 0 | 0 | 6 | 6 | 2 | 0 |
| `curl-impersonate` | bot | 1 | 0 | 0 | 0 | 0 | 0 |
| `floor-spoof` | bot | 0 | 0 | 4 | 2 | 2 | 0 |
| `full-stealth` | bot | 4 | 0 | 7 | 5 | 1 | 0 |
| `go-tls` | bot | 3 | 0 | 0 | 0 | 0 | 0 |
| `h2-continuation-flood` | bot | 1 | 0 | 1 | 0 | 0 | 0 |
| `h2-rapid-reset` | bot | 1 | 0 | 1 | 0 | 0 | 0 |
| `honeypot` | bot | 0 | 0 | 8 | 6 | 2 | 0 |
| `human-mouse` | bot | 0 | 0 | 7 | 6 | 1 | 0 |
| `iframe-spoof` | bot | 5 | 0 | 8 | 8 | 1 | 0 |
| `ios-ua-spoof` | bot | 10 | 0 | 4 | 6 | 1 | 0 |
| `lang-list-spoof` | bot | 1 | 0 | 7 | 6 | 1 | 0 |
| `lang-spoof` | bot | 1 | 0 | 7 | 6 | 1 | 0 |
| `linear-bot` | bot | 0 | 0 | 7 | 6 | 5 | 0 |
| `max-stealth` | bot | 0 | 0 | 4 | 6 | 1 | 0 |
| `naive-tz-spoof` | bot | 3 | 0 | 7 | 6 | 1 | 0 |
| `native-spoof` | bot | 2 | 1 | 7 | 6 | 1 | 0 |
| `nodriver` | bot | 1 | 0 | 2 | 4 | 2 | 0 |
| `os-spoof` | bot | 4 | 0 | 5 | 8 | 0 | 0 |
| `patchright` | bot | 0 | 0 | 5 | 6 | 0 | 0 |
| `primp` | bot | 2 | 0 | 0 | 0 | 0 | 0 |
| `pydoll` | bot | 0 | 0 | 2 | 4 | 2 | 0 |
| `quic-no-grease` | bot | 5 | 0 | 0 | 0 | 0 | 0 |
| `rebrowser` | bot | 0 | 0 | 5 | 6 | 0 | 0 |
| `renderer-spoof` | bot | 1 | 1 | 8 | 7 | 1 | 0 |
| `selenium-driverless` | bot | 0 | 0 | 2 | 4 | 2 | 0 |
| `spoof-ua` | bot | 6 | 0 | 4 | 5 | 1 | 0 |
| `stealth-naive` | bot | 0 | 0 | 7 | 6 | 1 | 0 |
| `stealth-patched` | bot | 5 | 0 | 6 | 8 | 1 | 0 |
| `tls-stale-template` | bot | 6 | 0 | 0 | 0 | 0 | 0 |
| `tz-spoof` | bot | 3 | 0 | 7 | 6 | 1 | 0 |
| `undetected` | bot | 0 | 0 | 2 | 4 | 2 | 0 |
| `vanilla` | bot | 5 | 0 | 0 | 0 | 0 | 0 |
| `worker-spoof` | bot | 0 | 0 | 8 | 6 | 1 | 0 |
| `worker-wrap` | bot | 0 | 1 | 7 | 6 | 1 | 0 |
| `zendriver` | bot | 0 | 0 | 1 | 5 | 2 | 0 |

## Coverage gaps — 37/118 rules catch nothing yet

**Evaded** (7) — reads present in the corpus, but every sample passed:
- `net.tls_vs_ua_browser`
- `net.h2_vs_tls_browser`
- `net.accept_lang_vs_navigator`
- `net.h2_settings_vs_order`
- `br.low_hardware_concurrency`
- `br.oscpu_vs_ua`
- `br.font_os_vs_ua`

**Unexercised** (30) — a read signal is absent from every recording, so the corpus cannot trip them yet (e.g. signals the recordings predate); these are validated by the detector unit + precision tests, and need a corpus refresh to appear here:
- `net.tls_os_vs_tcp_os`
- `br.automation_globals`
- `br.electron_process`
- `br.screen_impossible`
- `net.quic_pq_keyshare_vs_ua`
- `net.h2_header_order_vs_ua`
- `br.csp_bypassed`
- `br.canvas_lie`
- `rep.datacenter_asn`
- `net.h2_control_flood`
- `rep.known_proxy_exit`
- `br.languages_empty`
- `br.screen_zero`
- `br.no_devicememory`
- `br.platform_empty`
- `br.cdc_artifacts`
- `br.screen_avail_invalid`
- `br.color_depth_anomaly`
- `br.devicepixelratio_anomaly`
- `br.voice_os_vs_ua`
- `br.engine_feature_vs_ua`
- `br.audio_missing`
- `br.audio_noise`
- `br.domrect_invariant`
- `br.measuretext_offscreen_vs`
- `br.adblock_present`
- `br.font_mac_internal`
- `net.webrtc_ip_vs_observed`
- `br.webgpu_vendor_vs_webgl`
- `br.rfp_browser`
