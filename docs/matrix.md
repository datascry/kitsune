# Kitsune detection matrix — 117 rules vs 71 evaders

_68/71 evaders caught (`bot`). Generated from the committed captures at ruleset `0.74.37`._

## Per-evader verdict — score and the convicting tells that caught each evader

| Evader | verdict | score | fired | convicting tells |
|---|---|---|---:|---|
| `accept-lang-spoof` | bot | 1.00 | 15/117 | `br.cdp_runtime_enabled`, `net.accept_lang_vs_navigator`, `br.headless_ua` +5 |
| `audio-noise` | bot | 1.00 | 14/117 | `br.cdp_runtime_enabled`, `br.headless_ua`, `br.ch_he_headless` +4 |
| `audio-readback-spoof` | bot | 1.00 | 14/117 | `br.cdp_runtime_enabled`, `br.headless_ua`, `br.ch_he_headless` +4 |
| `azuretls` | bot | 1.00 | 4/117 | `net.h2_header_order_vs_ua`, `net.tcp_os_vs_ua`, `net.no_js_execution` +1 |
| `baseline-firefox` | bot | 1.00 | 6/117 | `br.webdriver_present` |
| `brave-fake` | bot | 1.00 | 14/117 | `br.cdp_runtime_enabled`, `br.headless_ua`, `br.ch_he_headless` +4 |
| `brave` | bot | 1.00 | 9/117 | `br.webdriver_present`, `br.headless_ua`, `br.canvas_noise` |
| `camoufox-hardened` | bot | 0.98 | 5/117 | `br.pointer_touch_incoherent` |
| `camoufox-headful` | suspicious | 0.95 | 4/117 | — |
| `camoufox-macos` | bot | 1.00 | 7/117 | `net.tcp_os_vs_ua`, `br.font_mac_internal` |
| `camoufox` | bot | 1.00 | 3/117 | `net.tcp_os_vs_ua`, `net.no_js_execution`, `net.tls_grease_vs_ua` |
| `canvas-geometry-spoof` | bot | 1.00 | 14/117 | `br.cdp_runtime_enabled`, `br.headless_ua`, `br.ch_he_headless` +4 |
| `canvas-lie` | bot | 1.00 | 15/117 | `br.cdp_runtime_enabled`, `br.canvas_lie`, `br.headless_ua` +5 |
| `canvas-spoof` | bot | 1.00 | 16/117 | `br.cdp_runtime_enabled`, `br.headless_ua`, `br.ch_he_headless` +6 |
| `cdc-leak` | bot | 1.00 | 14/117 | `br.webdriver_present`, `br.cdp_runtime_enabled`, `br.headless_ua` +4 |
| `ch-ua-hardcoded` | bot | 1.00 | 6/117 | `net.tcp_os_vs_ua`, `net.no_js_execution`, `net.sec_fetch_vs_ua` +3 |
| `chrome-clone-1` | bot | 1.00 | 13/117 | `br.webdriver_present`, `br.cdp_runtime_enabled`, `br.headless_ua` +2 |
| `chrome-clone-2` | bot | 1.00 | 13/117 | `br.webdriver_present`, `br.cdp_runtime_enabled`, `br.headless_ua` +2 |
| `coalesce-proxy` | bot | 1.00 | 14/117 | `br.cdp_runtime_enabled`, `br.headless_ua`, `br.ch_he_headless` +4 |
| `coalesce-spoof` | bot | 1.00 | 14/117 | `br.cdp_runtime_enabled`, `br.headless_ua`, `br.ch_he_headless` +4 |
| `csp-bypass` | bot | 1.00 | 14/117 | `br.cdp_runtime_enabled`, `br.csp_bypassed`, `br.headless_ua` +4 |
| `curl-http2` | bot | 1.00 | 7/117 | `net.h2_unknown_vs_ua`, `net.h2_header_order_vs_ua`, `net.tcp_os_vs_ua` +4 |
| `curl-impersonate` | bot | 0.90 | 1/117 | `net.no_js_execution` |
| `domrect-spoof` | bot | 1.00 | 14/117 | `br.cdp_runtime_enabled`, `br.headless_ua`, `br.ch_he_headless` +4 |
| `electron-leak` | bot | 1.00 | 15/117 | `br.automation_globals`, `br.electron_process`, `br.cdp_runtime_enabled` +5 |
| `firefox-os-spoof` | bot | 1.00 | 12/117 | `br.webdriver_present`, `net.tcp_os_vs_ua`, `br.navplatform_vs_ua` +2 |
| `floor-spoof` | bot | 1.00 | 8/117 | `br.tostring_tampered`, `br.nav_property_spoofed`, `br.webdriver_getter_tampered` +1 |
| `font-os-leak` | bot | 1.00 | 18/117 | `br.cdp_runtime_enabled`, `net.ch_ua_version_vs_ua`, `net.tcp_os_vs_ua` +7 |
| `full-stealth` | bot | 1.00 | 16/117 | `br.cdp_runtime_enabled`, `net.ch_ua_version_vs_ua`, `br.ch_he_headless` +7 |
| `go-tls` | bot | 0.99 | 3/117 | `net.h2_unknown_vs_ua`, `net.no_js_execution`, `net.tls_pq_keyshare_vs_ua` |
| `h2-continuation-flood` | bot | 0.99 | 2/117 | `net.h2_continuation_flood`, `net.no_js_execution` |
| `h2-control-flood` | bot | 0.99 | 2/117 | `net.h2_control_flood`, `net.no_js_execution` |
| `h2-rapid-reset` | bot | 0.99 | 2/117 | `net.h2_rapid_reset`, `net.no_js_execution` |
| `h2-settings-split` | bot | 0.96 | 2/117 | `net.h2_settings_vs_order`, `net.no_js_execution` |
| `honeypot` | bot | 1.00 | 15/117 | `br.webdriver_present`, `br.cdp_runtime_enabled`, `br.honeypot_interaction` +4 |
| `http2-naive` | bot | 1.00 | 7/117 | `net.h2_header_order_vs_ua`, `net.h2_vs_tls_browser`, `net.tcp_os_vs_ua` +4 |
| `human-mouse` | bot | 1.00 | 13/117 | `br.webdriver_present`, `br.cdp_runtime_enabled`, `br.headless_ua` +3 |
| `iframe-spoof` | bot | 1.00 | 21/117 | `br.ua_platform_vs_ch_platform`, `br.cdp_runtime_enabled`, `net.ch_platform_header_vs_ua` +9 |
| `ios-ua-spoof` | bot | 1.00 | 22/117 | `net.tls_vs_ua_browser`, `net.h2_vs_ua_browser`, `br.ua_platform_vs_ch_platform` +11 |
| `lang-list-spoof` | bot | 1.00 | 14/117 | `br.cdp_runtime_enabled`, `br.headless_ua`, `br.ch_he_headless` +4 |
| `lang-spoof` | bot | 1.00 | 14/117 | `br.cdp_runtime_enabled`, `br.headless_ua`, `br.ch_he_headless` +4 |
| `linear-bot` | bot | 1.00 | 17/117 | `br.webdriver_present`, `br.cdp_runtime_enabled`, `br.headless_ua` +3 |
| `max-stealth` | bot | 1.00 | 10/117 | `br.webdriver_spoofed`, `br.permissions_anomaly`, `br.no_chrome_object` |
| `measuretext-spoof` | bot | 1.00 | 14/117 | `br.cdp_runtime_enabled`, `br.headless_ua`, `br.ch_he_headless` +4 |
| `naive-tz-spoof` | bot | 1.00 | 16/117 | `br.cdp_runtime_enabled`, `br.headless_ua`, `br.ch_he_headless` +6 |
| `native-spoof` | bot | 1.00 | 16/117 | `br.native_invariant_violated`, `br.cdp_runtime_enabled`, `br.headless_ua` +6 |
| `nodriver` | bot | 1.00 | 7/117 | `br.headless_ua` |
| `os-spoof` | bot | 1.00 | 16/117 | `br.cdp_runtime_enabled`, `net.ch_ua_version_vs_ua`, `net.tcp_os_vs_ua` +5 |
| `patchright-headful` | suspicious | 0.93 | 4/117 | — |
| `patchright` | bot | 1.00 | 10/117 | `br.headless_ua`, `br.ch_he_headless`, `br.permissions_anomaly` +1 |
| `primp` | bot | 0.97 | 2/117 | `net.tcp_os_vs_ua`, `net.no_js_execution` |
| `pydoll` | bot | 1.00 | 7/117 | `br.headless_ua` |
| `quic-no-grease` | bot | 1.00 | 4/117 | `net.no_js_execution`, `net.sec_fetch_vs_ua`, `net.accept_encoding_vs_ua` +1 |
| `rebrowser` | bot | 1.00 | 10/117 | `br.webdriver_present`, `br.headless_ua`, `br.permissions_anomaly` +1 |
| `renderer-spoof` | bot | 1.00 | 17/117 | `br.cdp_runtime_enabled`, `br.headless_ua`, `br.ch_he_headless` +6 |
| `screen-impossible` | bot | 1.00 | 15/117 | `br.screen_impossible`, `br.cdp_runtime_enabled`, `br.headless_ua` +4 |
| `selenium-driverless` | bot | 1.00 | 7/117 | `br.headless_ua` |
| `spoof-ua` | bot | 1.00 | 17/117 | `net.tls_vs_ua_browser`, `net.h2_vs_ua_browser`, `net.ch_ua_vs_ua_browser` +8 |
| `stale-engine` | bot | 1.00 | 15/117 | `br.cdp_runtime_enabled`, `net.ch_ua_version_vs_ua`, `br.ch_he_headless` +5 |
| `stealth-naive` | bot | 1.00 | 13/117 | `br.webdriver_present`, `br.cdp_runtime_enabled`, `br.headless_ua` +3 |
| `stealth-patched` | bot | 1.00 | 19/117 | `br.cdp_runtime_enabled`, `net.ch_ua_version_vs_ua`, `net.tcp_os_vs_ua` +7 |
| `tls-stale-template` | bot | 1.00 | 6/117 | `net.tcp_os_vs_ua`, `net.no_js_execution`, `net.sec_fetch_vs_ua` +3 |
| `tz-spoof` | bot | 1.00 | 16/117 | `br.cdp_runtime_enabled`, `br.headless_ua`, `br.ch_he_headless` +6 |
| `uach-coherent` | bot | 1.00 | 11/117 | `br.cdp_runtime_enabled`, `br.permissions_anomaly`, `br.no_chrome_object` +1 |
| `undetected` | bot | 1.00 | 7/117 | `br.headless_ua` |
| `vanilla` | bot | 1.00 | 5/117 | `net.tcp_os_vs_ua`, `net.no_js_execution`, `net.sec_fetch_vs_ua` +2 |
| `webkit-ua-spoof` | bot | 1.00 | 18/117 | `net.tls_vs_ua_browser`, `net.h2_unknown_vs_ua`, `net.h2_header_order_vs_ua` +8 |
| `worker-spoof` | bot | 1.00 | 14/117 | `br.cdp_runtime_enabled`, `br.headless_ua`, `br.ch_he_headless` +4 |
| `worker-wrap` | bot | 1.00 | 14/117 | `br.cdp_runtime_enabled`, `br.headless_ua`, `br.ch_he_headless` +4 |
| `zendriver-uach` | suspicious | 0.99 | 7/117 | — |
| `zendriver` | bot | 1.00 | 8/117 | `net.h2_header_order_vs_ua` |

## Per-rule coverage — 102/117 rules catch ≥1 evader (rest in Gaps)

| Detector | layer | category | catches |
|---|---|---|---:|
| `br.media_devices_empty` | browser | environment | 55 |
| `br.voices_empty` | browser | environment | 54 |
| `br.webgl_software` | browser | environment | 46 |
| `br.mimetypes_empty` | browser | environment | 42 |
| `br.no_plugins` | browser | environment | 42 |
| `br.permissions_anomaly` | browser | automation | 41 |
| `br.no_chrome_object` | browser | automation | 39 |
| `br.no_pdfviewer` | browser | environment | 39 |
| `br.cdp_runtime_enabled` | browser | automation | 36 |
| `br.headless_ua` | browser | automation | 36 |
| `br.ch_he_headless` | browser | automation | 35 |
| `bh.keystroke_entropy_floor` | behavioral | behavioral | 32 |
| `br.webdriver_getter_tampered` | browser | automation | 27 |
| `net.no_js_execution` | network,browser | coherence | 15 |
| `net.tcp_os_vs_ua` | network | coherence | 15 |
| `br.webdriver_present` | browser | automation | 12 |
| `bh.input_entropy_floor` | behavioral | behavioral | 11 |
| `bh.no_input_before_action` | behavioral | behavioral | 10 |
| `net.tls_grease_vs_ua` | network,browser | coherence | 9 |
| `br.hover_none_desktop` | browser | environment | 7 |
| `br.navplatform_vs_ua` | browser | coherence | 7 |
| `net.sec_fetch_vs_ua` | network,browser | coherence | 7 |
| `br.webdriver_spoofed` | browser | automation | 6 |
| `br.webgl2_missing` | browser | environment | 6 |
| `br.webgl_os_vs_ua` | browser | coherence | 6 |
| `net.accept_encoding_vs_ua` | network,browser | coherence | 6 |
| `bh.synthetic_no_coalesced` | behavioral | behavioral | 5 |
| `br.ch_he_version_vs_ua` | browser | coherence | 5 |
| `br.codec_os_incoherent` | browser | environment | 5 |
| `br.font_linux_leak` | browser | environment | 5 |
| `br.webrtc_unavailable` | browser | environment | 5 |
| `net.ch_ua_version_vs_ua` | network,browser | coherence | 5 |
| `net.h2_header_order_vs_ua` | network | coherence | 5 |
| `br.tostring_tampered` | browser | automation | 4 |
| `bh.path_too_straight` | behavioral | behavioral | 3 |
| `br.error_engine_vs_ua` | browser | coherence | 3 |
| `br.vendor_vs_ua` | browser | coherence | 3 |
| `br.webgl_worker_vs_main` | browser | coherence | 3 |
| `br.webgpu_webgl_vs` | browser | environment | 3 |
| `net.h2_unknown_vs_ua` | network | coherence | 3 |
| `net.tls_vs_ua_browser` | network,browser | coherence | 3 |
| `bh.power_law_violation` | behavioral | behavioral | 2 |
| `br.canvas_noise` | browser | artifact | 2 |
| `br.fingerprint_improbable` | browser | prevalence | 2 |
| `br.languages_worker_vs_main` | browser | coherence | 2 |
| `br.macos_dpr1` | browser | environment | 2 |
| `br.no_connection` | browser | environment | 2 |
| `br.timezone_inconsistent` | browser | coherence | 2 |
| `br.timezone_offset_vs_intl` | browser | coherence | 2 |
| `br.timezone_worker_vs_main` | browser | coherence | 2 |
| `br.ua_platform_vs_ch_platform` | browser | coherence | 2 |
| `br.webgl_getparameter_tampered` | browser | automation | 2 |
| `br.webgl_not_angle` | browser | environment | 2 |
| `br.worker_divergence` | browser | automation | 2 |
| `net.ch_ua_vs_ua_browser` | network,browser | coherence | 2 |
| `net.h2_vs_ua_browser` | network,browser | coherence | 2 |
| `net.tls_pq_keyshare_vs_ua` | network,browser | coherence | 2 |
| `bh.uniform_velocity` | behavioral | behavioral | 1 |
| `br.apple_ua_nonwebkit` | browser | coherence | 1 |
| `br.audio_noise` | browser | artifact | 1 |
| `br.automation_globals` | browser | automation | 1 |
| `br.brave_spoofed` | browser | artifact | 1 |
| `br.canvas_geometry_noise` | browser | artifact | 1 |
| `br.canvas_lie` | browser | automation | 1 |
| `br.canvas_worker_vs_main` | browser | coherence | 1 |
| `br.cdc_artifacts` | browser | automation | 1 |
| `br.coalesced_untrusted` | browser | artifact | 1 |
| `br.csp_bypassed` | browser | automation | 1 |
| `br.domrect_invariant` | browser | artifact | 1 |
| `br.electron_process` | browser | automation | 1 |
| `br.engine_feature_vs_ua` | browser | coherence | 1 |
| `br.engine_stack_vs_ua` | browser | coherence | 1 |
| `br.firefox_ua_nongecko` | browser | coherence | 1 |
| `br.font_mac_internal` | browser | artifact | 1 |
| `br.font_os_vs_ua` | browser | coherence | 1 |
| `br.honeypot_interaction` | browser | automation | 1 |
| `br.iframe_divergence` | browser | automation | 1 |
| `br.language_vs_languages` | browser | coherence | 1 |
| `br.measuretext_offscreen_vs` | browser | artifact | 1 |
| `br.native_invariant_violated` | browser | artifact | 1 |
| `br.nav_property_spoofed` | browser | automation | 1 |
| `br.no_devicememory` | browser | environment | 1 |
| `br.notification_getter_tampered` | browser | automation | 1 |
| `br.oscpu_vs_ua` | browser | coherence | 1 |
| `br.plugins_spoofed` | browser | automation | 1 |
| `br.pointer_touch_incoherent` | browser | coherence | 1 |
| `br.productsub_vs_ua` | browser | coherence | 1 |
| `br.readback_noise` | browser | artifact | 1 |
| `br.safari_ua_no_webkit_api` | browser | coherence | 1 |
| `br.screen_avail_invalid` | browser | environment | 1 |
| `br.screen_impossible` | browser | artifact | 1 |
| `br.webgl_renderer_artifact` | browser | artifact | 1 |
| `br.worker_constructor_tampered` | browser | artifact | 1 |
| `net.accept_lang_vs_navigator` | network,browser | coherence | 1 |
| `net.ch_platform_header_vs_ua` | network,browser | coherence | 1 |
| `net.ch_ua_mobile_vs_ua` | network,browser | coherence | 1 |
| `net.ch_ua_no_grease_brand` | network | artifact | 1 |
| `net.h2_continuation_flood` | network | automation | 1 |
| `net.h2_control_flood` | network | automation | 1 |
| `net.h2_rapid_reset` | network | automation | 1 |
| `net.h2_settings_vs_order` | network | coherence | 1 |
| `net.h2_vs_tls_browser` | network | coherence | 1 |

## Detection class — coherence/artifact = spoofing caught; environment/automation = headless too

| Evader | verdict | coherence | artifact | automation | environment | behavioral | reputation |
|---|---|---|---|---|---|---|---|
| `accept-lang-spoof` | bot | 2 | 0 | 6 | 6 | 1 | 0 |
| `audio-noise` | bot | 0 | 1 | 6 | 6 | 1 | 0 |
| `audio-readback-spoof` | bot | 0 | 1 | 6 | 6 | 1 | 0 |
| `azuretls` | bot | 4 | 0 | 0 | 0 | 0 | 0 |
| `baseline-firefox` | bot | 0 | 0 | 1 | 5 | 0 | 0 |
| `brave-fake` | bot | 0 | 1 | 6 | 6 | 1 | 0 |
| `brave` | bot | 0 | 1 | 2 | 4 | 2 | 0 |
| `camoufox-hardened` | bot | 1 | 0 | 0 | 4 | 0 | 0 |
| `camoufox-headful` | suspicious | 0 | 0 | 0 | 4 | 0 | 0 |
| `camoufox-macos` | bot | 1 | 1 | 0 | 5 | 0 | 0 |
| `camoufox` | bot | 3 | 0 | 0 | 0 | 0 | 0 |
| `canvas-geometry-spoof` | bot | 0 | 1 | 6 | 6 | 1 | 0 |
| `canvas-lie` | bot | 0 | 0 | 8 | 6 | 1 | 0 |
| `canvas-spoof` | bot | 1 | 1 | 7 | 6 | 1 | 0 |
| `cdc-leak` | bot | 0 | 0 | 7 | 6 | 1 | 0 |
| `ch-ua-hardcoded` | bot | 5 | 1 | 0 | 0 | 0 | 0 |
| `chrome-clone-1` | bot | 0 | 0 | 5 | 6 | 2 | 0 |
| `chrome-clone-2` | bot | 0 | 0 | 5 | 6 | 2 | 0 |
| `coalesce-proxy` | bot | 0 | 1 | 6 | 6 | 1 | 0 |
| `coalesce-spoof` | bot | 0 | 0 | 7 | 6 | 1 | 0 |
| `csp-bypass` | bot | 0 | 0 | 7 | 6 | 1 | 0 |
| `curl-http2` | bot | 7 | 0 | 0 | 0 | 0 | 0 |
| `curl-impersonate` | bot | 1 | 0 | 0 | 0 | 0 | 0 |
| `domrect-spoof` | bot | 0 | 1 | 6 | 6 | 1 | 0 |
| `electron-leak` | bot | 0 | 0 | 8 | 6 | 1 | 0 |
| `firefox-os-spoof` | bot | 4 | 0 | 1 | 6 | 1 | 0 |
| `floor-spoof` | bot | 0 | 0 | 4 | 2 | 2 | 0 |
| `font-os-leak` | bot | 5 | 0 | 5 | 8 | 0 | 0 |
| `full-stealth` | bot | 4 | 0 | 6 | 5 | 1 | 0 |
| `go-tls` | bot | 3 | 0 | 0 | 0 | 0 | 0 |
| `h2-continuation-flood` | bot | 1 | 0 | 1 | 0 | 0 | 0 |
| `h2-control-flood` | bot | 1 | 0 | 1 | 0 | 0 | 0 |
| `h2-rapid-reset` | bot | 1 | 0 | 1 | 0 | 0 | 0 |
| `h2-settings-split` | bot | 2 | 0 | 0 | 0 | 0 | 0 |
| `honeypot` | bot | 0 | 0 | 7 | 6 | 2 | 0 |
| `http2-naive` | bot | 7 | 0 | 0 | 0 | 0 | 0 |
| `human-mouse` | bot | 0 | 0 | 6 | 6 | 1 | 0 |
| `iframe-spoof` | bot | 5 | 0 | 7 | 8 | 1 | 0 |
| `ios-ua-spoof` | bot | 11 | 0 | 3 | 6 | 1 | 0 |
| `lang-list-spoof` | bot | 1 | 0 | 6 | 6 | 1 | 0 |
| `lang-spoof` | bot | 1 | 0 | 6 | 6 | 1 | 0 |
| `linear-bot` | bot | 0 | 0 | 6 | 6 | 5 | 0 |
| `max-stealth` | bot | 0 | 0 | 3 | 6 | 1 | 0 |
| `measuretext-spoof` | bot | 0 | 1 | 6 | 6 | 1 | 0 |
| `naive-tz-spoof` | bot | 3 | 0 | 6 | 6 | 1 | 0 |
| `native-spoof` | bot | 2 | 1 | 6 | 6 | 1 | 0 |
| `nodriver` | bot | 0 | 0 | 1 | 4 | 2 | 0 |
| `os-spoof` | bot | 4 | 0 | 4 | 8 | 0 | 0 |
| `patchright-headful` | suspicious | 0 | 0 | 0 | 3 | 1 | 0 |
| `patchright` | bot | 0 | 0 | 4 | 6 | 0 | 0 |
| `primp` | bot | 2 | 0 | 0 | 0 | 0 | 0 |
| `pydoll` | bot | 0 | 0 | 1 | 4 | 2 | 0 |
| `quic-no-grease` | bot | 4 | 0 | 0 | 0 | 0 | 0 |
| `rebrowser` | bot | 0 | 0 | 4 | 6 | 0 | 0 |
| `renderer-spoof` | bot | 1 | 1 | 7 | 7 | 1 | 0 |
| `screen-impossible` | bot | 0 | 1 | 6 | 7 | 1 | 0 |
| `selenium-driverless` | bot | 0 | 0 | 1 | 4 | 2 | 0 |
| `spoof-ua` | bot | 8 | 0 | 3 | 5 | 1 | 0 |
| `stale-engine` | bot | 3 | 0 | 5 | 6 | 1 | 0 |
| `stealth-naive` | bot | 0 | 0 | 6 | 6 | 1 | 0 |
| `stealth-patched` | bot | 5 | 0 | 5 | 8 | 1 | 0 |
| `tls-stale-template` | bot | 6 | 0 | 0 | 0 | 0 | 0 |
| `tz-spoof` | bot | 3 | 0 | 6 | 6 | 1 | 0 |
| `uach-coherent` | bot | 0 | 0 | 4 | 6 | 1 | 0 |
| `undetected` | bot | 0 | 0 | 1 | 4 | 2 | 0 |
| `vanilla` | bot | 5 | 0 | 0 | 0 | 0 | 0 |
| `webkit-ua-spoof` | bot | 9 | 0 | 2 | 4 | 2 | 0 |
| `worker-spoof` | bot | 0 | 0 | 7 | 6 | 1 | 0 |
| `worker-wrap` | bot | 0 | 1 | 6 | 6 | 1 | 0 |
| `zendriver-uach` | suspicious | 0 | 0 | 0 | 5 | 2 | 0 |
| `zendriver` | bot | 1 | 0 | 0 | 5 | 2 | 0 |

## Coverage gaps — 15/117 rules catch nothing yet

**Evaded** (1) — reads present in the corpus, but every sample passed:
- `br.low_hardware_concurrency`

**Unexercised** (14) — a read signal is absent from every recording, so the corpus cannot trip them yet (e.g. signals the recordings predate); these are validated by the detector unit + precision tests, and need a corpus refresh to appear here:
- `net.tls_os_vs_tcp_os`
- `rep.datacenter_asn`
- `rep.known_proxy_exit`
- `br.languages_empty`
- `br.screen_zero`
- `br.platform_empty`
- `br.color_depth_anomaly`
- `br.devicepixelratio_anomaly`
- `br.voice_os_vs_ua`
- `br.audio_missing`
- `br.adblock_present`
- `net.webrtc_ip_vs_observed`
- `br.webgpu_vendor_vs_webgl`
- `br.rfp_browser`
