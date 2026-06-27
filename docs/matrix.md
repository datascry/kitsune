# Kitsune detection matrix — 138 rules vs 102 evaders

_92/102 evaders caught (`bot`). Generated from the committed captures at ruleset `0.74.52`._

## Per-evader verdict — score and the convicting tells that caught each evader

| Evader | verdict | score | fired | convicting tells |
|---|---|---|---:|---|
| `accept-lang-spoof` | bot | 1.00 | 15/138 | `br.cdp_runtime_enabled`, `net.accept_lang_vs_navigator`, `br.headless_ua` +5 |
| `apify-fp-inject` | bot | 1.00 | 14/138 | `br.cdp_runtime_enabled`, `br.permissions_anomaly`, `br.no_chrome_object` +3 |
| `audio-noise` | bot | 1.00 | 14/138 | `br.cdp_runtime_enabled`, `br.headless_ua`, `br.ch_he_headless` +4 |
| `audio-readback-spoof` | bot | 1.00 | 14/138 | `br.cdp_runtime_enabled`, `br.headless_ua`, `br.ch_he_headless` +4 |
| `azuretls` | bot | 1.00 | 4/138 | `net.h2_header_order_vs_ua`, `net.tcp_os_vs_ua`, `net.no_js_execution` +1 |
| `baseline-firefox` | bot | 1.00 | 6/138 | `br.webdriver_present` |
| `brave-fake-proxy` | bot | 1.00 | 14/138 | `br.cdp_runtime_enabled`, `br.headless_ua`, `br.ch_he_headless` +4 |
| `brave-fake` | bot | 1.00 | 14/138 | `br.cdp_runtime_enabled`, `br.headless_ua`, `br.ch_he_headless` +4 |
| `brave` | bot | 1.00 | 8/138 | `br.webdriver_present`, `br.headless_ua` |
| `camoufox-hardened-behave` | suspicious | 0.97 | 5/138 | — |
| `camoufox-hardened` | suspicious | 0.99 | 6/138 | — |
| `camoufox-headful` | suspicious | 0.95 | 4/138 | — |
| `camoufox-linux-coherent` | suspicious | 0.99 | 6/138 | — |
| `camoufox-linux` | suspicious | 0.99 | 6/138 | — |
| `camoufox-macos` | bot | 1.00 | 7/138 | `net.tcp_os_vs_ua`, `br.font_mac_internal` |
| `camoufox-socks-webrtc` | suspicious | 0.97 | 5/138 | — |
| `camoufox-touch-incoherent` | bot | 0.99 | 6/138 | `br.pointer_touch_incoherent` |
| `camoufox` | bot | 1.00 | 3/138 | `net.tcp_os_vs_ua`, `net.no_js_execution`, `net.tls_grease_vs_ua` |
| `canvas-geometry-spoof` | bot | 1.00 | 14/138 | `br.cdp_runtime_enabled`, `br.headless_ua`, `br.ch_he_headless` +4 |
| `canvas-lie` | bot | 1.00 | 15/138 | `br.cdp_runtime_enabled`, `br.canvas_lie`, `br.headless_ua` +5 |
| `canvas-spoof` | bot | 1.00 | 16/138 | `br.cdp_runtime_enabled`, `br.headless_ua`, `br.ch_he_headless` +6 |
| `cdc-leak` | bot | 1.00 | 14/138 | `br.webdriver_present`, `br.cdp_runtime_enabled`, `br.headless_ua` +4 |
| `ch-ua-hardcoded` | bot | 1.00 | 6/138 | `net.tcp_os_vs_ua`, `net.no_js_execution`, `net.sec_fetch_vs_ua` +3 |
| `chrome-clone-1` | bot | 1.00 | 13/138 | `br.webdriver_present`, `br.cdp_runtime_enabled`, `br.headless_ua` +2 |
| `chrome-clone-2` | bot | 1.00 | 13/138 | `br.webdriver_present`, `br.cdp_runtime_enabled`, `br.headless_ua` +2 |
| `coalesce-proxy` | bot | 1.00 | 14/138 | `br.cdp_runtime_enabled`, `br.headless_ua`, `br.ch_he_headless` +4 |
| `coalesce-spoof` | bot | 1.00 | 14/138 | `br.cdp_runtime_enabled`, `br.headless_ua`, `br.ch_he_headless` +4 |
| `csp-bypass` | bot | 1.00 | 14/138 | `br.cdp_runtime_enabled`, `br.csp_bypassed`, `br.headless_ua` +4 |
| `curl-http2` | bot | 1.00 | 7/138 | `net.h2_unknown_vs_ua`, `net.h2_header_order_vs_ua`, `net.tcp_os_vs_ua` +4 |
| `curl-impersonate` | bot | 0.90 | 1/138 | `net.no_js_execution` |
| `datacenter-origin-proxied` | bot | 1.00 | 7/138 | `net.datacenter_origin_proxied` |
| `domrect-spoof` | bot | 1.00 | 14/138 | `br.cdp_runtime_enabled`, `br.headless_ua`, `br.ch_he_headless` +4 |
| `electron-leak` | bot | 1.00 | 15/138 | `br.automation_globals`, `br.electron_process`, `br.cdp_runtime_enabled` +5 |
| `firefox-coherent` | bot | 1.00 | 10/138 | `br.webdriver_present` |
| `firefox-os-spoof` | bot | 1.00 | 12/138 | `br.webdriver_present`, `net.tcp_os_vs_ua`, `br.navplatform_vs_ua` +2 |
| `floor-spoof` | bot | 1.00 | 8/138 | `br.tostring_tampered`, `br.nav_property_spoofed`, `br.webdriver_getter_tampered` +1 |
| `font-os-leak` | bot | 1.00 | 18/138 | `br.cdp_runtime_enabled`, `net.ch_ua_version_vs_ua`, `net.tcp_os_vs_ua` +7 |
| `fp-rotation` | bot | 1.00 | 7/138 | `br.fingerprint_unstable_within_session` |
| `full-stealth` | bot | 1.00 | 16/138 | `br.cdp_runtime_enabled`, `net.ch_ua_version_vs_ua`, `br.ch_he_headless` +7 |
| `go-tls-h2-rotate` | bot | 0.99 | 3/138 | `net.h2_unknown_vs_ua`, `net.h2_unstable_within_session`, `net.no_js_execution` |
| `go-tls-madeyoureset` | bot | 1.00 | 6/138 | `net.h2_unknown_vs_ua`, `net.h2_header_order_vs_ua`, `net.h2_madeyoureset` +3 |
| `go-tls-rotate` | bot | 1.00 | 5/138 | `net.h2_unknown_vs_ua`, `net.ja4_unstable_within_session`, `net.no_js_execution` +2 |
| `go-tls-static-ext` | bot | 1.00 | 4/138 | `net.h2_unknown_vs_ua`, `net.tls_ext_order_static_within_session`, `net.no_js_execution` +1 |
| `go-tls-web-bot-auth-replay` | bot | 0.98 | 2/138 | `net.web_bot_auth_nonce_replay`, `net.no_js_execution` |
| `go-tls-web-bot-auth` | bot | 0.98 | 2/138 | `net.web_bot_auth_invalid`, `net.no_js_execution` |
| `go-tls` | bot | 0.99 | 3/138 | `net.h2_unknown_vs_ua`, `net.no_js_execution`, `net.tls_pq_keyshare_vs_ua` |
| `h2-continuation-flood` | bot | 0.99 | 2/138 | `net.h2_continuation_flood`, `net.no_js_execution` |
| `h2-control-flood` | bot | 0.99 | 2/138 | `net.h2_control_flood`, `net.no_js_execution` |
| `h2-rapid-reset` | bot | 0.99 | 2/138 | `net.h2_rapid_reset`, `net.no_js_execution` |
| `h2-settings-split` | bot | 0.96 | 2/138 | `net.h2_settings_vs_order`, `net.no_js_execution` |
| `honeypot` | bot | 1.00 | 15/138 | `br.webdriver_present`, `br.cdp_runtime_enabled`, `br.honeypot_interaction` +4 |
| `http2-naive` | bot | 1.00 | 7/138 | `net.h2_header_order_vs_ua`, `net.h2_vs_tls_browser`, `net.tcp_os_vs_ua` +4 |
| `human-mouse` | bot | 1.00 | 13/138 | `br.webdriver_present`, `br.cdp_runtime_enabled`, `br.headless_ua` +3 |
| `iframe-spoof` | bot | 1.00 | 21/138 | `br.ua_platform_vs_ch_platform`, `br.cdp_runtime_enabled`, `net.ch_platform_header_vs_ua` +9 |
| `ios-ua-spoof` | bot | 1.00 | 22/138 | `net.tls_vs_ua_browser`, `net.h2_vs_ua_browser`, `br.ua_platform_vs_ch_platform` +11 |
| `ip-rotation` | bot | 1.00 | 5/138 | `net.ip_rotation_within_session`, `net.no_js_execution`, `net.sec_fetch_vs_ua` +2 |
| `keystroke-human` | bot | 1.00 | 14/138 | `br.cdp_runtime_enabled`, `br.headless_ua`, `br.ch_he_headless` +3 |
| `lang-list-spoof` | bot | 1.00 | 14/138 | `br.cdp_runtime_enabled`, `br.headless_ua`, `br.ch_he_headless` +4 |
| `lang-spoof` | bot | 1.00 | 14/138 | `br.cdp_runtime_enabled`, `br.headless_ua`, `br.ch_he_headless` +4 |
| `linear-bot` | bot | 1.00 | 17/138 | `br.webdriver_present`, `br.cdp_runtime_enabled`, `br.headless_ua` +3 |
| `max-stealth` | bot | 1.00 | 10/138 | `br.webdriver_spoofed`, `br.permissions_anomaly`, `br.no_chrome_object` |
| `measuretext-spoof` | bot | 1.00 | 14/138 | `br.cdp_runtime_enabled`, `br.headless_ua`, `br.ch_he_headless` +4 |
| `mobile-emulation` | bot | 1.00 | 14/138 | `br.webdriver_present`, `br.cdp_runtime_enabled`, `br.ch_he_headless` +3 |
| `naive-tz-spoof` | bot | 1.00 | 16/138 | `br.cdp_runtime_enabled`, `br.headless_ua`, `br.ch_he_headless` +6 |
| `native-spoof` | bot | 1.00 | 16/138 | `br.native_invariant_violated`, `br.cdp_runtime_enabled`, `br.headless_ua` +6 |
| `nodriver` | bot | 1.00 | 7/138 | `br.headless_ua` |
| `os-spoof` | bot | 1.00 | 16/138 | `br.cdp_runtime_enabled`, `net.ch_ua_version_vs_ua`, `net.tcp_os_vs_ua` +5 |
| `patchright-headful` | suspicious | 0.93 | 4/138 | — |
| `patchright` | bot | 1.00 | 10/138 | `br.headless_ua`, `br.ch_he_headless`, `br.permissions_anomaly` +1 |
| `playwright-extra-coherent` | bot | 1.00 | 12/138 | `br.cdp_runtime_enabled`, `br.ch_he_headless`, `br.worker_divergence` +2 |
| `playwright-extra` | bot | 1.00 | 14/138 | `br.cdp_runtime_enabled`, `net.tcp_os_vs_ua`, `br.ch_he_headless` +3 |
| `primp` | bot | 0.97 | 2/138 | `net.tcp_os_vs_ua`, `net.no_js_execution` |
| `pydoll` | bot | 1.00 | 7/138 | `br.headless_ua` |
| `quic-no-grease` | bot | 1.00 | 4/138 | `net.no_js_execution`, `net.sec_fetch_vs_ua`, `net.accept_encoding_vs_ua` +1 |
| `rebrowser` | bot | 1.00 | 10/138 | `br.webdriver_present`, `br.headless_ua`, `br.permissions_anomaly` +1 |
| `renderer-spoof` | bot | 1.00 | 17/138 | `br.cdp_runtime_enabled`, `br.headless_ua`, `br.ch_he_headless` +6 |
| `screen-impossible` | bot | 1.00 | 15/138 | `br.screen_impossible`, `br.cdp_runtime_enabled`, `br.headless_ua` +4 |
| `selenium-driverless` | bot | 1.00 | 7/138 | `br.headless_ua` |
| `spoof-ua` | bot | 1.00 | 17/138 | `net.tls_vs_ua_browser`, `net.h2_vs_ua_browser`, `net.ch_ua_vs_ua_browser` +8 |
| `stale-engine` | bot | 1.00 | 15/138 | `br.cdp_runtime_enabled`, `net.ch_ua_version_vs_ua`, `br.ch_he_headless` +5 |
| `stealth-naive` | bot | 1.00 | 13/138 | `br.webdriver_present`, `br.cdp_runtime_enabled`, `br.headless_ua` +3 |
| `stealth-patched` | bot | 1.00 | 19/138 | `br.cdp_runtime_enabled`, `net.ch_ua_version_vs_ua`, `net.tcp_os_vs_ua` +7 |
| `tls-stale-template` | bot | 1.00 | 6/138 | `net.tcp_os_vs_ua`, `net.no_js_execution`, `net.sec_fetch_vs_ua` +3 |
| `trace-replay` | bot | 1.00 | 13/138 | `bh.trace_replay_within_session`, `br.cdp_runtime_enabled`, `br.headless_ua` +4 |
| `tz-spoof` | bot | 1.00 | 16/138 | `br.cdp_runtime_enabled`, `br.headless_ua`, `br.ch_he_headless` +6 |
| `ua-rotation` | bot | 1.00 | 8/138 | `net.h2_unknown_vs_ua`, `net.h2_header_order_vs_ua`, `net.ua_rotation_within_session` +5 |
| `uach-coherent` | bot | 1.00 | 11/138 | `br.cdp_runtime_enabled`, `br.permissions_anomaly`, `br.no_chrome_object` +1 |
| `undetected` | bot | 1.00 | 7/138 | `br.headless_ua` |
| `vanilla` | bot | 1.00 | 5/138 | `net.tcp_os_vs_ua`, `net.no_js_execution`, `net.sec_fetch_vs_ua` +2 |
| `webgl-caps-worker-spoof` | bot | 1.00 | 12/138 | `br.automation_globals`, `net.tls_ext_order_static_within_session`, `br.webdriver_present` +3 |
| `webgl-renderer-spoof` | bot | 1.00 | 21/138 | `br.automation_globals`, `net.tls_ext_order_static_within_session`, `br.webdriver_present` +9 |
| `webkit-safari-coherent` | bot | 1.00 | 9/138 | `net.h2_unknown_vs_ua`, `br.webdriver_present`, `net.tcp_os_vs_ua` +3 |
| `webkit-ua-spoof` | bot | 1.00 | 18/138 | `net.tls_vs_ua_browser`, `net.h2_unknown_vs_ua`, `net.h2_header_order_vs_ua` +8 |
| `webrtc-leak` | suspicious | 1.00 | 5/138 | — |
| `webrtc-origin-datacenter` | bot | 1.00 | 7/138 | `net.datacenter_origin_proxied` |
| `worker-proxy-fix` | bot | 1.00 | 14/138 | `br.cdp_runtime_enabled`, `br.headless_ua`, `br.ch_he_headless` +4 |
| `worker-proxy` | bot | 1.00 | 14/138 | `br.cdp_runtime_enabled`, `br.headless_ua`, `br.ch_he_headless` +4 |
| `worker-spoof` | bot | 1.00 | 14/138 | `br.cdp_runtime_enabled`, `br.headless_ua`, `br.ch_he_headless` +4 |
| `worker-wrap` | bot | 1.00 | 14/138 | `br.cdp_runtime_enabled`, `br.headless_ua`, `br.ch_he_headless` +4 |
| `zendriver-uach-behave` | suspicious | 0.99 | 6/138 | — |
| `zendriver-uach` | suspicious | 0.99 | 7/138 | — |
| `zendriver` | bot | 1.00 | 8/138 | `net.h2_header_order_vs_ua` |

## Per-rule coverage — 118/138 rules catch ≥1 evader (rest in Gaps)

| Detector | layer | category | catches |
|---|---|---|---:|
| `br.media_devices_empty` | browser | environment | 78 |
| `br.voices_empty` | browser | environment | 76 |
| `br.webgl_software` | browser | environment | 55 |
| `br.mimetypes_empty` | browser | environment | 50 |
| `br.no_plugins` | browser | environment | 50 |
| `br.permissions_anomaly` | browser | automation | 49 |
| `br.no_pdfviewer` | browser | environment | 48 |
| `br.cdp_runtime_enabled` | browser | automation | 47 |
| `br.no_chrome_object` | browser | automation | 47 |
| `br.ch_he_headless` | browser | automation | 44 |
| `br.headless_ua` | browser | automation | 42 |
| `bh.keystroke_entropy_floor` | behavioral | behavioral | 35 |
| `br.webdriver_getter_tampered` | browser | automation | 30 |
| `net.no_js_execution` | network,browser | coherence | 23 |
| `bh.input_entropy_floor` | behavioral | behavioral | 18 |
| `net.tcp_os_vs_ua` | network | coherence | 18 |
| `bh.synthetic_no_coalesced` | behavioral | behavioral | 17 |
| `br.webdriver_present` | browser | automation | 17 |
| `bh.no_input_before_action` | behavioral | behavioral | 16 |
| `br.webgl2_missing` | browser | environment | 16 |
| `net.tls_grease_vs_ua` | network,browser | coherence | 13 |
| `br.webrtc_unavailable` | browser | environment | 12 |
| `net.sec_fetch_vs_ua` | network,browser | coherence | 10 |
| `br.hover_none_desktop` | browser | environment | 9 |
| `net.accept_encoding_vs_ua` | network,browser | coherence | 9 |
| `net.h2_unknown_vs_ua` | network | coherence | 9 |
| `bh.power_law_violation` | behavioral | behavioral | 8 |
| `br.navplatform_vs_ua` | browser | coherence | 8 |
| `br.webdriver_spoofed` | browser | automation | 8 |
| `bh.path_too_straight` | behavioral | behavioral | 7 |
| `br.font_linux_leak` | browser | environment | 7 |
| `br.webgl_os_vs_ua` | browser | coherence | 7 |
| `br.webgl_worker_vs_main` | browser | coherence | 7 |
| `net.h2_header_order_vs_ua` | network | coherence | 7 |
| `br.codec_os_incoherent` | browser | environment | 6 |
| `br.webgpu_webgl_vs` | browser | environment | 6 |
| `br.ch_he_version_vs_ua` | browser | coherence | 5 |
| `br.languages_worker_vs_main` | browser | coherence | 5 |
| `br.worker_divergence` | browser | automation | 5 |
| `net.ch_ua_version_vs_ua` | network,browser | coherence | 5 |
| `br.tostring_tampered` | browser | automation | 4 |
| `br.webgl_getparameter_tampered` | browser | automation | 4 |
| `br.webgl_not_angle` | browser | environment | 4 |
| `net.tls_pq_keyshare_vs_ua` | network,browser | coherence | 4 |
| `br.automation_globals` | browser | automation | 3 |
| `br.error_engine_vs_ua` | browser | coherence | 3 |
| `br.fingerprint_improbable` | browser | prevalence | 3 |
| `br.font_os_vs_ua` | browser | coherence | 3 |
| `br.macos_dpr1` | browser | environment | 3 |
| `br.vendor_vs_ua` | browser | coherence | 3 |
| `net.tls_ext_order_static_within_session` | network | coherence | 3 |
| `net.tls_vs_ua_browser` | network,browser | coherence | 3 |
| `net.webrtc_ip_vs_observed` | network,browser | reputation | 3 |
| `br.brave_spoofed` | browser | artifact | 2 |
| `br.no_connection` | browser | environment | 2 |
| `br.timezone_inconsistent` | browser | coherence | 2 |
| `br.timezone_offset_vs_intl` | browser | coherence | 2 |
| `br.timezone_worker_vs_main` | browser | coherence | 2 |
| `br.ua_platform_vs_ch_platform` | browser | coherence | 2 |
| `br.worker_constructor_tampered` | browser | artifact | 2 |
| `net.ch_ua_vs_ua_browser` | network,browser | coherence | 2 |
| `net.datacenter_origin_proxied` | network,browser,reputation | coherence | 2 |
| `net.h2_vs_ua_browser` | network,browser | coherence | 2 |
| `rep.webrtc_origin_datacenter` | reputation | reputation | 2 |
| `bh.trace_replay_within_session` | behavioral | coherence | 1 |
| `bh.uniform_velocity` | behavioral | behavioral | 1 |
| `br.apple_ua_nonwebkit` | browser | coherence | 1 |
| `br.audio_noise` | browser | artifact | 1 |
| `br.canvas_geometry_noise` | browser | artifact | 1 |
| `br.canvas_lie` | browser | automation | 1 |
| `br.canvas_noise` | browser | artifact | 1 |
| `br.canvas_worker_vs_main` | browser | coherence | 1 |
| `br.cdc_artifacts` | browser | automation | 1 |
| `br.coalesced_untrusted` | browser | artifact | 1 |
| `br.csp_bypassed` | browser | automation | 1 |
| `br.domrect_invariant` | browser | artifact | 1 |
| `br.electron_process` | browser | automation | 1 |
| `br.engine_feature_vs_ua` | browser | coherence | 1 |
| `br.engine_stack_vs_ua` | browser | coherence | 1 |
| `br.fingerprint_unstable_within_session` | browser | coherence | 1 |
| `br.firefox_ua_nongecko` | browser | coherence | 1 |
| `br.font_mac_internal` | browser | artifact | 1 |
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
| `br.webgl_caps_worker_vs_main` | browser | coherence | 1 |
| `br.webgl_renderer_artifact` | browser | artifact | 1 |
| `br.webgl_renderer_caps_mismatch` | browser | coherence | 1 |
| `br.worker_source_rewritten` | browser | artifact | 1 |
| `net.accept_lang_vs_navigator` | network,browser | coherence | 1 |
| `net.ch_platform_header_vs_ua` | network,browser | coherence | 1 |
| `net.ch_ua_mobile_vs_ua` | network,browser | coherence | 1 |
| `net.ch_ua_no_grease_brand` | network | artifact | 1 |
| `net.h2_continuation_flood` | network | automation | 1 |
| `net.h2_control_flood` | network | automation | 1 |
| `net.h2_madeyoureset` | network | automation | 1 |
| `net.h2_rapid_reset` | network | automation | 1 |
| `net.h2_settings_vs_order` | network | coherence | 1 |
| `net.h2_unstable_within_session` | network | coherence | 1 |
| `net.h2_vs_tls_browser` | network | coherence | 1 |
| `net.ip_rotation_within_session` | network | coherence | 1 |
| `net.ja4_unstable_within_session` | network | coherence | 1 |
| `net.ua_rotation_within_session` | network | coherence | 1 |
| `net.web_bot_auth_invalid` | network | coherence | 1 |
| `net.web_bot_auth_nonce_replay` | network | coherence | 1 |

## Detection class — coherence/artifact = spoofing caught; environment/automation = headless too

| Evader | verdict | coherence | artifact | automation | environment | behavioral | reputation |
|---|---|---|---|---|---|---|---|
| `accept-lang-spoof` | bot | 2 | 0 | 6 | 6 | 1 | 0 |
| `apify-fp-inject` | bot | 2 | 0 | 4 | 6 | 2 | 0 |
| `audio-noise` | bot | 0 | 1 | 6 | 6 | 1 | 0 |
| `audio-readback-spoof` | bot | 0 | 1 | 6 | 6 | 1 | 0 |
| `azuretls` | bot | 4 | 0 | 0 | 0 | 0 | 0 |
| `baseline-firefox` | bot | 0 | 0 | 1 | 5 | 0 | 0 |
| `brave-fake-proxy` | bot | 0 | 1 | 6 | 6 | 1 | 0 |
| `brave-fake` | bot | 0 | 1 | 6 | 6 | 1 | 0 |
| `brave` | bot | 0 | 0 | 2 | 4 | 2 | 0 |
| `camoufox-hardened-behave` | suspicious | 0 | 0 | 0 | 4 | 1 | 0 |
| `camoufox-hardened` | suspicious | 0 | 0 | 0 | 4 | 2 | 0 |
| `camoufox-headful` | suspicious | 0 | 0 | 0 | 4 | 0 | 0 |
| `camoufox-linux-coherent` | suspicious | 0 | 0 | 0 | 4 | 2 | 0 |
| `camoufox-linux` | suspicious | 0 | 0 | 0 | 4 | 2 | 0 |
| `camoufox-macos` | bot | 1 | 1 | 0 | 5 | 0 | 0 |
| `camoufox-socks-webrtc` | suspicious | 0 | 0 | 0 | 4 | 1 | 0 |
| `camoufox-touch-incoherent` | bot | 1 | 0 | 0 | 4 | 1 | 0 |
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
| `datacenter-origin-proxied` | bot | 1 | 0 | 0 | 3 | 1 | 2 |
| `domrect-spoof` | bot | 0 | 1 | 6 | 6 | 1 | 0 |
| `electron-leak` | bot | 0 | 0 | 8 | 6 | 1 | 0 |
| `firefox-coherent` | bot | 0 | 0 | 1 | 6 | 3 | 0 |
| `firefox-os-spoof` | bot | 4 | 0 | 1 | 6 | 1 | 0 |
| `floor-spoof` | bot | 0 | 0 | 4 | 2 | 2 | 0 |
| `font-os-leak` | bot | 5 | 0 | 5 | 8 | 0 | 0 |
| `fp-rotation` | bot | 1 | 0 | 0 | 4 | 2 | 0 |
| `full-stealth` | bot | 4 | 0 | 6 | 5 | 1 | 0 |
| `go-tls-h2-rotate` | bot | 3 | 0 | 0 | 0 | 0 | 0 |
| `go-tls-madeyoureset` | bot | 5 | 0 | 1 | 0 | 0 | 0 |
| `go-tls-rotate` | bot | 5 | 0 | 0 | 0 | 0 | 0 |
| `go-tls-static-ext` | bot | 4 | 0 | 0 | 0 | 0 | 0 |
| `go-tls-web-bot-auth-replay` | bot | 2 | 0 | 0 | 0 | 0 | 0 |
| `go-tls-web-bot-auth` | bot | 2 | 0 | 0 | 0 | 0 | 0 |
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
| `ip-rotation` | bot | 5 | 0 | 0 | 0 | 0 | 0 |
| `keystroke-human` | bot | 0 | 0 | 6 | 6 | 2 | 0 |
| `lang-list-spoof` | bot | 1 | 0 | 6 | 6 | 1 | 0 |
| `lang-spoof` | bot | 1 | 0 | 6 | 6 | 1 | 0 |
| `linear-bot` | bot | 0 | 0 | 6 | 6 | 5 | 0 |
| `max-stealth` | bot | 0 | 0 | 3 | 6 | 1 | 0 |
| `measuretext-spoof` | bot | 0 | 1 | 6 | 6 | 1 | 0 |
| `mobile-emulation` | bot | 1 | 0 | 5 | 5 | 2 | 0 |
| `naive-tz-spoof` | bot | 3 | 0 | 6 | 6 | 1 | 0 |
| `native-spoof` | bot | 2 | 1 | 6 | 6 | 1 | 0 |
| `nodriver` | bot | 0 | 0 | 1 | 4 | 2 | 0 |
| `os-spoof` | bot | 4 | 0 | 4 | 8 | 0 | 0 |
| `patchright-headful` | suspicious | 0 | 0 | 0 | 3 | 1 | 0 |
| `patchright` | bot | 0 | 0 | 4 | 6 | 0 | 0 |
| `playwright-extra-coherent` | bot | 2 | 0 | 3 | 5 | 2 | 0 |
| `playwright-extra` | bot | 3 | 0 | 3 | 6 | 2 | 0 |
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
| `trace-replay` | bot | 1 | 0 | 6 | 6 | 0 | 0 |
| `tz-spoof` | bot | 3 | 0 | 6 | 6 | 1 | 0 |
| `ua-rotation` | bot | 8 | 0 | 0 | 0 | 0 | 0 |
| `uach-coherent` | bot | 0 | 0 | 4 | 6 | 1 | 0 |
| `undetected` | bot | 0 | 0 | 1 | 4 | 2 | 0 |
| `vanilla` | bot | 5 | 0 | 0 | 0 | 0 | 0 |
| `webgl-caps-worker-spoof` | bot | 2 | 0 | 4 | 3 | 3 | 0 |
| `webgl-renderer-spoof` | bot | 4 | 0 | 8 | 6 | 3 | 0 |
| `webkit-safari-coherent` | bot | 5 | 0 | 1 | 2 | 1 | 0 |
| `webkit-ua-spoof` | bot | 9 | 0 | 2 | 4 | 2 | 0 |
| `webrtc-leak` | suspicious | 0 | 0 | 0 | 3 | 1 | 1 |
| `webrtc-origin-datacenter` | bot | 1 | 0 | 0 | 3 | 1 | 2 |
| `worker-proxy-fix` | bot | 0 | 1 | 6 | 6 | 1 | 0 |
| `worker-proxy` | bot | 0 | 1 | 6 | 6 | 1 | 0 |
| `worker-spoof` | bot | 0 | 0 | 7 | 6 | 1 | 0 |
| `worker-wrap` | bot | 0 | 1 | 6 | 6 | 1 | 0 |
| `zendriver-uach-behave` | suspicious | 0 | 0 | 0 | 5 | 1 | 0 |
| `zendriver-uach` | suspicious | 0 | 0 | 0 | 5 | 2 | 0 |
| `zendriver` | bot | 1 | 0 | 0 | 5 | 2 | 0 |

## Coverage gaps — 20/138 rules catch nothing yet

**Evaded** (1) — reads present in the corpus, but every sample passed:
- `br.low_hardware_concurrency`

**Unexercised** (19) — a read signal is absent from every recording, so the corpus cannot trip them yet (e.g. signals the recordings predate); these are validated by the detector unit + precision tests, and need a corpus refresh to appear here:
- `net.tls_os_vs_tcp_os`
- `rep.datacenter_asn`
- `net.fake_declared_crawler`
- `bh.touch_uniform_velocity`
- `bh.click_without_trajectory`
- `bh.mobile_keystroke_interval_floor`
- `bh.keystroke_interval_floor`
- `rep.known_proxy_exit`
- `br.languages_empty`
- `br.screen_zero`
- `br.platform_empty`
- `br.color_depth_anomaly`
- `br.devicepixelratio_anomaly`
- `br.mobile_no_touch`
- `br.voice_os_vs_ua`
- `br.audio_missing`
- `br.adblock_present`
- `br.webgpu_vendor_vs_webgl`
- `br.rfp_browser`
