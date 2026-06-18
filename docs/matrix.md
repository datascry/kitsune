# Kitsune detection matrix — 97 rules

| Detector | layer | baseline-firefox | brave | camoufox-hardened | camoufox-headful | camoufox | ch-ua-hardcoded | chrome-clone-1 | chrome-clone-2 | curl-impersonate | floor-spoof | full-stealth | go-tls | h2-continuation-flood | h2-rapid-reset | human-mouse | max-stealth | nodriver | os-spoof | patchright | primp | pydoll | quic-no-grease | rebrowser | selenium-driverless | spoof-ua | stealth-naive | stealth-patched | tls-stale-template | undetected | vanilla | zendriver | catches |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `net.tls_os_vs_tcp_os` | network | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `net.tls_vs_ua_browser` | network,browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | 1 |
| `net.h2_vs_ua_browser` | network,browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | 1 |
| `br.automation_globals` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.screen_impossible` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `net.quic_grease_vs_ua` | network,browser | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | 3 |
| `net.quic_pq_keyshare_vs_ua` | network,browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `net.h2_unknown_vs_ua` | network | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 1 |
| `br.ua_platform_vs_ch_platform` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.webdriver_present` | browser | ✓ | ✓ | · | · | · | · | ✓ | ✓ | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | ✓ | · | · | ✓ | · | · | · | · | · | 7 |
| `br.cdp_runtime_enabled` | browser | · | · | · | · | · | · | ✓ | ✓ | · | · | ✓ | · | · | · | ✓ | · | · | ✓ | · | · | · | · | · | · | · | ✓ | ✓ | · | · | · | · | 7 |
| `br.csp_bypassed` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.canvas_lie` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `bh.input_entropy_floor` | behavioral | · | ✓ | · | · | · | · | ✓ | ✓ | · | · | · | · | · | · | · | · | ✓ | · | · | · | ✓ | · | · | ✓ | · | · | · | · | ✓ | · | ✓ | 8 |
| `bh.no_input_before_action` | behavioral | · | ✓ | · | · | · | · | ✓ | ✓ | · | · | · | · | · | · | · | · | ✓ | · | · | · | ✓ | · | · | ✓ | · | · | · | · | ✓ | · | ✓ | 8 |
| `bh.power_law_violation` | behavioral | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 1 |
| `rep.datacenter_asn` | reputation | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `net.h2_vs_tls_browser` | network | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `net.accept_lang_vs_navigator` | network,browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `net.ch_platform_header_vs_ua` | network,browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `net.ch_ua_vs_ua_browser` | network,browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | 1 |
| `net.ch_ua_version_vs_ua` | network,browser | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | 3 |
| `net.tcp_os_vs_ua` | network | · | · | · | · | ✓ | ✓ | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | ✓ | · | · | · | · | · | · | ✓ | ✓ | · | ✓ | · | 7 |
| `net.h2_settings_vs_order` | network | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `net.h2_rapid_reset` | network | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 1 |
| `net.h2_continuation_flood` | network | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 1 |
| `net.h2_control_flood` | network | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.headless_ua` | browser | · | ✓ | · | · | · | · | ✓ | ✓ | · | · | · | · | · | · | ✓ | · | ✓ | · | ✓ | · | ✓ | · | ✓ | ✓ | · | ✓ | · | · | ✓ | · | · | 11 |
| `bh.keystroke_entropy_floor` | behavioral | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 1 |
| `rep.known_proxy_exit` | reputation | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `bh.path_too_straight` | behavioral | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `bh.uniform_velocity` | behavioral | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `bh.synthetic_no_coalesced` | behavioral | · | · | · | · | ✓ | · | · | · | · | ✓ | · | · | · | · | ✓ | ✓ | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | 5 |
| `br.webdriver_spoofed` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | ✓ | · | · | · | · | · | · | ✓ | · | ✓ | · | · | · | · | 4 |
| `br.webgl_software` | browser | · | ✓ | · | · | · | · | ✓ | ✓ | · | ✓ | · | · | · | · | ✓ | ✓ | ✓ | ✓ | ✓ | · | ✓ | · | ✓ | ✓ | ✓ | ✓ | ✓ | · | ✓ | · | ✓ | 17 |
| `br.permissions_anomaly` | browser | · | · | · | · | · | · | ✓ | ✓ | · | · | ✓ | · | · | · | ✓ | ✓ | · | ✓ | ✓ | · | · | · | ✓ | · | ✓ | ✓ | ✓ | · | · | · | · | 11 |
| `br.no_chrome_object` | browser | · | · | · | · | · | · | ✓ | ✓ | · | · | · | · | · | · | ✓ | ✓ | · | ✓ | ✓ | · | · | · | ✓ | · | · | ✓ | ✓ | · | · | · | · | 9 |
| `br.tostring_tampered` | browser | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 1 |
| `br.low_hardware_concurrency` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.no_plugins` | browser | ✓ | · | · | · | · | · | ✓ | ✓ | · | ✓ | · | · | · | · | ✓ | ✓ | · | ✓ | ✓ | · | · | · | ✓ | · | ✓ | ✓ | ✓ | · | · | · | · | 12 |
| `br.webgl_getparameter_tampered` | browser | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 1 |
| `br.plugins_spoofed` | browser | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 1 |
| `br.nav_property_spoofed` | browser | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 1 |
| `br.webdriver_getter_tampered` | browser | · | · | · | · | · | · | · | · | · | ✓ | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 2 |
| `br.notification_getter_tampered` | browser | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 1 |
| `br.webgl_os_vs_ua` | browser | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | 3 |
| `br.navplatform_vs_ua` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | 2 |
| `br.worker_divergence` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.vendor_vs_ua` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | 1 |
| `br.oscpu_vs_ua` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.languages_empty` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.screen_zero` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.no_connection` | browser | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 1 |
| `br.no_pdfviewer` | browser | · | · | · | · | · | · | ✓ | ✓ | · | · | ✓ | · | · | · | ✓ | ✓ | · | ✓ | ✓ | · | · | · | ✓ | · | · | ✓ | ✓ | · | · | · | · | 10 |
| `br.chrome_runtime_missing` | browser | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | ✓ | · | · | ✓ | · | · | · | · | ✓ | · | ✓ | 6 |
| `br.mimetypes_empty` | browser | ✓ | · | · | · | · | · | ✓ | ✓ | · | · | ✓ | · | · | · | ✓ | ✓ | · | ✓ | ✓ | · | · | · | ✓ | · | ✓ | ✓ | ✓ | · | · | · | · | 12 |
| `br.no_devicememory` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.notification_denied` | browser | · | · | · | · | · | · | ✓ | ✓ | · | · | ✓ | · | · | · | ✓ | ✓ | · | ✓ | ✓ | · | · | · | ✓ | · | ✓ | ✓ | ✓ | · | · | · | · | 11 |
| `br.platform_empty` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.productsub_vs_ua` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | 1 |
| `br.cdc_artifacts` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.webgl2_missing` | browser | ✓ | · | ✓ | ✓ | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 4 |
| `br.iframe_divergence` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.font_os_vs_ua` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.screen_avail_invalid` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.color_depth_anomaly` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.devicepixelratio_anomaly` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.hover_none_desktop` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | ✓ | · | · | ✓ | · | · | · | · | ✓ | · | ✓ | 5 |
| `br.pointer_touch_incoherent` | browser | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 1 |
| `br.voices_empty` | browser | ✓ | ✓ | ✓ | ✓ | ✓ | · | ✓ | ✓ | · | · | ✓ | · | · | · | ✓ | ✓ | ✓ | ✓ | ✓ | · | ✓ | · | ✓ | ✓ | ✓ | ✓ | ✓ | · | ✓ | · | ✓ | 21 |
| `br.voice_os_vs_ua` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.webgl_renderer_artifact` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.audio_missing` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.audio_noise` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.media_devices_empty` | browser | ✓ | ✓ | ✓ | ✓ | ✓ | · | ✓ | ✓ | · | · | ✓ | · | · | · | ✓ | ✓ | ✓ | ✓ | ✓ | · | ✓ | · | ✓ | ✓ | ✓ | ✓ | ✓ | · | ✓ | · | ✓ | 21 |
| `br.adblock_present` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.macos_dpr1` | browser | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 1 |
| `br.font_linux_leak` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | 2 |
| `br.font_mac_internal` | browser | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 1 |
| `br.codec_os_incoherent` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | 2 |
| `br.webrtc_unavailable` | browser | · | · | ✓ | ✓ | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | 4 |
| `net.webrtc_ip_vs_observed` | network,browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.timezone_inconsistent` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.engine_stack_vs_ua` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | 1 |
| `net.no_js_execution` | network,browser | · | · | · | · | · | ✓ | · | · | ✓ | · | · | ✓ | ✓ | ✓ | · | · | · | · | · | ✓ | · | ✓ | · | · | · | · | · | ✓ | · | ✓ | · | 9 |
| `br.webgpu_webgl_vs` | browser | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 1 |
| `br.webgpu_vendor_vs_webgl` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.error_engine_vs_ua` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | 1 |
| `br.math_engine_vs_ua` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | ✓ | · | · | · | · | · | · | 2 |
| `net.sec_fetch_vs_ua` | network,browser | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | ✓ | · | ✓ | · | 4 |
| `net.accept_encoding_vs_ua` | network,browser | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | ✓ | · | ✓ | · | 4 |
| `net.tls_grease_vs_ua` | network,browser | · | · | · | · | ✓ | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | ✓ | · | ✓ | · | 5 |
| `net.tls_pq_keyshare_vs_ua` | network,browser | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | 2 |
| `net.ch_ua_mobile_vs_ua` | network,browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `net.ch_ua_no_grease_brand` | network | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 1 |
| `br.rfp_browser` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.canvas_noise` | browser | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 1 |
| **flagged** |  | **6/97** | **10/97** | **5/97** | **4/97** | **11/97** | **6/97** | **14/97** | **14/97** | **1/97** | **8/97** | **13/97** | **3/97** | **2/97** | **2/97** | **13/97** | **11/97** | **9/97** | **17/97** | **12/97** | **2/97** | **8/97** | **5/97** | **11/97** | **8/97** | **16/97** | **12/97** | **17/97** | **6/97** | **8/97** | **5/97** | **8/97** |  |
| **verdict** |  | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** |  |

## Detection class — coherence/artifact = spoofing caught; environment/automation = headless too

| Evader | verdict | coherence | artifact | automation | environment | behavioral | reputation |
|---|---|---|---|---|---|---|---|
| `baseline-firefox` | bot | 0 | 0 | 1 | 5 | 0 | 0 |
| `brave` | bot | 0 | 1 | 3 | 4 | 2 | 0 |
| `camoufox-hardened` | bot | 1 | 1 | 0 | 3 | 0 | 0 |
| `camoufox-headful` | bot | 0 | 1 | 0 | 3 | 0 | 0 |
| `camoufox` | bot | 3 | 2 | 0 | 4 | 2 | 0 |
| `ch-ua-hardcoded` | bot | 5 | 1 | 0 | 0 | 0 | 0 |
| `chrome-clone-1` | bot | 0 | 0 | 6 | 6 | 2 | 0 |
| `chrome-clone-2` | bot | 0 | 0 | 6 | 6 | 2 | 0 |
| `curl-impersonate` | bot | 1 | 0 | 0 | 0 | 0 | 0 |
| `floor-spoof` | bot | 0 | 0 | 4 | 2 | 2 | 0 |
| `full-stealth` | bot | 3 | 0 | 6 | 4 | 0 | 0 |
| `go-tls` | bot | 3 | 0 | 0 | 0 | 0 | 0 |
| `h2-continuation-flood` | bot | 1 | 0 | 1 | 0 | 0 | 0 |
| `h2-rapid-reset` | bot | 1 | 0 | 1 | 0 | 0 | 0 |
| `human-mouse` | bot | 0 | 0 | 6 | 6 | 1 | 0 |
| `max-stealth` | bot | 0 | 0 | 4 | 6 | 1 | 0 |
| `nodriver` | bot | 1 | 0 | 2 | 4 | 2 | 0 |
| `os-spoof` | bot | 6 | 0 | 5 | 6 | 0 | 0 |
| `patchright` | bot | 1 | 0 | 4 | 6 | 1 | 0 |
| `primp` | bot | 2 | 0 | 0 | 0 | 0 | 0 |
| `pydoll` | bot | 0 | 0 | 2 | 4 | 2 | 0 |
| `quic-no-grease` | bot | 5 | 0 | 0 | 0 | 0 | 0 |
| `rebrowser` | bot | 0 | 0 | 5 | 6 | 0 | 0 |
| `selenium-driverless` | bot | 0 | 0 | 2 | 4 | 2 | 0 |
| `spoof-ua` | bot | 8 | 0 | 3 | 5 | 0 | 0 |
| `stealth-naive` | bot | 0 | 0 | 6 | 6 | 0 | 0 |
| `stealth-patched` | bot | 6 | 0 | 5 | 6 | 0 | 0 |
| `tls-stale-template` | bot | 6 | 0 | 0 | 0 | 0 | 0 |
| `undetected` | bot | 0 | 0 | 2 | 4 | 2 | 0 |
| `vanilla` | bot | 5 | 0 | 0 | 0 | 0 | 0 |
| `zendriver` | bot | 0 | 1 | 1 | 4 | 2 | 0 |

## Coverage gaps — 39/97 rules catch nothing yet

**Evaded** (10) — reads present in the corpus, but every sample passed:
- `br.ua_platform_vs_ch_platform`
- `net.h2_vs_tls_browser`
- `net.accept_lang_vs_navigator`
- `net.ch_platform_header_vs_ua`
- `net.h2_settings_vs_order`
- `bh.path_too_straight`
- `bh.uniform_velocity`
- `br.low_hardware_concurrency`
- `br.oscpu_vs_ua`
- `br.font_os_vs_ua`

**Unexercised** (29) — a read signal is absent from every recording, so the corpus cannot trip them yet (e.g. signals the recordings predate); these are validated by the detector unit + precision tests, and need a corpus refresh to appear here:
- `net.tls_os_vs_tcp_os`
- `br.automation_globals`
- `br.screen_impossible`
- `net.quic_pq_keyshare_vs_ua`
- `br.csp_bypassed`
- `br.canvas_lie`
- `rep.datacenter_asn`
- `net.h2_control_flood`
- `rep.known_proxy_exit`
- `br.worker_divergence`
- `br.languages_empty`
- `br.screen_zero`
- `br.no_devicememory`
- `br.platform_empty`
- `br.cdc_artifacts`
- `br.iframe_divergence`
- `br.screen_avail_invalid`
- `br.color_depth_anomaly`
- `br.devicepixelratio_anomaly`
- `br.voice_os_vs_ua`
- `br.webgl_renderer_artifact`
- `br.audio_missing`
- `br.audio_noise`
- `br.adblock_present`
- `net.webrtc_ip_vs_observed`
- `br.timezone_inconsistent`
- `br.webgpu_vendor_vs_webgl`
- `net.ch_ua_mobile_vs_ua`
- `br.rfp_browser`
