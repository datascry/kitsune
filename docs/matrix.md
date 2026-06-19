# Kitsune detection matrix — 111 rules

| Detector | layer | baseline-firefox | brave | camoufox-hardened | camoufox-headful | camoufox | canvas-spoof | ch-ua-hardcoded | chrome-clone-1 | chrome-clone-2 | curl-impersonate | floor-spoof | full-stealth | go-tls | h2-continuation-flood | h2-rapid-reset | human-mouse | iframe-spoof | linear-bot | max-stealth | native-spoof | nodriver | os-spoof | patchright | primp | pydoll | quic-no-grease | rebrowser | selenium-driverless | spoof-ua | stealth-naive | stealth-patched | tls-stale-template | tz-spoof | undetected | vanilla | worker-spoof | zendriver | catches |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `net.tls_os_vs_tcp_os` | network | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `net.tls_vs_ua_browser` | network,browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `net.h2_vs_ua_browser` | network,browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | 1 |
| `br.automation_globals` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.electron_process` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.native_invariant_violated` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 1 |
| `br.screen_impossible` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `net.quic_grease_vs_ua` | network,browser | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | 3 |
| `net.quic_pq_keyshare_vs_ua` | network,browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `net.h2_unknown_vs_ua` | network | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 1 |
| `net.h2_header_order_vs_ua` | network | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.ua_platform_vs_ch_platform` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 1 |
| `br.webdriver_present` | browser | ✓ | ✓ | · | · | · | · | · | ✓ | ✓ | · | · | · | · | · | · | ✓ | · | ✓ | · | · | · | · | · | · | · | · | ✓ | · | · | ✓ | · | · | · | · | · | · | · | 8 |
| `br.cdp_runtime_enabled` | browser | · | · | · | · | · | ✓ | · | ✓ | ✓ | · | · | ✓ | · | · | · | ✓ | ✓ | ✓ | · | ✓ | · | ✓ | · | · | · | · | · | · | · | ✓ | ✓ | · | ✓ | · | · | ✓ | · | 13 |
| `br.csp_bypassed` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.canvas_lie` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `bh.input_entropy_floor` | behavioral | · | ✓ | · | · | · | · | · | ✓ | ✓ | · | · | · | · | · | · | · | · | ✓ | · | · | ✓ | · | · | · | ✓ | · | · | ✓ | · | · | · | · | · | ✓ | · | · | ✓ | 9 |
| `bh.no_input_before_action` | behavioral | · | ✓ | · | · | · | · | · | ✓ | ✓ | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | ✓ | · | · | ✓ | · | · | · | · | · | ✓ | · | · | ✓ | 8 |
| `bh.power_law_violation` | behavioral | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 2 |
| `rep.datacenter_asn` | reputation | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `net.h2_vs_tls_browser` | network | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `net.accept_lang_vs_navigator` | network,browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `net.ch_platform_header_vs_ua` | network,browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 1 |
| `net.ch_ua_vs_ua_browser` | network,browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | 1 |
| `net.ch_ua_version_vs_ua` | network,browser | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | 3 |
| `net.tcp_os_vs_ua` | network | · | · | · | · | ✓ | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | ✓ | · | · | · | · | · | · | ✓ | ✓ | · | · | ✓ | · | · | 7 |
| `net.h2_settings_vs_order` | network | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `net.h2_rapid_reset` | network | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 1 |
| `net.h2_continuation_flood` | network | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 1 |
| `net.h2_control_flood` | network | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.headless_ua` | browser | · | ✓ | · | · | · | ✓ | · | ✓ | ✓ | · | · | · | · | · | · | ✓ | · | ✓ | · | ✓ | ✓ | · | ✓ | · | ✓ | · | ✓ | ✓ | · | ✓ | · | · | ✓ | ✓ | · | ✓ | · | 16 |
| `br.ch_he_headless` | browser | · | · | · | · | · | ✓ | · | · | · | · | · | ✓ | · | · | · | ✓ | ✓ | ✓ | · | ✓ | · | · | ✓ | · | · | · | · | · | ✓ | ✓ | ✓ | · | ✓ | · | · | ✓ | · | 12 |
| `br.ch_he_version_vs_ua` | browser | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | 3 |
| `bh.keystroke_entropy_floor` | behavioral | · | · | · | · | · | ✓ | · | · | · | · | ✓ | ✓ | · | · | · | · | ✓ | · | · | ✓ | · | · | · | · | · | · | · | · | ✓ | ✓ | ✓ | · | · | · | · | ✓ | · | 9 |
| `rep.known_proxy_exit` | reputation | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `bh.path_too_straight` | behavioral | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 1 |
| `bh.uniform_velocity` | behavioral | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 1 |
| `bh.synthetic_no_coalesced` | behavioral | · | · | · | · | ✓ | · | · | · | · | · | ✓ | · | · | · | · | ✓ | · | ✓ | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 5 |
| `br.webdriver_spoofed` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | ✓ | · | · | · | · | · | · | ✓ | · | ✓ | · | · | · | · | · | · | 4 |
| `br.webgl_software` | browser | · | ✓ | · | · | · | ✓ | · | ✓ | ✓ | · | ✓ | · | · | · | · | ✓ | ✓ | ✓ | ✓ | · | ✓ | ✓ | ✓ | · | ✓ | · | ✓ | ✓ | ✓ | ✓ | ✓ | · | ✓ | ✓ | · | ✓ | ✓ | 22 |
| `br.permissions_anomaly` | browser | · | · | · | · | · | ✓ | · | ✓ | ✓ | · | · | ✓ | · | · | · | ✓ | ✓ | ✓ | ✓ | ✓ | · | ✓ | ✓ | · | · | · | ✓ | · | ✓ | ✓ | ✓ | · | ✓ | · | · | ✓ | · | 17 |
| `br.no_chrome_object` | browser | · | · | · | · | · | ✓ | · | ✓ | ✓ | · | · | · | · | · | · | ✓ | ✓ | ✓ | ✓ | ✓ | · | ✓ | ✓ | · | · | · | ✓ | · | · | ✓ | ✓ | · | ✓ | · | · | ✓ | · | 15 |
| `br.tostring_tampered` | browser | · | · | · | · | · | ✓ | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 2 |
| `br.low_hardware_concurrency` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.no_plugins` | browser | ✓ | · | · | · | · | ✓ | · | ✓ | ✓ | · | ✓ | · | · | · | · | ✓ | ✓ | ✓ | ✓ | ✓ | · | ✓ | ✓ | · | · | · | ✓ | · | ✓ | ✓ | ✓ | · | ✓ | · | · | ✓ | · | 18 |
| `br.webgl_getparameter_tampered` | browser | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 1 |
| `br.plugins_spoofed` | browser | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 1 |
| `br.nav_property_spoofed` | browser | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 1 |
| `br.webdriver_getter_tampered` | browser | · | · | · | · | · | ✓ | · | · | · | · | ✓ | ✓ | · | · | · | · | ✓ | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | ✓ | · | 7 |
| `br.notification_getter_tampered` | browser | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 1 |
| `br.webgl_os_vs_ua` | browser | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | ✓ | · | · | ✓ | · | ✓ | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | 5 |
| `br.navplatform_vs_ua` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | 3 |
| `br.worker_divergence` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | 2 |
| `br.timezone_worker_vs_main` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | 1 |
| `br.canvas_worker_vs_main` | browser | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 1 |
| `br.webgl_worker_vs_main` | browser | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 2 |
| `br.vendor_vs_ua` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | 1 |
| `br.oscpu_vs_ua` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.languages_empty` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.screen_zero` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.no_connection` | browser | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 1 |
| `br.no_pdfviewer` | browser | · | · | · | · | · | ✓ | · | ✓ | ✓ | · | · | ✓ | · | · | · | ✓ | ✓ | ✓ | ✓ | ✓ | · | ✓ | ✓ | · | · | · | ✓ | · | · | ✓ | ✓ | · | ✓ | · | · | ✓ | · | 16 |
| `br.chrome_runtime_missing` | browser | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | ✓ | · | · | ✓ | · | · | · | · | · | ✓ | · | · | ✓ | 6 |
| `br.mimetypes_empty` | browser | ✓ | · | · | · | · | ✓ | · | ✓ | ✓ | · | · | ✓ | · | · | · | ✓ | ✓ | ✓ | ✓ | ✓ | · | ✓ | ✓ | · | · | · | ✓ | · | ✓ | ✓ | ✓ | · | ✓ | · | · | ✓ | · | 18 |
| `br.no_devicememory` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.notification_denied` | browser | · | · | · | · | · | ✓ | · | ✓ | ✓ | · | · | ✓ | · | · | · | ✓ | ✓ | ✓ | ✓ | ✓ | · | ✓ | ✓ | · | · | · | ✓ | · | ✓ | ✓ | ✓ | · | ✓ | · | · | ✓ | · | 17 |
| `br.platform_empty` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.productsub_vs_ua` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | 1 |
| `br.cdc_artifacts` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.webgl2_missing` | browser | ✓ | · | ✓ | ✓ | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 4 |
| `br.iframe_divergence` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 1 |
| `br.font_os_vs_ua` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.screen_avail_invalid` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.color_depth_anomaly` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.devicepixelratio_anomaly` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.hover_none_desktop` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | ✓ | · | · | ✓ | · | · | · | · | · | ✓ | · | · | ✓ | 5 |
| `br.pointer_touch_incoherent` | browser | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 1 |
| `br.voices_empty` | browser | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | · | ✓ | ✓ | · | · | ✓ | · | · | · | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | · | ✓ | · | ✓ | ✓ | ✓ | ✓ | ✓ | · | ✓ | ✓ | · | ✓ | ✓ | 27 |
| `br.voice_os_vs_ua` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.webgl_renderer_artifact` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.engine_feature_vs_ua` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.webgl_not_angle` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.audio_missing` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.audio_noise` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.readback_noise` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.domrect_invariant` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.measuretext_offscreen_vs` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.fingerprint_improbable` | browser | · | ✓ | · | · | · | · | · | ✓ | ✓ | · | ✓ | · | · | · | · | · | ✓ | · | ✓ | · | · | ✓ | · | · | ✓ | · | ✓ | ✓ | · | · | ✓ | · | · | ✓ | · | · | ✓ | 13 |
| `br.media_devices_empty` | browser | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | · | ✓ | ✓ | · | · | ✓ | · | · | · | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | · | ✓ | · | ✓ | ✓ | ✓ | ✓ | ✓ | · | ✓ | ✓ | · | ✓ | ✓ | 27 |
| `br.adblock_present` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.macos_dpr1` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.font_linux_leak` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | 3 |
| `br.font_mac_internal` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.codec_os_incoherent` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | 3 |
| `br.webrtc_unavailable` | browser | · | · | ✓ | ✓ | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | 4 |
| `net.webrtc_ip_vs_observed` | network,browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.timezone_inconsistent` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | 1 |
| `br.engine_stack_vs_ua` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | 1 |
| `net.no_js_execution` | network,browser | · | · | · | · | · | · | ✓ | · | · | ✓ | · | · | ✓ | ✓ | ✓ | · | · | · | · | · | · | · | · | ✓ | · | ✓ | · | · | · | · | · | ✓ | · | · | ✓ | · | · | 9 |
| `br.webgpu_webgl_vs` | browser | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 2 |
| `br.webgpu_vendor_vs_webgl` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.error_engine_vs_ua` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | 1 |
| `br.math_engine_vs_ua` | browser | · | · | · | · | · | ✓ | · | · | · | · | · | ✓ | · | · | · | ✓ | ✓ | ✓ | · | ✓ | · | · | ✓ | · | · | · | · | · | · | ✓ | ✓ | · | ✓ | · | · | ✓ | · | 11 |
| `net.sec_fetch_vs_ua` | network,browser | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | ✓ | · | · | ✓ | · | · | 4 |
| `net.accept_encoding_vs_ua` | network,browser | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | ✓ | · | · | ✓ | · | · | 4 |
| `net.tls_grease_vs_ua` | network,browser | · | · | · | · | ✓ | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | ✓ | · | · | ✓ | · | · | 5 |
| `net.tls_pq_keyshare_vs_ua` | network,browser | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | 2 |
| `net.ch_ua_mobile_vs_ua` | network,browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `net.ch_ua_no_grease_brand` | network | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 1 |
| `br.rfp_browser` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.canvas_noise` | browser | · | ✓ | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 2 |
| **flagged** |  | **6/111** | **11/111** | **5/111** | **4/111** | **9/111** | **18/111** | **6/111** | **15/111** | **15/111** | **1/111** | **9/111** | **18/111** | **3/111** | **2/111** | **2/111** | **15/111** | **24/111** | **19/111** | **12/111** | **18/111** | **9/111** | **18/111** | **12/111** | **2/111** | **9/111** | **5/111** | **12/111** | **9/111** | **16/111** | **15/111** | **22/111** | **6/111** | **16/111** | **9/111** | **5/111** | **16/111** | **9/111** |  |
| **verdict** |  | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** |  |

## Detection class — coherence/artifact = spoofing caught; environment/automation = headless too

| Evader | verdict | coherence | artifact | automation | environment | behavioral | reputation |
|---|---|---|---|---|---|---|---|
| `baseline-firefox` | bot | 0 | 0 | 1 | 5 | 0 | 0 |
| `brave` | bot | 0 | 1 | 3 | 4 | 2 | 0 |
| `camoufox-hardened` | bot | 1 | 1 | 0 | 3 | 0 | 0 |
| `camoufox-headful` | bot | 0 | 1 | 0 | 3 | 0 | 0 |
| `camoufox` | bot | 3 | 1 | 0 | 3 | 2 | 0 |
| `canvas-spoof` | bot | 2 | 1 | 8 | 6 | 1 | 0 |
| `ch-ua-hardcoded` | bot | 5 | 1 | 0 | 0 | 0 | 0 |
| `chrome-clone-1` | bot | 0 | 0 | 6 | 6 | 2 | 0 |
| `chrome-clone-2` | bot | 0 | 0 | 6 | 6 | 2 | 0 |
| `curl-impersonate` | bot | 1 | 0 | 0 | 0 | 0 | 0 |
| `floor-spoof` | bot | 0 | 0 | 4 | 2 | 2 | 0 |
| `full-stealth` | bot | 6 | 0 | 7 | 4 | 1 | 0 |
| `go-tls` | bot | 3 | 0 | 0 | 0 | 0 | 0 |
| `h2-continuation-flood` | bot | 1 | 0 | 1 | 0 | 0 | 0 |
| `h2-rapid-reset` | bot | 1 | 0 | 1 | 0 | 0 | 0 |
| `human-mouse` | bot | 1 | 0 | 7 | 6 | 1 | 0 |
| `iframe-spoof` | bot | 8 | 0 | 8 | 6 | 1 | 0 |
| `linear-bot` | bot | 1 | 0 | 7 | 6 | 5 | 0 |
| `max-stealth` | bot | 0 | 0 | 4 | 6 | 1 | 0 |
| `native-spoof` | bot | 4 | 1 | 7 | 5 | 1 | 0 |
| `nodriver` | bot | 1 | 0 | 2 | 4 | 2 | 0 |
| `os-spoof` | bot | 6 | 0 | 5 | 6 | 0 | 0 |
| `patchright` | bot | 1 | 0 | 5 | 6 | 0 | 0 |
| `primp` | bot | 2 | 0 | 0 | 0 | 0 | 0 |
| `pydoll` | bot | 0 | 0 | 2 | 4 | 2 | 0 |
| `quic-no-grease` | bot | 5 | 0 | 0 | 0 | 0 | 0 |
| `rebrowser` | bot | 0 | 0 | 5 | 6 | 0 | 0 |
| `selenium-driverless` | bot | 0 | 0 | 2 | 4 | 2 | 0 |
| `spoof-ua` | bot | 6 | 0 | 4 | 5 | 1 | 0 |
| `stealth-naive` | bot | 1 | 0 | 7 | 6 | 1 | 0 |
| `stealth-patched` | bot | 8 | 0 | 6 | 6 | 1 | 0 |
| `tls-stale-template` | bot | 6 | 0 | 0 | 0 | 0 | 0 |
| `tz-spoof` | bot | 3 | 0 | 7 | 6 | 0 | 0 |
| `undetected` | bot | 0 | 0 | 2 | 4 | 2 | 0 |
| `vanilla` | bot | 5 | 0 | 0 | 0 | 0 | 0 |
| `worker-spoof` | bot | 1 | 0 | 8 | 6 | 1 | 0 |
| `zendriver` | bot | 0 | 1 | 1 | 4 | 2 | 0 |

## Coverage gaps — 42/111 rules catch nothing yet

**Evaded** (7) — reads present in the corpus, but every sample passed:
- `net.tls_vs_ua_browser`
- `net.h2_vs_tls_browser`
- `net.accept_lang_vs_navigator`
- `net.h2_settings_vs_order`
- `br.low_hardware_concurrency`
- `br.oscpu_vs_ua`
- `br.font_os_vs_ua`

**Unexercised** (35) — a read signal is absent from every recording, so the corpus cannot trip them yet (e.g. signals the recordings predate); these are validated by the detector unit + precision tests, and need a corpus refresh to appear here:
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
- `br.webgl_renderer_artifact`
- `br.engine_feature_vs_ua`
- `br.webgl_not_angle`
- `br.audio_missing`
- `br.audio_noise`
- `br.readback_noise`
- `br.domrect_invariant`
- `br.measuretext_offscreen_vs`
- `br.adblock_present`
- `br.macos_dpr1`
- `br.font_mac_internal`
- `net.webrtc_ip_vs_observed`
- `br.webgpu_vendor_vs_webgl`
- `net.ch_ua_mobile_vs_ua`
- `br.rfp_browser`
