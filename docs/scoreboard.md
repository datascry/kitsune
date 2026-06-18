# Kitsune scoreboard

- generated: `2026-06-18T13:22:01.257437+00:00`
- ruleset: `0.42.0`

| Evader | Ver | Network | Browser | Behavioral | Reputation | Incoh. | Score | Label |
|---|---|---|---|---|---|---|---|---|
| baseline-firefox | corpus | 0.00 | 1.00 | 0.00 | 0.00 | 0.00 | 1.00 | bot |
| brave | corpus | 0.00 | 1.00 | 0.80 | 0.00 | 0.00 | 1.00 | bot |
| camoufox-hardened | corpus | 0.00 | 0.98 | 0.00 | 0.00 | 0.00 | 0.98 | bot |
| camoufox-headful | corpus | 0.00 | 0.95 | 0.00 | 0.00 | 0.00 | 0.95 | bot |
| camoufox | corpus | 0.00 | 0.95 | 0.00 | 0.00 | 0.00 | 0.95 | bot |
| curl-impersonate | corpus | 0.60 | 0.60 | 0.00 | 0.00 | 0.60 | 0.90 | bot |
| floor-spoof | corpus | 0.00 | 1.00 | 0.75 | 0.00 | 0.00 | 1.00 | bot |
| full-stealth | corpus | 0.00 | 1.00 | 0.00 | 0.00 | 0.00 | 1.00 | bot |
| h2-continuation-flood | corpus | 0.96 | 0.60 | 0.00 | 0.00 | 0.60 | 0.99 | bot |
| h2-rapid-reset | corpus | 0.96 | 0.60 | 0.00 | 0.00 | 0.60 | 0.99 | bot |
| human-mouse | corpus | 0.00 | 1.00 | 0.45 | 0.00 | 0.00 | 1.00 | bot |
| max-stealth | corpus | 0.00 | 1.00 | 0.45 | 0.00 | 0.00 | 1.00 | bot |
| nodriver | corpus | 0.00 | 1.00 | 0.80 | 0.00 | 0.00 | 1.00 | bot |
| os-spoof | corpus | 0.88 | 1.00 | 0.00 | 0.00 | 0.60 | 1.00 | bot |
| patchright | corpus | 0.00 | 1.00 | 0.55 | 0.00 | 0.00 | 1.00 | bot |
| pydoll | corpus | 0.00 | 1.00 | 0.80 | 0.00 | 0.00 | 1.00 | bot |
| rebrowser | corpus | 0.00 | 1.00 | 0.00 | 0.00 | 0.00 | 1.00 | bot |
| selenium-driverless | corpus | 0.00 | 1.00 | 0.80 | 0.00 | 0.00 | 1.00 | bot |
| spoof-ua | corpus | 0.95 | 1.00 | 0.00 | 0.00 | 0.95 | 1.00 | bot |
| stealth-naive | corpus | 0.00 | 1.00 | 0.00 | 0.00 | 0.00 | 1.00 | bot |
| stealth-patched | corpus | 0.00 | 1.00 | 0.00 | 0.00 | 0.00 | 1.00 | bot |
| undetected | corpus | 0.00 | 1.00 | 0.80 | 0.00 | 0.00 | 1.00 | bot |
| vanilla | corpus | 0.99 | 0.98 | 0.00 | 0.00 | 0.98 | 1.00 | bot |
| zendriver | corpus | 0.00 | 0.99 | 0.80 | 0.00 | 0.00 | 1.00 | bot |

## Why

- **baseline-firefox** (bot): `br.webdriver_present`, `br.no_plugins`, `br.mimetypes_empty`, `br.webgl2_missing`, `br.voices_empty`, `br.media_devices_empty`
- **brave** (bot): `br.webdriver_present`, `bh.input_entropy_floor`, `bh.no_input_before_action`, `br.headless_ua`, `br.webgl_software`, `br.no_connection`, `br.chrome_runtime_missing`, `br.voices_empty`, `br.media_devices_empty`, `br.canvas_noise`
- **camoufox-hardened** (bot): `br.webgl2_missing`, `br.pointer_touch_incoherent`, `br.voices_empty`, `br.media_devices_empty`, `br.webrtc_unavailable`
- **camoufox-headful** (bot): `br.webgl2_missing`, `br.voices_empty`, `br.media_devices_empty`, `br.webrtc_unavailable`
- **camoufox** (bot): `br.webgl2_missing`, `br.voices_empty`, `br.media_devices_empty`, `br.webrtc_unavailable`
- **curl-impersonate** (bot): `net.no_js_execution`
- **floor-spoof** (bot): `bh.keystroke_entropy_floor`, `bh.synthetic_no_coalesced`, `br.webgl_software`, `br.tostring_tampered`, `br.no_plugins`, `br.nav_property_spoofed`, `br.webdriver_getter_tampered`, `br.notification_getter_tampered`
- **full-stealth** (bot): `br.cdp_runtime_enabled`, `br.permissions_anomaly`, `br.webgl_getparameter_tampered`, `br.plugins_spoofed`, `br.webdriver_getter_tampered`, `br.webgl_os_vs_ua`, `br.no_pdfviewer`, `br.mimetypes_empty`, `br.notification_denied`, `br.voices_empty`, `br.media_devices_empty`, `br.webgpu_webgl_vs`
- **h2-continuation-flood** (bot): `net.h2_continuation_flood`, `net.no_js_execution`
- **h2-rapid-reset** (bot): `net.h2_rapid_reset`, `net.no_js_execution`
- **human-mouse** (bot): `br.webdriver_present`, `br.cdp_runtime_enabled`, `br.headless_ua`, `bh.synthetic_no_coalesced`, `br.webgl_software`, `br.permissions_anomaly`, `br.no_chrome_object`, `br.no_plugins`, `br.no_pdfviewer`, `br.mimetypes_empty`, `br.notification_denied`, `br.voices_empty`, `br.media_devices_empty`
- **max-stealth** (bot): `bh.synthetic_no_coalesced`, `br.webdriver_spoofed`, `br.webgl_software`, `br.permissions_anomaly`, `br.no_chrome_object`, `br.no_plugins`, `br.no_pdfviewer`, `br.mimetypes_empty`, `br.notification_denied`, `br.voices_empty`, `br.media_devices_empty`
- **nodriver** (bot): `bh.input_entropy_floor`, `bh.no_input_before_action`, `br.headless_ua`, `br.webgl_software`, `br.chrome_runtime_missing`, `br.hover_none_desktop`, `br.voices_empty`, `br.media_devices_empty`
- **os-spoof** (bot): `br.cdp_runtime_enabled`, `net.ch_ua_version_vs_ua`, `net.tcp_os_vs_ua`, `br.webdriver_spoofed`, `br.webgl_software`, `br.permissions_anomaly`, `br.no_chrome_object`, `br.no_plugins`, `br.webgl_os_vs_ua`, `br.navplatform_vs_ua`, `br.no_pdfviewer`, `br.mimetypes_empty`, `br.notification_denied`, `br.voices_empty`, `br.media_devices_empty`, `br.font_linux_leak`, `br.codec_os_incoherent`
- **patchright** (bot): `br.headless_ua`, `bh.keystroke_entropy_floor`, `br.webgl_software`, `br.permissions_anomaly`, `br.no_chrome_object`, `br.no_plugins`, `br.no_pdfviewer`, `br.mimetypes_empty`, `br.notification_denied`, `br.voices_empty`, `br.media_devices_empty`
- **pydoll** (bot): `bh.input_entropy_floor`, `bh.no_input_before_action`, `br.headless_ua`, `br.webgl_software`, `br.chrome_runtime_missing`, `br.hover_none_desktop`, `br.voices_empty`, `br.media_devices_empty`
- **rebrowser** (bot): `br.webdriver_present`, `br.headless_ua`, `br.webgl_software`, `br.permissions_anomaly`, `br.no_chrome_object`, `br.no_plugins`, `br.no_pdfviewer`, `br.mimetypes_empty`, `br.notification_denied`, `br.voices_empty`, `br.media_devices_empty`
- **selenium-driverless** (bot): `bh.input_entropy_floor`, `bh.no_input_before_action`, `br.headless_ua`, `br.webgl_software`, `br.chrome_runtime_missing`, `br.hover_none_desktop`, `br.voices_empty`, `br.media_devices_empty`
- **spoof-ua** (bot): `net.tls_vs_ua_browser`, `net.h2_vs_ua_browser`, `net.ch_ua_vs_ua_browser`, `br.webdriver_spoofed`, `br.webgl_software`, `br.permissions_anomaly`, `br.no_plugins`, `br.vendor_vs_ua`, `br.mimetypes_empty`, `br.notification_denied`, `br.productsub_vs_ua`, `br.voices_empty`, `br.media_devices_empty`, `br.engine_stack_vs_ua`, `br.error_engine_vs_ua`
- **stealth-naive** (bot): `br.webdriver_present`, `br.cdp_runtime_enabled`, `br.headless_ua`, `br.webgl_software`, `br.permissions_anomaly`, `br.no_chrome_object`, `br.no_plugins`, `br.no_pdfviewer`, `br.mimetypes_empty`, `br.notification_denied`, `br.voices_empty`, `br.media_devices_empty`
- **stealth-patched** (bot): `br.cdp_runtime_enabled`, `br.webdriver_spoofed`, `br.webgl_software`, `br.permissions_anomaly`, `br.no_chrome_object`, `br.no_plugins`, `br.webgl_os_vs_ua`, `br.navplatform_vs_ua`, `br.no_pdfviewer`, `br.mimetypes_empty`, `br.notification_denied`, `br.voices_empty`, `br.media_devices_empty`, `br.font_linux_leak`, `br.codec_os_incoherent`
- **undetected** (bot): `bh.input_entropy_floor`, `bh.no_input_before_action`, `br.headless_ua`, `br.webgl_software`, `br.chrome_runtime_missing`, `br.hover_none_desktop`, `br.voices_empty`, `br.media_devices_empty`
- **vanilla** (bot): `net.tcp_os_vs_ua`, `net.no_js_execution`, `net.sec_fetch_vs_ua`, `net.accept_encoding_vs_ua`, `net.tls_grease_vs_ua`
- **zendriver** (bot): `bh.input_entropy_floor`, `bh.no_input_before_action`, `br.webgl_software`, `br.chrome_runtime_missing`, `br.hover_none_desktop`, `br.voices_empty`, `br.media_devices_empty`, `br.webrtc_unavailable`
