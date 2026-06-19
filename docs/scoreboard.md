# Kitsune scoreboard

- generated: `2026-06-19T02:10:24.360383+00:00`
- ruleset: `live`

| Evader | Ver | Network | Browser | Behavioral | Reputation | Incoh. | Score | Label |
|---|---|---|---|---|---|---|---|---|
| vanilla | live | 0.99 | 0.98 | 0.00 | 0.00 | 0.98 | 1.00 | bot |
| stealth-naive | live | 0.00 | 1.00 | 0.55 | 0.00 | 0.00 | 1.00 | bot |
| stealth-patched | live | 0.88 | 1.00 | 0.55 | 0.00 | 0.60 | 1.00 | bot |
| spoof-ua | live | 0.84 | 1.00 | 0.55 | 0.00 | 0.84 | 1.00 | bot |
| full-stealth | live | 0.60 | 1.00 | 0.55 | 0.00 | 0.60 | 1.00 | bot |
| worker-spoof | live | 0.00 | 1.00 | 0.55 | 0.00 | 0.00 | 1.00 | bot |
| iframe-spoof | live | 0.60 | 1.00 | 0.55 | 0.00 | 0.60 | 1.00 | bot |
| native-spoof | live | 0.00 | 1.00 | 0.55 | 0.00 | 0.00 | 1.00 | bot |
| linear-bot | live | 0.00 | 1.00 | 0.98 | 0.00 | 0.00 | 1.00 | bot |
| human-mouse | live | 0.00 | 1.00 | 0.45 | 0.00 | 0.00 | 1.00 | bot |
| patchright | live | 0.00 | 1.00 | 0.55 | 0.00 | 0.00 | 1.00 | bot |
| camoufox | live | 0.95 | 0.84 | 0.00 | 0.00 | 0.84 | 1.00 | bot |
| nodriver | live | 0.60 | 1.00 | 0.80 | 0.00 | 0.60 | 1.00 | bot |

## Why

- **vanilla** (bot): `net.tcp_os_vs_ua`, `net.no_js_execution`, `net.sec_fetch_vs_ua`, `net.accept_encoding_vs_ua`, `net.tls_grease_vs_ua`
- **stealth-naive** (bot): `br.webdriver_present`, `br.cdp_runtime_enabled`, `br.headless_ua`, `br.ch_he_headless`, `bh.keystroke_entropy_floor`, `br.webgl_software`, `br.permissions_anomaly`, `br.no_chrome_object`, `br.no_plugins`, `br.no_pdfviewer`, `br.mimetypes_empty`, `br.notification_denied`, `br.voices_empty`, `br.media_devices_empty`, `br.math_engine_vs_ua`
- **stealth-patched** (bot): `br.cdp_runtime_enabled`, `net.ch_ua_version_vs_ua`, `net.tcp_os_vs_ua`, `br.ch_he_headless`, `br.ch_he_version_vs_ua`, `bh.keystroke_entropy_floor`, `br.webdriver_spoofed`, `br.webgl_software`, `br.permissions_anomaly`, `br.no_chrome_object`, `br.no_plugins`, `br.webgl_os_vs_ua`, `br.navplatform_vs_ua`, `br.no_pdfviewer`, `br.mimetypes_empty`, `br.notification_denied`, `br.voices_empty`, `br.fingerprint_improbable`, `br.media_devices_empty`, `br.font_linux_leak`, `br.codec_os_incoherent`, `br.math_engine_vs_ua`
- **spoof-ua** (bot): `net.h2_vs_ua_browser`, `net.ch_ua_vs_ua_browser`, `br.ch_he_headless`, `bh.keystroke_entropy_floor`, `br.webdriver_spoofed`, `br.webgl_software`, `br.permissions_anomaly`, `br.no_plugins`, `br.vendor_vs_ua`, `br.mimetypes_empty`, `br.notification_denied`, `br.productsub_vs_ua`, `br.voices_empty`, `br.media_devices_empty`, `br.engine_stack_vs_ua`, `br.error_engine_vs_ua`
- **full-stealth** (bot): `br.cdp_runtime_enabled`, `net.ch_ua_version_vs_ua`, `br.ch_he_headless`, `br.ch_he_version_vs_ua`, `bh.keystroke_entropy_floor`, `br.permissions_anomaly`, `br.webgl_getparameter_tampered`, `br.plugins_spoofed`, `br.webdriver_getter_tampered`, `br.webgl_os_vs_ua`, `br.no_pdfviewer`, `br.mimetypes_empty`, `br.notification_denied`, `br.voices_empty`, `br.media_devices_empty`, `br.webgpu_webgl_vs`, `br.math_engine_vs_ua`
- **worker-spoof** (bot): `br.cdp_runtime_enabled`, `br.headless_ua`, `br.ch_he_headless`, `bh.keystroke_entropy_floor`, `br.webgl_software`, `br.permissions_anomaly`, `br.no_chrome_object`, `br.no_plugins`, `br.webdriver_getter_tampered`, `br.worker_divergence`, `br.no_pdfviewer`, `br.mimetypes_empty`, `br.notification_denied`, `br.voices_empty`, `br.media_devices_empty`, `br.math_engine_vs_ua`
- **iframe-spoof** (bot): `br.ua_platform_vs_ch_platform`, `br.cdp_runtime_enabled`, `net.ch_platform_header_vs_ua`, `br.ch_he_headless`, `br.ch_he_version_vs_ua`, `bh.keystroke_entropy_floor`, `br.webgl_software`, `br.permissions_anomaly`, `br.no_chrome_object`, `br.no_plugins`, `br.webdriver_getter_tampered`, `br.webgl_os_vs_ua`, `br.navplatform_vs_ua`, `br.worker_divergence`, `br.no_pdfviewer`, `br.mimetypes_empty`, `br.notification_denied`, `br.iframe_divergence`, `br.voices_empty`, `br.fingerprint_improbable`, `br.media_devices_empty`, `br.font_linux_leak`, `br.codec_os_incoherent`, `br.math_engine_vs_ua`
- **native-spoof** (bot): `br.native_invariant_violated`, `br.cdp_runtime_enabled`, `br.headless_ua`, `br.ch_he_headless`, `bh.keystroke_entropy_floor`, `br.permissions_anomaly`, `br.no_chrome_object`, `br.no_plugins`, `br.webdriver_getter_tampered`, `br.webgl_os_vs_ua`, `br.no_pdfviewer`, `br.mimetypes_empty`, `br.notification_denied`, `br.voices_empty`, `br.media_devices_empty`, `br.webgpu_webgl_vs`, `br.math_engine_vs_ua`
- **linear-bot** (bot): `br.webdriver_present`, `br.cdp_runtime_enabled`, `bh.input_entropy_floor`, `bh.power_law_violation`, `br.headless_ua`, `br.ch_he_headless`, `bh.path_too_straight`, `bh.uniform_velocity`, `bh.synthetic_no_coalesced`, `br.webgl_software`, `br.permissions_anomaly`, `br.no_chrome_object`, `br.no_plugins`, `br.no_pdfviewer`, `br.mimetypes_empty`, `br.notification_denied`, `br.voices_empty`, `br.media_devices_empty`, `br.math_engine_vs_ua`
- **human-mouse** (bot): `br.webdriver_present`, `br.cdp_runtime_enabled`, `br.headless_ua`, `br.ch_he_headless`, `bh.synthetic_no_coalesced`, `br.webgl_software`, `br.permissions_anomaly`, `br.no_chrome_object`, `br.no_plugins`, `br.no_pdfviewer`, `br.mimetypes_empty`, `br.notification_denied`, `br.voices_empty`, `br.media_devices_empty`, `br.math_engine_vs_ua`
- **patchright** (bot): `br.headless_ua`, `br.ch_he_headless`, `bh.keystroke_entropy_floor`, `br.webgl_software`, `br.permissions_anomaly`, `br.no_chrome_object`, `br.no_plugins`, `br.no_pdfviewer`, `br.mimetypes_empty`, `br.notification_denied`, `br.voices_empty`, `br.media_devices_empty`, `br.math_engine_vs_ua`
- **camoufox** (bot): `net.tcp_os_vs_ua`, `net.no_js_execution`, `net.tls_grease_vs_ua`
- **nodriver** (bot): `net.quic_grease_vs_ua`, `bh.input_entropy_floor`, `bh.no_input_before_action`, `br.headless_ua`, `br.webgl_software`, `br.chrome_runtime_missing`, `br.hover_none_desktop`, `br.voices_empty`, `br.media_devices_empty`
