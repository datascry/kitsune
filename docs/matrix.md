# Kitsune detection matrix — 81 engines

| Detector | layer | baseline-firefox | brave | camoufox-hardened | camoufox-headful | camoufox | curl-impersonate | floor-spoof | full-stealth | human-mouse | max-stealth | nodriver | patchright | pydoll | rebrowser | selenium-driverless | spoof-ua | stealth-naive | stealth-patched | undetected | vanilla | zendriver | catches |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `net.tls_os_vs_tcp_os` | network | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `net.tls_vs_ua_browser` | network,browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | 1 |
| `net.h2_vs_ua_browser` | network,browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | 1 |
| `br.ua_platform_vs_ch_platform` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.webdriver_present` | browser | ✓ | ✓ | · | · | · | · | · | · | ✓ | · | · | · | · | ✓ | · | · | ✓ | · | · | · | · | 5 |
| `br.cdp_runtime_enabled` | browser | · | · | · | · | · | · | · | ✓ | ✓ | · | · | · | · | · | · | · | ✓ | ✓ | · | · | · | 4 |
| `br.csp_bypassed` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.canvas_lie` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `bh.input_entropy_floor` | behavioral | · | ✓ | · | · | · | · | · | · | · | · | ✓ | · | ✓ | · | ✓ | · | · | · | ✓ | · | ✓ | 6 |
| `bh.no_input_before_action` | behavioral | · | ✓ | · | · | · | · | · | · | · | · | ✓ | · | ✓ | · | ✓ | · | · | · | ✓ | · | ✓ | 6 |
| `rep.datacenter_asn` | reputation | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `net.h2_vs_tls_browser` | network | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `net.accept_lang_vs_navigator` | network,browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `net.ch_platform_header_vs_ua` | network,browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `net.ch_ua_vs_ua_browser` | network,browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | 1 |
| `net.h2_settings_vs_order` | network | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.headless_ua` | browser | · | ✓ | · | · | · | · | · | · | ✓ | · | ✓ | ✓ | ✓ | ✓ | ✓ | · | ✓ | · | ✓ | · | · | 9 |
| `bh.keystroke_entropy_floor` | behavioral | · | · | · | · | · | · | ✓ | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | 2 |
| `rep.known_proxy_exit` | reputation | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `bh.path_too_straight` | behavioral | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `bh.uniform_velocity` | behavioral | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `bh.synthetic_no_coalesced` | behavioral | · | · | · | · | · | · | ✓ | · | ✓ | ✓ | · | · | · | · | · | · | · | · | · | · | · | 3 |
| `br.webdriver_spoofed` | browser | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | ✓ | · | ✓ | · | · | · | 3 |
| `br.webgl_software` | browser | · | ✓ | · | · | · | · | ✓ | · | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | · | ✓ | 14 |
| `br.permissions_anomaly` | browser | · | · | · | · | · | · | · | ✓ | ✓ | ✓ | · | ✓ | · | ✓ | · | ✓ | ✓ | ✓ | · | · | · | 8 |
| `br.no_chrome_object` | browser | · | · | · | · | · | · | · | · | ✓ | ✓ | · | ✓ | · | ✓ | · | · | ✓ | ✓ | · | · | · | 6 |
| `br.tostring_tampered` | browser | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 1 |
| `br.low_hardware_concurrency` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.no_plugins` | browser | ✓ | · | · | · | · | · | ✓ | · | ✓ | ✓ | · | ✓ | · | ✓ | · | ✓ | ✓ | ✓ | · | · | · | 9 |
| `br.webgl_getparameter_tampered` | browser | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | 1 |
| `br.plugins_spoofed` | browser | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | 1 |
| `br.nav_property_spoofed` | browser | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 1 |
| `br.webdriver_getter_tampered` | browser | · | · | · | · | · | · | ✓ | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | 2 |
| `br.notification_getter_tampered` | browser | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 1 |
| `br.webgl_os_vs_ua` | browser | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | 2 |
| `br.navplatform_vs_ua` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | 1 |
| `br.worker_divergence` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.vendor_vs_ua` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | 1 |
| `br.oscpu_vs_ua` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.languages_empty` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.screen_zero` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.no_connection` | browser | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 1 |
| `br.no_pdfviewer` | browser | · | · | · | · | · | · | · | ✓ | ✓ | ✓ | · | ✓ | · | ✓ | · | · | ✓ | ✓ | · | · | · | 7 |
| `br.chrome_runtime_missing` | browser | · | ✓ | · | · | · | · | · | · | · | · | ✓ | · | ✓ | · | ✓ | · | · | · | ✓ | · | ✓ | 6 |
| `br.mimetypes_empty` | browser | ✓ | · | · | · | · | · | · | ✓ | ✓ | ✓ | · | ✓ | · | ✓ | · | ✓ | ✓ | ✓ | · | · | · | 9 |
| `br.no_devicememory` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.notification_denied` | browser | · | · | · | · | · | · | · | ✓ | ✓ | ✓ | · | ✓ | · | ✓ | · | ✓ | ✓ | ✓ | · | · | · | 8 |
| `br.platform_empty` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.productsub_vs_ua` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | 1 |
| `br.cdc_artifacts` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.webgl2_missing` | browser | ✓ | · | ✓ | ✓ | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 4 |
| `br.iframe_divergence` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.font_os_vs_ua` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.screen_avail_invalid` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.color_depth_anomaly` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.devicepixelratio_anomaly` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.hover_none_desktop` | browser | · | · | · | · | · | · | · | · | · | · | ✓ | · | ✓ | · | ✓ | · | · | · | ✓ | · | ✓ | 5 |
| `br.pointer_touch_incoherent` | browser | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 1 |
| `br.voices_empty` | browser | ✓ | ✓ | ✓ | ✓ | ✓ | · | · | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | · | ✓ | 18 |
| `br.voice_os_vs_ua` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.webgl_renderer_artifact` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.audio_missing` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.audio_noise` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.media_devices_empty` | browser | ✓ | ✓ | ✓ | ✓ | ✓ | · | · | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | · | ✓ | 18 |
| `br.adblock_present` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.macos_dpr1` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.font_linux_leak` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | 1 |
| `br.font_mac_internal` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.codec_os_incoherent` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | 1 |
| `br.webrtc_unavailable` | browser | · | · | ✓ | ✓ | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | 4 |
| `net.webrtc_ip_vs_observed` | network,browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.timezone_inconsistent` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.engine_stack_vs_ua` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | 1 |
| `net.no_js_execution` | network,browser | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | 2 |
| `br.webgpu_webgl_vs` | browser | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | 1 |
| `br.webgpu_vendor_vs_webgl` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.error_engine_vs_ua` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | 1 |
| `net.sec_fetch_vs_ua` | network,browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | 1 |
| `net.accept_encoding_vs_ua` | network,browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | 1 |
| `br.rfp_browser` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.canvas_noise` | browser | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 1 |
| **flagged** |  | **6/81** | **10/81** | **5/81** | **4/81** | **4/81** | **1/81** | **8/81** | **12/81** | **13/81** | **11/81** | **8/81** | **11/81** | **8/81** | **11/81** | **8/81** | **15/81** | **12/81** | **15/81** | **8/81** | **3/81** | **8/81** |  |
| **verdict** |  | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** |  |

## Detection class — coherence/artifact = spoofing caught; environment/automation = headless too

| Evader | verdict | coherence | artifact | automation | environment | behavioral | reputation |
|---|---|---|---|---|---|---|---|
| `baseline-firefox` | bot | 0 | 0 | 1 | 5 | 0 | 0 |
| `brave` | bot | 0 | 1 | 3 | 4 | 2 | 0 |
| `camoufox-hardened` | bot | 1 | 1 | 0 | 3 | 0 | 0 |
| `camoufox-headful` | bot | 0 | 1 | 0 | 3 | 0 | 0 |
| `camoufox` | bot | 0 | 1 | 0 | 3 | 0 | 0 |
| `curl-impersonate` | bot | 1 | 0 | 0 | 0 | 0 | 0 |
| `floor-spoof` | bot | 0 | 0 | 4 | 2 | 2 | 0 |
| `full-stealth` | bot | 2 | 0 | 6 | 4 | 0 | 0 |
| `human-mouse` | bot | 0 | 0 | 6 | 6 | 1 | 0 |
| `max-stealth` | bot | 0 | 0 | 4 | 6 | 1 | 0 |
| `nodriver` | bot | 1 | 0 | 2 | 3 | 2 | 0 |
| `patchright` | bot | 0 | 0 | 4 | 6 | 1 | 0 |
| `pydoll` | bot | 1 | 0 | 2 | 3 | 2 | 0 |
| `rebrowser` | bot | 0 | 0 | 5 | 6 | 0 | 0 |
| `selenium-driverless` | bot | 1 | 0 | 2 | 3 | 2 | 0 |
| `spoof-ua` | bot | 7 | 0 | 3 | 5 | 0 | 0 |
| `stealth-naive` | bot | 0 | 0 | 6 | 6 | 0 | 0 |
| `stealth-patched` | bot | 4 | 0 | 5 | 6 | 0 | 0 |
| `undetected` | bot | 1 | 0 | 2 | 3 | 2 | 0 |
| `vanilla` | bot | 3 | 0 | 0 | 0 | 0 | 0 |
| `zendriver` | bot | 1 | 1 | 1 | 3 | 2 | 0 |

## Coverage gaps — 36/81 engines catch nothing yet

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

**Unexercised** (26) — a read signal is absent from every recording, so the corpus cannot trip them yet (e.g. signals the recordings predate); these are validated by the detector unit + precision tests, and need a corpus refresh to appear here:
- `net.tls_os_vs_tcp_os`
- `br.csp_bypassed`
- `br.canvas_lie`
- `rep.datacenter_asn`
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
- `br.macos_dpr1`
- `br.font_mac_internal`
- `net.webrtc_ip_vs_observed`
- `br.timezone_inconsistent`
- `br.webgpu_vendor_vs_webgl`
- `br.rfp_browser`
