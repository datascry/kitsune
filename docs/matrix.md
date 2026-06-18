# Kitsune detection matrix — 72 engines

| Detector | layer | baseline-firefox | brave | camoufox-hardened | camoufox-headful | camoufox | full-stealth | human-mouse | max-stealth | nodriver | patchright | rebrowser | spoof-ua | stealth-naive | stealth-patched | undetected | vanilla | catches |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `net.tls_os_vs_tcp_os` | network | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `net.tls_vs_ua_browser` | network,browser | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | 1 |
| `net.h2_vs_ua_browser` | network,browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.ua_platform_vs_ch_platform` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.webdriver_present` | browser | ✓ | ✓ | · | · | · | · | ✓ | · | · | · | ✓ | · | ✓ | · | · | · | 5 |
| `br.cdp_runtime_enabled` | browser | · | · | · | · | · | ✓ | ✓ | · | · | · | · | · | ✓ | · | · | · | 3 |
| `br.canvas_lie` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `bh.input_entropy_floor` | behavioral | · | ✓ | · | · | · | · | · | · | ✓ | · | · | · | · | · | ✓ | · | 3 |
| `bh.no_input_before_action` | behavioral | · | ✓ | · | · | · | · | · | · | ✓ | · | · | · | · | · | ✓ | · | 3 |
| `rep.datacenter_asn` | reputation | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `net.h2_vs_tls_browser` | network | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.headless_ua` | browser | · | ✓ | · | · | · | · | ✓ | · | ✓ | ✓ | ✓ | · | ✓ | · | ✓ | · | 7 |
| `bh.keystroke_entropy_floor` | behavioral | · | · | · | · | · | ✓ | · | · | · | · | · | ✓ | ✓ | · | · | · | 3 |
| `rep.known_proxy_exit` | reputation | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `bh.path_too_straight` | behavioral | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `bh.uniform_velocity` | behavioral | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.webdriver_spoofed` | browser | · | · | · | · | · | · | · | ✓ | · | · | · | ✓ | · | ✓ | · | · | 3 |
| `br.webgl_software` | browser | · | ✓ | · | · | · | · | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | · | 10 |
| `br.permissions_anomaly` | browser | · | · | · | · | · | ✓ | ✓ | ✓ | · | ✓ | ✓ | ✓ | ✓ | ✓ | · | · | 8 |
| `br.no_chrome_object` | browser | · | · | · | · | · | · | ✓ | ✓ | · | ✓ | ✓ | · | ✓ | ✓ | · | · | 6 |
| `br.tostring_tampered` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.low_hardware_concurrency` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.no_plugins` | browser | ✓ | · | · | · | · | · | ✓ | ✓ | · | ✓ | ✓ | ✓ | ✓ | ✓ | · | · | 8 |
| `br.webgl_getparameter_tampered` | browser | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | 1 |
| `br.plugins_spoofed` | browser | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | 1 |
| `br.webdriver_getter_tampered` | browser | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | 1 |
| `br.webgl_os_vs_ua` | browser | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | ✓ | · | · | 2 |
| `br.navplatform_vs_ua` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.worker_divergence` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.vendor_vs_ua` | browser | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | 1 |
| `br.oscpu_vs_ua` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.languages_empty` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.screen_zero` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.no_connection` | browser | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 1 |
| `br.no_pdfviewer` | browser | · | · | · | · | · | ✓ | ✓ | ✓ | · | ✓ | ✓ | · | ✓ | · | · | · | 6 |
| `br.chrome_runtime_missing` | browser | · | ✓ | · | · | · | · | · | · | ✓ | · | · | · | · | · | ✓ | · | 3 |
| `br.mimetypes_empty` | browser | ✓ | · | · | · | · | ✓ | ✓ | ✓ | · | ✓ | ✓ | ✓ | ✓ | · | · | · | 8 |
| `br.no_devicememory` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.notification_denied` | browser | · | · | · | · | · | ✓ | ✓ | ✓ | · | ✓ | ✓ | ✓ | ✓ | · | · | · | 7 |
| `br.platform_empty` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.productsub_vs_ua` | browser | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | 1 |
| `br.cdc_artifacts` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.webgl2_missing` | browser | ✓ | · | ✓ | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | 3 |
| `br.iframe_divergence` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.font_os_vs_ua` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.screen_avail_invalid` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.color_depth_anomaly` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.devicepixelratio_anomaly` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.hover_none_desktop` | browser | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | ✓ | · | 2 |
| `br.pointer_touch_incoherent` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.voices_empty` | browser | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | · | ✓ | · | 14 |
| `br.voice_os_vs_ua` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.webgl_renderer_artifact` | browser | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | 1 |
| `br.audio_missing` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.audio_noise` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.media_devices_empty` | browser | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | · | ✓ | · | 14 |
| `br.adblock_present` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.macos_dpr1` | browser | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | 1 |
| `br.font_linux_leak` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.font_mac_internal` | browser | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | 1 |
| `br.codec_os_incoherent` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.webrtc_unavailable` | browser | · | · | ✓ | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | 2 |
| `net.webrtc_ip_vs_observed` | network,browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.timezone_inconsistent` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.engine_stack_vs_ua` | browser | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | 1 |
| `net.no_js_execution` | network,browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | 1 |
| `br.webgpu_webgl_vs` | browser | · | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | 1 |
| `br.webgpu_vendor_vs_webgl` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.error_engine_vs_ua` | browser | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | · | 1 |
| `net.sec_fetch_vs_ua` | network,browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.rfp_browser` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.canvas_noise` | browser | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 1 |
| **flagged** |  | **6/72** | **10/72** | **4/72** | **3/72** | **6/72** | **13/72** | **12/72** | **10/72** | **8/72** | **10/72** | **11/72** | **14/72** | **13/72** | **6/72** | **8/72** | **1/72** |  |
| **verdict** |  | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** |  |

## Detection class — coherence/artifact = spoofing caught; environment/automation = headless too

| Evader | verdict | coherence | artifact | automation | environment | behavioral | reputation |
|---|---|---|---|---|---|---|---|
| `baseline-firefox` | bot | 0 | 0 | 1 | 5 | 0 | 0 |
| `brave` | bot | 0 | 1 | 3 | 4 | 2 | 0 |
| `camoufox-hardened` | bot | 0 | 1 | 0 | 3 | 0 | 0 |
| `camoufox-headful` | bot | 0 | 1 | 0 | 2 | 0 | 0 |
| `camoufox` | bot | 1 | 2 | 0 | 3 | 0 | 0 |
| `full-stealth` | bot | 2 | 0 | 6 | 4 | 1 | 0 |
| `human-mouse` | bot | 0 | 0 | 6 | 6 | 0 | 0 |
| `max-stealth` | bot | 0 | 0 | 4 | 6 | 0 | 0 |
| `nodriver` | bot | 1 | 0 | 2 | 3 | 2 | 0 |
| `patchright` | bot | 0 | 0 | 4 | 6 | 0 | 0 |
| `rebrowser` | bot | 0 | 0 | 5 | 6 | 0 | 0 |
| `spoof-ua` | bot | 5 | 0 | 3 | 5 | 1 | 0 |
| `stealth-naive` | bot | 0 | 0 | 6 | 6 | 1 | 0 |
| `stealth-patched` | bot | 1 | 0 | 3 | 2 | 0 | 0 |
| `undetected` | bot | 1 | 0 | 2 | 3 | 2 | 0 |
| `vanilla` | bot | 1 | 0 | 0 | 0 | 0 | 0 |

## Coverage gaps — 36/72 engines catch nothing yet

- `net.tls_os_vs_tcp_os`
- `net.h2_vs_ua_browser`
- `br.ua_platform_vs_ch_platform`
- `br.canvas_lie`
- `rep.datacenter_asn`
- `net.h2_vs_tls_browser`
- `rep.known_proxy_exit`
- `bh.path_too_straight`
- `bh.uniform_velocity`
- `br.tostring_tampered`
- `br.low_hardware_concurrency`
- `br.navplatform_vs_ua`
- `br.worker_divergence`
- `br.oscpu_vs_ua`
- `br.languages_empty`
- `br.screen_zero`
- `br.no_devicememory`
- `br.platform_empty`
- `br.cdc_artifacts`
- `br.iframe_divergence`
- `br.font_os_vs_ua`
- `br.screen_avail_invalid`
- `br.color_depth_anomaly`
- `br.devicepixelratio_anomaly`
- `br.pointer_touch_incoherent`
- `br.voice_os_vs_ua`
- `br.audio_missing`
- `br.audio_noise`
- `br.adblock_present`
- `br.font_linux_leak`
- `br.codec_os_incoherent`
- `net.webrtc_ip_vs_observed`
- `br.timezone_inconsistent`
- `br.webgpu_vendor_vs_webgl`
- `net.sec_fetch_vs_ua`
- `br.rfp_browser`
