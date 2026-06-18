# Kitsune detection matrix — 66 engines

| Detector | layer | baseline-firefox | camoufox-hardened | camoufox-headful | camoufox | full-stealth | human-mouse | max-stealth | nodriver | patchright | rebrowser | spoof-ua | stealth-naive | stealth-patched | vanilla | catches |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `net.tls_os_vs_tcp_os` | network | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `net.tls_vs_ua_browser` | network,browser | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | 1 |
| `net.h2_vs_ua_browser` | network,browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.ua_platform_vs_ch_platform` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.webdriver_present` | browser | ✓ | · | · | · | · | ✓ | · | · | · | ✓ | · | ✓ | · | · | 4 |
| `br.cdp_runtime_enabled` | browser | · | · | · | · | · | ✓ | · | · | · | · | · | ✓ | · | · | 2 |
| `br.canvas_lie` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `bh.input_entropy_floor` | behavioral | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | 1 |
| `bh.no_input_before_action` | behavioral | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | 1 |
| `rep.datacenter_asn` | reputation | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `net.h2_vs_tls_browser` | network | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.headless_ua` | browser | · | · | · | · | · | ✓ | · | ✓ | ✓ | ✓ | · | ✓ | · | · | 5 |
| `bh.keystroke_entropy_floor` | behavioral | · | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | 1 |
| `rep.known_proxy_exit` | reputation | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `bh.path_too_straight` | behavioral | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `bh.uniform_velocity` | behavioral | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.webdriver_spoofed` | browser | · | · | · | · | · | · | ✓ | · | · | · | ✓ | · | ✓ | · | 3 |
| `br.webgl_software` | browser | · | · | · | · | · | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | · | 8 |
| `br.permissions_anomaly` | browser | · | · | · | · | ✓ | ✓ | ✓ | · | ✓ | ✓ | ✓ | ✓ | ✓ | · | 8 |
| `br.no_chrome_object` | browser | · | · | · | · | · | ✓ | ✓ | · | ✓ | ✓ | · | ✓ | ✓ | · | 6 |
| `br.tostring_tampered` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.low_hardware_concurrency` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.no_plugins` | browser | ✓ | · | · | · | · | ✓ | ✓ | · | ✓ | ✓ | ✓ | ✓ | ✓ | · | 8 |
| `br.webgl_getparameter_tampered` | browser | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | 1 |
| `br.plugins_spoofed` | browser | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | 1 |
| `br.webdriver_getter_tampered` | browser | · | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | 1 |
| `br.webgl_os_vs_ua` | browser | · | · | · | · | ✓ | · | · | · | · | · | · | · | ✓ | · | 2 |
| `br.navplatform_vs_ua` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.worker_divergence` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.vendor_vs_ua` | browser | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | 1 |
| `br.oscpu_vs_ua` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.languages_empty` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.screen_zero` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.no_connection` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.no_pdfviewer` | browser | · | · | · | · | · | ✓ | ✓ | · | ✓ | ✓ | · | ✓ | · | · | 5 |
| `br.chrome_runtime_missing` | browser | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | 1 |
| `br.mimetypes_empty` | browser | ✓ | · | · | · | · | ✓ | ✓ | · | ✓ | ✓ | ✓ | ✓ | · | · | 7 |
| `br.no_devicememory` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.notification_denied` | browser | · | · | · | · | · | ✓ | ✓ | · | ✓ | ✓ | ✓ | ✓ | · | · | 6 |
| `br.platform_empty` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.productsub_vs_ua` | browser | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | 1 |
| `br.cdc_artifacts` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.webgl2_missing` | browser | ✓ | ✓ | · | ✓ | · | · | · | · | · | · | · | · | · | · | 3 |
| `br.iframe_divergence` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.font_os_vs_ua` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.screen_avail_invalid` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.color_depth_anomaly` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.devicepixelratio_anomaly` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.hover_none_desktop` | browser | · | · | · | · | · | · | · | ✓ | · | · | · | · | · | · | 1 |
| `br.pointer_touch_incoherent` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.voices_empty` | browser | ✓ | ✓ | ✓ | ✓ | · | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | · | · | 11 |
| `br.voice_os_vs_ua` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.webgl_renderer_artifact` | browser | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | · | 1 |
| `br.audio_missing` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.audio_noise` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.media_devices_empty` | browser | ✓ | ✓ | ✓ | ✓ | · | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | · | · | 11 |
| `br.adblock_present` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.macos_dpr1` | browser | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | 1 |
| `br.font_linux_leak` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.font_mac_internal` | browser | · | · | · | ✓ | · | · | · | · | · | · | · | · | · | · | 1 |
| `br.codec_os_incoherent` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.webrtc_unavailable` | browser | · | ✓ | · | ✓ | · | · | · | · | · | · | · | · | · | · | 2 |
| `net.webrtc_ip_vs_observed` | network,browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.timezone_inconsistent` | browser | · | · | · | · | · | · | · | · | · | · | · | · | · | · | 0 |
| `br.engine_stack_vs_ua` | browser | · | · | · | · | · | · | · | · | · | · | ✓ | · | · | · | 1 |
| `net.no_js_execution` | network,browser | · | · | · | · | · | · | · | · | · | · | · | · | · | ✓ | 1 |
| **flagged** |  | **6/66** | **4/66** | **3/66** | **6/66** | **5/66** | **12/66** | **10/66** | **8/66** | **10/66** | **11/66** | **12/66** | **13/66** | **6/66** | **1/66** |  |
| **verdict** |  | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** | **bot** |  |

## Detection class — coherence/artifact = spoofing caught; environment/automation = headless too

| Evader | verdict | coherence | artifact | automation | environment | behavioral | reputation |
|---|---|---|---|---|---|---|---|
| `baseline-firefox` | bot | 0 | 0 | 1 | 5 | 0 | 0 |
| `camoufox-hardened` | bot | 0 | 1 | 0 | 3 | 0 | 0 |
| `camoufox-headful` | bot | 0 | 1 | 0 | 2 | 0 | 0 |
| `camoufox` | bot | 1 | 2 | 0 | 3 | 0 | 0 |
| `full-stealth` | bot | 1 | 0 | 4 | 0 | 0 | 0 |
| `human-mouse` | bot | 0 | 0 | 6 | 6 | 0 | 0 |
| `max-stealth` | bot | 0 | 0 | 4 | 6 | 0 | 0 |
| `nodriver` | bot | 1 | 0 | 2 | 3 | 2 | 0 |
| `patchright` | bot | 0 | 0 | 4 | 6 | 0 | 0 |
| `rebrowser` | bot | 0 | 0 | 5 | 6 | 0 | 0 |
| `spoof-ua` | bot | 4 | 0 | 3 | 5 | 0 | 0 |
| `stealth-naive` | bot | 0 | 0 | 6 | 6 | 1 | 0 |
| `stealth-patched` | bot | 1 | 0 | 3 | 2 | 0 | 0 |
| `vanilla` | bot | 1 | 0 | 0 | 0 | 0 | 0 |

## Coverage gaps — 34/66 engines catch nothing yet

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
- `br.no_connection`
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
