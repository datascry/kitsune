# Kitsune detection matrix — 28 engines

| Detector | layer | camoufox | full-stealth | patchright | spoof-ua | stealth-naive | stealth-patched | vanilla | catches |
|---|---|---|---|---|---|---|---|---|---|
| `net.tls_os_vs_tcp_os` | network | · | · | · | · | · | · | · | 0 |
| `net.tls_vs_ua_browser` | network,browser | · | · | · | ✓ | · | · | · | 1 |
| `net.h2_vs_ua_browser` | network,browser | · | · | · | · | · | · | · | 0 |
| `br.ua_platform_vs_ch_platform` | browser | · | · | · | · | · | · | · | 0 |
| `br.webdriver_present` | browser | · | · | · | · | ✓ | · | · | 1 |
| `br.cdp_runtime_enabled` | browser | · | · | · | · | · | · | · | 0 |
| `br.canvas_lie` | browser | · | · | · | · | · | · | · | 0 |
| `bh.input_entropy_floor` | behavioral | · | · | · | · | · | · | · | 0 |
| `bh.no_input_before_action` | behavioral | · | · | · | · | · | · | · | 0 |
| `rep.datacenter_asn` | reputation | · | · | · | · | · | · | · | 0 |
| `net.h2_vs_tls_browser` | network | · | · | · | · | · | · | · | 0 |
| `br.headless_ua` | browser | · | · | ✓ | · | ✓ | · | · | 2 |
| `bh.keystroke_entropy_floor` | behavioral | · | · | · | · | · | · | · | 0 |
| `rep.known_proxy_exit` | reputation | · | · | · | · | · | · | · | 0 |
| `bh.path_too_straight` | behavioral | · | · | · | · | · | · | · | 0 |
| `bh.uniform_velocity` | behavioral | · | · | · | · | · | · | · | 0 |
| `br.webdriver_spoofed` | browser | · | · | · | ✓ | · | ✓ | · | 2 |
| `br.webgl_software` | browser | · | · | ✓ | ✓ | ✓ | ✓ | · | 4 |
| `br.permissions_anomaly` | browser | · | ✓ | ✓ | ✓ | ✓ | ✓ | · | 5 |
| `br.no_chrome_object` | browser | · | · | ✓ | · | ✓ | ✓ | · | 3 |
| `br.tostring_tampered` | browser | · | · | · | · | · | · | · | 0 |
| `br.low_hardware_concurrency` | browser | · | · | · | · | · | · | · | 0 |
| `br.no_plugins` | browser | · | · | ✓ | ✓ | ✓ | ✓ | · | 4 |
| `br.webgl_getparameter_tampered` | browser | · | ✓ | · | · | · | · | · | 1 |
| `br.plugins_spoofed` | browser | · | ✓ | · | · | · | · | · | 1 |
| `br.webdriver_getter_tampered` | browser | · | ✓ | · | · | · | · | · | 1 |
| `br.webgl_os_vs_ua` | browser | · | ✓ | · | · | · | ✓ | · | 2 |
| `br.navplatform_vs_ua` | browser | · | · | · | · | · | · | · | 0 |
| **flagged** |  | **0/28** | **5/28** | **5/28** | **5/28** | **6/28** | **6/28** | **0/28** |  |
| **verdict** |  | **human** | **bot** | **bot** | **bot** | **bot** | **bot** | **human** |  |

## Coverage gaps — 16/28 engines catch nothing yet

- `net.tls_os_vs_tcp_os`
- `net.h2_vs_ua_browser`
- `br.ua_platform_vs_ch_platform`
- `br.cdp_runtime_enabled`
- `br.canvas_lie`
- `bh.input_entropy_floor`
- `bh.no_input_before_action`
- `rep.datacenter_asn`
- `net.h2_vs_tls_browser`
- `bh.keystroke_entropy_floor`
- `rep.known_proxy_exit`
- `bh.path_too_straight`
- `bh.uniform_velocity`
- `br.tostring_tampered`
- `br.low_hardware_concurrency`
- `br.navplatform_vs_ua`
