# Kitsune detection matrix — 23 engines

| Detector | layer | spoof-ua | stealth-naive | stealth-patched | vanilla | catches |
|---|---|---|---|---|---|---|
| `net.tls_os_vs_tcp_os` | network | · | · | · | · | 0 |
| `net.tls_vs_ua_browser` | network,browser | ✓ | · | · | · | 1 |
| `net.h2_vs_ua_browser` | network,browser | · | · | · | · | 0 |
| `br.ua_platform_vs_ch_platform` | browser | · | · | · | · | 0 |
| `br.webdriver_present` | browser | · | ✓ | · | · | 1 |
| `br.cdp_runtime_enabled` | browser | · | · | · | · | 0 |
| `br.canvas_lie` | browser | · | · | · | · | 0 |
| `bh.input_entropy_floor` | behavioral | · | · | · | · | 0 |
| `bh.no_input_before_action` | behavioral | · | · | · | · | 0 |
| `rep.datacenter_asn` | reputation | · | · | · | · | 0 |
| `net.h2_vs_tls_browser` | network | · | · | · | · | 0 |
| `br.headless_ua` | browser | · | ✓ | · | · | 1 |
| `bh.keystroke_entropy_floor` | behavioral | · | · | · | · | 0 |
| `rep.known_proxy_exit` | reputation | · | · | · | · | 0 |
| `bh.path_too_straight` | behavioral | · | · | · | · | 0 |
| `bh.uniform_velocity` | behavioral | · | · | · | · | 0 |
| `br.webdriver_spoofed` | browser | ✓ | · | ✓ | · | 2 |
| `br.webgl_software` | browser | ✓ | ✓ | ✓ | · | 3 |
| `br.permissions_anomaly` | browser | ✓ | ✓ | ✓ | · | 3 |
| `br.no_chrome_object` | browser | · | ✓ | ✓ | · | 2 |
| `br.tostring_tampered` | browser | · | · | · | · | 0 |
| `br.low_hardware_concurrency` | browser | · | · | · | · | 0 |
| `br.no_plugins` | browser | ✓ | ✓ | ✓ | · | 3 |
| **flagged** |  | **5/23** | **6/23** | **5/23** | **0/23** |  |
| **verdict** |  | **bot** | **bot** | **bot** | **human** |  |
