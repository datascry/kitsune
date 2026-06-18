# Kitsune scoreboard

- generated: `2026-06-18T02:38:51.695483+00:00`
- ruleset: `live`

| Evader | Ver | Network | Browser | Behavioral | Reputation | Incoh. | Score | Label |
|---|---|---|---|---|---|---|---|---|
| vanilla | live | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | human |
| stealth-naive | live | 0.00 | 1.00 | 0.00 | 0.00 | 0.00 | 1.00 | bot |
| stealth-patched | live | 0.00 | 1.00 | 0.00 | 0.00 | 0.00 | 1.00 | bot |
| spoof-ua | live | 0.70 | 1.00 | 0.00 | 0.00 | 0.70 | 1.00 | bot |
| full-stealth | live | 0.00 | 1.00 | 0.00 | 0.00 | 0.00 | 1.00 | bot |

## Why

- **stealth-naive** (bot): `br.webdriver_present`, `br.headless_ua`, `br.webgl_software`, `br.permissions_anomaly`, `br.no_chrome_object`, `br.no_plugins`
- **stealth-patched** (bot): `br.webdriver_spoofed`, `br.webgl_software`, `br.permissions_anomaly`, `br.no_chrome_object`, `br.no_plugins`, `br.webgl_os_vs_ua`
- **spoof-ua** (bot): `net.tls_vs_ua_browser`, `br.webdriver_spoofed`, `br.webgl_software`, `br.permissions_anomaly`, `br.no_plugins`
- **full-stealth** (bot): `br.permissions_anomaly`, `br.webgl_getparameter_tampered`, `br.plugins_spoofed`, `br.webdriver_getter_tampered`, `br.webgl_os_vs_ua`
