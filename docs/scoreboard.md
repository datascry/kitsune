# Kitsune scoreboard

- generated: `2026-06-18T01:56:14.105877+00:00`
- ruleset: `live`

| Evader | Ver | Network | Browser | Behavioral | Reputation | Incoh. | Score | Label |
|---|---|---|---|---|---|---|---|---|
| vanilla | live | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | human |
| stealth-naive | live | 0.00 | 0.98 | 0.00 | 0.00 | 0.00 | 0.98 | bot |
| stealth-patched | live | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | human |
| spoof-ua | live | 0.70 | 0.70 | 0.00 | 0.00 | 0.70 | 1.00 | bot |
| agent | live | 0.00 | 0.00 | 0.80 | 0.00 | 0.00 | 0.80 | bot |

## Why

- **stealth-naive** (bot): `br.webdriver_present`, `br.headless_ua`
- **spoof-ua** (bot): `net.tls_vs_ua_browser`
- **agent** (bot): `bh.input_entropy_floor`, `bh.no_input_before_action`
