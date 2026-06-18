## Coordination — 1 graded cluster(s) across 3 sessions

### `fleet` — score **1.00** · 3 sessions
- members: rp1, rp2, rp3
- 3 sessions share JA4 cipher prefix `t13d1717h2_5b57614c22b0`
- cipher suites identical but JS divergent across members: hardware_concurrency x3, nav_platform_os x2, ua_platform x2
- cipher suites identical but JA4 extensions/sig-algs divergent (3 variants) — per-launch TLS randomization
- timing lockstep: all members arrived within 23s
- distributed across 3 distinct source IPs — residential-proxy fleet pattern (IP diversity masks one shared engine, defeating IP/ASN rules)
- 3 proxy IPs front one real IP `45.137.0.42` (WebRTC) — same-origin fleet

