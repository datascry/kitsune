# Coordination verdicts — the two fleet shapes a spoofing fleet cannot both avoid

A fleet hides behind a shared engine identity (JA4) but must look like distinct users. It has exactly two
ways to do that, and the scorer catches each with a complementary signal:

- **Randomize JS per instance** (Camoufox) → the JS-divergence paradox: shared TLS, divergent JS.
- **Clone one fingerprint profile** (BotBrowser) → the fingerprint-collision: identical high-entropy
  `fp_hash` across distinct source IPs (where real machines each hash differently).

Both verdicts below are **real `score_cluster` output**, not hand-authored, on a synthetic 3-node fleet
(the lab has no live proxies/BotBrowser build to capture).

## The conviction gate (why the JS-divergence paradox cannot convict alone)

A `fleet` *label* requires a **convicting** coordination signal — one a real diverse cohort cannot
produce: JA4_c divergence (per-launch TLS-extension randomization; real Chrome's JA4_c is stable), a
cloned-fingerprint collision across distinct IPs, or a shared WebRTC origin behind distinct proxy IPs.
The JS-divergence paradox, IP spread and lockstep are **corroborating only**, because they are *also* the
null hypothesis: distinct real users on one Chrome build share a JA4 (TLS is per-build) yet legitimately
differ in `hardware_concurrency`, `device_memory` and OS-platform (Win/Mac/Linux Chrome share a JA4) and
arrive from distinct IPs. Without the gate, a 4-user real cohort on one popular build — diverse hardware,
distinct IPs, distinct `fp_hash`, spread over 15 min — scored `fleet` 1.00 (a botnet verdict on a
browser's user base); it is now correctly capped at `candidate`. Both fleets below clear the gate (one via
JA4_c divergence + shared origin, the other via the fingerprint collision), so their verdicts are
unchanged — the gate only withholds conviction where the only evidence is what legitimate diversity also
produces. This mirrors the detector's convicting-signal gate (`scoring.label_for`) on the per-session side.

## Randomizing fleet (residential proxies) — 1 graded cluster across 3 sessions

### `fleet` — score **1.00** · 3 sessions
- **severity: moderate** (12 requests, 7.8/min)
- members: rp1, rp2, rp3
- 3 sessions share JA4 cipher prefix `t13d1717h2_5b57614c22b0`
- cipher suites identical but JS divergent across members: hardware_concurrency x3, nav_platform_os x2, ua_platform x2
- cipher suites identical but JA4 extensions/sig-algs divergent (3 variants) — per-launch TLS randomization
- timing lockstep: all members arrived within 23s
- distributed across 3 distinct source IPs — residential-proxy fleet pattern (IP diversity masks one shared engine, defeating IP/ASN rules)
- 3 proxy IPs front one real IP `45.137.0.42` (WebRTC) — same-origin fleet

## Cloned-profile fleet (BotBrowser-style reuse) — 1 graded cluster across 3 sessions

The trap this closes: JS is **homogeneous** (the scorer notes it "consistent with a real cohort"), so the
JS-divergence paradox stays silent and the old scorer rated this only a `candidate`. The fingerprint
collision across distinct IPs is what convicts it.

### `fleet` — score **1.00** · 3 sessions (illustrative synthetic)
- **severity: moderate** (6 requests, 8.2/min)
- members: bb1, bb2, bb3
- 3 sessions share JA4 cipher prefix `t13d1516h2_8daaf6152771`
- JS traits homogeneous across members — consistent with a real cohort
- identical high-entropy fingerprint `7c3a9f12` across 3 distinct source IPs — cloned-profile reuse (one anti-detect profile shared fleet-wide)
- timing lockstep: all members arrived within 22s
- distributed across 3 distinct source IPs — residential-proxy fleet pattern (IP diversity masks one shared engine, defeating IP/ASN rules)

### `fleet` — score **1.00** · 2 sessions (**live capture**, `corpus/sessions/chrome-clone-*.json`)

Two stock **headless Chromium** instances are a cloned profile by construction (same build +
deterministic SwiftShader rendering → byte-identical `fp_hash`). Captured concurrently so the edge sees
distinct container IPs, each ran the in-browser collector and emitted the same hash — real scorer output:

- members: chrome-clone-1, chrome-clone-2
- 2 sessions share JA4 cipher prefix `t13d1516h2_8daaf6152771`
- JS traits homogeneous across members — consistent with a real cohort
- identical high-entropy fingerprint `28718b97` across 2 distinct source IPs — cloned-profile reuse (one anti-detect profile shared fleet-wide)
- timing lockstep: all members arrived within 1s
- distributed across 2 distinct source IPs — residential-proxy fleet pattern (IP diversity masks one shared engine, defeating IP/ASN rules)

