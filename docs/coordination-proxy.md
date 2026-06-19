# Coordination verdicts — the two fleet shapes a spoofing fleet cannot both avoid

A fleet hides behind a shared engine identity (JA4) but must look like distinct users. It has exactly two
ways to do that, and the scorer catches each with a complementary signal:

- **Randomize JS per instance** (Camoufox) → the JS-divergence paradox: shared TLS, divergent JS.
- **Clone one fingerprint profile** (BotBrowser) → the fingerprint-collision: identical high-entropy
  `fp_hash` across distinct source IPs (where real machines each hash differently).

Both verdicts below are **real `score_cluster` output**, not hand-authored, on a synthetic 3-node fleet
(the lab has no *ongoing* live proxy harness).

## Validated against the REAL captured fleets (not just synthetic)

The coordination detector was synthetic-only; it is now also grounded on the **real fleet captures**
that came through the edge→detector pipeline (`corpus/fleet-proxy/`, `corpus/fleet-cloned/`, `corpus/fleet/`),
pinned in `test_coordination.py`:

| capture | members | verdict | why |
|---|---|---|---|
| `corpus/fleet-proxy/` (residential proxy) | rp1·rp2·rp3 | **`fleet`** (1.00) | convicting signals a real cohort cannot make: **per-launch JA4_c randomization** (3 extension/sig-alg variants behind one cipher prefix) **and** one WebRTC-leaked origin `45.137.0.42` behind 3 distinct proxy IPs |
| `corpus/fleet-cloned/` (cloned-profile) | cn1·cn2·cn3 | **`fleet`** (1.00) | the **fp-collision** convicting path, grounded live for the first time (previously synthetic-only): 3 concurrent instances of one evader image, each on a distinct container IP (172.22.0.4/.5/.6), share one deterministic `fp_hash` `bf779223` across 3 distinct IPs — convicted by the collision alone, with **stable** JA4_c and no shared WebRTC origin |
| `corpus/fleet/` (camoufox) | cf1·cf2 | `candidate` (0.42) | **trusted-but-verified surprise:** the real camoufox capture has **stable** JA4_c (not divergent) and homogeneous JS — indistinguishable from two real users on one build, so the conviction gate correctly **withholds** `fleet` |

The `fleet-cloned` capture is the live coordination harness (`harness/tools/fleet_capture.sh`): with no
residential proxies, N concurrent containers each hold a distinct compose-bridge IP, so one image's
deterministic SwiftShader `fp_hash` collides across distinct sources — the cloned-profile-behind-proxies
shape. Concurrency is load-bearing: run sequentially, the containers reuse the freed bridge IP and the
detector correctly reads them as one machine over many sessions (benign), not a fleet. The **online**
`FleetTracker` was validated on the same capture too — replaying cn1·cn2·cn3 in arrival order raises the
`fleet` alert on the second arrival (the moment the collision spans two IPs), pinned by
`test_real_cloned_fleet_online_alert`. Still open: the **IP-reputation** half (`rep.datacenter_asn`,
`rep.known_proxy_exit`, `net.webrtc_ip_vs_observed`) needs real public/proxy egress — private container IPs
are not ASN-classifiable and WebRTC leaks the same container IP, so no proxy-vs-origin mismatch is producible.

The camoufox result corrects an assumption baked into the synthetic `fleet-ja4c-randomizer` scenario: real
camoufox (at least the captured build/config) does **not** randomize its JA4_c per launch, so a small
homogeneous camoufox cohort reads as a legitimate same-build cohort. The JA4_c-randomization signal is still
validated on real traffic — by the **residential-proxy** fleet, which genuinely does randomize. Net: the
convicting set fires on the fleet that is genuinely distinguishable and stays silent on the one that is not
(FP-safety), confirmed against real captures rather than only synthetic constructions.

## A third dimension: the behavioural clone (`trace_collision`)

A fingerprint collision catches a fleet that clones one *fingerprint*; the **trace collision** catches a
fleet that clones one *behaviour*. The collector hashes the pointer trajectory's shape (`behavioral.trace_hash`,
timing excluded), and an identical `trace_hash` across distinct source IPs is one tool replaying a single
canned "humanised" mouse path — two real users never trace the same path. It convicts a fleet that
randomises its fingerprint per instance yet reuses one recorded trajectory, where the fp-collision stays
silent. **Grounded on real captures:** three distinct stealth-evader configs (`full-stealth`,
`naive-tz-spoof`, `stealth-naive`) all reuse the harness's one hardcoded mouse path, so they share the trace
`a0214e60`; placed on distinct IPs they score `fleet` on the trace collision, while the curved-motion
`human-mouse` control has a unique hash and never collides. It is a convicting coordination signal (behind
the same conviction gate as the fp-collision).

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

