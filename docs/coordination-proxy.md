# Coordination verdicts — the two fleet shapes a spoofing fleet cannot both avoid

A fleet hides behind a shared engine identity (JA4) but must look like distinct users. It has exactly two
ways to do that, and the scorer catches each with a complementary signal:

- **Randomize JS per instance** (Camoufox) → the JS-divergence paradox: shared TLS, divergent JS.
- **Clone one fingerprint profile** (BotBrowser) → the fingerprint-collision: identical high-entropy
  `fp_hash` across distinct source IPs (where real machines each hash differently).

The verdicts below are **real `score_cluster` output**, not hand-authored, on real captured fleets plus a
few illustrative synthetic clusters where noted.

## Signal matrix — what each coordination signal convicts, and why it is FP-safe

Four signals can carry a `fleet` *label*. Two are **ambiguous** (a real cohort has a benign twin that
produces the same shape, so they convict only when *corroborated*); two are **unambiguous** (no benign twin,
verified by construction). Rule IDs and the live corroboration sources are in
[`contracts/rules/registry.yaml`](../contracts/rules/registry.yaml); the full rule table is the generated
[`docs/detection-catalog.md`](detection-catalog.md).

| signal | ambiguous? | benign twin | corroboration to convict | grounded-by (real capture) |
|---|---|---|---|---|
| `fp_collision` (one `fp_hash` across distinct IPs) | **yes** | a standardized **corporate fleet** — locked OS+browser image hashes byte-identically | a per-session automation/headless tell on a member, a cluster-property signal (JA4_c randomization / shared origin), **or** datacenter/proxy IP reputation (`rep.datacenter_asn` / `rep.known_proxy_exit`) | `corpus/fleet-cloned` (cn1·cn2·cn3) |
| `ja4c_divergent` (per-launch TLS-ext randomization) | **yes** | a **multi-Chrome-version cohort** — JA4_c varies across versions while the cipher prefix holds | same gate: an automation tell, or an unambiguous coordination signal (cloned trace / shared origin) | `corpus/fleet-proxy` (rp1·rp2·rp3) |
| `trace_collision` (one `behavioral.trace_hash` across distinct IPs) | no | — | **solo-convicting**: the trace hash is high-entropy (≥12 points, integer-pixel FNV over the whole trajectory); two real humans cannot collide | `corpus/fleet-randfp-trace` (ft1·ft2·ft3), `corpus/fleet-replay` (rt1·rt2·rt3) |
| `shared_real_ip` (distinct proxy IPs fronting one WebRTC origin) | no | — | **solo-convicting**: the collector emits only the srflx/PUBLIC candidate, so distinct real users each leak their OWN distinct origin | `corpus/fleet-webrtc-leak` (wr1·wr2·wr3), `corpus/fleet-proxy` |

The two ambiguous signals each have a benign twin a real cohort produces, so they convict only when
corroborated; the two unambiguous signals have no benign twin (verified by construction below, not just
asserted). The JS-divergence paradox, IP spread and timing lockstep are **corroborating only** — they are
*also* the null hypothesis (distinct real users on one Chrome build) — see the conviction gate below.

## Operator entrypoints

Two Taskfile targets drive the coordination detector (run from the repo root; see
[`Taskfile.yml`](../Taskfile.yml)):

```sh
task coordination-eval      # precision/recall across the legit + malicious coordination scenario battery
task coordination-live      # grade coordination against the LIVE detector's session store (set KITSUNE_DETECTOR)
```

- `coordination-eval` runs `kitsune_harness.coordination_scenarios` — the offline battery that grades the
  malicious fleets (which must convict) against the legit cohorts (which must cap at `candidate`), reporting
  precision/recall. This is what pins the FP-safety of the ambiguous signals.
- `coordination-live` runs `kitsune_harness.live_coordination` against a running detector's store — the
  production-shaped path (set `KITSUNE_DETECTOR` to the detector URL).

The real fleet captures below are also pinned offline in `harness/tests/test_coordination.py`.

## Validated against the REAL captured fleets (not just synthetic)

The coordination detector was synthetic-only; it is now grounded on **real fleet captures** that came
through the edge→detector pipeline, each pinned in `harness/tests/test_coordination.py`. Every signal in the
matrix above now has at least one real capture exercising it in isolation:

| capture | members | verdict | convicting signal — why |
|---|---|---|---|
| `corpus/fleet-proxy/` (residential proxy) | rp1·rp2·rp3 | **`fleet`** (1.00) | **JA4_c randomization + shared origin**: per-launch JA4_c randomization (3 ext/sig-alg variants behind one cipher prefix) **and** one WebRTC-leaked origin `45.137.0.42` behind 3 distinct proxy IPs |
| `corpus/fleet-cloned/` (cloned-profile) | cn1·cn2·cn3 | **`fleet`** (1.00) | **fp-collision**: 3 concurrent instances of one evader image on distinct container IPs (172.22.0.4/.5/.6) share one deterministic `fp_hash` `bf779223` — convicted by the collision (members carry automation tells), with stable JA4_c and no shared WebRTC origin |
| `corpus/fleet-randfp-trace/` (fp-randomizing, shared trace) | ft1·ft2·ft3 | **`fleet`** | **trace-collision ALONE**: 3 apify fingerprint-injector instances each sample a DISTINCT `fp_hash` (fp-collision defeated, `cloned_fingerprint` stays None) yet replay one canned trajectory → one `trace_hash` across 3 IPs. The botright/multilogin pattern; proves the behavioural-clone signal catches what fp-collision cannot |
| `corpus/fleet-replay/` (replayed trace) | rt1·rt2·rt3 | **`fleet`** | **trace-collision**: 3 stealth-evader REPLAY_TRACE instances inject the SAME recorded pointer path → identical `trace_hash` across distinct IPs. Grounds that a coordinate-based clone hash IS byte-identical across a real fleet (unlike a timing hash, which scheduler jitter perturbs) |
| `corpus/fleet-webrtc-leak/` (one origin behind proxies) | wr1·wr2·wr3 | **`fleet`** | **shared_real_ip ALONE**: 3 camoufox instances each route HTTPS through a DISTINCT CONNECT proxy (distinct `observed_ip`) while WebRTC UDP leaks ONE shared origin. Diverse fps + jittered traces (no fp/trace collision), so the only convicting signal is the shared origin — the FP-safe convicting twin of the per-session (corroborating-only) `net.webrtc_ip_vs_observed` leak |
| `corpus/fleet/` (camoufox) | cf1·cf2 | `candidate` (0.42) | **trusted-but-verified surprise**: the real camoufox capture has **stable** JA4_c (not divergent) and homogeneous JS — indistinguishable from two real users on one build, so the conviction gate correctly **withholds** `fleet` |

The camoufox result corrects an assumption baked into the synthetic `fleet-ja4c-randomizer` scenario: real
camoufox (at least the captured build/config) does **not** randomize its JA4_c per launch, so a small
homogeneous camoufox cohort reads as a legitimate same-build cohort. The JA4_c-randomization signal is still
validated on real traffic — by the **residential-proxy** fleet, which genuinely does randomize. Net: the
convicting set fires on the fleets that are genuinely distinguishable and stays silent on the one that is not
(FP-safety), confirmed against real captures rather than only synthetic constructions.

## A third dimension: the behavioural clone (`trace_collision`)

A fingerprint collision catches a fleet that clones one *fingerprint*; the **trace collision** catches a
fleet that clones one *behaviour*. The collector hashes the pointer trajectory's shape (`behavioral.trace_hash`,
timing excluded), and an identical `trace_hash` across distinct source IPs is one tool replaying a single
canned "humanised" mouse path — two real users never trace the same path. It convicts a fleet that
randomises its fingerprint per instance yet reuses one recorded trajectory, where the fp-collision stays
silent (`corpus/fleet-randfp-trace` is exactly this shape, grounded in isolation). It is a convicting
coordination signal (behind the same conviction gate as the unambiguous signals).

## The conviction gate (why the JS-divergence paradox cannot convict alone)

A `fleet` *label* requires a **convicting** coordination signal — one a real diverse cohort cannot
produce: JA4_c divergence (per-launch TLS-extension randomization; real Chrome's JA4_c is stable per launch),
a cloned-fingerprint collision across distinct IPs, a cloned-trace collision, or a shared WebRTC origin
behind distinct proxy IPs. The JS-divergence paradox, IP spread and lockstep are **corroborating only**,
because they are *also* the null hypothesis: distinct real users on one Chrome build share a JA4 (TLS is
per-build) yet legitimately differ in `hardware_concurrency`, `device_memory` and OS-platform (Win/Mac/Linux
Chrome share a JA4) and arrive from distinct IPs. Without the gate, a 4-user real cohort on one popular
build — diverse hardware, distinct IPs, distinct `fp_hash`, spread over 15 min — scored `fleet` 1.00 (a
botnet verdict on a browser's user base); it is now correctly capped at `candidate`. This mirrors the
detector's convicting-signal gate (`scoring.label_for`) on the per-session side.

### Why the two ambiguous signals are corroboration-gated

Both `fp_collision` and `ja4c_divergent` looked convicting but each has a benign twin a real cohort produces
— so each is gated to require a corroborating signal a clean cohort lacks:

- **`fp_collision` ↔ a standardized corporate fleet.** The rationale "real machines each hash differently"
  is an overstatement: a locked OS+browser image hashes its canvas/WebGL/audio byte-identically, and on
  distinct work-from-home residential IPs that is the *exact* shape fp-collision convicted (a botnet verdict
  on a corporate cohort). It cannot be disambiguated from a cloned bot fleet by the fingerprint alone (a
  native anti-detect browser clones the fp with clean JS and can synthesize distinct behaviour). So
  fp-collision **no longer solo-convicts**: it needs a per-session automation/headless tell on a member, a
  cluster-property signal (JA4_c randomization / shared origin), or datacenter/proxy IP reputation. An
  uncorroborated identical-fp cluster caps at `candidate` for operator review.
- **`ja4c_divergent` ↔ a multi-Chrome-version cohort.** "Real Chrome's JA4_c is stable" holds per-launch but
  NOT per-version: JA4_c changes across Chrome versions while the cipher prefix holds, so a normal mix of
  auto-update states diverges JA4_c. So `ja4c_divergent` gets the same corroboration gate.

The cloned-trace and shared-origin signals stay solo-convicting — neither can fire on a clean cohort (real
humans never share a trace; there is no shared WebRTC origin).

**Corroboration includes IP reputation (wired, not just documented).** The detector classifies the source IP
against curated public datacenter/proxy/Tor-exit CIDR lists (`ip_reputation.py`, emitting
`reputation.asn_is_datacenter` / `is_proxy_exit`); those signals are a corroboration source for the ambiguous
gate. This is the real disambiguator: a cloned/randomizer bot fleet runs on datacenter or proxy
infrastructure (flagged); a corporate or multi-version real cohort runs on genuine residential IPs (never
flagged, and private IPs classify as neither). So a clean native clone (no automation tell) on datacenter IPs
convicts. The classification is **not** blocked (public CIDR data, no live proxy needed); only the
*in-sandbox live exercise* is limited — container IPs are private (172.x), so the live fleet captures
corroborate via their automation tells instead. A production deployment seeing real datacenter/proxy IPs gets
the flag. CIDR seed lists are non-exhaustive (refresh per [`docs/ip-reputation-data.md`](ip-reputation-data.md)).

## Live-proxy egress plumbing — built; only real proxies are missing

The blocker for the live proxy half (`rep.datacenter_asn`, `rep.known_proxy_exit`, `net.webrtc_ip_vs_observed`,
the proxy-topology coordination signals) was that the in-sandbox fleet egresses from private container IPs
(172.x), not real ASN-classifiable IPs. The routing plumbing to fix that is built:

- The stealth evader honours `KS_PROXY=<url>` (`http(s)://`, `socks5://`) — routes the context through a
  proxy so the edge observes a REAL egress IP. The edge demonstrably attributes the session to the proxy's
  egress, not the client (validated with a local CONNECT-proxy stand-in; see Grounding history) — exactly the
  substitution `rep.datacenter_asn` / `rep.known_proxy_exit` need.
- `fleet_capture.sh` honours `PROXIES=url1,url2,url3` — node *i* routes via `PROXIES[i]` (round-robin), so a
  fleet egresses from distinct real IPs.

```sh
# Turnkey: supply real residential/datacenter proxies (target stays the allow-listed edge; the proxy is only
# the egress path), then the rep.* + webrtc-leak + proxy-topology signals fire on real IPs:
IMAGE=kitsune-stealth:latest N=3 ENV="-e STEALTH=1" \
  PROXIES="socks5://p1:1080,socks5://p2:1080,socks5://p3:1080" \
  OUT=corpus/fleet-proxy harness/tools/fleet_capture.sh
```

So this frontier is **data-only-blocked** (needs proxy endpoints, no code change) — the parallel of the
turnkey real-traffic prevalence prior (`build_prior_from_dir`, [`docs/prevalence-model.md`](prevalence-model.md)).
Ethics: the proxy is the egress path only; the TARGET stays the allow-listed edge, so the allow-list is not
weakened.

The `net.webrtc_ip_vs_observed` half (a proxy-vs-origin IP mismatch) is the one piece that still needs real
connectivity to produce live — diagnosed precisely as a headless-Chromium ICE limitation, not a Kitsune one
(see Grounding history). The rule's logic is unit-tested; only its live collector→signal path needs a real
browser with real STUN reachability.

## Worked snapshot

The clusters below are real `score_cluster` output illustrating the two primary fleet shapes end to end.

### Randomizing fleet (residential proxies) — `corpus/fleet-proxy`, score **1.00** · 3 sessions
- **severity: moderate** (12 requests, 7.8/min)
- members: rp1, rp2, rp3
- 3 sessions share JA4 cipher prefix `t13d1717h2_5b57614c22b0`
- cipher suites identical but JS divergent across members: hardware_concurrency x3, nav_platform_os x2, ua_platform x2
- cipher suites identical but JA4 extensions/sig-algs divergent (3 variants) — per-launch TLS randomization
- timing lockstep: all members arrived within 23s
- distributed across 3 distinct source IPs — residential-proxy fleet pattern (IP diversity masks one shared engine, defeating IP/ASN rules)
- 3 proxy IPs front one real IP `45.137.0.42` (WebRTC) — same-origin fleet

### Cloned-profile fleet (BotBrowser-style reuse) — score **1.00** · 3 sessions (illustrative synthetic)

The trap this closes: JS is **homogeneous** (the scorer notes it "consistent with a real cohort"), so the
JS-divergence paradox stays silent and the old scorer rated this only a `candidate`. The fingerprint
collision across distinct IPs is what convicts it.

- **severity: moderate** (6 requests, 8.2/min)
- members: bb1, bb2, bb3
- 3 sessions share JA4 cipher prefix `t13d1516h2_8daaf6152771`
- JS traits homogeneous across members — consistent with a real cohort
- identical high-entropy fingerprint `7c3a9f12` across 3 distinct source IPs — cloned-profile reuse (one anti-detect profile shared fleet-wide)
- timing lockstep: all members arrived within 22s
- distributed across 3 distinct source IPs — residential-proxy fleet pattern (IP diversity masks one shared engine, defeating IP/ASN rules)

### Cloned headless Chromium — score **1.00** · 2 sessions (**live capture**, `corpus/sessions/chrome-clone-*.json`)

Two stock **headless Chromium** instances are a cloned profile by construction (same build +
deterministic SwiftShader rendering → byte-identical `fp_hash`). Captured concurrently so the edge sees
distinct container IPs, each ran the in-browser collector and emitted the same hash — real scorer output:

- members: chrome-clone-1, chrome-clone-2
- 2 sessions share JA4 cipher prefix `t13d1516h2_8daaf6152771`
- JS traits homogeneous across members — consistent with a real cohort
- identical high-entropy fingerprint `28718b97` across 2 distinct source IPs — cloned-profile reuse (one anti-detect profile shared fleet-wide)
- timing lockstep: all members arrived within 1s
- distributed across 2 distinct source IPs — residential-proxy fleet pattern (IP diversity masks one shared engine, defeating IP/ASN rules)

## Scenario battery

`task coordination-eval` grades the malicious fleets (must convict) against the legit cohorts (must cap at
`candidate`), reporting precision/recall (`kitsune_harness.coordination_scenarios`). The benign twins above
are each pinned by a legit scenario:

- `legit-corporate-fleet` (standardized corporate fleet, residential IPs) → `candidate` (precision stays 1.0).
- `legit-multi-version-cohort` (clean 4-user cohort spanning 2 Chrome versions) → `candidate`.
- The malicious `fleet-cloned-fingerprint` and `fleet-ja4c-randomizer` scenarios were made AUTOMATED
  (realistic) so recall stays 1.0; `fleet-cloned-datacenter` exercises the IP-reputation corroboration of a
  clean native clone on datacenter IPs.

The live captures (`corpus/fleet-*`) are pinned offline in `harness/tests/test_coordination.py` and serve as
the real-traffic complement to the synthetic battery.

## Grounding history (appendix)

Dated lab-notebook entries, kept for provenance. Current behaviour is described above; these record how each
piece was grounded.

### The fp-collision FP: a standardized corporate fleet (fixed)

The fp-collision rationale — "real machines each hash differently (GPU/driver/OS/font variance)" — is an
**overstatement**, and trusting it produced a real false positive. A **standardized corporate fleet** (the
same laptop model running a *locked* OS + browser image) hashes its canvas/WebGL/audio **byte-identically**;
on distinct work-from-home residential IPs that is the *exact* shape fp-collision convicted — grounded by
constructing it: **4 clean Windows laptops, one shared `fp_hash`, 4 residential IPs → `fleet` 1.00**, evidence
reading "cloned-profile reuse" and "residential-proxy fleet." A botnet verdict on a corporate cohort. Fix:
fp-collision no longer solo-convicts (corroboration-gated, above); pinned by `legit-corporate-fleet` and
`test_corporate_fleet_fp_collision_is_not_convicted`. The cloned-fingerprint malicious scenario was made
AUTOMATED so recall stays 1.0, and the live `fleet-cloned` fixture still convicts (its stealth-evader members
carry automation tells).

### The JA4_c-divergence FP: a multi-Chrome-version cohort (fixed)

The same lesson recurred on `ja4c_divergent`. Its rationale — "real Chrome's JA4_c is stable" — holds
per-**launch** but NOT per-**version**: JA4_c changes across Chrome versions while the cipher prefix
(JA4_a+JA4_b) stays, so a normal mix of auto-update states diverges JA4_c. Grounded in the fleet captures
themselves — one cipher prefix `t13d1516h2_8daaf6152771` carries **two** real JA4_c (`02713d6af862`,
`d8a2da3f94cd`) across older vs newer captures, i.e. a Chromium version bump — and by construction: a clean
4-user cohort spanning 2 versions (distinct IPs/fps/traces, no automation) scored `fleet 0.92`, the evidence
wrongly reading "per-launch TLS randomization." Fix: same corroboration gate; pinned by
`legit-multi-version-cohort` (→ candidate) and a now-AUTOMATED `fleet-ja4c-randomizer` (→ fleet); the live
`fleet-proxy` fixture is unaffected (it convicts via its shared WebRTC origin).

### Precision review — the unambiguous signals verified, not asserted

- `trace_collision` is **safe by construction**: the trace hash is high-entropy (≥12 points, exact
  integer-pixel FNV over the whole trajectory), so two real humans cannot coincidentally collide. Grounded:
  three distinct stealth-evader configs (`full-stealth`, `naive-tz-spoof`, `stealth-naive`) all reuse the
  harness's one hardcoded mouse path → share trace `a0214e60` → score `fleet` on the trace collision; the
  curved-motion `human-mouse` control has a unique hash and never collides.
- `shared_real_ip` is **safe by construction**: the collector emits only the srflx/PUBLIC WebRTC candidate
  (host/private candidates excluded), so distinct real users each leak their OWN distinct public IP — they
  cannot share an origin (pinned by `test_distinct_public_ips_do_not_share_origin`).

### Live re-validation (2026-06-19, ruleset 0.74.21)

A fresh concurrent 3-instance cloned capture through the live edge→detector stack (new sids, `fp_hash
bf779223` across distinct container IPs 172.22.0.4/.5/.6), scored by the live coordination detector → `fleet
1.00` via the **fp-collision** path. The corroboration source was verified by inspecting the captured
signals: each member carries automation tells (`cdp_runtime_enabled`, `ch_he_headless`,
`chrome_object_missing`) on a **private** IP with an empty `reputation` layer — so the conviction is carried
by `_has_automation_tell`, NOT an IP-reputation flag, exactly as the gate intends. This confirmed the
`a4d1ac0` corroboration-gating did not break the live cloned-fleet conviction end-to-end. CI drift fixed in
the same pass (two ruff findings). No rule semantics changed → no ruleset bump.

### Turnkey live-proxy harness (2026-06-19) — egress plumbing built; only real proxies missing

The IP-attribution substitution was validated end-to-end: a local CONNECT-proxy stand-in container was run on
the lab network, then the same evader was scored twice — `STEALTH=1` alone gave `observed_ip = 172.22.0.5`
(the evader's own container IP), while `STEALTH=1` + `KS_PROXY=http://proxy` gave `observed_ip = 172.22.0.4`
(**the proxy's** IP). So the edge demonstrably attributes the session to the proxy's egress, not the client.

The `net.webrtc_ip_vs_observed` half is NOT demonstrable in-sandbox (diagnosed 2026-06-19). The rule fires
when the WebRTC-leaked srflx IP ≠ the proxy-observed IP, and WebRTC's UDP bypasses the HTTP proxy, so it
*should* leak the real container IP. A full attempt was made: a minimal STUN responder + the CONNECT proxy on
the lab net, with the evader's WebRTC STUN host redirected to the local responder via Chromium
`--host-resolver-rules=MAP stun.l.google.com <ip>`. The STUN responder works (a direct UDP probe gets a
reflected address) and UDP egress works, and the headless browser DOES gather host/mDNS candidates
(`webrtc_unavailable` never fires) — but it never sends a STUN binding request to the redirected responder, so
no `srflx` candidate and no `webrtc_public_ip`. So **headless Chromium's WebRTC `srflx` gathering does not
honour the host-resolver redirect** (its ICE stack resolves STUN outside the override) — a Chromium-headless
limitation, not a Kitsune one. The unvalidated `KS_STUN` evader hook was reverted — per "never ship a
signature you couldn't ground." The IP-attribution plumbing — the load-bearing piece — is proven; the WebRTC
leak is the icing that genuinely needs real connectivity.

## Scenario battery — measured precision/recall

_Merged from the former `coordination-scenarios.md` (2026-06-26 docs consolidation). The measured
proof of the FP-safety prose above — regenerate via `task coordination-eval`._


- **precision: 100%** (no legitimate cohort labelled `fleet`)
- **recall: 100%** (every fleet shape caught)

| scenario | expected | label | ✓ | why |
|---|---|---|---|---|
| `legit-corporate-fleet` | not-fleet | `candidate` | ✓ | a STANDARDIZED corporate fleet: identical laptop model + locked image hashes byte-identically, on distinct WFH residential IPs, with DISTINCT human traces and NO automation tell — fp collides but the cohort is real; must cap at candidate, not `fleet` (the fp-collision-vs-corporate FP) |
| `legit-diverse-cohort` | not-fleet | `candidate` | ✓ | distinct real users on one Chrome build: diverse hw/OS, distinct IPs+fps+traces, spread timing |
| `legit-homogeneous-pair` | not-fleet | `candidate` | ✓ | two users, identical JS (same build+config) but distinct fps/traces — a benign same-build pair |
| `legit-large-cohort` | not-fleet | `candidate` | ✓ | 8 distinct users on one build — paradox + IP spread at scale must still not convict |
| `legit-multi-version-cohort` | not-fleet | `candidate` | ✓ | real Chrome users spanning auto-update versions: ONE cipher prefix but a few distinct JA4_c (JA4_c varies across Chrome versions), distinct IPs + fps + traces, NO automation — diverges JA4_c but is a real cohort; must cap at candidate, not `fleet` (the JA4_c-randomizer-vs-multi-version FP) |
| `legit-nat-cohort` | not-fleet | `candidate` | ✓ | 5 distinct users behind ONE NAT IP — collisions need distinct IPs, so a shared IP never convicts |
| `fleet-cloned-datacenter` | fleet | `fleet` | ✓ | a CLEAN native anti-detect clone (BotBrowser-style, no automation tell, no JS divergence) but on DATACENTER IPs — the IP-reputation flag corroborates the fp-collision as a bot fleet where no automation tell does; distinguishes it from a residential corporate cohort |
| `fleet-cloned-fingerprint` | fleet | `fleet` | ✓ | BotBrowser-style: homogeneous JS but one fp_hash cloned across distinct IPs, AUTOMATED (webdriver) — the automation tell corroborates the collision as a cloned bot fleet, not standardized hardware |
| `fleet-cloned-trace` | fleet | `fleet` | ✓ | behavioural clone: distinct fps but one canned pointer trace replayed across distinct IPs |
| `fleet-ja4c-randomizer` | fleet | `fleet` | ✓ | uTLS-style fingerprint randomizer: shared cipher prefix but per-launch JA4_c randomization (NOT Camoufox — real Camoufox emits a stable JA4_c per config, grounded 2026-06-20), diverse JS, distinct IPs, AUTOMATED (webdriver) — the automation tell corroborates the JA4_c divergence as a fleet, not a benign multi-browser-version cohort (which also diverges JA4_c, hence the corroboration gate) |
| `fleet-shared-origin` | fleet | `fleet` | ✓ | proxies fronting one origin: diverse JS, distinct proxy IPs, ONE shared WebRTC-leaked real IP |

## Worked snapshot

_Merged from the former `coordination.md` (2026-06-26 docs consolidation). A sample graded cluster
emitted by the coordination grader (`task coordination-eval` output) — a real cohort capped at
`candidate`, not convicted._

## Coordination — 1 graded cluster(s) across 2 sessions

### `candidate` — score **0.42** · 2 sessions
- members: cf1, cf2
- 2 sessions share JA4 cipher prefix `t13d1717h2_5b57614c22b0`
- JS traits homogeneous across members — consistent with a real cohort
- timing lockstep: all members arrived within 10s

