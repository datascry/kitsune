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

## The fp-collision FP: a standardized corporate fleet (fixed)

The fp-collision rationale — "real machines each hash differently (GPU/driver/OS/font variance)" — is an
**overstatement**, and trusting it produced a real false positive. A **standardized corporate fleet** (the
same laptop model running a *locked* OS + browser image) hashes its canvas/WebGL/audio **byte-identically**;
on distinct work-from-home residential IPs that is the *exact* shape fp-collision convicted — grounded by
constructing it: **4 clean Windows laptops, one shared `fp_hash`, 4 residential IPs → `fleet` 1.00**, evidence
reading "cloned-profile reuse" and "residential-proxy fleet." A botnet verdict on a corporate cohort.

It cannot be disambiguated from a cloned bot fleet by the fingerprint alone — a native anti-detect browser
(BotBrowser, C++-level spoofing) clones the fp with clean JS APIs and can synthesize distinct per-instance
behaviour, so neither tampering tells nor behavioural diversity separate them. The only true discriminator is
**IP reputation** (datacenter/proxy = clone; residential/corporate = legit), the still-blocked coordination
half.

**Fix (FP-safe):** fp-collision **no longer solo-convicts**. It convicts only when *corroborated* by a signal
a clean corporate cohort lacks — a per-session **automation/headless tell** on a cluster member (a cloned bot
fleet is automated; the real `corpus/fleet-cloned` captures carry `webdriver`/`cdp_runtime_enabled`), or
another cluster-property signal (JA4_c randomization / shared WebRTC origin). An *uncorroborated* identical-fp
cluster is genuinely ambiguous (corporate hardware vs a clean native clone) → capped at `candidate` for
operator review. Pinned by `legit-corporate-fleet` in the scenario battery (precision stays 1.0) and
`test_corporate_fleet_fp_collision_is_not_convicted`; the malicious `fleet-cloned-fingerprint` scenario was
made AUTOMATED (realistic) so recall stays 1.0, and the live `fleet-cloned` fixture still convicts (its
stealth-evader members carry automation tells). The cloned-TRACE and shared-origin signals stay
solo-convicting — neither can fire on a clean corporate cohort (real humans never share a trace; there is no
shared WebRTC origin). (`ja4c_divergent` gets the same corroboration gate — see the next section.)

## The JA4_c-divergence FP: a multi-Chrome-version cohort (fixed)

The same lesson recurred on `ja4c_divergent`. Its rationale — "real Chrome's JA4_c is stable" — holds
per-**launch** but NOT per-**version**: JA4_c (the extensions/sig-algs hash) changes across Chrome versions
while the cipher prefix (JA4_a+JA4_b) stays, so a normal mix of auto-update states **diverges JA4_c**.
Grounded in the fleet captures themselves — one cipher prefix `t13d1516h2_8daaf6152771` carries **two** real
JA4_c (`02713d6af862`, `d8a2da3f94cd`) across older vs newer captures, i.e. a Chromium version bump — and by
construction: a clean 4-user cohort spanning 2 versions (distinct IPs/fps/traces, no automation) scored
`fleet 0.92`, the evidence wrongly reading "per-launch TLS randomization."

So `ja4c_divergent` is **AMBIGUOUS** exactly like `fp_collision` — per-launch randomization (anti-detect) vs
a multi-version cohort (real) — and gets the same corroboration gate: it convicts only with a per-session
automation tell or an unambiguous signal (cloned trace / shared origin); uncorroborated it caps at
`candidate`. Pinned by `legit-multi-version-cohort` (→ candidate) and a now-AUTOMATED `fleet-ja4c-randomizer`
(→ fleet); the live `fleet-proxy` fixture is unaffected (it convicts via its **shared WebRTC origin**, an
unambiguous signal). Only `trace_collision` and `shared_real_ip` remain solo-convicting — no real cohort,
standardized or multi-version, can produce them.

## Precision review complete — all four convicting signals

The coordination detector's four convicting signals have now had a full FP-safety pass:

| signal | benign twin (the FP risk) | status |
|---|---|---|
| `fp_collision` | a standardized corporate fleet (identical hardware hashes alike) | **corroboration-gated** |
| `ja4c_divergent` | a multi-Chrome-version cohort (JA4_c varies across versions) | **corroboration-gated** |
| `trace_collision` | — | **safe by construction**: the trace hash is high-entropy (≥12 points, exact integer-pixel FNV over the whole trajectory), so two real humans cannot coincidentally collide |
| `shared_real_ip` | distinct users sharing a private `192.168.x` WebRTC IP | **safe by construction**: the collector emits only the srflx/PUBLIC WebRTC candidate (host/private candidates are excluded), so distinct real users each leak their OWN distinct public IP — they cannot share an origin (pinned by `test_distinct_public_ips_do_not_share_origin`) |

The two *ambiguous* signals each have a benign twin a real cohort produces, so they convict only when
corroborated; the two *unambiguous* signals have no benign twin (verified above, not just asserted).

**Corroboration now includes IP reputation (wired, not just documented).** The detector already classifies
the source IP against curated public datacenter/proxy/Tor-exit CIDR lists (`ip_reputation.py`, emitting
`reputation.asn_is_datacenter` / `is_proxy_exit`); those signals are now a corroboration source for the
ambiguous gate. This is the real disambiguator: a CLONED/randomizer bot fleet runs on datacenter or proxy
infrastructure (flagged), a corporate or multi-version real cohort on genuine residential IPs (never flagged,
and private IPs classify as neither). So a CLEAN native clone (no automation tell) on datacenter IPs now
convicts — `fleet-cloned-datacenter` in the battery, pinned by `test_datacenter_ip_corroborates_a_clean_clone`
— closing the recall gap, while `legit-corporate-fleet` (residential) stays `candidate`. The classification
is NOT blocked (public CIDR data, no live proxy needed); only the *in-sandbox live exercise* is limited —
container IPs are private (172.x), so the live fleet captures corroborate via their automation tells instead,
not via an IP-reputation flag. A production deployment seeing real datacenter/proxy IPs gets the flag.

**Live re-validation (2026-06-19, ruleset 0.74.21):** a fresh concurrent 3-instance cloned capture through
the live edge→detector stack (new sids, `fp_hash bf779223` across distinct container IPs 172.22.0.4/.5/.6),
scored by the live coordination detector → `fleet 1.00` via the **fp-collision** path. The corroboration
source was verified by inspecting the captured signals: each member carries automation tells
(`cdp_runtime_enabled`, `ch_he_headless`, `chrome_object_missing`) on a **private** IP with an empty
`reputation` layer — so the conviction is carried by `_has_automation_tell`, NOT an IP-reputation flag,
exactly as the gate intends (the cloned fleet IS automated → it self-corroborates; a clean residential
corporate fleet would not, and stays `candidate`). This confirms the `a4d1ac0` corroboration-gating
(fp-collision / JA4_c-divergence now require corroboration) did not break the live cloned-fleet conviction
end-to-end. CI drift fixed in the same pass (two ruff findings in the coordination module/test). No rule
semantics changed → no ruleset bump. The remaining genuinely-blocked piece is narrower than before:
`net.webrtc_ip_vs_observed` (a proxy-vs-origin IP mismatch) needs a real proxy egress to produce live, and
the datacenter/proxy CIDR seed lists are non-exhaustive (refresh per docs/ip-reputation-data.md).

## Turnkey live-proxy harness (2026-06-19) — the egress plumbing is built; only real proxies are missing

The blocker for the live proxy half (`rep.datacenter_asn`, `rep.known_proxy_exit`, `net.webrtc_ip_vs_observed`,
and the proxy-topology coordination signals) was that the in-sandbox fleet egresses from private container
IPs (172.x), not real ASN-classifiable IPs. The routing plumbing to fix that is now built:

- The stealth evader honours `KS_PROXY=<url>` (`http(s)://`, `socks5://`) — routes the context through a proxy
  so the edge observes a REAL egress IP. **End-to-end validated (2026-06-19):** a local CONNECT-proxy
  stand-in container was run on the lab network, then the same evader was scored twice — `STEALTH=1` alone
  gave `observed_ip = 172.22.0.5` (the evader's own container IP), while `STEALTH=1` + `KS_PROXY=http://proxy`
  gave `observed_ip = 172.22.0.4` (**the proxy's** IP). So the edge demonstrably attributes the session to the
  PROXY's egress, not the client — exactly the substitution `rep.datacenter_asn`/`rep.known_proxy_exit` need:
  swap the local stand-in for a real residential/datacenter proxy and the edge sees a real ASN-classifiable IP.
  (The `net.webrtc_ip_vs_observed` half is NOT demonstrable in-sandbox — diagnosed precisely 2026-06-19. The
  rule fires when the WebRTC-leaked srflx IP ≠ the proxy-observed IP, and WebRTC's UDP bypasses the HTTP proxy,
  so it *should* leak the real container IP. A full attempt was made: a minimal STUN responder + the CONNECT
  proxy on the lab net, with the evader's WebRTC STUN host redirected to the local responder via Chromium
  `--host-resolver-rules=MAP stun.l.google.com <ip>`. The STUN responder works (a direct UDP probe gets a
  reflected address) and UDP egress works, and the headless browser DOES gather host/mDNS candidates
  (`webrtc_unavailable` never fires) — but it never sends a STUN binding request to the redirected responder,
  so no `srflx` candidate and no `webrtc_public_ip`. So **headless Chromium's WebRTC `srflx` gathering does not
  honour the host-resolver redirect** (its ICE stack resolves STUN outside the override) — a Chromium-headless
  limitation, not a Kitsune one. The rule's logic is unit-tested (`test_engine`); only its live collector→signal
  path needs a real browser with real STUN reachability. The unvalidated `KS_STUN` evader hook was reverted —
  per "never ship a signature you couldn't ground." The IP-attribution plumbing — the load-bearing piece — is
  proven; the WebRTC leak is the icing that genuinely needs real connectivity.)
- `fleet_capture.sh` honours `PROXIES=url1,url2,url3` — node *i* routes via `PROXIES[i]` (round-robin), so a
  fleet egresses from distinct real IPs.

```sh
# Turnkey: supply real residential/datacenter proxies (target stays the allow-listed edge; the proxy is only
# the egress path), then the rep.* + webrtc-leak + proxy-topology signals fire on real IPs:
IMAGE=kitsune-stealth:latest N=3 ENV="-e STEALTH=1" \
  PROXIES="socks5://p1:1080,socks5://p2:1080,socks5://p3:1080" \
  OUT=corpus/fleet-proxy harness/tools/fleet_capture.sh
```

So this frontier is now **data-only-blocked** (needs proxy endpoints, no code change) — the parallel of the
turnkey real-traffic prevalence prior (`build_prior_from_dir`, docs/prevalence-model.md). Ethics: the proxy
is the egress path only; the TARGET stays the allow-listed edge, so the allow-list is not weakened.

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

