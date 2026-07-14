# coordination-catalog — the fleet coordination ladder and the blue signals that catch it

Per-session detection is saturated: with enough resources any single session can look clean (real GPU,
anti-detect browser, residential proxy). A coordinated **fleet** cannot escape so cheaply — it must either
*clone* one profile (a fingerprint/trace collision across distinct IPs) or *randomize* per instance (the
TLS-vs-JS paradox); it cannot do neither. This is the red⇄blue **coordination** ladder: every fleet shape the
Skulk kit emits, and the blue binding that catches it — generated from the strategy registry so it cannot drift.

**How a fleet is graded** — not per-session human/bot, but at the coordination axis. The detector clusters
sessions by their **JA4 TLS-engine prefix** (the layer below JS spoofing), then convicts two ways: **Axis B**, a
per-cluster binding that repeats across distinct IPs (a fingerprint, a trace, a TLS ticket, a WebRTC origin);
and **Axis A**, a population that correlates across ≥3 independent soft dimensions when no single binding
repeats. Some bindings convict alone; ambiguous ones need an independent corroborator. Grade any fleet on the
live detector view with `task coordination-live`; see [fleet & Skulk](fleet.md) for the kit itself.

<!-- GENERATED:coordination:start -->
### Every fleet shape, and the blue binding that catches it

> **Generated** from the Skulk strategy registry (`uv run python -m skulk.catalog`) — do not edit by hand. **18 strategies**: 9 convicted at the cluster axis (`fleet`), 4 at the population axis (`campaign`), 4 `candidate` at the external-data-bound frontier, 1 shed even that in-sandbox. A fleet is a *shape* across N sessions, graded at the COORDINATION axis — not a per-session human/bot verdict.

**Verdict tiers** (weakest→strongest conviction):

- **⬜ below-candidate** — sheds even the 2-dim candidate binding in-sandbox — no in-box coordination tell
- **🔶 candidate** — flagged, not convicted — conviction is external-data-bound (IP-rep / prevalence): the frontier
- **✅ campaign** — convicted at the POPULATION axis (Axis A) — ≥3 independent correlated dimensions
- **✅ fleet** — convicted at the per-CLUSTER axis (Axis B) — a binding catches the JA4-prefix cluster

| strategy | attacker class it models | blue binding that catches it | verdict |
|---|---|---|---|
| `cloned` | BotBrowser — one pinned profile cloned fleet-wide | [`fp_collision`](#fp_collision) — identical high-entropy fp across distinct IPs | ✅ fleet |
| `fuzzy-rotate` | the hardest shape — rotate JA4 per node AND fuzz fp/trace | [`shared_real_ip`](#shared_real_ip) — one WebRTC origin survives rotation (+ template_similarity) | ✅ fleet |
| `httpflood` | L7 HTTP flood (MHDDoS class) — many no-JS tool sources in lockstep | [`flood_shape`](#flood_shape) — the aggregate flood shape (large + lockstep + many origins) + tool JA4 | ✅ fleet |
| `ipv6-rotate` | cloned fleet spraying IPv6 /128s inside a few /64s to fake IP spread | the /64 origin-fold collapses the spray; [`fp_collision`](#fp_collision) still convicts | ✅ fleet |
| `similarity` | the evolved adversary, profiled — jittered traces from one humanizer model | [`template_similarity`](#template_similarity) — descriptors cluster below the human floor (corroboration-gated) | ✅ fleet |
| `staggered` | a cloned fleet spreading arrivals over time to look organic | [`fp_collision`](#fp_collision) still convicts — lockstep is corroborating-only | ✅ fleet |
| `ticket-reuse` | rotated JA4 + fuzzed, bound by a reused TLS-resumption ticket | [`shared_ticket`](#shared_ticket) — one `tls_ticket_id` across distinct IPs (corroboration-gated) | ✅ fleet |
| `tool-fleet` | no-JS automation-tool fleet (curl / Go / Python), one tool JA4 | [`shared_ticket`](#shared_ticket) + the non-browser JA4 (`ja4_client_hint`) corroborates | ✅ fleet |
| `trace-replay` | engagement / review farm — one canned mouse path replayed | [`trace_collision`](#trace_collision) — identical trace across distinct IPs (unambiguous) | ✅ fleet |
| `diffuse-automated` | a diffuse fleet that leaks a per-session automation tell (webdriver) | the automation tell lifts a 2-dim community to campaign (Axis-A corroboration) | ✅ campaign |
| `diffuse-scheduled` | a diffuse fleet that staggers on a fixed SCHEDULE | [`arrival_regularity`](#arrival_regularity) — scheduled CV≈0 vs independent-user Poisson CV≈1 | ✅ campaign |
| `residential-proxy` | a diffuse fleet on clean residential IPs behind one tunnel pool | [`proxy_egress`](#proxy_egress) — a shared reduced tunnel MSS (WireGuard-class), gated on descriptor | ✅ campaign |
| `socks-proxy` | a diffuse fleet on a SOCKS pool that re-originates TCP | [`proxy_egress`](#proxy_egress) — shared SYN-stack-vs-UA-OS divergence, gated on descriptor | ✅ campaign |
| `diffuse` | the maximal in-sandbox evader — diffuse, Poisson-staggered, fully clean | none in-sandbox — conviction is external-data-bound (the frontier the ladder converges on) | 🔶 candidate |
| `diffuse-campaign` | the maximal evader base — shared build + lockstep + one humanizer | none in-sandbox — a 2-dim (ja4_prefix + descriptor) candidate | 🔶 candidate |
| `fuzzy` | the evolved adversary — jitter the fp *and* the trace per instance | none yet — defeats exact-hash matching | 🔶 candidate |
| `randomizer` | Multilogin / GoLogin multi-accounting — coherent per-instance fps, one JA4 | the TLS/JS paradox — shared JA4 + divergent JS (needs corroboration) | 🔶 candidate |
| `morph-diffuse` | the distinct-coherent-build diffuse fleet — one real engine per node | sheds the shared build → `ja4_prefix` no longer dense (drops below candidate) | ⬜ below-candidate |

### The blue signals it targets

> Each binding above links here. **Unambiguous** signals convict alone; **ambiguous** ones need an independent corroborator (an automation tell, a datacenter/proxy IP, a non-browser JA4); **Axis-A dimensions** convict only as one of ≥3 independent correlations. The scorer lives in the detector (`kitsune_harness.coordination`); this is the red team's map of what it targets.

#### fp_collision

an identical high-entropy fingerprint (canvas + audio + WebGL) across ≥2 distinct IPs. **ambiguous** — corroboration-gated: an exact high-entropy collision across distinct IPs is strong, but a standardized corporate image needs an independent bot corroborator.

#### trace_collision

an identical pointer-trajectory hash across ≥2 distinct IPs. **unambiguous** — a replayed human mouse-path has no benign explanation.

#### template_similarity

pointer-trace *descriptors* clustering below the human-motion floor across ≥2 IPs — one humanizer model, even when every trace_hash differs. **ambiguous** — corroboration-gated (calibrated against real human motion so it stays FP-safe).

#### shared_real_ip

one WebRTC-leaked origin behind ≥2 distinct proxy IPs. **unambiguous** — the same real origin behind the proxies; survives JA4 rotation + fp/trace fuzzing.

#### shared_ticket

one TLS-resumption ticket (`tls_ticket_id`) reused across ≥2 distinct IPs. **ambiguous** — corroboration-gated (a roaming user resumes from a second IP too).

#### flood_shape

a large cluster in timing lockstep across many distinct origins with no per-node binding. **aggregate** — corroborated by a non-browser tool JA4; the coordination scorer as L7-flood attributor.

#### arrival_regularity

scheduled inter-arrival (coefficient-of-variation ≈0) vs independent users' Poisson arrivals (CV≈1). **Axis-A dimension** — restores timing as an independent correlated dim; a Poisson-random stagger evades.

#### proxy_egress

a shared reduced tunnel MSS (WireGuard-class), or a shared re-originated SYN-stack (proxy kernel ≠ UA-claimed OS), across the fleet. **Axis-A dimension** — gated on the descriptor dim so a legit VPN/mobile cohort stays clean.

> The `candidate` frontier (`fuzzy`, `randomizer`, `diffuse*`) is where conviction becomes external-data-bound: a fleet that sheds every in-sandbox binding — distinct builds, real-hardware fps, clean residential egress, Poisson-random timing — is, by construction, indistinguishable from N independent real users without IP-reputation or real-traffic prevalence data. That is the economic wall, not a missing rule. Grade any fleet on the live detector view with `task coordination-live`.

<!-- GENERATED:coordination:end -->
