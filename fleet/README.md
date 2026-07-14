# Skulk — fleet adversary-emulation for coordination-defense testing

> A *skulk* is a group of foxes. Skulk emulates a coordinated **fleet** of bots to test whether a
> bot-detector catches them — the red half of the Kitsune red⇄blue exercise, as a standalone, reusable kit.

Per-session detection is a losing game: with enough resources you can make any single layer of any single
session look clean (real GPU, anti-detect browser, residential proxy). What you **can't** cheaply beat is
**coherence across sessions at fleet scale** — a coordinated fleet must either *randomize* its fingerprints
(the TLS-vs-JS paradox) or *clone* one profile (a fingerprint/trace collision across distinct IPs); it cannot
do neither. Skulk generates exactly those fleet shapes so you can **measure whether a coordination detector
catches them** — for education, and for authorized red-team engagements against your own defenses.

## ⚠️ Authorized use only

Skulk is a **detection-validation** tool (like Atomic Red Team / Caldera), not an attack tool. It emits
**benign coordination-shaped sessions** to a detector's ingest surface — there is **no** flood/DoS,
credential, or scraping capability, and there never will be. Every run is **authorization-scoped in code**
(`skulk/scope.py`): it resolves the target host against an allow-list and **refuses anything outside it**.

- The bundled scope is **Kitsune's own lab** (`detector`/`edge`/`arena`/`localhost`) — runs with no extra flags.
- Any **other** target must be added explicitly **and** affirmed: `--authorize your.host --i-am-authorized`.
- There is **no flag that disables the check.** Only point it at infrastructure you own or have **written
  authorization** to test.

## Quickstart

```sh
cd fleet
uv run skulk list                          # the strategy catalog
uv run skulk describe fuzzy -n 5           # show a fleet shape + Skulk's self-assessment (no emission)
uv run skulk run cloned --target http://localhost:8099 -n 3   # emit a cloned fleet at the lab detector
# grade it on the target's own coordination view (Kitsune):
KITSUNE_DETECTOR=http://localhost:8099 task coordination-live
```

`--dry-run` generates and prints a fleet without emitting anything — the safe default for teaching.

## The strategy ladder (red⇄blue)

**How a fleet is graded** — not per-session human/bot, but at the *coordination* axis. The detector clusters
sessions by their **JA4 TLS-engine prefix** (the layer below JS spoofing), then looks for coordination two ways:

- **Axis B — a per-cluster binding:** does one *thing* repeat across distinct IPs inside a cluster — a
  fingerprint, a mouse-trace, a TLS ticket, a WebRTC origin? Some bindings **convict alone** (a replayed trace,
  a shared origin); others are **ambiguous** — a shared fingerprint or a tight trace-descriptor cluster also
  describes a corporate cohort — so they convict only when **corroborated** by an independent bot signal (an
  automation tell, a datacenter/proxy IP, a non-browser JA4).
- **Axis A — population correlation:** when no single binding repeats, does a community correlate across **≥3
  independent soft dimensions** (shared JA4 + one descriptor family + a scheduled cadence + a shared proxy
  egress …)? Three independent coincidences is a `campaign`; two is a `candidate`.

So a fleet's verdict is `benign → candidate → fleet` (Axis B) / `campaign` (Axis A). The ladder below is the
red⇄blue menu — each strategy is the *evolved* adversary that defeats the rung above it, paired with the blue
binding that catches it (or the frontier where conviction becomes external-data-bound). The `fleet`-tier rows
are locked to the code by Skulk's own collision self-check; the `campaign` rows are grounded end-to-end live
(`task coordination-live`).

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
| `cloned` | BotBrowser — one pinned profile cloned fleet-wide | `fp_collision` — identical high-entropy fp across distinct IPs | ✅ fleet |
| `fuzzy-rotate` | the hardest shape — rotate JA4 per node AND fuzz fp/trace | `shared_real_ip` — one WebRTC origin survives rotation (+ template_similarity) | ✅ fleet |
| `httpflood` | L7 HTTP flood (MHDDoS class) — many no-JS tool sources in lockstep | the aggregate flood shape (large + lockstep + many origins) + tool JA4 | ✅ fleet |
| `ipv6-rotate` | cloned fleet spraying IPv6 /128s inside a few /64s to fake IP spread | the /64 origin-fold collapses the spray; `fp_collision` still convicts | ✅ fleet |
| `similarity` | the evolved adversary, profiled — jittered traces from one humanizer model | `template_similarity` — descriptors cluster below the human floor (corroboration-gated) | ✅ fleet |
| `staggered` | a cloned fleet spreading arrivals over time to look organic | `fp_collision` still convicts — lockstep is corroborating-only | ✅ fleet |
| `ticket-reuse` | rotated JA4 + fuzzed, bound by a reused TLS-resumption ticket | `shared_ticket` — one `tls_ticket_id` across distinct IPs (corroboration-gated) | ✅ fleet |
| `tool-fleet` | no-JS automation-tool fleet (curl / Go / Python), one tool JA4 | `shared_ticket` + the non-browser JA4 (`ja4_client_hint`) corroborates | ✅ fleet |
| `trace-replay` | engagement / review farm — one canned mouse path replayed | `trace_collision` — identical trace across distinct IPs (unambiguous) | ✅ fleet |
| `diffuse-automated` | a diffuse fleet that leaks a per-session automation tell (webdriver) | the automation tell lifts a 2-dim community to campaign (Axis-A corroboration) | ✅ campaign |
| `diffuse-scheduled` | a diffuse fleet that staggers on a fixed SCHEDULE | `arrival_regularity` — scheduled CV≈0 vs independent-user Poisson CV≈1 | ✅ campaign |
| `residential-proxy` | a diffuse fleet on clean residential IPs behind one tunnel pool | `proxy_egress` — a shared reduced tunnel MSS (WireGuard-class), gated on descriptor | ✅ campaign |
| `socks-proxy` | a diffuse fleet on a SOCKS pool that re-originates TCP | `proxy_egress` — shared SYN-stack-vs-UA-OS divergence, gated on descriptor | ✅ campaign |
| `diffuse` | the maximal in-sandbox evader — diffuse, Poisson-staggered, fully clean | none in-sandbox — conviction is external-data-bound (the frontier the ladder converges on) | 🔶 candidate |
| `diffuse-campaign` | the maximal evader base — shared build + lockstep + one humanizer | none in-sandbox — a 2-dim (ja4_prefix + descriptor) candidate | 🔶 candidate |
| `fuzzy` | the evolved adversary — jitter the fp *and* the trace per instance | none yet — defeats exact-hash matching | 🔶 candidate |
| `randomizer` | Multilogin / GoLogin multi-accounting — coherent per-instance fps, one JA4 | the TLS/JS paradox — shared JA4 + divergent JS (needs corroboration) | 🔶 candidate |
| `morph-diffuse` | the distinct-coherent-build diffuse fleet — one real engine per node | sheds the shared build → `ja4_prefix` no longer dense (drops below candidate) | ⬜ below-candidate |

> The `candidate` frontier (`fuzzy`, `randomizer`, `diffuse*`) is where conviction becomes external-data-bound: a fleet that sheds every in-sandbox binding — distinct builds, real-hardware fps, clean residential egress, Poisson-random timing — is, by construction, indistinguishable from N independent real users without IP-reputation or real-traffic prevalence data. That is the economic wall, not a missing rule. Grade any fleet on the live detector view with `task coordination-live`.

<!-- GENERATED:coordination:end -->

`fuzzy` was the point of the tool: once an attacker knows we hash, they perturb just enough to dodge
*exact-match* collision. It exposed the next blue rung — **template-similarity clustering** (N near-identical
traces across distinct IPs = one humanization model, not N humans) — which `similarity` now grounds: every node
jitters its `trace_hash` distinct (exact-match finds nothing), but the collector's motion-feature *descriptors*
cluster below the human floor (calibrated against real human motion — `task template-calibrate`, SapiMouse),
so on datacenter/proxy egress the IP-reputation flag corroborates the cluster and it convicts.

### Grounded live (Kitsune detector, ruleset 0.74.57)
> Results are stable across ruleset 0.74.52 → 0.74.57: the coordination scorer
> (`kitsune_harness.coordination` / `live_coordination`) is unchanged since these were first grounded — the
> intervening releases are unrelated axes (arena gates, session-flow, mobile, the `track` LLM-agent gate).
> Re-confirmed live at 0.74.57: `cloned → fleet 1.00` reproduces exactly.
```
skulk run cloned        →  detector grades `fleet` 1.00   (cloned-profile reuse caught)
skulk run similarity    →  detector grades `fleet` 1.00   (humanizer-model descriptors cluster below the human floor)
skulk run fuzzy-rotate  →  detector grades `fleet` 1.00   (rotated JA4 + fuzzed fp/trace; the shared WebRTC origin
                                                          survives, template-similarity corroborates)
skulk run ticket-reuse  →  detector grades `fleet` 1.00   (rotated JA4 + fuzzed; one reused TLS-resumption ticket
                                                          survives the rotation, datacenter corroborates)
skulk run staggered     →  detector grades `fleet` 1.00   (arrivals spread 600s — "no lockstep" — but the cloned
                                                          fp-collision still convicts; timing-stagger is weak)
skulk run fuzzy         →  detector grades `candidate`    (no descriptor profiled — still evades; the open frontier)
```

> **Why `fuzzy-rotate` needs a leaked binding.** A fleet that rotates its JA4 *and* fuzzes fp/trace lands as N
> singleton clusters — descriptor *similarity* alone cannot recover it FP-safely. Measured
> (`task template-calibrate`): without a binding to constrain the candidate set, a population of *distinct*
> humans always contains a coincidentally-tighter trace subset than a real fleet, and that false-cluster floor
> *drops as the corpus grows*. So similarity is a within-cluster **corroborator**, never a primary cross-corpus
> key. `fuzzy-rotate` is convicted only when an unambiguous binding survives the rotation (a shared WebRTC
> origin here; a reused TLS session ticket next). A fleet that leaks *neither* is genuinely indistinguishable
> in-sandbox — catching it is external-data-bound (a production-scale real-trace population to calibrate the
> floor), and the lab marks it so rather than shipping an FP-unsafe rule.

## Scenarios this is for

Credential stuffing / ATO · mass account creation & multi-accounting fraud · scalping (ticket/sneaker/GPU
drops) · distributed scraping · L7-flood attribution · astroturfing / review fraud / engagement farms ·
sybil attacks. In every one the attacker makes each session look like a distinct clean user; only the
**cluster property** convicts.

## Modes

- **Signal mode (built in):** Skulk POSTs coordination-shaped sessions to the target `/ingest` — fast,
  browserless, deterministic; distinct source IPs are modelled via the `observed_ip` signal (the in-sandbox
  analog of proxy egress). Best for testing the *detection logic*.
- **Browser mode (authentic):** for genuine TLS/JS captures with real distinct container IPs, drive the real
  evader fleet via `harness/tools/fleet_capture.sh` (`task coordination-fleet-capture`) — the heavier,
  fully-authentic path. (Real residential-proxy egress is the external input via that tool's `PROXIES=`.)

## Extending

Add a strategy by duck-typing `skulk.strategy.Strategy` (`name`, `summary`, `members(n, seed) -> [FleetMember]`)
and decorating it with `@register`. Keep it deterministic in `seed` so runs are reproducible and fixtures are
stable. The `similarity` (template-similarity), `fuzzy-rotate` (surviving WebRTC origin), and `ticket-reuse`
(reused TLS-resumption ticket — the edge now captures `tls_ticket_id` from pre_shared_key / session_ticket)
strategies + their blue rungs are **done** — see above, as is the `staggered` timing strategy (it grounds that
lockstep is corroborating-only, never load-bearing for conviction). The remaining frontier is external-data-bound:
the corpus-wide trace-similarity floor and Tier-3 real-GPU validation (see `docs/research-radar.md`).

## Design

- **Stdlib-only** (no dependencies) — portable, trivially vendored into an engagement, no install footprint.
- **Contracts-only** — speaks the detector's JSON signal contract directly; never imports a detector, so it
  works against any Kitsune-compatible coordination surface.
- **Reproducible** — every strategy is seeded.

Ethics, in one line: **only test what you own or are authorized to test.** The scope gate enforces it.
