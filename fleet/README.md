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

## Strategy catalog (the red⇄blue ladder)

Each strategy models a real attacker class and grounds a specific blue coordination signal:

| `strategy` | Attacker class | Blue signal it grounds | Convicted today? |
|---|---|---|---|
| `cloned` | BotBrowser-class — one pinned profile cloned fleet-wide | `fp_collision` (identical high-entropy fp across distinct IPs) | ✅ `fleet` |
| `trace-replay` | engagement / review farms — one canned "humanised" mouse path replayed | `trace_collision` (unambiguous) | ✅ `fleet` |
| `randomizer` | Multilogin/GoLogin multi-accounting — coherent per-instance fingerprints, one JA4 | the TLS/JS paradox (corroborating; needs an automation tell or IP-rep flag to convict) | 🔶 `candidate` unless corroborated |
| `fuzzy` | **the evolved adversary** — jitter the fingerprint *and* the trace per instance | **none yet** — defeats exact-hash matching | ❌ `candidate` — **the frontier** |
| `similarity` | the same evolved adversary, **profiled** — its jittered traces all come from one humanizer model | `template_similarity` (descriptors cluster below the human floor; corroboration-gated like `fp_collision`) | ✅ `fleet` (with corroboration) |
| `fuzzy-rotate` | the hardest shape — **rotate JA4 per node** AND fuzz fp/trace; defeats prefix clustering *and* exact collision | `shared_real_ip` (one WebRTC origin survives rotation; recovered by collision-clustering) + `template_similarity` corroborates | ✅ `fleet` *iff a binding leaks*; otherwise **uncatchable in-sandbox** (see note) |
| `ticket-reuse` | rotated JA4 + fuzzed, bound by a **reused TLS-resumption ticket** (one TLS session across the nodes) | `shared_ticket` (one `tls_ticket_id` across distinct IPs; the edge captures it from pre_shared_key / session_ticket; corroboration-gated — a roaming user resumes too) | ✅ `fleet` (with corroboration) |
| `staggered` | a cloned fleet that **spreads arrivals over time** (beyond the lockstep window) to look organic | demonstrates the timing axis: lockstep is *corroborating-only*, so it sheds the bonus but the `fp_collision` binding still convicts | ✅ `fleet` (timing-stagger is a weak evasion) |
| `ipv6-rotate` | a cloned fleet **spraying IPv6 /128s inside a few /64s** to fake IP spread / bypass per-IP limits for free | the **/64 origin fold** — `_ip_origin` counts distinct /64 origins, so the spray collapses to its true origin count; a cloned fp across distinct /64s still convicts | ✅ `fleet` (the IPv6 evasion buys nothing) |

`fuzzy` was the point of the tool: once an attacker knows we hash, they perturb just enough to dodge
*exact-match* collision. It exposed the next blue rung — **template-similarity clustering** (N near-identical
traces across distinct IPs = one humanization model, not N humans) — which `similarity` now grounds: every node
jitters its `trace_hash` distinct (exact-match finds nothing), but the collector's motion-feature *descriptors*
cluster below the human floor (calibrated against real human motion — `task template-calibrate`, SapiMouse),
so on datacenter/proxy egress the IP-reputation flag corroborates the cluster and it convicts.

### Grounded live (Kitsune detector, ruleset 0.74.52)
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
