# Fleet & coordination — the red⇄blue coordination loop

Per-session detection saturates: with enough budget you can make any *single* session look clean — a real
GPU, an engine-level anti-detect browser, a residential proxy. What stays expensive is **coherence across
many sessions at fleet scale**. A coordinated fleet must either *clone* one profile (a fingerprint/trace
collision across distinct IPs) or *randomize* per node (the TLS-vs-JS paradox, or a behavioral template all
nodes share). It cannot cheaply do neither. Kitsune runs **both sides** of that level of the arms race.

This page is the map. The standalone red kit has its own [`fleet/README.md`](../fleet/README.md); the blue
scorers live in [`harness/.../coordination.py`](../harness/src/kitsune_harness/coordination.py).

---

## Red — Skulk and the fleet manager

### Skulk (`fleet/`) — the adversary-emulation kit

[Skulk](../fleet/README.md) generates **coordination-shaped sessions** and emits them to a detector's
`/ingest`. It is a **detection-validation** tool (in the spirit of Atomic Red Team / Caldera), **not** an
attack tool: there is no flood/DoS, credential, or scraping capability, and every run is
**authorization-scoped in code** ([`scope.py`](../fleet/src/skulk/scope.py)) — it resolves the target against
an allow-list (Kitsune's own `detector`/`edge`/`arena`/`localhost` by default) and refuses anything else.
There is no flag that disables the check.

```sh
cd fleet
uv run skulk list                                              # the strategy catalog
uv run skulk describe fuzzy -n 5                               # show a fleet shape (no emission)
uv run skulk run cloned --target http://localhost:8099 -n 3   # emit a cloned fleet at the lab detector
KITSUNE_DETECTOR=http://localhost:8099 task coordination-live # grade it on the detector's own view
```

The **strategy ladder** climbs from naive to evasive — each models a real attacker class and grounds one
blue signal (full table with conviction status in [`fleet/README.md`](../fleet/README.md)):

| Strategy | Models | What it grounds |
|---|---|---|
| `cloned` | one profile cloned fleet-wide | `fp_collision` |
| `trace-replay` | one canned pointer trace replayed | `trace_collision` |
| `randomizer` | coherent per-instance fp, one JA4 | the TLS/JS paradox (corroborating) |
| `fuzzy` | jitter fp *and* trace per node | the exact-hash frontier |
| `similarity` | jittered traces from one humanizer model | `template_similarity` |
| `fuzzy-rotate` | rotate JA4 per node + fuzz fp/trace | `shared_real_ip` (a leaked binding) |
| `ticket-reuse` | rotated + fuzzed, bound by a reused TLS ticket | `shared_ticket` |
| `staggered` | a cloned fleet spreading arrivals over time | the lockstep timing axis (corroborating-only) |
| `ipv6-rotate` | spray IPv6 /128s inside a few /64s | the /64 origin fold |
| `diffuse-campaign` | distinct everything, tuned above the template floor | axis A (aggregate correlation) |
| `tool-fleet` | a heterogeneous scripted-tool fleet | shared JA4-tool / ext signature |

### The fleet manager — driving *real* evader containers

[`fleet_manager.py`](../harness/src/kitsune_harness/fleet_manager.py) runs the same shapes with **real evader
containers** instead of synthetic ingest, from a registry of **named evasions**, **plans**, **archetypes**
and **campaigns**. Each replica gets a per-node `KS_NODE_SEED` (so its fingerprint/behavior differ
deterministically), an optional per-node proxy, retries, and a `stagger_seconds` launch spread. The
`--validate-archetypes` mode turns every adversary persona's `expected` outcome into a tested contract
(`task archetype-validate`).

```sh
task coordination-fleet-manage -- --evasion camoufox-linux --evasion zendriver-uach --n 2 \
  --detector http://localhost:8099
task archetype-validate -- --detector http://localhost:8099   # every persona vs its expected verdict
```

### Objectives — actions-on-objective, sharded per worker

A coordinated fleet doesn't just exist; it *does work*. [`objectives.py`](../harness/src/kitsune_harness/objectives.py)
models an `Objective` (name, target, work items, a behavioral template, per-item wait) and **shards** it
round-robin across N workers via `compile(n)`, producing a distinct `BehavioralTask` per node so no two
workers replay the same trajectory. The registry's targets are **synthetic lab endpoints only** — the
`example.test` form on the harness allow-list — and the modeled objectives (e.g. credential-stuffing,
account-creation) are *shapes for the detector to catch*, never a working attack. There is no credential
generator and no real target.

### Humanization — beating the structural behavioral tells

The hardest behavioral tells are structural, not shape-based: `getCoalescedEvents()` length + `isTrusted`
catch CDP-injected input regardless of how human the *path* looks. The `real-input` evasion mode
(`KS_REAL_INPUT`, in [`evaders/stealth/run.mjs`](../evaders/stealth/run.mjs)) drives **real OS-level pointer
input** via XTEST/`xdotool` under `xvfb`, producing genuine coalesced events and `isTrusted` — so the red
team can exercise (and the blue team must hold up against) input that is structurally real, not synthesized.

---

## Blue — two coordination scorers

Both scorers run over the session **corpus** (`list[(session_id, Session)]`), typically fetched live from a
detector's store ([`live_coordination.py`](../harness/src/kitsune_harness/live_coordination.py)).

### Per-binding — `score_corpus` → `FleetVerdict`

Clusters sessions by **JA4 prefix** and looks for cross-instance **collisions**. Convicting bindings:
`fp_collision`, `trace_collision`, `shared_origin` (one WebRTC/real origin), `ticket_reuse` (one TLS
resumption ticket). Ambiguous bindings (`fp_collision` on a low-entropy fp, `ja4c`, `template_similarity`,
`ticket`) are **corroboration-gated** — they need an automation tell or an IP-reputation flag to convict.
Every conviction requires **≥2 distinct /64 origins** (`_ip_origin` folds an IPv6 spray to its true origin),
so a real cohort behind one NAT, or one office on one browser build, never reads as a botnet.

### Axis A — `score_campaigns` → `CampaignVerdict`

The **aggregate** view: community detection over a multi-dimensional similarity graph. The dimensions
(`_CAMPAIGN_DIMS`) are **JA4 prefix**, **behavioral descriptor** (soft ε ≤ 0.15), **lockstep arrival**
(≤ 120 s), **origin reputation**, and **prevalence tail**. An edge joins two sessions sharing ≥ 2 dimensions;
a **campaign** is a community spanning ≥ 2 origins that is *dense* (≥ 0.5 of its internal pairs) on ≥ 3
dimensions; ≥ 2 dimensions is a **candidate**. Candidate generation is blocked by JA4+time so it scales, and
`replay_campaigns` runs it as a windowed stream. Axis A is what catches the **residual correlation** a
diffuse fleet leaves *after* it has defeated every pairwise binding.

---

## The escalation ladder — why both are needed

`task adversary-showcase` ([`harness/tools/adversary_showcase.py`](../harness/tools/adversary_showcase.py))
emits canonical fleet shapes to a live detector and grades each through **both** scorers, printing the ladder:

| Fleet shape | Per-binding (`score_corpus`) | Axis A (`score_campaigns`) |
|---|---|---|
| `cloned` | **FLEET** (`fp_collision`) | — |
| `trace-replay` | **FLEET** (`trace_collision`) | — |
| `diffuse-campaign` | candidate (evades) | **CAMPAIGN** (caught) |
| `diffuse-staggered` | candidate (evades) | **CAMPAIGN** (stagger alone isn't enough) |
| `diversified` | candidate (evades) | no-campaign (evades **both**) |

The pairwise scorer falls first; axis A catches the build-rotating-but-correlated residual; and only a
**fully diversified** fleet — distinct build/fingerprint/trace, spread descriptors, spread arrivals — evades
both. At that point it is, by construction, **N independent real users** (the economic bind: conviction there
is [external-data-bound](research-radar.md), not an in-sandbox signal).

### Diversification levers ⇄ axis-A dimensions

Each red lever that gets a fleet to the frontier maps **one-to-one** onto the axis-A dimension it defeats —
which is also why defeating all of them costs as much as running real users:

| Red lever | Axis-A dimension it drops |
|---|---|
| distinct browser builds per node | `ja4_prefix` |
| distinct (real) behavior per node | behavioral `descriptor` |
| stagger arrivals beyond the window | `lockstep` |
| clean / residential egress per node | `origin_reputation` |
| real, varied hardware | `prevalence_tail` |

---

## Running the loop

```sh
task coordination-eval                         # precision/recall over legit + malicious scenarios
task adversary-showcase -- --detector http://localhost:8099   # the full red⇄blue ladder
task coordination-fleet-demo                   # ingest a coordinated fleet, then grade it live
task coordination-fleet-capture                # AUTHENTIC: N real evader containers through the edge
```

## Ethics

Skulk, the fleet manager and objectives target **only** Kitsune's own detector/edge/arena and the
`harness/allowlist.py` endpoints — never a third-party or production site. They model coordination *shapes*
for a detector to catch; they are not a flood, DoS, credential, or scraping tool, and the allow-list is
enforced in code. See [`fleet/README.md`](../fleet/README.md) §Authorized-use and the repo
[ethics policy](../README.md#ethics).
