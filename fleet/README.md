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

`fuzzy` is the point of the tool: once an attacker knows we hash, they perturb just enough to dodge
*exact-match* collision. It exposes the next blue rung — **template-similarity clustering** (N near-identical
traces across distinct IPs = one humanization model, not N humans). Skulk lets you prove that gap on demand.

### Grounded live (Kitsune detector, ruleset 0.74.52)
```
skulk run cloned  →  detector grades `fleet` 1.00   (cloned-profile reuse caught)
skulk run fuzzy   →  detector grades `candidate`    (evades exact-hash — the frontier)
```

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
stable. The roadmap: a `similarity`/`fuzzy-trace` strategy paired with template-similarity clustering on the
blue side; a `ticket-reuse` strategy (shared TLS session ticket across IPs); a `staggered` timing strategy.

## Design

- **Stdlib-only** (no dependencies) — portable, trivially vendored into an engagement, no install footprint.
- **Contracts-only** — speaks the detector's JSON signal contract directly; never imports a detector, so it
  works against any Kitsune-compatible coordination surface.
- **Reproducible** — every strategy is seeded.

Ethics, in one line: **only test what you own or are authorized to test.** The scope gate enforces it.
