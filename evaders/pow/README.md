# evaders/pow — proof-of-work arms-race testbed (defense ⇄ evasion)

A self-contained PoW testbed: a **blue-team gate** that issues challenges and mints a signed pass token,
and a **red-team native solver** (no browser) that beats it. It models the catalogued PoW families
(`docs/catalog.md §6`) as distinct **classes** so the red-team can measure each one's cost asymmetry.

Like every evader it targets only Kitsune's own surfaces — here a self-contained gate, never a
third-party site. It does **not** import the detector/edge (license-isolated; the only dep is the
permissive `golang.org/x/crypto/argon2`).

## Classes (the work functions to evade)

| Class | Catalog source | Work function | Native-solver cost |
|---|---|---|---|
| `hashcash` | anubis | SHA-256 leading-zero-bits, one puzzle | **cheap** (~2M hashes/s) |
| `many-small` | friendlycaptcha | N independent low-difficulty hashcash puzzles (variance reduction) | **cheap** (same hash rate) |
| `memory-hard` | altcha | Argon2id (memory-bound) | **~8000× costlier per eval** (~240/s) — levels CPU vs browser |

The `cap`-class (PoW **fused** with a browser-instrumentation challenge) is the on-thesis rung: its tell is
whether a *real browser ran the challenge JS* — a coherence signal, not a hash a headless solver can
brute-force. Documented as the next blue-team build in `docs/red-team-roadmap.md` (Vein D).

## Run

```sh
# cost-asymmetry sweep (in-process, no gate)
docker run --rm -e BENCH=1 -v "$PWD":/src -w /src/evaders/pow golang:1.26-alpine go run ./cmd/pow-solver

# live: gate vs solver
docker run -d --name pow-gate --network kitsune_default -v "$PWD":/src -w /src/evaders/pow golang:1.26-alpine go run ./cmd/pow-gate
docker run --rm --network kitsune_default -e POW_GATE=http://pow-gate:8090 -e POW_CLASS=memory-hard \
  -v "$PWD":/src -w /src/evaders/pow golang:1.26-alpine go run ./cmd/pow-solver
```

`POW_CLASS` ∈ {`hashcash`,`many-small`,`memory-hard`}; `POW_ROUNDS=N` hammers the gate (the fleet-cost
angle); the gate reads `POW_DIFFICULTY` / `?class=` / `?difficulty=`.

## Finding (grounded 2026-06-20)

The native no-browser solver **passes every class and redeems the token** — a raw PoW gate is a volumetric
*cost* mechanism, not a bot/human discriminator, so it adds **no coherence signal** to Kitsune's passive
detector. Class choice changes only the cost: SHA-256 classes hand a native scraper an ~8000× speed edge;
the memory-hard class erases it (the right choice for a raw gate) but still admits the bot. The durable,
on-thesis signal is the `cap`-style instrumentation coherence, not the PoW itself.
