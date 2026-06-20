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

The `cap`-class — PoW **fused** with a browser-instrumentation challenge — is the on-thesis rung. The gate
serves it with `POW_INSTRUMENTED=1` (or `?instrumented=1`): it additionally demands a **realm proof** (a
nonce'd canvas/realm hash from the main thread AND a Worker, which a real browser produces equal). Grounded
(iter-63): it blocks the naive no-browser solver, but `FORGE=1` defeats it by echoing two equal fabricated
hashes — a *client-asserted* proof is forgeable. So robust instrumentation must be **server-observed**
(Kitsune's collector, where the detector independently witnesses the worker realm). See `docs/red-team-roadmap.md`
Vein D.

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

## Findings (grounded 2026-06-20)

- **Raw PoW (iter-62):** the native no-browser solver **passes every class and redeems the token** — a raw
  PoW gate is a volumetric *cost* mechanism, not a bot/human discriminator. Class choice changes only cost:
  SHA-256 classes hand a native scraper an ~8000× speed edge; memory-hard erases it but still admits the bot.
- **Instrumented PoW (iter-63):** the `cap`-style realm-proof gate blocks the *naive* no-browser solver, but
  a *forging* solver (`FORGE=1`, two equal fabricated hashes) passes — a client-asserted browser proof is
  forgeable. Robust instrumentation must be **server-observed** = Kitsune's collector.
- **Conclusion:** PoW is an orthogonal cost/volumetric front-end; the real discriminator is Kitsune's
  existing passive coherence layer (`net.no_js_execution` for a no-browser solver; `br.worker_divergence`
  for a main-realm spoof). PoW adds no new convicting signal — Vein D mapped and closed in-sandbox.
