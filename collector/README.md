# collector/ — in-browser signal collection (TypeScript)

Runs in the page, reads fingerprint + behavioral tells, and POSTs contract-valid `Signal` envelopes
to the detector — tagged with the `ks_sid` correlation cookie the edge set, so browser telemetry
joins the network signals into one session.

## Design

The browser globals are abstracted behind a `BrowserEnv` interface, so all collection logic is
**pure and testable without a real browser** (100% coverage). Only `index.ts` touches live
globals — it's the thin glue, excluded from the coverage gate (tier-2).

| Module          | Role                                                                            |
| --------------- | ------------------------------------------------------------------------------- |
| `signal.ts`     | Build contract-valid `Signal` envelopes.                                        |
| `detect.ts`     | UA → browser/platform; normalise Client-Hints platform (feeds UA↔CH coherence). |
| `behavioral.ts` | Pointer event count + normalised movement-direction entropy (the human floor).  |
| `session.ts`    | Read the `ks_sid` correlation cookie.                                           |
| `collect.ts`    | Assemble a session's signals from a `BrowserEnv` snapshot.                      |
| `transport.ts`  | POST signals to the detector's `/ingest` (injected `fetch`).                    |
| `index.ts`      | Browser entrypoint: wire live DOM/navigator probes, collect, send.              |

## Develop

```sh
pnpm install
pnpm test          # vitest + coverage gate (>=95%, currently 100%)
pnpm run typecheck # tsc --strict (+ noUncheckedIndexedAccess, exactOptionalPropertyTypes)
pnpm run lint && pnpm exec prettier --check .
pnpm run build     # tsup → dist/ (ESM + d.ts)
```

> The CDP `Runtime.enable` probe (`cdp.ts`, prototype-chain Proxy `ownKeys` trap) is implemented and
> tested — it stays `false` in a clean page and trips when a CDP preview enumerates the marker (the
> live replacement for the dead `Error.stack` trick; see `docs/catalog.md` §4). The canvas-lie probe
> (native `toString` check) is also live.
