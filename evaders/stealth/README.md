# evaders/stealth — anti-detect browser evader (Camoufox / Playwright)

Status: **design stub.** The structure and integration are specified here; the implementation needs a
real browser runtime (Camoufox binary + Playwright), which is why it is not yet wired or tested in CI.

## Design

Drive a hardened browser through the edge so the detector sees a *coherent* fingerprint that beats
the browser-FP and CDP layers, while the collector still runs in-page:

```
stealth (Camoufox) ──HTTPS──▶ edge (JA3/JA4 + ks_sid) ──▶ detector app (serves collector.js)
        │                                                          │
        └── in-page collector posts browser+behavioral signals ────┘  (same ks_sid)
```

It implements the harness `Scenario` surface: launch the browser, navigate to the edge, let the
page's collector report, then read the verdict back by `ks_sid`.

## Seeds (from `docs/catalog.md` §7)

- **Camoufox** — C++-level fingerprint spoofing (defeats JS-probe detection). Primary engine.
- **patchright** — isolated ExecutionContexts to neutralise the `Runtime.enable` CDP leak.
- **fingerprint-suite / BrowserForge** — coherent fingerprint + header generation.
- **ghost-cursor** + human-typing — behavioral input so the behavioral layer doesn't trip.

## Why it beats the lower rungs

It produces a coherent fingerprint *and* (with human-input sim) plausible behavior — so unlike
`vanilla`/`go-tls` it can push the browser layer scores down. The expected scoreboard story is
`vanilla → stealth` showing the browser/CDP layers drop. Building this is phase 3.
