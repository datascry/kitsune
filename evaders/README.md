# evaders/ — the red-team ladder

A spectrum of **real open-source anti-detect tools and browsers**, each driven against Kitsune's
**own** detector (never a third party — see [Ethics](#ethics)) to validate that the detections fire.
Every evader produces a session's signals by driving a client through the `edge`, then reads the
detector's verdict back by `ks_sid`, so the detector scores them all identically. They form a
difficulty ladder that maps onto the cross-layer incoherence thesis: **flag incoherence across
layers, not just bad signals.**

## The families

| Family | Evaders | Layer attacked | Outcome |
|---|---|---|---|
| **Control** | `vanilla` (httpx) | none | the detection floor — scores `human` |
| **Scripted / TLS-mimicry** | `primp`, `curl-impersonate`, `go-tls` (uTLS) | network (JA3/JA4, HTTP/2) | win the fingerprint, caught above/below it (`no_js_execution`, `tcp_os_vs_ua`) |
| **Playwright + CDP-leak patches** | `stealth` (patchright, rebrowser) | browser-FP + CDP | defeat single-layer FP checks; caught by realm-coherence + cross-layer |
| **CDP-native** | `nodriver`, `zendriver`, `pydoll` | automation surface | no webdriver/CDP tells, still caught by the headless environment |
| **Isolated-world Selenium** | `undetected`, `selenium-driverless` | `Runtime.enable` CDP leak | dodge the CDP leak, caught by the headless floor |
| **Engine-level** | `camoufox` | the whole JS-surface ruleset | C++-level spoofing; coherent across vectors |
| **Farbling** | `brave` | canvas/audio readback | per-session noise caught reference-free |
| **HTTP/2 DoS** | `h2-rapid-reset` | protocol abuse (CVE-2023-44487 / -2024-27316) | attributed to a minted session |
| **LLM agent** | `agent` (`claude -p`) | behavioral / intent | beats network + browser, caught **behaviorally** (the headline result) |

Each per-evader README documents the tool, the layer it targets, its live verdict, and how to run it.

## The thesis, on the scoreboard

`scripts/live_scoreboard.sh` brings up `detector` + `edge` + `browser`, runs the fleet, and renders
`docs/scoreboard.md` + `docs/matrix.md`. The arc:

- **`vanilla`** scores `human` — the floor everything is measured against.
- The **TLS-mimicry** family wins the network fingerprint outright (real Chrome JA4, GREASE, the
  `X25519MLKEM768` PQ key share) yet is convicted on what is *not* part of the fingerprint:
  `net.no_js_execution` (no browser) and `net.tcp_os_vs_ua` (Linux kernel under a Windows UA).
- Every **Chromium-based** tool (nodriver, undetected, zendriver, pydoll, selenium-driverless,
  patchright, rebrowser) closes the automation/CDP tells but is still caught by the **headless
  environment floor** (`webgl_software`, `voices_empty`, `media_devices_empty`, `chrome_runtime_missing`).
- **`camoufox`** (engine-level Firefox) is the only browser evader to ever score `human` — it spoofs
  below the JS surface and stays coherent across vectors. The detector has since closed the gap via
  OS-*capability* tells a container lacks. The realistic counters left are behavioral.
- **`agent`** (`claude -p`) defeats the network and browser/fingerprint layers but is caught by the
  **behavioral** layer — its actions don't produce human-like pointer/keystroke entropy. The durable
  signal is behavioral / intent, exactly the thesis.

## The `stealth` evader (Playwright multi-mode)

`stealth/run.mjs` is a single Playwright-based evader with many env-selected modes — the fleet's
workbench for the **realm-coherence** rules. Beyond naive vs patched stealth, it spoofs the main JS
realm while *forgetting* a sibling scope (Worker, iframe), so the detector's divergence probes catch
the realm the patch never reached; `WORKER_WRAP` is the escalation that hides from `worker_divergence`
but trips `worker_constructor_tampered`. See [`stealth/README.md`](stealth/README.md) for the full
mode table.

## Ethics — non-negotiable, enforced in code

Every evader may target **only** Kitsune's own detector/edge and the approved public test endpoints in
`harness/src/kitsune_harness/allowlist.py`; the harness raises `EthicsError` on anything else. The
self-contained arena *is* the ethics design. Never point an evader at a third-party/production site,
and never weaken the allow-list. See `SECURITY.md`.
