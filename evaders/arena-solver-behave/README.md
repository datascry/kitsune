# arena-solver-behave — red-team evasions for the behavioural arena gates

A single stdlib Python evader (`behave.py`, one **mode per gate**) that **defeats the FP-safe
solve-behaviour tells** of the 10 behavioural/CV arena gates by solving each coherently **and**
humanizing the solve so the server-observed anomaly stays silent.

**Ethics:** allow-list-scoped — it targets **only Kitsune's own `/arena/*` gates** (`KS_BASE`,
default the owned service). Never a third-party challenge; no lifted assets.

## What it demonstrates

The arena thesis, from the **red** side: an FP-safe tell (one calibrated below a human floor) means
a **coherent human-paced solver evades it** — the gate is a cost / Turing test, not a bot/human
discriminator. Each gate is grounded **both directions**:

- **naive** mode → a superhuman/instant solve **trips** the tell (`anomaly` present → the joined
  detector session convicts, `label=bot`).
- **human** mode → the same puzzle solved but humanized → the gate passes with **`anomaly: null`**,
  so nothing joins to `ks_sid` and no bot session is created (the `/verdict` 404 is the evasion
  signature).

A passed-and-silent gate does **not** clear the session: coherence still convicts unless the solve
runs inside a **coherent browser** (see below). This evader isolates the gate-behaviour layer.

## Gates + how each tell is defeated

| Gate | Tell | Humanization |
|---|---|---|
| `presshold` | `bh.arena_hold_robotic` | hold the real duration + drifting held-pointer tremor (std > 0.5px) |
| `pursuit` | `bh.arena_pursuit_superhuman` | follow with human tracking error (~18px, in the 8–55px band) |
| `reaction` | `bh.arena_reaction_superhuman` | wait a ~250ms reaction after the go (> 120ms floor) |
| `pattern` | `bh.arena_pattern_superhuman` | wobbly stroke (dev > 1.5px) at human pace (> N·300ms) |
| `sequence` | `bh.arena_seqclick_superhuman` | ordered clicks, varied cadence (std > 15ms), age > N·250ms |
| `locate` | `bh.arena_localize_superhuman` | CV centroid, click off it > 2.5px, spend > 500ms |
| `spotdiff` | `bh.arena_spotdiff_superhuman` | image-diff, click off-centroid > 3px over > K·1200ms |
| `slide` | `bh.arena_slide_superhuman` | BFS-solve + a wasted round-trip (non-optimal), > nMoves·350ms |
| `match` | `bh.arena_match_superhuman` | density-filtered apex orientation, correct answer paced > (N+1)·250ms |
| `count` | `bh.arena_count_superhuman` | connected-component count, correct answer paced > totalShapes·220ms |

## Run

```sh
# one gate (default KS_BASE=http://arena:8095, KS_MODE=human, KS_LEVEL=medium)
KS_GATE=pursuit KS_MODE=naive python behave.py     # trips the tell
KS_GATE=pursuit KS_MODE=human python behave.py     # evades

# the whole layer at once
KS_GATE=all KS_MODE=human python behave.py         # -> {"evaded": 10, "of": 10, ...}

# through the detector relay, joined to a session (shows the dual verdict)
KS_BASE=http://localhost:8080 KS_SID=demo KS_GATE=all KS_MODE=human python behave.py
```

## The full session-level evasion

Defeating the gate tell is only the gate layer. The **complete** evasion is these humanized solves
driven **inside a coherent browser** (e.g. `camoufox` with the provisioned audio/voices/WebRTC
floor): the gate stays silent **and** the session's fingerprint coheres — reaching `suspicious`
rather than `bot`, held off `human` only by the container GPU/WebRTC environment floor (the
in-sandbox wall; see `docs/coherent-stack.md` and the `single-session-wall` memory).
