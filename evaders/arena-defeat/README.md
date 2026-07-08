# evaders/arena-defeat — the composed arena-gate DEFEAT profile

**DEFEAT ≠ solve.** Every reference solver *passes* an arena gate but is *convicted* on coherence — a solved
gate is a cost/Turing test, not a bot/human discriminator (the arena thesis). This profile does the harder
thing: pass the gate **and escape conviction in the same session**, for all three latest gates (clock,
spatial, audio).

It is the empirical proof of the thesis from the red side: the *only* way to defeat these gates is to
**genuinely be a coherent browser** (engine-level, provisioned, real input, no CDP) **and pace** the solve.
There is no gate-specific trick — defeating the gate just relocates the fight to per-session coherence, which
is crossed only by the maximal coherent stack.

## The two tells every naive solve trips (and how the profile beats each)

| Tell | Why a script trips it | How the profile clears it |
|---|---|---|
| `arena_*_superhuman` (server-observed speed) | solves in ms | **PACE** the verify past the human floor (clock 800ms, spatial 500ms, audio real-time playback) |
| `net.no_js_execution` + automation/headless/behavioural tells | a script, not a browser | run the solve **inside** the coherent Camoufox stack (engine FP, provisioned floor, real XTEST input) |

## The recipe (grounded live over the edge)

The solve rides **inside** `evaders/camoufox` (`KS_ARENA_SOLVE=<gate>`): after the collector POSTs, the browser
mints the challenge in-session, solves it (clock ray-cast / spatial top-face colour / audio NCC matched-filter),
paces past the floor, and verifies — all on one coherent `ks_sid`.

```sh
# clock / spatial — pure in-page solve
docker run --rm --network kitsune_default \
  -e KS_HARDENED=1 -e KS_PROVISION=1 -e KS_HEADFUL=1 -e KS_REAL_INPUT=1 \
  -e KS_ARENA_SOLVE=clock   kitsune-camoufox:latest    # or KS_ARENA_SOLVE=spatial

# audio — the matched-filter needs the FSDD templates + numpy (baked in); mount the corpus
docker run --rm --network kitsune_default \
  -v "$PWD/arena/assets/fsdd:/fsdd" -e FSDD_DIR=/fsdd \
  -e KS_HARDENED=1 -e KS_PROVISION=1 -e KS_HEADFUL=1 -e KS_REAL_INPUT=1 \
  -e KS_ARENA_SOLVE=audio   kitsune-camoufox:latest

# ALL THREE on ONE ks_sid — the whole latest arena defeated in a single coherent session
docker run --rm --network kitsune_default \
  -v "$PWD/arena/assets/fsdd:/fsdd" -e FSDD_DIR=/fsdd \
  -e KS_HARDENED=1 -e KS_PROVISION=1 -e KS_HEADFUL=1 -e KS_REAL_INPUT=1 \
  -e KS_ARENA_SOLVE=all   kitsune-camoufox:latest
```

The maximal coherent stack: `KS_HARDENED` (os=linux coherent, no touch), `KS_PROVISION` (native PulseAudio +
speech-dispatcher → media/voices present), `KS_HEADFUL` + `KS_REAL_INPUT` (XTEST hardware motion → coalesced
events, behavioural layer 0). Engine-level Gecko FP → network 0, no CDP.

## Grounded results (ruleset 0.74.57)

| Gate | Solve | Gate verdict | Session verdict |
|---|---|---|---|
| clock | ray-cast the hands | `ok=True` paced, no anomaly | **`suspicious` 0.36 — not bot** |
| spatial | top-face colour sample | `ok=True` paced, no anomaly | **`suspicious` 0.36 — not bot** |
| audio | NCC matched-filter (FSDD) | `ok=True` paced, no anomaly | **`suspicious` 0.36 — not bot** |

In every defeat `net.no_js_execution` and `arena_*_superhuman` are **absent**, and `network / behavioral /
reputation = 0.0`. The **only** residual is 2 *environment* tells — `br.webgl_software` (software GPU) and
`br.webrtc_unavailable` (no ICE) — the container's hardware floor. It is **provisionable** (a real GPU +
WebRTC would clear it toward `human`) and is **neither a gate tell nor a coherence tell**: the arena thesis
holds exactly.

## Honest caveats

- **`suspicious`, not `human`** — held off from `human` only by the container environment floor above.
- **Audio needs the known corpus** — the NCC matched-filter passes `easy` ~100% (grounded 15/15 vs the plain
  dot-product's 2/15) but `medium/hard` distortion needs a real ASR (Whisper), which is external.
- **The software-WebGL floor is flaky** — ~1 run in 4 trips the heavier `br.webgl_maxtexture_unallocatable`
  → `bot` even on a correct solve; a real GPU removes the flake.

## Ethics

Allow-list-scoped: talks **only** to Kitsune's own edge/arena. It reproduces documented open mechanisms on
owned infra and never contacts a third-party challenge.
