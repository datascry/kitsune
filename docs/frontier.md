# The Frontier — Kitsune's live edge

**What this is.** The single, current source of truth for where the red⇄blue arms race actually stands — what is
**saturated**, what is an **open in-sandbox vein**, and what is **blocked on external data**. It exists because the
other trackers can't be a current snapshot: [`research-radar.md`](research-radar.md) is an append-only rung log
(exhaustive, ~half a MB), and the phase roadmaps ([`red-team-roadmap.md`](red-team-roadmap.md),
[`adversary-emulation-roadmap.md`](adversary-emulation-roadmap.md)) are structured but drift. **This doc is kept
current**: when an axis closes or a frontier moves, edit it *here*. If a claim here disagrees with the radar, the
radar's newest dated entry wins — reconcile it up into this doc.

_Last reconciled: **2026-07-04**, detector ruleset **0.74.57**._

## The one-sentence state

Per-session **fingerprint** detection is saturated and per-session evasion needs a **coherent real browser** (built);
the live arms race has moved to **behaviour** (a wide, permanent human band), **coordination** (earned-closed
in-sandbox — the fully-clean fleet is external-bound), and **LLM agents** (caught by loop *structure*, not cognition
— the `track` gate). Every remaining frontier is either a **permanent human band** or **gated on external data we
have no in-sandbox source for**.

## Axis status board

| Axis | Status | Current edge | What would move it |
|---|---|---|---|
| per-session fingerprint | **saturated** (blue) · **evaded by a coherent browser** (red) | coherence convicts every spoof; a real headful browser is coherent by construction | nothing in-sandbox — it's a wall |
| session-intent / timing | **band** (permanent) | 2 FP-safe cadence floors (superhuman + machine-regular); a humanly-paced serial bot evades | real production think-time *distributions* |
| behavioural (mouse / input) | **band** | biomech power-law floor, 2-source corroborated (SapiMouse); a good humanizer lives in the band | production behavioural corpora |
| coordination / fleet | **earned-closed** | convicts on collision · non-Poisson schedule · per-session bot tell · shared proxy-egress (tunnel MSS / SOCKS stack-divergence) · IP-rep | a fully-clean diffuse fleet ⇒ **residential egress + real-hardware fps + prevalence** |
| LLM-agent | **earned-closed** | `track` gate convicts by the snapshot→reason→act loop's physics; reasoning honeypots defeated by alignment | — (structural tell shipped + live-validated) |
| active TCP-stack probe | **infra-bound** | unforgeable net fp, but veth never segments to MSS, edge has `NET_RAW` not `NET_ADMIN`, no middleboxes | a physical network + real middleboxes (ADR-0005) |
| mobile (Android / iOS) | **earned-closed** | no in-sandbox coherent Android fp; actual-behaviour GPU probes convict emulation/forks | real device hardware |

## The red frontier — the morphing-human headful fleet

**→ Documented as the research output in [`coherent-stack.md`](coherent-stack.md)** (the composed stack, its layers,
and the atomic morph-on-demand mechanism). The composed evader that keeps coming up. **Its components are built and
grounded.** A *fleet* of them, fully clean, is the terminus — external-bound.

**Config (the knobs — `evaders/stealth/run.mjs` unless noted):**
- `KS_DEVICE=<name>|random|list` — coherent per-OS **device sampler** (morphing devices drawn from a real device DB)
- `KS_ENGINE=webkit` — WebKit/Safari runtime (a coherent iOS slice; Blink self-defeats into `apple_ua_nonwebkit`)
- `KS_PROVISION` — the **provisioned floor** (audio / voices / webrtc) that lifts a bare headless past the empty-realm tells
- `KS_HUMANIZE` / `HUMAN_MOUSE` — **humanized input** (bézier mouse + paced, jittered timing)
- **`evaders/stealth/devices.json`** — the **curated device corpus** (17 coherent tuples w/ GPU + cores + memory, the fields Playwright's registry lacks); the morph data source
- **Headful** engine-coherent stack: `patchright-headful` / `camoufox-headful` (kills `cdp_runtime_enabled`, `no_chrome_object`, `permissions_anomaly`)
- **Fleet composition + capture:** `harness/tools/fleet_capture.sh` (`task coordination-fleet-capture`), `harness/tools/headful_capture.mjs`

**State.** A single coherent headful, morphing, humanized node scores **`human`** (per-session is saturated → it
evades). A **fleet** of them also evades per-session, and evades **coordination** *unless it leaks a binding* —
a shared build, a humanizer-descriptor cluster, a proxy-egress signature, or a bad IP reputation. The **fully-clean
diffuse fleet** (distinct builds · real-hardware fps · clean residential egress · Poisson-staggered) is the
**terminus**: catching it is external-data-bound, and shedding the last correlation *is* becoming N genuinely
independent real users — the economic wall. (Detail: `coordination-axis-closed` memory; radar `diffuse` /
`residential-proxy` / `socks-proxy` rows.)

## The external "buy list" — what unblocks each frontier

None of these are buildable in-sandbox; each is the real-world input a mature engagement or deployment supplies. This
is the honest boundary of the lab.

| External input | Unblocks |
|---|---|
| **Residential proxy egress** (paid pool) | the clean-fleet coordination frontier; the direct-residential humanizer fleet (native MSS, no tunnel tell) |
| **Real-hardware fingerprint corpora** (real GPUs / devices) | distinct-build fleet fingerprints; Tier-3 real-GPU validation. *Partly curated:* `evaders/stealth/devices.json` holds 17 coherent tuples (screen/DPR/GPU/cores/memory) from verified public specs — what's still external is **live-capture verification** of each tuple + real-silicon GPU-behaviour validation |
| **Prevalence / production traffic** | IP-reputation, rarity/prevalence scoring, think-time distributions, the corpus-wide trace-similarity floor |
| **Real mobile devices** | the coherent Android / iOS device slice |
| **A physical network** (`NET_ADMIN`, middleboxes) | active TCP-stack probing; QUIC/HTTP-3 paths (ADR-0005) |

## Closed — do not re-grind

Each earned-closed axis has a memory file naming its external-data-bound frontier; this doc is the roll-up. See:
`per-session-detection-saturated`, `coordination-axis-closed`, `session-intent-axis-closed`, `llm-agent-axis-closed`,
`mobile-axis-closed`, `active-probe-axis-infra-bound`, `arena-solve-coherence-closed`, `captcha-bench-ocr-characterized`,
`within-session-coherence-axis`.

## Keeping this doc current (the contract)

- **On an axis close** → patch its status-board row + add it to *Closed*, and write/refresh its memory file.
- **On a frontier move** (a new tell ships, an evasion is grounded) → update the row's *current edge*.
- **When an external input arrives** (e.g., a proxy buy) → move that frontier from the buy list into an active vein
  in the roadmaps, and update its row here.
- The radar stays the append-only detail log; this doc is the reconciled ≤1-screen state. **Reconcile on every close.**
