# Kitsune — a bot detection ⇄ evasion lab

> **TL;DR** — Both sides of the bot-vs-human arms race in one repo: a cross-layer fingerprint +
> behavioral **detector** (blue) and a fleet of real anti-detect **evaders** (red), scored against each
> other. The thesis: **catch the contradiction across layers, not the signal.** [Try it live →](https://kitsune.id)
>
> **Your privacy:** the live site captures **nothing** — it scores your signals in memory to show *you* a
> verdict, then forgets them. Never written to disk, retained, sold, shared, or used to track. [Details →](docs/privacy.md)

[![ci](https://github.com/datascry/kitsune/actions/workflows/ci.yml/badge.svg)](https://github.com/datascry/kitsune/actions/workflows/ci.yml)
[![security](https://github.com/datascry/kitsune/actions/workflows/security.yml/badge.svg)](https://github.com/datascry/kitsune/actions/workflows/security.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![conventional commits](https://img.shields.io/badge/commits-conventional-fe5196.svg)](https://www.conventionalcommits.org)

<p align="center"><strong><a href="https://kitsune.id">Try the live test → kitsune.id</a></strong></p>

<p align="center">
  <a href="https://kitsune.id"><img src="docs/img/verdict.png" alt="Kitsune's live verdict page catching a headless automation: a BOT verdict at 100% bot-likelihood, with the per-layer bars and the coherent feature-prediction" width="760" /></a>
  <br /><sub>The live verdict, catching this capture's own headless browser — per-layer bars and the explainable tells.</sub>
</p>

The two sides run against each other to produce a reproducible, per-layer scoreboard, and the red team
keeps the blue team honest: no detection ships until a real evader has exercised it and the calibration
gate proves it doesn't flag real browsers. Named after the shapeshifting fox spirit.

## The thesis: catch the *contradiction*, not the signal

Modern anti-detect tools defeat single-signal detection — they patch `navigator.webdriver`, forge a
Chrome TLS fingerprint, randomize the canvas, spoof the timezone. So Kitsune doesn't grade signals in
isolation. It correlates everything a session emits — across the TLS handshake, the HTTP/2 preface, the
TCP/IP stack, the JS runtime, and behavior — and flags the **incoherence between layers** that a spoof
can't avoid:

- the TLS handshake says **Chrome on Windows**, but the TCP/IP stack says **Linux**;
- the page's `navigator` reports **8 cores**, but a **Web Worker** it spawns reports **12** — the spoof
  patched the main thread and forgot the second realm;
- every field is individually valid and mutually consistent, yet the **joint fingerprint is one no
  real user has** (the statistical-improbability frontier);
- one shared TLS identity fans out across **300 residential IPs** with per-instance-randomized JS — a
  coordinated fleet wearing distinct masks.

A real browser is coherent for free. A bot has to reproduce that coherence across *every* layer
simultaneously — and that is much harder than fooling any one of them.

## How it works

```
              one session_id — threaded through every hop

  evader ─▶ EDGE (Go) ─▶ COLLECTOR (TS) ─▶ DETECTOR (Python) ─▶ Verdict
             │              │                  │
       network.*       browser.* +       coherence engine (rules-as-data)
       TLS·JA4·HTTP-2   behavioral.*     → noisy-or ⊕ incoherence ⊕ gate
       QUIC·TCP/IP·DoS  canvas·WebGL              │
                        audio·realm·biomech       ▼
                        STORE ─▶ HARNESS ─▶ per-layer SCOREBOARD
```

The **edge** (Go) fingerprints the network layers a UA-spoofer can't reach — it terminates TLS and reads
the raw ClientHello for **JA3/JA4** (GREASE-filtered, post-quantum-aware), the **JA4+ suite** (JA4H for
HTTP/2, JA4T for TCP), the **HTTP/2** SETTINGS + frame-order (Akamai) fingerprint, **QUIC/HTTP-3** (RFC 9001
ClientHello decrypt), the **TCP/IP-OS** stack (p0f-style SYN sniff) and HTTP/2 **DoS** attribution — then
mints a `session_id` and forwards `network.*` signals. The **collector** runs in the
browser and emits `browser.*` + `behavioral.*` signals under the same session. The **detector** groups
them into a session, runs a generic engine over the rules-as-data registry, and emits an explainable
verdict where every point of bot-likelihood traces back to its evidence. Components are polyglot and
**never import each other** — the JSON-Schema [`contracts/`](contracts) are the only coupling.

## What it detects

<!-- GENERATED:readme-stats:start -->
**184 live rules** (129 active · 55 experimental; 6 retired, ruleset `0.74.57`) — each a small predicate over the correlated session. **137 can convict** (coherence/automation/artifact); the rest only corroborate. Grouped by detection class:

| Class | Rules | Convicts? | What it catches |
|---|---:|:--:|---|
| **coherence** | 85 | ✦ | cross-vector contradictions (TLS↔TCP↔UA↔JS↔h2↔QUIC) — the thesis core |
| **automation** | 36 | ✦ | the framework surface: `webdriver`, CDP runtime, Electron, isolated-world leaks |
| **artifact** | 16 | ✦ | anti-detect *implementation* flaws: tampered natives, spoof placeholders |
| **environment** | 27 | — | stripped/headless capability gaps (corroborating only — see precision) |
| **behavioral** | 14 | — | mouse/keystroke biomechanics — path straightness, velocity CV, entropy floors |
| **reputation** | 5 | — | datacenter ASN / known proxy exit / WebRTC-leaked origin |
| **prevalence** | 1 | — | statistically-improbable-but-coherent fingerprints |

_✦ convicting · — corroborating-only. The conviction gate means corroborating signals can never reach `bot` alone._

<!-- GENERATED:readme-stats:end -->

A distinctive capability is the **realm-coherence family**: anti-detect tools spoof the main JS realm but
systematically forget *other* realms. Kitsune compares `navigator`, timezone, languages, the WebGL
renderer, and the canvas pixel-hash across the main thread vs a **Web Worker** and an **iframe** — and a
guard (`worker_constructor_tampered`) closes the one escalation, since wrapping `Worker` to spoof the
worker scope makes the constructor non-native. See the [detection catalog](docs/detection-catalog.md).

## Precision is a first-class concern

Catching bots is easy; not flagging real people is the hard part. Scoring is a transparent **noisy-or**
with cross-layer amplification, behind a **conviction gate**: a `bot` verdict requires at least one
*convicting* signal (coherence / automation / artifact). The *corroborating* classes — environment,
behavioral, reputation, prevalence — raise suspicion but can never convict alone, so a stripped-but-real
browser (no webcam, no plugins) can't noisy-or its way to `bot`.

The [**calibration harness**](docs/calibration.md) is the trusted-but-verified false-positive gate: it
scores thousands of real browser fingerprints and measures, per rule, how often each fires on a
legitimate browser. It is deliberately multi-source — a generated distribution (browserforge) *plus* real
Chromium/Firefox/WebKit captures — because you must never down-weight a rule on a single source's number.
Every new rule is grounded against a real browser *before* it ships, and a regression test fails the build
if any rule starts firing on a real engine.

## How a detection gets built — the grounding loop

No rule ships on a hunch. Every detection runs the same red⇄blue loop, and the *order* is the discipline:

1. **Red confirms the evasion first.** A purpose-built evader mode has to actually *defeat* the current
   detector — if nothing evades, there's nothing to detect.
2. **Blue builds the detection** as data in the registry, and it must **CONVICT that evader**.
3. **The FP gate has the last word.** The rule is scored against thousands of real fingerprints and ships
   only if it stays clean — and a regression test fails the build if it ever fires on a real engine.

The gate is deliberately **multi-source**, because you must never trust a single dataset's number: a
generated distribution (**browserforge**) *plus* real Chromium/Firefox/WebKit captures, cross-checked against
**Intoli** user-agents and **fpgen**, with the behavioral floors grounded on real human motion —
**SapiMouse** (mouse), **BrainRun** (161k mobile swipes) and **Aalto** (keystroke). Mobile and touch get
their *own* grounded floors, not desktop heuristics reused.

What feeds the loop is [`docs/research-radar.md`](docs/research-radar.md): an intake queue of external
papers, tools and releases, each mapped to a Kitsune seam and tagged **groundable-in-sandbox** vs
**external-data-bound**. Groundable leads become rules; external-data-bound ones (real residential-proxy
egress, real-device GPUs, large-scale prevalence) are queued with the exact data they'd need — never shipped
on a guess. See [grounding.md](docs/grounding.md) and [calibration.md](docs/calibration.md).

## The red team

The evader fleet is a ladder of *real* open-source anti-detect tools, run only against Kitsune's own
detector — scripted TLS-mimicry (`curl-impersonate`, `primp`, `go-tls`/uTLS), Playwright-stealth and
CDP-leak patches (`patchright`, `rebrowser`), CDP-native drivers (`nodriver`, `zendriver`, `pydoll`),
isolated-world Selenium (`undetected`, `selenium-driverless`), the engine-level frontier (`Camoufox`),
farbling (`Brave`), HTTP/2 DoS, and an LLM agent — plus a multi-mode stealth harness that demonstrates
each realm-coherence evasion.

<!-- GENERATED:readme-redteam:start -->
**93 of 103 evaders score `bot`** ([full matrix](docs/matrix.md), ruleset `0.74.57`). The remaining 10 reach only `suspicious` — the conviction-gate frontier (top evaders, below): they defeat every *convicting* rule and trip only corroborating tells, which can never reach `bot` alone.

Each evader is a real anti-detect tool/technique; **Caught by** is the top convicting tell:

| Evader | Caught by (top convicting tell) | Incoh. | Score | Label |
|---|---|---|---|---|
| `curl-impersonate` | `net.no_js_execution` | 0.60 | 0.90 | bot |
| `nodriver` | `br.headless_ua` | 0.00 | 0.92 | bot |
| `full-stealth` | `br.cdp_runtime_enabled` | 0.60 | 1.00 | bot |
| `camoufox` | `net.tcp_os_vs_ua` | 0.84 | 1.00 | bot |
| `ios-ua-spoof` | `br.ch_he_headless` | 0.98 | 1.00 | bot |

**Top evaders — the conviction-gate frontier (10).** These real tools defeat every *convicting* (coherence/automation/artifact) rule and trip only corroborating tells, so the gate holds them at `suspicious` — never `bot` on corroboration alone:

| Evader | Trips (corroborating only) | Score | Label |
|---|---|---|---|
| `zendriver-uach` | `bh.input_entropy_floor`, `br.hover_none_desktop` | 0.50 | suspicious |
| `webrtc-leak` | `net.webrtc_ip_vs_observed`, `br.media_devices_empty` | 0.49 | suspicious |
| `camoufox-hardened` | `br.webrtc_unavailable`, `bh.power_law_violation` | 0.49 | suspicious |
| `camoufox-linux-coherent` | `br.webrtc_unavailable`, `bh.power_law_violation` | 0.49 | suspicious |
| `camoufox-linux` | `br.webrtc_unavailable`, `bh.power_law_violation` | 0.49 | suspicious |
| `zendriver-uach-behave` | `br.hover_none_desktop`, `br.webrtc_unavailable` | 0.49 | suspicious |
| `camoufox-hardened-behave` | `br.webrtc_unavailable`, `br.media_devices_empty` | 0.49 | suspicious |
| `camoufox-socks-webrtc` | `br.webrtc_unavailable`, `br.media_devices_empty` | 0.49 | suspicious |
| `camoufox-headful` | `br.webrtc_unavailable`, `br.media_devices_empty` | 0.47 | suspicious |
| `patchright-headful` | `br.media_devices_empty`, `br.voices_empty` | 0.46 | suspicious |

<!-- GENERATED:readme-redteam:end -->

## Coordinated fleets — the red⇄blue coordination loop

Per-session detection saturates, so the durable arms race moves up a level: **many sessions acting as one
adversary**. Kitsune runs both sides of it.

**Red — [Skulk](fleet/README.md), the fleet adversary-emulation kit** (`fleet/`, authorization-scoped in
`scope.py`). Skulk emits *coordination-shaped* sessions to a detector's `/ingest` — it is a modeling tool,
**not** a flood/DoS/credential generator. Strategies range from naive to evasive: `cloned` (one fingerprint
fleet-wide), `trace-replay` (one canned pointer trace), `randomizer`/`fuzzy` (per-node jitter),
`fuzzy-rotate` / `ticket-reuse` / `ipv6-rotate` (within-session rotation), `staggered` (spread arrivals),
and `diffuse-campaign` (distinct everything, tuned just above the template floor). The
[**fleet manager**](harness/src/kitsune_harness/fleet_manager.py) drives *real* evader containers as named
evasions, plans, archetypes and campaigns — per-node `KS_NODE_SEED`, per-node proxy, `stagger_seconds` — and
shards an [**objective**](harness/src/kitsune_harness/objectives.py) into distinct per-worker behavioral
tasks (synthetic lab targets only — `example.test`, the harness allow-list; never a real site).

**Blue — two coordination scorers** over the session corpus:
- **Per-binding** (`coordination.py` `score_corpus`) clusters by JA4 prefix and convicts on cross-instance
  *collisions* — fingerprint/trace collision, shared WebRTC origin, TLS ticket reuse — behind a gate that
  requires **≥2 distinct /64 origins** before anything reads as a fleet (a real cohort on one office build
  must not look like a botnet).
- **Axis A** (`score_campaigns`) is the *aggregate* view: community detection over a multi-dimensional
  similarity graph (JA4 prefix, behavioral descriptor, lockstep arrival, origin reputation, prevalence tail).
  It catches the *residual correlation* a diffuse fleet leaves after it defeats every pairwise binding.

The two compose into an **escalation ladder** (`task adversary-showcase`): a cloned fleet falls to the
per-binding scorer; a build-rotating, behavior-jittered fleet evades that yet axis A catches the aggregate;
and only a **fully diversified** fleet — distinct build/fingerprint/trace, spread descriptors, spread
arrivals — evades both, at which point it is, by construction, *N independent real users* (the economic bind;
conviction there is external-data-bound). The **diversification levers** that get a red fleet there map one
to one onto the axis-A dimensions they each defeat. The full loop — strategies, manager, objectives, both
scorers, levers and the showcase — is documented in [**docs/fleet.md**](docs/fleet.md).

## The arena — a solved challenge ≠ a human

The [**arena**](docs/arena.md) (`arena/`, Go) is a public, self-hosted reproduction of the documented **open**
web-challenge families — **proof-of-work**, **CAPTCHA** (text / math / honeypot), **slider**, **rotate**,
**emoji / Quick-Draw / procedural-shape image-select**, a **reCAPTCHA-style checkbox**, a **Turnstile-style
managed ladder**, **PACT / Privacy-Pass** attestation, a **rate-limit** and a **virtual waiting-room queue** —
plus one Kitsune-original gate, **`track`**, a **real-time visual-tracking** challenge — each (where it has a
difficulty axis) at **easy / medium / hard**. A visitor brings any client to a gate and sees **two verdicts at
once**: did you *solve* the challenge, and does your client *cohere* across layers, read independently over the edge?

That juxtaposition is the whole point: **a solved challenge is a cost or Turing test, not a bot/human
discriminator.** Every gate here falls to the right scripted solver (`evaders/arena-solver`,
`arena-solver-ocr`) — and the detector still convicts the no-JS client on the network layer regardless.
**Coherence + attestation is the durable signal; the puzzle is not.** The one refinement is **`track`**: against
an **LLM browser agent** (a real, coherent, humanly-paced browser that evades every fingerprint and behavioural
tell), a real-time tracking task *is* a discriminator — its snapshot→reason(seconds)→act loop clicks a stale
position while a human servos to the live one, convicting it (`bh.arena_stale_snapshot`), validated live against a
claude-driven agent. Like everything else in the lab, the gates and solvers are vendor-neutral and talk only to
Kitsune's own infrastructure — never a third-party widget.

## What's novel — detections unique to Kitsune

The field's pages (CreepJS, Sannysoft, pixelscan, …) are single-layer, client-side point-checks. Kitsune's
edge is **incoherence across layers _and_ time, scored server-side**. The three most differentiating
mechanisms:

- **Within-session temporal incoherence** — flags an *invariant* field that rotates under one session:
  TLS (`net.ja4_unstable_within_session`), origin (`net.ip_rotation_within_session`), browser fingerprint
  (`br.fingerprint_unstable_within_session`), trajectory replay (`bh.trace_replay_within_session`). No public
  fingerprinting page tracks rotation across a session — it catches the re-randomizing anti-detect browser
  that reuses one cookie.
- **Coalesced-pointer-event structural tell** (`bh.synthetic_no_coalesced` / `br.coalesced_untrusted`) —
  catches CDP-injected input via `getCoalescedEvents()` length + `isTrusted`, *independent of trajectory
  shape*, so a GAN/diffusion mouse-path humanizer that beats every shape metric is still caught.
- **Worker-realm coherence ladder** (`br.worker_source_rewritten`, `br.worker_constructor_tampered`) —
  convicts worker-scope spoof injection by the blob-URL + constructor-identity round-trip, robust to the
  entire Proxy-over-native disguise ladder.
- **Cryptographic agent identity** (`net.web_bot_auth_invalid`) — verifies an RFC 9421 Web Bot Auth
  signature at the edge: a *valid* signer is allow-listed as a `verified` agent (sound only under
  signing-key secrecy), while a forged/replayed signature for a known key convicts. FP-safe by
  construction — a real browser sends no such headers.

The rest — four-wire-layer ⇄ JS fusion and 2/3-power-law biomechanics
([`docs/detection-landscape.md`](docs/detection-landscape.md)), plus cloud-behind-residential-proxy
([`docs/coordination-proxy.md`](docs/coordination-proxy.md)) — round out the gap analysis. Every one was
grounded the same way: confirm the evasion **EVADES** first (a purpose-built red-team mode), then ship the
detection only once it **CONVICTS** that evader and stays clean on the calibration FP gate.

## The structural frontiers

Per-session detection saturates; the durable signals are structural, and Kitsune has working models for
both the red team flagged:

- **[Prevalence / likelihood](docs/prevalence-model.md)** — scores how improbable a fingerprint's *joint*
  field combination is under a real-traffic prior. It is the one class that scores a generator-assembled
  fingerprint with no contradiction. Corroborating-only (its prior is single-source) until a second source
  validates it.
- **[Coordination / fleet detection](docs/fleet.md)** — clusters sessions by JA4 and grades fleets via the
  TLS-identical-but-JS-divergent paradox + fingerprint-collision + per-launch TLS randomization, plus the
  aggregate **axis-A campaign detector** for the residual correlation a diffuse fleet leaves — behind its own
  conviction gate (a real cohort sharing one browser build must not read as a botnet). The matching red side
  (Skulk + the fleet manager) and the full red⇄blue ladder are in [docs/fleet.md](docs/fleet.md).

## Components

| Component | Lang | What it is | Tests |
|---|---|---|---|
| [`contracts/`](contracts) | JSON Schema | The stable wire contracts + the rules-as-data registry — the only coupling | CI-validated |
| [`detector/`](detector) | Python | Session correlation, the coherence engine, the conviction-gated scorer, the prevalence model, keyless (DB-IP Lite) City+ASN geo / IP-reputation enrichment | ~100% |
| [`harness/`](harness) | Python | The scoreboard, the calibration precision gate, the coordination scorer, biomech calibration (ethics enforced in code) | ~97% |
| [`edge/`](edge) | Go | TLS→JA3/JA4 (+ GREASE, post-quantum), HTTP/2 (Akamai + JA4H + unknown-engine), TCP/IP-OS, QUIC/HTTP-3 (RFC 9001 decrypt), HTTP/2 DoS attribution | ~97% (fp) |
| [`collector/`](collector) | TypeScript | In-browser fingerprint + behavioral collection + a CreepJS-style live self-test page running the full probe suite | 100% (logic) |
| [`evaders/`](evaders) | Py/TS/Go | The red-team ladder of real anti-detect tools (above) | all `bot` |
| [`fleet/`](fleet) | Python | **Skulk** — the fleet adversary-emulation kit (coordination-shaped sessions; authorization-scoped in code) | ~97% |
| [`arena/`](arena) | Go | Public self-hosted challenge gates (PoW · CAPTCHA · slider · image-select · PACT), each easy/medium/hard | ~95% |

## Quickstart

```sh
# the Python spine (detector + harness): run the scoreboard demo
cd harness && uv sync && uv run python -m kitsune_harness

# everything, locally (headers · detector · harness · edge · collector)
task ci

# measure the false-positive rate against real browser fingerprints
task calibrate
```

Go and Node aren't required locally — use Docker (`golang:1.26-alpine`, `node:22-alpine`) for those.

## Docs

- [**Architecture**](docs/architecture.md) — the design: the pipeline, the coherence engine, the
  conviction-gated scorer, the structural frontiers, and the calibration discipline.
- [**Findings**](docs/findings.md) — the arms-race narrative: each evasion, the layer that caught it, and
  why (the Camoufox frontier, the precision turn, the realm-coherence family, the HTTP/2 DoS family, …).
- [Calibration](docs/calibration.md) · [Prevalence model](docs/prevalence-model.md) · [Coordination & the fleet](docs/fleet.md) — the precision gate and the two structural frontiers.
- [**Fleet & coordination**](docs/fleet.md) — Skulk, the fleet manager, objectives, both coordination scorers, the diversification levers and the escalation showcase.
- [**Arena**](docs/arena.md) — the public challenge gates (PoW · CAPTCHA · slider · image-select · PACT) and the *solved-challenge ≠ human* thesis.
- [**Grounding loop**](docs/grounding.md) · [Research radar](docs/research-radar.md) — how every rule is grounded, and the external-research intake queue that feeds it.
- [**Privacy**](docs/privacy.md) — the public site captures **no** visitor data: signals are scored in memory and never written to disk, retained, sold, shared, or used to track.
- [Detection catalog](docs/detection-catalog.md) · [Evasion catalog](docs/evasion-catalog.md) — the blue/red work queues.
- [Coverage matrix](docs/matrix.md) — every detector rule × every evader.
- [Decision records](docs/adr) — MADR ADRs for the load-bearing decisions.
- [Contributing](CONTRIBUTING.md) · [Code of Conduct](CODE_OF_CONDUCT.md) · [Security](SECURITY.md) · [Changelog](CHANGELOG.md)

**Explore it live** (the same data, rendered + cross-linked at [kitsune.id](https://kitsune.id)):
[Detections](https://kitsune.id/detections) · [Evasions](https://kitsune.id/evasions) ·
[Matrix](https://kitsune.id/matrix) · [Arena](https://kitsune.id/arena) ·
[How it works](https://kitsune.id/how-it-works) · [Research](https://kitsune.id/research)

## Ethics

Evaders target **only** Kitsune's own detector and a fixed set of public endpoints built for bot/
fingerprint testing (sannysoft, CreepJS, BrowserLeaks, tls.peet.ws, the fingerprint.com demo,
incolumitas). Never a third-party or production site. The allow-list is **enforced in code**
([`harness/.../allowlist.py`](harness/src/kitsune_harness/allowlist.py)) — the self-contained arena *is*
the ethics design.

## License

[MIT](LICENSE).
