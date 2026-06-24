# Adversary-emulation roadmap

The plan for maturing Kitsune's **red team** from a *technique ladder* (does evasion X defeat tell Y) into
an **adversary-emulation platform** (emulate threat actor Z end-to-end — tooling + infrastructure +
behavior + scale + objective — and measure which layer catches it, at what scale, over what time).

Grounded in the 2026 research surveyed in [`research-radar.md`](research-radar.md). The premise of this
roadmap is the session-long finding: **per-session detection is saturated** (a perfectly coherent single
session has no contradiction to flag), so the live frontier — and the place a mature red team earns its
keep — is the **structural** layers: coordination, behaviour-over-time, **AI-agent cognition**, and
**application-layer (L7) DoS**. The arms race has moved past single-session fingerprinting; the red team
must move with it.

## Where we are (already mature, the foundation)

- **Technique ladder:** 22 real OSS anti-detect tools / 96 configs, white-box-grounded (confirm-EVADES-first),
  scored against the blue team with a reproducible matrix/scoreboard.
- **Fleet modes:** `fleet-cloned` / `fleet-replay` / `fleet-proxy` / `fleet-randfp-trace` + `KS_PROXY` egress.
- **Coordination scorer:** the TLS-vs-JS paradox + fp/JA4/trace collision + `shared_real_ip` — grounded on
  concurrent-container captures.
- **L7 DoS:** the edge `H2FrameScanner` detects rapid-reset (CVE-2023-44487), CONTINUATION flood
  (CVE-2024-27316), and control-frame floods (CVE-2019-9515/9512) **at the frame layer**, with a matching
  `h2-rapid-reset` evader and a fuzz target. Ahead of request-log-based defenders (CONTINUATION leaves no
  requests in access logs).
- **Discipline:** ground before convict, FP gates, single-author history, and the **ethics arena** —
  evaders target ONLY Kitsune's own detector + the `allowlist.py` endpoints (the destination is always our
  own edge; a proxy is just an egress path, never a third-party target).

The gap is the *adversary* level: named actors run as end-to-end campaigns, with the two non-saturated
frontiers below as the headline phases.

## Adversary archetypes

| Archetype | Tooling | Infrastructure | Behaviour | Scale |
|---|---|---|---|---|
| Scraper | curl-impersonate / go-tls / nodriver | rotating DC→residential | pagination crawl | medium fleet |
| Credential-stuffer | playwright-extra | residential rotating | login-retry bursts | large, lockstep |
| Ad-fraud | camoufox / commercial-class | residential, geo-targeted | view/click arcs | large, distributed |
| Scalper/sneaker | undetected / patchright | ISP sticky | checkout rush | small, high-coordination |
| Account farm | camoufox + profiles | one residential IP / profile | aged, slow | many identities |
| **AI agent** | Browser-Use / Operator / Computer-Use | residential | goal-directed, deliberative | small |
| **DDoS (L7)** | h2-rapid-reset / slowhttptest / httpflood fleet | botnet / fleet | flood / slow-hold | large, lockstep |

---

## Phase 1 — Adversary profiles (declarative campaigns)

Turn the env-driven evader modes into named, composable **adversary profiles** (YAML, mirroring the
rules-as-data registry) + a runner that composes evader mode + `KS_PROXY` + `FLEET_SIZE` into an end-to-end
campaign against the local detector, emitting a **per-adversary detection report** (which layer convicted,
at what fleet size). Reframes the lab from technique-tests to adversary emulation. Mostly composition of
what exists — the right first brick.

## Phase 2 — AI-agent emulation (headline frontier)

The first non-saturated in-sandbox vein. Research basis: **FP-Agent** (arXiv 2605.01247) — for AI agents,
*browser fingerprints have limited discriminative power; the discriminator is behavioural, strongest =
mouse-trajectory*. That is Kitsune's thesis exactly; FP-Agent detects all 7 agents where Cloudflare detects
1. Most agents (Browser-Use/Skyvern/Stagehand/Operator) drive via **CDP** → already caught by
`cdp_runtime_enabled` / `__playwright__binding__` / coalesced. The new groundable tells (radar G11–G15):

- **G11 `bh.click_without_trajectory`** (teleport click — the #1 signal): a mouse-origin click with no
  coalesced pointer stream. FP-safe-gated against keyboard/a11y users.
- **G12 `bh.action_cadence_deliberative`** (LLM think-time): inter-action gaps at LLM-inference latency
  (~3–8 s/step) vs human sub-second bursts. Novel — FP-Agent didn't measure it. The durable one.
- **G13 `bh.keystroke_interval_floor`** (1–5 ms inter-key); **G14 `bh.scroll_teleport`** (0 ms
  scrollIntoView — needs a scroll collector capture); **G15 `bh.input_via_paste`** (value-change, no keys).

**Red-team capability — the AI-agent evader (difficulty tiers):** enhance `evaders/agent` into a real
LLM-in-the-loop agent (accessibility-tree perception + ref→CDP actions + an LLM deciding), run against our
own detector:

```
AGENT_CDP        Tier 1 — Browser-Use-style; caught by existing tells (validates coverage)
AGENT_TELEPORT   CDP click, no synthesized trajectory  → grounds G11
AGENT_THINKTIME  real LLM deliberation pauses          → grounds G12
AGENT_PASTE      fill via paste / value-set            → grounds G13 + G15
AGENT_REALINPUT  Tier 3 terminus: vision + real OS input (XTEST), goal-directed —
                 real trusted input beats the input-mechanic tells, but the COGNITIVE
                 signature (think-time + teleport + no exploration) should survive
```

Collector addition required: **scroll events + inter-action timing** (Kitsune doesn't capture these today).
Ship the tells **corroborating + FP-gated** (an agent reaches suspicious; conviction stays on the
automation/wire layer for CDP tiers).

## Phase 3 — DDoS L7 expansion

Scoping is decisive: **volumetric L3/L4 (31 Tbps records) is an anycast/scrubbing infrastructure problem,
OUT of scope** for a per-session detector. L7 is Kitsune's domain and already leads. New rungs:

- **G16 `net.slow_http_attack`** — slow-HTTP (slowloris / slow-POST / slow-read): connection-table
  exhaustion by HOLDING connections, a different mechanism from frame-floods. Needs an edge slow/incomplete-
  connection detector; ground with a `slowhttptest`-style evader mode (`KS_MODE=slowloris|slowpost|slowread`)
  against the local edge. The clearest L7 gap.
- **G17 L7-flood-as-coordination** (Kitsune-unique) — an application HTTP flood from a botnet looks like N
  clients per connection; the DDoS signature is the AGGREGATE (lockstep timing + shared JA4/fp). That IS the
  coordination scorer. Wire it as the L7-flood attributor; ground with an `httpflood` FLEET tier. The
  bot↔DDoS convergence: **a fleet can't hide, scraping or flooding.**
- **QUIC/HTTP-3 DoS** — EXTERNAL/frontier (QUIC capture partly infra-blocked; ties to ADR-0005).

## Phase 4 — Infrastructure fidelity (needs a proxy buy)

Real proxy fleets (ethics-filtered, **consent-sourced only** — exclude the malware-flagged LunaProxy /
922proxy / AbcProxy) give each instance a distinct real egress IP, so campaigns can emulate both the caught
fleet (shared IP → `shared_real_ip`) and the evasion terminus (distinct IP per instance → drops to
`candidate`). Minimal buy: one static ISP/residential IP (~$1.5–3) grounds the caught case; rotating
residential (one IP/instance) practices the evasion. The consumer path is wired (`KS_PROXY` + the grounding
sweep) — drop in a real endpoint and capture.

## Phase 5 — Emulation-platform maturity

- **TTP matrix (MITRE-analog):** formalize the detection-catalog + evasion-catalog into a tactic/technique
  taxonomy + a coverage dashboard (which adversary TTPs are emulated, which detected, where the white space).
- **Orchestration:** spin up mixed-tooling/mixed-infra N-instance campaigns, scheduled, reproducible.
- **Automated arms-race regression:** every blue-team change re-runs the adversary suite and reports which
  adversaries newly evade or newly get caught.
- **Difficulty tiers** per archetype (commodity → APT-grade) so each actor has a maturity ladder.
- **Purple-team closure:** red campaigns feed `task grounding` directly — one loop.

---

## The strategic insight

Two adversary classes give Kitsune an **intrinsic** detection edge, because their signature is structural,
not incidental:

1. **AI agents** are slow and deliberate by their cognitive architecture (perceive → reason for seconds →
   act, teleporting to goals with no exploratory motion). To look human *behaviourally* they must inject
   human latency and motor noise — which destroys the speed/cost advantage that justifies automation AND
   lands on exactly the behavioural surface Kitsune scores. The fingerprint can be made perfect; the
   deliberation rhythm cannot, without the agent ceasing to be efficient.
2. **Fleets** (scraping or flooding) can't hide shared infrastructure — coordination is a cluster property,
   not an instance property, and the L7 DDoS and the coordinated-bot problem are the *same problem at two
   scales*.

Both are the behavioural/structural layers — Kitsune's home. The honest caveat (FP-Agent): it's an arms
race and the advantage is temporal. But for these two classes the *cost of human-like behaviour rises for
the attacker faster than for the defender* — which is the asymmetry to build on.

## Sequencing

1. **Phase 1** (adversary profiles + `FLEET_SIZE`/`KS_PROXY` runner) — composition of what exists.
2. **G11 teleport-click + G16 slow-HTTP** — the cleanest first bricks (both groundable now, no external dep).
3. **G12 think-time + G17 coordination-DDoS** — highest-leverage/novel.
4. **Phase 4** in parallel, gated on a proxy buy.
5. **Phase 5** once 1–3 prove out.

Don't invest more in per-session evasion (saturated). Invest in AI-agent + fleet/DDoS adversary emulation —
where the live frontier is, and where the asymmetry favours the detector.
