# prevalence model — scoring improbable-but-coherent fingerprints

The structural detection gap the red-team enumeration flagged: **Kitsune flags hard *contradictions*
(coherence rules) but cannot score "improbable-but-not-impossible" joint field combinations.** That is
exactly the niespodd / BrowserForge frontier — generators sample a *real-traffic joint distribution* to
produce fingerprints where every field is individually valid and mutually consistent, so no coherence
rule fires, yet the *combination* is one no real user has. A prevalence (likelihood) model is the
principled counter: score a fingerprint by how probable its field combination is under the real-traffic
prior, and flag the deep-tail improbable ones.

## Proof of concept (validated)

A prototype built a joint prior from 4000 real-distribution fingerprints (conditional frequency tables
for `gpu_family | platform`, `screen | platform`, `colorDepth | platform`, and `cores`), scored a log-
prevalence per fingerprint, and tested it against **scrambled** fingerprints — a real fingerprint with its
GPU + screen swapped in from a different one (each field still valid, the *joint* improbable; the case the
coherence rules miss):

| set | p10 | median | p90 |
|---|---|---|---|
| real (held-out) | −9.4 | **−5.6** | −3.7 |
| scrambled (improbable joint) | −19.0 | **−10.3** | −4.2 |

At a threshold of the real distribution's 5th percentile (−11.1): **46% of scrambled caught, 5% of real
flagged** — on just four fields. More fields (timezone, fonts, audio/codec support, UA-CH high-entropy)
and proper conditional modeling raise the separation. The class works.

## How it complements the existing rules

- **Coherence rules** catch *hard* contradictions (UA says Windows, TCP says Linux). Binary, high-precision.
- **Prevalence model** catches *soft* improbability (a coherent combo that's vanishingly rare). Continuous,
  corroborating. It is the only thing that scores a statistically-assembled fingerprint with no contradiction.

## The over-leverage caveat (why it stays corroborating, for now)

The prior here is browserforge — a single generated distribution, not measured real traffic. Per the
calibration discipline, a single-source prior cannot be a **convicting** signal: its deep tail may reflect
browserforge's own sampling gaps, not true rarity. So the prevalence model ships as a **corroborating**
signal (low weight, amplifies an existing suspicion) until its prior is corroborated against a second
source — Tier-3 real-traffic data (a real-device matrix or the hosted-demo opt-in). The mechanism (real vs
scrambled separation) is proven; the prior's *fidelity* is the open item.

## Foundation built (tested + reproducible)

The prototype is now a tested module — `harness/prevalence.py` (`features_from_fingerprint`, `build_prior`,
`log_prevalence`, pure + unit-tested) — and the prior is a committed, regenerable artifact:

```sh
uv run --with browserforge python -m kitsune_harness.browserforge_corpus --build-prior corpus/calibration/prevalence_prior.json --n 5000
```

Validated on three independent inputs: the synthetic improbable joint (Windows UA + Apple GPU + Mac
screen) scores `-23.5`, far below the real-engine Tier-2 captures (`-8.9` … `-16.0`) — the deep tail is
the improbable combination, exactly as intended.

## Integrated (v0.63.0) — live as a corroborating signal

Wired into the live detector: the collector now emits raw `screen_resolution` + `color_depth` (alongside
`webgl_renderer`, `hardware_concurrency`, `ua_platform`); `detector/prevalence.py` scores the session against
the committed prior (`detector/.../data/prevalence_prior.json`) and emits `browser.prevalence_low` below the
prior's p1 threshold; the rule `br.fingerprint_improbable` (experimental, weight 0.25) fires on it.
**`task calibrate` confirms the legitimate-browser human rate is unchanged at 77%** — the rule fires on ~1%
by design at corroborating weight, so it never convicts a clean browser alone. Stays experimental until the
prior is corroborated against Tier-3 real traffic.

## Remaining (future loop iterations)

1. Build the prior offline from the largest available real-distribution sample; ship it as a data table
   (rules-as-data stays the coupling) with the ruleset.
2. Emit a `prevalence_score` browser signal from the collector's collected fields; a detector rule fires
   `below_threshold` at a conservative tail (e.g. real p1 → ~1% FP) — **corroborating weight only**.
3. Gate it through `task calibrate` against *both* browserforge and the real-engine corpus; never let it
   raise the legitimate-browser flag rate.
4. Corroborate the prior against Tier-3 before raising its weight toward convicting.
