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

**Why this matters for power, not just FP-safety (measured):** the prior is the SAME generator a
`fingerprint-injector`-class attacker samples from, so a browserforge-sampled fingerprint is probable in our
prior *by construction* — same-source-blind. Scoring 800 browserforge fingerprints through the full
browser-layer ruleset gives 80% `human`, and `br.fingerprint_improbable` fires on only ~1% (browserforge's
own p1 tail). So an independent prior is needed for *detection power* against generator-based attacks, not
merely FP-hygiene (see docs/evasion-catalog.md "Prevalence / likelihood model").

**Scope limit (grounded via botright, 2026-06-19):** an independent real-traffic prior catches *improbable*
joints (generated or incoherent), but NOT **real-value reuse** — a tool like botright that drives a fresh
*self-scraped REAL* fingerprint per session presents joints that are genuinely probable in real traffic, so
no prevalence prior flags them. Prevalence's scope is therefore "improbable joints," not all evasion;
real-value-reuse fleets are the **coordination** layer's job (`fp_collision` on reuse, or the leak signals
if each session is a distinct real fp). The prevalence prior and the coordination harness are complementary,
not redundant.

### Turnkey second-source procedure (the builder is ready; only the data is missing)

The infrastructure to swap in a real-traffic prior is built and tested — `build_prior_from_dir`
(`harness/browserforge_corpus.py`, guarded by `tests/test_prior_builder.py`). When a Tier-3 capture exists,
one command rebuilds the prior from REAL ground truth and the detector uses it automatically (it loads
`data/prevalence_prior.json`):

Two builders, by capture shape (both write `../detector/src/kitsune_detector/data/prevalence_prior.json`,
which the detector loads automatically):

```sh
# PRIMARY real-traffic path — SESSION captures (what the collector+edge produce; a hosted-demo opt-in
# yields these, shape = corpus/sessions/*.json). Uses the detector's own features_from_session, so the
# prior matches what the scorer computes on live sessions:
cd harness && uv run python -m kitsune_harness.browserforge_corpus --build-prior-from-sessions <session-dir>

# ALT path — raw fingerprint dicts (the shape signals_from_fingerprint reads, e.g. a real-device matrix
# exported as fingerprint JSONs):
cd harness && uv run python -m kitsune_harness.browserforge_corpus --build-prior-from-dir <real-fp-dir>
```

Both produce a prior with the identical schema/factors (gpu/screen/cores) the model already loads, so it is a
drop-in replacement — verified (`tests/test_prior_builder.py`) against the real-engine fingerprints AND real
session captures. **The frontier is now data-only-blocked:** supply real-traffic captures (a hosted-demo
opt-in is the natural source — its sessions feed `--build-prior-from-sessions` directly) and the prevalence
model gains power immediately, no code change. Promoting it from corroborating to a higher weight then
becomes defensible — the single-source caveat above is exactly what a real prior removes.

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

**Corroborating-only is now enforced structurally, not just by weight (v0.65.0).** The rule carries its own
`prevalence` rule-category, which is deliberately excluded from `scoring.CONVICTING_CATEGORIES`. After the
convicting-signal gate (v0.64.0), category — not weight — decides whether a tell can unlock a `bot` label,
and a single-source likelihood signal must not. The latent case this closes, grounded: a real-but-rare
browser (an improbable-but-coherent joint) on a no-webcam desktop — `prevalence_low` (0.25) ⊕
`media_devices_empty` (0.55) = 0.66 — crossed the bot threshold with prevalence as the *sole* convicting
signal. It is now capped at `suspicious`: the browserforge prior corroborates a suspicion but cannot convict
a legitimate browser on rarity alone until the prior is corroborated against a second source.

## Cross-source check of the prior (v0.73.1) — the screen factor was a circular single-source FP

The standing rule is "never act on a single-source number." The prevalence rule is *calibrated on
browserforge*, so calibrating it against browserforge is circular — it cannot reveal a factor that is common
in reality but rare in the generator. Cross-checking the prior's `screen | platform` factor against the
**Intoli real-traffic source** (its `screen` and UA-derived `plat` fields are faithful — verified in
[calibration.md](calibration.md)) exposed exactly that:

| platform | real Intoli sessions in a browserforge near-zero (≤eps) **exact-`WxH`** screen bucket |
|---|---|
| Windows | **46.2%** |
| macOS | 13.2% |
| Linux | 13.5% |
| Android | 1.1% |

A prevalence model with an exact-resolution screen factor would assign deep-tail (`log eps`) probability to
13–46% of **real desktop users** — a latent false positive masked entirely by the circular browserforge
calibration. The browserforge *generated* distribution simply does not cover the long tail of real screen
sizes.

**Fix:** coarsen the screen feature to `(size-class, orientation)` — `mobile/small/laptop/desktop/large` ×
`port/land` (`prevalence.screen_bucket`, mirrored in the detector). The same cross-source check on the coarse
buckets drops the real-traffic miss to **~0%** (macOS/Android/Linux; Windows ~12.6%, mostly Intoli's own
incoherent UA×screen pairs), while keeping the joint signal — a randomizer pairing a `mobile-port` screen
with a Windows + nvidia-desktop GPU is still improbable. The exact-`WxH` FP landmine is removed.

`gpu`, `colour`, and `cores` are low-cardinality and stable, but Intoli does not carry them, so they remain
single-source (browserforge) until a Tier-3 source can corroborate them — which is why the rule stays
`experimental` / corroborating-only.

## Partial-vector abstention (v0.74.8) — "unknown never fires"

A second single-source FP, this one structural rather than per-factor. The committed threshold is the **1st
percentile of *full-vector* browserforge fingerprints** (`browserforge_corpus.build_prior_file`), so it is
only a meaningful cut-off for a fully-observed feature vector. But `is_improbable` scored *any* session with
a platform + GPU, summing `log(P + eps)` over every factor — and a **missing** factor contributes
`log(eps) ≈ -9.2` nats. A real session that simply didn't emit `screen` + `colour` therefore sank ~-18 below
the threshold and tripped on **absence**, not improbability. On the live corpus this was the dominant cause
of firing: 11 of 14 `prevalence_low` fires were partial-vector captures (`screen=None`/`colour=None`),
already hard-convicted by coherence/automation — the rule was claiming "improbable" on a data gap.

**Fix:** `is_improbable` now abstains unless `gpu`, `screen`, `colour`, and `cores` are **all** observed —
the registry's "unknown never fires" discipline. This is strictly monotonic (it can only make the rule fire
*less*), so it cannot raise the legitimate-browser flag rate; the browserforge calibration corpus is
full-vector, so its numbers are unchanged. On the corpus the fires dropped **14 → 3** — the survivors are
the genuine full-vector improbable joints (`iframe-spoof`, `stealth-patched`, `ios-ua-spoof`: a SwiftShader
GPU under a desktop platform with a real screen/colour/cores) — with **zero net detection loss** (the 11
dropped remain `bot`). Locked by `test_partial_vector_abstains_unknown_never_fires`.

## Remaining (future loop iterations)

1. Build the prior offline from the largest available real-distribution sample; ship it as a data table
   (rules-as-data stays the coupling) with the ruleset.
2. Emit a `prevalence_score` browser signal from the collector's collected fields; a detector rule fires
   `below_threshold` at a conservative tail (e.g. real p1 → ~1% FP) — **corroborating weight only**.
3. Gate it through `task calibrate` against *both* browserforge and the real-engine corpus; never let it
   raise the legitimate-browser flag rate.
4. Corroborate the prior against Tier-3 before raising its weight toward convicting.

## Colour factor dropped (v0.74.20) — the second circular single-source FP

The screen-factor lesson recurred on colour. `color_depth` is a **display** property — 24 (sRGB) or 30
(HDR/wide-gamut) — and is **OS-independent**: every real browser reports 24 regardless of platform (grounded
on the headful Chromium/Firefox/WebKit captures, all 24; `screen.colorDepth` does not depend on the OS). But
the browserforge prior generates `color_depth=32` for **Windows at 93%**, so the colour factor charged every
real Windows user (who reports 24) a ~−3 log penalty. Like the exact-`WxH` screen artifact, it is **invisible
to the browserforge calibration** — browserforge scores its own generated 32s against a 32-heavy prior, so no
penalty shows; the bias only bites real 24-reporting traffic, which the single source can't represent.

Conditioning a display property on the OS is unsound, and the colour prior is **uncorroborable** (Intoli
carries no `color_depth`, and the Tier-2 captures only confirm 24). Per the standing rule — never act on a
single-source number — the factor was **removed** rather than trusted. The prior and p1 threshold were
regenerated over `gpu`/`screen`/`cores` (threshold −10.75 → −9.04). A real-Windows-like fingerprint's margin
improved (−6.55 → −3.48 vs the threshold) and the corpus label distribution is unchanged (51 bot / 1
suspicious — zero detection loss; the rule is corroborating-only). `gpu` and `cores` remain single-source
pending a Tier-3 real-device matrix.

## Cores factor coarsened (v0.74.21) — the screen-factor fix, applied to the last single-source factor

After colour was dropped, `cores` (`hardware_concurrency`) was the last exact-value single-source factor —
and it had the **same eps-gap FP** the exact-`WxH` screen factor did. browserforge under-samples real cores
diversity and its prior carries gaps + garbage (a `384`-cores value), so a real but uncommon-or-high count
took a deep penalty invisible to the browserforge calibration: a real **128-core workstation** hit the eps
floor (−9.2) and was flagged improbable on **cores alone** (below the −9.04 threshold), and a common
**6-core** CPU took ~−3.7.

**Fix:** coarsen to size-class buckets — `<=2 / 3-4 / 5-8 / 9-16 / 17+` (`prevalence._cores_bucket`, mirrored
in the harness `cores_bucket`), so every plausible real count maps to a populated bin and the eps-gap is
gone. After the fix a real Windows + 128-core workstation scores −4.91 (was effectively −9.2 on cores), a
6/8-core −3.32 — both well above the regenerated threshold (−9.04 → −7.73). Corpus label distribution
unchanged (51 bot / 1 suspicious — zero detection loss; the rule is corroborating-only).

**Prevalence factor status after this arc:** `gpu` × `screen` × `cores`. `screen` and `cores` are
coarsened-robust (immune to browserforge's exact-value coverage gaps); `colour` is dropped (an OS-independent
display property browserforge generated wrong); `gpu` remains single-source pending a Tier-3 real-device
matrix (it cannot be coarsened — the engine family IS the signal — and Intoli does not carry it).

## GPU factor — investigated, irreducible single-source (the Tier-3 pending item)

With screen + cores coarsened and colour dropped, `gpu` (gpu_family given platform) is the last single-source
factor. It was examined for the same circular-FP class and is **mostly sound** — unlike cores it has no
eps-gaps for the major pairings: Windows {intel 55%, nvidia 24%, amd 17%}, Linux {intel 41%, amd 31%, nvidia
21%}, Android {mobile 98%} all cover real GPUs well. The one weakness is **macOS at 98% `apple`**, which
under-samples **Intel Macs** (Apple shipped Intel iGPUs on all, plus AMD/NVIDIA discrete GPUs on 15"/16"
MacBook Pro, iMac, Mac Pro): `amd|macOS` scores −6.35, so a real Intel-Mac-with-Radeon could be pushed to
improbable when combined with another factor.

This is **not safely fixable in-sandbox**, and the discipline says leave it:
- It cannot be **coarsened** — the GPU family *is* the discriminator (apple-on-Windows, swiftshader-on-desktop
  are the catches); collapsing families destroys the signal.
- It cannot be **dropped** — it is the prevalence model's primary signal.
- It cannot be **corroborated** — Intoli carries no GPU, and every in-sandbox real capture is SwiftShader
  (the container has no real GPU), so the true macOS GPU distribution is unobservable here.

So `gpu` stays single-source, with the documented Intel-Mac under-sampling, until a **Tier-3 real-device
matrix** (or hosted-demo opt-in) supplies a measured GPU/platform distribution. This concludes the
prevalence-hardening arc: of the four original factors, `screen` is cross-checked vs Intoli, `cores` is
coarsened-robust, `colour` is dropped, and `gpu` is the one genuinely-irreducible single-source factor —
which is itself the honest, precise answer to "what does the prevalence model still need from a second
source." (Deployed live at ruleset 0.74.21; IFRAME_SPOOF — swiftshader-on-desktop — still fires
`fingerprint_improbable` end-to-end, zero detection loss.)
