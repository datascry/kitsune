# Red-team roadmap — Kitsune's evasion arms-race backlog

The work queue for the **red-team loop**. Kitsune is a detection ⇄ evasion lab; a sharper red-team is how
you find the blue-team's blind spots. **Ethics (hard, enforced in code):** every evader here targets ONLY
Kitsune's own detector + the approved endpoints in `harness/src/kitsune_harness/allowlist.py` — self-contained
lab research, never a third-party/production site, never weaken the allow-list.

## Where the red-team stands (researched 2026-06-20)

16 tools, 66 techniques, **63 caught / 3 evade** (`camoufox-headful`, `patchright-headful`, `zendriver` — all
escape via engine-level / CDP-patched spoofing with no headless tell). The per-session **JS-patch layer is
saturated**: every single-tool Chromium evader hits the headless-environment floor, and every cross-layer or
realm-coherence spoof is caught. The detector's durable signals are the headless floor, cross-layer coherence
(TLS/H2 ≠ UA), realm coherence, and the behavioral / coordination / prevalence frontiers.

**What the red-team has NOT exploited — the open veins:**
- **Behavioral synthesis — the single least-explored frontier.** The fleet's only motion is basic bézier
  (`HUMAN_MOUSE`); it has never deployed a SOTA generator against the biomech floor (`bh.power_law_violation`,
  `bh.path_too_straight`, `bh.uniform_velocity`, `bh.input_entropy_floor`) — which is SapiMouse-corroborated, so
  this is a live, two-sided arms race, not a static target.
- **Cross-layer tool stacking — untapped.** Every evader is a single tool. None composes engine-spoof + current
  network template + behavioral synthesis + proxy egress into ONE coherent full-stack identity.
- **Current network templates incl. H3/QUIC.** `go-tls` is deliberately stale (uTLS 1.6.7, no PQ keyshare); the
  fleet has no *current* QUIC/H3 forger at all.

## Backlog (prioritized) — the loop draws ONE move per iteration

### Vein A — BUILD a missing evasion feature
1. **[behavioral] SOTA mouse/keystroke synthesis.** ⚠ **PARTLY CLOSED — grounded iter-1 (2026-06-20).** The
   biomech floor is ALREADY defeated by the fleet's existing bézier humanizer (`HUMAN_MOUSE`): run live, it trips
   NONE of `bh.power_law_violation` (β≈0.45 ≫ the 0.05 floor — the 2/3 power law), `bh.path_too_straight`,
   `bh.uniform_velocity`, `bh.input_entropy_floor`. So a SOTA generator (sigma-lognormal / DMTG) is NOT the open
   vein the external research implied — bézier already passes. The SOLE behavioral residual is
   **`bh.synthetic_no_coalesced`** (synthetic input → `getCoalescedEvents().length <= 1`; real hardware batches
   intermediate samples). ✅ **DEFEATED iter-1 by the new `COALESCE_SPOOF` stealth mode** — patches
   `getCoalescedEvents` to fabricate distinct interpolated intermediate samples (length > 1), and the tell goes
   quiet live. **Blue-team counter LANDED iter-2 (v0.74.36):** added `getCoalescedEvents` to the
   collector's native-tamper list (`demo.py` + `probes.ts`) → the plain-function COALESCE_SPOOF override is now
   caught by `br.tostring_tampered` (convicting automation). Grounded live: COALESCE_SPOOF fires it, HUMAN_MOUSE +
   plain STEALTH (native) do NOT (FP-safe); 0 new browserforge FPs. So the red-team traded a corroborating tell
   for a convicting one — **blue wins this round.** NEXT red-team escalation: a **Proxy-over-native** coalesce
   patch (`new Proxy(realGCE, …)` preserving the native toString) to defeat `br.tostring_tampered`, which then
   needs the deeper `br.native_invariant_violated` check (and if that's also beaten → a coalesced-COHERENCE check
   on the fabricated batch's timestamps/coords, or → coordination). The ladder is live.
2. **[network] azuretls-client** (Go, `github.com/Noooste/azuretls-client`) — a current TLS/JA3 + HTTP/2 +
   **HTTP/3 / QUIC** template forger. Exercises the QUIC layer (detector rules retired on a broken capture) and a
   *current* template vs the deliberately-stale `go-tls`.
3. **[network] JA4 profile rotation** — an evader that rotates between several realistic JA4 fingerprints over a
   session (the "too-random vs too-static" frontier JA4 normalization targets).
4. **[fingerprint] real-value-reuse injection** (botright / apify fingerprint-injector class) — Proxy-over-native
   injection of real-sampled `(gpu, screen, cores, …)` joints; attacks the artifact + prevalence layers head-on
   (the white-boxed limit of per-session prevalence).
5. **[environment] stock-Chrome `--headless=new`** — a real Chrome binary (NOT Playwright's bundled Chromium,
   which still reports HeadlessChrome) driving a CDP-minimal tool → drops the last headless UA token; the whole
   CDP-minimal class joins the EVADES frontier.

### Vein B — STACK tools across layers (the cross-layer-coherence attack)
1. **Full-stack coherent evader:** Camoufox (real Gecko engine) + a current network template (azuretls / primp) +
   SOTA behavioral + proxy egress → one identity coherent across TLS, H2/H3, JS, behavior, and IP. Measure it
   against the cross-layer-incoherence thesis and the EVADES frontier.
2. **patchright + current-template + human behavioral** — the Chromium analog of the above.

### Vein C — MODIFY a tool (white-box → enhance the anti-detect feature)
1. **Push the 3 EVADERS.** White-box exactly *why* `camoufox-headful` / `patchright-headful` / `zendriver`
   escape, and whether the residual (capability tells, coordination) can be closed too — i.e. make a fully-clean
   evader, then see what (if anything) the blue-team can still FP-safely do.
2. **Harden a stealth mode** to silence a remaining convicting tell (e.g. the `br.chrome_runtime_missing`
   patchright-headless residual) — white-box the gap, patch it, confirm the tell goes quiet without a new artifact.

## New tools to add to the fleet (cutting edge, researched)
`azuretls-client` (TLS+H2+H3 forger) · `ghost-cursor` + `PHC-mouse-movement-gen` + DMTG (behavioral) ·
CloakBrowser · playwright-extra (the ~20-patch baseline). Browser-patch (C++-level) tools beat JS-injection
tools, and Gecko engine diversity (Camoufox) evades Chrome-specific behavioral models — favor those.

## Arms-race discipline (every iteration)
Run the enhanced/stacked/modified evader **live against the detector** (docker, `kitsune_default` net); record
its verdict + which tells it now evades vs still trips. A new EVADES result is either **(a)** answerable by an
FP-safe blue-team detection → build it, version-bump the ruleset, mark the catalog gap; or **(b)** a genuine
external-gated frontier → document the precise residual tell in `docs/evasion-catalog.md`. Keep the
evasion-catalog the living ledger. Modify REAL tools; ground every claim live; never fabricate a capability.

## Sources (research 2026-06-20)
- Behavioral: DMTG diffusion mouse trajectories (arXiv:2410.18233); BeCAPTCHA-Mouse (BiDAlab); ghost-cursor
  (Fitts' law); PHC-mouse-movement-gen (sigma-lognormal).
- Network: `azuretls-client` (Noooste); JA4 normalization (FoxIO); HTTP/2 + H3 fingerprinting (Scrapfly).
- Landscape: anti-detect benchmarks 2026 (techinz/browsers-benchmark; ianlpaterson.com); Castle.io anti-detect
  framework evolution; "browser-patch beats JS-injection" + "Gecko engine diversity" (scrapewise/proxies.sx).
