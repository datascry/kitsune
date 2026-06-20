# Red-team roadmap — Kitsune's evasion arms-race backlog

The work queue for the **red-team loop**. Kitsune is a detection ⇄ evasion lab; a sharper red-team is how
you find the blue-team's blind spots. **Ethics (hard, enforced in code):** every evader here targets ONLY
Kitsune's own detector + the approved endpoints in `harness/src/kitsune_harness/allowlist.py` — self-contained
lab research, never a third-party/production site, never weaken the allow-list.

## Where the red-team stands (researched 2026-06-20)

16 tools, 66 techniques, **63 caught / 3 evade** (`camoufox-headful`, `patchright-headful`, `zendriver` — all
escape via engine-level / CDP-patched spoofing with no headless tell). *(Corrected iter-9: `zendriver` is NOT an
evader — grounded live it is caught by `net.h2_header_order_vs_ua` (its CDP nav sends no Sec-CH-UA trio + a
non-Chromium regular-header order, while real Chrome does); the frozen capture was stale. Frontier is now **2
evade**: `camoufox-headful`, `patchright-headful`.)* The per-session **JS-patch layer is
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
   for a convicting one — **blue wins this round.** **Red-team escalation LANDED iter-3: `COALESCE_PROXY`** —
   wraps the real `getCoalescedEvents` in `new Proxy(realGCE, {apply})` (the fingerprint-injector technique). The
   Proxy inherits the native invariants + `[native code]` toString, so grounded live it defeats ALL THREE:
   `br.tostring_tampered` ✗, `br.native_invariant_violated` ✗, AND `bh.synthetic_no_coalesced` ✗ — the whole
   per-session artifact layer is beaten on the coalesced surface. **Exposed gap (Proxy-PROOF):** the fabricated
   `PointerEvent`s are constructed at read-time, so their `timeStamp`s come AFTER the parent pointermove event,
   whereas real coalesced events are intermediate samples gathered BEFORE dispatch (`timeStamp <= e.timeStamp`,
   monotonic). **Blue-team counter LANDED iter-4 (v0.74.37): `br.coalesced_untrusted`** (artifact,
   convicting). The data-coherence check the Proxy cannot fix: `getCoalescedEvents()` must return the UA's OWN
   native samples, which are ALWAYS `isTrusted` (hardware AND CDP-dispatched events are trusted); a
   constructor-built `new PointerEvent()` is `isTrusted=false`. So an untrusted event inside a length>1 coalesced
   batch is a hard fabrication artifact. Grounded live: COALESCE_PROXY + COALESCE_SPOOF fire it; HUMAN_MOUSE +
   plain STEALTH (real CDP events / length<=1) do NOT (FP-safe); 0 calibration FPs. The Proxy keeps the FUNCTION
   native but cannot forge trusted DATA — **blue wins the round.** **COALESCED LADDER TERMINUS:** the next red-team
   rung needs genuinely-trusted coalesced events, which only real hardware input produces (`new PointerEvent()` is
   always untrusted; no in-sandbox way to forge a trusted event) → **external/real-device frontier.** Behavioral
   vein mapped: synthesis defeats the biomech floor; the coalesced residual is now a 4-rung ladder ending at
   real-hardware-input. `coalesce-proxy.json` frozen as the lit-capture for `br.coalesced_untrusted`.
2. **[network] azuretls-client** (Go, `github.com/Noooste/azuretls-client`) — a current TLS/JA3 + HTTP/2 +
   **HTTP/3 / QUIC** template forger. Exercises the QUIC layer (detector rules retired on a broken capture) and a
   *current* template vs the deliberately-stale `go-tls`.
3. **[network] JA4 profile rotation** — an evader that rotates between several realistic JA4 fingerprints over a
   session (the "too-random vs too-static" frontier JA4 normalization targets).
4. **[fingerprint] real-value-reuse injection** (botright / apify fingerprint-injector class) — Proxy-over-native
   injection of real-sampled `(gpu, screen, cores, …)` joints; attacks the artifact + prevalence layers head-on
   (the white-boxed limit of per-session prevalence).
5. **[environment] stock-Chrome `--headless=new`** — ❌ **REFUTED iter-8 (grounded live).** The hypothesis was
   that a stock Chrome binary's new-headless drops the HeadlessChrome UA token → the CDP-minimal class EVADES.
   Installed real stock Chrome 149: `--headless=new`/`--headless=old`/`--headless` ALL report
   `HeadlessChrome/149.0.0.0` (token removal never shipped through 149); nodriver+stock-Chrome-new-headless →
   **bot** via `br.headless_ua`. So `br.headless_ua` HOLDS — no EVADES class. See "Grounded corrections" below.

### Vein A.5 — DONE iter-5: coherent UA-CH (`UACH_COHERENT`)
Grounded the frontier (2026-06-20): `MAX_STEALTH`-headless is NOT close to EVADES — its browser layer has 0
signals (the patchright **collector self-defeat** → `net.no_js_execution`), so its "clean" browser layer is
illusory. The real per-session UA tell is the naive UA-string spoof forgetting the network/UA-CH layers. Built
`UACH_COHERENT`: a CDP `Network.setUserAgentOverride` with full `userAgentMetadata` sets the UA string + Sec-CH-UA
headers + `getHighEntropyValues` to ONE coherent Linux-Chrome identity. Grounded live — defeats **all three** UA
tells at once (`net.ch_ua_version_vs_ua` ✗, `br.ch_he_headless` ✗, `br.headless_ua` ✗), collector still runs.
**This is frontier (b), not a blue-team gap:** a coherent UA-CH is legitimate (a real Chrome's is identical), so
the detector correctly cannot FP-safely fire on it — the residual catch is the **automation floor**
(`br.cdp_runtime_enabled`, `br.permissions_anomaly`, `br.no_chrome_object`, `br.webdriver_getter_tampered`), which
still convicts. Capture frozen as `uach-coherent.json`. **Opens the STACK:** UACH_COHERENT (UA layer) +
patchright (CDP layer, kills `cdp_runtime_enabled`) + headful (kills `no_chrome_object`/`permissions_anomaly`) +
behavioral synthesis = the full cross-layer coherent identity → next, Vein B.

### Vein B — STACK tools across layers (the cross-layer-coherence attack)
**GROUNDED iter-6 (2026-06-20) — the cross-layer-coherent stack already exists and EVADES the entire convicting
layer.** `patchright-headful` IS the stack capstone (patchright = CDP stealth, kills `cdp_runtime_enabled` +
`webdriver_getter_tampered`; headful = real display, kills `no_chrome_object` + `permissions_anomaly`; the
headful Chromium UA is already coherent so the UA-CH tells stay quiet — `UACH_COHERENT` would be redundant on it).
Scored through the live 0.74.37 detector: **`suspicious` 0.926, ZERO convicting tells.** Its residual is 100%
**corroborating** and 100% **external-hardware-gated**: `bh.synthetic_no_coalesced` (needs real hardware mouse →
[[the coalesced ladder]] terminus), `br.webgl2_missing` (needs a real GPU), `br.voices_empty` (needs real OS TTS),
`br.media_devices_empty` (needs real media devices). Faking any of the environment ones trips the tamper check
(`getVoices`/`enumerateDevices` are in the native-tamper list; spoofed WebGL2 → `native_invariant`), and having
them for real needs hardware — so the residual is **irreducible in-sandbox.**

**⇒ PER-SESSION RED-TEAM EVASION IS SATURATED in-sandbox.** The cross-layer-coherent identity defeats every
*convicting* tell; the detector's only remaining hold is environment **corroboration** that is external-hardware-
gated (symmetric with the blue-team's external-data frontier — neither side can advance per-session without real
hardware). This validates the core thesis from the red side: coherence across layers is achievable, so the durable
detector signal is **NOT per-session** but **coordination (bots-at-scale)** + a **real-traffic prevalence prior**.
**PIVOT (matches the standing loop clause):** future iterations go to the cross-layer/external frontiers —
(1) a real-hardware/real-device capture to test the environment residual + ground the coalesced/voice/webgl
coherence checks; (2) the live proxy/coordination harness (`task coordination-live` is wired) with real residential
egress for the IP-reputation half. Both are external-data-gated; the consumption infra is built and waiting.

*(Original backlog, now subsumed by the capstone above: Camoufox/patchright + current-template + behavioral +
proxy — the network + behavioral layers add nothing the capstone doesn't already show, and the proxy/IP half is
the external-gated coordination frontier.)*

**Coordination capstone — GROUNDED LIVE iter-7 (2026-06-20).** After per-session saturation, demonstrated the
durable answer end-to-end with `kitsune_harness.live_coordination` against the running detector's real session
store (32 accumulated red-team sessions): the live consumer graded my DIVERSE evader modes (divergent
fingerprints) as `candidate` — correctly NOT convicting (a real diverse cohort produces the same shape, FP-safe
boundary). Then launched 3 **identical** STEALTH clones (deterministic SwiftShader → one fp_hash `bf779223` across
3 distinct container IPs): the Chromium JA4 cluster FLIPPED `candidate → fleet` (score 1.0, `cloned_fingerprint`
set) via the `fp_collision` convicting signal, while the camoufox cluster (per-launch-randomized fp) stayed
`candidate`. So the live coordination harness convicts a cloned fleet and spares a diverse cohort — exactly the
thesis: **per-session is defeatable, but bots-at-scale leak a shared signature below the spoofing layer.** The ONE
remaining gap is convicting a *diverse/randomized* fleet (no fp/trace collision) — which is genuinely ambiguous
with a real cohort and needs **IP-reputation (residential vs datacenter), the external-data half.** RED-TEAM LOOP
CONVERGED in-sandbox: per-session saturated, coordination's in-sandbox half (clone tells) grounded live, the
convicting frontiers (IP-rep, real-traffic prevalence, real-hardware environment) all external-data-gated.

### Vein C — MODIFY a tool (white-box → enhance the anti-detect feature)
1. **Push the 2 EVADERS** (`camoufox-headful` / `patchright-headful` — `zendriver` REFUTED iter-9, it's caught by
   `net.h2_header_order_vs_ua`). White-box exactly *why* they escape, and whether the residual (capability tells,
   coordination) can be closed too — i.e. make a fully-clean evader, then see what (if anything) the blue-team can
   still FP-safely do. (Both remaining evaders are headful + external-hardware-gated per the iter-6 stack capstone.)
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

## Grounded corrections (live grounding refutes a documented assumption)
- **iter-8 (2026-06-20): the `--headless=new` EVADES frontier is REFUTED.** The catalog assumed stock Chrome's
  new-headless is token-less, so the CDP-minimal class (nodriver/pydoll/selenium-driverless/undetected) would
  EVADE. Installed real **stock Google Chrome 149** and read the UA via CDP `/json/version`: `--headless=new`,
  `--headless=old`, and bare `--headless` ALL report `HeadlessChrome/149.0.0.0`. nodriver+stock-Chrome-new-headless
  scored **bot** via `br.headless_ua`. So `br.headless_ua` is **robust, not fragile** — no EVADES class opens; the
  token removal never shipped through Chrome 149. Lesson: an ungrounded catalog assumption was FALSE — the loop's
  "ground every claim live" discipline is load-bearing.
- **iter-9 (2026-06-20): the `zendriver` EVADES claim is REFUTED.** The catalog marked zendriver `suspicious`/EVADES
  from a stale frozen capture. Grounded live (2/2 runs): zendriver scores **bot**, convicted by
  `net.h2_header_order_vs_ua` — its CDP-driven Chrome navigation emits NO Sec-CH-UA trio (`ch_ua_browser=None`) and a
  non-Chromium regular-header order, whereas real Chrome (chrome-stable/firefox/msedge, FP-clean for this rule) sends
  the trio. zendriver hides the headless UA token (unlike nodriver) but leaks at the network/Client-Hints layer.
  Re-captured `zendriver.json`; EVADES frontier 3→2. FP-safe (real browsers don't trip it).
