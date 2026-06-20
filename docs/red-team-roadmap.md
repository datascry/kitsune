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

**Open axis (iters 15–16): WITHIN-SESSION coherence — the temporal axis the saturation analysis missed.** The
detector's `ingest.merge` keeps only the *latest* signal per kind, so it was **blind to mid-session rotation of
any session-invariant field**. A real client holds ONE identity for a session's lifetime; rotating it is the
naive evasion's tell. Two members built & grounded: `net.ja4_unstable_within_session` (TLS-engine rotation, JA4_b,
iter-15) and `net.ip_rotation_within_session` (rotating-proxy-pool, ≥3 distinct egress IPs, iter-16). Both are
**reputation-free coherence** (no external data) — iter-16 specifically carves an in-sandbox-detectable CONVICTING
signal out of what the catalog filed wholesale under the "external-gated IP frontier" (that gating is about IP
*reputation*, residential-vs-datacenter — NOT the rotation *count*). Remaining candidates in the class (lower
leverage / harder to ground in-sandbox): h2-fingerprint rotation, tcp_kernel (OS) rotation, raw-UA rotation (UA
not currently edge-emitted). Cross-session rotation (per-identity) stays the coordination/prevalence frontier.

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
   **KEYSTROKE axis closed — iter-18 (2026-06-20).** The mouse floor was the only behavioral synthesis grounded;
   `bh.keystroke_entropy_floor` had NO evader defeating it by synthesis — the naive path types at a FIXED 95ms
   (entropy ~0 → trips it) and HUMAN_MOUSE merely types <4 keys (keyEntropy returns 1, unjudged). Built the
   `KEYSTROKE_HUMAN` stealth mode (the keystroke analog of HUMAN_MOUSE): presses a phrase with per-key delays from
   a skewed lognormal-ish spread + rare think-pauses. Grounded live: `keystroke_entropy = 0.935` (≫ 0.15 floor) →
   `bh.keystroke_entropy_floor` SILENT, while the naive fixed-delay control still trips it. So the keystroke floor
   is now a grounded two-sided arms race like the mouse floor: it catches fixed-delay typing, passes human-like
   varied timing (FP-safe by design — real humans vary digraph latencies). Corroborating-only, so the verdict stays
   bot via the convicting headless tells; no detector change. `keystroke-human.json` frozen. **Behavioral synthesis
   is now fully mapped (mouse + keystroke + coalesced ladder); the only behavioral residual is real-hardware input.**
2. **[network] azuretls-client** (Go) — ✅ **DONE iter-13: BUILT + grounded; the "redundant" inference was WRONG.**
   Added `evaders/azuretls` (a real popular Go TLS/JA3+H2 library). I had repeatedly *asserted* it would be
   redundant with primp (caught only by `net.no_js_execution`); grounded live it is caught by **FOUR** net tells —
   `net.h2_header_order_vs_ua`, `net.sec_fetch_vs_ua`, `net.tcp_os_vs_ua`, `net.no_js_execution`. So azuretls forges
   the TLS/JA3 HANDSHAKE but NOT the HTTP request profile (no Sec-Fetch headers, non-Chromium h2 regular-header
   order / no Sec-CH-UA) — the "spoof TLS, forget the HTTP layer" mistake, a network-layer cross-layer incoherence
   on a real third-party tool. It is the LEAST-faithful network template in the fleet (more tells than
   primp/curl-impersonate, which are caught only by `no_js_execution`). The H3/QUIC angle was moot — the edge is
   h2, so azuretls negotiates h2. Validates the detector's network-coherence suite end-to-end. Capture frozen.
3. **[network] JA4 profile rotation** — ✅ **BUILT + GROUNDED + BLUE-TEAM COUNTER LANDED iter-15 (2026-06-20).**
   Added the `go-tls KS_ROTATE` mode: uTLS rotates HelloChrome→HelloFirefox→HelloSafari (Chromium/Gecko/WebKit —
   distinct cipher lists → distinct JA4_b) across connections under ONE `ks_sid`. **Exposed an architectural blind
   spot:** the detector's `ingest.merge` kept only the *latest* JA4 per kind, so within-session TLS-engine rotation
   was invisible — a red-team win that revealed a real blue-team gap. **Closed it FP-safely:** the detector now
   derives `network.ja4_unstable` over the pre-collapse per-request JA4 history (sticky once seen), and the new rule
   **`net.ja4_unstable_within_session`** (coherence, convicting, w0.8, v0.74.38) fires on >1 distinct **JA4_b** — the
   GREASE-free, cipher-sorted engine identity, invariant for a real client across transport (H2/H3), TLS resumption
   and Chrome's per-connection extension/GREASE shuffle. Grounded live: the rotation evader → `bot` 0.9998 (rule
   fires); single-engine go-tls (one JA4_b) → rule silent (FP-safe); browserforge calibration carries no JA4 → 0 FP.
   So the "too-random vs too-static" frontier collapses on the *within-session* axis: rotating JA4 to dodge
   per-connection blocklists is self-defeating once the session correlates the rotation. The residual is the
   *cross-session* axis (rotate JA4 per identity) → coordination/prevalence, the external-data frontier. Capture
   `go-tls-rotate.json` frozen + lit-test guard.
4. **[fingerprint] real-value-reuse injection** (apify fingerprint-injector class) — ✅ **BUILT + GROUNDED iter-14
   (2026-06-20).** Created the `apify-fp-inject` evader (18th fleet tool): `fingerprint-generator` samples a real
   Linux-Chrome joint, `newInjectedContext` injects it via Proxy-over-native. **The white-boxed "defeats the
   artifact + coherence layer by design" inference was INCOMPLETE.** Grounded live: it DOES defeat the artifact
   layer (no `native_invariant`/`tostring_tampered`) AND the network layer (`network` score **0** — coherent
   Sec-CH-UA, no `headless_ua`/`ch_he_headless`). But the injection is **MAIN-realm only** (init script), so a Web
   Worker sees the un-injected headless navigator → it MANUFACTURES three realm-coherence trips the un-spoofed
   browser never had: `br.worker_divergence` + `br.languages_worker_vs_main` + `br.webgl_worker_vs_main`. Scored
   `bot` (0.99999) — the injection ADDS detectability on the coherence axis (textbook thesis demo). No new rule
   (existing realm-coherence catches it); capture frozen, lit-test guard on `br.worker_divergence`. Worker-realm
   coherence is a robust FP-safe catch for the whole main-realm-injection class; beating it needs identical
   worker/OffscreenCanvas-realm spoofing apify does not do (→ external/coordination frontier).
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

**HEADLESS capstone GROUNDED + behavioral synthesis STACKED — iter-19 (2026-06-20).** `patchright-headful` is
headful (xvfb, flaky); the reliable maximal stack is **`zendriver-uach-behave`** — the clean-per-session headless
evader (`zendriver` + `KS_UACH` coherent UA-CH: no automation floor, no `headless_ua`) with behavioral synthesis
(`KS_BEHAVE`: a curved, varied-timing mouse path via CDP `Input.dispatchMouseEvent`, events the kernel marks
`isTrusted`) STACKED on. Re-grounded live at 0.74.39: `zendriver-uach` alone EVADES (CONVICTING none, suspicious
0.995) with residual = behavioral (`bh.input_entropy_floor` + `bh.no_input_before_action`, from sending ZERO
input) + environment. Stacking `KS_BEHAVE` **defeats both input tells** — but **reveals `bh.synthetic_no_coalesced`**
(CDP-injected events are discrete; real hardware batches coalesced intermediate samples). So the behavioral residual
does NOT vanish — it **MOVES from input-absence tells to [[the coalesced ladder]] terminus**, whose only escape is
real-hardware trusted-coalesced input. Net: `zendriver-uach-behave` scores `suspicious` 0.986, **CONVICTING none**,
residual = `bh.synthetic_no_coalesced` + `br.webgl_software` / `br.voices_empty` / `br.media_devices_empty` /
`br.hover_none_desktop` / `br.webrtc_unavailable` — **every tell external-hardware-gated.** This is the precise,
grounded saturation boundary: no in-sandbox move closes any residual (synthetic input → coalesced terminus; faking
environment → tamper check; real values → real hardware). `zendriver-uach-behave.json` frozen. No detector change.

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

**Durable `trace_collision` ISOLATED + grounded live — iter-17 (2026-06-20).** iter-7 grounded `fp_collision`
(identical-fp clones); the `fleet-replay` rt1/2/3 fixture grounded `trace_collision` but its members share one
deterministic `fp_hash`, so it CO-FIRES with `fp_collision` and never proved the durable claim. Closed that gap:
a new `apify-fp-inject KS_TRACE=1` mode (the botright/multilogin pattern — distinct injected fingerprint per
instance + ONE replayed canned trace) ran live as a 3-node fleet; the live coordination consumer graded it
`fleet` (1.0) via **`cloned_trace` alone, `cloned_fingerprint=None`** — the fp-randomising fleet that DEFEATS
`fp_collision` is still convicted by the behavioural-clone signal. First live isolated proof of the catalog's
central durable-signal claim; frozen `corpus/fleet-randfp-trace/ft1-3` + regression test. No detector change.

### Vein C — MODIFY a tool (white-box → enhance the anti-detect feature)
1. **Push the 2 EVADERS** (`camoufox-headful` / `patchright-headful` — `zendriver` REFUTED iter-9, it's caught by
   `net.h2_header_order_vs_ua`). White-box exactly *why* they escape, and whether the residual (capability tells,
   coordination) can be closed too — i.e. make a fully-clean evader, then see what (if anything) the blue-team can
   still FP-safely do. (Both remaining evaders are headful + external-hardware-gated per the iter-6 stack capstone.)
2. **Harden a stealth mode** to silence a remaining convicting tell (e.g. the `br.chrome_runtime_missing`
   patchright-headless residual) — white-box the gap, patch it, confirm the tell goes quiet without a new artifact.

## New tools to add to the fleet (cutting edge, researched)
`azuretls-client` (TLS+H2+H3 forger — ✅ DONE iter-13; H3 path moot, edge sniffs QUIC but doesn't serve it) ·
`ghost-cursor` + `PHC-mouse-movement-gen` + DMTG (behavioral — synthetic mouse trips `bh.synthetic_no_coalesced`
regardless of trajectory, see iter-19, so confirmatory) · CloakBrowser · **playwright-extra (✅ DONE iter-20).**
Browser-patch (C++-level) tools beat JS-injection tools, and Gecko engine diversity (Camoufox) evades
Chrome-specific behavioral models — favor those.

**playwright-extra + puppeteer-extra-plugin-stealth — GROUNDED iter-20 (2026-06-20).** Added the ubiquitous
~17-evasion JS-injection stealth baseline (the 19th fleet tool). White-box: its `webgl.vendor` uses
`replaceWithProxy` (Proxy-over-native, defeats the artifact layer like apify), adds `chrome.runtime/app/loadTimes`,
hides `navigator.webdriver`, mocks plugins/codecs. **Grounded live → `bot` 1.0, caught SIX ways — and it SELF-INFLICTS
the cross-layer-incoherence thesis:** (1) `net.tcp_os_vs_ua` — its `user-agent-override` evasion rewrites the
platform to **Windows** while the container's TCP/IP stack is **Linux** (`ua_kernel=windows` vs `tcp_kernel=linux`):
the textbook "spoof the UA, forget the network layer" mistake, live, from the world's most-deployed stealth tool;
(2) `br.ch_he_headless` — it de-`Headless`'d the UA string but NOT the Sec-CH-UA high-entropy brand list (the
UACH-coherent lesson); (3) `br.worker_divergence` + `languages_worker_vs_main` + `webgl_worker_vs_main` — its spoofs
are MAIN-realm only (same blind spot as apify); (4) `br.cdp_runtime_enabled` — JS-stealth does NOT hide CDP (unlike
patchright). So the OG stealth baseline is FAR more detectable than the fleet's modern tools (patchright EVADES;
this is caught 6 ways), and is a live demonstration that naive stealth evasions ADD incoherence. All six are
existing rules → no new detection, no version bump. `playwright-extra.json` frozen.

**Root cause white-boxed + hardened — iter-21.** The `tcp_os_vs_ua` is not incidental: the `user-agent-override`
evasion defaults to **`maskLinux: true`**, which on a Linux host REWRITES the UA platform to `Windows NT 10.0`
while the TCP/IP stack stays Linux — a GUARANTEED `net.tcp_os_vs_ua` on the exact servers scrapers run (the
plugin's own README admits unmasking "makes detection very easy", but masking creates a WORSE cross-layer tell).
Generalizable: every default-config puppeteer-extra-plugin-stealth deployment on Linux self-inflicts it. Hardened
it live (`KS_COHERENT_UA=1` → `maskLinux:false`): `tcp_os_vs_ua` GOES QUIET, but the residual is **structural and
irreducible for JS-injection stealth** — `br.cdp_runtime_enabled` (can't hide the CDP transport, only patchright
does), `br.ch_he_headless` (fixes the UA string but NOT the Sec-CH-UA high-entropy brand list — still
HeadlessChrome), and `br.worker_divergence`×3 (main-realm-only spoofs). So even OPTIMALLY configured the most
popular stealth plugin is caught 5 ways, none config-hardenable. `playwright-extra-coherent.json` frozen. No new
detection (existing rules); no version bump.

**Coherent-WebKit engine profile GROUNDED — iter-22 (2026-06-20).** The fleet had only `webkit-ua-spoof` (WebKit +
a CHROME UA → caught by the TLS/JA4 engine mismatch). Grounded the COHERENT case (`KS_COHERENT=1`: WebKit + a real
Safari UA, so `net.tls_vs_ua_browser` stays quiet) to map WebKit's evasion axes. Result `bot` 1.0, caught SIX ways
with a clean split: (1) **WebKit DOES evade the Chromium automation floor** — `br.cdp_runtime_enabled` and
`br.headless_ua` do NOT fire (WebKit speaks no CDP, carries no HeadlessChrome token), the one engine-axis WebKit
wins; BUT (2) **the Safari⟹macOS⟹not-a-Linux-server incoherence is caught across THREE layers** —
`net.tcp_os_vs_ua` (Mac UA vs Linux TCP/IP), `br.navplatform_vs_ua` (JS `navigator.platform`), `br.font_os_vs_ua`
(Linux fonts under a Mac UA); and (3) **Playwright-WebKit artifacts leak** — `br.webdriver_present` (Playwright
WebKit leaves `navigator.webdriver=true`, unlike the stealth Chromium tools), `net.h2_unknown_vs_ua` +
`net.tls_grease_vs_ua` (its h2/TLS are not real-Safari's). So a WebKit bot can only be coherent on REAL Mac
hardware (closing the OS axis) AND would still need to hide webdriver + forge a real-Safari TLS/h2 — i.e. real
Safari on a real Mac, the external-hardware frontier. `webkit-safari-coherent.json` frozen; all existing rules →
no new detection, no version bump.

**Coherent-Gecko is the THINNEST-caught stock engine — iter-23 (2026-06-20).** The Gecko analog of the WebKit
grounding, but Firefox-on-Linux IS OS-coherent (unlike Safari⟹Mac), so it isolates the engine axis cleanly. Added
`firefox-coherent` (`KS_COHERENT=1`: a real LINUX Firefox UA on the Linux host). Grounded live → caught by a
**SINGLE convicting tell, `br.webdriver_present`** — no `cdp_runtime_enabled` (Gecko speaks no CDP), no
`headless_ua` (no token), no OS-incoherence (Linux UA + Linux host + Linux oscpu all agree). Far cleaner than
Chromium (many tells) or WebKit (6). **That single tell is a ROBUST 2-rung ladder, grounded:** (a) stock →
`br.webdriver_present` (Playwright sets `navigator.webdriver=true`); (b) the native `dom.webdriver.enabled` pref is
OVERRIDDEN by Playwright's automation (still `webdriver_present` — grounded, the pref does nothing); (c) a JS
redefine (`KS_HIDEWD=1`) hides `webdriver_present` but makes the getter non-native → `br.webdriver_getter_tampered`
fires instead. So the webdriver tell is escapable only by an ENGINE-LEVEL patch (Camoufox sets `webdriver=false`
natively with no JS tamper) — **this precisely locates WHY Camoufox exists and EVADES while stock Playwright
Firefox does not**: coherent Gecko is one engine-level webdriver patch away from clean, and that patch is exactly
Camoufox's value-add. `firefox-coherent.json` frozen; all existing rules → no new detection, no version bump.

**Headless Camoufox EVADES (lowest-bar) — iters 24-27, fully resolved 2026-06-20.** Net result: **headless
Camoufox + a Linux profile EVADES the convicting layer (no xvfb)** — the per-session bar IS below headful. The path
here was messy and is worth recording as a methodology lesson (TWO wrong intermediate corrections):
- iter-24 grounded headless camoufox-linux EVADES (correct) but with `KS_FAST=1`.
- iter-25 saw ONE non-FAST run trip `br.pointer_touch_incoherent`, wrongly blamed `?fast` "under-probing" and
  declared the bar stays at headful. **Both wrong.** White-boxing `demo.py` settles it: `?fast` skips ONLY the
  behavioral layer + shortens the send timer (line 1135/1173); it does NOT touch the browser-layer
  `pointer_touch_incoherent` probe. The real cause is **Camoufox's per-launch RANDOM `navigator.maxTouchPoints`** —
  it occasionally (measured ~1/14 ≈ 7% of launches) picks `maxTouchPoints > 0` (a touch device) on a desktop while
  the CSS `@media(any-pointer:coarse)` stays false → `matchMedia("(any-pointer: coarse)").matches !==
  (maxTouchPoints>0)` → the tell fires (also `maxtouch_desktop`). So plain headless camoufox-linux EVADES the COMMON
  case (~93%) and self-inflicts a FLAKY `pointer_touch_incoherent` catch the rare unlucky launch.
- iter-26/27 — the deterministic fix: `KS_NOTOUCH=1` passes Camoufox `config={"navigator.maxTouchPoints": 0}` (a
  coherent fine-pointer desktop) → the tell can never fire → `camoufox-linux-coherent` EVADES every launch. Grounded
  under the FULL collector: suspicious ~0.987, CONVICTING NONE, headless, no xvfb.

Residual on both = corroborating only (`bh.synthetic_no_coalesced` — Gecko's Playwright mouse does NOT escape it,
resolving the iter-19 question; naive-path `bh.power_law_violation`; environment `webgl2/voices/media/webrtc`), all
external-hardware-gated → frontier (b), no FP-safe counter (a `maxTouchPoints=0` + fine-pointer desktop is exactly
a real headless Linux server browser). `camoufox-linux.json` (common EVADES) + `camoufox-linux-coherent.json`
(deterministic EVADES) frozen. `br.pointer_touch_incoherent` stays a valid FP-safe catch for the ~7% naive-camoufox
flake (stock Firefox is coherent). No new detection, no version bump. **EVADES set is 6: camoufox-headful,
camoufox-linux, camoufox-linux-coherent, patchright-headful, zendriver-uach, zendriver-uach-behave.**
**METHODOLOGY LESSON: verify a proposed mechanism against the collector SOURCE before committing it — I shipped two
wrong explanations (`?fast` under-probing; "bar stays headful") by inferring from a single flaky run instead of
reading `demo.py` and measuring the rate.**

**Fixed the SELF-DEFEATING camoufox-hardened config — iter-28 (2026-06-20).** `KS_HARDENED` is meant to be the
"close every per-session tell" config, but it pinned `os="windows"` (to dodge the macOS dpr/font tells) on a Linux
host → grounded live, it self-inflicted **`net.tcp_os_vs_ua`** (Windows UA vs Linux TCP) as its SOLE convicting
tell — i.e. the "hardened" build was WORSE than plain `camoufox-linux-coherent`. Its comment also cited
`br.webgl_renderer_artifact` as "unavoidable" — STALE: that rule (the `", or similar"` Firefox WebGL
generalisation) is dropped by `detector.applicability` for `ua_engine==firefox` since v0.74.10, so it is NOT a
Camoufox tell at all. Corrected `HARDENED_KW` to the coherent recipe (`os="linux"` — dodges the macOS tells AND
`tcp_os`; `config={"navigator.maxTouchPoints": 0}` — kills the ~7% pointer_touch flake; keep WebRTC on). Grounded
live under the full collector → **CONVICTING NONE, EVADES**, residual corroborating-only (behavioral
`synthetic_no_coalesced`/`power_law`; environment `webgl2/voices/media/webrtc`). NB `webrtc_unavailable` persists
despite `block_webrtc=False` — in-sandbox WebRTC gathers no ICE candidates (no STUN), so the tell is
external-gated regardless (the config is correct for real infra). `camoufox-hardened.json` re-frozen (now EVADES).
EVADES set = 7. No new detection, no version bump.

**Coordination boundary GROUNDED with the maximal evader — + a real red-team fix — iter-29 (2026-06-20).** Set out
to confirm (expected `candidate`) that the strongest per-session EVADES (`camoufox-hardened`) is not convictable at
scale. **The expectation was WRONG (recurring lesson):** a 3-instance camoufox-hardened fleet (diverse `fp_hash`,
distinct IPs) graded **`fleet` (1.0)** via **`cloned_trace`** — the camoufox evader's mouse sim used FIXED
coordinates (`page.mouse.move(100 + i*7, 120 + (i%5)*12)`), so every instance emitted ONE identical `trace_hash` →
`coordination._trace_collision` convicted the whole fleet despite divergent fingerprints. A live demonstration that
`trace_collision` catches the fp-randomizing fleet (the catalog's central durable-signal claim, here self-inflicted
by a naive evader). **Red-team counter (the fix):** per-instance random jitter on the pointer path (distinct per
container process) → diverse `trace_hash` → `trace_collision` defeated. Re-grounded live: the jittered fleet grades
**`candidate` (0.87)** — `cloned_trace=None`, `cloned_fingerprint=None`, `shared_real_ip=None`. So the truly-maximal
evasive fleet (diverse fp + diverse trace + distinct IPs + shared engine JA4) is **NOT convictable in-sandbox** — a
real diverse cohort on one browser build produces the identical shape, so the gate correctly caps it at `candidate`;
the only signal that would convict it is `shared_real_ip` (the WebRTC real-IP leak behind proxies), which is
external-gated (the collector's STUN is unreachable in-sandbox → no `srflx` candidate → no `webrtc_public_ip`).
**This is the definitive per-session→coordination boundary, grounded with the strongest evader: per-session
saturated, the in-sandbox coordination tells (`fp_collision`/`trace_collision`) catch the NAIVE fleet, and the
maximal evasive fleet is external-data-bound (IP-reputation / WebRTC leak).** Fixed the camoufox evader's
self-inflicted trace collision; no detector change (`trace_collision` works as designed), no version bump.

**WebRTC real-IP leak GROUNDED in-sandbox + the rule demoted FP-safe — iter-30 (2026-06-20, v0.74.40).** Pivoted to
the last durable convicting signal the catalog filed under "external/STUN-gated": `net.webrtc_ip_vs_observed` (the
proxied-bot WebRTC leak), which had NEVER had a live positive. First verified the gating: a container on
kitsune_default resolves `stun.l.google.com` but has NO UDP egress (STUN times out) → so `br.webrtc_unavailable` is
a **no-STUN-egress sandbox artifact, not a real tell**. Then BUILT the missing infra: a minimal local STUN server +
an HTTP CONNECT proxy on kitsune_default, DNS-overrode the collector's STUN to the local one (`--add-host`), added
`KS_PROXY` to the camoufox evader. Grounded LIVE: camoufox's HTTPS routed through the proxy (`observed_ip`=proxy)
while its WebRTC UDP went direct to the STUN (`webrtc_public_ip`=real container IP) → **the two differ → the rule
fired (its first live positive)** — the cross-layer thesis end-to-end (hide the IP at the network layer, leak it at
the browser layer; an HTTP CONNECT proxy cannot carry WebRTC's UDP). With the STUN reachable, `webrtc_unavailable`
also went quiet (srflx candidate gathered) — confirming it's a sandbox artifact. **FP-safety fix (the red-team win
exposed it):** per-session this is NOT FP-safe — a real split-tunnel-VPN user whose WebRTC isn't tunnelled shows the
IDENTICAL shape (real IP ≠ VPN connection IP), undisambiguable from a proxied bot without IP reputation. So DEMOTED
`coherence → reputation` (convicting → corroborating, v0.74.40); the FP-safe CONVICTING version is the coordination
signal `shared_real_ip` (MANY sessions sharing ONE leaked origin = a single-machine fleet; a diverse VPN cohort
leaks DISTINCT origins). Re-grounded post-demotion: the proxied-leak session now scores `suspicious` (corroborated,
CONVICTING none). `webrtc-leak.json` frozen; calibration unaffected (no WebRTC layer); detector 241 green. The
red-team COUNTER to the leak: block WebRTC (→ the corroborating `webrtc_unavailable`) or use a SOCKS proxy that
carries the WebRTC UDP. This closes the WebRTC frontier's in-sandbox-groundable half; the residual external gate is
real IP-reputation (datacenter-vs-residential), which `shared_real_ip` needs to convict a single proxied session.

**`shared_real_ip` GROUNDED on a REAL WebRTC-leak fleet — iter-31 (2026-06-20).** The FP-safe CONVICTING version of
the iter-30 leak, previously tested only synthetically. Built the single-machine-behind-many-proxies shape: a local
STUN that reports ONE fixed origin IP (`203.0.113.7`, simulating one machine) + 3 HTTP CONNECT proxies, then ran 3
camoufox-hardened instances each via a DISTINCT proxy. Result: 3 sessions, distinct `observed_ip` (the 3 proxies) +
ONE shared `webrtc_public_ip` (the origin) + shared camoufox JA4. The live coordination consumer graded them
**`fleet` (1.0) via `shared_real_ip` ALONE** — `cloned_fingerprint=None`, `cloned_trace=None` (diverse fps + jittered
traces, so neither collision fires): "3 proxy IPs front one real IP `203.0.113.7` (WebRTC) — same-origin fleet."
**So the iter-29 maximal evasive fleet (diverse fp + diverse trace + distinct proxy IPs) that graded `candidate` is
CONVICTED the moment it leaks ONE shared WebRTC origin** — the durable signal working as designed. FP-safe: a
diverse real-user cohort behind proxies leaks DISTINCT home origins (`len(webrtc) > 1`), never one, so
`shared_real_ip` only fires on a true single-machine fleet. **All THREE durable convicting coordination signals are
now grounded with REAL captures through the live stack: `fp_collision` (iter-7), `trace_collision` (iter-17/29),
`shared_real_ip` (iter-31).** Frozen `corpus/fleet-webrtc-leak/wr1-3` + a regression test (`fleet` via shared_real_ip
alone). Red-team COUNTER to `shared_real_ip`: block WebRTC (→ the corroborating `webrtc_unavailable`) or route each
session's WebRTC through its OWN per-session SOCKS proxy (so every session's WebRTC shows its proxy IP, not the
shared origin → `len(webrtc) > 1` → no fire). No detector change (signal is FP-safe + works), no version bump.
**The coordination frontier is now FULLY grounded in-sandbox; the only residual external gate is real IP-reputation
to convict a SINGLE proxied session that does NOT leak via WebRTC.**

**Red-team COUNTER to `shared_real_ip` GROUNDED — the WebRTC arms race closes — iter-32 (2026-06-20).** Added
`KS_NOWEBRTC=1` to the camoufox evader (`block_webrtc=True`) — a real anti-detect tool disables WebRTC precisely to
stop the IP leak. Ran the same 3-proxy fleet (distinct `observed_ip`) WITH the reachable local STUN, to prove the
block works rather than relying on the no-STUN artifact: every session had `webrtc_public_ip` **ABSENT** (despite
the STUN being reachable) + `webrtc_unavailable` true. The live coordination consumer graded the fleet
**`candidate`** — `shared_real_ip=None` (no shared origin to leak). So **blocking WebRTC defeats `shared_real_ip`**,
trading the convicting coordination signal for the corroborating-only `webrtc_unavailable` — the fully-evasive
proxied fleet (diverse fp + jittered trace + distinct proxies + WebRTC blocked) is genuinely external-data-bound
(only real IP-reputation would convict it). Minor wrinkle observed: 2/3 camoufox launches chance-collided on
`fp_hash` → an UNCORROBORATED `fp_collision` (camoufox's per-launch fp randomisation is not perfectly diverse) —
still capped at `candidate` (a real standardized-hardware cohort hashes alike). **The WebRTC arms race is now
complete and grounded both ways:** leak it (HTTP proxy + WebRTC direct) → `shared_real_ip` convicts (iter-31);
block it → `candidate`, external-gated (iter-32). No detector change, no version bump.

**NEW DETECTION: `rep.webrtc_origin_datacenter` — the WebRTC leak exposes a blue-team blind spot (iter-33, v0.74.41).**
Grounding the WebRTC leak (iters 30-32) surfaced a real gap: the detector classifies ONLY `observed_ip`'s reputation
(`rep.datacenter_asn`), never the WebRTC-leaked origin. But the leaked `webrtc_public_ip` is the REAL machine running
the browser — a cloud bot HIDES behind a residential proxy (clean `observed_ip`) while its WebRTC leaks its DATACENTER
origin (the cloud VM). So `rep.datacenter_asn` (observed_ip only) MISSES the cloud-bot-behind-residential-proxy. Built
the detection: `detector._with_derived` now also classifies `webrtc_public_ip` → `reputation.webrtc_origin_datacenter`
→ the new rule. **KEY FP-SAFETY** (vs the demoted per-session `net.webrtc_ip_vs_observed`): it is the REPUTATION of the
origin, not merely that it differs — a real VPN user leaks their RESIDENTIAL home IP (never datacenter), so the rule
does NOT fire on them. Corroborating (category reputation, not convicting): the residual FP is a real user running the
browser ON a datacenter machine (cloud desktop / remote browser / dev VM) — rare but real, so it corroborates (matching
`rep.datacenter_asn`'s stance). GROUNDED LIVE: local STUN configured to report `52.0.0.1` (the committed AWS
datacenter CIDR) + an HTTP CONNECT proxy → camoufox `observed_ip`=clean proxy, `webrtc_public_ip`=52.0.0.1 →
**`rep.webrtc_origin_datacenter` FIRED while `rep.datacenter_asn` did NOT** (the exact cloud-bot-hidden shape). Unit
tests: datacenter origin behind a clean proxy fires; a residential WebRTC origin (VPN user) does NOT. Calibration
unaffected (no WebRTC layer); detector 243 green, mypy clean. `webrtc-origin-datacenter.json` frozen. **This is the
first NEW convicting-class detection surface the in-sandbox WebRTC infra unlocked — the leaked-origin reputation, a
distinct IP from the proxy, catching the residential-proxy disguise the observed_ip rules cannot see.**

**CONVICTING upgrade: `net.datacenter_origin_proxied` — the cross-layer thesis applied to IP-rep (iter-34, v0.74.42).**
iter-33's `rep.webrtc_origin_datacenter` had to be corroborating because a cloud-desktop user (browser on a cloud VM,
DIRECT) also leaks a datacenter WebRTC origin. The FP-safe CONVICTING refinement adds one clause — `observed_ip is NOT
datacenter` — making it the cross-layer contradiction: **the real machine is in a DATACENTER (WebRTC origin) yet it
CONNECTS through a NON-datacenter (residential) IP** — a datacenter VM HIDING behind a residential proxy, the dominant
commercial-scraping pattern (cloud VM + residential proxy pool) that defeats `observed_ip` reputation entirely
(`rep.datacenter_asn` sees only the clean proxy). The `observed_ip not datacenter` clause removes the one real FP:
a cloud-desktop user connects FROM the datacenter (observed_ip datacenter too → does NOT fire; caught corroboratively
by `rep.datacenter_asn` instead). A datacenter machine reached via a residential IP has no legitimate explanation. The
detector derives `network.datacenter_origin_proxied` in `_with_derived` (webrtc datacenter AND observed not-datacenter)
→ a convicting coherence rule. GROUNDED LIVE (STUN reports `52.0.0.1` AWS CIDR + HTTP CONNECT proxy → camoufox
observed_ip=clean proxy, webrtc=datacenter → **label bot**, `net.datacenter_origin_proxied` convicts while
`rep.datacenter_asn` stays quiet). Unit tests: the hiding bot convicts; a cloud-desktop-DIRECT user (observed_ip
datacenter) does NOT fire it. Calibration unaffected (no WebRTC layer); detector 245 green, mypy clean.
`datacenter-origin-proxied.json` frozen + lit-test guard. **So the WebRTC red-team work (iters 30-34) yielded the
in-sandbox grounding of all 3 durable coordination signals + TWO new detections (`rep.webrtc_origin_datacenter`
corroborating, `net.datacenter_origin_proxied` convicting) that catch the cloud-VM-behind-residential-proxy the
observed_ip reputation rules are structurally blind to.** The residual external gate narrows further: a bot that
runs on a RESIDENTIAL machine (real residential device) OR routes WebRTC through its residential proxy (SOCKS-UDP)
leaks no datacenter origin — that needs real residential-device infra, genuinely external.

**Ledger consolidated + the precise external residual GROUNDED — iter-35 (2026-06-20).** Updated the
evasion-catalog's stale strategic-gaps #2 + coverage-envelope (they still said the coordination/WebRTC/IP-rep
frontier was "Still BLOCKED" — wrong after iters 30-34 grounded it via a local STUN + proxy). Grounded the exact
external boundary the residual now rests on: a maximally-evasive cloud bot that BLOCKS WebRTC — `camoufox-hardened`
(per-session EVADES) + `KS_NOWEBRTC` + a non-datacenter (residential-looking) HTTP proxy — scores **`suspicious`,
CONVICTING NONE, EVADES per-session**; its residual is 100% corroborating + external-hardware/data-gated
(`bh.synthetic_no_coalesced`; `br.webgl2_missing`/`voices_empty`/`media_devices_empty`; `br.webrtc_unavailable` the
cost of blocking WebRTC). So the ONLY thing that would convict it is real residential-vs-datacenter IP-reputation on
the proxy (in-sandbox `observed_ip` is always private 172.x → classified clean) OR it leaking via WebRTC (which it
blocked). **That is the precise, grounded saturation boundary: a cloud bot that runs engine-coherent, blocks WebRTC,
and fronts with a residential proxy is indistinguishable from a residential user without real IP-reputation data —
the single remaining external gate.** No code change (consolidation + boundary grounding); no version bump.

**SOCKS WebRTC counter GROUNDED — it degrades to `webrtc_unavailable`; the WebRTC arms race CLOSES — iter-36
(2026-06-20).** The one ungrounded red-team capability left: route WebRTC through a residential SOCKS5 proxy (which
carries UDP, unlike an HTTP CONNECT proxy) so the srflx shows the PROXY's IP (residential) instead of the real
datacenter machine — evading `net.datacenter_origin_proxied` WITHOUT the `webrtc_unavailable` cost. Built it
(`KS_SOCKS` on the camoufox evader: `proxy=socks5://…` + Camoufox `firefox_user_prefs media.peerconnection.ice.
proxy_only=true` to force WebRTC through the SOCKS) and grounded it against a real `gost` SOCKS5 proxy + the
source-reporting STUN. **Result: the counter FAILS to produce a clean residential srflx — `webrtc_public_ip` is
ABSENT, `br.webrtc_unavailable` fires.** HTTP routes through the SOCKS fine (observed_ip = gost, TCP works), but
Firefox gathers NO UDP srflx candidate through SOCKS (`proxy_only` forces WebRTC through the SOCKS, and Firefox does
not do UDP STUN over SOCKS5-UDP) → it degrades to the SAME outcome as blocking WebRTC: `suspicious`, CONVICTING NONE,
EVADES per-session, residual all external-hardware-gated (`webrtc_unavailable` + `synthetic_no_coalesced` +
environment). **So a proxied bot has NO in-sandbox-achievable way to obtain a clean residential WebRTC origin: it
either LEAKS its real origin direct (datacenter → caught by `net.datacenter_origin_proxied`/`shared_real_ip`) or
gets `webrtc_unavailable` (block OR SOCKS-degrade). A clean residential srflx requires real residential HARDWARE —
the WebRTC frontier's residual is genuinely external.** `camoufox-socks-webrtc.json` frozen (EVADES via the
webrtc_unavailable residual). No detector change, no version bump. The WebRTC/IP-rep arc (iters 30-36) is complete:
the leaked-origin reputation is a robust convicting surface, and the only escape is real residential infra.

## Comprehensive saturation — full-corpus regression validation (iter-37, 2026-06-20, ruleset 0.74.42)

Re-scored ALL 86 `corpus/sessions/*.json` against the current ruleset to verify the ~20 rules added across iters
15-34 (within-session rotation: `ja4_unstable`/`ip_rotation`; WebRTC: `webrtc_ip_vs_observed`; IP-rep cross-layer:
`rep.webrtc_origin_datacenter`/`net.datacenter_origin_proxied`; the coalesced ladder; engine/realm tells) caused
NO regression: **77 `bot`, 9 `suspicious`, 0 `human`** — every previously-convicted capture still convicts, and no
known evader regressed to a clean verdict. The 9 `suspicious` are the saturated EVADES set: **7 genuine per-session
EVADES** (`camoufox-headful`, `camoufox-linux`, `camoufox-linux-coherent`, `camoufox-hardened`, `patchright-headful`,
`zendriver-uach`, `zendriver-uach-behave` — all engine-coherent with a residual that is 100% external-hardware-gated)
+ **2 WebRTC demonstrations** (`webrtc-leak` — per-session ambiguous with a VPN user, convicted at scale by
`shared_real_ip`; `camoufox-socks-webrtc` — the SOCKS counter degraded to `webrtc_unavailable`).

**SATURATION STATEMENT (in-sandbox evasion + detection are comprehensively mapped):**
- **Per-session**: saturated. 7 EVADES all reduce to one recipe (engine-spoof + coherent OS profile + maxTouchPoints
  pin); residual = the external-hardware-gated environment floor (`webgl2_missing`/`voices_empty`/`media_devices_empty`)
  + `synthetic_no_coalesced` (the coalesced ladder's real-hardware terminus).
- **Engine axis** (Chromium/WebKit/Gecko), **behavioral** (mouse/keystroke/coalesced), **within-session rotation**
  (JA4/IP), **coordination** (`fp_collision`/`trace_collision`/`shared_real_ip` all real-grounded + the maximal-fleet
  boundary), and the **WebRTC/IP-rep cross-layer frontier** (the leaked-origin reputation, both counters grounded):
  all mapped and grounded LIVE.
- **The single remaining convicting frontier is real IP-reputation / residential-hardware data** — a bot that runs
  engine-coherent on RESIDENTIAL hardware, blocks/SOCKS-routes WebRTC, and fronts with a residential proxy is
  indistinguishable from a residential user without real datacenter-vs-residential ASN data (in-sandbox `observed_ip`
  is always private 172.x → classified clean; verified against `ip_reputation.py` + the edge's TCP-source `clientIP`).
  Likewise the prevalence model needs a Tier-3 real-traffic prior. Both genuinely external.
- **Productive moves from here:** an operator supplies that external data (IP-rep / real-traffic prevalence / real
  hardware) → build the blocked detections; OR a genuinely-new anti-detect tool appears to white-box. Not further
  in-sandbox grinding of the rotation-family / cosmetic-tweak kind. No detector change, no version bump this iter.

**NEW SURFACE — mobile emulation, comprehensively caught (iter-38, 2026-06-20).** The all-desktop fleet had never
tested the MOBILE surface. Added `mobile-emulation` (the 20th fleet tool): a desktop Chromium running Playwright's
Pixel 5 device (Android Chrome UA + `hasTouch` + `isMobile` + a mobile viewport) — coherent UA-engine (Chromium UA,
not an iPhone/Safari mismatch). Grounded live → `bot` 1.0, caught SIX convicting ways, and crucially the cross-layer
thesis HOLDS for mobile: a mobile UA over a desktop host cannot hide its real OS. Beyond the automation floor
(`webdriver`/`cdp_runtime`/`permissions`/`no_chrome`) + `ch_he_headless`, it trips **`br.font_os_vs_ua`** (Android UA
but Linux container fonts — convicting) and corroboratively `br.codec_os_incoherent` (codecs vs Android),
`br.font_linux_leak`, `br.webgl_software` (desktop SwiftShader, not a mobile GPU), and **`br.fingerprint_improbable`**
— the prevalence model's FIRST live-evader positive: the mobile-UA + desktop-GPU/screen/cores joint is improbable
even under the same-source browserforge prior (browserforge would never generate a Pixel-5-with-desktop-GPU). So no
mobile-coherence gap exists — the detector catches a desktop-emulating-mobile across fonts/codecs/GPU + prevalence +
the automation floor. A COHERENT mobile evader needs real mobile hardware (real Adreno/Mali GPU, Android fonts) →
the same external-hardware frontier as desktop. `mobile-emulation.json` frozen + lit-test guard on
`br.fingerprint_improbable` (it had no prior live positive — this validates the prevalence model fires on a real
incoherent-joint attack, distinct from its documented same-source blindness to a CLEAN browserforge injection). No
new detection (existing rules), no version bump.

**UNLIT-RULE AUDIT — restored a lost lit-capture (iter-39, 2026-06-20).** With the in-sandbox evasion surface
saturated, pivoted from "find a new EVADES" to "which convicting rules have NO live-evader positive proving they
fire?" — a regression-coverage frontier, not a new-coverage one. Audited all 121 active rules against the lit-capture
corpus: 15 convicting rules had no committed capture, 4 of them structurally lightable by the fleet. One,
**`br.pointer_touch_incoherent`**, had SILENTLY lost its guard — the iter-27 `KS_NOTOUCH` counter (pin
`maxTouchPoints=0`) was the right red-team move but it also removed the only capture that *lit* the rule, since
Camoufox's incoherent touch-desktop is a ~7%-per-launch RANDOM flake (not deterministically reproducible). Added the
inverse flag **`KS_TOUCH=1`** (Camoufox `config={"navigator.maxTouchPoints": 5}` on a Linux-pinned desktop → touch JS
but fine CSS pointer → the deterministic incoherence) and mode `camoufox-touch-incoherent`. Grounded live → `bot`,
`br.pointer_touch_incoherent` the SOLE convicting tell. Froze `camoufox-touch-incoherent.json` + a lit-test guard so
the rule can't silently lose coverage again. The 3 remaining unlit-convicting rules are structurally-hard/external,
NOT regressions: `net.tls_os_vs_tcp_os` (JA4 rarely OS-hints, so the TLS-OS field is usually absent — needs a tool
that forges a mismatched TLS-OS, which none do); `br.voice_os_vs_ua` (the container ships no TTS voices → the prior
tell is `br.voices_empty`, never reaching the OS-vs-UA compare — needs a host with real OS voices); and
`br.webgpu_vendor_vs_webgl` (needs a CLEAN WebGL→real-GPU spoof *plus* a software-WebGPU adapter whose vendor
disagrees — the naive WebGL override the fleet can produce trips `br.webgl_getparameter_tampered` first). No detector
change, no version bump — `br.pointer_touch_incoherent` is a pre-existing rule; this iteration restores its
regression guard, it does not add detection.

**WITHIN-SESSION UA ROTATION — closed the same-engine gap (iter-40, 2026-06-20, v0.74.43).** The within-session
invariant-rotation axis (flagged as the non-saturated in-sandbox vein) had JA4 (TLS engine, v0.74.38) and IP origin
(v0.74.39); the third invariant — the **User-Agent string** — had no rotation tell. A real client sends ONE fixed UA
for a session's lifetime (pinned per browser build; a version change requires a restart = a new session). A
UA-rotating scraper that cycles Chrome→Firefox→Safari is already caught per-request by `net.tls_vs_ua_browser` (the UA
disagrees with the invariant JA4 engine), but one that rotates WITHIN an engine family — cycling Chrome BUILD strings
(124/125/126, or Chrome-Win/Mac/Linux), the realistic "look like many users on one proxy" tactic to dodge UA-keyed
rate limits — keeps JA4/h2/Sec-CH-UA/OS coherent and **slips past every cross-layer UA rule**. Built the full stack:
the **edge** now emits the raw `http_user_agent` on every forwarded request (mirroring `observed_ip`); the **detector
ingest** accumulates the distinct UAs under a ks_sid in a running `ua_seen` set (surviving the latest-per-kind merge
collapse, like `observed_ip_seen`) and derives a sticky `network.ua_rotation` at **>=2** distinct UAs (a stricter
floor than ip_rotation's 3 — unlike IPs there is NO legitimate mid-session UA change, no CGNAT/handoff analog); and a
new convicting rule **`net.ua_rotation_within_session`** (coherence, weight 0.7) reads it. GROUNDED LIVE: minted one
ks_sid through the rebuilt edge, replayed the SAME cookie with three same-engine Chrome UAs (124/125/126 on Windows)
→ the detector accumulated 3 distinct `http_user_agent`, derived `ua_rotation`, and tripped the rule (label `bot`) —
and critically, with `net.tls_vs_ua_browser`/`net.h2_vs_ua_browser` STAYING QUIET, proving the same-engine rotation is
invisible to the cross-layer UA rules and this within-session count is the only tell that closes it. Frozen as the
`ua-rotation.json` lit-capture + a regression guard. `task calibrate` (browserforge, n=500): zero new FPs — the rule
is absent from the re-tier table because browserforge fingerprints carry no network/UA-rotation layer, so promotion
cannot raise the legit flag rate (same FP-safety class as its JA4/IP siblings). Edge `go vet`/tests + detector
mypy/249 tests green. This **completes the within-session invariant-rotation triad** (TLS engine · network origin ·
UA string); the residual is the same external-proxy edge case the JA4/IP rules carry (a UA-rewriting forward proxy
fronting a real browser — but the lab edge is the first hop, so it is not an in-fleet FP).

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
- **iter-10 (2026-06-20): zendriver → a HEADLESS evader of the convicting layer (red-team WIN).** Grounded the
  CDP-minimal class live: `nodriver`/`pydoll`/`undetected` are each caught by `br.headless_ua` alone (they keep the
  HeadlessChrome token + send Sec-CH-UA), but `zendriver` is caught by `net.h2_header_order_vs_ua` alone — it HIDES
  the token (its built-in stealth) but the UA override CLEARS the Sec-CH-UA hints (a textbook single-layer-stealth-
  forgot-the-network-layer incoherence, a third-party live demo of the thesis). zendriver already avoids the
  automation floor (no `cdp_runtime_enabled`/`no_chrome_object`/`permissions_anomaly`, unlike patchright-headless),
  so fixing that ONE cross-layer tell makes it evade. Added `KS_UACH=1` to the zendriver evader (CDP
  `Network.setUserAgentOverride` + full `userAgentMetadata` → coherent Sec-CH-UA); grounded live `zendriver-uach`
  scores **suspicious, ZERO convicting tells** — the FIRST and ONLY **headless** evader of the convicting layer (no
  xvfb, unlike camoufox-headful/patchright-headful). **Frontier (b):** a coherent UA-CH is legitimate (no FP-safe
  counter); residual is external-hardware-gated environment + behavioural corroboration. EVADES frontier now **3**.
- **iter-11 (2026-06-20): the WHOLE CDP-minimal class evades headless with a coherent UA-CH override (class-wide,
  grounded).** Generalized the iter-10 win: `nodriver` + the same coherent UA-CH override (CDP
  `setUserAgentOverride` removing the HeadlessChrome token + sending a coherent Sec-CH-UA) → grounded live
  `suspicious`, ZERO convicting tells — EVADES, exactly like zendriver-uach. So the entire CDP-minimal class
  (nodriver/pydoll/undetected/zendriver) — each caught by a SINGLE convicting tell (`br.headless_ua` or
  `net.h2_header_order_vs_ua`), none with an automation floor — ALL evade the convicting layer HEADLESS with one
  legitimate coherent-UA fix. **Refines iter-8:** `br.headless_ua` holds against `--headless=new` (token persists)
  but is DEFEATED by an explicit coherent UA override — it is NOT a robust catch for the CDP-minimal class.
  Frontier (b): coherent UA-CH is legitimate (no FP-safe counter); the durable answer is the external-hardware-
  gated environment floor + coordination. **The catch-profile audit (iter-8→11) is complete:** 2 false EVADES
  assumptions refuted, 1 real headless evader built + generalized class-wide.
- **iter-12 (2026-06-20): catch-profile audit COMPLETE — selenium-driverless grounded, no new finding.**
  Grounded the last CDP-minimal tool live: `selenium-driverless` → `bot`, `br.headless_ua` alone (keeps the token,
  sends Sec-CH-UA, no automation floor) — same pattern as nodriver/pydoll/undetected. Its isolated-world execution
  produces NO per-session tell (confirms `br.isolated_world` is DEAD: the collector can't observe an isolated
  world). So the full CDP-minimal catch profile is grounded: {nodriver, pydoll, undetected, selenium-driverless} →
  `br.headless_ua`; {zendriver} → `net.h2_header_order_vs_ua`; ALL evade the convicting layer headless via the
  coherent-UA-CH override (grounded on zendriver-uach + nodriver-uach). The audit thread (iter-8→12) is closed:
  every EVADES/frontier claim grounded, 2 false assumptions refuted, 1 headless evader built + generalized.
  **In-sandbox red-team comprehensively saturated** — all remaining frontiers are external-data-gated (real
  hardware for the environment residual; real proxies for coordination IP-reputation).
- **iter-13 (2026-06-20): azuretls BUILT + grounded — another "redundant" inference REFUTED.** Built the
  `evaders/azuretls` evader (real Go TLS/JA3+H2 library, the 17th fleet tool). I had asserted it redundant with
  primp; grounded live it is caught by FOUR net tells (h2_header_order, sec_fetch, tcp_os, no_js_execution) — it
  forges the TLS handshake but NOT the HTTP request profile (no Sec-Fetch, non-Chromium h2 order / no Sec-CH-UA),
  the LEAST-faithful network template in the fleet. The audit lesson generalizes beyond EVADES claims to ANY
  ungrounded inference — "redundant" was wrong twice (azuretls here; --headless=new earlier). Validates the
  detector's network-coherence suite on a real third-party tool. Capture frozen.
