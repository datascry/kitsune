# evaders/camoufox/run — drive Camoufox (engine-level anti-detect Firefox) through the edge.
# Evaluates a C++-level fingerprint-spoofing browser vs the chromium tools; prints the verdict.

from __future__ import annotations

import json
import os
import random
import urllib.request

from camoufox.sync_api import Camoufox

EDGE = os.environ.get("KITSUNE_EDGE", "https://edge:8443/")
DETECTOR = os.environ.get("KITSUNE_DETECTOR", "http://detector:8080")
# KS_FAST=1: detection-only capture — skip the mouse simulation + fixed 2s wait and instead drive the
# collector's `?fast` path, completing the moment signals are POSTed (body[data-ks=sent]). Trades the
# behavioral layer (not needed for the single-Camoufox fingerprint test) for ~3s less per capture.
FAST = os.environ.get("KS_FAST") == "1"
# KS_REPEAT=N: capture N sessions from ONE browser launch (a fresh context each), amortizing the
# ~10s Camoufox cold-start — the dominant cost — across captures. Use for fast single-instance
# iteration. NOT for the fleet: Camoufox randomizes its JS fingerprint per *launch*, so contexts of
# one launch share a fingerprint and would not exhibit the cross-instance divergence a fleet shows.
REPEAT = max(1, int(os.environ.get("KS_REPEAT", "1")))
# KS_HEADFUL=1: run Camoufox *headful* inside a virtual display (Xvfb) instead of headless. Tests
# whether the per-session "capability" tells (no WebGL2, no TTS voices) are real spoofing flaws or
# just artifacts of a minimal headless container — a determined adversary runs headful with a stack.
HEADFUL = os.environ.get("KS_HEADFUL") == "1"
# KS_BASELINE=1: run *stock* Playwright Firefox (Camoufox's engine, but with NO spoofing) through the
# same pipeline — the control group. Rules that fire on the baseline too are environment/headless tells;
# rules that fire only on Camoufox are genuine anti-detect-spoofing tells. Keeps the detector honest.
BASELINE = os.environ.get("KS_BASELINE") == "1"
# KS_HARDENED=1: red-team the detector's own findings — apply Camoufox config to close every per-session tell
# Kitsune discovered. CORRECTED iter-28: the old config pinned os="windows" to dodge the macOS dpr/font tells,
# but Windows-on-a-Linux-host self-inflicts net.tcp_os_vs_ua (grounded live, it was the sole convicting tell).
# os="linux" dodges the macOS tells too AND is coherent with the host (no tcp_os). Also pin maxTouchPoints=0 to
# kill the ~7% pointer_touch flake, and keep WebRTC on to avoid webrtc_unavailable. (The old comment cited
# webgl_renderer_artifact as "unavoidable" — stale: that rule is dropped for the Gecko engine since v0.74.10.)
HARDENED = os.environ.get("KS_HARDENED") == "1"
# KS_MACOS=1: pin Camoufox to a macOS profile. Camoufox's bundled fonts.json `mac` list contains 49
# dot-prefixed internal system fonts (`.Aqua Kana`, `.Apple Color Emoji UI`, …) that a real Mac hides from
# web font enumeration; the macOS profile naively exposes the whole list, so they become web-measurable —
# the faithful tell for the (until now unexercised) `br.font_mac_internal` rule. HARDENED pins Windows
# precisely to dodge this; this mode does the opposite to LIGHT it.
MACOS = os.environ.get("KS_MACOS") == "1"
# KS_LINUX=1: pin Camoufox to a LINUX OS profile, COHERENT with the Linux container host. By default Camoufox
# RANDOMIZES the OS, often picking Windows/macOS → a non-Linux UA on a Linux TCP/IP stack → net.tcp_os_vs_ua
# (the sole convicting tell on headless Camoufox once the collector posts). Pinning Linux makes UA-OS == TCP-OS,
# so that tell goes quiet. Camoufox already patches navigator.webdriver at the ENGINE level (no webdriver_present,
# no webdriver_getter_tampered — the holdout that catches stock Playwright Firefox, see firefox-coherent) and
# speaks no CDP, so a Linux-pinned headless Camoufox should EVADE the convicting layer with NO xvfb — the
# lowest-bar EVADES (residual = the external-hardware-gated environment floor only).
LINUX = os.environ.get("KS_LINUX") == "1"
# KS_NOTOUCH=1: pin navigator.maxTouchPoints=0 (coherent desktop). The red-team counter to the headless
# CSS-pointer-media leak (br.pointer_touch_incoherent) — with KS_LINUX this turns the otherwise-caught headless
# Camoufox into an EVADES under the FULL collector (no xvfb). See main().
NOTOUCH = os.environ.get("KS_NOTOUCH") == "1"
# KS_TOUCH=1: force navigator.maxTouchPoints>0 on a DESKTOP profile — the INCOHERENT touch-desktop that trips
# br.pointer_touch_incoherent (maxTouchPoints says touch, but the CSS @media(any-pointer:coarse) Camoufox does
# NOT spoof says fine pointer). This is what Camoufox's default randomiser produces ~7% of launches; forcing it
# is the deterministic lit-record for that convicting rule (the coherence tell that keeps headless Camoufox at
# the headful bar unless maxTouchPoints is pinned to 0 — the inverse of KS_NOTOUCH).
TOUCH = os.environ.get("KS_TOUCH") == "1"
# KS_FPROTATE=1: the within-session BROWSER-fingerprint rotation attack. Camoufox's defining feature is per-LAUNCH
# fingerprint randomization; a scraper that restarts the browser mid-crawl while REUSING one site cookie (ks_sid)
# therefore presents DIVERGENT hardware-invariant fingerprints under ONE session — a single client whose CPU/GPU
# "changed", which no real browser does. This mode runs TWO Camoufox launches (distinct hardwareConcurrency, the
# deterministic stand-in for Camoufox's per-launch randomisation of that field) sharing one ks_sid: launch 1 mints
# the session, launch 2 reuses the cookie. The session ends up carrying two hardware_concurrency values -> the
# within-session analog of the JA4/IP/UA network-rotation triad, on the browser layer.
FPROTATE = os.environ.get("KS_FPROTATE") == "1"
# KS_BEHAVE=1: behavioral synthesis — a variable-velocity curved mouse path + varied-cadence keystrokes (the
# Gecko analog of zendriver's KS_BEHAVE). Composes with KS_HARDENED/KS_LINUX to ground the GECKO maximal stack
# (engine-spoof + coherent OS + behavioral synthesis) — the cross-layer-coherent identity, the STACK vein's
# Gecko corner that the Chromium zendriver-uach-behave already covers.
BEHAVE = os.environ.get("KS_BEHAVE") == "1"
_BASE_MODE = (
    "camoufox-hardened" if HARDENED
    else "baseline-firefox" if BASELINE
    else "camoufox-headful" if HEADFUL
    else "camoufox-macos" if MACOS
    else "camoufox-fp-rotation" if FPROTATE
    else "camoufox-touch-incoherent" if (LINUX and TOUCH)
    else "camoufox-linux-coherent" if (LINUX and NOTOUCH)
    else "camoufox-linux" if LINUX
    else "camoufox"
)
MODE = _BASE_MODE + ("-behave" if BEHAVE else "")
HARDENED_KW: dict[str, object] = {
    "os": "linux",  # coherent with the Linux host: dodges the macOS dpr/font tells AND net.tcp_os_vs_ua
    "block_webrtc": False,  # keep WebRTC → avoid webrtc_unavailable
    "config": {"navigator.maxTouchPoints": 0},  # coherent desktop → kill the ~7% pointer_touch_incoherent flake
    # NB: br.webgl_renderer_artifact (the ", or similar" Firefox WebGL generalisation) does NOT apply to Gecko —
    # detector.applicability drops it for ua_engine==firefox since v0.74.10, so it is NOT a Camoufox tell.
}


def _synth_behavior(page: object) -> None:
    """Behavioral synthesis (KS_BEHAVE): a variable-velocity curved mouse path + varied-cadence keystrokes.

    Richer than the fixed-step jitter: each segment uses a random step count and a skewed inter-move delay
    (the sigma-lognormal-ish timing that clears the biomech floor), and a typed phrase exercises the keystroke
    floor. Real motion varies per session, so this also avoids the self-inflicted trace_collision (iter-29).
    """
    x, y = 140.0, 160.0
    for _seg in range(6):
        tx = 120 + random.randint(0, 700)
        ty = 140 + random.randint(0, 400)
        steps = random.randint(6, 14)
        for s in range(steps):
            t = (s + 1) / steps
            # ease-in-out curve + perpendicular wobble → non-straight, non-constant-velocity
            ease = t * t * (3 - 2 * t)
            x = x + (tx - x) * ease * 0.5 + random.uniform(-3, 3)
            y = y + (ty - y) * ease * 0.5 + random.uniform(-3, 3)
            page.mouse.move(x, y)  # type: ignore[attr-defined]
            page.wait_for_timeout(random.choice([6, 9, 12, 16, 24, 40]))  # type: ignore[attr-defined]
    # Keystroke synthesis: varied inter-key delays + occasional think-pause (clears bh.keystroke_entropy_floor).
    for ch in "the quick brown fox":
        key = "Space" if ch == " " else f"Key{ch.upper()}"
        page.keyboard.press(key)  # type: ignore[attr-defined]
        page.wait_for_timeout(random.choice([55, 80, 95, 120, 150, 240]))  # type: ignore[attr-defined]


def _capture(browser: object) -> dict[str, object]:
    context = browser.new_context(ignore_https_errors=True)  # type: ignore[attr-defined]
    try:
        page = context.new_page()
        if FAST:
            page.goto(EDGE + ("&fast" if "?" in EDGE else "?fast"), wait_until="load")
            page.wait_for_selector("body[data-ks='sent']", timeout=8000)
        elif BEHAVE:
            page.goto(EDGE, wait_until="load")
            _synth_behavior(page)
            try:
                page.wait_for_selector("body[data-ks='sent']", timeout=8000)
            except Exception:  # noqa: BLE001 — fall back to a fixed wait if the marker never lands
                page.wait_for_timeout(2000)
        else:
            page.goto(EDGE, wait_until="load")
            # Per-instance RANDOM jitter on the pointer path: the trace_hash is coordinate-based (rounded x,y),
            # so a FIXED path makes a FLEET of instances emit one identical trace_hash → coordination._trace_
            # collision convicts the whole fleet `fleet` even though their fingerprints diverge (grounded iter-29).
            # Real bots vary their motion per session; jitter (distinct per container process) defeats the
            # self-inflicted trace collision so the fleet is only catchable by the external shared_real_ip leak.
            for i in range(24):
                page.mouse.move(100 + i * 7 + random.randint(-18, 18), 120 + (i % 5) * 12 + random.randint(-18, 18))
            # Wait for the collector's POST marker (body[data-ks='sent']), not a flat 2s — headless Camoufox's
            # collector posts later than 2s, which silently yielded 0 browser signals (a measurement bug that
            # made headless Camoufox look caught by net.no_js_execution; see camoufox-linux). Keeps the mouse.
            try:
                page.wait_for_selector("body[data-ks='sent']", timeout=8000)
            except Exception:  # noqa: BLE001 — fall back to a fixed wait if the marker never lands
                page.wait_for_timeout(2000)
        cookie = next((c for c in context.cookies() if c["name"] == "ks_sid"), None)
    finally:
        context.close()
    if cookie is None:
        raise SystemExit("no ks_sid cookie")
    with urllib.request.urlopen(f"{DETECTOR}/verdict/{cookie['value']}") as resp:
        verdict: dict[str, object] = json.load(resp)
    return verdict


def _run_baseline() -> None:
    """Control group: stock Playwright Firefox (same engine as Camoufox, no spoofing)."""
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = p.firefox.launch(headless=not HEADFUL)
        try:
            for _ in range(REPEAT):
                verdict = _capture(browser)
                print("__KS__" + json.dumps({"mode": MODE, **verdict}), flush=True)
        finally:
            browser.close()


def _capture_to_sid(browser: object, sid: str | None) -> str:
    """One page load through the edge; inject ``sid`` if given (cookie reuse), return the session id."""
    context = browser.new_context(ignore_https_errors=True)  # type: ignore[attr-defined]
    try:
        if sid is not None:
            context.add_cookies([{"name": "ks_sid", "value": sid, "url": EDGE}])
        page = context.new_page()
        page.goto(EDGE, wait_until="load")
        try:
            page.wait_for_selector("body[data-ks='sent']", timeout=8000)
        except Exception:  # noqa: BLE001 — fall back to a fixed wait if the marker never lands
            page.wait_for_timeout(2000)
        cookie = next((c for c in context.cookies() if c["name"] == "ks_sid"), None)
    finally:
        context.close()
    if cookie is None:
        raise SystemExit("no ks_sid cookie")
    return str(cookie["value"])


def _run_fprotate() -> None:
    """Two Camoufox launches (divergent hardwareConcurrency) sharing ONE ks_sid — within-session fp rotation.

    The UA is PINNED identical across both launches (the sophisticated re-randomiser keeps its network identity —
    IP/JA4/UA — stable, since rotating those is separately caught) so the ONLY divergence is the browser
    fingerprint, isolating br.fingerprint_unstable_within_session as the sole catch.
    """
    ua = "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0"
    pin_ua = {"general.useragent.override": ua}
    # Launch 1: a fresh random profile, hardwareConcurrency pinned to 4 — mints the session.
    with Camoufox(headless=True, os="linux", firefox_user_prefs=pin_ua, config={"navigator.hardwareConcurrency": 4}) as b1:  # type: ignore[arg-type]
        sid = _capture_to_sid(b1, None)
    # Launch 2: a SECOND fresh Camoufox (Camoufox re-randomises per launch), hardwareConcurrency pinned to 16,
    # REUSING the ks_sid cookie — so one session now carries two distinct hardware_concurrency values.
    with Camoufox(headless=True, os="linux", firefox_user_prefs=pin_ua, config={"navigator.hardwareConcurrency": 16}) as b2:  # type: ignore[arg-type]
        _capture_to_sid(b2, sid)
    with urllib.request.urlopen(f"{DETECTOR}/verdict/{sid}") as resp:
        verdict: dict[str, object] = json.load(resp)
    print("__KS__" + json.dumps({"mode": MODE, "session_id": sid, **verdict}), flush=True)


def main() -> None:
    if BASELINE:
        _run_baseline()
        return
    if FPROTATE:
        _run_fprotate()
        return
    kwargs: dict[str, object] = {"headless": "virtual" if HEADFUL else True}
    if HARDENED:
        kwargs.update(HARDENED_KW)
    if MACOS:
        kwargs["os"] = "macos"
    if os.environ.get("KS_NOWEBRTC") == "1":
        # The red-team COUNTER to coordination.shared_real_ip: block WebRTC so the proxied fleet leaks NO origin
        # IP → no webrtc_public_ip → no same-origin signal → the fleet drops from `fleet` to `candidate`. The cost
        # is the corroborating br.webrtc_unavailable (a real anti-detect tool disables WebRTC for exactly this
        # IP-leak reason). Grounded WITH a reachable STUN to prove the block works (not the no-STUN artifact).
        kwargs["block_webrtc"] = True
    proxy = os.environ.get("KS_PROXY")
    if proxy:
        # Route HTTPS through an HTTP CONNECT proxy → the edge sees the PROXY's IP as observed_ip. WebRTC's UDP
        # cannot traverse an HTTP proxy, so its STUN srflx reveals the REAL origin IP → net.webrtc_ip_vs_observed
        # (the proxied-bot WebRTC leak; a fleet sharing one origin → coordination shared_real_ip).
        kwargs["proxy"] = {"server": proxy}
    socks = os.environ.get("KS_SOCKS")
    if socks:
        # The COUNTER to the WebRTC leak (net.datacenter_origin_proxied / net.webrtc_ip_vs_observed): a SOCKS5
        # proxy carries UDP, so route BOTH HTTPS and WebRTC through it (media.peerconnection.ice.proxy_only) →
        # the STUN srflx shows the SOCKS proxy's IP, equal to observed_ip → no leak, and the proxy's reputation
        # (residential) — not the real machine's (datacenter) — is what the WebRTC reveals. The do-it-right bot.
        kwargs["proxy"] = {"server": socks}
        kwargs["firefox_user_prefs"] = {"media.peerconnection.ice.proxy_only": True}
    if LINUX:
        kwargs["os"] = "linux"  # coherent with the Linux host → silence net.tcp_os_vs_ua
    if NOTOUCH:
        # Camoufox's randomized profile sets navigator.maxTouchPoints > 0 (a touch device) but does NOT make the
        # CSS @media(any-pointer: coarse) query match → HEADLESS trips br.pointer_touch_incoherent (the catch that
        # otherwise keeps the bar at headful, iter-25). Pin a coherent DESKTOP profile (maxTouchPoints=0): with no
        # touch and the default fine pointer, cssTouch==jsTouch==false → the tell goes quiet. The red-team counter
        # to the CSS-pointer-media leak — grounded under the FULL collector (no ?fast, which under-probes).
        kwargs["config"] = {"navigator.maxTouchPoints": 0}
    if TOUCH:
        # Force the incoherent touch-desktop (maxTouchPoints > 0 but Camoufox leaves the CSS pointer fine) → the
        # deterministic lit-record for br.pointer_touch_incoherent.
        kwargs["config"] = {"navigator.maxTouchPoints": 5}
    with Camoufox(**kwargs) as browser:  # type: ignore[arg-type]
        for _ in range(REPEAT):
            verdict = _capture(browser)
            print("__KS__" + json.dumps({"mode": MODE, **verdict}), flush=True)


if __name__ == "__main__":
    main()
