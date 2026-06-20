# evaders/camoufox/run — drive Camoufox (engine-level anti-detect Firefox) through the edge.
# Evaluates a C++-level fingerprint-spoofing browser vs the chromium tools; prints the verdict.

from __future__ import annotations

import json
import os
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
# KS_HARDENED=1: red-team the detector's own findings — apply Camoufox config to fix the spoof-specific
# tells Kitsune discovered (pin OS to Windows to avoid the macOS-only dPR/font tells, re-enable WebRTC to
# avoid webrtc_unavailable, set a clean WebGL renderer with no ", or similar" artifact). Measures what the
# detector still catches once an adversary closes every per-session tell it knows about.
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
MODE = (
    "camoufox-hardened" if HARDENED
    else "baseline-firefox" if BASELINE
    else "camoufox-headful" if HEADFUL
    else "camoufox-macos" if MACOS
    else "camoufox-linux" if LINUX
    else "camoufox"
)
HARDENED_KW: dict[str, object] = {
    "os": "windows",  # avoid macOS-draw tells (macos_dpr1, font_mac_internal)
    "block_webrtc": False,  # re-enable WebRTC → avoid webrtc_unavailable
    # Note: webgl_config can only PICK from Camoufox's webgl_data.db, and every renderer in it carries the
    # ", or similar" suffix — so webgl_renderer_artifact is unavoidable via config (a fundamental tell).
}


def _capture(browser: object) -> dict[str, object]:
    context = browser.new_context(ignore_https_errors=True)  # type: ignore[attr-defined]
    try:
        page = context.new_page()
        if FAST:
            page.goto(EDGE + ("&fast" if "?" in EDGE else "?fast"), wait_until="load")
            page.wait_for_selector("body[data-ks='sent']", timeout=8000)
        else:
            page.goto(EDGE, wait_until="load")
            for i in range(24):
                page.mouse.move(100 + i * 7, 120 + (i % 5) * 12)
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


def main() -> None:
    if BASELINE:
        _run_baseline()
        return
    kwargs: dict[str, object] = {"headless": "virtual" if HEADFUL else True}
    if HARDENED:
        kwargs.update(HARDENED_KW)
    if MACOS:
        kwargs["os"] = "macos"
    if LINUX:
        kwargs["os"] = "linux"  # coherent with the Linux host → silence net.tcp_os_vs_ua
    with Camoufox(**kwargs) as browser:  # type: ignore[arg-type]
        for _ in range(REPEAT):
            verdict = _capture(browser)
            print("__KS__" + json.dumps({"mode": MODE, **verdict}), flush=True)


if __name__ == "__main__":
    main()
