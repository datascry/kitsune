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
ARENA_SOLVE = os.environ.get("KS_ARENA_SOLVE")  # e.g. "clock" — solve that arena gate in-session, paced (defeat)
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
# KS_REAL_INPUT=1: the behavioral TERMINUS fused into the coherent Gecko stack. Launch Camoufox headful on a
# real Xvfb display (the image entrypoint wraps in xvfb-run) and drive the cursor with GENUINE X-server input
# (XTEST via xdotool) — the browser receives hardware-originated motion, so getCoalescedEvents() batches for
# real and isTrusted holds by provenance (bh.synthetic_no_coalesced silent), with NO JS tamper. Composes with
# KS_HARDENED/KS_LINUX/KS_NOTOUCH to build the MAXIMAL coherent single-session stack: engine-level FP (network
# 0, no CDP) + coherent OS + real input (behavioral 0). The residual is then purely the environment floor.
REAL_INPUT = os.environ.get("KS_REAL_INPUT") == "1"
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
# KS_TASK: a JSON behavioral SCRIPT (the kitsune_harness.tasks DSL) the fleet manager passes per node — the
# Gecko executor of the same DSL zendriver runs, proving it is portable across automation backends (here
# sync Playwright/Firefox, not CDP). Replays {move:[x,y]}/{click:[x,y]}/{scroll:dy}/{type:"…"}/{wait:ms} so the
# captured session carries a real interaction flow. Supersedes KS_BEHAVE when set.
TASK = os.environ.get("KS_TASK")
# KS_TASK_SEED: pin the task executor's RNG so a FLEET replays the IDENTICAL humanized path → one shared
# trace_hash across nodes (the canned-replay / review-farm shape). The trace_hash is coordinate-based, so a
# fixed seed makes the per-instance jitter identical fleet-wide → coordination._trace_collision convicts even
# though the fingerprints diverge (camoufox randomizes them). Absent → distinct jitter per node (no collision).
TASK_SEED = os.environ.get("KS_TASK_SEED")
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
MODE = _BASE_MODE + ("-task" if TASK else "-realinput" if REAL_INPUT else "-behave" if BEHAVE else "")
HARDENED_KW: dict[str, object] = {
    "os": "linux",  # coherent with the Linux host: dodges the macOS dpr/font tells AND net.tcp_os_vs_ua
    "block_webrtc": False,  # keep WebRTC → avoid webrtc_unavailable
    # NB: br.webrtc_unavailable is NOT clearable by a browser pref in-sandbox — it is INFRA-BOUND. The collector's
    # STUN (stun.l.google.com) is unreachable with no egress, and disabling mDNS host-obfuscation still yields no
    # host candidate here (grounded), so ICE gathers nothing. Needs real network egress (or an in-network STUN the
    # collector would use), not a config. Left ON so a real-network deployment gathers candidates normally.
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


def _real_input_move(page: object) -> None:
    """Behavioral TERMINUS (KS_REAL_INPUT): drive the cursor with REAL X-server input (XTEST via xdotool)
    instead of Playwright's synthetic page.mouse, so Camoufox receives genuine hardware motion — real
    getCoalescedEvents() batches + isTrusted, no JS tamper (the Gecko twin of stealth's KS_REAL_INPUT). Page
    coords map to screen coords via the window's screenX/Y + chrome height; each burst of SUB sub-frame samples
    (~2ms apart) lands within one ~16ms frame so the browser coalesces it, and the inter-burst sleep crosses a
    frame boundary so each burst is a distinct primary pointermove carrying a real coalesced batch."""
    import subprocess
    import sys

    geo = page.evaluate(  # type: ignore[attr-defined]
        "() => ({ sx: window.screenX, sy: window.screenY,"
        " chromeH: Math.max(0, window.outerHeight - window.innerHeight),"
        " iw: window.innerWidth, ih: window.innerHeight })"
    )
    page.evaluate(  # type: ignore[attr-defined]  — passive probe: self-report the real coalescing
        "() => { window.__ksMoves=0; window.__ksMaxCo=0; window.__ksTrusted=true;"
        " addEventListener('pointermove', e => { window.__ksMoves++;"
        " if(!e.isTrusted) window.__ksTrusted=false;"
        " const n = e.getCoalescedEvents ? e.getCoalescedEvents().length : 0;"
        " if(n>window.__ksMaxCo) window.__ksMaxCo=n; }, {passive:true}); }"
    )

    def clamp(v: float, lo: float, hi: float) -> float:
        return min(hi, max(lo, v))

    def bezier(p0, p1, p2, p3, t):  # type: ignore[no-untyped-def]
        u = 1 - t
        return (
            u * u * u * p0[0] + 3 * u * u * t * p1[0] + 3 * u * t * t * p2[0] + t * t * t * p3[0],
            u * u * u * p0[1] + 3 * u * u * t * p1[1] + 3 * u * t * t * p2[1] + t * t * t * p3[1],
        )

    frames, sub = 30, 6  # >= 20 primary pointermoves (the coalesced rule's gate) with real sub-frame coalescing
    for _pass in range(2):  # two passes with a dwell → enough primary moves for the ptrMoves>=20 gate
        frm = (60 + random.random() * 140, 110 + random.random() * 140)
        to = (geo["iw"] * 0.45 + random.random() * geo["iw"] * 0.25, geo["ih"] * 0.4 + random.random() * geo["ih"] * 0.25)
        c1 = (frm[0] + (random.random() - 0.5) * geo["iw"] * 0.4, frm[1] + (random.random() - 0.5) * geo["ih"] * 0.4)
        c2 = (to[0] + (random.random() - 0.5) * geo["iw"] * 0.4, to[1] + (random.random() - 0.5) * geo["ih"] * 0.4)
        args: list[str] = []
        for f in range(frames):
            for s in range(sub):
                lin = (f + s / sub) / frames
                t = 2 * lin * lin if lin < 0.5 else 1 - ((-2 * lin + 2) ** 2) / 2  # ease-in-out velocity
                p = bezier(frm, c1, c2, to, t)
                sx = round(geo["sx"] + clamp(p[0] + (random.random() - 0.5) * 2, 5, geo["iw"] - 5))
                sy = round(geo["sy"] + geo["chromeH"] + clamp(p[1] + (random.random() - 0.5) * 2, 5, geo["ih"] - 5))
                args += ["mousemove", str(sx), str(sy), "sleep", "0.002"]
            args += ["sleep", "0.013"]  # ~one frame between bursts → each is a distinct coalesced primary event
        args += ["click", "1"]
        subprocess.run(["xdotool", *args], check=False)  # noqa: S603,S607
        page.wait_for_timeout(180 + random.randint(0, 220))  # type: ignore[attr-defined]
    probe = page.evaluate("() => ({moves: window.__ksMoves, maxCo: window.__ksMaxCo, trusted: window.__ksTrusted})")  # type: ignore[attr-defined]
    print(f"real-input: {probe['moves']} pointermoves, max coalesced batch {probe['maxCo']}, isTrusted={probe['trusted']}", file=sys.stderr)


def _run_task(page: object, steps: list[dict]) -> None:
    """Replay a behavioral task script (the harness DSL) via sync Playwright/Firefox input — the Gecko twin of
    zendriver's CDP _run_task. Each step is best-effort so a flaky action never loses the session."""
    if TASK_SEED is not None:
        random.seed(int(TASK_SEED))  # canned replay: identical jittered path fleet-wide → shared trace_hash
    x, y = 200.0, 200.0
    for step in steps:
        try:
            ((action, param),) = step.items()
            if action in ("move", "click"):
                tx, ty = float(param[0]), float(param[1])
                steps_n = random.randint(8, 14)
                for s in range(steps_n):  # curved, non-constant-velocity path (clears the biomech floor)
                    t = (s + 1) / steps_n
                    ease = t * t * (3 - 2 * t)
                    x += (tx - x) * ease * 0.5 + random.uniform(-3, 3)
                    y += (ty - y) * ease * 0.5 + random.uniform(-3, 3)
                    page.mouse.move(x, y)  # type: ignore[attr-defined]
                    page.wait_for_timeout(random.choice([6, 9, 12, 16, 24]))  # type: ignore[attr-defined]
                x, y = tx, ty
                if action == "click":
                    page.mouse.click(x, y)  # type: ignore[attr-defined]
            elif action == "scroll":
                page.mouse.wheel(0, float(param))  # type: ignore[attr-defined]
                page.wait_for_timeout(random.randint(80, 160))  # type: ignore[attr-defined]
            elif action == "type":
                page.keyboard.type(str(param), delay=random.randint(40, 90))  # type: ignore[attr-defined]
            elif action == "wait":
                page.wait_for_timeout(int(param))  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001 — one flaky step never loses the session
            continue


_ARENA_CLOCK_JS = r"""
async () => {
  const c = await (await fetch("/arena/captcha?kind=clock&level=easy")).json();
  const bytes = Uint8Array.from(atob(c.image.split(",")[1]), (ch) => ch.charCodeAt(0));
  const bmp = await createImageBitmap(new Blob([bytes], { type: "image/png" }));
  const cv = document.createElement("canvas"); cv.width = 100; cv.height = 100;
  const ctx = cv.getContext("2d", { willReadFrequently: true }); ctx.drawImage(bmp, 0, 0);
  const px = ctx.getImageData(0, 0, 100, 100).data;
  const dark = (x, y) => { const i = (y * 100 + x) * 4; return px[i] < 110 && px[i+1] < 110 && px[i+2] < 110; };
  const reach = [];
  for (let a = 0; a < 360; a++) {
    const rad = a * Math.PI / 180, dx = Math.sin(rad), dy = -Math.cos(rad); let run = 0, miss = 0;
    for (let d = 3; d < 40; d++) { const x = Math.round(50 + d*dx), y = Math.round(50 + d*dy);
      if (x>=0&&x<100&&y>=0&&y<100&&dark(x,y)) { run=d; miss=0; } else { miss++; if (miss>2) break; } }
    reach[a] = run;
  }
  let ma = 0; for (let a=0;a<360;a++) if (reach[a]>reach[ma]) ma=a;
  let ha = 0; for (let a=0;a<360;a++) { const dd=Math.min(Math.abs(a-ma),360-Math.abs(a-ma)); if (dd>18&&reach[a]>reach[ha]) ha=a; }
  const minute = Math.round(ma/6)%60; let hour = Math.round(ha/30 - minute/60)%12; if (hour===0) hour=12;
  const answer = hour + ":" + String(minute).padStart(2, "0");
  await new Promise((r) => setTimeout(r, 2600));  // PACE past the 800ms clock floor
  const v = await (await fetch("/arena/captcha/verify", { method: "POST",
    headers: {"content-type":"application/json"}, body: JSON.stringify({kind:"clock", id:c.id, answer}) })).json();
  return { answer, ok: v.ok, anomaly: v.anomaly ?? null, token: !!v.token };
}
"""


_ARENA_SPATIAL_JS = r"""
async () => {
  const s = await (await fetch("/arena/spatial?level=easy")).json();
  const COLORS = {red:[220,50,50],green:[50,170,70],blue:[60,90,220],yellow:[225,195,40],orange:[235,140,40],purple:[150,70,200]};
  const target = s.prompt.match(/with the (\w+) face/)[1];
  const selected = [];
  for (let i = 0; i < s.tiles.length; i++) {
    const bytes = Uint8Array.from(atob(s.tiles[i].image.split(",")[1]), (ch) => ch.charCodeAt(0));
    const bmp = await createImageBitmap(new Blob([bytes], { type: "image/png" }));
    const cv = document.createElement("canvas"); cv.width = 64; cv.height = 64;
    const ctx = cv.getContext("2d", { willReadFrequently: true }); ctx.drawImage(bmp, 0, 0);
    const px = ctx.getImageData(0, 0, 64, 64).data;
    let acc = [0,0,0], n = 0;
    for (let y = 22; y < 29; y++) for (let x = 29; x < 36; x++) {
      const idx = (y*64+x)*4; acc[0]+=px[idx]; acc[1]+=px[idx+1]; acc[2]+=px[idx+2]; n++; }
    const avg = [acc[0]/n, acc[1]/n, acc[2]/n];
    let best = null, bd = 1e9;
    for (const k in COLORS) { const d = COLORS[k].reduce((sm,c,j) => sm+(avg[j]-c)**2, 0); if (d<bd){bd=d;best=k;} }
    if (best === target) selected.push(i);
  }
  await new Promise((r) => setTimeout(r, 2000));  // PACE past the 500ms spatial floor
  const v = await (await fetch("/arena/spatial/verify", { method: "POST",
    headers: {"content-type":"application/json"}, body: JSON.stringify({id:s.id, selected}) })).json();
  return { target, selected, ok: v.ok, anomaly: v.anomaly ?? null, token: !!v.token };
}
"""


def _arena_solve_audio(page: object) -> dict[str, object]:
    # The audio (ASR) gate: fetch the clip IN-SESSION, matched-filter it against the mounted FSDD templates
    # (numpy) to transcribe the digits, then verify IN-SESSION paced past the real-time-playback floor. The
    # solve is Python compute; the mint + verify stay in the browser so the session is coherent + JS-executed.
    import base64
    import glob
    import io
    import wave

    import numpy as np

    fsdd = os.environ.get("FSDD_DIR", "/fsdd")
    templates: list[tuple[int, object]] = []
    for f in sorted(glob.glob(os.path.join(fsdd, "*.wav"))):
        w = wave.open(f)
        s = np.frombuffer(w.readframes(w.getnframes()), dtype=np.int16).astype(np.float32)
        templates.append((int(os.path.basename(f)[0]), s / (np.linalg.norm(s) + 1e-9)))
    ch = page.evaluate(  # type: ignore[attr-defined]
        '() => fetch("/arena/audio?level=easy").then(r => r.json())'
        ".then(c => ({ id: c.id, clip: c.clip, digits: c.digits }))"
    )
    raw = base64.b64decode(str(ch["clip"]).split(",", 1)[1])
    w = wave.open(io.BytesIO(raw))
    clip = np.frombuffer(w.readframes(w.getnframes()), dtype=np.int16).astype(np.float32)
    n = int(ch["digits"])
    peaks = []
    for digit, tn in templates:
        if len(clip) < len(tn):
            continue
        # NORMALIZED cross-correlation: divide by the local clip energy so the best-MATCHING digit wins at each
        # position, not the loudest region. Lifts the easy pass rate ~13% -> ~100% (grounded), so no retries.
        dot = np.correlate(clip, tn, mode="valid")
        energy = np.sqrt(np.convolve(clip**2, np.ones(len(tn)), mode="valid")) + 1e-9
        score = dot / energy
        p = int(np.argmax(score))
        peaks.append((float(score[p]), p, digit))
    peaks.sort(reverse=True)
    chosen: list[tuple[float, int, int]] = []
    for sc, pos, digit in peaks:
        if all(abs(pos - q) > 3000 for _, q, _ in chosen):
            chosen.append((sc, pos, digit))
        if len(chosen) == n:
            break
    chosen.sort(key=lambda x: x[1])
    answer = "".join(str(d) for _, _, d in chosen)
    v: dict[str, object] = page.evaluate(  # type: ignore[attr-defined]
        "async (a) => { await new Promise((r) => setTimeout(r, 3000));"  # PACE past the playback floor
        ' const v = await (await fetch("/arena/audio/verify", { method: "POST",'
        ' headers: {"content-type":"application/json"}, body: JSON.stringify({id:a.id, answer:a.answer}) })).json();'
        " return { ok: v.ok, anomaly: v.anomaly ?? null, token: !!v.token }; }",
        {"id": ch["id"], "answer": answer},
    )
    return {"answer": answer, "digits": n, **v}


def _arena_solve(page: object, kind: str) -> dict[str, object]:
    # Solve an arena gate IN-SESSION (same origin as the collector), paced past the human floor. The verify rides
    # the edge->detector relay so the anomaly-join sees a HUMAN-paced correct solve (no arena_*_superhuman).
    if kind == "audio":
        return _arena_solve_audio(page)
    js = {"clock": _ARENA_CLOCK_JS, "spatial": _ARENA_SPATIAL_JS}.get(kind)
    if js is None:
        return {"error": f"unsupported arena kind {kind}"}
    result: dict[str, object] = page.evaluate(js)  # type: ignore[attr-defined]
    return result


def _capture(browser: object) -> dict[str, object]:
    context = browser.new_context(ignore_https_errors=True)  # type: ignore[attr-defined]
    arena_result: dict[str, object] | None = None
    try:
        page = context.new_page()
        if FAST:
            page.goto(EDGE + ("&fast" if "?" in EDGE else "?fast"), wait_until="load")
            page.wait_for_selector("body[data-ks='sent']", timeout=8000)
        elif TASK:
            page.goto(EDGE, wait_until="load")
            _run_task(page, json.loads(TASK))  # the scripted behavioral flow (supersedes KS_BEHAVE)
            try:
                page.wait_for_selector("body[data-ks='sent']", timeout=8000)
            except Exception:  # noqa: BLE001 — fall back to a fixed wait if the marker never lands
                page.wait_for_timeout(2000)
        elif REAL_INPUT:
            page.goto(EDGE, wait_until="load")
            _real_input_move(page)  # GENUINE XTEST input (headful on Xvfb) — real coalesced batches, isTrusted
            try:
                page.wait_for_selector("body[data-ks='sent']", timeout=8000)
            except Exception:  # noqa: BLE001 — fall back to a fixed wait if the marker never lands
                page.wait_for_timeout(2000)
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
        if ARENA_SOLVE:
            # one kind -> the result directly (back-compat); "all" or a comma list -> solve each on ONE ks_sid,
            # proving a single coherent session defeats the WHOLE latest arena (clock + spatial + audio).
            kinds = ["clock", "spatial", "audio"] if ARENA_SOLVE == "all" else [k.strip() for k in ARENA_SOLVE.split(",")]
            solved = {k: _arena_solve(page, k) for k in kinds}
            arena_result = solved[kinds[0]] if len(kinds) == 1 else solved
        cookie = next((c for c in context.cookies() if c["name"] == "ks_sid"), None)
    finally:
        context.close()
    if cookie is None:
        raise SystemExit("no ks_sid cookie")
    with urllib.request.urlopen(f"{DETECTOR}/verdict/{cookie['value']}") as resp:
        verdict: dict[str, object] = json.load(resp)
    if arena_result is not None:
        verdict["arena"] = arena_result
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
    # REAL_INPUT runs headful (headless=False) on the real Xvfb display the entrypoint's xvfb-run provides, so
    # xdotool's XTEST motion lands in the on-screen Firefox window; HEADFUL uses Camoufox's own virtual display.
    kwargs: dict[str, object] = {"headless": False if REAL_INPUT else "virtual" if HEADFUL else True}
    if HARDENED:
        kwargs.update(HARDENED_KW)
    if MACOS:
        kwargs["os"] = "macos"
        # Real macOS is Retina (devicePixelRatio >= 2); Camoufox headless reports DPR 1 → br.macos_dpr1. Pin DPR 2
        # at the ENGINE level (all realms, unlike a JS patch) so the macOS profile is coherent on the backing scale
        # too — evades macos_dpr1, the DPR half of the device manifold. Merges with any existing config.
        _cfg: dict[str, object] = dict(kwargs.get("config") or {})  # type: ignore[arg-type]
        _cfg["window.devicePixelRatio"] = 2.0
        kwargs["config"] = _cfg
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
    if os.environ.get("KS_LLVMPIPE") == "1":
        # Fall the GPU-caps wall in software, and be PROFILE-DRIVEN. camoufox's default webgl fingerprint can pair a
        # real-GPU renderer STRING with a WRONG MAX_TEXTURE_SIZE (its "Apple M1" DB entry reports 8192 though a real
        # M1 exposes 16384) → br.webgl_renderer_caps_mismatch. Pin a webgl_config whose DB entry carries a COHERENT
        # 16384 cap, and render on Mesa llvmpipe (16384, RAM-backed) so the claim also genuinely ALLOCATES →
        # br.webgl_maxtexture_unallocatable stays silent. The composer sets KS_OS + KS_WEBGL_VENDOR + KS_WEBGL_RENDERER
        # from a unified profile; the default (no env) is a Windows NVIDIA GTX 980. Set GALLIUM_DRIVER=llvmpipe in env.
        kwargs["os"] = os.environ.get("KS_OS", "windows")
        _v = os.environ.get("KS_WEBGL_VENDOR")
        _r = os.environ.get("KS_WEBGL_RENDERER")
        kwargs["webgl_config"] = (
            (_v, _r)
            if _v and _r
            else ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce GTX 980 Direct3D11 vs_5_0 ps_5_0), or similar")
        )
        if kwargs["os"] == "macos":
            # A profile-driven macOS morph (KS_OS=macos, distinct from the KS_MACOS knob above) must also be Retina —
            # a real Mac is DPR >= 2; Camoufox defaults to 1 → br.macos_dpr1. Pin DPR 2 at the engine level (all realms).
            _cfg_mac: dict[str, object] = dict(kwargs.get("config") or {})  # type: ignore[arg-type]
            _cfg_mac["window.devicePixelRatio"] = 2.0
            kwargs["config"] = _cfg_mac
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
    if os.environ.get("KS_PROVISION") == "1":
        # Real WebRTC: enable peer connections and expose host ICE candidates (no mDNS obfuscation) so the
        # collector's RTCPeerConnection gathers a genuine candidate → br.webrtc_unavailable goes silent. The
        # host candidate equals observed_ip (no proxy here), so no webrtc_ip_vs_observed leak. Merges with prefs.
        prefs: dict[str, object] = dict(kwargs.get("firefox_user_prefs") or {})  # type: ignore[arg-type]
        prefs.update(
            {
                "media.peerconnection.enabled": True,
                "media.peerconnection.ice.obfuscate_host_addresses": False,
                "media.navigator.enabled": True,
            }
        )
        kwargs["firefox_user_prefs"] = prefs
    with Camoufox(**kwargs) as browser:  # type: ignore[arg-type]
        for _ in range(REPEAT):
            verdict = _capture(browser)
            print("__KS__" + json.dumps({"mode": MODE, **verdict}), flush=True)


if __name__ == "__main__":
    main()
