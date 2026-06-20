# evaders/xtest-coalesce/probe — pressure-test: can X11 XTEST motion injection defeat the coalesced tell?
# Injects TRUSTED X11 motion under Xvfb into a headful browser, measures getCoalescedEvents — grounds the terminus.

"""Behavioral pressure-test for the coalesced-events ladder (bh.synthetic_no_coalesced / br.coalesced_untrusted).

The detector's coalesced terminus was grounded only against CDP dispatch (downstream of the browser's
coalescing stage → 0 coalesced). This probes the OTHER software path: X11 XTEST injection, which enters the
input pipeline UPSTREAM (where real hardware does). The hypothesis: XTEST motion is trusted AND high-rate, so
it might coalesce — defeating both coalesced tells without real hardware.

GROUNDED RESULT (2026-06-20, Chromium + Firefox under Xvfb): XTEST motion arrives TRUSTED but
max_coalesced == 0 — X11 motion compression discards the intermediate samples before the browser's
coalescing stage, so each frame delivers ONE position and getCoalescedEvents() is empty. So XTEST still
trips bh.synthetic_no_coalesced (coalescedMax <= 1). The stronger path, a uinput kernel device (evdev), is
architecturally excluded under Xvfb (a virtual X server has no evdev/libinput input driver; that needs
Xorg+libinput — a real-hardware-like display stack). So the terminus HOLDS, now grounded against three
mechanisms (CDP / XTEST / uinput-path), not just CDP: defeating the coalesced tell needs a real input stack.

Run (self-contained): python /probe/probe.py inside an Xvfb-capable Playwright image; it pip-installs
python-xlib + playwright and prints `XTEST_RESULT engine=… max_coalesced=… any_untrusted=… …`.
"""

from __future__ import annotations

import os
import subprocess
import time

_PAGE = """<!doctype html><html><body style='margin:0;width:100vw;height:100vh'>
<script>window.__max=0;window.__untrusted=false;window.__count=0;
addEventListener('pointermove',function(e){window.__count++;var c=e.getCoalescedEvents();
if(c.length>window.__max)window.__max=c.length;
if(c.length>1&&c.some(function(v){return v.isTrusted===false;}))window.__untrusted=true;},{passive:true});
</script></body></html>"""


def _run(engine: str) -> None:
    from playwright.sync_api import sync_playwright
    from Xlib import X, display
    from Xlib.ext import xtest

    with sync_playwright() as p:
        try:
            browser = getattr(p, engine).launch(headless=False)
        except Exception as exc:  # a missing browser in the image — skip, not a result
            print(f"XTEST_RESULT engine={engine} SKIP ({type(exc).__name__})", flush=True)
            return
        page = browser.new_page(viewport={"width": 1280, "height": 1024})
        page.set_content(_PAGE)
        page.wait_for_timeout(600)
        d = display.Display()
        # 15 XTEST motions per frame for 50 frames — a burst within one frame is exactly what the browser
        # coalesces for real hardware. d.sync() flushes the burst; the frame wait lets the page dispatch.
        for frame in range(50):
            for i in range(15):
                px = 200 + (frame * 15 + i) % 700
                py = 300 + ((frame * 13 + i) // 2) % 300
                xtest.fake_input(d, X.MotionNotify, x=px, y=py)
            d.sync()
            page.wait_for_timeout(16)
        mx = page.evaluate("window.__max")
        unt = page.evaluate("window.__untrusted")
        cnt = page.evaluate("window.__count")
        print(
            f"XTEST_RESULT engine={engine} max_coalesced={mx} any_untrusted={unt} pointermove_count={cnt}",
            flush=True,
        )
        browser.close()


def main() -> None:
    os.environ["DISPLAY"] = ":99"
    os.environ.setdefault("PLAYWRIGHT_BROWSERS_PATH", "/ms-playwright")
    xvfb = subprocess.Popen(["Xvfb", ":99", "-screen", "0", "1280x1024x24"])
    time.sleep(2.0)
    subprocess.run(
        ["pip", "install", "--no-cache-dir", "python-xlib"],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    for engine in ("chromium", "firefox"):
        try:
            _run(engine)
        except Exception as exc:  # a probe; report and continue to the next engine
            print(f"XTEST_RESULT engine={engine} ERROR {type(exc).__name__}: {exc}", flush=True)
    xvfb.terminate()


if __name__ == "__main__":
    main()
