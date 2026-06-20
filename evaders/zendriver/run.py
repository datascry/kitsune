# evaders/zendriver/run — drive zendriver (maintained nodriver successor) through the edge.
# CDP-based, no Selenium/webdriver; evaluates whether the current frontier fork closes any tell nodriver leaves.

from __future__ import annotations

import asyncio
import glob
import json
import math
import os
import random
import urllib.request

import zendriver as zd
from zendriver import cdp

EDGE = os.environ.get("KITSUNE_EDGE", "https://edge:8443/")
DETECTOR = os.environ.get("KITSUNE_DETECTOR", "http://detector:8080")
# KS_UACH=1: the cross-layer fix that turns zendriver into a HEADLESS evader of the convicting layer. Plain
# zendriver hides the HeadlessChrome UA token (its built-in stealth) but its UA override CLEARS the Sec-CH-UA
# client hints, so a Chrome UA carrying no Sec-CH-UA trip trips net.h2_header_order_vs_ua — a textbook
# single-layer-stealth-forgot-the-network-layer incoherence (a live third-party demonstration of the thesis).
# This mode sets a COHERENT UA-CH via CDP Network.setUserAgentOverride with full userAgentMetadata (UA string +
# Sec-CH-UA headers + getHighEntropyValues = one Linux-Chrome identity). zendriver already avoids the automation
# floor (no cdp_runtime / no_chrome / permissions tells, unlike patchright-headless), so once the UA-CH is
# coherent its only convicting tell is gone → it EVADES headless (no xvfb); residual is external-hardware-gated
# environment/behavioural corroboration only.
UACH = os.environ.get("KS_UACH") == "1"
# KS_BEHAVE=1: stack behavioral synthesis onto the clean-per-session UACH evader — the cross-layer capstone.
# zendriver-uach EVADES the convicting layer (no automation floor + coherent UA-CH), leaving a corroborating
# residual of TWO parts: behavioral (bh.input_entropy_floor + bh.no_input_before_action, because it sends ZERO
# input) and environment (webgl_software / voices_empty / media_devices_empty — external-hardware-gated). This
# mode injects a curved, varied-timing mouse path via CDP Input.dispatchMouseEvent (events the kernel marks
# isTrusted, unlike JS dispatchEvent), defeating the behavioral half → the residual collapses to ONLY the
# external-hardware-gated environment floor. Grounds the precise saturation boundary of in-sandbox evasion.
BEHAVE = os.environ.get("KS_BEHAVE") == "1"


async def _human_mouse(tab: object) -> None:
    """Dispatch a curved, varied-timing mouse path via CDP (trusted mousemove events the collector captures).

    A varied trajectory + jittered dwell lifts the movement entropy above bh.input_entropy_floor, and the
    non-zero pointer-event count clears bh.no_input_before_action — the behavioral analog of a real cursor.
    """
    x, y = 240.0, 220.0
    for i in range(30):
        x += 17 * math.cos(i / 3.0) + random.uniform(-7, 7)
        y += 13 * math.sin(i / 2.0) + random.uniform(-7, 7)
        await tab.send(cdp.input_.dispatch_mouse_event(type_="mouseMoved", x=x, y=y))  # type: ignore[attr-defined]
        await asyncio.sleep(0.018 + random.random() * 0.05)  # varied dwell → interval entropy


def _coherent_ua_override() -> object:
    v, fv = "149", "149.0.0.0"
    brand = cdp.emulation.UserAgentBrandVersion
    return cdp.network.set_user_agent_override(
        user_agent=f"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{fv} Safari/537.36",
        user_agent_metadata=cdp.emulation.UserAgentMetadata(
            platform="Linux",
            platform_version="6.5.0",
            architecture="x86",
            model="",
            mobile=False,
            bitness="64",
            wow64=False,
            brands=[brand(brand="Chromium", version=v), brand(brand="Google Chrome", version=v), brand(brand="Not.A/Brand", version="99")],
            full_version_list=[
                brand(brand="Chromium", version=fv),
                brand(brand="Google Chrome", version=fv),
                brand(brand="Not.A/Brand", version="99.0.0.0"),
            ],
            full_version=fv,
        ),
    )


async def main() -> None:
    chrome = sorted(glob.glob("/ms-playwright/chromium-*/chrome-linux/chrome"))[-1]
    browser = await zd.start(
        headless=True,
        browser_executable_path=chrome,
        browser_args=["--no-sandbox", "--ignore-certificate-errors"],
    )
    if UACH:
        tab = browser.main_tab or await browser.get("about:blank")
        await tab.send(_coherent_ua_override())  # coherent Sec-CH-UA before the edge request
    tab = await browser.get(EDGE)
    if BEHAVE:
        await _human_mouse(tab)  # behavioral synthesis before the collector's send window closes
    await asyncio.sleep(4)  # margin for the collector's async probes (WebRTC/audio) to POST
    cookies = await browser.cookies.get_all()
    sid = next((c.value for c in cookies if c.name == "ks_sid"), None)
    await browser.stop()
    if not sid:
        raise SystemExit("no ks_sid cookie")
    with urllib.request.urlopen(f"{DETECTOR}/verdict/{sid}") as resp:
        verdict = json.load(resp)
    mode = "zendriver-uach-behave" if (UACH and BEHAVE) else "zendriver-uach" if UACH else "zendriver"
    print("__KS__" + json.dumps({"mode": mode, **verdict}))


if __name__ == "__main__":
    asyncio.run(main())
