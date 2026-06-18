# evaders/nodriver/run — drive nodriver (undetected-chromedriver successor) through the edge.
# CDP-based, no Selenium/webdriver; evaluates its stealth on the matrix vs the other tools.

from __future__ import annotations

import asyncio
import glob
import json
import os
import urllib.request

import nodriver as uc

EDGE = os.environ.get("KITSUNE_EDGE", "https://edge:8443/")
DETECTOR = os.environ.get("KITSUNE_DETECTOR", "http://detector:8080")


async def main() -> None:
    chrome = sorted(glob.glob("/ms-playwright/chromium-*/chrome-linux/chrome"))[-1]
    browser = await uc.start(
        headless=True,
        browser_executable_path=chrome,
        browser_args=["--no-sandbox", "--ignore-certificate-errors"],
    )
    await browser.get(EDGE)
    await asyncio.sleep(3)
    cookies = await browser.cookies.get_all()
    sid = next((c.value for c in cookies if c.name == "ks_sid"), None)
    browser.stop()
    if not sid:
        raise SystemExit("no ks_sid cookie")
    with urllib.request.urlopen(f"{DETECTOR}/verdict/{sid}") as resp:
        verdict = json.load(resp)
    print("__KS__" + json.dumps({"mode": "nodriver", **verdict}))


uc.loop().run_until_complete(main())
