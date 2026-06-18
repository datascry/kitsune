# evaders/zendriver/run — drive zendriver (maintained nodriver successor) through the edge.
# CDP-based, no Selenium/webdriver; evaluates whether the current frontier fork closes any tell nodriver leaves.

from __future__ import annotations

import asyncio
import glob
import json
import os
import urllib.request

import zendriver as zd

EDGE = os.environ.get("KITSUNE_EDGE", "https://edge:8443/")
DETECTOR = os.environ.get("KITSUNE_DETECTOR", "http://detector:8080")


async def main() -> None:
    chrome = sorted(glob.glob("/ms-playwright/chromium-*/chrome-linux/chrome"))[-1]
    browser = await zd.start(
        headless=True,
        browser_executable_path=chrome,
        browser_args=["--no-sandbox", "--ignore-certificate-errors"],
    )
    await browser.get(EDGE)
    await asyncio.sleep(4)  # margin for the collector's async probes (WebRTC/audio) to POST
    cookies = await browser.cookies.get_all()
    sid = next((c.value for c in cookies if c.name == "ks_sid"), None)
    await browser.stop()
    if not sid:
        raise SystemExit("no ks_sid cookie")
    with urllib.request.urlopen(f"{DETECTOR}/verdict/{sid}") as resp:
        verdict = json.load(resp)
    print("__KS__" + json.dumps({"mode": "zendriver", **verdict}))


if __name__ == "__main__":
    asyncio.run(main())
