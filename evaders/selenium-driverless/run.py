# evaders/selenium-driverless/run — drive selenium-driverless through the edge and read the verdict.
# It executes in isolated worlds to dodge the Runtime.enable leak — a direct test of br.cdp_runtime_enabled.

from __future__ import annotations

import asyncio
import glob
import json
import os
import urllib.request

from selenium_driverless import webdriver

EDGE = os.environ.get("KITSUNE_EDGE", "https://edge:8443/")
DETECTOR = os.environ.get("KITSUNE_DETECTOR", "http://detector:8080")


async def main() -> None:
    chrome = sorted(glob.glob("/ms-playwright/chromium-*/chrome-linux/chrome"))[-1]
    options = webdriver.ChromeOptions()
    options.binary_location = chrome
    options.add_argument("--no-sandbox")
    options.add_argument("--ignore-certificate-errors")
    options.add_argument("--headless=new")  # no display in the container; new headless = closest to headful
    options.add_argument("--disable-dev-shm-usage")  # tiny /dev/shm in containers → Chrome won't start
    options.add_argument("--disable-gpu")
    async with webdriver.Chrome(options=options) as driver:
        await driver.get(EDGE)
        await asyncio.sleep(4)  # margin for the collector's async probes (WebRTC/audio) to POST
        cookies = await driver.get_cookies()
    sid = next((c["value"] for c in cookies if c.get("name") == "ks_sid"), None)
    if not sid:
        raise SystemExit("no ks_sid cookie")
    with urllib.request.urlopen(f"{DETECTOR}/verdict/{sid}") as resp:
        verdict = json.load(resp)
    print("__KS__" + json.dumps({"mode": "selenium-driverless", **verdict}))


if __name__ == "__main__":
    asyncio.run(main())
