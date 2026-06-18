# evaders/pydoll/run — drive pydoll (async CDP-native, no webdriver) through the edge and read the verdict.
# A distinct tool family from the nodriver/Selenium lines; completes the open-source anti-detect survey.

from __future__ import annotations

import asyncio
import glob
import json
import os
import re
import urllib.request

from pydoll.browser.chromium import Chrome
from pydoll.browser.options import ChromiumOptions

EDGE = os.environ.get("KITSUNE_EDGE", "https://edge:8443/")
DETECTOR = os.environ.get("KITSUNE_DETECTOR", "http://detector:8080")


def _find_sid(cookies: object) -> str | None:
    """Pull ks_sid out of whatever shape pydoll's cookie API returns (list of dicts or objects)."""
    for c in cookies or []:  # type: ignore[union-attr]
        name = c.get("name") if isinstance(c, dict) else getattr(c, "name", None)
        if name == "ks_sid":
            return c.get("value") if isinstance(c, dict) else getattr(c, "value", None)
    return None


async def _sid(tab: object, browser: object) -> str | None:
    for getter in (getattr(tab, "get_cookies", None), getattr(browser, "get_cookies", None)):
        if getter is None:
            continue
        try:
            sid = _find_sid(await getter())
            if sid:
                return sid
        except Exception:
            pass
    # Fallback: ks_sid is not HttpOnly (the collector reads it), so it is in document.cookie.
    try:
        res = await tab.execute_script("return document.cookie")  # type: ignore[attr-defined]
        m = re.search(r"ks_sid=([0-9a-fA-F]+)", json.dumps(res))
        return m.group(1) if m else None
    except Exception:
        return None


async def main() -> None:
    chrome = sorted(glob.glob("/ms-playwright/chromium-*/chrome-linux/chrome"))[-1]
    options = ChromiumOptions()
    options.binary_location = chrome
    for arg in ("--no-sandbox", "--ignore-certificate-errors", "--headless=new", "--disable-dev-shm-usage", "--disable-gpu"):
        options.add_argument(arg)
    async with Chrome(options=options) as browser:
        tab = await browser.start()
        await tab.go_to(EDGE)
        await asyncio.sleep(4)  # margin for the collector's async probes (WebRTC/audio) to POST
        sid = await _sid(tab, browser)
    if not sid:
        raise SystemExit("no ks_sid cookie")
    with urllib.request.urlopen(f"{DETECTOR}/verdict/{sid}") as resp:
        verdict = json.load(resp)
    print("__KS__" + json.dumps({"mode": "pydoll", **verdict}))


if __name__ == "__main__":
    asyncio.run(main())
