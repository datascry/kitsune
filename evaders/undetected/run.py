# evaders/undetected/run — drive undetected-chromedriver through the edge and read the verdict.
# The classic Selenium-based anti-detect tool; compares against nodriver (its CDP-minimal successor).

from __future__ import annotations

import json
import os
import re
import subprocess
import time
import urllib.request

import undetected_chromedriver as uc  # type: ignore

EDGE = os.environ.get("KITSUNE_EDGE", "https://edge:8443/")
DETECTOR = os.environ.get("KITSUNE_DETECTOR", "http://detector:8080")


def _chrome_major() -> int | None:
    """The installed Chrome's major version, so UC fetches a matching patched chromedriver."""
    try:
        out = subprocess.check_output(["google-chrome", "--version"], text=True)
        m = re.search(r"(\d+)\.", out)
        return int(m.group(1)) if m else None
    except Exception:
        return None


def main() -> None:
    opts = uc.ChromeOptions()
    opts.add_argument("--no-sandbox")
    opts.add_argument("--ignore-certificate-errors")
    opts.add_argument("--disable-dev-shm-usage")  # containers have a tiny /dev/shm → Chrome crashes
    driver = uc.Chrome(options=opts, headless=True, version_main=_chrome_major())
    try:
        driver.get(EDGE)
        time.sleep(4)
        sid = next((c["value"] for c in driver.get_cookies() if c["name"] == "ks_sid"), None)
    finally:
        driver.quit()
    if not sid:
        raise SystemExit("no ks_sid cookie")
    with urllib.request.urlopen(f"{DETECTOR}/verdict/{sid}") as resp:
        verdict = json.load(resp)
    print("__KS__" + json.dumps({"mode": "undetected-chromedriver", **verdict}))


if __name__ == "__main__":
    main()
