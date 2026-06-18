# evaders/camoufox/run — drive Camoufox (engine-level anti-detect Firefox) through the edge.
# Evaluates a C++-level fingerprint-spoofing browser vs the chromium tools; prints the verdict.

from __future__ import annotations

import json
import os
import urllib.request

from camoufox.sync_api import Camoufox

EDGE = os.environ.get("KITSUNE_EDGE", "https://edge:8443/")
DETECTOR = os.environ.get("KITSUNE_DETECTOR", "http://detector:8080")


def main() -> None:
    with Camoufox(headless=True) as browser:
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()
        page.goto(EDGE, wait_until="load")
        for i in range(24):
            page.mouse.move(100 + i * 7, 120 + (i % 5) * 12)
        page.wait_for_timeout(2000)
        cookie = next((c for c in context.cookies() if c["name"] == "ks_sid"), None)

    if cookie is None:
        raise SystemExit("no ks_sid cookie")
    with urllib.request.urlopen(f"{DETECTOR}/verdict/{cookie['value']}") as resp:
        verdict = json.load(resp)
    print("__KS__" + json.dumps({"mode": "camoufox", **verdict}))


if __name__ == "__main__":
    main()
