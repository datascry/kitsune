# evaders/curl-impersonate/run — drive curl_cffi (curl-impersonate) through the edge and read the verdict.
# Perfect browser TLS/HTTP-2/header mimicry with no JS: tests the limit of pure network-layer evasion.

from __future__ import annotations

import json
import os
import urllib.request

from curl_cffi import requests

EDGE = os.environ.get("KITSUNE_EDGE", "https://edge:8443/")
DETECTOR = os.environ.get("KITSUNE_DETECTOR", "http://detector:8080")


def main() -> None:
    # impersonate="chrome" gives a real recent-Chrome JA3/JA4, HTTP/2 SETTINGS, and the full browser
    # header set (Sec-Fetch-*, Accept, Accept-Encoding with br/zstd) — coherent at every network layer.
    resp = requests.get(EDGE, impersonate="chrome", verify=False, timeout=15)
    sid = resp.cookies.get("ks_sid")
    if not sid:
        raise SystemExit("no ks_sid cookie")
    with urllib.request.urlopen(f"{DETECTOR}/verdict/{sid}") as r:
        verdict = json.load(r)
    print("__KS__" + json.dumps({"mode": "curl-impersonate", **verdict}))


if __name__ == "__main__":
    main()
