# evaders/vanilla/runner — drive one request through the edge and read the verdict.
# The control: a plain HTTPS client with no evasion; establishes the detection floor.

"""Vanilla evader runner.

Makes a request through the transparent edge proxy (which fingerprints the TLS handshake and
forwards network signals to the detector), then reads the verdict back from the detector by the
``ks_sid`` session the edge minted. The ``httpx.Client`` is injected so the flow is fully testable.
"""

from __future__ import annotations

import os
from typing import Any

import httpx

NAME = "vanilla"
VERSION = "0.1.0"


class VanillaError(RuntimeError):
    """Raised when the live flow does not yield a correlated session."""


def run_once(edge_url: str, detector_url: str, *, client: httpx.Client) -> dict[str, Any]:
    """Hit the edge, recover the ``ks_sid`` session, and fetch the detector's verdict for it."""
    resp = client.get(edge_url)
    resp.raise_for_status()

    session_id = resp.cookies.get("ks_sid")
    if not session_id:
        raise VanillaError("edge did not set a ks_sid session cookie")

    verdict = client.get(f"{detector_url}/verdict/{session_id}")
    verdict.raise_for_status()
    result: dict[str, Any] = verdict.json()
    return result


def build_client() -> httpx.Client:
    """An httpx client that accepts the edge's self-signed cert (lab-only).

    ``KS_UA`` fakes a browser User-Agent over plain httpx (no Sec-Fetch headers) — the classic
    UA-spoofing scripted client that the edge's ``net.sec_fetch_vs_ua`` HTTP-layer tell catches.
    """
    headers = {}
    if ua := os.environ.get("KS_UA"):
        headers["User-Agent"] = ua
    return httpx.Client(verify=False, timeout=10.0, follow_redirects=True, headers=headers)
