# evaders/vanilla/tests/test_runner — tests for the live-flow runner.
# Mocks edge + detector via httpx MockTransport; covers success and the no-session error.

from __future__ import annotations

import httpx
import pytest

from kitsune_vanilla.runner import VanillaError, run_once


def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_run_once_returns_verdict() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, headers={"set-cookie": "ks_sid=sess-1; Path=/"})
        if request.url.path == "/verdict/sess-1":
            return httpx.Response(200, json={"session_id": "sess-1", "label": "human"})
        return httpx.Response(404)

    with _client(handler) as client:
        result = run_once("http://edge/", "http://detector", client=client)
    assert result["session_id"] == "sess-1"
    assert result["label"] == "human"


def test_run_once_without_cookie_raises() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200)

    with _client(handler) as client, pytest.raises(VanillaError, match="ks_sid"):
        run_once("http://edge/", "http://detector", client=client)
