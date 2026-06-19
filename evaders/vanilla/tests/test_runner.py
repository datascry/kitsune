# evaders/vanilla/tests/test_runner — tests for the live-flow runner.
# Mocks edge + detector via httpx MockTransport; covers success and the no-session error.

from __future__ import annotations

import httpx
import pytest

from kitsune_vanilla.runner import VanillaError, build_client, run_once


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


def test_build_client_default_has_no_faked_ua(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("KS_UA", raising=False)
    with build_client() as client:
        assert "User-Agent" not in client.headers or "httpx" in client.headers["user-agent"]


def test_build_client_ks_ua_fakes_browser(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KS_UA", "Mozilla/5.0 Chrome/125.0.0.0")
    with build_client() as client:
        assert client.headers["user-agent"] == "Mozilla/5.0 Chrome/125.0.0.0"


def test_build_client_http2_opt_in(monkeypatch: pytest.MonkeyPatch) -> None:
    # KS_HTTP2=1 negotiates HTTP/2 (exercises the env branch + proves the h2 stack is installed); default
    # stays HTTP/1.1. A naive h2 client faking a Chrome UA does not replicate Chrome's on-wire header order,
    # so the edge's h2_header_order_non_chromium signal can fire where Chrome-impersonating stacks defeat it.
    monkeypatch.delenv("KS_HTTP2", raising=False)
    with build_client() as default_client:
        assert isinstance(default_client, httpx.Client)
    monkeypatch.setenv("KS_HTTP2", "1")
    with build_client() as h2_client:  # raises ImportError if h2 is not installed
        assert isinstance(h2_client, httpx.Client)
