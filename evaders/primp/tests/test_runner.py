# evaders/primp/tests/test_runner — tests for the live-flow runner.
# Mocks the edge + detector with a fake client; covers success, no-session error, profile choice.

from __future__ import annotations

from typing import Any

import pytest

from kitsune_primp.runner import PrimpError, run_once, select_impersonate


class _Resp:
    def __init__(self, headers: dict[str, str], payload: Any = None) -> None:
        self.headers = headers
        self._payload = payload

    def json(self) -> Any:
        return self._payload


class _Client:
    """Returns a Set-Cookie on the edge hit and the verdict JSON on the /verdict/ hit."""

    def __init__(self, *, cookie: str, verdict: dict[str, Any]) -> None:
        self._cookie = cookie
        self._verdict = verdict
        self.calls: list[str] = []

    def get(self, url: str) -> _Resp:
        self.calls.append(url)
        if "/verdict/" in url:
            return _Resp({}, self._verdict)
        return _Resp({"set-cookie": self._cookie})


def test_run_once_returns_verdict() -> None:
    client = _Client(
        cookie="ks_sid=abc123; Path=/",
        verdict={"session_id": "abc123", "label": "bot"},
    )
    result = run_once("https://edge:8443/healthz", "http://detector:8080", client=client)
    assert result["label"] == "bot"
    assert client.calls[-1] == "http://detector:8080/verdict/abc123"


def test_run_once_without_cookie_raises() -> None:
    client = _Client(cookie="", verdict={})
    with pytest.raises(PrimpError, match="ks_sid"):
        run_once("https://edge:8443/healthz", "http://detector:8080", client=client)


def test_select_impersonate_default() -> None:
    assert select_impersonate() == "chrome_146"


def test_select_impersonate_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KS_IMPERSONATE", "chrome_148")
    assert select_impersonate() == "chrome_148"
