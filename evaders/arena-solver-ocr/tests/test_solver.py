# evaders/arena-solver-ocr/tests/test_solver — the OCR evasion flow, tested without any ML model.
# A stub recognizer + a MockTransport fake gate cover allow-list, data-URI decode, and the solve/verify flow.

from __future__ import annotations

import base64
import json

import httpx
import pytest
from kitsune_arena_ocr import EthicsError, decode_png_data_uri, is_own_target, solve_text


class _StubRecognizer:
    def __init__(self, text: str) -> None:
        self._text = text

    def recognize(self, png: bytes) -> str:
        return self._text


def _png_data_uri(payload: bytes = b"\x89PNG\r\n\x1a\n") -> str:
    return "data:image/png;base64," + base64.b64encode(payload).decode()


def test_is_own_target() -> None:
    assert is_own_target("http://detector:8080")
    assert is_own_target("https://edge:8443/")
    assert not is_own_target("https://challenges.cloudflare.com/")
    assert not is_own_target("not-a-url")


def test_decode_png_data_uri() -> None:
    assert decode_png_data_uri(_png_data_uri(b"hello")) == b"hello"
    with pytest.raises(ValueError, match="data URI"):
        decode_png_data_uri("https://example.com/x.png")


def _fake_gate(expected: str) -> httpx.MockTransport:
    """A fake arena gate: serves a text challenge and accepts the verify iff the answer matches `expected`."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/arena/captcha":
            return httpx.Response(200, json={"kind": "text", "id": "t1", "image": _png_data_uri()})
        if request.url.path == "/arena/captcha/verify":
            body = json.loads(request.content)
            return httpx.Response(200, json={"ok": body.get("answer") == expected, "kind": "text"})
        return httpx.Response(404)

    return httpx.MockTransport(handler)


def test_solve_text_passes_when_ocr_is_correct() -> None:
    with httpx.Client(transport=_fake_gate("AB7K9")) as client:
        ok, answer = solve_text("http://detector:8080", _StubRecognizer("ab7k9"), client)
    assert ok is True and answer == "AB7K9"  # recognizer output is upper-cased + trimmed


def test_solve_text_fails_when_ocr_is_wrong() -> None:
    with httpx.Client(transport=_fake_gate("AB7K9")) as client:
        ok, _ = solve_text("http://detector:8080", _StubRecognizer("WRONG"), client)
    assert ok is False


def test_solve_text_refuses_foreign_target() -> None:
    with httpx.Client(transport=_fake_gate("X")) as client:
        with pytest.raises(EthicsError, match="own gates"):
            solve_text("https://challenges.cloudflare.com", _StubRecognizer("x"), client)
