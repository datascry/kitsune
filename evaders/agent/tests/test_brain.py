# evaders/agent/tests/test_brain — tests for claude-action parsing + the injected runner.
# Covers clean/embedded JSON, type text, and fallbacks for unknown/garbage/bad-JSON output.

from __future__ import annotations

import pytest

import kitsune_agent.brain as brain
from kitsune_agent.brain import Action, decide, parse_action


def test_parse_clean_json() -> None:
    assert parse_action('{"kind":"move","x":120,"y":200}') == Action("move", 120, 200)


def test_parse_embedded_json() -> None:
    raw = 'sure, do this: {"kind":"click","x":50,"y":60} ok'
    assert parse_action(raw) == Action("click", 50, 60)


def test_parse_type_text() -> None:
    assert parse_action('{"kind":"type","text":"hello"}') == Action("type", 0, 0, "hello")


@pytest.mark.parametrize("raw", ['{"kind":"hack"}', "no json here at all", "{not valid json}"])
def test_parse_falls_back_to_done(raw: str) -> None:
    assert parse_action(raw) == Action("done")


def test_decide_uses_injected_runner() -> None:
    seen: dict[str, str] = {}

    def fake(prompt: str) -> str:
        seen["prompt"] = prompt
        return '{"kind":"scroll"}'

    action = decide("read the headline", "Kitsune lab", claude=fake)
    assert action.kind == "scroll"
    assert "read the headline" in seen["prompt"]
    assert "Kitsune lab" in seen["prompt"]


def test_default_claude_invokes_cli(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeProc:
        stdout = '{"kind":"done"}'

    monkeypatch.setattr(brain.subprocess, "run", lambda *a, **k: FakeProc())
    assert brain.default_claude("hi") == '{"kind":"done"}'
