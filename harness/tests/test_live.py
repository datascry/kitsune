# tests/test_live — tests for live scoreboard assembly from evader verdict JSON.
# Covers verdict validation (mode stripped), board rendering, and CLI arg parsing.

from __future__ import annotations

import json
from pathlib import Path

from kitsune_harness.live import build_board, result_from_verdict
from kitsune_harness.liveboard import _parse_arg
from kitsune_harness.scoreboard import render_markdown

from .conftest import FIXED

VERDICT = {
    "schema_version": "0.1",
    "session_id": "s",
    "layer_scores": {"network": 0.0, "browser": 0.0, "behavioral": 0.8, "reputation": 0.0},
    "contradictions": [],
    "incoherence_score": 0.0,
    "score": 0.8,
    "label": "bot",
    "ruleset_version": "0.2.0",
    "scored_at": "2026-06-18T00:00:00Z",
}


def test_result_from_verdict_strips_mode() -> None:
    result = result_from_verdict("agent", "live", {**VERDICT, "mode": "agent"})
    assert result.scenario == "agent"
    assert result.verdict.label.value == "bot"


def test_build_board_renders_all() -> None:
    board = build_board(
        [
            ("vanilla", "live", {**VERDICT, "label": "human", "score": 0.0}),
            ("agent", "live", VERDICT),
        ],
        generated_at=FIXED,
        ruleset_version="live",
    )
    md = render_markdown(board)
    assert "vanilla" in md and "agent" in md


def test_parse_arg_explicit_label(tmp_path: Path) -> None:
    p = tmp_path / "v.json"
    p.write_text(json.dumps({**VERDICT, "mode": "agent"}))
    label, _ = _parse_arg(f"naive-bot={p}")
    assert label == "naive-bot"


def test_parse_arg_bare_uses_mode(tmp_path: Path) -> None:
    p = tmp_path / "v.json"
    p.write_text(json.dumps({**VERDICT, "mode": "stealth"}))
    label, _ = _parse_arg(str(p))
    assert label == "stealth"


def test_parse_arg_bare_uses_stem(tmp_path: Path) -> None:
    p = tmp_path / "vanilla.json"
    p.write_text(json.dumps(VERDICT))  # no "mode"
    label, _ = _parse_arg(str(p))
    assert label == "vanilla"
