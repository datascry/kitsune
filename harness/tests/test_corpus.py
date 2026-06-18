# tests/test_corpus — tests for the recorded-session corpus fast-feedback loop.
# Loads example sessions, scores in-process, asserts labels + sorted ordering.

from __future__ import annotations

import shutil
from pathlib import Path

from kitsune_detector.contracts import contracts_dir
from kitsune_detector.detector import Detector

from kitsune_harness.corpus import load_corpus, score_corpus

from .conftest import FIXED


def _seed(tmp_path: Path) -> Path:
    examples = contracts_dir() / "examples"
    shutil.copy(examples / "session_human.json", tmp_path / "human.json")
    shutil.copy(examples / "session_bot.json", tmp_path / "bot.json")
    return tmp_path


def test_load_corpus_sorted(tmp_path: Path) -> None:
    corpus = load_corpus(_seed(tmp_path))
    assert [name for name, _ in corpus] == ["bot", "human"]


def test_score_corpus(detector: Detector, tmp_path: Path) -> None:
    corpus = load_corpus(_seed(tmp_path))
    board = score_corpus(detector, corpus, generated_at=FIXED, ruleset_version="x")
    labels = {r.scenario: r.verdict.label.value for r in board.results}
    assert labels == {"human": "human", "bot": "bot"}


def test_empty_corpus(tmp_path: Path, detector: Detector) -> None:
    board = score_corpus(detector, load_corpus(tmp_path), generated_at=FIXED, ruleset_version="x")
    assert board.results == []
