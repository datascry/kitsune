# tests/test_contracts — detector test module.
# Asserts behaviour and edge cases for the unit under test.

from __future__ import annotations

import pytest

from kitsune_detector import contracts
from kitsune_detector.contracts import (
    ValidationError,
    contracts_dir,
    load_rule_registry,
    load_schema,
    validate,
)

from .conftest import load_example


def test_contracts_dir_found() -> None:
    path = contracts_dir()
    assert (path / "signal.schema.json").is_file()


def test_load_schema_has_id() -> None:
    schema = load_schema("signal.schema.json")
    assert schema["$id"].endswith("signal.schema.json")


def test_validate_accepts_example_sessions() -> None:
    validate(load_example("session_human.json"), "session.schema.json")
    validate(load_example("session_bot.json"), "session.schema.json")


def test_validate_rejects_bad_instance() -> None:
    with pytest.raises(ValidationError):
        validate({"layer": "not-a-layer"}, "signal.schema.json")


def test_load_rule_registry() -> None:
    version, rules = load_rule_registry()
    assert version
    ids = {r["id"] for r in rules}
    assert "br.webdriver_present" in ids


def test_env_override_invalid(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    monkeypatch.setenv("KITSUNE_CONTRACTS_DIR", str(tmp_path))
    contracts.contracts_dir.cache_clear()
    with pytest.raises(FileNotFoundError):
        contracts_dir()


def test_env_override_valid(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    (tmp_path / "signal.schema.json").write_text("{}")
    monkeypatch.setenv("KITSUNE_CONTRACTS_DIR", str(tmp_path))
    contracts.contracts_dir.cache_clear()
    assert contracts_dir() == tmp_path


def test_walk_up_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("KITSUNE_CONTRACTS_DIR", raising=False)
    monkeypatch.setattr(contracts, "_looks_like_contracts", lambda _p: False)
    contracts.contracts_dir.cache_clear()
    with pytest.raises(FileNotFoundError):
        contracts_dir()
