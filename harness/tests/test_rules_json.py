# tests/test_rules_json — the browser-consumable rule registry the livepage fetches.
# Pins _client_evaluable (incl. the empty-reads vacuous-true guard) and build()'s shape.

from __future__ import annotations

from kitsune_harness.rules_json import _client_evaluable, build


def test_client_evaluable_guards_empty_reads() -> None:
    assert _client_evaluable({"reads": []}) is False  # vacuous-true guard: no reads => not client-evaluable
    assert _client_evaluable({"reads": ["browser.x"]}) is True
    assert _client_evaluable({"reads": ["browser.x", "behavioral.y"]}) is True
    assert _client_evaluable({"reads": ["network.x"]}) is False
    assert _client_evaluable({"reads": ["browser.x", "network.y"]}) is False


def test_build_emits_nonretired_client_flagged_rules() -> None:
    out = build()
    assert out["ruleset_version"]
    rules = out["rules"]
    assert rules and all("clientEvaluable" in r for r in rules)
    assert all(r["status"] != "retired" for r in rules)  # retired rules are excluded from the client bundle
    assert any(r["clientEvaluable"] for r in rules) and any(not r["clientEvaluable"] for r in rules)
