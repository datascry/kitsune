# harness/tests/test_rule_catalog — the generated rule registry is complete AND committed-fresh (no drift).
# Guards the catalog's new purpose: an exhaustive, always-current list of every rule, generated from the registry.

from __future__ import annotations

from pathlib import Path

import yaml

from kitsune_harness.rule_catalog import _CATALOG, _END, _REGISTRY, _START, generate_registry_md, render_into

_ROOT = Path(__file__).resolve().parents[2]


def test_registry_block_lists_every_rule() -> None:
    md = generate_registry_md()
    rules = yaml.safe_load(_REGISTRY.read_text())["rules"]
    assert rules, "registry has no rules"
    # Every rule id appears exactly once in the generated table.
    for r in rules:
        assert f"`{r['id']}`" in md, f"{r['id']} missing from the generated registry"
    # The header reports the true count.
    assert f"**{len(rules)} rules**" in md


def test_convicting_marker_only_on_convicting_categories() -> None:
    md = generate_registry_md()
    # A convicting category carries the ✦ marker; environment never does.
    assert "coherence✦" in md
    assert "environment✦" not in md  # environment corroborates, never convicts


def test_committed_catalog_is_fresh() -> None:
    # The generated block in the committed doc must match a fresh render — `task catalog` keeps it current.
    assert _CATALOG.read_text() == render_into(), "docs/detection-catalog.md is stale — run `task catalog`"


def test_markers_present_and_curated_prose_preserved() -> None:
    text = _CATALOG.read_text()
    assert _START in text and _END in text
    # Splicing only the marked block must leave the curated frontier prose intact.
    assert "## Provenance of the gap analysis" in text
    assert "Complete rule registry" in text
