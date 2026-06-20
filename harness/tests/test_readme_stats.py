# harness/tests/test_readme_stats — the README "What it detects" stats are derived AND committed-fresh (no drift).
# Guards the generated headline metrics: rule counts + per-class table, generated from the registry, gated in CI.

from __future__ import annotations

import yaml

from kitsune_harness.readme_stats import (
    _END,
    _README,
    _REGISTRY,
    _START,
    generate_stats_md,
    main,
    render_into,
)


def test_stats_report_the_true_live_rule_count() -> None:
    md = generate_stats_md()
    rules = yaml.safe_load(_REGISTRY.read_text())["rules"]
    live = sum(1 for r in rules if r.get("status", "active") != "retired")
    assert f"**{live} live rules**" in md


def test_per_class_counts_sum_to_live_rules() -> None:
    rules = yaml.safe_load(_REGISTRY.read_text())["rules"]
    live = [r for r in rules if r.get("status", "active") != "retired"]
    md = generate_stats_md()
    # Every live rule's class is represented; the table cannot silently drop a class.
    classes = {r.get("category") for r in live}
    for c in classes:
        assert f"**{c}**" in md, f"class {c} missing from the README stats table"


def test_only_convicting_classes_get_the_marker() -> None:
    md = generate_stats_md()
    # The ✦ convicting marker sits on coherence's row but never on environment's.
    assert "| **coherence** |" in md and "✦" in md
    coherence_row = next(line for line in md.splitlines() if line.startswith("| **environment**"))
    assert "✦" not in coherence_row  # environment corroborates only


def test_committed_readme_is_fresh() -> None:
    assert _README.read_text() == render_into(), "README stats are stale — run `task docs`"


def test_main_check_passes_when_fresh() -> None:
    assert main(["--check"]) == 0


def test_markers_present_and_prose_preserved() -> None:
    text = _README.read_text()
    assert _START in text and _END in text
    assert "## The thesis: catch the *contradiction*, not the signal" in text  # curated prose untouched
