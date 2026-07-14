# fleet/tests/test_catalog — cover the coordination-catalog generator: completeness, the self-check cross-guard,
# the rendered table, and that the committed fleet/README.md block is up to date (the drift gate CI enforces).

from __future__ import annotations

from pathlib import Path

import pytest

from skulk import catalog
from skulk.catalog import Grade, generate_catalog_md, main, render_into
from skulk.strategy import all_strategies


def test_every_registered_strategy_has_a_catalog_row() -> None:
    # The completeness invariant: a new strategy with no _GRADE entry must fail generation (so it cannot ship
    # uncatalogued). Here it holds — every registered strategy renders a row.
    md = generate_catalog_md()
    for s in all_strategies():
        assert f"| `{s.name}` |" in md, s.name


def test_catalog_has_the_legend_and_tier_badges() -> None:
    md = generate_catalog_md()
    assert "**Verdict tiers**" in md
    for badge, _gloss in catalog._TIERS.values():
        assert badge in md
    assert "| strategy | attacker class it models | blue binding that catches it | verdict |" in md


def test_missing_catalog_entry_is_a_hard_error(monkeypatch: pytest.MonkeyPatch) -> None:
    # Drop one strategy's entry — generation must refuse (the CI drift gate for "added a strategy, forgot the row").
    victim = all_strategies()[0].name
    pruned = {k: v for k, v in catalog._GRADE.items() if k != victim}
    monkeypatch.setattr(catalog, "_GRADE", pruned)
    with pytest.raises(SystemExit, match="missing a catalog entry"):
        generate_catalog_md()


def test_cross_guard_rejects_a_binding_that_contradicts_the_self_check(monkeypatch: pytest.MonkeyPatch) -> None:
    # `cloned` self-checks to an fp_hash collision; a declared binding that omits `fp_collision` must be rejected,
    # so the catalog can never claim a binding the code disagrees with.
    bad = dict(catalog._GRADE)
    bad["cloned"] = Grade("BotBrowser", "some unrelated binding", "fleet")
    monkeypatch.setattr(catalog, "_GRADE", bad)
    with pytest.raises(SystemExit, match="omits its live self-check signal"):
        generate_catalog_md()


def test_render_into_requires_the_markers(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    nomarkers = tmp_path / "README.md"
    nomarkers.write_text("# no markers here\n")
    monkeypatch.setattr(catalog, "_README", nomarkers)
    with pytest.raises(SystemExit, match="missing the"):
        render_into()


def test_committed_readme_block_is_up_to_date() -> None:
    # The drift gate, exercised in-process: the committed fleet/README.md must equal a fresh render. If this
    # fails, run `task coordination-catalog`. (CI runs the same assertion via `python -m skulk.catalog --check`.)
    assert catalog._README.read_text() == render_into()


def test_main_check_reports_up_to_date(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--check"]) == 0
    assert "up to date" in capsys.readouterr().out
