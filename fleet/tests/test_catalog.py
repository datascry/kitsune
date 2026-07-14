# fleet/tests/test_catalog — cover the coordination-catalog generator: completeness, the self-check cross-guard,
# the linked bindings + blue-signal glossary, and that both committed GENERATED blocks are up to date (the CI gate).

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


def test_catalog_has_the_legend_glossary_and_linked_bindings() -> None:
    md = generate_catalog_md()
    assert "**Verdict tiers**" in md
    for badge, _gloss in catalog._TIERS.values():
        assert badge in md
    assert "### The blue signals it targets" in md
    # Every glossary signal has an anchor heading, and every strategy with a primary signal links to it.
    for sig in catalog._SIGNALS:
        assert f"#### {sig}" in md
    for g in catalog._GRADE.values():
        if g.signal:
            assert f"[`{g.signal}`](#{g.signal})" in md, g.signal


def test_missing_catalog_entry_is_a_hard_error(monkeypatch: pytest.MonkeyPatch) -> None:
    # Drop one strategy's entry — generation must refuse (the CI drift gate for "added a strategy, forgot the row").
    victim = all_strategies()[0].name
    pruned = {k: v for k, v in catalog._GRADE.items() if k != victim}
    monkeypatch.setattr(catalog, "_GRADE", pruned)
    with pytest.raises(SystemExit, match="missing a catalog entry"):
        generate_catalog_md()


def test_unknown_blue_signal_is_a_hard_error(monkeypatch: pytest.MonkeyPatch) -> None:
    # A binding that links a signal with no glossary entry must fail (the glossary can't dangle).
    bad = dict(catalog._GRADE)
    bad["cloned"] = Grade("BotBrowser", "`fp_collision` — cloned", "fleet", signal="not_a_real_signal")
    monkeypatch.setattr(catalog, "_GRADE", bad)
    with pytest.raises(SystemExit, match="unknown blue signal"):
        generate_catalog_md()


def test_cross_guard_rejects_a_binding_that_contradicts_the_self_check(monkeypatch: pytest.MonkeyPatch) -> None:
    # `cloned` self-checks to an fp_hash collision; a declared binding that omits `fp_collision` must be rejected,
    # so the catalog can never claim a binding the code disagrees with.
    bad = dict(catalog._GRADE)
    bad["cloned"] = Grade("BotBrowser", "some unrelated binding", "fleet")
    monkeypatch.setattr(catalog, "_GRADE", bad)
    with pytest.raises(SystemExit, match="omits its live self-check signal"):
        generate_catalog_md()


def test_render_into_requires_the_markers(tmp_path: Path) -> None:
    nomarkers = tmp_path / "README.md"
    nomarkers.write_text("# no markers here\n")
    with pytest.raises(SystemExit, match="missing the"):
        render_into(nomarkers)


def test_both_committed_blocks_are_up_to_date() -> None:
    # The drift gate, exercised in-process: every committed target (fleet/README.md + docs/coordination-catalog.md)
    # must equal a fresh render. If this fails, run `task coordination-catalog`. (CI runs the same via --check.)
    for target in catalog._TARGETS:
        assert target.read_text() == render_into(target), target


def test_main_check_reports_up_to_date(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--check"]) == 0
    assert "up to date" in capsys.readouterr().out
