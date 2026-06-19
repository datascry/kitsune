# harness/tests/test_evasion_catalog — the generated evasion registry is complete AND committed-fresh.
# Guards the evasion catalog's purpose: an exhaustive, always-current list of every evader + exercised technique.

from __future__ import annotations

from kitsune_harness.evasion_catalog import (
    _CATALOG,
    _EVADERS,
    _SESSIONS,
    _START,
    generate_evasion_md,
    main,
    render_into,
)


def test_registry_lists_every_evader_and_technique() -> None:
    md = generate_evasion_md()
    # Every evader directory appears in the fleet table.
    for evader_dir in (p for p in _EVADERS.iterdir() if p.is_dir()):
        assert f"`{evader_dir.name}`" in md, f"{evader_dir.name} missing from the fleet table"
    # Every captured corpus session appears as an exercised technique.
    for session in _SESSIONS.glob("*.json"):
        assert f"`{session.stem}`" in md, f"{session.stem} missing from the technique table"


def test_evades_flag_marks_non_convicted_techniques() -> None:
    # A technique scored below bot is surfaced as EVADES (the red-team frontier), not silently hidden.
    md = generate_evasion_md()
    if "| suspicious |" in md or "| human |" in md:
        assert "EVADES" in md


def test_committed_catalog_is_fresh() -> None:
    assert _CATALOG.read_text() == render_into(), "docs/evasion-catalog.md is stale — run `task evasion-catalog`"


def test_main_check_passes_when_fresh() -> None:
    assert main(["--check"]) == 0  # the CI freshness gate returns 0 on a current catalog


def test_markers_present_and_curated_prose_preserved() -> None:
    text = _CATALOG.read_text()
    assert _START in text
    assert "Complete evasion registry" in text
    assert "## Provenance of the leverage analysis" in text  # curated prose survives the splice
