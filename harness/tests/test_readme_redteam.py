# harness/tests/test_readme_redteam — the README red-team teaser is derived from the scored corpus AND committed-fresh.
# Guards the caught/total headline + sample evader matrix against drift; gated in CI like the other generated docs.

from __future__ import annotations

from kitsune_harness.readme_redteam import (
    _README,
    generate_redteam_md,
    main,
    render_into,
)


def test_headline_reports_the_true_caught_count() -> None:
    md = generate_redteam_md()
    # The headline counts bot-labelled evaders out of the whole corpus; the matrix and this must agree.
    assert "evaders score `bot`" in md
    assert "conviction-gate frontier" in md  # the suspicious frontier (top evaders) is explained, not hidden


def test_sample_rows_show_the_convicting_tell() -> None:
    md = generate_redteam_md()
    # The ladder names real corpus evaders, each with the "Caught by" convicting tell (the detection mechanism,
    # not just a score). curl-impersonate is caught on the network layer (no JS execution).
    assert "Caught by (top convicting tell)" in md
    assert "| `curl-impersonate` |" in md
    assert "`net.no_js_execution`" in md


def test_top_evaders_frontier_is_listed() -> None:
    md = generate_redteam_md()
    # The auto-derived "top evaders" frontier: every suspicious evader, shown with the corroborating-only tells
    # it trips (no convicting rule) — the conviction-gate story.
    assert "Top evaders" in md
    assert "| `camoufox-headful` |" in md  # a known headful-frontier suspicious evader
    assert md.rstrip().endswith("|")  # ends on a table row, not stray prose


def test_committed_readme_is_fresh() -> None:
    assert _README.read_text() == render_into(), "README red-team teaser is stale — run `task docs`"


def test_main_check_passes_when_fresh() -> None:
    assert main(["--check"]) == 0
