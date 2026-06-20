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
    assert "conviction gate" in md  # the suspicious frontier is explained, not hidden


def test_sample_rows_are_real_corpus_evaders() -> None:
    md = generate_redteam_md()
    # A representative spread down the ladder appears, each as a backticked session name with a verdict.
    assert "| `vanilla` |" in md
    assert "| `camoufox-headful` |" in md  # the suspicious frontier row
    assert md.rstrip().endswith("|")  # ends on a table row, not stray prose


def test_committed_readme_is_fresh() -> None:
    assert _README.read_text() == render_into(), "README red-team teaser is stale — run `task docs`"


def test_main_check_passes_when_fresh() -> None:
    assert main(["--check"]) == 0
