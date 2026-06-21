# tests/test_grounding — the grounding sweep: per-session FP/recall + coordination over real captures.
# Pure over synthetic sessions; pins the legit-FP, bot-recall, and caught-via-fleet semantics.

from __future__ import annotations

from datetime import UTC, datetime

from kitsune_detector.ingest import group_signals
from kitsune_detector.models import Layer, Session, Signal, Source

from kitsune_harness.grounding import evaluate, parse_args, render

_NOW = datetime(2026, 6, 21, tzinfo=UTC)


def _sess(name: str, **kv: object) -> Session:
    sigs = [
        Signal(session_id=name, layer=Layer(layer), kind=kind, value=value, source=Source.collector, observed_at=_NOW)
        for (layer, kind), value in (((k.split("__", 1)[0], k.split("__", 1)[1]), v) for k, v in kv.items())
    ]
    return group_signals(sigs)[0]


def _detector():
    from kitsune_detector.detector import Detector

    return Detector()


def test_legit_corpus_grounds_clean() -> None:
    # Real users: coherent sessions with a JS-layer signal (so no_js_execution stays quiet) and no convicting
    # tell score human; the sweep grounds clean.
    corpus = [
        (f"u{i}", _sess(f"u{i}", network__observed_ip=f"9.9.9.{i}", browser__hardware_concurrency=8)) for i in range(3)
    ]
    report = evaluate(_detector(), corpus, expect="legit")
    assert report.misclassified == []
    assert report.fleets == []
    assert report.ok
    assert "GROUNDS CLEAN" in render(report)


def test_legit_false_positive_is_flagged() -> None:
    # A real capture that trips a convicting rule under `legit` is a false positive the sweep must surface.
    corpus = [("fp", _sess("fp", browser__mobile_no_touch=True))]
    report = evaluate(_detector(), corpus, expect="legit")
    assert [o.name for o in report.misclassified] == ["fp"]
    assert "br.mobile_no_touch" in report.misclassified[0].convicting
    assert not report.ok


def test_bot_caught_per_session() -> None:
    # A per-session automation tell (webdriver) is caught directly under `bot`.
    corpus = [("b", _sess("b", browser__webdriver=True))]
    report = evaluate(_detector(), corpus, expect="bot")
    assert report.misclassified == []
    assert report.ok


def test_render_surfaces_false_positives_and_fleets() -> None:
    # The operator-facing NEEDS-ATTENTION path: a legit corpus with one convicting FP renders the offending
    # rule, and a coordination fleet renders its cluster line. This is the output that matters when real data
    # exposes a regression, so pin it.
    fp = evaluate(_detector(), [("fp", _sess("fp", browser__mobile_no_touch=True))], expect="legit")
    out = render(fp)
    assert "NEEDS ATTENTION" in out and "false positives" in out and "`br.mobile_no_touch`" in out

    ja4 = "t13d1516h2_8daaf6152771_e5627efa2ab1"
    fleet_corpus = [
        (f"t{i}", _sess(f"t{i}", network__ja4=ja4, network__observed_ip=f"8.8.8.{i}", behavioral__trace_hash="x"))
        for i in range(3)
    ]
    fleet_out = render(evaluate(_detector(), fleet_corpus, expect="bot"))
    assert "coordination fleets" in fleet_out and "fleet" in fleet_out


def test_parse_args_defaults_and_basic() -> None:
    assert parse_args([]) == ("../corpus/sessions", "legit", None)
    assert parse_args(["caps"]) == ("caps", "legit", None)
    assert parse_args(["caps", "--expect", "bot"]) == ("caps", "bot", None)


def test_parse_args_build_prior_value_not_mistaken_for_corpus_dir() -> None:
    # Regression: the old index-based scan only excluded --expect's value, so --build-prior's value placed
    # before the positional dir was picked up AS the corpus directory. parse_args consumes both option values.
    assert parse_args(["--build-prior", "out.json", "--expect", "bot", "caps"]) == ("caps", "bot", "out.json")
    assert parse_args(["caps", "--build-prior", "out.json"]) == ("caps", "legit", "out.json")
    # An unknown flag is skipped, not treated as the directory.
    assert parse_args(["--verbose", "caps"]) == ("caps", "legit", None)


def test_bot_caught_via_fleet_membership_not_counted_as_miss() -> None:
    # Sessions with no per-session convicting tell but a shared replayed trace across distinct IPs are caught
    # at the COORDINATION layer; under `bot` they must NOT count as missed (the thesis: cluster-layer catch).
    ja4 = "t13d1516h2_8daaf6152771_e5627efa2ab1"
    corpus = [
        (f"t{i}", _sess(f"t{i}", network__ja4=ja4, network__observed_ip=f"8.8.8.{i}", behavioral__trace_hash="canned"))
        for i in range(3)
    ]
    report = evaluate(_detector(), corpus, expect="bot")
    assert report.fleets and report.fleets[0].label == "fleet"
    assert report.misclassified == []  # caught via fleet membership, not per-session
    assert report.ok
