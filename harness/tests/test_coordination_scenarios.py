# harness/tests/test_coordination_scenarios — the coordination precision/recall gate.
# Legit cohorts must never label `fleet`; every fleet shape (one per convicting signal) must.

from __future__ import annotations

from kitsune_harness.coordination_scenarios import evaluate, precision_recall, render, scenarios


def test_gate_is_perfect() -> None:
    results = evaluate()
    precision, recall = precision_recall(results)
    # Precision 1.0 is the load-bearing assertion: NO legitimate cohort may be convicted as a fleet — the
    # conviction gate must clear the diverse-cohort / large-cohort / NAT / homogeneous-pair shapes that
    # share a JA4 and (some of) the paradox + IP spread. Recall 1.0: every convicting signal is exercised.
    assert precision == 1.0, [r.name for r in results if r.is_fleet and not r.malicious]
    assert recall == 1.0, [r.name for r in results if not r.is_fleet and r.malicious]
    assert all(r.correct for r in results)


def test_covers_each_convicting_signal_and_legit_shape() -> None:
    names = {s.name for s in scenarios()}
    # one malicious scenario per convicting coordination signal …
    assert {
        "fleet-ja4c-randomizer",
        "fleet-cloned-fingerprint",
        "fleet-cloned-trace",
        "fleet-shared-origin",
    } <= names
    # … and the legit shapes the gate must clear (the FP surface)
    assert {"legit-diverse-cohort", "legit-large-cohort", "legit-nat-cohort"} <= names


def test_render_reports_precision_recall() -> None:
    md = render(evaluate())
    assert "precision: 100%" in md and "recall: 100%" in md
    assert "legit-diverse-cohort" in md and "fleet-cloned-trace" in md
