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
        "fleet-httpflood",
    } <= names
    # … and the legit shapes the gate must clear (the FP surface)
    assert {"legit-diverse-cohort", "legit-large-cohort", "legit-nat-cohort", "legit-flash-crowd"} <= names


def test_l7_flood_convicts_but_flash_crowd_caps_at_candidate() -> None:
    # The G17 rung: an L7 flood is caught by the aggregate flood shape corroborated by the non-browser tool JA4
    # ALONE — no fp/trace/ticket collision, no datacenter flag (clean residential). A legit flash-crowd has the
    # SAME aggregate shape (large + lockstep + many origins) but no corroborator, so it must cap at candidate.
    by_name = {r.name: r.verdict for r in evaluate()}
    flood = by_name["fleet-httpflood"]
    assert flood.label == "fleet" and flood.l7_flood  # convicted AND attributed as an L7 flood
    crowd = by_name["legit-flash-crowd"]
    assert crowd.label != "fleet" and not crowd.l7_flood  # same shape, real browsers → not a flood


def test_render_reports_precision_recall() -> None:
    md = render(evaluate())
    assert "precision: 100%" in md and "recall: 100%" in md
    assert "legit-diverse-cohort" in md and "fleet-cloned-trace" in md
