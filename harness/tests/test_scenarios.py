# tests/test_scenarios — harness test module.
# Asserts behaviour and edge cases for the unit under test.

from __future__ import annotations

from kitsune_harness.scenarios import ReplayScenario, Scenario


def test_replay_collects_fixture_signals(human_scenario: ReplayScenario) -> None:
    signals = human_scenario.collect()
    assert human_scenario.name == "vanilla"
    assert human_scenario.version == "0.1.0"
    # human fixture: 4 network + 4 browser + 2 behavioral + 1 reputation = 11
    assert len(signals) == 11
    assert {s.session_id for s in signals} == {"human-001"}


def test_replay_satisfies_scenario_protocol(human_scenario: ReplayScenario) -> None:
    assert isinstance(human_scenario, Scenario)
    assert not isinstance(object(), Scenario)
