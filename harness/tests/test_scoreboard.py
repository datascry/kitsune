# tests/test_scoreboard — harness test module.
# Asserts behaviour and edge cases for the unit under test.

from __future__ import annotations

from kitsune_harness.harness import Harness
from kitsune_harness.scenarios import ReplayScenario
from kitsune_harness.scoreboard import _pct, render_json, render_markdown


def test_pct() -> None:
    assert _pct(0.0) == "0.00"
    assert _pct(0.9) == "0.90"


def test_render_markdown_has_table_and_why(
    detector, fixed_clock, human_scenario: ReplayScenario, bot_scenario: ReplayScenario
) -> None:
    board = Harness(detector, clock=fixed_clock).run([human_scenario, bot_scenario])
    md = render_markdown(board)
    assert "# Kitsune scoreboard" in md
    assert "| Evader | Ver |" in md
    assert "naive-bot" in md
    # the bot row's evidence appears under Why; the clean human row does not
    assert "## Why" in md
    assert "br.webdriver_present" in md


def test_render_markdown_no_why_when_clean(
    detector, fixed_clock, human_scenario: ReplayScenario
) -> None:
    board = Harness(detector, clock=fixed_clock).run([human_scenario])
    assert "## Why" not in render_markdown(board)


def test_render_json_round_trips(detector, fixed_clock, bot_scenario: ReplayScenario) -> None:
    board = Harness(detector, clock=fixed_clock).run([bot_scenario])
    blob = render_json(board)
    assert blob["ruleset_version"] == board.ruleset_version
    assert blob["results"][0]["verdict"]["label"] == "bot"
