# harness/scoreboard — render a scoreboard to Markdown / JSON.
# Per-layer, per-evader table plus the evidence behind each verdict.

"""Render a scoreboard to Markdown / JSON.

The scoreboard is the artifact: a per-layer, per-evader table plus the evidence behind each verdict,
stamped with the ruleset version and date so boards stay comparable as the lab evolves.
"""

from __future__ import annotations

from typing import Any

from .models import ScenarioResult, Scoreboard

_COLUMNS = (
    "Evader",
    "Ver",
    "Network",
    "Browser",
    "Behavioral",
    "Reputation",
    "Incoh.",
    "Score",
    "Label",
)


def _pct(value: float) -> str:
    return f"{value:.2f}"


def _row(result: ScenarioResult) -> list[str]:
    v = result.verdict
    ls = v.layer_scores
    return [
        result.scenario,
        result.version,
        _pct(ls.network),
        _pct(ls.browser),
        _pct(ls.behavioral),
        _pct(ls.reputation),
        _pct(v.incoherence_score),
        _pct(v.score),
        v.label.value,
    ]


def render_markdown(board: Scoreboard) -> str:
    lines = [
        "# Kitsune scoreboard",
        "",
        f"- generated: `{board.generated_at.isoformat()}`",
        f"- ruleset: `{board.ruleset_version}`",
        "",
        "| " + " | ".join(_COLUMNS) + " |",
        "|" + "|".join(["---"] * len(_COLUMNS)) + "|",
    ]
    lines.extend("| " + " | ".join(_row(r)) + " |" for r in board.results)

    # Evidence: why each non-human verdict scored as it did.
    explained = [r for r in board.results if r.verdict.contradictions]
    if explained:
        lines += ["", "## Why", ""]
        for r in explained:
            rules = ", ".join(f"`{c.rule_id}`" for c in r.verdict.contradictions)
            lines.append(f"- **{r.scenario}** ({r.verdict.label.value}): {rules}")
    return "\n".join(lines) + "\n"


def render_json(board: Scoreboard) -> dict[str, Any]:
    return board.model_dump(mode="json")
