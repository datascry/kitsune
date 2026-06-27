# harness/tasks — a behavioral task DSL for fleet workers (move/click/scroll/type/wait) + named presets.
# A worker reads the serialized task from KS_TASK and drives it via CDP, so a fleet does more than navigate+mint.

"""Behavioral task scripts for fleet nodes.

A fleet worker that only navigates and mints a session sends ZERO input — it trips the behavioral floor and
exhibits no realistic interaction. A :class:`BehavioralTask` is a small, declarative script of pointer/scroll/
keyboard steps the worker replays (via trusted CDP input) after landing, so an engagement can model a real flow
(a reader scrolling, a form being filled, a scraper crawling) and the captured session carries genuine
behavioral signals. The task is serialized to the ``KS_TASK`` env the worker reads — the harness owns the DSL,
the evader owns the CDP execution, so the script is portable across evader images that support it.

Steps are single-action dicts (YAML/JSON friendly), one of:
``{move: [x, y]}`` · ``{click: [x, y]}`` · ``{scroll: dy}`` · ``{type: "text"}`` · ``{wait: ms}``.
A task in a plan is either a preset NAME (``task: browse``) or an inline list of steps.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

#: action -> the python type its parameter must have (a 2-int list for points, an int for scroll/wait, str for type).
_PARAM_TYPE: dict[str, str] = {"move": "point", "click": "point", "scroll": "int", "type": "str", "wait": "int"}


@dataclass(frozen=True)
class BehavioralTask:
    """A named, validated sequence of behavioral steps. ``to_env()`` is what the worker receives in ``KS_TASK``."""

    name: str
    steps: list[dict[str, Any]]

    def to_env(self) -> str:
        return json.dumps(self.steps, separators=(",", ":"))


def _validate_step(step: Any) -> dict[str, Any]:
    if not isinstance(step, dict) or len(step) != 1:
        raise ValueError(f"step must be a single-action dict, got {step!r}")
    ((action, param),) = step.items()
    kind = _PARAM_TYPE.get(action)
    if kind is None:
        raise ValueError(f"unknown action {action!r}; known: {', '.join(sorted(_PARAM_TYPE))}")
    if kind == "point":
        if not (isinstance(param, (list, tuple)) and len(param) == 2 and all(isinstance(v, int) for v in param)):
            raise ValueError(f"{action} needs [x, y] integers, got {param!r}")
        return {action: [int(param[0]), int(param[1])]}
    if kind == "int":
        if not isinstance(param, int) or isinstance(param, bool):
            raise ValueError(f"{action} needs an integer, got {param!r}")
        return {action: param}
    if not isinstance(param, str):
        raise ValueError(f"{action} needs a string, got {param!r}")
    return {action: param}


_PRESETS: dict[str, list[dict[str, Any]]] = {
    # a cursor that drifts in a varied path — the behavioral-floor-clearing minimum (the old KS_BEHAVE shape).
    "idle-cursor": [{"move": [240, 220]}, {"move": [300, 260]}, {"move": [380, 230]}, {"move": [330, 300]}],
    # a reader: drift, scroll down the page, pause, scroll more.
    "browse": [
        {"move": [260, 240]},
        {"scroll": 320},
        {"wait": 350},
        {"move": [420, 360]},
        {"scroll": 280},
        {"wait": 300},
    ],
    # a scraper crawling a long page: repeated scroll-and-pause.
    "scrape-scroll": [{"scroll": 500}, {"wait": 250}, {"scroll": 500}, {"wait": 250}, {"scroll": 500}, {"wait": 250}],
    # a form being filled: move to a field, click, type, move to submit, click.
    "form-fill": [
        {"move": [300, 280]},
        {"click": [300, 280]},
        {"type": "kitsune@example.test"},
        {"move": [300, 340]},
        {"click": [300, 340]},
    ],
}


def presets() -> list[str]:
    return sorted(_PRESETS)


def get_preset(name: str) -> BehavioralTask:
    try:
        steps = _PRESETS[name]
    except KeyError:
        raise KeyError(f"unknown task preset {name!r}; known: {', '.join(presets())}") from None
    return BehavioralTask(name=name, steps=[dict(s) for s in steps])


def task_from_obj(obj: Any) -> BehavioralTask:
    """Resolve a plan's ``task:`` value — a preset NAME (str) or an inline list of step dicts — to a task."""
    if isinstance(obj, str):
        return get_preset(obj)
    if isinstance(obj, list):
        return BehavioralTask(name="inline", steps=[_validate_step(s) for s in obj])
    raise ValueError(f"task must be a preset name or a list of steps, got {obj!r}")
