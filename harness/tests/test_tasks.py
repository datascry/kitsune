# harness/tests/test_tasks — the behavioral task DSL: validation, presets, inline scripts, env serialization.
# Asserts the step validator rejects malformed scripts and presets serialize to compact worker-parseable JSON.

from __future__ import annotations

import json

import pytest

from kitsune_harness.tasks import BehavioralTask, get_preset, presets, task_from_obj


def test_presets_exist_and_resolve() -> None:
    assert {"idle-cursor", "browse", "scrape-scroll", "form-fill"} <= set(presets())
    browse = get_preset("browse")
    assert browse.name == "browse" and any("scroll" in s for s in browse.steps)


def test_unknown_preset_lists_known() -> None:
    with pytest.raises(KeyError) as exc:
        get_preset("nope")
    assert "browse" in str(exc.value)


def test_to_env_is_compact_json_roundtrips() -> None:
    task = get_preset("scrape-scroll")
    decoded = json.loads(task.to_env())
    assert decoded == task.steps and " " not in task.to_env()  # compact, worker-parseable


def test_inline_task_validates_each_step() -> None:
    task = task_from_obj([{"move": [10, 20]}, {"click": [10, 20]}, {"scroll": 300}, {"type": "hi"}, {"wait": 200}])
    assert task.name == "inline" and len(task.steps) == 5
    assert task.steps[0] == {"move": [10, 20]}


def test_task_from_obj_accepts_preset_name() -> None:
    assert task_from_obj("browse").name == "browse"


@pytest.mark.parametrize(
    "bad",
    [
        {"move": [1, 2], "click": [3, 4]},  # two actions in one step
        {"jump": [1, 2]},  # unknown action
        {"move": [1]},  # point needs two ints
        {"move": ["a", "b"]},  # non-int point
        {"scroll": "down"},  # scroll needs an int
        {"scroll": True},  # bool is not an int here
        {"type": 5},  # type needs a string
        "not-a-dict",  # not a single-action dict
    ],
)
def test_invalid_steps_are_rejected(bad: object) -> None:
    with pytest.raises(ValueError):
        task_from_obj([bad])


def test_task_from_obj_rejects_wrong_type() -> None:
    with pytest.raises(ValueError, match="preset name or a list"):
        task_from_obj(42)


def test_behavioral_task_is_constructible() -> None:
    t = BehavioralTask(name="x", steps=[{"wait": 1}])
    assert t.to_env() == '[{"wait":1}]'
