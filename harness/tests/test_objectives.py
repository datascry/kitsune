# harness/tests/test_objectives — fleet objectives: work-sharding, per-worker task compilation, the registry.
# Asserts the work set is distributed disjointly and each worker compiles a DISTINCT parameterized task.

from __future__ import annotations

import json

import pytest

from kitsune_harness.objectives import Objective, all_objectives, get


def _obj() -> Objective:
    return Objective(
        name="t",
        summary="s",
        target="/",
        work=[{"cred": f"u{k}"} for k in range(5)],
        template=[{"click": [10, 20]}, {"type": "{cred}"}],
        per_item_wait_ms=100,
    )


def test_shard_distributes_work_disjointly_and_completely() -> None:
    shards = _obj().shard(3)
    assert len(shards) == 3
    flat = [item["cred"] for s in shards for item in s]
    assert sorted(flat) == [f"u{k}" for k in range(5)]  # every item assigned exactly once
    # round-robin: worker 0 gets u0,u3; worker 1 u1,u4; worker 2 u2 — disjoint, balanced
    assert [i["cred"] for i in shards[0]] == ["u0", "u3"]
    assert [i["cred"] for i in shards[2]] == ["u2"]


def test_compile_gives_each_worker_a_distinct_filled_task() -> None:
    tasks = _obj().compile(3)
    assert len(tasks) == 3
    # each worker's task is its shard's creds, template-filled (the {cred} placeholder substituted)
    w0 = tasks[0].steps
    typed0 = [s["type"] for s in w0 if "type" in s]
    assert typed0 == ["u0", "u3"]  # worker 0 typed exactly its shard, no other worker's creds
    assert "wait" in {next(iter(s)) for s in w0}  # a dwell between items
    # no two workers run the same script (sharded, not identical) — the anti-coordination point
    envs = {t.to_env() for t in tasks}
    assert len(envs) == 3
    # collectively the fleet covers the whole work set
    all_typed = [s for t in tasks for step in t.steps if (s := step.get("type"))]
    assert sorted(all_typed) == ["u0", "u1", "u2", "u3", "u4"]


def test_compiled_steps_are_valid_and_serialize() -> None:
    task = _obj().compile(1)[0]
    # round-trips through json (what KS_TASK carries) and every step is a single-action dict
    steps = json.loads(task.to_env())
    assert all(isinstance(s, dict) and len(s) == 1 for s in steps)


def test_registry_resolves_known_objectives_and_lists_unknown() -> None:
    cs = get("credential-stuffing")
    assert cs.target == "/" and cs.work and "cred" in cs.work[0]
    assert all("example.test" in item["cred"] for item in cs.work)  # synthetic, lab-only by construction
    assert {o.name for o in all_objectives()} >= {"credential-stuffing", "account-creation"}
    with pytest.raises(KeyError, match="credential-stuffing"):
        get("nope")
