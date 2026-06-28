# harness/objectives — coordinated-fleet OBJECTIVES: a goal + a work set SHARDED across workers.
# Each worker compiles a parameterized behavioral task over its own shard, so the fleet pursues one goal together.

"""Fleet objectives — driving a coordinated fleet at a goal, with the work distributed across workers.

The archetype/task layer gives every worker the SAME action script (the same typed text, the same clicks). A
real coordinated fleet pursuing an objective instead SHARDS the work — credential batch *i* to worker *i*, page
range *i* to worker *i* — so the fleet collectively covers the goal with distributed, non-identical work (the
identical-script fleet is both unrealistic and a coordination tell).

An :class:`Objective` names the goal, holds the WORK SET (one dict of fields per item), and a TASK TEMPLATE whose
string steps carry ``{field}`` placeholders. :meth:`Objective.compile` round-robin-shards the work across *n*
workers and fills the template per item, yielding one distinct :class:`~kitsune_harness.tasks.BehavioralTask` per
worker — which the fleet manager drops into each node's ``KS_TASK`` (alongside its distinct ``KS_NODE_SEED``).

ETHICS: every objective targets ONLY the lab's own arena gates / detector endpoints (the allow-list). The work
sets are SYNTHETIC and lab-only (``example.test`` credentials, fabricated identities) — these MODEL an
adversary's objective against Kitsune's OWN form/gate to measure whether coordination detection catches the
fleet; there is no real authentication, no third-party target, and no credential is real. The same scope the
archetype catalog already enforces.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .tasks import BehavioralTask, _validate_step


def _fill(step: dict[str, Any], item: dict[str, str]) -> dict[str, Any]:
    """Substitute ``{field}`` placeholders in a step's STRING value from the shard item; non-string values
    (points/ints) pass through. A single-action dict in, a filled single-action dict out."""
    ((action, param),) = step.items()
    return {action: param.format(**item) if isinstance(param, str) else param}


@dataclass(frozen=True)
class Objective:
    """A fleet goal + a work set sharded across workers into per-worker parameterized tasks."""

    name: str
    summary: str
    target: str  # the allow-listed path the objective exercises (the lab's own form/gate)
    work: list[dict[str, str]]  # the work set: one dict of fields per item (synthetic, lab-only)
    template: list[dict[str, Any]]  # task-step template; string values may contain {field} placeholders
    per_item_wait_ms: int = 600  # human-plausible dwell between attempts within a worker's batch

    def shard(self, n: int) -> list[list[dict[str, str]]]:
        """Round-robin-distribute the work set across ``n`` workers (each gets a disjoint batch)."""
        if n < 1:
            raise ValueError("need >= 1 worker")
        return [self.work[i::n] for i in range(n)]

    def compile(self, n: int) -> list[BehavioralTask]:
        """One :class:`BehavioralTask` per worker: its shard's items, each expanded from the template (with a
        dwell between items). Worker *i*'s task is DISTINCT from the others — the fleet covers the work set
        collectively, no two workers repeating the same action script."""
        tasks: list[BehavioralTask] = []
        for i, batch in enumerate(self.shard(n)):
            steps: list[dict[str, Any]] = []
            for item in batch:
                for step in self.template:
                    steps.append(_validate_step(_fill(step, item)))
                steps.append({"wait": self.per_item_wait_ms})
            tasks.append(BehavioralTask(name=f"{self.name}-{i}", steps=steps))
        return tasks


_REGISTRY: dict[str, Objective] = {}


def _reg(obj: Objective) -> None:
    _REGISTRY[obj.name] = obj


# The form-fill flow on the lab's OWN demo page (#ks-bio-text input region) — typing models the submit step.
_FORM_TEMPLATE: list[dict[str, Any]] = [
    {"move": [300, 280]},
    {"click": [300, 280]},
    {"type": "{cred}"},
    {"move": [300, 340]},
    {"click": [300, 340]},
]

# credential-stuffing: each worker submits a DISTINCT batch of SYNTHETIC credential pairs (no real auth, lab
# form only). Models the sharded cred-stuffing fleet so coordination detection can be measured against it.
_reg(
    Objective(
        name="credential-stuffing",
        summary="sharded synthetic credential pairs typed into the lab's own form — the cred-stuffing fleet shape",
        target="/",
        work=[{"cred": f"user{k}@example.test:pw{k:04d}"} for k in range(12)],
        template=_FORM_TEMPLATE,
    )
)

# account-creation: each worker registers a DISTINCT fabricated identity (the sybil/fraudulent-signup shape).
_reg(
    Objective(
        name="account-creation",
        summary="sharded fabricated signup identities into the lab's own form — the fraudulent-account fleet shape",
        target="/",
        work=[{"cred": f"newuser{k}@example.test:Acct!{k:04d}"} for k in range(9)],
        template=_FORM_TEMPLATE,
    )
)


def get(name: str) -> Objective:
    """Resolve a named objective, or raise ``KeyError`` listing the known names."""
    try:
        return _REGISTRY[name]
    except KeyError:
        raise KeyError(f"unknown objective {name!r}; known: {', '.join(sorted(_REGISTRY))}") from None


def all_objectives() -> list[Objective]:
    """Every registered objective, sorted by name."""
    return sorted(_REGISTRY.values(), key=lambda o: o.name)
