# fleet/skulk/runner — orchestrate a fleet run: scope-check the target, generate members, emit to /ingest.
# The emit step is stdlib urllib (contracts-only); --dry-run skips emission and just shows the fleet shape.

from __future__ import annotations

import datetime
import json
import urllib.request
from dataclasses import dataclass

from .model import FleetMember
from .scope import Scope
from .strategy import Strategy


@dataclass
class RunResult:
    host: str
    strategy: str
    members: list[FleetMember]
    session_ids: list[str]
    emitted: bool


def _now() -> str:
    return datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _post_ingest(target: str, signals: list[dict[str, object]], timeout: float) -> None:
    body = json.dumps(signals).encode()
    req = urllib.request.Request(
        target.rstrip("/") + "/ingest", data=body, headers={"content-type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # target is scope-checked before any call
        resp.read()


def run(
    *,
    target: str,
    strategy: Strategy,
    nodes: int,
    seed: int,
    scope: Scope,
    dry_run: bool = False,
    timeout: float = 10.0,
    when: str | None = None,
) -> RunResult:
    """Emulate ``nodes`` of ``strategy`` against ``target``. The scope check runs FIRST and raises before any
    network I/O if the target is not authorized. ``dry_run`` generates + returns the fleet without emitting."""
    host = scope.check(target)  # ETHICS GATE — raises AuthorizationError before anything is sent
    stamp = when or _now()
    members = strategy.members(nodes, seed)
    sids: list[str] = []
    for i, m in enumerate(members):
        sid = f"skulk-{strategy.name}-{seed}-{i}"
        if not dry_run:
            _post_ingest(target, m.signals(sid, stamp), timeout)
        sids.append(sid)
    return RunResult(host=host, strategy=strategy.name, members=members, session_ids=sids, emitted=not dry_run)
