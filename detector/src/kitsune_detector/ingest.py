# detector/ingest — correlate a flat signal stream into sessions.
# Groups signals by session_id into Session objects (the architectural join).

"""Ingest — group a flat stream of signals into correlated sessions.

This is the join that the whole architecture rests on: signals from the edge (network) and the
collector (browser/behavioral), tagged with the same ``session_id``, become one ``Session``.
"""

from __future__ import annotations

from collections import defaultdict

from .config import SCHEMA_VERSION
from .models import Session, Signal, SignalGroups, Source


def group_signals(signals: list[Signal]) -> list[Session]:
    """Group signals by ``session_id`` into ``Session`` objects, ordered by first appearance."""
    by_session: dict[str, list[Signal]] = defaultdict(list)
    order: list[str] = []
    for sig in signals:
        if sig.session_id not in by_session:
            order.append(sig.session_id)
        by_session[sig.session_id].append(sig)
    return [_build_session(sid, by_session[sid]) for sid in order]


def _build_session(session_id: str, signals: list[Signal]) -> Session:
    groups = SignalGroups()
    for sig in signals:
        groups.of(sig.layer).append(sig)

    timestamps = [sig.observed_at for sig in signals]
    # request_count approximates distinct forwarded requests via edge-sourced signals.
    request_count = sum(1 for sig in signals if sig.source is Source.edge)

    return Session(
        schema_version=SCHEMA_VERSION,
        session_id=session_id,
        first_seen=min(timestamps),
        last_seen=max(timestamps),
        request_count=request_count,
        signals=groups,
    )
