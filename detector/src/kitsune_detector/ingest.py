# detector/ingest — correlate a flat signal stream into sessions.
# Groups signals by session_id into Session objects (the architectural join).

"""Ingest — group a flat stream of signals into correlated sessions.

This is the join that the whole architecture rests on: signals from the edge (network) and the
collector (browser/behavioral), tagged with the same ``session_id``, become one ``Session``.
"""

from __future__ import annotations

from collections import defaultdict

from .config import SCHEMA_VERSION
from .models import Layer, Session, Signal, SignalGroups, Source


def _ja4b(value: object) -> str | None:
    """The JA4_b segment (the GREASE-free, sorted cipher-suite hash) — the TLS-engine identity.

    JA4 is ``<a>_<b>_<c>``; JA4_b is invariant for a real client across every connection in a session
    (transport H2/H3, TLS resumption and Chrome's per-connection extension/GREASE shuffle all leave the
    cipher list — hence JA4_b — untouched). So it is the FP-safe key for within-session TLS stability.
    """
    if not isinstance(value, str):
        return None
    parts = value.split("_")
    return parts[1] if len(parts) >= 3 else None


def _annotate_ja4_instability(network: list[Signal]) -> None:
    """Append a sticky ``ja4_unstable`` signal when a session's network signals carry >1 distinct JA4_b.

    One real client speaks ONE TLS engine for the session's lifetime, so its JA4_b is invariant. Two
    distinct JA4_b under one session id is a single client rotating its TLS fingerprint mid-session —
    impossible for a real browser, the signature of a JA4-rotation evader. The flag is sticky: once a
    rotation is seen it stays flagged even if later requests revert to one fingerprint.
    """
    if any(s.kind == "ja4_unstable" for s in network):
        return
    distinct = {b for s in network if s.kind == "ja4" and (b := _ja4b(s.value)) is not None}
    if len(distinct) <= 1:
        return
    ref = next(s for s in network if s.kind == "ja4")
    network.append(
        Signal(
            schema_version=ref.schema_version,
            session_id=ref.session_id,
            layer=Layer.network,
            kind="ja4_unstable",
            value=True,
            source=ref.source,
            observed_at=max(s.observed_at for s in network if s.kind == "ja4"),
        )
    )


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
    _annotate_ja4_instability(groups.network)  # a single batch carrying >1 JA4 is already a rotation

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


def merge_sessions(existing: Session, new: Session) -> Session:
    """Accumulate ``new`` into ``existing`` (same session).

    Signals arrive across multiple ingests — the edge posts network signals, the collector posts
    browser/behavioral ones. We must *merge*, not replace: combine per layer, keeping the latest
    signal for each ``kind`` so a session grows across requests instead of clobbering itself.
    """
    groups = SignalGroups()
    for layer in Layer:
        latest: dict[str, Signal] = {}
        for sig in [*existing.signals.of(layer), *new.signals.of(layer)]:
            current = latest.get(sig.kind)
            if current is None or sig.observed_at >= current.observed_at:
                latest[sig.kind] = sig
        ordered = sorted(latest.values(), key=lambda s: (s.observed_at, s.kind))
        groups.of(layer).extend(ordered)

    # Within-session TLS coherence runs over the FULL pre-collapse history: the collapse keeps only the
    # latest JA4 per kind, so a mid-session rotation is visible only across existing+new before merging.
    history = [*existing.signals.network, *new.signals.network]
    _annotate_ja4_instability(history)
    if any(s.kind == "ja4_unstable" for s in history) and not any(s.kind == "ja4_unstable" for s in groups.network):
        groups.network.append(next(s for s in history if s.kind == "ja4_unstable"))

    return Session(
        schema_version=SCHEMA_VERSION,
        session_id=existing.session_id,
        remote_ip=existing.remote_ip or new.remote_ip,
        first_seen=min(existing.first_seen, new.first_seen),
        last_seen=max(existing.last_seen, new.last_seen),
        request_count=existing.request_count + new.request_count,
        signals=groups,
    )
