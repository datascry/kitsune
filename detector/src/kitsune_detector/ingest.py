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


#: A real short HTTP/cookie session egresses from ONE edge-observed IP (CGNAT and a wifi<->cellular
#: handoff present at most 1-2); >=3 distinct egress IPs under one session id is a rotating proxy pool —
#: the dominant scraper evasion. This is a reputation-free coherence count (no residential/datacenter
#: data needed), conservative enough to spare every legitimate multi-IP case.
_IP_ROTATION_MIN = 3


def _annotate_ip_rotation(network: list[Signal]) -> None:
    """Append a sticky ``ip_rotation`` signal when a session egresses from >=_IP_ROTATION_MIN distinct IPs.

    The merge keeps only the latest ``observed_ip`` per kind, so a running set is persisted as
    ``observed_ip_seen`` (a list) to count distinct egress IPs across ingests without disturbing the
    singular ``observed_ip`` that other rules read. ``ip_rotation`` is sticky once tripped.
    """
    ips: set[str] = set()
    for s in network:
        if s.kind == "observed_ip" and isinstance(s.value, str):
            ips.add(s.value)
        elif s.kind == "observed_ip_seen" and isinstance(s.value, list):
            ips.update(v for v in s.value if isinstance(v, str))
    if not ips:
        return
    ref = next(s for s in network if s.kind in ("observed_ip", "observed_ip_seen"))
    acc = next((s for s in network if s.kind == "observed_ip_seen"), None)
    if acc is None:
        network.append(
            Signal(
                schema_version=ref.schema_version,
                session_id=ref.session_id,
                layer=Layer.network,
                kind="observed_ip_seen",
                value=sorted(ips),
                source=ref.source,
                observed_at=ref.observed_at,
            )
        )
    else:
        acc.value = sorted(ips)
    if len(ips) >= _IP_ROTATION_MIN and not any(s.kind == "ip_rotation" for s in network):
        network.append(
            Signal(
                schema_version=ref.schema_version,
                session_id=ref.session_id,
                layer=Layer.network,
                kind="ip_rotation",
                value=True,
                source=ref.source,
                observed_at=ref.observed_at,
            )
        )


def _annotate_ua_rotation(network: list[Signal]) -> None:
    """Append a sticky ``ua_rotation`` signal when a session sends >1 distinct HTTP User-Agent.

    A real client presents ONE fixed User-Agent for the session's lifetime (the UA string is pinned per
    browser build; changing it requires a restart, i.e. a new session). Two distinct ``http_user_agent``
    under one session id is therefore a single client rotating its UA mid-session — the within-session
    analog of ``ja4_unstable``/``ip_rotation``, and the tell that catches a SAME-ENGINE UA rotator
    (cycling Chrome build strings) that keeps JA4/h2/OS coherent and slips past every cross-layer UA rule.
    The merge keeps only the latest ``http_user_agent``, so a running set is persisted as ``ua_seen``;
    ``ua_rotation`` is sticky once tripped. FP-safe: no real browser varies its UA within a session, and
    browserforge calibration carries no network/UA layer, so promotion cannot raise its legit flag rate.
    """
    uas: set[str] = set()
    for s in network:
        if s.kind == "http_user_agent" and isinstance(s.value, str):
            uas.add(s.value)
        elif s.kind == "ua_seen" and isinstance(s.value, list):
            uas.update(v for v in s.value if isinstance(v, str))
    if not uas:
        return
    ref = next(s for s in network if s.kind in ("http_user_agent", "ua_seen"))
    acc = next((s for s in network if s.kind == "ua_seen"), None)
    if acc is None:
        network.append(
            Signal(
                schema_version=ref.schema_version,
                session_id=ref.session_id,
                layer=Layer.network,
                kind="ua_seen",
                value=sorted(uas),
                source=ref.source,
                observed_at=ref.observed_at,
            )
        )
    else:
        acc.value = sorted(uas)
    if len(uas) >= 2 and not any(s.kind == "ua_rotation" for s in network):
        network.append(
            Signal(
                schema_version=ref.schema_version,
                session_id=ref.session_id,
                layer=Layer.network,
                kind="ua_rotation",
                value=True,
                source=ref.source,
                observed_at=ref.observed_at,
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
    _annotate_ip_rotation(groups.network)
    _annotate_ua_rotation(groups.network)

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

    # Within-session network coherence runs over the FULL pre-collapse history: the latest-per-kind
    # collapse hides a mid-session rotation (and the running observed_ip_seen accumulator would collide),
    # so derive these from existing+new, then carry the result into the collapsed group authoritatively.
    history = [*existing.signals.network, *new.signals.network]
    _annotate_ja4_instability(history)
    _annotate_ip_rotation(history)
    _annotate_ua_rotation(history)
    for kind in ("ja4_unstable", "ip_rotation", "observed_ip_seen", "ua_rotation", "ua_seen"):
        derived = next((s for s in history if s.kind == kind), None)
        groups.network = [s for s in groups.network if s.kind != kind]
        if derived is not None:
            groups.network.append(derived)

    return Session(
        schema_version=SCHEMA_VERSION,
        session_id=existing.session_id,
        remote_ip=existing.remote_ip or new.remote_ip,
        first_seen=min(existing.first_seen, new.first_seen),
        last_seen=max(existing.last_seen, new.last_seen),
        request_count=existing.request_count + new.request_count,
        signals=groups,
    )
