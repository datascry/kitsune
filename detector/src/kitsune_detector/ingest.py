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


def _annotate_h2_instability(network: list[Signal]) -> None:
    """Append a sticky ``h2_unstable`` signal when a session's network signals carry >1 distinct h2 fingerprint.

    The edge's ``h2`` is the Akamai HTTP/2 fingerprint — SETTINGS + WINDOW_UPDATE + PRIORITY + the request
    PSEUDO-header order, all connection-preface choices fixed per browser build (the pseudo-header order is
    request-type-invariant; the regular header order is NOT in the string). So a real client emits ONE h2
    fingerprint for the session's lifetime, the same way JA4_b is its TLS-engine identity. Two distinct ``h2``
    under one session id is a single client rotating its HTTP/2 stack mid-session — distinct from JA4 rotation
    (a tool can pin one TLS ClientHello, hence one JA4_b, yet vary its h2 SETTINGS), so this catches the h2
    rotator that slips past ``ja4_unstable``. Sticky once tripped; FP-safe (no real browser varies its h2
    preface within a session, and browserforge calibration carries no network layer).
    """
    if any(s.kind == "h2_unstable" for s in network):
        return
    distinct = {s.value for s in network if s.kind == "h2" and isinstance(s.value, str)}
    if len(distinct) <= 1:
        return
    ref = next(s for s in network if s.kind == "h2")
    network.append(
        Signal(
            schema_version=ref.schema_version,
            session_id=ref.session_id,
            layer=Layer.network,
            kind="h2_unstable",
            value=True,
            source=ref.source,
            observed_at=max(s.observed_at for s in network if s.kind == "h2"),
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


#: Browser-fingerprint fields that are HARDWARE/OS-invariant for a session's lifetime — a real client's CPU, GPU
#: and OS do not change without a new browser process (a new session). A re-randomising anti-detect browser
#: (Camoufox randomises these per LAUNCH) that restarts mid-crawl while reusing one cookie presents >1 distinct
#: value here. screen_resolution/color_depth are deliberately EXCLUDED — a real user can resize a window or move it
#: to another monitor mid-session, so those are not FP-safe within-session invariants.
_FP_INVARIANT_FIELDS = ("hardware_concurrency", "webgl_renderer", "webgl_vendor", "nav_platform_os")


def _annotate_fp_rotation(browser: list[Signal]) -> None:
    """Append a sticky ``fp_unstable`` signal when a session presents >1 distinct value on any hardware-invariant
    browser-fingerprint field — the browser-layer analog of ja4/ip/ua rotation.

    The merge keeps only the latest signal per kind, so the running per-field seen-sets are persisted as ``fp_seen``
    (a dict field->sorted list) to survive the collapse. ``fp_unstable`` is sticky once tripped. FP-safe: no real
    browser changes its CPU/GPU/OS mid-session, and browserforge calibration samples one fingerprint per session
    (one value per field), so promotion cannot raise its legit-browser flag rate.
    """
    seen: dict[str, set[str]] = {}
    for s in browser:
        if s.kind == "fp_seen" and isinstance(s.value, dict):
            for k, v in s.value.items():
                if isinstance(v, list):
                    seen.setdefault(k, set()).update(str(x) for x in v)
        elif s.kind in _FP_INVARIANT_FIELDS:
            seen.setdefault(s.kind, set()).add(str(s.value))
    if not seen:
        return
    ref = next(s for s in browser if s.kind in _FP_INVARIANT_FIELDS or s.kind == "fp_seen")
    payload = {k: sorted(v) for k, v in seen.items()}
    acc = next((s for s in browser if s.kind == "fp_seen"), None)
    if acc is None:
        browser.append(
            Signal(
                schema_version=ref.schema_version,
                session_id=ref.session_id,
                layer=Layer.browser,
                kind="fp_seen",
                value=payload,
                source=ref.source,
                observed_at=ref.observed_at,
            )
        )
    else:
        acc.value = payload
    if any(len(v) >= 2 for v in seen.values()) and not any(s.kind == "fp_unstable" for s in browser):
        browser.append(
            Signal(
                schema_version=ref.schema_version,
                session_id=ref.session_id,
                layer=Layer.browser,
                kind="fp_unstable",
                value=True,
                source=ref.source,
                observed_at=ref.observed_at,
            )
        )


def _annotate_trace_replay(behavioral: list[Signal]) -> None:
    """Append a sticky ``trace_replay`` signal when one session emits the SAME pointer ``trace_hash`` on >1 page load.

    The within-session analog of coordination's cross-session ``trace_collision``: a ``trace_hash`` is a coordinate-
    quantised pointer-trajectory shape (null below a 12-point movement floor, so trivial/no-motion loads cannot
    collide). A real human never reproduces a path — every page load traces differently — so an INVARIANT trace_hash
    across two loads under one session id is a record-and-replay bot injecting one canned "humanised" trajectory.
    The merge keeps only the latest trace_hash, so the per-hash set of distinct page-load timestamps is persisted as
    ``trace_seen`` (a dict hash->sorted timestamp list, surviving the collapse); ``trace_replay`` is sticky once a
    hash recurs on >=2 distinct timestamps. FP-safe by construction (no real motion repeats byte-for-byte) and
    browserforge calibration carries no behavioral trace, so promotion cannot raise its legit-browser flag rate.
    """
    # Tag each trace_hash by the PAGE-LOAD it came from, not the emission timestamp: the live collector
    # re-posts the same unchanged trajectory several times within ONE load (the "Analyze" re-score, periodic
    # flushes, a paused pointer), which under the old observed_at keying self-collided and false-positived a
    # real human. The collector now stamps each load with a `load_nonce`; a hash only counts as replayed when
    # it recurs under >=2 DISTINCT nonces. Falls back to observed_at for nonce-less inputs (older captures and
    # the evader fixtures, whose separate loads already carry distinct timestamps).
    # Pair each trace_hash with the load_nonce emitted in the SAME post (same observed_at); the merged
    # history spans several posts/loads, so a single nonce would mis-tag. Falls back to the timestamp itself.
    nonce_at = {s.observed_at: s.value for s in behavioral if s.kind == "load_nonce" and isinstance(s.value, str)}
    seen: dict[str, set[str]] = {}
    for s in behavioral:
        if s.kind == "trace_seen" and isinstance(s.value, dict):
            for h, ts in s.value.items():
                if isinstance(ts, list):
                    seen.setdefault(h, set()).update(str(t) for t in ts)
        elif s.kind == "trace_hash" and isinstance(s.value, str):
            seen.setdefault(s.value, set()).add(nonce_at.get(s.observed_at) or s.observed_at.isoformat())
    if not seen:
        return
    ref = next(s for s in behavioral if s.kind in ("trace_hash", "trace_seen"))
    payload = {h: sorted(ts) for h, ts in seen.items()}
    acc = next((s for s in behavioral if s.kind == "trace_seen"), None)
    if acc is None:
        behavioral.append(
            Signal(
                schema_version=ref.schema_version,
                session_id=ref.session_id,
                layer=Layer.behavioral,
                kind="trace_seen",
                value=payload,
                source=ref.source,
                observed_at=ref.observed_at,
            )
        )
    else:
        acc.value = payload
    if any(len(ts) >= 2 for ts in seen.values()) and not any(s.kind == "trace_replay" for s in behavioral):
        behavioral.append(
            Signal(
                schema_version=ref.schema_version,
                session_id=ref.session_id,
                layer=Layer.behavioral,
                kind="trace_replay",
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
    _annotate_h2_instability(groups.network)  # ...likewise >1 h2 fingerprint in one batch
    _annotate_ip_rotation(groups.network)
    _annotate_ua_rotation(groups.network)
    _annotate_fp_rotation(groups.browser)
    _annotate_trace_replay(groups.behavioral)

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
    _annotate_h2_instability(history)
    _annotate_ip_rotation(history)
    _annotate_ua_rotation(history)
    for kind in ("ja4_unstable", "h2_unstable", "ip_rotation", "observed_ip_seen", "ua_rotation", "ua_seen"):
        derived = next((s for s in history if s.kind == kind), None)
        groups.network = [s for s in groups.network if s.kind != kind]
        if derived is not None:
            groups.network.append(derived)

    # The browser-layer analog: a re-randomising anti-detect browser reusing one cookie diverges its
    # hardware-invariant fingerprint fields across page loads; derive over the full pre-collapse browser history.
    browser_history = [*existing.signals.browser, *new.signals.browser]
    _annotate_fp_rotation(browser_history)
    for kind in ("fp_unstable", "fp_seen"):
        derived = next((s for s in browser_history if s.kind == kind), None)
        groups.browser = [s for s in groups.browser if s.kind != kind]
        if derived is not None:
            groups.browser.append(derived)

    # Within-session behavioral coherence: a record-and-replay bot emits the same trace_hash across page loads.
    behavioral_history = [*existing.signals.behavioral, *new.signals.behavioral]
    _annotate_trace_replay(behavioral_history)
    for kind in ("trace_replay", "trace_seen"):
        derived = next((s for s in behavioral_history if s.kind == kind), None)
        groups.behavioral = [s for s in groups.behavioral if s.kind != kind]
        if derived is not None:
            groups.behavioral.append(derived)

    return Session(
        schema_version=SCHEMA_VERSION,
        session_id=existing.session_id,
        remote_ip=existing.remote_ip or new.remote_ip,
        first_seen=min(existing.first_seen, new.first_seen),
        last_seen=max(existing.last_seen, new.last_seen),
        request_count=existing.request_count + new.request_count,
        signals=groups,
    )
