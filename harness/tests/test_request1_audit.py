# tests/test_request1_audit — the request-1 / no-JS separation audit.
# Guards the botwall pitch number: real browsers never convict network-only, evaders do, and the rule set is sound.

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from kitsune_detector.detector import Detector
from kitsune_detector.models import Layer, Session, Signal, SignalGroups, Source

from kitsune_harness.request1_audit import (
    CAPTURE_INFIDELITIES,
    GRACE_OR_MULTICONN,
    audit,
    network_only,
    render,
    request1_rule_ids,
)

REPO = Path(__file__).resolve().parents[2]
FIXED = datetime(2026, 7, 16, 12, 0, 0, tzinfo=UTC)


def test_request1_rule_ids_are_convicting_network_and_exclude_grace() -> None:
    ids = request1_rule_ids()
    assert ids, "expected a non-empty request-1 convicting rule set"
    assert GRACE_OR_MULTICONN.isdisjoint(ids), "grace-window / multi-connection rules must be excluded"
    assert "net.no_js_execution" not in ids
    # a representative spread of genuinely request-1 network-coherence rules
    assert {"net.tls_vs_ua_browser", "net.h2_vs_ua_browser", "net.tcp_os_vs_ua"} <= ids


def test_network_only_strips_the_js_layers() -> None:
    def sig(layer: Layer, kind: str, value: object) -> Signal:
        return Signal(session_id="x", layer=layer, kind=kind, value=value, source=Source.edge, observed_at=FIXED)

    session = Session(
        session_id="x",
        first_seen=FIXED,
        last_seen=FIXED,
        request_count=1,
        signals=SignalGroups(
            network=[sig(Layer.network, "ja4_browser_hint", "chrome")],
            browser=[sig(Layer.browser, "webdriver", True)],
            behavioral=[sig(Layer.behavioral, "mouse_entropy", 0.1)],
            reputation=[sig(Layer.reputation, "asn_is_datacenter", True)],
        ),
    )
    stripped = network_only(session)
    assert stripped.signals.browser == []
    assert stripped.signals.behavioral == []
    assert len(stripped.signals.network) == 1
    assert len(stripped.signals.reputation) == 1  # reputation is IP-derived, available with no JS


def test_real_browsers_never_convict_request1_and_evaders_do() -> None:
    report = audit(Detector(), REPO)
    assert report.real, "expected real-browser captures loaded"
    assert report.evaders, "expected evader captures loaded"
    # The regression guard: no FAITHFUL real-browser capture convicts on request-1 network-only.
    unexpected = {o.name for o in report.false_positives} - CAPTURE_INFIDELITIES
    assert unexpected == set(), f"real browsers convicted network-only on request 1: {unexpected}"
    assert report.faithful_false_positives == []
    # The edge stops a real fraction of evaders at the door with no JS.
    assert report.recall > 0.0
    assert 0.0 <= report.fp_rate <= 1.0


def test_render_emits_the_headline_number() -> None:
    text = render(audit(Detector(), REPO))
    assert "Request-1 / no-JS separation audit" in text
    assert "Recall on evaders" in text
    assert "request-1 convicting rules" in text
