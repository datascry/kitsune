# tests/test_detector — detector test module.
# Asserts behaviour and edge cases for the unit under test.

from __future__ import annotations

import ipaddress

from kitsune_detector.detector import Detector
from kitsune_detector.ip_reputation import IPReputation
from kitsune_detector.models import Label, Layer, Session, Source

from .conftest import FIXED, make_signal


def test_classify_ip_projects_reputation_for_the_wire_panel() -> None:
    # The wire panel's IP-reputation row reads this: datacenter/hosting + proxy/VPN/Tor membership against
    # the curated CIDR lists, with a clean residential IP returning both False.
    det = Detector(
        ip_reputation=IPReputation(
            datacenter=(ipaddress.ip_network("11.0.0.0/24"),),
            proxy_exit=(ipaddress.ip_network("12.0.0.0/24"),),
        )
    )
    assert det.classify_ip("11.0.0.7") == {"datacenter": True, "proxy_exit": False}
    assert det.classify_ip("12.0.0.7") == {"datacenter": False, "proxy_exit": True}
    assert det.classify_ip("203.0.113.7") == {"datacenter": False, "proxy_exit": False}


def test_scores_human_as_clean(detector: Detector, human_session: Session) -> None:
    verdict = detector.score(human_session)
    assert verdict.label is Label.human
    assert verdict.score == 0.0
    assert verdict.contradictions == []
    assert verdict.scored_at == FIXED
    assert verdict.ruleset_version == detector.ruleset_version


def test_scores_bot_as_bot(detector: Detector, bot_session: Session) -> None:
    verdict = detector.score(bot_session)
    assert verdict.label is Label.bot
    assert verdict.score > 0.9
    assert verdict.incoherence_score > 0.0
    assert len(verdict.contradictions) >= 5
    # explainability: every contradiction carries evidence
    assert all(c.evidence for c in verdict.contradictions)


def test_fake_declared_crawler_convicts(detector: Detector) -> None:
    # A UA declaring a crawler whose IP fails FCrDNS (edge emits network.fake_declared_crawler) is a
    # convicting coherence tell — the network identity contradicts the declared crawler UA.
    verdicts = detector.ingest_and_score(
        [make_signal("c", Layer.network, "fake_declared_crawler", True, source=Source.edge)]
    )
    v = verdicts[0]
    assert v.label is Label.bot
    assert any(c.rule_id == "net.fake_declared_crawler" for c in v.contradictions)


def test_verified_web_bot_auth_agent_is_allow_listed(detector: Detector) -> None:
    # A cryptographically verified Web Bot Auth agent that also has no JS (a real, declared good bot) is
    # allow-listed (Label.verified), overriding the bot verdict its automation signals would earn.
    verified = detector.ingest_and_score(
        [
            make_signal("v", Layer.network, "web_bot_auth_verified", True, source=Source.edge),
            make_signal("v", Layer.network, "browser_absent", True, source=Source.edge),
        ]
    )[0]
    assert verified.label is Label.verified
    # A FORGED signature (web_bot_auth_invalid) is convicted, never allow-listed.
    forged = detector.ingest_and_score(
        [make_signal("f", Layer.network, "web_bot_auth_invalid", True, source=Source.edge)]
    )[0]
    assert forged.label is Label.bot
    assert any(c.rule_id == "net.web_bot_auth_invalid" for c in forged.contradictions)


def test_ingest_and_score(detector: Detector) -> None:
    signals = [
        make_signal("z", Layer.browser, "webdriver", True, source=Source.collector),
        make_signal("z", Layer.network, "ja4_os_hint", "windows", source=Source.edge),
    ]
    verdicts = detector.ingest_and_score(signals)
    assert len(verdicts) == 1
    assert verdicts[0].session_id == "z"


def test_default_clock_is_timezone_aware(human_session: Session) -> None:
    verdict = Detector().score(human_session)  # no injected clock -> _utcnow
    assert verdict.scored_at.tzinfo is not None
