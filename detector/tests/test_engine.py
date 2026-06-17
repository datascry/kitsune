# tests/test_engine — detector test module.
# Asserts behaviour and edge cases for the unit under test.

from __future__ import annotations

from kitsune_detector.coherence import load_registry
from kitsune_detector.coherence.engine import CoherenceEngine
from kitsune_detector.coherence.rules import CoherenceRule, RuleSet
from kitsune_detector.models import Layer, Session


def test_engine_flags_bot_incoherence(bot_session: Session) -> None:
    engine = CoherenceEngine(load_registry())
    fired = {c.rule_id for c in engine.evaluate(bot_session)}
    # A representative spread across all four layers.
    assert {
        "net.tls_os_vs_tcp_os",
        "net.tls_vs_ua_browser",
        "br.ua_platform_vs_ch_platform",
        "br.webdriver_present",
        "rep.datacenter_asn",
    } <= fired


def test_engine_clears_human(human_session: Session) -> None:
    engine = CoherenceEngine(load_registry())
    assert engine.evaluate(human_session) == []


def test_engine_exposes_ruleset_version() -> None:
    engine = CoherenceEngine(load_registry())
    assert engine.ruleset_version


def test_engine_skips_retired_rules(bot_session: Session) -> None:
    retired = CoherenceRule(
        id="br.webdriver_present",
        title="t",
        layers=[Layer.browser],
        reads=["browser.webdriver"],
        predicate="present",
        weight=0.9,
        status="retired",
    )
    engine = CoherenceEngine(RuleSet(ruleset_version="0", rules=[retired]))
    assert engine.evaluate(bot_session) == []
