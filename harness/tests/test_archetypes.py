# harness/tests/test_archetypes — the adversary archetype catalog: lookup, plan shape, threat/binding coverage.
# Asserts every persona resolves to a runnable plan dict and the caught/candidate outcomes span the ladder.

from __future__ import annotations

import pytest

from kitsune_harness.archetypes import all_archetypes, get


def test_catalog_is_populated_and_well_formed() -> None:
    archs = all_archetypes()
    assert len(archs) >= 4
    for a in archs:
        assert a.name and a.threat and a.summary and a.nodes
        assert a.expected in ("caught", "candidate") or a.expected.startswith("caught")
        assert all(n.replicas >= 1 for n in a.nodes)


def test_known_archetypes_resolve() -> None:
    stuffer = get("credential-stuffer")
    assert stuffer.threat == "account-fraud" and stuffer.binding == "fp_collision"
    assert stuffer.nodes[0].evasion == "camoufox-hardened" and stuffer.nodes[0].task == "form-fill"
    sybil = get("sybil-farmer")
    assert sybil.expected == "candidate" and len({n.evasion for n in sybil.nodes}) >= 3  # diverse → no collision


def test_unknown_archetype_lists_known() -> None:
    with pytest.raises(KeyError) as exc:
        get("nope")
    assert "credential-stuffer" in str(exc.value)


def test_to_plan_obj_is_plan_shaped() -> None:
    obj = get("scraper").to_plan_obj(detector="http://localhost:8099")
    assert obj["detector"] == "http://localhost:8099"
    assert obj["nodes"] == [{"evasion": "zendriver-uach", "replicas": 3, "task": "scrape-scroll"}]
    # a node with no task omits the key
    sybil = get("sybil-farmer").to_plan_obj()
    assert all("task" not in n for n in sybil["nodes"])


def test_catalog_spans_caught_and_evaded() -> None:
    outcomes = {a.expected.split()[0] for a in all_archetypes()}  # "caught (with …)" → "caught"
    assert "caught" in outcomes and "candidate" in outcomes  # the honest ladder: some caught, the diversified evades
