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
    # a cloned-fp persona must use a DETERMINISTIC-fingerprint tool (not camoufox, which randomizes per launch)
    assert stuffer.nodes[0].evasion == "zendriver-uach" and stuffer.nodes[0].task == "form-fill"
    sybil = get("sybil-farmer")
    # diversity via camoufox's per-launch fp randomization (NOT a Chromium mix, which would collide → caught)
    assert sybil.expected == "candidate" and all(n.evasion.startswith("camoufox") for n in sybil.nodes)


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


def test_binding_matches_tool_fingerprint_behaviour() -> None:
    # The structural contract the live validator taught: fp_collision needs a DETERMINISTIC-fingerprint Chromium
    # clone (one tool, NOT camoufox — it randomizes per launch); a `none`/diverse persona avoids collision via
    # camoufox's per-launch randomization (a Chromium-tool mix would COLLIDE — zendriver+nodriver render alike).
    from kitsune_harness.evasions import get as get_evasion

    for a in all_archetypes():
        if a.binding == "fp_collision":
            assert len({n.evasion for n in a.nodes}) == 1, f"{a.name}: a cloned persona must use ONE tool"
            assert get_evasion(a.nodes[0].evasion).family != "camoufox", f"{a.name}: camoufox randomizes — no fp"
        if a.binding == "none":
            assert all(get_evasion(n.evasion).family == "camoufox" for n in a.nodes), f"{a.name}: not fp-diverse"
        if a.binding == "trace_collision":
            # a canned-replay persona: DISTINCT fingerprints (camoufox) but ONE shared trace via a pinned seed.
            assert all(get_evasion(n.evasion).family == "camoufox" for n in a.nodes), f"{a.name}: needs distinct fps"
            assert all(n.env.get("KS_TASK_SEED") and n.task for n in a.nodes), f"{a.name}: needs a seeded task"


def test_catalog_spans_caught_and_evaded() -> None:
    outcomes = {a.expected.split()[0] for a in all_archetypes()}  # "caught (with …)" → "caught"
    assert "caught" in outcomes and "candidate" in outcomes  # the honest ladder: some caught, the diversified evades
