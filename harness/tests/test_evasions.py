# harness/tests/test_evasions — the red-team evasion registry: lookup, env overlay, families, naming.
# Asserts every named evasion resolves to a buildable kitsune-* image so the fleet manager can launch it.

from __future__ import annotations

import re

import pytest

from kitsune_harness.evasions import all_evasions, families, get


def test_registry_is_populated_and_well_formed() -> None:
    evs = all_evasions()
    assert len(evs) >= 15
    for ev in evs:
        assert ev.name and ev.image and ev.family and ev.summary


def test_known_evasions_resolve_to_image_and_env() -> None:
    uach = get("zendriver-uach")
    assert uach.image == "kitsune-zendriver:latest" and uach.env == {"KS_UACH": "1"}
    capstone = get("zendriver-uach-behave")
    assert capstone.env == {"KS_UACH": "1", "KS_BEHAVE": "1"}
    assert get("camoufox-linux").env == {"KS_LINUX": "1"}
    assert get("vanilla").env == {}  # the control carries no evasion env


def test_unknown_evasion_lists_the_known_names() -> None:
    with pytest.raises(KeyError) as exc:
        get("does-not-exist")
    assert "camoufox-linux" in str(exc.value)  # the error lists what IS available


def test_env_with_overlays_extra() -> None:
    ev = get("camoufox-linux")
    assert ev.env_with({"KS_PROXY": "socks5://p"}) == {"KS_LINUX": "1", "KS_PROXY": "socks5://p"}
    assert ev.env == {"KS_LINUX": "1"}  # the registry entry is not mutated (frozen + copy)


def test_families_group_the_ladder() -> None:
    fams = families()
    assert {"camoufox", "chromium-cdp", "control"} <= set(fams)
    assert {e.name for e in fams["chromium-cdp"]} >= {"zendriver-uach", "nodriver", "pydoll", "undetected"}


def test_every_image_is_a_kitsune_tag() -> None:
    # Each evasion must map to a buildable kitsune-*:latest image (so the fleet manager can launch it).
    for ev in all_evasions():
        assert re.fullmatch(r"kitsune-[a-z0-9-]+:latest", ev.image), ev.image
