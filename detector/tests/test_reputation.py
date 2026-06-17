# tests/test_reputation — detector test module.
# Asserts behaviour and edge cases for the unit under test.

from __future__ import annotations

import pytest

from kitsune_detector.models import Layer, Source
from kitsune_detector.reputation import is_datacenter_asn, reputation_signal

from .conftest import FIXED


@pytest.mark.parametrize(
    ("org", "expected"),
    [
        (None, False),
        ("", False),
        ("Comcast Cable", False),
        ("Amazon.com, Inc.", True),
        ("HETZNER ONLINE GMBH", True),  # case-insensitive
        ("OVH SAS", True),
    ],
)
def test_is_datacenter_asn(org: str | None, expected: bool) -> None:
    assert is_datacenter_asn(org) is expected


def test_reputation_signal_with_explicit_time() -> None:
    sig = reputation_signal("s", "Amazon AWS", observed_at=FIXED)
    assert sig.layer is Layer.reputation
    assert sig.kind == "asn_is_datacenter"
    assert sig.value is True
    assert sig.source is Source.detector
    assert sig.observed_at == FIXED


def test_reputation_signal_defaults_time() -> None:
    sig = reputation_signal("s", "Comcast")
    assert sig.value is False
    assert sig.observed_at is not None
