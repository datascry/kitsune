# tests/test_allowlist — harness test module.
# Asserts behaviour and edge cases for the unit under test.

from __future__ import annotations

import pytest

from kitsune_harness.allowlist import EthicsError, assert_allowed, is_allowed


@pytest.mark.parametrize(
    ("url", "allowed"),
    [
        ("http://localhost:8080/ingest", True),
        ("https://127.0.0.1/", True),
        ("https://tls.peet.ws/api/all", True),
        ("https://bot.sannysoft.com/", True),
        ("https://example.com/", False),
        ("https://www.google.com/search", False),
        ("not-a-url", False),
        ("mailto:someone@example.com", False),
    ],
)
def test_is_allowed(url: str, allowed: bool) -> None:
    assert is_allowed(url) is allowed


def test_assert_allowed_passes() -> None:
    assert_allowed("https://tls.peet.ws/api/all")


def test_assert_allowed_raises() -> None:
    with pytest.raises(EthicsError, match="allow-list"):
        assert_allowed("https://example.com/")
