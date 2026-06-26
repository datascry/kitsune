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
        # Self-hosted arena replicas (owned-only — the challenge-gate service + PoW gate testbed).
        ("http://arena:8095/arena/challenge", True),
        ("http://arena-gate:8095/arena/verify", True),
        ("http://pow-gate:8090/challenge", True),
        # Newly approved dedicated test/demo hosts.
        ("https://accounts.hcaptcha.com/demo", True),
        ("https://demo.funcaptcha.com/", True),
        ("https://scrapfly.io/web-scraping-tools/ja3-fingerprint", True),
        ("https://browserscan.net/", True),
        ("https://arh.antoinevastel.com/bots/areyouheadless", True),
        ("https://example.com/", False),
        ("https://www.google.com/search", False),  # over-broad host stays OUT (reCAPTCHA demo path notwithstanding)
        ("https://hcaptcha.com/", False),  # marketing root is not the demo host (accounts.hcaptcha.com is)
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


@pytest.mark.parametrize(
    "url",
    [
        "https://challenges.cloudflare.com/turnstile/v0/api.js",  # live Turnstile — the arena models, never solves
        "https://www.google.com/recaptcha/api2/demo",  # over-broad host stays OUT
        "https://hcaptcha.com/1/api.js",  # marketing root, not the demo host
    ],
)
def test_arena_solver_refuses_live_third_party_challenge(url: str) -> None:
    # The arena's reference solvers may only ever hit our own gates (arena/pow-gate). A live third-party
    # challenge endpoint is refused — the self-hosted-replica line, enforced in code.
    assert is_allowed(url) is False
    with pytest.raises(EthicsError, match="allow-list"):
        assert_allowed(url)
