# harness/allowlist — the ethics invariant, enforced in code.
# Evaders may target only the local detector or the approved public test endpoints.

"""Ethics, enforced in code — not just documented.

Evaders may target only Kitsune's own detector and a fixed allow-list of public test endpoints
built for this. The harness refuses anything else; the self-contained arena *is* the ethics design.
"""

from __future__ import annotations

from urllib.parse import urlparse

#: Kitsune's own detector, reachable locally.
_OWN_DETECTOR_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "detector", "edge"})

#: Public endpoints explicitly built for bot/fingerprint testing (see docs/architecture.md §11).
ALLOWED_TEST_HOSTS = frozenset(
    {
        "bot.sannysoft.com",
        "abrahamjuliot.github.io",
        "browserleaks.com",
        "tls.peet.ws",
        "demo.fingerprint.com",
        "bot.incolumitas.com",
    }
)


class EthicsError(RuntimeError):
    """Raised when an evader is pointed at a target outside the allow-list."""


def is_allowed(url: str) -> bool:
    host = urlparse(url).hostname
    if host is None:
        return False
    return host in _OWN_DETECTOR_HOSTS or host in ALLOWED_TEST_HOSTS


def assert_allowed(url: str) -> None:
    if not is_allowed(url):
        raise EthicsError(
            f"target {url!r} is not on the Kitsune allow-list; "
            "evaders may only hit the local detector or the approved public test endpoints"
        )
