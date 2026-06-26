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

#: Self-hosted ARENA replicas we run (the challenge-gate service + the PoW gate testbed). These are owned,
#: loopback/compose-internal hostnames that model documented OPEN mechanisms — never a third-party endpoint.
#: New self-hosted replicas are added here explicitly (the plan's §0.3); the list stays owned-only.
_OWN_REPLICA_HOSTS = frozenset({"arena", "arena-gate", "pow-gate"})

#: Public endpoints explicitly built for bot/fingerprint testing (see docs/architecture.md §13).
#: Only DEDICATED test/demo hosts belong here — never a third-party production site, and never an
#: over-broad host (e.g. ``www.google.com`` is EXCLUDED: it would permit all of Google, not just the
#: reCAPTCHA demo path; host matching is exact, so reCAPTCHA/Turnstile are evaluated via self-hosting instead).
ALLOWED_TEST_HOSTS = frozenset(
    {
        # Fingerprint / bot self-test pages (the original set).
        "bot.sannysoft.com",
        "abrahamjuliot.github.io",  # CreepJS
        "browserleaks.com",
        "tls.peet.ws",  # JA3/JA4 + HTTP/2 echo
        "demo.fingerprint.com",  # FingerprintJS Pro Smart-Signals demo
        "bot.incolumitas.com",  # static + behavioral bot test
        # Vendor-official challenge demos (built by the vendor for evaluation).
        "accounts.hcaptcha.com",  # hCaptcha official demo
        "demo.funcaptcha.com",  # Arkose Labs / FunCaptcha official demo
        # Fingerprint-echo / bot-test services (purpose-built tools, not production sites).
        "scrapfly.io",  # JA3/JA4 + HTTP/2 fingerprint + antibot-detector tools
        "browserscan.net",  # composite fingerprint-authenticity + bot test
        "pixelscan.net",  # fingerprint <-> IP/geo coherence test
        "deviceandbrowserinfo.com",  # Vastel fingerprint + bot signals
        "arh.antoinevastel.com",  # Vastel are-you-headless / fp-collect
        "fingerprint-scan.com",  # fingerprint + bot-risk-score tool
    }
)


class EthicsError(RuntimeError):
    """Raised when an evader is pointed at a target outside the allow-list."""


def is_allowed(url: str) -> bool:
    host = urlparse(url).hostname
    if host is None:
        return False
    return host in _OWN_DETECTOR_HOSTS or host in _OWN_REPLICA_HOSTS or host in ALLOWED_TEST_HOSTS


def assert_allowed(url: str) -> None:
    if not is_allowed(url):
        raise EthicsError(
            f"target {url!r} is not on the Kitsune allow-list; "
            "evaders may only hit the local detector or the approved public test endpoints"
        )
