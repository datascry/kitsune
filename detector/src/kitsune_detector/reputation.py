# detector/reputation — offline datacenter/hosting ASN classification.
# AS-org keyword match; builds the reputation.asn_is_datacenter signal.

"""Reputation enrichment — offline datacenter/hosting ASN classification.

Deliberately data-light for the spine: an AS-org keyword match, no paid API, matching the
self-contained-lab ethics. Swap in a real IP→ASN MMDB (iptoasn.com / GeoLite2-ASN) later behind
the same interface.
"""

from __future__ import annotations

from datetime import UTC, datetime

from .config import SCHEMA_VERSION
from .models import Layer, Signal, Source

#: AS-org substrings that indicate a datacenter / hosting / cloud provider (lower-cased match).
DATACENTER_ORG_MARKERS = frozenset(
    {
        "amazon",
        "aws",
        "google",
        "gcp",
        "microsoft",
        "azure",
        "hetzner",
        "ovh",
        "vultr",
        "digitalocean",
        "linode",
        "akamai",
        "cloudflare",
        "oracle",
        "scaleway",
        "leaseweb",
        "contabo",
        "alibaba",
        "tencent",
        "datacamp",
        "hosting",
        "colo",
    }
)


def is_datacenter_asn(asn_org: str | None) -> bool:
    """True if the AS organisation name looks like a datacenter / hosting provider."""
    if not asn_org:
        return False
    org = asn_org.lower()
    return any(marker in org for marker in DATACENTER_ORG_MARKERS)


def reputation_signal(
    session_id: str,
    asn_org: str | None,
    *,
    observed_at: datetime | None = None,
) -> Signal:
    """Build the ``reputation.asn_is_datacenter`` signal for a session."""
    return Signal(
        schema_version=SCHEMA_VERSION,
        session_id=session_id,
        layer=Layer.reputation,
        kind="asn_is_datacenter",
        value=is_datacenter_asn(asn_org),
        source=Source.detector,
        observed_at=observed_at or datetime.now(UTC),
    )
