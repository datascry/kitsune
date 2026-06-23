# detector/ip_reputation — classify an observed IP as datacenter/hosting or a known proxy/VPN/Tor exit.
# Pure-stdlib CIDR matching over curated public lists (cloud ranges, Tor exits); no paid API.

"""IP reputation — the producer for ``reputation.asn_is_datacenter`` / ``reputation.is_proxy_exit``.

Commercial anti-bot leans heavily on IP reputation (datacenter ASN, proxy/VPN/Tor exit); Kitsune had the
rules but no feed (see ``docs/landscape.md``). This is the feed: match the observed source IP against
curated public CIDR lists with stdlib ``ipaddress``. Lists load from committed seeds (``data/*.txt``) and
are refreshable from the public sources documented in ``docs/ip-reputation-data.md`` — no paid API, in
keeping with the self-contained lab. Linear CIDR scan: fine for a seed; a production feed would use a
prefix trie.
"""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass
from pathlib import Path

_Net = ipaddress.IPv4Network | ipaddress.IPv6Network
_DATA = Path(__file__).parent / "data"


def _seed_file(name: str) -> str:
    """Read a seed list, preferring a deploy-mounted ``KITSUNE_IPREP_DIR`` (the refreshed full lists) and
    falling back to the committed in-package seed. Mirrors ``KITSUNE_GEOIP_DIR`` — lets the operator land a
    bigger ``ip_reputation_refresh`` output on the VPS via a read-only mount without rebuilding the image."""
    base = os.environ.get("KITSUNE_IPREP_DIR")
    if base:
        mounted = Path(base) / name
        if mounted.is_file():
            return mounted.read_text(encoding="utf-8")
    return (_DATA / name).read_text(encoding="utf-8")


def _parse_cidrs(text: str) -> tuple[_Net, ...]:
    """Parse one-CIDR-per-line text, ignoring blanks and ``#`` comments."""
    nets: list[_Net] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            nets.append(ipaddress.ip_network(line, strict=False))
    return tuple(nets)


@dataclass(frozen=True)
class IPReputation:
    """Curated datacenter/hosting and proxy/VPN/Tor-exit CIDR sets; classifies an IP against them."""

    datacenter: tuple[_Net, ...] = ()
    proxy_exit: tuple[_Net, ...] = ()

    def classify(self, ip: str) -> tuple[bool, bool]:
        """Return ``(is_datacenter, is_proxy_exit)`` for ``ip``; ``(False, False)`` if it is invalid,
        private, or matches nothing (a private/LAN address is never datacenter or proxy)."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return (False, False)
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return (False, False)
        is_dc = any(addr in net for net in self.datacenter)
        is_px = any(addr in net for net in self.proxy_exit)
        return (is_dc, is_px)

    @classmethod
    def from_seed(cls) -> IPReputation:
        """Load the committed seed lists (non-exhaustive; refresh per docs/ip-reputation-data.md)."""
        return cls(
            datacenter=_parse_cidrs(_seed_file("datacenter_cidrs.txt")),
            proxy_exit=_parse_cidrs(_seed_file("proxy_exit_cidrs.txt")),
        )
