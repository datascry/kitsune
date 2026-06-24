# detector/ip_reputation — classify an observed IP as datacenter/hosting or a known proxy/VPN/Tor exit.
# Pure-stdlib CIDR matching over curated public lists (cloud ranges, Tor exits); no paid API.

"""IP reputation — the producer for ``reputation.asn_is_datacenter`` / ``reputation.is_proxy_exit``.

Commercial anti-bot leans heavily on IP reputation (datacenter ASN, proxy/VPN/Tor exit); Kitsune had the
rules but no feed (see ``docs/landscape.md``). This is the feed: match the observed source IP against
curated public CIDR lists with stdlib ``ipaddress``. Lists load from committed seeds (``data/*.txt``) and
are refreshable from the public sources documented in ``docs/ip-reputation-data.md`` — no paid API, in
keeping with the self-contained lab.

Lookup is a **prefix-length-indexed hash**, not a linear scan: a network of prefix length *P* contains an
address *A* iff ``(A & mask_P) == network_address``, so each network's masked integer is stored in a
per-``(version, prefixlen)`` set and an address is tested by masking it to every prefix length present and
probing that set. That is O(distinct prefix lengths) — ~15-25 hash probes — instead of O(N) over the whole
list, which matters once a deploy populates the full ~67k-CIDR production feed (the seed was small enough
that a linear scan was fine; the full feed, scanned twice per session, was not).
"""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from pathlib import Path

_Net = ipaddress.IPv4Network | ipaddress.IPv6Network
_DATA = Path(__file__).parent / "data"
_BITS = {4: 32, 6: 128}

#: Per-version index: {version: {prefixlen: {masked network int, …}}} plus the sorted prefix lengths present.
_Index = tuple[dict[int, dict[int, set[int]]], dict[int, tuple[int, ...]]]


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


def _build_index(nets: tuple[_Net, ...]) -> _Index:
    """Index networks by (version, prefixlen) for O(distinct-prefix-lengths) membership. ``network_address``
    is already masked (``ip_network`` canonicalises, even with ``strict=False``), so it is exactly the value
    a contained address masks down to."""
    by_len: dict[int, dict[int, set[int]]] = {4: {}, 6: {}}
    for net in nets:
        by_len[net.version].setdefault(net.prefixlen, set()).add(int(net.network_address))
    lens = {v: tuple(sorted(by_len[v])) for v in (4, 6)}
    return by_len, lens


def _index_contains(addr_int: int, version: int, index: _Index) -> bool:
    """True iff some indexed network of this version contains ``addr_int``."""
    by_len, lens = index
    table = by_len[version]
    bits = _BITS[version]
    for plen in lens[version]:
        mask = ((1 << plen) - 1) << (bits - plen)  # plen leading 1-bits (plen=0 -> 0, the /0 case)
        if (addr_int & mask) in table[plen]:
            return True
    return False


@dataclass(frozen=True)
class IPReputation:
    """Curated datacenter/hosting and proxy/VPN/Tor-exit CIDR sets; classifies an IP against them."""

    datacenter: tuple[_Net, ...] = ()
    proxy_exit: tuple[_Net, ...] = ()
    # Derived prefix-length indexes (built once in __post_init__). Excluded from eq/hash/repr — the CIDR
    # tuples above are the canonical, public data; these are just accelerators over the same content.
    _dc_index: _Index = field(init=False, repr=False, compare=False)
    _px_index: _Index = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "_dc_index", _build_index(self.datacenter))
        object.__setattr__(self, "_px_index", _build_index(self.proxy_exit))

    def classify(self, ip: str) -> tuple[bool, bool]:
        """Return ``(is_datacenter, is_proxy_exit)`` for ``ip``; ``(False, False)`` if it is invalid,
        private, or matches nothing (a private/LAN address is never datacenter or proxy)."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return (False, False)
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return (False, False)
        addr_int, version = int(addr), addr.version
        return (
            _index_contains(addr_int, version, self._dc_index),
            _index_contains(addr_int, version, self._px_index),
        )

    @classmethod
    def from_seed(cls) -> IPReputation:
        """Load the committed seed lists (non-exhaustive; refresh per docs/ip-reputation-data.md)."""
        return cls(
            datacenter=_parse_cidrs(_seed_file("datacenter_cidrs.txt")),
            proxy_exit=_parse_cidrs(_seed_file("proxy_exit_cidrs.txt")),
        )
