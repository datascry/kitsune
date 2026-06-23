# detector/ip_reputation_refresh — refresh the IP-reputation seed lists from authoritative public sources.
# Fetches Tor exits + cloud ranges + X4BNet VPN/datacenter lists into data/*.txt; run at deploy (output not committed).

"""Refresh the IP-reputation feed (``data/datacenter_cidrs.txt`` / ``data/proxy_exit_cidrs.txt``).

The committed seeds are illustrative — the datacenter list is a curated sample and the proxy/Tor-exit
list ships empty, because real exits are dynamic public IPs that go stale within hours (see
``docs/ip-reputation-data.md``). This is the documented refresh path: at deploy time an operator runs
``python -m kitsune_detector.ip_reputation_refresh`` to pull live, authoritative ranges into the same
one-CIDR-per-line seed format the producer (:mod:`kitsune_detector.ip_reputation`) already reads.

Sources: Tor bulk exit list + the MIT-licensed X4BNet VPN list (proxy/VPN/Tor exits); AWS + GCP cloud
ranges + the X4BNet datacenter list (hosting). X4BNet widens both feeds well beyond the original Tor-only
proxy seed and cloud-only datacenter seed — its MIT licence (stated in the repo README, covering the list
data) keeps the lab self-contained and redistributable.

Pure-stdlib (``urllib`` + ``json``), no paid API — in keeping with the self-contained lab. The fetch is
injectable (:func:`refresh` takes a ``Fetcher``) so the parsing/normalisation is unit-tested hermetically;
only the thin network/file-write shell touches the wire. Generated output is intentionally NOT committed:
it is stale-prone and large, and the repo's curated seeds remain the documented fallback.
"""

from __future__ import annotations

import ipaddress
import json
import os
from collections.abc import Callable, Iterable
from pathlib import Path

TOR_BULK_EXIT_URL = "https://check.torproject.org/torbulkexitlist"
AWS_RANGES_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"
GCP_RANGES_URL = "https://www.gstatic.com/ipranges/cloud.json"
# X4BNet/lists_vpn — MIT-licensed (LICENSE text in the repo README explicitly covers "the list itself
# (source files and generated output)"). The Tor list alone is a thin slice of proxy egress; the VPN list
# (~11k CIDRs) is the real VPN/proxy-exit feed, and the datacenter list (~42k) covers hosting beyond AWS+GCP.
X4BNET_VPN_URL = "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt"
X4BNET_DATACENTER_URL = "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt"
# Additional cloud/CDN hosting ranges beyond AWS+GCP — each a STABLE official direct URL (Azure is omitted:
# its Service-Tags JSON download URL rotates weekly behind a portal redirect, so it needs a discovery step,
# tracked in docs/research-radar.md). A client connecting FROM these is server-side egress (a bot on the
# provider's compute), never a real eyeball, so they fold into the datacenter slice FP-safely.
ORACLE_RANGES_URL = "https://docs.oracle.com/iaas/tools/public_ip_ranges.json"
DIGITALOCEAN_RANGES_URL = "https://www.digitalocean.com/geo/google.csv"
CLOUDFLARE_V4_URL = "https://www.cloudflare.com/ips-v4"
CLOUDFLARE_V6_URL = "https://www.cloudflare.com/ips-v6"
FASTLY_RANGES_URL = "https://api.fastly.com/public-ip-list"

_DATA = Path(__file__).parent / "data"
_Net = ipaddress.IPv4Network | ipaddress.IPv6Network


class SourceDriftError(RuntimeError):
    """A refresh source returned implausibly few entries — its URL or response format likely drifted.

    The parsers are unit-tested against fixed sample payloads, so a live source changing its URL or JSON
    shape would slip past CI and silently write a near-empty seed (degrading rep.* without any error). The
    deploy path (:func:`main`) enforces per-source floors so that drift fails LOUD instead.
    """


#: Conservative per-source minimum entry counts enforced at deploy time. Live counts (X4BNet validated
#: 2026-06-21: VPN 10994, datacenter 41977; Tor/AWS/GCP 2026-06-19: Tor 1238, AWS 10613, GCP 979) — these
#: floors sit ~10x below, so normal source fluctuation passes while a format/URL drift (which collapses a
#: parse to ~0) trips the guard.
_PRODUCTION_FLOORS = {
    "tor": 100,
    "aws": 1000,
    "gcp": 100,
    "x4b_vpn": 1000,
    "x4b_datacenter": 1000,
    "oracle": 50,
    "digitalocean": 50,
    "cloudflare": 10,
    "fastly": 10,
}

#: A function that fetches a URL and returns the body as text. Injected so tests stay offline.
Fetcher = Callable[[str], str]


def parse_tor_bulk_exit(text: str) -> list[str]:
    """One IP per line → host CIDR (``/32`` IPv4, ``/128`` IPv6). Blanks, ``#`` comments, junk skipped."""
    out: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            addr = ipaddress.ip_address(line)
        except ValueError:
            continue
        out.append(f"{line}/32" if addr.version == 4 else f"{line}/128")
    return out


def parse_cidr_list(text: str) -> list[str]:
    """Plain one-CIDR-per-line list (X4BNet vpn/datacenter ipv4.txt) → validated CIDRs.

    Blanks, ``#`` comments, and unparseable lines are skipped — so a source switching to an HTML error page
    or a comment-only file parses to ~0 and trips the deploy-time floor guard rather than poisoning the seed.
    """
    out: list[str] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        try:
            ipaddress.ip_network(line, strict=False)
        except ValueError:
            continue
        out.append(line)
    return out


def parse_aws_ranges(text: str) -> list[str]:
    """AWS ``ip-ranges.json`` → ``prefixes[].ip_prefix`` + ``ipv6_prefixes[].ipv6_prefix``."""
    doc = json.loads(text)
    out: list[str] = []
    if not isinstance(doc, dict):
        return out
    for key, field in (("prefixes", "ip_prefix"), ("ipv6_prefixes", "ipv6_prefix")):
        entries = doc.get(key, [])
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if isinstance(entry, dict):
                prefix = entry.get(field)
                if isinstance(prefix, str):
                    out.append(prefix)
    return out


def parse_gcp_ranges(text: str) -> list[str]:
    """GCP ``cloud.json`` → ``prefixes[].ipv4Prefix`` / ``ipv6Prefix``."""
    doc = json.loads(text)
    out: list[str] = []
    if not isinstance(doc, dict):
        return out
    entries = doc.get("prefixes", [])
    if not isinstance(entries, list):
        return out
    for entry in entries:
        if isinstance(entry, dict):
            prefix = entry.get("ipv4Prefix") or entry.get("ipv6Prefix")
            if isinstance(prefix, str):
                out.append(prefix)
    return out


def parse_oracle_ranges(text: str) -> list[str]:
    """Oracle ``public_ip_ranges.json`` → ``regions[].cidrs[].cidr``."""
    doc = json.loads(text)
    out: list[str] = []
    if not isinstance(doc, dict):
        return out
    regions = doc.get("regions", [])
    if not isinstance(regions, list):
        return out
    for region in regions:
        if not isinstance(region, dict):
            continue
        for entry in region.get("cidrs", []) or []:
            if isinstance(entry, dict) and isinstance(entry.get("cidr"), str):
                out.append(entry["cidr"])
    return out


def parse_digitalocean_csv(text: str) -> list[str]:
    """DigitalOcean ``google.csv`` → the first column of each row is the CIDR (no header row)."""
    out: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        cidr = line.split(",", 1)[0].strip()
        if cidr:
            out.append(cidr)
    return out


def parse_fastly_ranges(text: str) -> list[str]:
    """Fastly ``public-ip-list`` → ``addresses[]`` + ``ipv6_addresses[]``."""
    doc = json.loads(text)
    out: list[str] = []
    if not isinstance(doc, dict):
        return out
    for key in ("addresses", "ipv6_addresses"):
        for cidr in doc.get(key, []) or []:
            if isinstance(cidr, str):
                out.append(cidr)
    return out


def normalize_cidrs(cidrs: Iterable[str]) -> list[str]:
    """Validate, dedupe, and sort CIDRs (by version, then network address, then prefix). Junk dropped.

    Provider granularity is preserved (no supernet collapse) so a future trie can index exact blocks.
    """
    nets: set[_Net] = set()
    for cidr in cidrs:
        try:
            nets.add(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            continue
    ordered = sorted(nets, key=lambda n: (n.version, int(n.network_address), n.prefixlen))
    return [str(n) for n in ordered]


def render_seed(title: str, note: str, cidrs: list[str]) -> str:
    """Render the two-comment-line header + one-CIDR-per-line body the seed parser expects."""
    lines = [f"# {title}", f"# {note}", ""]
    lines.extend(cidrs)
    return "\n".join(lines) + "\n"


def refresh(fetch: Fetcher, *, min_counts: dict[str, int] | None = None) -> dict[str, str]:
    """Fetch every source via ``fetch`` and return ``{filename: rendered_seed_text}``.

    Pure but for ``fetch`` — the orchestration is fully exercised in tests with an offline fetcher. When
    ``min_counts`` is given (the deploy path passes :data:`_PRODUCTION_FLOORS`), each source's parsed count
    is checked against its floor and a :class:`SourceDriftError` is raised if it falls short — so a drifted
    URL/format fails loud instead of silently writing a near-empty seed. Default ``None`` skips the check
    (keeping the pure parser tests, which use tiny canned payloads, untouched).
    """
    tor_raw = parse_tor_bulk_exit(fetch(TOR_BULK_EXIT_URL))
    aws_raw = parse_aws_ranges(fetch(AWS_RANGES_URL))
    gcp_raw = parse_gcp_ranges(fetch(GCP_RANGES_URL))
    x4b_vpn_raw = parse_cidr_list(fetch(X4BNET_VPN_URL))
    x4b_dc_raw = parse_cidr_list(fetch(X4BNET_DATACENTER_URL))
    oracle_raw = parse_oracle_ranges(fetch(ORACLE_RANGES_URL))
    do_raw = parse_digitalocean_csv(fetch(DIGITALOCEAN_RANGES_URL))
    cloudflare_raw = parse_cidr_list(fetch(CLOUDFLARE_V4_URL)) + parse_cidr_list(fetch(CLOUDFLARE_V6_URL))
    fastly_raw = parse_fastly_ranges(fetch(FASTLY_RANGES_URL))
    if min_counts:
        for src, got in (
            ("tor", len(tor_raw)),
            ("aws", len(aws_raw)),
            ("gcp", len(gcp_raw)),
            ("x4b_vpn", len(x4b_vpn_raw)),
            ("x4b_datacenter", len(x4b_dc_raw)),
            ("oracle", len(oracle_raw)),
            ("digitalocean", len(do_raw)),
            ("cloudflare", len(cloudflare_raw)),
            ("fastly", len(fastly_raw)),
        ):
            floor = min_counts.get(src, 0)
            if got < floor:
                raise SourceDriftError(
                    f"{src} source returned {got} entries (< {floor} floor) — its URL or format likely drifted"
                )
    # Proxy/VPN/Tor exits: Tor bulk list + X4BNet VPN list. Datacenter: AWS + GCP + Oracle + DigitalOcean +
    # Cloudflare + Fastly cloud/CDN ranges + X4BNet datacenter list. normalize_cidrs dedupes + sorts the union.
    proxy_exit = normalize_cidrs(tor_raw + x4b_vpn_raw)
    datacenter = normalize_cidrs(aws_raw + gcp_raw + oracle_raw + do_raw + cloudflare_raw + fastly_raw + x4b_dc_raw)
    regen = (
        "Regenerate: python -m kitsune_detector.ip_reputation_refresh "
        "(output not committed — see docs/ip-reputation-data.md)."
    )
    return {
        "proxy_exit_cidrs.txt": render_seed(
            "detector/data/proxy_exit — GENERATED proxy/VPN/Tor-exit CIDRs (deploy-time; do not commit).",
            f"Sources: Tor bulk exit list + X4BNet VPN list, MIT ({len(proxy_exit)} entries). {regen}",
            proxy_exit,
        ),
        "datacenter_cidrs.txt": render_seed(
            "detector/data/datacenter_cidrs — GENERATED datacenter/hosting CIDRs (deploy-time; do not commit).",
            f"Sources: AWS + GCP + Oracle + DigitalOcean + Cloudflare + Fastly + X4BNet datacenter "
            f"({len(datacenter)} entries). {regen}",
            datacenter,
        ),
    }


def _http_get(url: str) -> str:  # pragma: no cover - network IO shell
    import urllib.request

    with urllib.request.urlopen(url, timeout=30) as resp:
        return str(resp.read().decode("utf-8"))


def main(fetch: Fetcher = _http_get, out_dir: Path = _DATA) -> None:  # pragma: no cover - IO wrapper
    # Deploy path: enforce the per-source floors so a drifted source fails loud, not silently degraded.
    for name, content in refresh(fetch, min_counts=_PRODUCTION_FLOORS).items():
        (out_dir / name).write_text(content, encoding="utf-8")
        print(f"wrote {out_dir / name} ({content.count(chr(10))} lines)")


if __name__ == "__main__":  # pragma: no cover
    # Write to KITSUNE_IPREP_DIR when set (the deploy mount the detector reads), else the in-package seed dir.
    _env_dir = os.environ.get("KITSUNE_IPREP_DIR")
    main(out_dir=Path(_env_dir) if _env_dir else _DATA)
