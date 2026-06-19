# detector/tests/test_ip_reputation_refresh — verify the IP-reputation seed refresh from live-source shapes.
# Offline: an injected fetcher returns canned AWS/GCP/Tor payloads; asserts parsing, dedupe, and seed format.

from __future__ import annotations

import json

from kitsune_detector.ip_reputation import IPReputation, _parse_cidrs
from kitsune_detector.ip_reputation_refresh import (
    AWS_RANGES_URL,
    GCP_RANGES_URL,
    TOR_BULK_EXIT_URL,
    normalize_cidrs,
    parse_aws_ranges,
    parse_gcp_ranges,
    parse_tor_bulk_exit,
    refresh,
    render_seed,
)

_TOR = "171.25.193.25\n80.67.167.81\n\n# a comment\n2001:db8::1\nnot-an-ip\n171.25.193.25\n"
_AWS = json.dumps(
    {
        "prefixes": [
            {"ip_prefix": "3.4.12.4/32", "service": "AMAZON"},
            {"ip_prefix": "3.5.140.0/22", "service": "EC2"},
            {"no_prefix_field": "x"},
            "not-a-dict",
        ],
        "ipv6_prefixes": [{"ipv6_prefix": "2600:1f00::/40"}],
    }
)
_GCP = json.dumps(
    {
        "prefixes": [
            {"ipv4Prefix": "34.1.208.0/20", "service": "Google Cloud"},
            {"ipv6Prefix": "2600:1900::/28"},
            {"service": "no-prefix"},
            42,
        ]
    }
)


def test_parse_tor_bulk_exit_makes_host_cidrs_and_skips_junk() -> None:
    cidrs = parse_tor_bulk_exit(_TOR)
    assert "171.25.193.25/32" in cidrs
    assert "2001:db8::1/128" in cidrs
    assert all("not-an-ip" not in c for c in cidrs)
    assert "# a comment" not in "".join(cidrs)


def test_parse_aws_ranges_collects_v4_and_v6() -> None:
    assert set(parse_aws_ranges(_AWS)) == {"3.4.12.4/32", "3.5.140.0/22", "2600:1f00::/40"}


def test_parse_gcp_ranges_prefers_v4_then_v6() -> None:
    assert set(parse_gcp_ranges(_GCP)) == {"34.1.208.0/20", "2600:1900::/28"}


def test_parsers_tolerate_malformed_top_level() -> None:
    assert parse_aws_ranges("[]") == []
    assert parse_aws_ranges(json.dumps({"prefixes": "nope"})) == []
    assert parse_gcp_ranges("42") == []
    assert parse_gcp_ranges(json.dumps({"prefixes": {}})) == []


def test_normalize_dedupes_sorts_and_drops_invalid() -> None:
    out = normalize_cidrs(["10.0.0.0/8", "1.2.3.4/32", "1.2.3.4/32", "garbage", "::1/128"])
    assert out == ["1.2.3.4/32", "10.0.0.0/8", "::1/128"]


def test_render_seed_round_trips_through_the_producer_parser() -> None:
    text = render_seed("title — what", "what it does", ["1.2.3.4/32", "5.6.7.8/32"])
    assert text.splitlines()[0].startswith("#")
    # The seed parser must recover exactly the CIDRs, ignoring the comment header.
    assert {str(n) for n in _parse_cidrs(text)} == {"1.2.3.4/32", "5.6.7.8/32"}


def test_refresh_wires_sources_into_loadable_seeds() -> None:
    payloads = {TOR_BULK_EXIT_URL: _TOR, AWS_RANGES_URL: _AWS, GCP_RANGES_URL: _GCP}
    files = refresh(payloads.__getitem__)
    assert set(files) == {"proxy_exit_cidrs.txt", "datacenter_cidrs.txt"}

    rep = IPReputation(
        datacenter=_parse_cidrs(files["datacenter_cidrs.txt"]),
        proxy_exit=_parse_cidrs(files["proxy_exit_cidrs.txt"]),
    )
    # A fetched datacenter range classifies as datacenter, a Tor exit as a proxy exit.
    assert rep.classify("3.5.140.9") == (True, False)  # inside the AWS 3.5.140.0/22 block
    assert rep.classify("34.1.208.9") == (True, False)  # inside the GCP 34.1.208.0/20 block
    assert rep.classify("171.25.193.25") == (False, True)
    # A residential-style address in neither set stays clean — the FP-safety invariant.
    assert rep.classify("203.0.113.7") == (False, False)
