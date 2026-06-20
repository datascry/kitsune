# detector/tests/test_ip_reputation — CIDR classifier + detector enrichment for IP reputation.
# A datacenter/proxy source IP must produce the rep.* signals; residential/private must not.

from __future__ import annotations

import ipaddress

from kitsune_detector.detector import Detector
from kitsune_detector.ingest import group_signals
from kitsune_detector.ip_reputation import IPReputation, _parse_cidrs
from kitsune_detector.models import Layer, Source

from .conftest import make_signal


def _rep() -> IPReputation:
    # Public (non-private) blocks so classify() does not short-circuit them; stand in for hosting/exit lists.
    return IPReputation(
        datacenter=(ipaddress.ip_network("11.0.0.0/24"),),
        proxy_exit=(ipaddress.ip_network("12.0.0.0/24"),),
    )


def test_parse_cidrs_ignores_comments_and_blanks() -> None:
    nets = _parse_cidrs("# header\n\n10.0.0.0/8  # private\n  \n192.0.2.0/24\n")
    assert nets == (ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("192.0.2.0/24"))


def test_classify_datacenter_proxy_residential() -> None:
    rep = _rep()
    assert rep.classify("11.0.0.7") == (True, False)  # datacenter
    assert rep.classify("12.0.0.9") == (False, True)  # proxy/exit
    assert rep.classify("8.8.4.4") == (False, False)  # neither (public, unlisted)


def test_classify_private_and_invalid_are_clean() -> None:
    rep = _rep()
    assert rep.classify("172.22.0.4") == (False, False)  # private (the lab's own container range)
    assert rep.classify("127.0.0.1") == (False, False)  # loopback
    assert rep.classify("not-an-ip") == (False, False)  # invalid


def test_from_seed_loads_committed_lists() -> None:
    rep = IPReputation.from_seed()
    assert rep.datacenter, "datacenter seed should be non-empty"
    assert rep.classify("52.0.0.1") == (True, False)  # in the AWS seed block
    assert rep.proxy_exit == ()  # proxy seed ships empty (live exit lists fetched at refresh time)


def _session_with_ip(ip: str):
    return group_signals([make_signal("s", Layer.network, "observed_ip", ip, source=Source.edge)])[0]


def test_detector_enriches_datacenter_ip() -> None:
    det = Detector(ip_reputation=_rep())
    verdict = det.score(_session_with_ip("11.0.0.10"))
    fired = {c.rule_id for c in verdict.contradictions}
    assert "rep.datacenter_asn" in fired
    assert "rep.known_proxy_exit" not in fired


def test_detector_enriches_proxy_ip() -> None:
    det = Detector(ip_reputation=_rep())
    fired = {c.rule_id for c in det.score(_session_with_ip("12.0.0.20")).contradictions}
    assert "rep.known_proxy_exit" in fired


def test_detector_residential_ip_no_reputation() -> None:
    det = Detector(ip_reputation=_rep())
    fired = {c.rule_id for c in det.score(_session_with_ip("8.8.8.8")).contradictions}
    assert "rep.datacenter_asn" not in fired and "rep.known_proxy_exit" not in fired


def _session_with_webrtc(observed: str, webrtc: str):
    return group_signals(
        [
            make_signal("s", Layer.network, "observed_ip", observed, source=Source.edge),
            make_signal("s", Layer.browser, "webrtc_public_ip", webrtc, source=Source.collector),
        ]
    )[0]


def test_datacenter_webrtc_origin_behind_clean_proxy_is_flagged() -> None:
    # Cloud bot: observed_ip is a clean (residential-looking) proxy, but WebRTC leaks a DATACENTER origin —
    # the cloud-bot-behind-residential-proxy shape that rep.datacenter_asn (observed_ip only) misses.
    det = Detector(ip_reputation=_rep())
    fired = {c.rule_id for c in det.score(_session_with_webrtc("8.8.4.4", "11.0.0.20")).contradictions}
    assert "rep.webrtc_origin_datacenter" in fired
    assert "rep.datacenter_asn" not in fired  # observed_ip is NOT datacenter


def test_residential_webrtc_origin_is_clean() -> None:
    # FP-safety: a real VPN user leaks their RESIDENTIAL home IP via WebRTC (observed_ip = the VPN datacenter).
    # The origin-reputation rule must NOT fire on them (it is the reputation of the ORIGIN, not that it differs).
    det = Detector(ip_reputation=_rep())
    fired = {c.rule_id for c in det.score(_session_with_webrtc("11.0.0.10", "8.8.4.4")).contradictions}
    assert "rep.webrtc_origin_datacenter" not in fired  # webrtc origin is residential
    assert "rep.datacenter_asn" in fired  # observed (VPN) is datacenter
