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


def test_from_seed_prefers_mounted_iprep_dir(tmp_path, monkeypatch) -> None:
    # The deploy mount: KITSUNE_IPREP_DIR overrides the in-image seed when it holds the refreshed list,
    # and falls back to the committed seed per-file when the mounted file is absent (an empty mount).
    (tmp_path / "proxy_exit_cidrs.txt").write_text("12.0.0.0/24\n", encoding="utf-8")  # routable (not RFC-5737)
    monkeypatch.setenv("KITSUNE_IPREP_DIR", str(tmp_path))
    rep = IPReputation.from_seed()
    assert rep.classify("12.0.0.7") == (False, True)  # from the mounted proxy_exit list
    assert rep.datacenter  # datacenter file absent in the mount -> fell back to the committed seed


def test_parse_cidrs_ignores_comments_and_blanks() -> None:
    nets = _parse_cidrs("# header\n\n10.0.0.0/8  # private\n  \n192.0.2.0/24\n")
    assert nets == (ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("192.0.2.0/24"))


def test_classify_datacenter_proxy_residential() -> None:
    rep = _rep()
    assert rep.classify("11.0.0.7") == (True, False)  # datacenter
    assert rep.classify("12.0.0.9") == (False, True)  # proxy/exit
    assert rep.classify("8.8.4.4") == (False, False)  # neither (public, unlisted)


def test_index_matches_across_prefix_lengths_and_nesting() -> None:
    # The prefix-length index must agree with naive containment across mixed/nested prefixes, /32 host CIDRs
    # (the Tor-exit shape), and IPv6 — all public ranges so classify() does not short-circuit them.
    rep = IPReputation(
        datacenter=(
            ipaddress.ip_network("13.0.0.0/8"),  # broad
            ipaddress.ip_network("13.1.2.0/24"),  # nested inside the /8
            ipaddress.ip_network("17.5.6.7/32"),  # host CIDR
            ipaddress.ip_network("2606:4700::/32"),  # IPv6
        ),
    )
    assert rep.classify("13.1.2.3") == (True, False)  # matches the /24 (and the /8)
    assert rep.classify("13.9.9.9") == (True, False)  # matches the /8 only
    assert rep.classify("17.5.6.7") == (True, False)  # exact /32 host
    assert rep.classify("17.5.6.8") == (False, False)  # adjacent host, not listed
    assert rep.classify("2606:4700::1") == (True, False)  # inside the IPv6 /32
    assert rep.classify("2606:4800::1") == (False, False)  # outside it
    assert rep.classify("8.8.4.4") == (False, False)  # public, unlisted


def test_index_agrees_with_naive_containment_on_a_sample() -> None:
    # Differential guard on the masking arithmetic: the fast index must return the SAME verdict as a naive
    # `any(addr in net)` scan (with the private short-circuit) for a spread of addresses + prefix lengths.
    nets = tuple(
        ipaddress.ip_network(c)
        for c in ("1.2.0.0/16", "1.2.3.0/24", "1.2.3.4/32", "8.0.0.0/9", "13.0.0.0/25", "2606:4700::/32")
    )
    rep = IPReputation(datacenter=nets)
    sample = ("1.2.3.4", "1.2.3.5", "1.2.9.9", "1.3.0.0", "8.1.2.3", "8.200.0.1", "13.0.0.50", "2606:4700::9")
    for ip in sample:
        addr = ipaddress.ip_address(ip)
        not_special = not (addr.is_private or addr.is_loopback or addr.is_link_local)
        expected = not_special and any(addr in n for n in nets)
        assert rep.classify(ip)[0] == expected, ip


def test_ipreputation_stays_hashable_and_equal_with_derived_index() -> None:
    # The derived index fields are compare=False, so two reputations from the same CIDRs remain equal AND
    # hashable — the frozen-dataclass invariants the rest of the code leans on.
    a = IPReputation(datacenter=(ipaddress.ip_network("11.0.0.0/24"),))
    b = IPReputation(datacenter=(ipaddress.ip_network("11.0.0.0/24"),))
    assert a == b and hash(a) == hash(b)


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


def test_datacenter_origin_behind_residential_proxy_convicts() -> None:
    # Cross-layer: datacenter WebRTC origin (the real cloud VM) hidden behind a non-datacenter proxy → convicts.
    det = Detector(ip_reputation=_rep())
    v = det.score(_session_with_webrtc("8.8.4.4", "11.0.0.20"))  # observed clean, webrtc datacenter
    fired = {c.rule_id for c in v.contradictions}
    assert "net.datacenter_origin_proxied" in fired
    assert v.label.value == "bot"  # coherence → convicting


def test_cloud_desktop_direct_user_is_not_convicted() -> None:
    # FP-safety: a cloud-desktop user connects FROM the datacenter (observed_ip datacenter too) → the cross-layer
    # rule must NOT fire (no hiding); they are only corroborated by rep.datacenter_asn / rep.webrtc_origin_datacenter.
    det = Detector(ip_reputation=_rep())
    fired = {c.rule_id for c in det.score(_session_with_webrtc("11.0.0.5", "11.0.0.20")).contradictions}
    assert "net.datacenter_origin_proxied" not in fired
    assert "rep.datacenter_asn" in fired  # observed_ip is datacenter
