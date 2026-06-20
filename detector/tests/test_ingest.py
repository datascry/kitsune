# tests/test_ingest — detector test module.
# Asserts behaviour and edge cases for the unit under test.

from __future__ import annotations

from datetime import timedelta

from kitsune_detector.ingest import group_signals, merge_sessions
from kitsune_detector.models import MISSING, Layer, Signal, Source

from .conftest import FIXED, make_signal


def test_group_empty() -> None:
    assert group_signals([]) == []


def test_group_correlates_by_session() -> None:
    later = FIXED + timedelta(seconds=5)
    signals = [
        make_signal("a", Layer.network, "ja4", "x", source=Source.edge, at=FIXED),
        make_signal("b", Layer.network, "ja4", "y", source=Source.edge, at=FIXED),
        make_signal("a", Layer.browser, "webdriver", True, source=Source.collector, at=later),
    ]
    sessions = group_signals(signals)

    assert [s.session_id for s in sessions] == ["a", "b"]  # first-seen order preserved
    session_a = sessions[0]
    assert session_a.request_count == 1  # one edge-sourced signal
    assert session_a.first_seen == FIXED
    assert session_a.last_seen == later
    assert session_a.value(Layer.browser, "webdriver") is True


def test_merge_accumulates_layers() -> None:
    net = make_signal("a", Layer.network, "ja4", "x", source=Source.edge, at=FIXED)
    later = FIXED + timedelta(seconds=1)
    web = make_signal("a", Layer.browser, "webdriver", True, source=Source.collector, at=later)
    merged = merge_sessions(group_signals([net])[0], group_signals([web])[0])
    assert merged.value(Layer.network, "ja4") == "x"
    assert merged.value(Layer.browser, "webdriver") is True
    assert merged.request_count == 1  # one edge-sourced signal


def test_merge_keeps_latest_per_kind() -> None:
    old = make_signal("a", Layer.browser, "ua_browser", "chrome", at=FIXED)
    new = make_signal("a", Layer.browser, "ua_browser", "firefox", at=FIXED + timedelta(seconds=5))
    merged = merge_sessions(group_signals([old])[0], group_signals([new])[0])
    assert merged.value(Layer.browser, "ua_browser") == "firefox"


# Within-session JA4 stability: distinct JA4_b (cipher identity) under one session id is a TLS-engine
# rotation a real client cannot do — net.ja4_unstable_within_session's read signal (derived in ingest).
_CHROME_JA4 = "t13d1516h2_8daaf6152771_d8a2da3f94cd"
_FIREFOX_JA4 = "t13d1715h2_5b57614c22b0_5c2c66f702b0"  # distinct JA4_b (Gecko cipher list)
_CHROME_JA4_RESHUFFLED = "t13d1516h2_8daaf6152771_aaaaaaaaaaaa"  # same JA4_b, different JA4_c (ext shuffle)


def test_merge_flags_ja4_rotation_across_ingests() -> None:
    c = make_signal("a", Layer.network, "ja4", _CHROME_JA4, source=Source.edge, at=FIXED)
    f = make_signal("a", Layer.network, "ja4", _FIREFOX_JA4, source=Source.edge, at=FIXED + timedelta(seconds=2))
    merged = merge_sessions(group_signals([c])[0], group_signals([f])[0])
    assert merged.value(Layer.network, "ja4_unstable") is True


def test_ja4_extension_reshuffle_is_not_instability() -> None:
    # Chrome reshuffles extensions per connection (JA4_c varies) but keeps its cipher list (JA4_b) — must
    # NOT flag, or every real Chrome session would convict. FP-safety of the JA4_b stability key.
    c1 = make_signal("a", Layer.network, "ja4", _CHROME_JA4, source=Source.edge, at=FIXED)
    at2 = FIXED + timedelta(seconds=2)
    c2 = make_signal("a", Layer.network, "ja4", _CHROME_JA4_RESHUFFLED, source=Source.edge, at=at2)
    merged = merge_sessions(group_signals([c1])[0], group_signals([c2])[0])
    assert merged.value(Layer.network, "ja4_unstable") is MISSING


def test_ja4_rotation_in_single_batch_is_flagged() -> None:
    c = make_signal("a", Layer.network, "ja4", _CHROME_JA4, source=Source.edge, at=FIXED)
    f = make_signal("a", Layer.network, "ja4", _FIREFOX_JA4, source=Source.edge, at=FIXED + timedelta(seconds=1))
    session = group_signals([c, f])[0]
    assert session.value(Layer.network, "ja4_unstable") is True


def test_ja4_flag_is_sticky_after_revert() -> None:
    # Rotate Chrome→Firefox (flagged), then revert to Chrome — the flag must persist (sticky).
    c = make_signal("a", Layer.network, "ja4", _CHROME_JA4, source=Source.edge, at=FIXED)
    f = make_signal("a", Layer.network, "ja4", _FIREFOX_JA4, source=Source.edge, at=FIXED + timedelta(seconds=2))
    flagged = merge_sessions(group_signals([c])[0], group_signals([f])[0])
    back = make_signal("a", Layer.network, "ja4", _CHROME_JA4, source=Source.edge, at=FIXED + timedelta(seconds=4))
    merged = merge_sessions(flagged, group_signals([back])[0])
    assert merged.value(Layer.network, "ja4_unstable") is True


# Within-session IP rotation: >=3 distinct egress IPs under one session id is a rotating proxy pool. The
# running set is accumulated across ingests in observed_ip_seen (the merge keeps only the latest
# observed_ip), and ip_rotation trips at the conservative threshold (a real short session has 1-2 IPs).
def _ip_sig(ip: str, secs: int) -> Signal:
    return make_signal("a", Layer.network, "observed_ip", ip, source=Source.edge, at=FIXED + timedelta(seconds=secs))


def test_ip_rotation_flagged_across_three_ingests() -> None:
    s = group_signals([_ip_sig("10.0.0.1", 0)])[0]
    s = merge_sessions(s, group_signals([_ip_sig("10.0.0.2", 1)])[0])
    assert s.value(Layer.network, "ip_rotation") is MISSING  # only 2 distinct so far
    s = merge_sessions(s, group_signals([_ip_sig("10.0.0.3", 2)])[0])
    assert s.value(Layer.network, "ip_rotation") is True
    assert sorted(s.value(Layer.network, "observed_ip_seen")) == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]


def test_single_ip_session_is_not_rotation() -> None:
    s = group_signals([_ip_sig("10.0.0.1", 0)])[0]
    s = merge_sessions(s, group_signals([_ip_sig("10.0.0.1", 1)])[0])
    s = merge_sessions(s, group_signals([_ip_sig("10.0.0.1", 2)])[0])
    assert s.value(Layer.network, "ip_rotation") is MISSING


def test_ip_rotation_is_sticky_after_revert() -> None:
    s = group_signals([_ip_sig("10.0.0.1", 0)])[0]
    s = merge_sessions(s, group_signals([_ip_sig("10.0.0.2", 1)])[0])
    s = merge_sessions(s, group_signals([_ip_sig("10.0.0.3", 2)])[0])
    s = merge_sessions(s, group_signals([_ip_sig("10.0.0.1", 3)])[0])  # revert to a seen IP
    assert s.value(Layer.network, "ip_rotation") is True


def test_ip_rotation_in_single_batch() -> None:
    batch = [_ip_sig("10.0.0.1", 0), _ip_sig("10.0.0.2", 1), _ip_sig("10.0.0.3", 2)]
    s = group_signals(batch)[0]
    assert s.value(Layer.network, "ip_rotation") is True
