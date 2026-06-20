# tests/test_live_coordination — the live coordination consumer rebuilds the detector's corpus and grades it.
# Injected HTTP getter (no running detector); asserts a planted cloned fleet is convicted and evictions skip.

from __future__ import annotations

from typing import Any

from kitsune_harness.live_coordination import fetch_live_corpus, score_live


def _signal(sid: str, layer: str, kind: str, value: Any, src: str, when: str) -> dict[str, Any]:
    return {
        "schema_version": "0.1",
        "session_id": sid,
        "layer": layer,
        "kind": kind,
        "value": value,
        "source": src,
        "observed_at": when,
    }


def _session_payload(sid: str, ja4: str, fp_hash: str, ip: str, *, webdriver: bool, when: str) -> dict[str, Any]:
    net = [_signal(sid, "network", "ja4", ja4, "edge", when), _signal(sid, "network", "observed_ip", ip, "edge", when)]
    browser = [_signal(sid, "browser", "fp_hash", fp_hash, "collector", when)]
    if webdriver:  # an automation tell — corroborates the fp-collision as a cloned bot fleet (not a corporate cohort)
        browser.append(_signal(sid, "browser", "webdriver", True, "collector", when))
    return {
        "schema_version": "0.1",
        "session_id": sid,
        "remote_ip": ip,
        "first_seen": when,
        "last_seen": when,
        "request_count": 1,
        "signals": {"network": net, "browser": browser, "behavioral": [], "reputation": []},
    }


# Two cloned bots (identical fp_hash across distinct IPs + an automation tell) sharing one JA4 = a fleet; plus a
# lone unrelated session. One id in the scoreboard 404s mid-poll (eviction) and must be skipped, not abort.
_JA4 = "t13d1516h2_8daaf6152771_e5627efa2ab1"
_PAYLOADS = {
    "clone-a": _session_payload("clone-a", _JA4, "cloned-fp", "11.0.0.1", webdriver=True, when="2026-06-20T00:00:00Z"),
    "clone-b": _session_payload("clone-b", _JA4, "cloned-fp", "22.0.0.2", webdriver=True, when="2026-06-20T00:00:05Z"),
    "lone": _session_payload(
        "lone", "t99x9999h2_aaaa_bbbb", "unique-fp", "33.0.0.3", webdriver=False, when="2026-06-20T00:00:09Z"
    ),
}


def _fake_get_json(url: str) -> Any:
    if url.endswith("/scoreboard"):  # the detector returns Verdicts; only session_id is needed here
        return [{"session_id": sid} for sid in (*_PAYLOADS, "evicted")]
    sid = url.rsplit("/session/", 1)[1]
    if sid == "evicted":  # a session evicted between the scoreboard list and the fetch
        raise RuntimeError("404 no session")
    return _PAYLOADS[sid]


def test_fetch_live_corpus_skips_evicted_sessions() -> None:
    corpus = fetch_live_corpus("http://detector:8080", get_json=_fake_get_json)
    names = {name for name, _ in corpus}
    assert names == {"clone-a", "clone-b", "lone"}  # 'evicted' (404) dropped, the rest survive


def test_score_live_convicts_the_planted_clone_fleet() -> None:
    verdicts = score_live("http://detector:8080/", get_json=_fake_get_json)
    # Only the shared-JA4 cluster (clone-a/clone-b) is graded; the lone session forms no cluster.
    assert len(verdicts) == 1
    v = verdicts[0]
    assert v.label == "fleet"
    assert v.cloned_fingerprint == "cloned-fp"
    assert sorted(v.members) == ["clone-a", "clone-b"]
