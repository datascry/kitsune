# fleet/tests/test_skulk — cover the ethics scope gate, the strategy shapes, the self-assessment, and the runner.
# The scope-enforcement tests are the load-bearing ones: an unauthorized / unaffirmed target must be refused.

from __future__ import annotations

import json

import pytest

from skulk import assess, get, run
from skulk.scope import AuthorizationError, Scope


def test_scope_allows_default_lab_without_affirmation() -> None:
    assert Scope().check("http://detector:8080") == "detector"
    assert Scope().check("https://edge:8443/") == "edge"


def test_scope_refuses_unauthorized_target() -> None:
    with pytest.raises(AuthorizationError, match="NOT in the authorized scope"):
        Scope().check("https://example.com/")


def test_scope_operator_host_requires_affirmation() -> None:
    s = Scope()
    s.authorize_host("my-staging.internal")
    with pytest.raises(AuthorizationError, match="affirm you are authorized"):
        s.check("https://my-staging.internal/")
    s.affirmed = True
    assert s.check("https://my-staging.internal/") == "my-staging.internal"


def test_scope_authorized_cidr() -> None:
    s = Scope(affirmed=True)
    s.authorize_network("10.8.0.0/24")
    assert s.check("http://10.8.0.5:8080") == "10.8.0.5"
    with pytest.raises(AuthorizationError):
        s.check("http://10.9.0.5:8080")


def test_cloned_strategy_shares_one_fingerprint() -> None:
    members = get("cloned").members(3, seed=7)
    assert len({m.fp_hash for m in members}) == 1  # one cloned profile
    assert len({m.observed_ip for m in members}) == 3  # across distinct IPs
    assert len({m.ja4 for m in members}) == 1  # one TLS engine
    assert all(m.automation for m in members)


def test_randomizer_diverges_js_under_one_ja4() -> None:
    members = get("randomizer").members(4, seed=3)
    assert len({m.ja4 for m in members}) == 1  # one engine
    assert len({m.fp_hash for m in members}) == 4  # distinct fingerprints (the paradox)
    assert len({m.observed_ip for m in members}) == 4


def test_trace_replay_shares_one_trace() -> None:
    members = get("trace-replay").members(3, seed=5)
    assert len({m.trace_hash for m in members}) == 1  # one replayed path
    assert len({m.fp_hash for m in members}) == 3  # distinct fingerprints


def test_fuzzy_has_no_byte_identical_collision() -> None:
    members = get("fuzzy").members(4, seed=9)
    assert len({m.fp_hash for m in members}) == 4
    assert len({m.trace_hash for m in members}) == 4


def test_assess_distinguishes_detectable_from_evasive() -> None:
    assert assess(get("cloned").members(3, 1)).detectable  # fp-collision
    assert assess(get("trace-replay").members(3, 1)).detectable  # trace-collision
    assert not assess(get("fuzzy").members(3, 1)).detectable  # the frontier
    assert not assess(get("randomizer").members(3, 1)).detectable


def test_strategies_are_deterministic_in_seed() -> None:
    assert get("randomizer").members(3, 42) == get("randomizer").members(3, 42)


def test_member_signals_carry_the_coordination_layers() -> None:
    m = get("cloned").members(1, 1)[0]
    sigs = m.signals("sid-1", "2026-06-27T00:00:00Z")
    kinds = {(s["layer"], s["kind"]) for s in sigs}
    assert ("network", "ja4") in kinds and ("network", "observed_ip") in kinds
    assert ("browser", "fp_hash") in kinds and ("browser", "webdriver") in kinds


def test_run_dry_run_does_not_emit_but_is_scope_checked() -> None:
    res = run(target="http://detector:8080", strategy=get("cloned"), nodes=3, seed=1, scope=Scope(), dry_run=True)
    assert res.emitted is False and len(res.session_ids) == 3 and res.host == "detector"
    with pytest.raises(AuthorizationError):
        run(target="https://evil.example/", strategy=get("cloned"), nodes=3, seed=1, scope=Scope(), dry_run=True)


def test_run_emits_to_ingest_when_authorized(monkeypatch: pytest.MonkeyPatch) -> None:
    posted: list[dict[str, object]] = []

    class _Resp:
        def __enter__(self) -> _Resp:
            return self

        def __exit__(self, *a: object) -> None:
            return None

        def read(self) -> bytes:
            return b""

    def _fake_urlopen(req: object, timeout: float = 0) -> _Resp:
        posted.append({"url": req.full_url, "body": json.loads(req.data)})  # type: ignore[attr-defined]
        return _Resp()

    monkeypatch.setattr("skulk.runner.urllib.request.urlopen", _fake_urlopen)
    res = run(target="http://detector:8080", strategy=get("trace-replay"), nodes=2, seed=4, scope=Scope())
    assert res.emitted and len(posted) == 2
    assert all(p["url"].endswith("/ingest") for p in posted)
    # each POST is one member's signal envelopes, sharing the replayed trace
    traces = {s["value"] for p in posted for s in p["body"] if s["kind"] == "trace_hash"}
    assert len(traces) == 1
