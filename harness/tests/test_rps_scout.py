# harness/tests/test_rps_scout — recon RPS scoping: classification, the ramp/budget/knee logic, ethics gate.
# HTTP + pacing are injected (fake requester / no-op sleep) so the logic is covered without a network.

from __future__ import annotations

import threading

import pytest

from kitsune_harness.allowlist import EthicsError
from kitsune_harness.rps_scout import _classify, _percentile, render, scout_rps

_NO_SLEEP = lambda _s: None  # noqa: E731 - a one-line no-op pacer for tests


def test_classify_each_outcome() -> None:
    assert _classify(200, "<html>ok</html>", ()) == "ok"
    assert _classify(429, "", ()) == "throttled"
    assert _classify(503, "", ()) == "blocked"
    assert _classify(200, "Please complete the CAPTCHA challenge", ("captcha",)) == "challenged"
    assert _classify(418, "", ()) == "error"


def test_percentile() -> None:
    assert _percentile([], 0.5) == 0.0
    assert _percentile([10.0, 20.0, 30.0, 40.0], 0.5) in (20.0, 30.0)


def test_ethics_gate_refuses_unauthorized_target() -> None:
    with pytest.raises(EthicsError):
        scout_rps("https://evil.example/", requester=lambda _u: (200, 1.0, ""), sleep=_NO_SLEEP)


def test_clean_target_budget_is_max_rate() -> None:
    # a fast, never-throttling endpoint → no knee, budget = the top rate tested.
    report = scout_rps(
        "http://localhost:8099/healthz",
        rates=[1, 2, 5],
        duration=1.0,
        requester=lambda _u: (200, 5.0, "ok"),
        sleep=_NO_SLEEP,
    )
    assert report.budget_rps == 5 and report.knee == "none"
    assert all(s.ok == s.sent for s in report.steps)


def test_throttle_knee_caps_the_budget() -> None:
    # the server starts returning 429 after a cumulative request count → the knee is found mid-ramp.
    seen = {"n": 0}
    lock = threading.Lock()

    def throttling(_url: str) -> tuple[int, float, str]:
        with lock:
            seen["n"] += 1
            count = seen["n"]
        return (429, 2.0, "") if count > 8 else (200, 2.0, "ok")

    report = scout_rps(
        "http://detector:8080/healthz", rates=[1, 2, 5, 10], duration=1.0, requester=throttling, sleep=_NO_SLEEP
    )
    assert report.knee == "throttled" and report.budget_rps < 10
    assert report.steps[-1].throttled > 0


def test_challenge_gate_knee() -> None:
    def gated(_url: str) -> tuple[int, float, str]:
        return (200, 3.0, "complete the proof-of-work challenge")

    report = scout_rps("http://arena:8095/", rates=[1, 2], duration=1.0, requester=gated, sleep=_NO_SLEEP)
    assert report.knee == "challenged" and report.budget_rps == 0  # gated from the first step


def test_latency_saturation_knee() -> None:
    # p95 latency blows past the baseline factor at higher load → a saturation knee (no explicit throttle).
    def slow_at_load(_url: str) -> tuple[int, float, str]:
        # latency grows with the global in-flight counter (modelled simply by call count buckets)
        with _lat_lock:
            _lat["n"] += 1
            n = _lat["n"]
        return (200, (5.0 if n <= 3 else 500.0), "ok")

    _lat = {"n": 0}
    _lat_lock = threading.Lock()
    report = scout_rps(
        "http://localhost:8099/healthz", rates=[1, 20], duration=1.0, requester=slow_at_load, sleep=_NO_SLEEP
    )
    assert report.knee == "latency"


def test_blocked_knee_and_to_dict() -> None:
    report = scout_rps(
        "http://localhost:8099/healthz",
        rates=[1, 2],
        duration=1.0,
        requester=lambda _u: (503, 2.0, ""),  # service-unavailable from the start → blocked
        sleep=_NO_SLEEP,
    )
    assert report.knee == "blocked" and report.budget_rps == 0
    d = report.to_dict()
    assert d["knee"] == "blocked" and d["budget_rps"] == 0 and d["steps"][0]["blocked"] > 0


def test_render_includes_budget_and_knee() -> None:
    report = scout_rps(
        "http://localhost:8099/healthz",
        rates=[1, 2],
        duration=1.0,
        requester=lambda _u: (200, 4.0, "ok"),
        sleep=_NO_SLEEP,
    )
    out = render(report)
    assert "budget: 2 rps" in out and "RPS scope" in out
