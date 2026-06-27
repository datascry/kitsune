# harness/rps_scout — recon RATE scoping: ramp request rate at an allow-listed target, find the throttle knee.
# Reports the request budget (max clean RPS before a 429 / challenge gate / saturation), the recon rate dimension.

"""Request-rate (RPS) reconnaissance.

The fleet manager scopes a target's FINGERPRINT/coordination posture, but not its RATE posture — at what
request rate does the defense start throttling, serving a challenge gate, or saturating. This is the recon
rate dimension: :func:`scout_rps` ramps a short, bounded probe through ascending target rates against an
ALLOW-LISTED url, classifies each request (ok / throttled 429 / blocked 403,503 / challenged — a gate marker in
the body), and reports the **budget** — the highest clean rate before the knee — plus what degraded.

Ethics: it hits a real endpoint, so the target is checked against the harness allow-list FIRST
(:func:`~kitsune_harness.allowlist.assert_allowed`) — owned edge/detector/arena or the approved test endpoints
only. It is a bounded recon probe (a few requests per step, ramp stops at the first knee — it does NOT keep
hammering), authorization-scoped in code; not a flood/DoS. The HTTP request and the pacing sleep are injected
so the ramp/budget logic is unit-tested without a network or real time.
"""

from __future__ import annotations

import time
import urllib.error
import urllib.request
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

from .allowlist import assert_allowed

#: substrings that mark a challenge/throttle gate in a response body (PoW / CAPTCHA / rate-limit pages).
_GATE_MARKERS: tuple[str, ...] = ("proof-of-work", "proof of work", "captcha", "challenge", "rate limit", "too many")
_DEFAULT_RATES: tuple[int, ...] = (1, 2, 5, 10, 20, 50)

#: a requester returns (status, latency_ms, body_head) for one GET — injected so tests need no network.
Requester = Callable[[str], "tuple[int, float, str]"]
Sleeper = Callable[[float], None]


@dataclass
class StepResult:
    rate: int  # target requests/sec for this ramp step
    sent: int
    ok: int
    throttled: int  # 429
    blocked: int  # 403 / 503
    challenged: int  # a gate marker in the body
    p50_ms: float
    p95_ms: float

    @property
    def degraded_by(self) -> str | None:
        """Which failure mode dominates this step (throttled/blocked/challenged), or None if mostly clean."""
        if self.throttled:
            return "throttled"
        if self.blocked:
            return "blocked"
        if self.challenged:
            return "challenged"
        return None


@dataclass
class RpsReport:
    url: str
    steps: list[StepResult]
    budget_rps: int  # the highest clean rate before the knee (0 if even the lowest rate degraded)
    knee: str  # what degraded at the budget+1 step: throttled | blocked | challenged | latency | none

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "budget_rps": self.budget_rps,
            "knee": self.knee,
            "steps": [vars(s) for s in self.steps],
        }


def _percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    return round(s[min(len(s) - 1, int(q * len(s)))], 1)


def _classify(status: int, body: str, markers: Sequence[str]) -> str:
    if status == 429:
        return "throttled"
    if status in (403, 503):
        return "blocked"
    low = body.lower()
    if any(m in low for m in markers):
        return "challenged"
    if 200 <= status < 400:
        return "ok"
    return "error"


def _http_request(url: str) -> tuple[int, float, str]:  # pragma: no cover - real network I/O
    start = time.monotonic()
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            body = resp.read(2048).decode("utf-8", "ignore")
            return int(resp.status), (time.monotonic() - start) * 1000, body
    except urllib.error.HTTPError as exc:
        return int(exc.code), (time.monotonic() - start) * 1000, ""
    except Exception:
        return 0, (time.monotonic() - start) * 1000, ""


def _run_step(
    url: str, rate: int, duration: float, requester: Requester, sleep: Sleeper, markers: Sequence[str]
) -> StepResult:
    """Fire ``rate * duration`` requests paced at ``rate``/sec (concurrently, so a slow response never stalls
    the pacing), and tally the outcomes + latency percentiles."""
    import concurrent.futures

    n = max(1, int(rate * duration))
    interval = 1.0 / rate
    outcomes: list[tuple[str, float]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(n, 32)) as pool:
        futures = []
        for i in range(n):
            futures.append(pool.submit(requester, url))
            if i < n - 1:
                sleep(interval)
        for fut in futures:
            status, latency, body = fut.result()
            outcomes.append((_classify(status, body, markers), latency))
    lat = [latency for _cls, latency in outcomes]
    counts = {k: sum(1 for cls, _ in outcomes if cls == k) for k in ("ok", "throttled", "blocked", "challenged")}
    return StepResult(
        rate=rate,
        sent=n,
        ok=counts["ok"],
        throttled=counts["throttled"],
        blocked=counts["blocked"],
        challenged=counts["challenged"],
        p50_ms=_percentile(lat, 0.5),
        p95_ms=_percentile(lat, 0.95),
    )


def scout_rps(
    url: str,
    *,
    rates: Sequence[int] = _DEFAULT_RATES,
    duration: float = 2.0,
    latency_factor: float = 4.0,
    requester: Requester = _http_request,
    sleep: Sleeper = time.sleep,
    markers: Sequence[str] = _GATE_MARKERS,
) -> RpsReport:
    """Ramp ascending ``rates`` against ``url`` and report the request budget + the knee. Stops ramping at the
    first degraded step (it does not keep hammering past the limit). The allow-list check runs FIRST."""
    assert_allowed(url)
    steps: list[StepResult] = []
    budget = 0
    knee = "none"
    baseline_p50: float | None = None
    for rate in sorted(rates):
        step = _run_step(url, rate, duration, requester, sleep, markers)
        steps.append(step)
        if baseline_p50 is None and step.ok:
            baseline_p50 = step.p50_ms
        gate = step.degraded_by
        saturated = baseline_p50 is not None and baseline_p50 > 0 and step.p95_ms > baseline_p50 * latency_factor
        if gate is not None or saturated:
            knee = gate or "latency"
            break
        budget = rate
    return RpsReport(url=url, steps=steps, budget_rps=budget, knee=knee)


def render(report: RpsReport) -> str:
    lines = [f"# RPS scope — {report.url}", ""]
    for s in report.steps:
        flag = s.degraded_by or ("latency" if s == report.steps[-1] and report.knee == "latency" else "")
        lines.append(
            f"- {s.rate:>4} rps: {s.ok}/{s.sent} ok · p50 {s.p50_ms}ms p95 {s.p95_ms}ms"
            + (f"  ⚠ {flag}" if flag else "")
        )
    lines += ["", f"**budget: {report.budget_rps} rps** (knee: {report.knee})"]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:  # pragma: no cover - thin CLI
    import argparse
    import json

    ap = argparse.ArgumentParser(description="Recon: scope a target's request-rate budget (authorized targets only).")
    ap.add_argument("url", help="allow-listed target URL to probe")
    ap.add_argument("--rates", default="1,2,5,10,20,50", help="comma-separated ascending RPS ramp")
    ap.add_argument("--duration", type=float, default=2.0, help="seconds per ramp step")
    ap.add_argument("--report", help="write the structured RPS report (JSON) to this path")
    args = ap.parse_args(argv)
    report = scout_rps(args.url, rates=[int(r) for r in args.rates.split(",")], duration=args.duration)
    print(render(report), end="")
    if args.report:
        from pathlib import Path

        Path(args.report).write_text(json.dumps(report.to_dict(), indent=2) + "\n")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
