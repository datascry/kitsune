# detector/flow_cadence — session-intent flow-cadence tells (the session-intent axis's timing detection).
# Pure predicates over a session's gate-completion timestamps: superhuman-median-gap and machine-regular-CV.

"""Session-intent multi-step FLOW cadence — the session-intent axis's first two tells.

A human completing a multi-gate flow needs perceive+decide+solve+submit time PER step (seconds); a bot
chains gate completions in milliseconds (``_flow_superhuman``) or at a metronomic fixed pace
(``_flow_robotic``). Both predicates are PURE over the timestamp list, so they are directly FP-safety-testable
against a synthesized population of diverse human session timings. ``app.py`` records the per-session step
timestamps and joins these tells to the session; the constants/predicates live here so the concern is one
readable unit rather than buried in the app factory.
"""

from __future__ import annotations

import math
from datetime import datetime, timedelta

#: _FLOW_STEP_FLOOR_MS is a conservative physiological floor on the MEDIAN inter-step gap — far under any real
#: human's per-gate time, so NO human session trips it (precision 1.0), only a machine chaining
#: >= _FLOW_MIN_STEPS gates that fast. FP-safe by construction as a LOWER bound; the median is robust to a
#: single slow step (a resumed/idle flow).
_FLOW_STEP_FLOOR_MS = 500.0
_FLOW_MIN_STEPS = 3
_FLOW_TTL = timedelta(minutes=5)

#: Machine-REGULARITY: a PACED bot (fixed inter-step sleep) chains gates at a near-constant interval — a
#: coefficient of variation (stddev/mean) far below what any human's reaction+think-time variance produces.
#: Needs more steps than the floor tell for a stable CV. _FLOW_REGULAR_CV sits below the CV floor of even a
#: metronomic human (~0.05-0.1), so no human trips it — only a machine timer. FP-safe by construction; catches
#: the naive fixed-sleep humanization tier (a jittered bot, CV well above this, evades it — the residual band).
_FLOW_REGULAR_MIN_STEPS = 5
_FLOW_REGULAR_CV = 0.03


def _flow_superhuman(steps: list[datetime]) -> bool:
    """True when a session's gate-completion sequence is superhuman: the MEDIAN inter-step gap across at least
    ``_FLOW_MIN_STEPS`` steps is below the physiological floor. Pure over the timestamp list so it is directly
    FP-safety-testable against a synthesized population of diverse human session timings."""
    if len(steps) < _FLOW_MIN_STEPS:
        return False
    gaps = sorted((steps[i] - steps[i - 1]).total_seconds() * 1000 for i in range(1, len(steps)))
    return gaps[len(gaps) // 2] < _FLOW_STEP_FLOOR_MS


def _flow_robotic(steps: list[datetime]) -> bool:
    """True when a session's inter-step gaps are MACHINE-REGULAR: the coefficient of variation is below the
    human floor across >= ``_FLOW_REGULAR_MIN_STEPS`` steps AND the mean gap is above the physiological floor (a
    PACED bot, not a superhuman one — that is the floor tell's job). No human's reaction+think-time is that
    regular. Pure so it is directly FP-safety-testable against diverse human timings (including a metronomic one)."""
    if len(steps) < _FLOW_REGULAR_MIN_STEPS:
        return False
    gaps = [(steps[i] - steps[i - 1]).total_seconds() * 1000 for i in range(1, len(steps))]
    mean = sum(gaps) / len(gaps)
    if mean < _FLOW_STEP_FLOOR_MS:
        return False  # superhuman-fast flows are the floor tell's domain, not regularity
    variance = sum((g - mean) * (g - mean) for g in gaps) / len(gaps)
    cv = math.sqrt(variance) / mean
    return cv < _FLOW_REGULAR_CV
