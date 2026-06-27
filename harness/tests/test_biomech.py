# harness/tests/test_biomech — validate the biomechanical feature math on controlled trajectories.
# Proves the extractor (power law, sub-movements, pauses) is correct; calibration vs Balabit comes next.

from __future__ import annotations

import math

from kitsune_harness.biomech import (
    DESCRIPTOR_DIM,
    Sample,
    _linregress,
    _menger_curvature,
    descriptor_distance,
    extract,
    pause_ratio,
    power_law,
    submovement_count,
    trace_descriptor,
)


def _arc(radius: float, n: int, t0: float, speed: float) -> list[Sample]:
    """A quarter-circle arc of the given radius, traversed at a constant tangential ``speed``."""
    out: list[Sample] = []
    dtheta = (math.pi / 2) / n
    ds = radius * dtheta  # arc length per step
    dt = ds / speed
    for i in range(n + 1):
        th = i * dtheta
        out.append((radius * math.cos(th), radius * math.sin(th), t0 + i * dt))
    return out


def _speed_profile(speeds: list[float]) -> list[Sample]:
    """A 1-D trajectory (x increasing by 1 each step) whose per-step speeds match ``speeds``."""
    out: list[Sample] = [(0.0, 0.0, 0.0)]
    t = 0.0
    for i, s in enumerate(speeds):
        t += 1.0 / s  # dx=1, so speed = 1/dt
        out.append((float(i + 1), 0.0, t))
    return out


def test_menger_curvature_unit_circle() -> None:
    # Three points on a unit circle → curvature ≈ 1/R = 1.
    pts = [(math.cos(a), math.sin(a), 0.0) for a in (0.0, 0.3, 0.6)]
    assert abs(_menger_curvature(pts[0], pts[1], pts[2]) - 1.0) < 1e-6


def test_menger_curvature_collinear_is_zero() -> None:
    assert _menger_curvature((0, 0, 0), (1, 0, 0), (2, 0, 0)) == 0.0
    assert _menger_curvature((0, 0, 0), (0, 0, 0), (2, 0, 0)) == 0.0  # degenerate (zero edge)


def test_linregress_recovers_known_line() -> None:
    xs = [0.0, 1.0, 2.0, 3.0]
    ys = [1.0, 3.0, 5.0, 7.0]  # y = 2x + 1
    slope, r2 = _linregress(xs, ys)
    assert abs(slope - 2.0) < 1e-9 and abs(r2 - 1.0) < 1e-9


def test_linregress_degenerate() -> None:
    assert _linregress([1.0, 1.0, 1.0], [1.0, 2.0, 3.0]) == (0.0, 0.0)  # no x variance
    assert _linregress([1.0, 2.0, 3.0], [5.0, 5.0, 5.0]) == (0.0, 0.0)  # no y variance


def test_power_law_direction_obeying_vs_violating() -> None:
    # The discriminative property: a hand obeys V ∝ R**(+1/3) → speed RISES with radius → β > 0.
    # A trajectory built the other way (V ∝ R**(-1/3), faster on tight curves) → β < 0. The extractor
    # must separate the two by sign (exact β is sensitive to Menger discretisation, so we test direction).
    obeying = _arc(20.0, 60, 0.0, 20.0 ** (1 / 3))
    obeying += _arc(80.0, 60, obeying[-1][2] + 0.01, 80.0 ** (1 / 3))
    ob = power_law(obeying)
    assert ob is not None and ob[0] > 0.1, ob

    violating = _arc(20.0, 60, 0.0, 20.0 ** (-1 / 3))
    violating += _arc(80.0, 60, violating[-1][2] + 0.01, 80.0 ** (-1 / 3))
    vi = power_law(violating)
    assert vi is not None and vi[0] < -0.1, vi


def test_power_law_none_on_straight_line() -> None:
    straight = [(float(i), 0.0, float(i)) for i in range(10)]  # no curvature anywhere
    assert power_law(straight) is None


def test_submovement_count_two_peaks() -> None:
    # Speed profile low-high-low-high-low → two corrective sub-movements.
    traj = _speed_profile([1.0, 6.0, 1.0, 6.0, 1.0])
    assert submovement_count(traj) == 2


def test_submovement_count_short() -> None:
    assert submovement_count([(0, 0, 0), (1, 0, 1)]) == 0


def test_pause_ratio() -> None:
    # Three near-stationary steps then fast motion → ~half the steps are pauses.
    traj = _speed_profile([0.001, 0.001, 0.001, 10.0, 10.0, 10.0])
    assert 0.4 < pause_ratio(traj) < 0.6


def test_pause_ratio_empty() -> None:
    assert pause_ratio([(0, 0, 0)]) == 0.0


def test_extract_full_and_short() -> None:
    traj = _arc(40.0, 40, 0.0, 3.0)
    feat = extract(traj)
    assert feat.n_samples == len(traj)
    assert feat.power_law_exponent is not None and feat.power_law_r2 is not None
    assert feat.submovement_count >= 0 and 0.0 <= feat.pause_ratio <= 1.0

    short = extract([(0.0, 0.0, 0.0)])
    assert short.power_law_exponent is None and short.submovement_count == 0


def test_trace_descriptor_is_bounded_and_fixed_length() -> None:
    d = trace_descriptor(_arc(40.0, 40, 0.0, 3.0))
    assert len(d) == DESCRIPTOR_DIM
    assert all(0.0 <= c <= 1.0 for c in d)


def test_trace_descriptor_degenerate_never_raises() -> None:
    # Too-short / single-point / stationary inputs fall back to neutral components (no power-law fit, etc.).
    for traj in ([], [(0.0, 0.0, 0.0)], [(5.0, 5.0, 0.0)] * 4):
        d = trace_descriptor(traj)
        assert len(d) == DESCRIPTOR_DIM and all(0.0 <= c <= 1.0 for c in d)


def test_descriptor_distance_is_jitter_stable() -> None:
    # The core property the similarity rung rests on: a small positional jitter moves the descriptor only a
    # little, while a structurally different reach moves it a lot.
    base = _arc(40.0, 50, 0.0, 3.0)
    jittered = [(x + 0.4, y - 0.3, t) for x, y, t in base]
    straight = [(float(i), 0.0, float(i)) for i in range(50)]
    near = descriptor_distance(trace_descriptor(base), trace_descriptor(jittered))
    far = descriptor_distance(trace_descriptor(base), trace_descriptor(straight))
    assert near < far
    assert descriptor_distance(trace_descriptor(base), trace_descriptor(base)) == 0.0
