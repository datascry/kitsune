# harness/biomech — biomechanical features of a pointer trajectory (human-vs-bot movement structure).
# Pure stdlib: the 2/3 power law, Fitts sub-movements, and pause structure real hands show and bots don't.

"""Biomechanical feature extraction for mouse trajectories.

The lab's behavioral *threshold* rules (path straightness, velocity CV) are trivially cleared by any
non-degenerate motion — a Bezier "humanizer" (GhostCursor) beats them. Real aimed hand movement has
structure those tools do not reproduce, and these features measure it so detection can be calibrated
against real human data (see ``docs/behavioral-data.md``) instead of hand-picked thresholds:

* **2/3 power law** — for curved hand motion the tangential speed ``V`` scales with the radius of
  curvature ``R`` as ``V ∝ R**β`` with ``β ≈ 1/3`` (Lacquaniti et al., 1983). A real hand obeys it with
  high fit; a Bezier ease or a constant-velocity script does not. We report the fitted ``β`` and ``R²``.
* **Sub-movements** — Fitts's-law aimed motion is a ballistic reach plus corrective sub-movements, so the
  speed profile has several peaks; a single Bezier ease has one. We count speed-profile peaks.
* **Pause ratio** — humans hesitate (near-zero-speed dwell); many scripts move without ever pausing.

All pure stdlib (no numpy). Inputs are ``(x, y, t)`` samples matching the collector's pointer stream;
``t`` units only need to be consistent. Degenerate/too-short inputs yield ``None`` rather than a guess.
"""

from __future__ import annotations

import itertools
import math
from dataclasses import dataclass

Sample = tuple[float, float, float]  # (x, y, t)


@dataclass(frozen=True)
class BiomechFeatures:
    """Biomechanical summary of one trajectory. ``power_law_*`` are ``None`` when too few curved points
    exist to fit (e.g. a straight or near-stationary path)."""

    n_samples: int
    power_law_exponent: float | None  # β in V ∝ R**β; a real hand ≈ 0.33
    power_law_r2: float | None  # goodness of the log-log fit; a real hand fits tightly
    submovement_count: int  # speed-profile peaks (Fitts corrective sub-movements)
    pause_ratio: float  # fraction of samples at near-zero speed


def _dist(a: Sample, b: Sample) -> float:
    return math.hypot(b[0] - a[0], b[1] - a[1])


def _speeds(traj: list[Sample]) -> list[float]:
    """Per-step speed (distance / dt), skipping non-increasing timestamps."""
    out: list[float] = []
    for a, b in itertools.pairwise(traj):
        dt = b[2] - a[2]
        if dt > 0:
            out.append(_dist(a, b) / dt)
    return out


def _menger_curvature(a: Sample, b: Sample, c: Sample) -> float:
    """Curvature of the circle through three points (0 if collinear/degenerate)."""
    ab, bc, ca = _dist(a, b), _dist(b, c), _dist(c, a)
    if ab == 0 or bc == 0 or ca == 0:
        return 0.0
    # Twice the triangle area via the cross product of the two edge vectors.
    area2 = abs((b[0] - a[0]) * (c[1] - a[1]) - (c[0] - a[0]) * (b[1] - a[1]))
    return 2.0 * area2 / (ab * bc * ca)


def _linregress(xs: list[float], ys: list[float]) -> tuple[float, float]:
    """Ordinary least-squares slope and R² of ys on xs (slope 0, R² 0 if undefined)."""
    n = len(xs)
    mx = sum(xs) / n
    my = sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    sxy = sum((x - mx) * (y - my) for x, y in zip(xs, ys, strict=True))
    syy = sum((y - my) ** 2 for y in ys)
    if sxx == 0 or syy == 0:
        return 0.0, 0.0
    slope = sxy / sxx
    r2 = (sxy * sxy) / (sxx * syy)
    return slope, r2


def power_law(traj: list[Sample]) -> tuple[float, float] | None:
    """Fit V ∝ R**β over curved interior points; return (β, R²) or None if too few curved points."""
    pairs: list[tuple[float, float]] = []  # (ln R, ln V)
    for a, b, c in zip(traj, traj[1:], traj[2:], strict=False):
        kappa = _menger_curvature(a, b, c)
        dt = c[2] - a[2]
        if kappa <= 0 or dt <= 0:
            continue
        speed = _dist(a, c) / dt  # central-difference tangential speed at b
        radius = 1.0 / kappa
        if speed > 0 and radius > 0:
            pairs.append((math.log(radius), math.log(speed)))
    if len(pairs) < 3:
        return None
    slope, r2 = _linregress([p[0] for p in pairs], [p[1] for p in pairs])
    return slope, r2


def submovement_count(traj: list[Sample], floor_frac: float = 0.1) -> int:
    """Count peaks in the speed profile above ``floor_frac`` of the max speed (corrective sub-movements)."""
    speeds = _speeds(traj)
    if len(speeds) < 3:
        return 0
    floor = max(speeds) * floor_frac
    peaks = 0
    for i in range(1, len(speeds) - 1):
        if speeds[i] > floor and speeds[i] >= speeds[i - 1] and speeds[i] > speeds[i + 1]:
            peaks += 1
    return peaks


def pause_ratio(traj: list[Sample], frac: float = 0.05) -> float:
    """Fraction of steps whose speed is below ``frac`` of the max speed (hesitation/dwell)."""
    speeds = _speeds(traj)
    if not speeds:
        return 0.0
    threshold = max(speeds) * frac
    return sum(1 for s in speeds if s <= threshold) / len(speeds)


def extract(traj: list[Sample]) -> BiomechFeatures:
    """Compute the full biomechanical feature set for one pointer trajectory."""
    pl = power_law(traj)
    return BiomechFeatures(
        n_samples=len(traj),
        power_law_exponent=None if pl is None else pl[0],
        power_law_r2=None if pl is None else pl[1],
        submovement_count=submovement_count(traj),
        pause_ratio=pause_ratio(traj),
    )
