# harness/template_calibration — grounds the template-similarity floor (co. _TEMPLATE_EPSILON) two ways.
# Synthetic humanizer-vs-distinct-humans separation (in-sandbox) + a SapiMouse second source (real, run locally).

"""Calibration for the template-similarity coordination rung.

``coordination._template_similarity`` convicts a fleet whose pointer traces are drawn from ONE "humanizer"
model: every node jitters its trace to a distinct ``trace_hash`` (defeating the EXACT trace-collision rule),
but the traces cluster in motion-feature space far tighter than N distinct humans do. The discriminator is a
floor — the median pairwise :func:`~kitsune_harness.biomech.descriptor_distance` BELOW which a cluster cannot
be N distinct people. This module justifies that floor (``_TEMPLATE_EPSILON``) instead of hand-picking it,
exactly as ``sapimouse_corpus`` justifies the biomech power-law floor:

* **In-sandbox (synthetic, runs in CI via the scenarios + tests):** one humanizer (a fixed Bézier template
  sampled with small per-instance jitter) yields a median pairwise descriptor distance ≈ 0.05-0.07; a cohort
  of distinct human reaches (varied endpoints/curvature + motor noise) yields ≈ 0.17-0.45. The floor sits
  between, with margin both ways. The generators here are the single source of truth for both the calibration
  and the ``coordination_scenarios`` template fixtures, so the scenarios convict/clear on REAL descriptors.

* **Second source (real, run locally):** SapiMouse (120 subjects) — the same corpus that corroborates the
  power-law floor. We compute the shipped :func:`~kitsune_harness.biomech.trace_descriptor` for each real
  sample and measure the median pairwise distance between DISTINCT subjects; its low percentile is the real
  human floor. The data is fetched at use-time, never committed (license + size) — see ``sapimouse_corpus``.

      KITSUNE_SAPIMOUSE_DIR=/path/to/sapimouse uv run python -m kitsune_harness.template_calibration
"""

from __future__ import annotations

import argparse
import itertools
import math
import os
import random
import statistics
import sys
from collections import defaultdict
from pathlib import Path

from .biomech import Sample, descriptor_distance, trace_descriptor

# The committed floor the engine uses (coordination._TEMPLATE_EPSILON). Kept here too so the calibration is
# self-contained and a drift between the two is a test failure (see tests/test_template_calibration).
TEMPLATE_EPSILON = 0.10
_STEPS = 60  # samples per synthetic trace (≈ a one-second pointer reach at 60 Hz)


def _bezier(p0: Sample, p1: Sample, p2: Sample, p3: Sample, steps: int) -> list[tuple[float, float]]:
    out: list[tuple[float, float]] = []
    for i in range(steps):
        t = i / (steps - 1)
        mt = 1 - t
        x = mt**3 * p0[0] + 3 * mt**2 * t * p1[0] + 3 * mt * t**2 * p2[0] + t**3 * p3[0]
        y = mt**3 * p0[1] + 3 * mt**2 * t * p1[1] + 3 * mt * t**2 * p2[1] + t**3 * p3[1]
        out.append((x, y))
    return out


def _trace(
    p0: tuple[float, float],
    p3: tuple[float, float],
    c1: tuple[float, float],
    c2: tuple[float, float],
    jitter: float,
    rng: random.Random,
) -> list[Sample]:
    """A Bézier reach A→B with control points c1/c2, control points jittered by ``jitter`` and a small
    per-sample positional noise — the trajectory a pointer "humanizer" emits."""

    def j(p: tuple[float, float]) -> Sample:
        return (p[0] + rng.gauss(0, jitter), p[1] + rng.gauss(0, jitter), 0.0)

    pts = _bezier(j(p0), j(c1), j(c2), j(p3), _STEPS)
    return [(x + rng.gauss(0, jitter * 0.3), y + rng.gauss(0, jitter * 0.3), float(i)) for i, (x, y) in enumerate(pts)]


# One fixed humanizer template — every node samples THIS curve with small jitter (the cloned-model fleet).
_TEMPLATE = ((0.0, 0.0), (400.0, 200.0), (120.0, 260.0), (300.0, -40.0))


def humanizer_descriptors(n: int, seed: int = 7, jitter: float = 2.0) -> list[tuple[float, ...]]:
    """``n`` trace descriptors from ONE humanizer model (a fleet that jitters one canned trace per node)."""
    rng = random.Random(seed)
    p0, p3, c1, c2 = _TEMPLATE
    return [trace_descriptor(_trace(p0, p3, c1, c2, jitter, rng)) for _ in range(n)]


def distinct_human_descriptors(n: int, seed: int = 11) -> list[tuple[float, ...]]:
    """``n`` trace descriptors from DISTINCT human reaches — varied endpoints/curvature + large motor noise."""
    rng = random.Random(seed)
    out: list[tuple[float, ...]] = []
    for _ in range(n):
        p0 = (rng.uniform(0, 100), rng.uniform(0, 100))
        p3 = (rng.uniform(300, 600), rng.uniform(-100, 300))
        c1 = (rng.uniform(50, 250), rng.uniform(-200, 400))
        c2 = (rng.uniform(200, 450), rng.uniform(-200, 400))
        out.append(trace_descriptor(_trace(p0, p3, c1, c2, 18.0, rng)))
    return out


def median_pairwise(descs: list[tuple[float, ...]]) -> float:
    """Median pairwise descriptor distance — the cohesion statistic the engine thresholds on."""
    dists = [descriptor_distance(a, b) for a, b in itertools.combinations(descs, 2)]
    return statistics.median(dists) if dists else 0.0


def synthetic_floor(cohorts: int = 20, size: int = 6) -> tuple[float, float]:
    """In-sandbox separation: ``(tightest distinct-human cohort median, one-humanizer median)``. The floor
    must sit strictly between — a CI-runnable proxy for the real SapiMouse measurement below."""
    human = min(median_pairwise(distinct_human_descriptors(size, seed=100 + s)) for s in range(cohorts))
    model = median_pairwise(humanizer_descriptors(size))
    return human, model


# --- SapiMouse second source (real human traces; run locally, data never committed) ---
_BLOCK = 128


def _reconstruct(parts: list[str]) -> list[Sample]:
    vals = [float(v) for v in parts[: 2 * _BLOCK]]
    dx, dy = vals[:_BLOCK], vals[_BLOCK : 2 * _BLOCK]
    out: list[Sample] = []
    x = y = 0.0
    for i in range(_BLOCK):
        x += dx[i]
        y += dy[i]
        out.append((x, y, float(i)))
    return out


def _descriptors_by_subject(csv_path: Path) -> dict[str, list[tuple[float, ...]]]:
    per: dict[str, list[tuple[float, ...]]] = defaultdict(list)
    for line in csv_path.read_text().splitlines():
        parts = line.strip().split(",")
        if len(parts) == 2 * _BLOCK + 1:
            per[parts[-1]].append(trace_descriptor(_reconstruct(parts)))
    return per


def _pctl(vals: list[float], q: float) -> float:
    s = sorted(vals)
    return s[max(0, min(len(s) - 1, int(q * len(s))))]


def corroborate(data_dir: Path, epsilon: float) -> int:
    """Measure the SapiMouse distinct-subject median-pairwise floor vs ``epsilon``. Non-zero if any real-human
    floor sits at/below the threshold (a real second-source FP), so CI / a human notices an over-loose floor."""
    csvs = sorted((data_dir / "input_csv_mouse").glob("sapimouse_ABS_dx_dy_*min.csv"))
    if not csvs:
        print(f"no SapiMouse CSVs under {data_dir}/input_csv_mouse — clone margitantal68/sapimouse", file=sys.stderr)
        return 2
    worst = math.inf
    for csv_path in csvs:
        per = _descriptors_by_subject(csv_path)
        subjects = [d for d in per.values() if len(d) >= 2]
        # one representative descriptor per subject (the per-subject centroid) → distances are BETWEEN people
        reps = [tuple(statistics.fmean(c[k] for c in ds) for k in range(len(ds[0]))) for ds in subjects]
        between = [descriptor_distance(a, b) for a, b in itertools.combinations(reps, 2)]
        if not between:
            continue
        floor = _pctl(between, 0.01)
        worst = min(worst, floor)
        below = sum(1 for d in between if d <= epsilon) / len(between)
        tag = csv_path.stem.split("_")[-1]
        print(
            f"SapiMouse {tag:>5}: subjects={len(reps):3d}  between-subject median-dist "
            f"p1={floor:.3f} median={statistics.median(between):.3f}  FP@{epsilon}={below * 100:.2f}%"
        )
    ok = worst > epsilon
    print(f"\n{'OK' if ok else 'FAIL'}: SapiMouse distinct-subject p1 floor {worst:.3f} vs epsilon {epsilon}")
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Calibrate the template-similarity floor (synthetic + SapiMouse).")
    ap.add_argument("--dir", default=os.environ.get("KITSUNE_SAPIMOUSE_DIR", ""), help="SapiMouse clone dir")
    ap.add_argument("--epsilon", type=float, default=TEMPLATE_EPSILON)
    args = ap.parse_args(argv)
    human, model = synthetic_floor()
    print(f"in-sandbox: one-humanizer median={model:.3f}  tightest distinct-human cohort median={human:.3f}")
    print(f"            floor {args.epsilon} sits between: {model < args.epsilon < human}\n")
    if not args.dir:
        print("set --dir or KITSUNE_SAPIMOUSE_DIR for the SapiMouse second source (real data, run locally)")
        return 0
    return corroborate(Path(args.dir), args.epsilon)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
