# harness/tests/test_template_calibration — the template-similarity floor is grounded, not hand-picked.
# Synthetic humanizer-vs-humans separation, the epsilon drift-guard, and the SapiMouse second-source path.

from __future__ import annotations

import math
import random
from pathlib import Path

from kitsune_harness.biomech import DESCRIPTOR_DIM
from kitsune_harness.coordination import _TEMPLATE_EPSILON
from kitsune_harness.template_calibration import (
    TEMPLATE_EPSILON,
    corroborate,
    distinct_human_descriptors,
    humanizer_descriptors,
    median_pairwise,
    synthetic_floor,
)


def test_epsilon_matches_the_engine() -> None:
    # Drift guard: the floor the calibration justifies must be the floor the coordination engine uses.
    assert TEMPLATE_EPSILON == _TEMPLATE_EPSILON


def test_descriptors_are_normalized_vectors() -> None:
    for d in humanizer_descriptors(4) + distinct_human_descriptors(4):
        assert len(d) == DESCRIPTOR_DIM
        assert all(0.0 <= c <= 1.0 for c in d)


def test_synthetic_floor_brackets_epsilon() -> None:
    # The in-sandbox separation that grounds the floor: one humanizer clusters BELOW epsilon, distinct humans
    # spread ABOVE it. This is the CI-runnable proxy for the SapiMouse measurement.
    human_floor, model_median = synthetic_floor()
    assert model_median < TEMPLATE_EPSILON < human_floor


def test_humanizer_is_tighter_than_distinct_humans() -> None:
    assert median_pairwise(humanizer_descriptors(8)) < median_pairwise(distinct_human_descriptors(8))


def test_humanizer_seed_is_reproducible() -> None:
    assert humanizer_descriptors(5, seed=3) == humanizer_descriptors(5, seed=3)


def _fake_sapimouse(tmp: Path, *, subjects: int) -> Path:
    """A synthetic SapiMouse-shaped CSV: each row is 128 dx, 128 dy, subject-label. Distinct subjects get
    distinct curved-reach geometry (varied arc radius + span → varied descriptors), several samples each. This
    exercises the parse→descriptor→between-subject-floor pipeline; the REAL pass verdict (human floor > epsilon)
    is a property of REAL SapiMouse data, measured locally — not something synthetic data should be tuned to fake."""
    d = tmp / "input_csv_mouse"
    d.mkdir(parents=True)
    path = d / "sapimouse_ABS_dx_dy_1min.csv"
    rows: list[str] = []
    for s in range(subjects):
        rng = random.Random(s * 7 + 1)
        radius, span = 30.0 + s * 55.0, 0.4 + 0.5 * s
        for _ in range(4):
            xs = [radius * math.sin(i * span / 127) for i in range(129)]
            ys = [radius * (1 - math.cos(i * span / 127)) for i in range(129)]
            dx = [xs[i + 1] - xs[i] + rng.gauss(0, 0.25) for i in range(128)]
            dy = [ys[i + 1] - ys[i] + rng.gauss(0, 0.25) for i in range(128)]
            rows.append(",".join(f"{v:.3f}" for v in dx + dy) + f",subj{s}")
    path.write_text("\n".join(rows) + "\n")
    return path


def test_corroborate_runs_the_second_source_path(tmp_path: Path) -> None:
    # Exercises the full SapiMouse pipeline (parse rows → per-subject descriptors → between-subject floor vs
    # epsilon → exit code). The verdict (0 pass / 1 fail) is a property of the data; we only assert the path runs
    # and returns a valid code — the real human-floor measurement runs locally on the real corpus.
    _fake_sapimouse(tmp_path, subjects=6)
    assert corroborate(tmp_path, TEMPLATE_EPSILON) in (0, 1)


def test_corroborate_reports_missing_data(tmp_path: Path) -> None:
    assert corroborate(tmp_path, TEMPLATE_EPSILON) == 2  # no input_csv_mouse/*.csv
