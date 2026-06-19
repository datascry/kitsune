# harness/tests/test_sapimouse_corpus — hermetic checks for the SapiMouse second-source corroboration.
# No network: synthesise dx/dy blocks (a power-law-obeying path, a malformed row) and assert the pipeline.

from __future__ import annotations

import math
from pathlib import Path

from kitsune_harness.sapimouse_corpus import _BLOCK, betas_by_subject, corroborate, main, reconstruct


def _obeying_block() -> tuple[list[float], list[float]]:
    """A two-arc path whose per-step distance scales with the radius of curvature (uniform Δt → speed =
    step distance), so V rises with R and β > 0 — a power-law *obeyer*. Returned as 128-length dx/dy."""
    pts: list[tuple[float, float]] = []
    for radius in (20.0, 80.0):
        dtheta = radius ** (-2 / 3) * 0.15  # step distance ∝ R**(1/3) → V ∝ R**(1/3)
        th = 0.0
        while th < math.pi / 2 and len(pts) < _BLOCK + 1:
            pts.append((radius * math.cos(th), radius * math.sin(th)))
            th += dtheta
    dx = [pts[i + 1][0] - pts[i][0] for i in range(len(pts) - 1)]
    dy = [pts[i + 1][1] - pts[i][1] for i in range(len(pts) - 1)]
    dx += [0.0] * (_BLOCK - len(dx))  # pad to a full block; zero-edge triples are skipped by the fit
    dy += [0.0] * (_BLOCK - len(dy))
    return dx[:_BLOCK], dy[:_BLOCK]


def _row(dx: list[float], dy: list[float], label: str) -> str:
    return ",".join(str(v) for v in (*dx, *dy, label))


def _write_corpus(dirpath: Path, name: str, subjects: int) -> Path:
    dx, dy = _obeying_block()
    csv = dirpath / "input_csv_mouse" / name
    csv.parent.mkdir(parents=True, exist_ok=True)
    csv.write_text("\n".join(_row(dx, dy, str(s)) for s in range(subjects)))
    return csv


def test_reconstruct_cumsums_deltas_with_uniform_time() -> None:
    traj = reconstruct([str(v) for v in (*([1.0] * _BLOCK), *([0.0] * _BLOCK), "7")])
    assert len(traj) == _BLOCK
    assert traj[0] == (1.0, 0.0, 0.0)  # x integrates the deltas, t is the uniform index, y stays put
    assert traj[-1] == (float(_BLOCK), 0.0, float(_BLOCK - 1))


def test_obeying_path_floor_above_threshold(tmp_path: Path) -> None:
    csv = _write_corpus(tmp_path, "sapimouse_ABS_dx_dy_1min.csv", subjects=3)
    per = betas_by_subject(csv)
    assert set(per) == {"0", "1", "2"}
    assert all(b > 0.05 for bs in per.values() for b in bs)  # obeys the power law above the floor
    assert corroborate(tmp_path, threshold=0.05) == 0  # floor above threshold → OK


def test_malformed_rows_are_skipped(tmp_path: Path) -> None:
    dx, dy = _obeying_block()
    csv = tmp_path / "input_csv_mouse" / "sapimouse_ABS_dx_dy_3min.csv"
    csv.parent.mkdir(parents=True)
    csv.write_text("not,enough,columns\n" + _row(dx, dy, "1"))
    assert set(betas_by_subject(csv)) == {"1"}  # the short row is ignored, the valid block parsed


def test_corroborate_missing_dir_returns_sentinel(tmp_path: Path) -> None:
    assert corroborate(tmp_path, threshold=0.05) == 2  # no input_csv_mouse → sentinel, not a crash


def test_main_requires_a_dir() -> None:
    assert main(["--dir", ""]) == 2  # no dir given and env unset in test → usage sentinel


def test_main_runs_over_a_corpus(tmp_path: Path) -> None:
    _write_corpus(tmp_path, "sapimouse_ABS_dx_dy_1min.csv", subjects=4)
    assert main(["--dir", str(tmp_path), "--threshold", "0.05"]) == 0
