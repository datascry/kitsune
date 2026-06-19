# harness/sapimouse_corpus — SECOND-source corroboration of the biomech power-law floor (SapiMouse, 120 subjects).
# Reconstructs (x,y,t) from SapiMouse dx/dy blocks, runs the SHIPPED biomech extractor, reports the FP table. CLI.

"""Second-source corroboration for the behavioral power-law rule (``bh.power_law_violation``).

The behavioral layer's one surviving threshold rule is calibrated against a SINGLE human-motion corpus
(Balabit, 10 subjects — see ``docs/behavioral-data.md``). The standing discipline that caught the
prevalence FP applies here too: *never trust a single-source floor*. This module adds an independent
second source — **SapiMouse** (Antal et al., Sapientia University; 120 subjects, a different rig and era
than Balabit) — and measures the power-law exponent's human floor on it with the EXACT extractor the
detector runs (``kitsune_harness.biomech.power_law``), so the number corroborates the *shipped* code path,
not a re-implementation.

SapiMouse's committed CSVs are model-ready fixed-length ``dx, dy`` blocks (128 dx, 128 dy, subject label),
not raw ``(x, y, t)``. That is fine for the power law: ``β`` is the slope of ``log V`` on ``log R``, and a
uniform-Δt reconstruction shifts only the intercept (``log V = log dist - log dt``, a constant offset under
constant dt), leaving the slope ``β`` invariant. We cumulative-sum the deltas into a trajectory with
``t = i`` and fit ``β`` over it.

Result (both 1-min and 3-min sessions, all 120 subjects): human ``β`` p1 ≈ 0.38, median ≈ 0.49 — and
**0% of samples fall below the 0.1 (or 0.05) threshold**, with 0/120 subjects' per-subject p1 below it.
Independent of Balabit, real aimed motion obeys the 2/3 power law well above the rule's floor — the
threshold is FP-safe on a second source.

The raw dataset is fetched at use-time, never committed (license + size): clone
``https://github.com/margitantal68/sapimouse`` and point ``KITSUNE_SAPIMOUSE_DIR`` at it (or pass
``--dir``). The committed artifact is this pipeline + the corroborated constant, not the data.

    KITSUNE_SAPIMOUSE_DIR=/path/to/sapimouse uv run python -m kitsune_harness.sapimouse_corpus
"""

from __future__ import annotations

import argparse
import os
import statistics
import sys
from collections import defaultdict
from pathlib import Path

from .biomech import Sample, power_law

# The rule's committed floor (contracts/rules/registry.yaml: bh.power_law_violation, below_threshold).
DEFAULT_THRESHOLD = 0.05
_BLOCK = 128  # SapiMouse fixed block length: 128 dx then 128 dy, then a subject label.


def reconstruct(parts: list[str]) -> list[Sample]:
    """Reconstruct an ``(x, y, t)`` trajectory from one SapiMouse ``dx,dy`` block row (uniform Δt → t=i)."""
    vals = [float(v) for v in parts[: 2 * _BLOCK]]
    dx, dy = vals[:_BLOCK], vals[_BLOCK : 2 * _BLOCK]
    out: list[Sample] = []
    x = y = 0.0
    for i in range(_BLOCK):
        x += dx[i]
        y += dy[i]
        out.append((x, y, float(i)))
    return out


def _pctl(vals: list[float], q: float) -> float:
    s = sorted(vals)
    return s[max(0, min(len(s) - 1, int(q * len(s))))]


def betas_by_subject(csv_path: Path) -> dict[str, list[float]]:
    """Fit the shipped biomech ``β`` for every SapiMouse sample, grouped by subject label."""
    per: dict[str, list[float]] = defaultdict(list)
    for line in csv_path.read_text().splitlines():
        parts = line.strip().split(",")
        if len(parts) != 2 * _BLOCK + 1:
            continue
        label = parts[-1]
        fit = power_law(reconstruct(parts))
        if fit is not None:
            per[label].append(fit[0])
    return per


def corroborate(data_dir: Path, threshold: float) -> int:
    """Print the SapiMouse power-law floor vs the rule threshold for each session length. Non-zero on a
    floor at/below threshold (a real second-source FP), so CI/a human notices an over-tight threshold."""
    csvs = sorted((data_dir / "input_csv_mouse").glob("sapimouse_ABS_dx_dy_*min.csv"))
    if not csvs:
        print(f"no SapiMouse CSVs under {data_dir}/input_csv_mouse — clone margitantal68/sapimouse", file=sys.stderr)
        return 2
    worst_floor = 1.0
    for csv_path in csvs:
        per = betas_by_subject(csv_path)
        allb = [b for bs in per.values() for b in bs]
        n = len(allb)
        if n == 0:
            continue
        below = sum(1 for b in allb if b < threshold) / n
        bad = sum(1 for bs in per.values() if _pctl(bs, 0.01) < threshold)
        floor = _pctl(allb, 0.01)
        worst_floor = min(worst_floor, floor)
        tag = csv_path.stem.split("_")[-1]
        print(
            f"SapiMouse {tag:>5}: subjects={len(per):3d} samples={n:5d}  "
            f"p1={floor:.3f} p5={_pctl(allb, 0.05):.3f} median={statistics.median(allb):.3f}  "
            f"FP@{threshold}={below * 100:.2f}%  subjects_p1<thr={bad}/{len(per)}"
        )
    ok = worst_floor > threshold
    print(f"\n{'OK' if ok else 'FAIL'}: second-source (SapiMouse) p1 floor {worst_floor:.3f} vs threshold {threshold}")
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Corroborate the biomech power-law floor against SapiMouse.")
    ap.add_argument("--dir", default=os.environ.get("KITSUNE_SAPIMOUSE_DIR", ""), help="SapiMouse clone dir")
    ap.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD)
    args = ap.parse_args(argv)
    if not args.dir:
        print("set --dir or KITSUNE_SAPIMOUSE_DIR to a margitantal68/sapimouse clone", file=sys.stderr)
        return 2
    return corroborate(Path(args.dir), args.threshold)


if __name__ == "__main__":
    raise SystemExit(main())
