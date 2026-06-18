# harness/balabit — load Balabit Mouse-Dynamics sessions into (x, y, t) trajectories for calibration.
# Parses the public CSV (record/client ts, button, state, x, y) and splits it into aimed-movement segments.

"""Balabit Mouse Dynamics loader (step 2/4 of the behavioral pipeline; see docs/behavioral-data.md).

Turns a Balabit session CSV — ``record timestamp, client timestamp, button, state, x, y`` — into the
``(x, y, t)`` trajectories ``kitsune_harness.biomech`` consumes, split into aimed-movement segments on
pauses. Pure parsing; the raw dataset is fetched at use-time and never committed (license + size). Use it
to calibrate the biomech features' human envelope from real data, then ground the behavioral rules in that
envelope instead of hand-picked thresholds.
"""

from __future__ import annotations

from .biomech import Sample


def parse_balabit(text: str) -> list[Sample]:
    """Parse a Balabit session CSV into ``(x, y, t)`` samples (client timestamp as t). Skips the header
    and any malformed row."""
    out: list[Sample] = []
    for line in text.splitlines():
        parts = line.split(",")
        if len(parts) < 6 or parts[0].strip() == "record timestamp":
            continue
        try:
            t = float(parts[1])
            x = float(parts[4])
            y = float(parts[5])
        except ValueError:
            continue
        out.append((x, y, t))
    return out


def movement_segments(
    samples: list[Sample], *, max_gap: float = 0.5, min_len: int = 8
) -> list[list[Sample]]:
    """Split a sample stream into aimed-movement segments: cut on a time gap > ``max_gap`` (a pause ends a
    movement) and keep only segments with at least ``min_len`` points (enough for the biomech features)."""
    segments: list[list[Sample]] = []
    current: list[Sample] = []
    for sample in samples:
        if current and sample[2] - current[-1][2] > max_gap:
            if len(current) >= min_len:
                segments.append(current)
            current = []
        current.append(sample)
    if len(current) >= min_len:
        segments.append(current)
    return segments
