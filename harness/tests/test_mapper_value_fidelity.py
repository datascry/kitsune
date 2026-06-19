# tests/test_mapper_value_fidelity — the calibration mapper must reproduce the real collector's signal VALUES.
# Deeper than test_mapper_coverage (which pins the emitted-kind set): this pins per-kind value fidelity.

"""Value-level mapper-fidelity guard (the standing constraint's methodology demand, part (a)).

``test_mapper_coverage`` proves the mapper emits the right *kinds*; this proves it emits the right *values*.
For each real engine we hold BOTH a fingerprint (``corpus/calibration/engines/<e>.json`` — the mapper's input)
AND a real collector session (``corpus/calibration/headful/<e>.json`` — what the live in-page collector emitted
for that engine). ``signals_from_fingerprint`` run on the fingerprint must reproduce the collector's value for
every signal kind they share — otherwise the browserforge calibration is scoring values a real browser never
emits, and a single-source FP number measured through the mapper would be an artifact.

The engine fingerprints are **headless** Playwright captures (they carry the headless stripped-browser tells —
``plugins_count`` 0, ``mimetypes_empty``, ``chrome_no_pdfviewer``), whereas the headful sessions are the
real-headful baseline. So a small set of (engine, kind) pairs legitimately differ on the headless/headful axis
and are allowlisted below WITH the reason; everything else must match exactly. (This also documents that the
engine fixtures are a valid baseline for the COHERENCE/ARTIFACT convicting categories — which match exactly —
but not for the headless-environment tells.)
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from kitsune_harness.calibration import signals_from_fingerprint

_CALIB = Path(__file__).resolve().parents[2] / "corpus" / "calibration"
_NOW = datetime(2026, 6, 19, tzinfo=UTC)
_ENGINES = ("chromium", "firefox", "webkit")

# (engine, kind) pairs whose mapper value legitimately differs from the headful collector because the engine
# fingerprint was captured HEADLESS. Each must carry a reason — never silence a real fidelity drift.
_HEADLESS_DIFFS: dict[tuple[str, str], str] = {
    ("chromium", "plugins_count"): "headless Chromium ships 0 plugins; headful has the 5 standard PDF plugins",
}


def _mapper_values(engine: str) -> dict[str, object]:
    fp = json.loads((_CALIB / "engines" / f"{engine}.json").read_text())
    return {s.kind: s.value for s in signals_from_fingerprint(fp, engine, _NOW)}


def _collector_values(engine: str) -> dict[str, object]:
    sess = json.loads((_CALIB / "headful" / f"{engine}.json").read_text())
    return {s["kind"]: s["value"] for s in sess.get("signals", {}).get("browser", [])}


@pytest.mark.parametrize("engine", _ENGINES)
def test_mapper_reproduces_collector_values(engine: str) -> None:
    mapper, collector = _mapper_values(engine), _collector_values(engine)
    shared = set(mapper) & set(collector)
    assert shared, f"{engine}: no shared signal kinds — fixtures out of sync"
    mismatches = {
        k: (mapper[k], collector[k])
        for k in shared
        if str(mapper[k]) != str(collector[k]) and (engine, k) not in _HEADLESS_DIFFS
    }
    assert not mismatches, f"{engine}: mapper value != real collector value (calibration artifact): {mismatches}"


def test_allowlisted_diffs_are_real() -> None:
    # Guard the allowlist itself: each allowlisted (engine, kind) must actually still differ — so a future
    # fixture re-capture that resolves the headless/headful gap forces the stale entry to be removed.
    for (engine, kind), _reason in _HEADLESS_DIFFS.items():
        mapper, collector = _mapper_values(engine), _collector_values(engine)
        if kind in mapper and kind in collector:
            assert str(mapper[kind]) != str(collector[kind]), (
                f"{engine}.{kind} no longer differs — drop the allowlist entry"
            )
