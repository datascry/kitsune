# tests/test_mapper_coverage — pin the calibration mapper's signal-kind SCOPE (what browserforge can measure).
# The browserforge FP gate is single-source and structurally blind to whole layers; this guards that scope.

"""Mapper-coverage scope guard (docs/calibration.md "Mapper fidelity & coverage scope").

``signals_from_fingerprint`` maps a static fingerprint to the browser-layer signals a real browser emits. A
browserforge fingerprint has no network/behavioural/automation/CH/webgpu layer, so the calibration that runs
through this mapper can only ever measure FP for the browser-fingerprint-coherence rules — it is BLIND to the
net.* / behavioural / automation / webgpu / client-hint convicting rules (those are validated against the live
evader fleet + the headful captures + the Intoli real-traffic source instead). If a future mapper change
silently adds or drops a measured kind, the calibration's *scope* changes — and a single-source FP number that
silently covers more/less than you think is exactly the trap the standing constraint warns about. This test
pins the scope over the committed REAL engine fingerprints (no browserforge needed), so any change is conscious.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from kitsune_harness.calibration import signals_from_fingerprint

_ENGINES = Path(__file__).resolve().parents[2] / "corpus" / "calibration" / "engines"
_NOW = datetime(2026, 6, 19, tzinfo=UTC)

# The exact browser-layer kinds the mapper derives from the three real engine fingerprints
# (Chromium/Firefox/WebKit). These — and ONLY these — are what the browserforge FP gate measures.
_EXPECTED_SCOPE = {
    "ch_he_headless",
    "ch_platform",
    "chrome_no_pdfviewer",
    "color_depth",
    "hardware_concurrency",
    "macos_dpr1",
    "media_devices_empty",
    "mimetypes_empty",
    "nav_platform_os",
    "oscpu_os",
    "plugins_count",
    "productsub_render",
    "screen_resolution",
    "ua_engine",
    "ua_platform",
    "ua_render",
    "vendor_engine",
    "webdriver",
    "webgl_os_hint",
    "webgl_renderer",
    "webgl_software",
}


def _mapper_kinds() -> set[str]:
    kinds: set[str] = set()
    for path in _ENGINES.glob("*.json"):
        fp = json.loads(path.read_text())
        kinds.update(s.kind for s in signals_from_fingerprint(fp, path.stem, _NOW))
    return kinds


def test_mapper_scope_is_pinned() -> None:
    # If this fails, the mapper's measurement scope changed. Update _EXPECTED_SCOPE *and* docs/calibration.md,
    # and re-confirm the new/removed kind is faithful to the real collector (demo.py) — not a mapper artifact.
    assert _mapper_kinds() == _EXPECTED_SCOPE


def test_mapper_emits_no_network_or_behavioural_kinds() -> None:
    # The structural blindness, asserted directly: browserforge has no such layer, so the mapper must not
    # invent one (which would make the FP gate silently "cover" rules it cannot actually exercise).
    kinds = _mapper_kinds()
    forbidden_substrings = ("ja3", "ja4", "h2", "quic", "tcp", "tls", "mouse", "trace", "pause", "submovement")
    leaked = {k for k in kinds if any(sub in k for sub in forbidden_substrings)}
    assert not leaked, f"mapper leaked network/behavioural kinds it cannot ground: {leaked}"
