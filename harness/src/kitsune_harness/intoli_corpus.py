# harness/intoli_corpus — Tier-2 calibration corpus from the Intoli user-agents dataset (real traffic).
# A SECOND, independent source to corroborate browserforge FP numbers; heavy on real mobile. CLI: __main__.

"""Real-traffic calibration corpus (a second, independent source).

The calibration's Tier-1 source is browserforge — a *generated* distribution. This module adds an
independent second source: the Intoli ``user-agents`` dataset (BSD-2-Clause, Intoli LLC), ~10k records
resampled from real site traffic, each a real ``userAgent`` paired with its real ``platform`` / ``vendor``
/ ``screen`` / language. It is ~75% mobile — exactly the surface browserforge under-represents and a
desktop-oriented coherence rule is most likely to false-fire on (a real Android UA carries
``navigator.platform = "Linux …"``, which a naive platform-coherence check reads as a contradiction).

Intoli does not capture WebGL / canvas / media-device / font fields, so this mapper deliberately emits
ONLY the signals the dataset genuinely supports — the UA / platform / vendor / language *coherence*
inputs. Emitting the absence-based environment tells would be a schema artifact (the field is missing from
the dataset, not from the real browser). Because the conviction gate lets only a coherence/automation/
artifact signal convict, the verdict rate over this corpus is a clean measure of *coherence-driven* false
positives on real traffic — corroborating or refuting the browserforge coherence numbers.

    uv run python -m kitsune_harness.intoli_corpus --n 4000

The dataset is fetched at runtime (not committed); set ``KITSUNE_INTOLI_URL`` to override the source.
"""

from __future__ import annotations

import gzip
import json
import os
import sys
import urllib.request
from datetime import UTC, datetime
from typing import Any

from kitsune_detector.detector import Detector
from kitsune_detector.models import Layer, Signal, Source

from .calibration import (
    _nav_platform_os,
    _ua_engine,
    _ua_platform,
    _vendor_engine,
    calibrate,
    render_report,
)

_INTOLI_URL = "https://raw.githubusercontent.com/intoli/user-agents/master/src/user-agents.json.gz"


def fetch_records(url: str | None = None) -> list[dict[str, Any]]:  # pragma: no cover - external data/IO
    """Download + decompress the Intoli user-agents dataset into a list of real-traffic records."""
    url = url or os.environ.get("KITSUNE_INTOLI_URL") or _INTOLI_URL
    with urllib.request.urlopen(url, timeout=60) as resp:
        raw = resp.read()
    data = gzip.decompress(raw) if url.endswith(".gz") else raw
    records: list[dict[str, Any]] = json.loads(data)
    return records


def intoli_signals(rec: dict[str, Any], session_id: str, now: datetime) -> list[Signal]:
    """Map one Intoli record to ONLY the coherence signals its fields genuinely support (UA / platform /
    vendor / language). No absence-based environment tells — those would be dataset-schema artifacts."""
    ua = str(rec.get("userAgent", ""))
    out: list[Signal] = []

    def sig(layer: Layer, kind: str, value: object) -> None:
        out.append(
            Signal(session_id=session_id, layer=layer, kind=kind, value=value, source=Source.collector, observed_at=now)
        )

    sig(Layer.browser, "ua_platform", _ua_platform(ua))
    sig(Layer.browser, "ua_engine", _ua_engine(ua))
    plat = str(rec.get("platform", ""))
    if plat:
        nav_os = _nav_platform_os(plat)
        if nav_os:
            sig(Layer.browser, "nav_platform_os", nav_os)
    vendor = str(rec.get("vendor", ""))
    if vendor:
        sig(Layer.browser, "vendor_engine", _vendor_engine(vendor))
    lang = str(rec.get("language", ""))
    if lang:
        sig(Layer.browser, "nav_language_primary", lang.split("-")[0].split(",")[0])
    w, h = int(rec.get("screenWidth", 0) or 0), int(rec.get("screenHeight", 0) or 0)
    if w and h:
        sig(Layer.browser, "screen_resolution", f"{w}x{h}")
    return out


def profiles(n: int, now: datetime, url: str | None = None) -> list[tuple[str, list[Signal]]]:  # pragma: no cover
    recs = fetch_records(url)
    # Weighted records over-represent popular browsers; take the first n in file order (already a sample).
    return [(f"intoli-{i:04d}", intoli_signals(r, f"intoli-{i:04d}", now)) for i, r in enumerate(recs[:n])]


def main(argv: list[str] | None = None) -> None:  # pragma: no cover - thin CLI
    argv = sys.argv[1:] if argv is None else argv
    n = int(argv[argv.index("--n") + 1]) if "--n" in argv else 4000
    now = datetime.now(UTC)
    report = calibrate(Detector(), profiles(n, now))
    print(render_report(report, fp_threshold=0.0), end="")


if __name__ == "__main__":  # pragma: no cover
    main()
