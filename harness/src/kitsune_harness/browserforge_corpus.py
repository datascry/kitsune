# harness/browserforge_corpus — Tier-1 calibration corpus from real browserforge fingerprints.
# Generates real-browser fingerprint distributions and scores them for false positives. CLI: see __main__.

"""browserforge real-fingerprint corpus (Tier-1 calibration data).

browserforge samples from a Bayesian network of *real* browser fingerprints (the same data anti-detect
tools use to look real), so its output is a stand-in for legitimate-browser distributions across
OS/engine — exactly what we need to measure rule false-positive rates without a live device farm. This
module is the thin generator glue (lazy ``browserforge`` import, excluded from coverage); the scoring +
report logic lives in ``calibration``.

    uv run --with browserforge python -m kitsune_harness.browserforge_corpus --n 400
"""

from __future__ import annotations

import sys
from datetime import UTC, datetime
from typing import Any

from kitsune_detector.detector import Detector

from .calibration import calibrate, render_report, signals_from_fingerprint


def _fingerprint_to_dict(fp: Any) -> dict[str, Any]:
    """Flatten a browserforge Fingerprint into the nested dict shape the signal mapper reads."""
    nav, scr = fp.navigator, fp.screen
    vc = fp.videoCard
    return {
        "navigator": {
            "userAgent": nav.userAgent,
            "platform": nav.platform,
            "languages": list(nav.languages or []),
            "hardwareConcurrency": nav.hardwareConcurrency,
            "deviceMemory": getattr(nav, "deviceMemory", None),
            "vendor": getattr(nav, "vendor", ""),
            "productSub": getattr(nav, "productSub", ""),
            "oscpu": getattr(nav, "oscpu", None),
            "maxTouchPoints": getattr(nav, "maxTouchPoints", 0),
            "webdriver": getattr(nav, "webdriver", False),
        },
        "userAgentData": getattr(nav, "userAgentData", None),
        "screen": {
            "width": scr.width,
            "height": scr.height,
            "availWidth": scr.availWidth,
            "availHeight": scr.availHeight,
            "colorDepth": scr.colorDepth,
            "devicePixelRatio": scr.devicePixelRatio,
            "outerWidth": scr.outerWidth,
            "outerHeight": scr.outerHeight,
        },
        "videoCard": {"renderer": getattr(vc, "renderer", ""), "vendor": getattr(vc, "vendor", "")} if vc else {},
        "audioCodecs": fp.audioCodecs or {},
        "videoCodecs": fp.videoCodecs or {},
        "multimediaDevices": fp.multimediaDevices or {},
        "fonts": list(fp.fonts or []),
        "pluginsData": fp.pluginsData or {},
    }


def generate_profiles(n: int, now: datetime) -> list[tuple[str, list[Any]]]:  # pragma: no cover - external data
    """Generate n real-browser profiles as (label, signals) via browserforge."""
    from browserforge.fingerprints import FingerprintGenerator

    fg = FingerprintGenerator()
    profiles: list[tuple[str, list[Any]]] = []
    for i in range(n):
        fp = _fingerprint_to_dict(fg.generate())
        ua = str(fp["navigator"]["userAgent"])
        profiles.append((f"bf-{i:04d}", signals_from_fingerprint(fp, f"bf-{i:04d}", now)))
        _ = ua
    return profiles


def profiles_from_dir(path: str, now: datetime) -> list[tuple[str, list[Any]]]:  # pragma: no cover - IO
    """Load real-captured fingerprint JSONs from a directory as calibration profiles (Tier-2/Tier-3).

    A second, independent data source to corroborate the browserforge (Tier-1) findings — never act on a
    single-source false-positive number. Each *.json is one captured browser fingerprint (the shape
    ``signals_from_fingerprint`` reads); e.g. corpus/calibration/engines/ holds real Chromium/Firefox/WebKit.
    """
    import json
    from pathlib import Path

    out: list[tuple[str, list[Any]]] = []
    for p in sorted(Path(path).glob("*.json")):
        fp = json.loads(p.read_text())
        out.append((p.stem, signals_from_fingerprint(fp, p.stem, now)))
    return out


def main(argv: list[str] | None = None) -> None:  # pragma: no cover - thin CLI
    argv = sys.argv[1:] if argv is None else argv
    now = datetime.now(UTC)
    detector = Detector()
    if "--from-dir" in argv:
        report = calibrate(detector, profiles_from_dir(argv[argv.index("--from-dir") + 1], now))
    else:
        n = int(argv[argv.index("--n") + 1]) if "--n" in argv else 400
        report = calibrate(detector, generate_profiles(n, now))
    print(render_report(report, fp_threshold=0.0), end="")


if __name__ == "__main__":  # pragma: no cover
    main()
