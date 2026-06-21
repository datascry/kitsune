# harness/tests/test_prevalence_real_corroborate — the real-traffic corroboration tool buckets + scores correctly.
# Grounds the LOGIC on a synthetic CSV (the operator grounds it on the real consented corpus, never committed).

from __future__ import annotations

from pathlib import Path

from kitsune_harness.prevalence_real_corroborate import (
    corroborate,
    detect_columns,
    row_to_fingerprint,
)

_HEADER = [
    "User Agent",
    "Platform",
    "WebGL Unmasked Renderer",
    "Screen resolution",
    "Color depth",
    "Hardware concurrency",
]


def _write(tmp_path: Path, rows: list[str]) -> Path:
    p = tmp_path / "synth.csv"
    p.write_text(",".join(_HEADER) + "\n" + "\n".join(rows) + "\n")
    return p


def test_detect_columns_maps_documented_attribute_names() -> None:
    cols = detect_columns(_HEADER)
    assert cols["renderer"] == "WebGL Unmasked Renderer"  # longest-keyword wins over bare "renderer"/"screen"
    assert cols["resolution"] == "Screen resolution"
    assert cols["cores"] == "Hardware concurrency"
    assert cols["ua"] == "User Agent" and cols["color"] == "Color depth"


def test_row_to_fingerprint_parses_bracketed_resolution() -> None:
    cols = detect_columns(_HEADER)
    row = dict(
        zip(
            _HEADER,
            ["Mozilla/5.0 (Windows NT 10.0) Chrome", "Win32", "ANGLE (Intel UHD)", "[1920,1080]", "24", "8"],
            strict=True,
        )
    )
    fp = row_to_fingerprint(row, cols)
    assert fp["screen"] == {"width": 1920, "height": 1080, "colorDepth": "24"}


def test_corroborate_scores_common_fingerprints_as_not_improbable(tmp_path: Path) -> None:
    csv = _write(
        tmp_path,
        [
            'Mozilla/5.0 (Windows NT 10.0; Win64) Chrome/120,Win32,ANGLE (Intel Iris Xe),"[1920,1080]",24,8',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) Safari,MacIntel,Apple GPU,"[2560,1440]",30,10',
        ],
    )
    r = corroborate(csv)
    assert r["rows_parsed"] == 2
    assert r["rows_full_vector"] == 2
    # Common real fingerprints must NOT trip br.fingerprint_improbable under the committed prior (FP-safety).
    assert r["real_traffic_fp_rate"] == 0.0
    assert r["promotion_fp_safe"] is True
    assert r["real_prior"]["gpu"]["Windows"]["intel"] == 1.0  # the one Windows row is Intel


def test_unclassifiable_gpu_abstains_not_flagged(tmp_path: Path) -> None:
    # A real Firefox software-rendering renderer ("llvmpipe") is unclassifiable -> gpu=None -> abstains (not a
    # full vector), exactly as the detector does, so it is NOT counted as an improbable FP.
    csv = _write(
        tmp_path, ['Mozilla/5.0 (X11; Linux x86_64) Firefox/121,Linux x86_64,llvmpipe (LLVM 15),"[1366,768]",24,4']
    )
    r = corroborate(csv)
    assert r["rows_parsed"] == 1
    assert r["rows_full_vector"] == 0  # llvmpipe -> gpu None -> abstain
