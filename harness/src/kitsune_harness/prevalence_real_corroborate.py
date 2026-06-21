# harness/prevalence_real_corroborate — corroborate the prevalence prior against a REAL-traffic fingerprint corpus.
# Buckets a real CSV to the model features, builds the real prior, and measures the rule's real-traffic FP rate.

"""Second-source corroboration of the prevalence prior against a real-traffic fingerprint corpus.

The prevalence rule (``br.fingerprint_improbable``) is corroborating-only because its prior is browserforge-
GENERATED (single-source) — the documented Tier-3 gap. This tool consumes a REAL-traffic fingerprint CSV
(operator-provided, NOT committed — e.g. the PoPETS-2025 consented corpus, terms: research-only, no re-share)
and, mirroring the SapiMouse/Intoli/fpgen second-source methodology, answers the promotion question:

  1. **FP rate** — what fraction of REAL fingerprints would ``br.fingerprint_improbable`` flag under the
     committed (browserforge) prior? If ~0%, the rule is FP-safe on real traffic → promotion candidate.
  2. **Divergence** — which joint cells does browserforge mis-estimate vs real traffic (the single-source bias)?
  3. **Real prior** — the bucketed real-traffic prior (an aggregate; safe to publish — it is not the dataset).

Run LOCALLY on your copy of the corpus (the raw CSV never needs to leave your machine):

    cd harness && uv run python -m kitsune_harness.prevalence_real_corroborate /path/to/real-fingerprints.csv

It prints the detected column mapping (verify it!), the FP rate, the top divergent cells, and the aggregate
real prior as JSON. Paste those de-identified aggregates back; they decide whether the rule can be promoted.
"""

from __future__ import annotations

import csv
import json
import re
import sys
from pathlib import Path
from typing import Any

from kitsune_harness.prevalence import build_prior, features_from_fingerprint, log_prevalence

_ROOT = Path(__file__).resolve().parents[3]
_PRIOR_PATH = _ROOT / "detector" / "src" / "kitsune_detector" / "data" / "prevalence_prior.json"
_SCORED = ("gpu", "screen", "cores")

# Column role -> ordered keyword candidates to fuzzy-match the corpus header (the dataset's attribute names).
_ROLE_KEYWORDS: dict[str, list[str]] = {
    "ua": ["user agent", "useragent", "user-agent"],
    "platform": ["platform"],
    "renderer": ["webgl unmasked renderer", "unmasked renderer", "webgl renderer", "renderer"],
    "resolution": ["screen resolution", "resolution", "screen"],
    "color": ["color depth", "colour depth", "colordepth", "color"],
    "cores": ["hardware concurrency", "hardwareconcurrency", "concurrency", "cores", "logical processors"],
}


def detect_columns(header: list[str]) -> dict[str, str]:
    """Fuzzy-match each model role to a header column (longest keyword wins). Returns {role: column}."""
    norm = {h: re.sub(r"[^a-z0-9 ]", " ", h.lower()).strip() for h in header}
    mapping: dict[str, str] = {}
    for role, keywords in _ROLE_KEYWORDS.items():
        best: tuple[int, str] | None = None
        for kw in keywords:
            for col, n in norm.items():
                if kw in n:
                    score = len(kw)
                    if best is None or score > best[0]:
                        best = (score, col)
        if best is not None:
            mapping[role] = best[1]
    return mapping


def _parse_resolution(raw: str) -> tuple[int, int]:
    """Parse a screen resolution given as ``[1920,1080]`` or ``1920x1080`` -> (width, height); (0,0) if absent."""
    m = re.findall(r"\d+", raw or "")
    if len(m) >= 2:
        return int(m[0]), int(m[1])
    return 0, 0


def row_to_fingerprint(row: dict[str, str], cols: dict[str, str]) -> dict[str, Any]:
    """Map a CSV row to the fingerprint dict shape ``features_from_fingerprint`` reads."""
    w, h = _parse_resolution(row.get(cols.get("resolution", ""), ""))
    ua = row.get(cols.get("ua", ""), "")
    # If no UA column, synthesise a platform hint from navigator.platform (Win32/MacIntel/Linux/Android) so
    # features_from_fingerprint's UA-based plat extraction still resolves an anchor.
    if not ua:
        plat_raw = row.get(cols.get("platform", ""), "")
        ua = (
            "Windows"
            if re.search(r"win", plat_raw, re.I)
            else "Macintosh"
            if re.search(r"mac", plat_raw, re.I)
            else "Android"
            if re.search(r"android|arm|linux a", plat_raw, re.I)
            else "Linux"
            if re.search(r"linux|x11", plat_raw, re.I)
            else ""
        )
    return {
        "navigator": {"userAgent": ua, "hardwareConcurrency": row.get(cols.get("cores", ""), "")},
        "screen": {"width": w, "height": h, "colorDepth": row.get(cols.get("color", ""), "")},
        "videoCard": {"renderer": row.get(cols.get("renderer", ""), "")},
    }


def corroborate(csv_path: Path) -> dict[str, Any]:
    """Score a real-traffic CSV against the committed prior; return the corroboration result (all aggregate)."""
    prior_doc = json.loads(_PRIOR_PATH.read_text())
    bf_prior, threshold = prior_doc["prior"], float(prior_doc["threshold"])

    with csv_path.open(newline="", encoding="utf-8", errors="replace") as fh:
        reader = csv.DictReader(fh)
        cols = detect_columns(list(reader.fieldnames or []))
        feats_list = [features_from_fingerprint(row_to_fingerprint(r, cols)) for r in reader]

    full = [f for f in feats_list if f["plat"] and f["plat"] != "?" and all(f.get(s) is not None for s in _SCORED)]
    flagged = sum(1 for f in full if log_prevalence(f, bf_prior) < threshold)
    real_prior = build_prior(full)

    # Divergence: largest |real - browserforge| per (factor, given, value) cell, over cells real traffic populates.
    divergence: list[dict[str, Any]] = []
    for field in real_prior:
        for given, table in real_prior[field].items():
            for value, real_p in table.items():
                bf_p = bf_prior.get(field, {}).get(given, {}).get(value, 0.0)
                divergence.append(
                    {
                        "factor": field,
                        "given": given,
                        "value": value,
                        "real": round(real_p, 4),
                        "browserforge": round(bf_p, 4),
                        "delta": round(real_p - bf_p, 4),
                    }
                )
    divergence.sort(key=lambda d: abs(d["delta"]), reverse=True)

    return {
        "csv": str(csv_path),
        "columns_detected": cols,
        "rows_parsed": len(feats_list),
        "rows_full_vector": len(full),
        "threshold": threshold,
        "real_traffic_fp_count": flagged,
        "real_traffic_fp_rate": round(flagged / len(full), 5) if full else None,
        "promotion_fp_safe": (flagged == 0) if full else None,
        "top_divergent_cells": divergence[:20],
        "real_prior": real_prior,
    }


def main(argv: list[str] | None = None) -> int:  # pragma: no cover - thin CLI over corroborate()
    args = argv if argv is not None else sys.argv[1:]
    if not args:
        print("usage: python -m kitsune_harness.prevalence_real_corroborate <real-fingerprints.csv>", file=sys.stderr)
        return 2
    path = Path(args[0])
    if not path.exists():
        print(f"no such file: {path}", file=sys.stderr)
        return 2
    result = corroborate(path)
    print("# === column mapping (VERIFY this is right before trusting the result) ===")
    for role, col in result["columns_detected"].items():
        print(f"  {role:11} <- {col!r}")
    missing = [r for r in _ROLE_KEYWORDS if r not in result["columns_detected"]]
    if missing:
        print(f"  !! unmatched roles: {missing} — pass the header so the mapping can be fixed", file=sys.stderr)
    print(f"\n# parsed {result['rows_parsed']} rows ({result['rows_full_vector']} with a full feature vector)")
    print(
        f"# REAL-TRAFFIC FP RATE under the committed (browserforge) prior: "
        f"{result['real_traffic_fp_count']}/{result['rows_full_vector']} = {result['real_traffic_fp_rate']}"
    )
    print(f"# promotion FP-safe (rate == 0): {result['promotion_fp_safe']}")
    print("\n# === full result (paste this back — all de-identified aggregates) ===")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
