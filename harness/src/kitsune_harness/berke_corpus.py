# harness/berke_corpus — build the prevalence prior from the Berke et al. (PoPETs 2025) real-fingerprint CSV.
# Maps each consented browser-attributes row into the fingerprint shape the prevalence extractor reads; aggregate-only.

"""Berke real-fingerprint corpus → prevalence prior (the Tier-3 prevalence unlock).

The shipped prevalence prior is browserforge-built — *same-source-blind*: a generator-based attacker samples
from the same distribution, so its fingerprints are probable in our prior by construction (see
docs/prevalence-model.md). The recurring unlock is a prior built from REAL traffic. Berke et al.,
*"How Unique is Whose Web Browser?"* (PoPETs 2025) published **8,400 consented** real browser fingerprints
covering Kitsune's exact prevalence attributes (User agent, Screen resolution, Hardware concurrency, WebGL
Unmasked Renderer, …) — the dataset is on Harvard Dataverse (``doi.org/10.7910/DVN/0SGZFF``).

**Data terms (must be honoured).** The browser-attributes file is *research-use only*; downloading it
requires accepting Berke's terms of use, which **prohibit re-identification and any further sharing/publishing
of the data**. So this module is the *consumer*, not a fetcher: an operator who has accepted those terms and
downloaded ``survey-and-browser-attributes-data.csv`` runs this to build the prior. Only the resulting prior
is emitted — coarse joint-frequency tables over bucketed features (P(gpu|plat), P(screen|plat), P(cores)),
de-identified aggregate statistics, NOT the rows — so committing the prior does not redistribute the dataset.

    cd harness && uv run python -m kitsune_harness.berke_corpus survey-and-browser-attributes-data.csv

Column names are the published data-dictionary headers (the repo's preprocessing notebook reads the CSV by
these same human-readable names). The row→fingerprint mapping deliberately reuses the detector's own
``features_from_fingerprint`` so the prior's features stay byte-for-byte in sync with what the scorer extracts
at runtime — no parallel bucketing logic to drift.
"""

from __future__ import annotations

import re
import sys
from typing import Any

from .browserforge_corpus import write_prior

# Published data-dictionary column headers (Berke et al., PoPETs 2025). Only the columns the prevalence model
# reads are mapped; the rest of the survey/fingerprint columns are ignored.
COL_UA = "User agent"
COL_SCREEN = "Screen resolution"
COL_COLOR = "Color depth"
COL_CORES = "Hardware concurrency"
COL_RENDERER = "WebGL Unmasked Renderer"


def parse_screen(value: str) -> tuple[int, int]:
    """Parse the Berke screen-resolution cell into ``(width, height)``; ``(0, 0)`` when unparseable.

    The published format is a ``[width,height]`` pair (e.g. ``[1920,1080]``); a bare ``WxH`` is also accepted
    defensively. Anything else (blank, malformed) returns ``(0, 0)``, which ``screen_bucket`` treats as
    unscored — so a missing/garbage screen abstains rather than poisoning the prior.
    """
    nums = re.findall(r"\d+", value or "")
    if len(nums) < 2:
        return (0, 0)
    return (int(nums[0]), int(nums[1]))


def fingerprint_from_berke_row(row: dict[str, str]) -> dict[str, Any]:
    """Map one Berke CSV row into the fingerprint dict ``features_from_fingerprint`` reads.

    Reusing that extractor (rather than re-deriving plat/gpu/screen/cores here) keeps the real-traffic prior's
    features identical to the detector's runtime extraction — the platform is UA-derived, the GPU family comes
    from the unmasked renderer, screen + cores are bucketed by the shared helpers.
    """
    w, h = parse_screen(row.get(COL_SCREEN, ""))
    return {
        "navigator": {
            "userAgent": row.get(COL_UA, ""),
            "hardwareConcurrency": row.get(COL_CORES),
        },
        "screen": {"width": w, "height": h, "colorDepth": row.get(COL_COLOR)},
        "videoCard": {"renderer": row.get(COL_RENDERER, "")},
    }


def features_from_berke_csv(csv_path: str) -> list[dict[str, Any]]:
    """Read the Berke CSV and extract a prevalence feature dict per row (skips rows with no usable plat)."""
    import csv

    from .prevalence import features_from_fingerprint

    with open(csv_path, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    if not rows:
        raise SystemExit(f"no rows in {csv_path}")
    if COL_UA not in rows[0]:
        raise SystemExit(
            f"{csv_path} is missing the '{COL_UA}' column — is this the survey-and-browser-attributes file? "
            "(the survey-experiment-data.csv variant excludes browser attributes and cannot build a prior)"
        )
    return [features_from_fingerprint(fingerprint_from_berke_row(r)) for r in rows]


def build_prior_from_berke(csv_path: str, out_path: str, source: str = "berke-popets2025") -> int:
    """Build the prevalence prior from the Berke real-fingerprint CSV and write it. Returns the row count.

    Emits ONLY the aggregate prior (joint-frequency tables + threshold), never the rows — honouring the
    dataset's no-redistribution term. The threshold is the self-p1 of this real distribution (a real-traffic
    prior is the ground truth the browserforge self-p1 was a stand-in for).
    """
    feats = features_from_berke_csv(csv_path)
    threshold = write_prior(feats, out_path, source)
    print(f"wrote prior from {len(feats)} {source} fingerprints (p1 threshold {threshold:.2f}) -> {out_path}")
    return len(feats)


def main(argv: list[str] | None = None) -> None:  # pragma: no cover - thin CLI / IO
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        raise SystemExit(
            "usage: python -m kitsune_harness.berke_corpus <survey-and-browser-attributes-data.csv> [out.json]\n"
            "  builds the prevalence prior from the Berke (PoPETs 2025) research-use CSV (terms: no resharing)."
        )
    csv_path = argv[0]
    out = argv[1] if len(argv) > 1 else "../detector/src/kitsune_detector/data/prevalence_prior.json"
    build_prior_from_berke(csv_path, out)


if __name__ == "__main__":  # pragma: no cover
    main()
