# harness/fpgen_corroborate — corroborate the single-source prevalence prior against Scrapfly's fpgen data.
# Diffs browserforge's gpu/screen/cores conditional distributions vs an independently-collected dataset. CLI.

"""Cross-source corroboration of the prevalence prior (the standing constraint's "never trust a single source").

The shipped prevalence prior (``detector/.../data/prevalence_prior.json``) is built from **browserforge**
alone. Its gpu/cores factors have had no independent corroboration (Intoli grounds screen only; there is no
public real-traffic gpu/cores distribution — see docs/prevalence-model.md). This module adds a partial,
honest cross-check: **fpgen** (Scrapfly's ``fingerprint-generator``) is the same author's Bayesian-network
model run on **Scrapfly's independently-collected data** — so it is NOT independent ground truth (same model
family → shared structural blind spots, and a same-family injector stays probable in both; see
docs/evasion-catalog.md "Scrapfly fingerprint-generator"), but its independent DATA makes it a legitimate
**overfit diagnostic**: where browserforge and fpgen agree, the prior's tail is not a browserforge
data-artifact; where they diverge, that factor is data-idiosyncratic and should be trusted less until real
Tier-3 data (a real-device matrix / hosted-demo capture through our own collector) lands.

It maps fpgen output through the SAME ``features_from_fingerprint`` the prior is built from, then reports the
total-variation distance (TVD: 0 = identical, 1 = disjoint) per factor and conditioning value. It changes no
rule — it is a trust diagnostic, run on demand (fpgen fetches its model over the network, so it is not a CI
test). Run: ``uv run --with fpgen python -m kitsune_harness.fpgen_corroborate --n 500``.
"""

from __future__ import annotations

import argparse
import collections
import json
from pathlib import Path
from typing import Any

from .prevalence import features_from_fingerprint

# Above this TVD a (factor | condition) cell is flagged data-idiosyncratic (browserforge-specific, trust less).
_HIGH_TVD = 0.35
# Below this sample count a cell's TVD is noise-dominated and reported as low-confidence.
_MIN_N = 50

_PRIOR_PATH = (
    Path(__file__).resolve().parents[3] / "detector" / "src" / "kitsune_detector" / "data" / "prevalence_prior.json"
)
_FACTORS: tuple[tuple[str, str | None], ...] = (("gpu", "plat"), ("screen", "plat"), ("cores", None))


def _tvd(p: dict[str, float], q: dict[str, float]) -> float:
    keys = set(p) | set(q)
    return 0.5 * sum(abs(p.get(k, 0.0) - q.get(k, 0.0)) for k in keys)


def _sample_fpgen(n: int) -> list[dict[str, Any]]:  # pragma: no cover - external data/network
    """Sample n fpgen fingerprints (natural distribution) and extract prevalence features through the shared mapper."""
    import fpgen

    feats: list[dict[str, Any]] = []
    for _ in range(n):
        fp = fpgen.generate()
        shaped = {
            "navigator": fp.get("navigator", {}),
            "screen": fp.get("screen", {}),
            "videoCard": {"renderer": fp.get("gpu", {}).get("renderer", "")},
        }
        feats.append(features_from_fingerprint(shaped))
    return feats


def _conditional(feats: list[dict[str, Any]], field: str, given: str | None) -> dict[str, dict[str, float]]:
    counts: dict[str, collections.Counter[str]] = collections.defaultdict(collections.Counter)
    for f in feats:
        key = str(f.get(given)) if given else "_"
        counts[key][str(f.get(field))] += 1
    return {k: {v: c / sum(cnt.values()) for v, c in cnt.items()} for k, cnt in counts.items()}


def corroborate(feats: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Compare fpgen's conditional distributions to the committed browserforge prior; return per-cell TVD rows."""
    bf = json.loads(_PRIOR_PATH.read_text())["prior"]
    rows: list[dict[str, Any]] = []
    for field, given in _FACTORS:
        fg = _conditional(feats, field, given)
        counts = collections.Counter(str(f.get(given)) if given else "_" for f in feats)
        for key in sorted(set(fg) | set(bf.get(field, {}))):
            bfd, fgd = bf.get(field, {}).get(key, {}), fg.get(key, {})
            rows.append(
                {
                    "factor": field,
                    "given": key,
                    "n_fpgen": counts.get(key, 0),
                    "tvd": _tvd(bfd, fgd) if (bfd and fgd) else None,
                    "note": "" if (bfd and fgd) else f"uncomparable (bf={bool(bfd)} fpgen={bool(fgd)})",
                }
            )
    return rows


def render(rows: list[dict[str, Any]]) -> str:
    out = ["# Prevalence prior corroboration — browserforge vs fpgen (Scrapfly data)", ""]
    out.append("TVD: 0 = identical, 1 = disjoint. HIGH = data-idiosyncratic (trust less); low-n = noisy.")
    out.append("")
    out.append("| factor | condition | n (fpgen) | TVD | flag |")
    out.append("|---|---|---|---|---|")
    for r in rows:
        if r["tvd"] is None:
            flag = r["note"]
            tvd = "—"
        else:
            tvd = f"{r['tvd']:.2f}"
            flag = "HIGH" if r["tvd"] > _HIGH_TVD else ("low-n" if r["n_fpgen"] < _MIN_N else "ok")
        out.append(f"| {r['factor']} | {r['given']} | {r['n_fpgen']} | {tvd} | {flag} |")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> None:  # pragma: no cover - thin CLI over external data
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--n", type=int, default=500, help="number of fpgen fingerprints to sample")
    args = ap.parse_args(argv)
    print(render(corroborate(_sample_fpgen(args.n))))


if __name__ == "__main__":  # pragma: no cover
    main()
