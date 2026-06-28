#!/usr/bin/env python
# harness/tools/adversary_showcase — the red⇄blue escalation ladder through BOTH coordination scorers.
# Emits canonical fleet shapes to the live detector, then grades each via score_corpus (per-binding) + axis A.

"""Adversary showcase: the coordination red⇄blue picture end-to-end, in one reproducible run.

Emits four canonical fleet shapes to a live detector's ``/ingest`` (the wire contract, no evader containers
needed — fast + deterministic), then grades each through BOTH coordination scorers and prints the escalation
ladder: as a fleet diversifies, the pairwise-binding scorer falls first, then the aggregate (axis A) campaign
detector catches the residual correlation, and only a FULLY diversified fleet evades both — at which point it is,
by construction, N independent real users (the economic bind).

Shapes (each N nodes across N distinct origins):
  * cloned          — one fingerprint cloned fleet-wide          -> per-binding FLEET (fp_collision)
  * trace-replay    — one canned pointer trace replayed          -> per-binding FLEET (trace_collision)
  * diffuse-campaign— distinct fp/trace, descriptors tuned just ABOVE the template floor, shared build, lockstep
                       -> per-binding CANDIDATE (evades), axis A CAMPAIGN (caught)
  * diversified     — distinct build/fp/trace, spread descriptors, spread arrivals -> evades BOTH (the frontier)

Run:  task adversary-showcase -- --detector http://localhost:8099   (or: python tools/adversary_showcase.py)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import urllib.request
from datetime import UTC, datetime, timedelta

from kitsune_harness.coordination import score_campaigns, score_corpus
from kitsune_harness.live_coordination import fetch_live_corpus

_BASE_TS = datetime(2026, 6, 28, 12, 0, 0, tzinfo=UTC)
_HUMANIZER = (0.22, 0.60, 0.10, 0.20, 0.30, 0.70)


def _h(*p: object) -> str:
    return hashlib.sha256("|".join(str(x) for x in p).encode()).hexdigest()[:16]


def _sig(sid: str, layer: str, kind: str, value: object, when: str, src: str = "edge") -> dict[str, object]:
    return {
        "schema_version": "0.1",
        "session_id": sid,
        "layer": layer,
        "kind": kind,
        "value": value,
        "source": src,
        "observed_at": when,
    }


def _post(detector: str, sigs: list[dict[str, object]]) -> None:
    req = urllib.request.Request(
        detector.rstrip("/") + "/ingest",
        data=json.dumps(sigs).encode(),
        headers={"content-type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        resp.read()


def _descriptor(i: int, d: float) -> list[float]:
    # Deterministic per-node descriptor: offset ONE distinct component of the humanizer base by ``d``. Two nodes
    # then differ in two components by ``d`` each, so EVERY pairwise distance is exactly d*sqrt(2) — no boundary
    # jitter. d=0.085 -> 0.12 (tight: above the 0.10 template floor, within axis A's 0.15 soft eps); d=0.30 ->
    # 0.42 (spread, beyond the soft eps). Robust + reproducible regardless of store state.
    out = list(_HUMANIZER)
    out[i % len(out)] = min(1.0, out[i % len(out)] + d)
    return out


def _emit(detector: str, shape: str, n: int = 4) -> list[str]:
    """Emit one fleet shape; return its session ids. Each node lands on a distinct source IP."""
    sids = []
    ja4 = "t13d1516h2_" + _h("ja4", shape)[:12] + "_" + _h("ext", shape)[:12]
    cloned_fp = _h("clonedfp", shape)
    canned_trace = _h("cannedtrace", shape)
    for i in range(n):
        sid = f"showcase-{shape}-{i}"
        sids.append(sid)
        # arrivals: lockstep for coordinated shapes; SPREAD (>120s window) for the staggered + diversified shapes
        # — the timing diversification lever that drops axis A's lockstep dimension.
        spread = shape in ("diffuse-staggered", "diversified")
        when = (_BASE_TS + timedelta(seconds=(i * 600 if spread else i))).strftime("%Y-%m-%dT%H:%M:%SZ")
        node_ja4 = (
            ("t13d" + _h("rot", shape, i)[:4] + "h2_" + _h("rj", shape, i)[:12]) if shape == "diversified" else ja4
        )
        sigs = [
            _sig(sid, "network", "ja4", node_ja4, when),
            _sig(sid, "network", "observed_ip", f"203.0.{i + 1}.{i + 7}", when),
        ]
        if shape == "cloned":
            sigs.append(_sig(sid, "browser", "fp_hash", cloned_fp, when, "collector"))
            sigs.append(_sig(sid, "browser", "webdriver", True, when, "collector"))  # a cloned bot fleet is automated
        elif shape == "trace-replay":
            sigs.append(_sig(sid, "browser", "fp_hash", _h("fp", shape, i), when, "collector"))
            sigs.append(_sig(sid, "behavioral", "trace_hash", canned_trace, when, "collector"))
        elif shape in ("diffuse-campaign", "diffuse-staggered"):
            # diffuse-staggered = diffuse-campaign with ONLY arrival timing changed — isolates the stagger lever.
            sigs.append(_sig(sid, "browser", "fp_hash", _h("fp", shape, i), when, "collector"))
            sigs.append(_sig(sid, "behavioral", "trace_hash", _h("tr", shape, i), when, "collector"))
            sigs.append(_sig(sid, "behavioral", "trace_descriptor", _descriptor(i, 0.085), when, "collector"))
        else:  # diversified — distinct everything, spread descriptors, spread arrivals
            sigs.append(_sig(sid, "browser", "fp_hash", _h("fp", shape, i), when, "collector"))
            sigs.append(_sig(sid, "behavioral", "trace_hash", _h("tr", shape, i), when, "collector"))
            sigs.append(_sig(sid, "behavioral", "trace_descriptor", _descriptor(i, 0.30), when, "collector"))
        _post(detector, sigs)
    return sids


def _grade(detector: str, sids: set[str]) -> tuple[str, str]:
    """Return (per-binding label, axis-A label) graded over JUST this shape's sessions — isolating the verdict
    from whatever else is in the live store, so the showcase is deterministic regardless of accumulated state."""
    corpus = [(n, s) for n, s in fetch_live_corpus(detector) if n in sids]
    pb = next((v.label for v in score_corpus(corpus) if sids & set(v.members)), "—")
    ax = next((c.label for c in score_campaigns(corpus) if sids & set(c.members)), "—")
    return pb, ax


def main() -> None:
    ap = argparse.ArgumentParser(description="Coordination red⇄blue escalation showcase")
    ap.add_argument("--detector", default="http://localhost:8099")
    ap.add_argument("--n", type=int, default=4)
    args = ap.parse_args()

    rows = []
    for shape in ("cloned", "trace-replay", "diffuse-campaign", "diffuse-staggered", "diversified"):
        sids = set(_emit(args.detector, shape, args.n))
        pb, ax = _grade(args.detector, sids)
        rows.append((shape, pb, ax))

    w = max(len(s) for s, _, _ in rows)
    print(f"\n  {'fleet shape'.ljust(w)}   per-binding (score_corpus)   axis A (score_campaigns)")
    print(f"  {'-' * w}   {'-' * 26}   {'-' * 24}")
    for shape, pb, ax in rows:
        print(f"  {shape.ljust(w)}   {pb.upper().ljust(26)}   {ax.upper()}")
    print(
        "\n  Ladder: pairwise bindings fall first (cloned/replay -> FLEET); a build-rotating-but-tuned humanizer\n"
        "  evades them yet axis A catches the aggregate correlation (diffuse-campaign -> CAMPAIGN); only a fully\n"
        "  diversified fleet (distinct build/fp/trace, spread descriptors, spread arrivals) evades BOTH — at which\n"
        "  point it is N independent real users (the economic bind; conviction there is external-data-bound).\n"
    )


if __name__ == "__main__":
    main()
