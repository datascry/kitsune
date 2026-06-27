# fleet/skulk/grade — Skulk's own minimal collision assessment: is this fleet catchable by EXACT-hash matching?
# Educational self-check (no target-detector import) — shows cloned/trace convict, fuzzy/randomizer evade.

"""A standalone collision + similarity assessor.

Skulk's job is to EMIT fleet shapes; grading whether a target convicts them is the target detector's job (for
Kitsune: ``task coordination-live``). But for education and for a fast self-check, Skulk computes its own
verdict on the generated members in two passes:

1. **Exact match** — does a high-entropy ``fp_hash`` or ``trace_hash`` repeat across >=2 DISTINCT source IPs?
   That is the exact-match collision a saturated per-session detector convicts (``cloned`` / ``trace-replay``).
2. **Template similarity** — failing an exact match, do the pointer-trace DESCRIPTORS cluster below the human
   floor across >=2 distinct IPs? That catches the evolved ``similarity`` fleet (one humanizer sampled per node)
   even though every ``trace_hash`` differs — the frontier rung exact matching alone misses.

``randomizer`` and ``fuzzy`` carry no clustering descriptor, so they report *evades* — the gap a profiled
``similarity`` fleet (which DOES emit descriptors) no longer enjoys.
"""

from __future__ import annotations

import itertools
import math
import statistics
from dataclasses import dataclass

from .model import FleetMember

# The human floor, mirrored from harness ``coordination._TEMPLATE_EPSILON`` (grounded in template_calibration).
_TEMPLATE_EPSILON = 0.10


@dataclass
class Assessment:
    detectable: bool  # would an exact-hash coordination scorer catch this fleet?
    signal: str  # which collision (fp / trace / none)
    detail: str


def assess(members: list[FleetMember]) -> Assessment:
    """Exact-match self-assessment of an emitted fleet."""
    for kind, attr in (("fp_hash", "fp_hash"), ("trace_hash", "trace_hash")):
        by_value: dict[str, set[str]] = {}
        for m in members:
            v = getattr(m, attr)
            if v is None:
                continue
            by_value.setdefault(str(v), set()).add(m.observed_ip)
        for value, ips in by_value.items():
            if len(ips) >= 2:
                return Assessment(
                    True,
                    kind,
                    f"identical {kind} `{value}` across {len(ips)} distinct IPs — exact-match collision (convicts)",
                )
    # No exact collision — try template similarity: pointer-trace descriptors that cluster below the human
    # floor across >= 2 distinct IPs are one humanizer model sampled per node (the `similarity` fleet).
    descns = [(m.trace_descriptor, m.observed_ip) for m in members if m.trace_descriptor is not None]
    if len(descns) >= 3 and len({ip for _, ip in descns}) >= 2:
        dists = [math.dist(a, b) for (a, _), (b, _) in itertools.combinations(descns, 2)]
        median = statistics.median(dists)
        if median <= _TEMPLATE_EPSILON:
            ip_count = len({ip for _, ip in descns})
            return Assessment(
                True,
                "template_similarity",
                f"trace descriptors cluster below the human floor (median {median:.3f} <= {_TEMPLATE_EPSILON}) "
                f"across {ip_count} distinct IPs — one humanizer model (convicts via template-similarity + corrob.)",
            )

    # No exact collision and no tight descriptor cluster: a paradox/fuzzy fleet — one JA4 + distinct
    # fingerprints, traces unprofiled. Caps at candidate today.
    ja4s = {m.ja4 for m in members}
    ips = {m.observed_ip for m in members}
    return Assessment(
        False,
        "none",
        f"shared JA4 ({len(ja4s)} variant) over {len(ips)} IPs but NO identical fp/trace and no clustering "
        f"descriptor — evades exact-match; needs template-SIMILARITY clustering (the frontier blue rung)",
    )
