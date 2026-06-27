# fleet/skulk/grade — Skulk's own minimal collision assessment: is this fleet catchable by EXACT-hash matching?
# Educational self-check (no target-detector import) — shows cloned/trace convict, fuzzy/randomizer evade.

"""A standalone, exact-match collision assessor.

Skulk's job is to EMIT fleet shapes; grading whether a target convicts them is the target detector's job (for
Kitsune: ``task coordination-live``). But for education and for a fast self-check, Skulk computes its own
verdict on the generated members: does a high-entropy ``fp_hash`` or ``trace_hash`` repeat across >=2 DISTINCT
source IPs? That is the exact-match collision a saturated per-session detector convicts. It deliberately models
ONLY exact matching — so it reports ``cloned``/``trace-replay`` as *detectable* and ``fuzzy``/``randomizer`` as
*evades exact-match*, making the template-similarity frontier (the next blue rung) concrete.
"""

from __future__ import annotations

from dataclasses import dataclass

from .model import FleetMember


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
    # No exact collision: a paradox/fuzzy fleet — one JA4 + distinct fingerprints. Caps at candidate today.
    ja4s = {m.ja4 for m in members}
    ips = {m.observed_ip for m in members}
    return Assessment(
        False,
        "none",
        f"shared JA4 ({len(ja4s)} variant) over {len(ips)} IPs but NO identical fp/trace — evades exact-match; "
        f"needs template-SIMILARITY clustering (the frontier blue rung)",
    )
