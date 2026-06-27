# harness/archetypes — named adversary personas the fleet emulates (credential-stuffer / scalper / scraper / …).
# Each packages a fleet SHAPE (evasions + replicas + behavioral task) + the coordination binding it exhibits.

"""A catalog of adversary archetypes.

The lab has the building blocks — named evasions, behavioral tasks, coordination shapes — but composing them
into a realistic adversary meant knowing which combination models which threat. An :class:`Archetype` packages
that knowledge: a named persona (the threat class it models, the fleet shape it runs, the coordination binding
it exhibits, and its rate/scale profile), so an engagement says ``--archetype credential-stuffer`` and gets a
ready fleet plan. The personas map to the real threat classes (account fraud, scalping, distributed scraping,
multi-accounting/sybil) — and to the HONEST blue outcome: a same-tool fleet collides on its fingerprint and is
``caught``, while a deliberately diversified sybil farm has no shared binding and correctly caps at ``candidate``.

The ``rate`` field is an informational scale/RPS profile today — active rate (RPS) scoping is the recon
dimension that probes the target's throttle/challenge thresholds; this catalog sets it up but does not drive it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ArchetypeNode:
    """One node type in an archetype's fleet: a named evasion, a replica count, an optional behavioral task."""

    evasion: str
    replicas: int
    task: str | None = None


@dataclass(frozen=True)
class Archetype:
    """A named adversary persona and the fleet it runs."""

    name: str
    threat: str  # the threat class: account-fraud / scalping / scraping / sybil
    summary: str
    nodes: list[ArchetypeNode]
    binding: str  # the coordination binding it exhibits (fp_collision / none / …)
    expected: str  # the honest blue outcome: "caught" | "candidate"
    rate: str  # informational scale/RPS profile (active RPS scoping is the recon dimension, not driven here)

    def to_plan_obj(self, **overrides: Any) -> dict[str, Any]:
        """A ``plan_from_obj``-shaped dict (so the fleet manager builds it without importing this module)."""
        nodes = [
            {"evasion": n.evasion, "replicas": n.replicas, **({"task": n.task} if n.task else {})} for n in self.nodes
        ]
        return {"name": self.name, "nodes": nodes, **overrides}


_REGISTRY: dict[str, Archetype] = {}


def _reg(a: Archetype) -> None:
    _REGISTRY[a.name] = a


_reg(
    Archetype(
        name="credential-stuffer",
        threat="account-fraud",
        summary="one cloned hardened profile fanned across nodes, replaying a login form — credential stuffing",
        nodes=[ArchetypeNode("camoufox-hardened", 3, task="form-fill")],
        binding="fp_collision",
        expected="caught",
        rate="burst — many login attempts in a short window",
    )
)
_reg(
    Archetype(
        name="scalper",
        threat="scalping",
        summary="a cloned checkout fleet hammering a limited drop (sneaker/ticket/GPU) the instant it opens",
        nodes=[ArchetypeNode("zendriver-uach", 4, task="browse")],
        binding="fp_collision",
        expected="caught",
        rate="spike at drop time — maximal RPS for a few seconds",
    )
)
_reg(
    Archetype(
        name="scraper",
        threat="scraping",
        summary="a distributed crawler fleet scrolling long pages — same tool across nodes, sustained",
        nodes=[ArchetypeNode("zendriver-uach", 3, task="scrape-scroll")],
        binding="fp_collision",
        expected="caught",
        rate="sustained moderate — steady page fetches per node",
    )
)
_reg(
    Archetype(
        name="sybil-farmer",
        threat="sybil",
        summary="multi-accounting: DIVERSE evasions per node (no shared fingerprint) to look like distinct users",
        nodes=[
            ArchetypeNode("camoufox-linux", 1),
            ArchetypeNode("zendriver-uach", 1),
            ArchetypeNode("nodriver", 1),
        ],
        binding="none",
        expected="candidate",
        rate="low and slow — a few accounts, spread over time, to avoid scale tells",
    )
)
_reg(
    Archetype(
        name="proxy-botnet",
        threat="account-fraud",
        summary="diverse fingerprints behind residential proxies fronting ONE origin — needs --proxy egress",
        nodes=[
            ArchetypeNode("camoufox-linux", 2),
            ArchetypeNode("zendriver-uach", 2),
        ],
        binding="shared_origin",
        expected="caught (with real proxy egress + WebRTC leak)",
        rate="distributed — one origin, many proxy IPs, to defeat IP/ASN rate-limiting",
    )
)


def get(name: str) -> Archetype:
    try:
        return _REGISTRY[name]
    except KeyError:
        raise KeyError(f"unknown archetype {name!r}; known: {', '.join(sorted(_REGISTRY))}") from None


def all_archetypes() -> list[Archetype]:
    return sorted(_REGISTRY.values(), key=lambda a: a.name)
