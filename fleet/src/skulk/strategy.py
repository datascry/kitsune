# fleet/skulk/strategy — the Strategy plugin contract + registry that makes fleet shapes pluggable.
# A strategy turns (n, seed) into N coordination-shaped FleetMembers; register() adds it to the catalog.

from __future__ import annotations

from typing import Protocol, runtime_checkable

from .model import FleetMember


@runtime_checkable
class Strategy(Protocol):
    """A fleet shape. ``name`` is the CLI key, ``summary`` the one-line description, ``members`` the generator
    (deterministic in ``seed`` so a run is reproducible and a fixture is stable)."""

    name: str
    summary: str

    def members(self, n: int, seed: int) -> list[FleetMember]: ...


_REGISTRY: dict[str, Strategy] = {}


def register(cls: type) -> type:
    """Class decorator: instantiate the strategy and add it to the registry under its ``name``."""
    inst = cls()
    _REGISTRY[inst.name] = inst
    return cls


def get(name: str) -> Strategy:
    try:
        return _REGISTRY[name]
    except KeyError:
        raise KeyError(f"unknown strategy {name!r}; available: {', '.join(sorted(_REGISTRY))}") from None


def all_strategies() -> list[Strategy]:
    return [_REGISTRY[k] for k in sorted(_REGISTRY)]
