# fleet/skulk — Skulk: fleet adversary-emulation for testing bot-detection coordination defenses.
# Public API: Scope (authorization), the strategy registry, run(); authorized targets only.

from __future__ import annotations

from . import strategies  # noqa: F401 - register the built-in strategies on import
from .grade import Assessment, assess
from .model import FleetMember
from .runner import RunResult, run
from .scope import AuthorizationError, Scope
from .strategy import Strategy, all_strategies, get, register

__all__ = [
    "Assessment",
    "AuthorizationError",
    "FleetMember",
    "RunResult",
    "Scope",
    "Strategy",
    "all_strategies",
    "assess",
    "get",
    "register",
    "run",
]
