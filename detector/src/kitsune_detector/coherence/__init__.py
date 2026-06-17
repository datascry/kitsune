# detector/coherence — the data-driven coherence engine (package).
# Re-exports CoherenceEngine, CoherenceRule, RuleSet, load_registry.

"""The coherence engine: a generic evaluator over data-driven rules."""

from .engine import CoherenceEngine
from .rules import CoherenceRule, RuleSet, load_registry

__all__ = ["CoherenceEngine", "CoherenceRule", "RuleSet", "load_registry"]
