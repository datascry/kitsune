# detector/detector — the Detector facade: ingest, score, emit verdicts.
# Wires the coherence engine + scoring behind a small stateless surface.

"""The Detector facade — ingest signals, score sessions, emit verdicts.

Ties the pieces together (coherence engine + scoring) behind a small surface the harness and the
HTTP app both use. Stateless: persistence is the store's job, not the detector's.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

from . import scoring
from .coherence import CoherenceEngine, RuleSet, load_registry
from .config import SCHEMA_VERSION
from .ingest import group_signals
from .models import Layer, Session, Signal, Source, Verdict

Clock = Callable[[], datetime]


def _utcnow() -> datetime:
    return datetime.now(UTC)


class Detector:
    def __init__(self, ruleset: RuleSet | None = None, *, clock: Clock = _utcnow) -> None:
        self._ruleset = ruleset or load_registry()
        self._engine = CoherenceEngine(self._ruleset)
        self._clock = clock

    @property
    def ruleset_version(self) -> str:
        return self._ruleset.ruleset_version

    def _with_derived(self, session: Session) -> Session:
        """Add score-time derived signals (not persisted). A session with a network fingerprint but an
        empty browser layer loaded the challenge page yet never executed JS — a scripted/non-browser
        client (e.g. an HTTP flood). Emitted as a cross-layer ``network.browser_absent`` so the registry
        rule (and the incoherence amplifier) handle it like any other tell."""
        if session.signals.network and not session.signals.browser:
            marker = Signal(
                schema_version=SCHEMA_VERSION,
                session_id=session.session_id,
                layer=Layer.network,
                kind="browser_absent",
                value=True,
                source=Source.detector,
                observed_at=session.last_seen,
            )
            groups = session.signals.model_copy(update={"network": [*session.signals.network, marker]})
            return session.model_copy(update={"signals": groups})
        return session

    def score(self, session: Session) -> Verdict:
        """Score one correlated session into an explainable verdict."""
        session = self._with_derived(session)
        contradictions = self._engine.evaluate(session)
        score = scoring.final_score(contradictions)
        return Verdict(
            schema_version=SCHEMA_VERSION,
            session_id=session.session_id,
            layer_scores=scoring.layer_scores(contradictions),
            contradictions=contradictions,
            incoherence_score=scoring.incoherence_score(contradictions),
            score=score,
            label=scoring.label_for(score),
            ruleset_version=self._ruleset.ruleset_version,
            scored_at=self._clock(),
        )

    def ingest_and_score(self, signals: list[Signal]) -> list[Verdict]:
        """Group a flat signal stream into sessions and score each one."""
        return [self.score(session) for session in group_signals(signals)]
