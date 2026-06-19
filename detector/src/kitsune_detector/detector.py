# detector/detector — the Detector facade: ingest, score, emit verdicts.
# Wires the coherence engine + scoring behind a small stateless surface.

"""The Detector facade — ingest signals, score sessions, emit verdicts.

Ties the pieces together (coherence engine + scoring) behind a small surface the harness and the
HTTP app both use. Stateless: persistence is the store's job, not the detector's.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

from . import applicability, prevalence, scoring
from .coherence import CoherenceEngine, RuleSet, load_registry
from .config import SCHEMA_VERSION
from .ingest import group_signals
from .ip_reputation import IPReputation
from .models import MISSING, Layer, Session, Signal, Source, Verdict

Clock = Callable[[], datetime]


def _utcnow() -> datetime:
    return datetime.now(UTC)


class Detector:
    def __init__(
        self,
        ruleset: RuleSet | None = None,
        *,
        clock: Clock = _utcnow,
        ip_reputation: IPReputation | None = None,
    ) -> None:
        self._ruleset = ruleset or load_registry()
        self._engine = CoherenceEngine(self._ruleset)
        self._clock = clock
        self._iprep = ip_reputation or IPReputation.from_seed()

    @property
    def ruleset_version(self) -> str:
        return self._ruleset.ruleset_version

    def _with_derived(self, session: Session) -> Session:
        """Add score-time derived signals (not persisted). Two enrichments: (1) a network fingerprint with
        an empty browser layer loaded the challenge page yet never ran JS — a scripted/non-browser client,
        emitted as ``network.browser_absent``; (2) IP reputation — the observed source IP classified against
        curated datacenter/proxy CIDR lists, emitted as ``reputation.asn_is_datacenter`` / ``is_proxy_exit``
        so the rep.* rules fire. Both feed the engine like any other tell."""

        def mk(layer: Layer, kind: str, value: object) -> Signal:
            return Signal(
                schema_version=SCHEMA_VERSION,
                session_id=session.session_id,
                layer=layer,
                kind=kind,
                value=value,
                source=Source.detector,
                observed_at=session.last_seen,
            )

        net_add: list[Signal] = []
        rep_add: list[Signal] = []
        browser_add: list[Signal] = []
        if session.signals.network and not session.signals.browser:
            net_add.append(mk(Layer.network, kind="browser_absent", value=True))
        # Prevalence: a coherent fingerprint whose platform/gpu/screen/colour/cores joint is deep in the
        # improbable tail of the real-traffic prior (the randomizer attack no coherence rule catches).
        if session.signals.browser and prevalence.is_improbable(session):
            browser_add.append(mk(Layer.browser, kind="prevalence_low", value=True))
        ip = session.value(Layer.network, "observed_ip")
        if ip is not MISSING:
            is_dc, is_px = self._iprep.classify(str(ip))
            if is_dc:
                rep_add.append(mk(Layer.reputation, kind="asn_is_datacenter", value=True))
            if is_px:
                rep_add.append(mk(Layer.reputation, kind="is_proxy_exit", value=True))
        if not net_add and not rep_add and not browser_add:
            return session
        update: dict[str, list[Signal]] = {}
        if net_add:
            update["network"] = [*session.signals.network, *net_add]
        if rep_add:
            update["reputation"] = [*session.signals.reputation, *rep_add]
        if browser_add:
            update["browser"] = [*session.signals.browser, *browser_add]
        return session.model_copy(update={"signals": session.signals.model_copy(update=update)})

    def score(self, session: Session) -> Verdict:
        """Score one correlated session into an explainable verdict."""
        session = self._with_derived(session)
        contradictions = self._engine.evaluate(session)
        # Per-browser applicability: drop tells that are a BY-DESIGN feature of the identified browser (e.g.
        # Brave's canvas/audio farbling) so a real browser is not convicted on them. Mirrors the live page.
        contradictions = applicability.filter_applicable(contradictions, session)
        score = scoring.final_score(contradictions)
        return Verdict(
            schema_version=SCHEMA_VERSION,
            session_id=session.session_id,
            layer_scores=scoring.layer_scores(contradictions),
            contradictions=contradictions,
            incoherence_score=scoring.incoherence_score(contradictions),
            score=score,
            label=scoring.label_for(score, contradictions),
            ruleset_version=self._ruleset.ruleset_version,
            scored_at=self._clock(),
        )

    def ingest_and_score(self, signals: list[Signal]) -> list[Verdict]:
        """Group a flat signal stream into sessions and score each one."""
        return [self.score(session) for session in group_signals(signals)]
