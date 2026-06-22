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
        # CSS⇄JS channel coherence (S1, docs/detection-landscape.md): the no-JS CSS @media beacon
        # (css_any_pointer_coarse, sent by the rendering engine) and the JS-reported js_touch describe the SAME
        # touch capability. On a real browser they always agree; they can only disagree when a spoof patches the
        # JS side (maxTouchPoints / a matchMedia hook) but cannot redirect the engine's CSS beacon fetch. Derived
        # detector-side because the CSS value arrives on a separate (server-side) channel the JS collector never
        # sees. Inert until the convicting rule lands — which is gated on headful real-browser FP-validation
        # (the browserforge calibration gate cannot exercise this, having no CSS channel).
        css_coarse = session.value(Layer.browser, "css_any_pointer_coarse")
        js_touch = session.value(Layer.browser, "js_touch")
        if css_coarse is not MISSING and js_touch is not MISSING and bool(css_coarse) != bool(js_touch):
            browser_add.append(mk(Layer.browser, kind="css_pointer_vs_js_incoherent", value=True))
        ip = session.value(Layer.network, "observed_ip")
        observed_is_dc: bool | None = None
        if ip is not MISSING:
            is_dc, is_px = self._iprep.classify(str(ip))
            observed_is_dc = is_dc
            if is_dc:
                rep_add.append(mk(Layer.reputation, kind="asn_is_datacenter", value=True))
            if is_px:
                rep_add.append(mk(Layer.reputation, kind="is_proxy_exit", value=True))
        # The WebRTC-leaked origin is the REAL machine running the browser (vs observed_ip = the proxy a bot
        # hides behind). A cloud bot behind a residential proxy has a clean observed_ip but leaks its DATACENTER
        # origin via WebRTC; a real user's machine is residential (a VPN user leaks their residential home IP).
        # So classify the leaked origin: a datacenter WebRTC origin is the cloud-bot-behind-residential-proxy
        # tell the observed_ip rules miss. (Corroborating — cloud-desktop/remote-browser users are a rare FP.)
        webrtc_ip = session.value(Layer.browser, "webrtc_public_ip")
        if webrtc_ip is not MISSING:
            wr_dc, _ = self._iprep.classify(str(webrtc_ip))
            if wr_dc:
                rep_add.append(mk(Layer.reputation, kind="webrtc_origin_datacenter", value=True))
                # Cross-layer contradiction: the real machine is in a datacenter (WebRTC origin) but it connects
                # through a NON-datacenter (residential) IP — a datacenter machine HIDDEN behind a residential
                # proxy, the dominant commercial-scraping pattern (cloud VM + residential proxy) that evades
                # observed_ip reputation. FP-safe to convict: a real cloud-desktop user connects FROM the
                # datacenter (observed_ip is datacenter too → not this), so only a hiding bot matches.
                if observed_is_dc is False:
                    net_add.append(mk(Layer.network, kind="datacenter_origin_proxied", value=True))
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
