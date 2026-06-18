# detector/app — FastAPI HTTP boundary (the spine's /ingest).
# Correlates posted signals, scores, persists, returns verdicts; injectable for tests.

"""FastAPI app — the detector's HTTP boundary (the spine's ``/ingest``).

The edge and collector POST contract-valid ``Signal`` envelopes here; the detector correlates,
scores, persists, and returns verdicts. ``create_app`` takes injectable ``Detector``/``Store`` so
the whole surface is testable in-memory with no network.
"""

from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse

from .detector import Detector
from .demo import DEMO_PAGE
from .models import Session, Signal, Verdict
from .store import Store


def create_app(detector: Detector | None = None, store: Store | None = None) -> FastAPI:
    detector = detector or Detector()
    store = store or Store(":memory:")
    app = FastAPI(title="Kitsune Detector", version="0.1.0")

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        # Served (via the edge) to a real browser; the inline collector posts signals to /ingest.
        return DEMO_PAGE

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok", "ruleset_version": detector.ruleset_version}

    @app.post("/ingest", response_model=list[Verdict])
    def ingest(signals: list[Signal]) -> list[Verdict]:
        from .ingest import group_signals, merge_sessions

        verdicts: list[Verdict] = []
        for session in group_signals(signals):
            existing = store.get_session(session.session_id)
            merged = merge_sessions(existing, session) if existing else session
            store.save_session(merged)
            verdict = detector.score(merged)
            store.save_verdict(verdict)
            verdicts.append(verdict)
        return verdicts

    @app.get("/session/{session_id}", response_model=Session)
    def get_session(session_id: str) -> Session:
        # Inspect a correlated session's raw signals (e.g. to read the captured JA4).
        session = store.get_session(session_id)
        if session is None:
            raise HTTPException(status_code=404, detail="no session")
        return session

    @app.get("/verdict/{session_id}", response_model=Verdict)
    def get_verdict(session_id: str) -> Verdict:
        verdict = store.get_verdict(session_id)
        if verdict is None:
            raise HTTPException(status_code=404, detail="no verdict for session")
        return verdict

    @app.get("/scoreboard", response_model=list[Verdict])
    def scoreboard() -> list[Verdict]:
        return store.list_verdicts()

    return app
