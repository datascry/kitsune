# detector/app — FastAPI HTTP boundary (the spine's /ingest).
# Correlates posted signals, scores, persists, returns verdicts; injectable for tests.

"""FastAPI app — the detector's HTTP boundary (the spine's ``/ingest``).

The edge and collector POST contract-valid ``Signal`` envelopes here; the detector correlates,
scores, persists, and returns verdicts. ``create_app`` takes injectable ``Detector``/``Store`` so
the whole surface is testable in-memory with no network.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse

from .demo import DEMO_PAGE
from .detector import Detector
from .models import Layer, Session, Signal, Source, Verdict
from .store import Store

# CSS @media beacon channel (no-JS). A same-origin @font-face fetch the rendering ENGINE makes per matched
# media value — unspoofable by the JS matchMedia hooks that defeat br.pointer_touch_incoherent (see
# docs/detection-landscape.md S1). Correlated by the ks_sid cookie (auto-sent with the fetch); the value lands
# as a browser.css_* signal a coherence rule can cross-check against the JS-reported equivalent. font-src (not
# the demo's img-src 'none') governs @font-face, so the beacon survives the CSP. Allow-listed (key,value) ONLY
# — never an open signal sink.
_CSS_BEACON_VALUES: dict[str, dict[str, bool]] = {
    "any_pointer_coarse": {"0": False, "1": True},
}


def create_app(detector: Detector | None = None, store: Store | None = None) -> FastAPI:
    detector = detector or Detector()
    store = store or Store(":memory:")
    app = FastAPI(title="Kitsune Detector", version="0.1.0")

    @app.get("/", response_class=HTMLResponse)
    def index() -> HTMLResponse:
        # Served (via the edge) to a real browser; the inline collector posts signals to /ingest.
        # The CSP is permissive for everything the collector uses (default-src *) but forbids images
        # (no signal uses <img>), so the collector can probe whether CSP is actually enforced. A real
        # browser fires a securitypolicyviolation on the forbidden image; an automation context that
        # called setBypassCSP(true) to inject scripts silently disables enforcement — a tell that
        # rebrowser-patches explicitly does not fix. See br.csp_bypassed.
        resp = HTMLResponse(DEMO_PAGE)
        resp.headers["Content-Security-Policy"] = (
            "default-src * data: blob: 'unsafe-inline' 'unsafe-eval'; img-src 'none'"
        )
        return resp

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok", "ruleset_version": detector.ruleset_version}

    @app.get("/b/{key}/{value}")
    def css_beacon(key: str, value: str, request: Request) -> Response:
        # No-JS CSS beacon receiver: record the engine-reported media value as a browser.css_* signal,
        # correlated by the ks_sid cookie. Allow-listed (key,value) only, so this is never an open signal
        # sink; an unknown key/value or a cookieless fetch is silently dropped. The request IS the signal,
        # so the body is empty (204) — the browser doesn't need a real font back.
        sid = request.cookies.get("ks_sid")
        allowed = _CSS_BEACON_VALUES.get(key)
        if sid and allowed is not None and value in allowed:
            from .ingest import group_signals, merge_sessions

            sig = Signal(
                session_id=sid,
                layer=Layer.browser,
                kind=f"css_{key}",
                value=allowed[value],
                source=Source.collector,
                observed_at=datetime.now(UTC),
            )
            for session in group_signals([sig]):
                existing = store.get_session(session.session_id)
                merged = merge_sessions(existing, session) if existing else session
                store.save_session(merged)
        return Response(status_code=204)

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
