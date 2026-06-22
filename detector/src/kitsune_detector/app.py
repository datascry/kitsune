# detector/app — FastAPI HTTP boundary (the spine's /ingest).
# Correlates posted signals, scores, persists, returns verdicts; injectable for tests.

"""FastAPI app — the detector's HTTP boundary (the spine's ``/ingest``).

The edge and collector POST contract-valid ``Signal`` envelopes here; the detector correlates,
scores, persists, and returns verdicts. ``create_app`` takes injectable ``Detector``/``Store`` so
the whole surface is testable in-memory with no network.
"""

from __future__ import annotations

import hmac
import os

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse

from .demo import DEMO_PAGE
from .detector import Detector
from .models import Session, Signal, Verdict
from .store import Store


def create_app(
    detector: Detector | None = None,
    store: Store | None = None,
    admin_token: str | None = None,
) -> FastAPI:
    detector = detector or Detector()
    store = store or Store(":memory:")
    # The inspection endpoints (/session, /verdict, /scoreboard) expose raw signals — including the
    # client IP — and the full verdict store. On a public host that is operator-data exposure, so when
    # KITSUNE_ADMIN_TOKEN is set they require an `Authorization: Bearer <token>` header and the
    # interactive API docs are hidden. Unset (dev/tests) leaves them open. An explicit admin_token
    # argument overrides the env (used in tests). An empty value counts as unset.
    admin_token = admin_token if admin_token is not None else os.environ.get("KITSUNE_ADMIN_TOKEN")

    def require_admin(authorization: str | None = Header(default=None)) -> None:
        if not admin_token:
            return  # gating disabled — no token configured
        expected = f"Bearer {admin_token}"
        if authorization is None or not hmac.compare_digest(authorization, expected):
            raise HTTPException(status_code=401, detail="admin token required")

    # Hide /docs + /redoc + /openapi.json on a token-hardened (public) deployment.
    if admin_token:
        app = FastAPI(
            title="Kitsune Detector",
            version="0.1.0",
            docs_url=None,
            redoc_url=None,
            openapi_url=None,
        )
    else:
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

    @app.get(
        "/session/{session_id}",
        response_model=Session,
        dependencies=[Depends(require_admin)],
    )
    def get_session(session_id: str) -> Session:
        # Inspect a correlated session's raw signals (e.g. to read the captured JA4).
        session = store.get_session(session_id)
        if session is None:
            raise HTTPException(status_code=404, detail="no session")
        return session

    @app.get(
        "/verdict/{session_id}",
        response_model=Verdict,
        dependencies=[Depends(require_admin)],
    )
    def get_verdict(session_id: str) -> Verdict:
        verdict = store.get_verdict(session_id)
        if verdict is None:
            raise HTTPException(status_code=404, detail="no verdict for session")
        return verdict

    @app.get(
        "/scoreboard",
        response_model=list[Verdict],
        dependencies=[Depends(require_admin)],
    )
    def scoreboard() -> list[Verdict]:
        return store.list_verdicts()

    return app
