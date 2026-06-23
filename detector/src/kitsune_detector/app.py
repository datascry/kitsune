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
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse, Response

from .demo import DEMO_PAGE
from .detector import Detector
from .models import Session, Signal, Verdict
from .store import Store

#: Canonical public origin — used for robots/sitemap absolute URLs and the page's canonical/OG tags.
SITE_ORIGIN = "https://kitsune.id"
#: Static brand assets (favicon set, OG card, web manifest), served at the URL root.
STATIC_DIR = Path(__file__).parent / "static"


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
        # The CSP is permissive for everything the collector uses (default-src *) but restricts images to
        # same-origin (img-src 'self') — which lets the favicon load while STILL blocking the collector's
        # csp_bypassed probe, whose bait is a `data:` image (data: is not 'self', so it's blocked). A real
        # browser fires a securitypolicyviolation on the blocked data: image; an automation context that
        # called setBypassCSP(true) to inject scripts silently disables enforcement, so the violation never
        # fires — a tell rebrowser-patches explicitly does not fix. See br.csp_bypassed.
        resp = HTMLResponse(DEMO_PAGE)
        resp.headers["Content-Security-Policy"] = (
            "default-src * data: blob: 'unsafe-inline' 'unsafe-eval'; img-src 'self'"
        )
        return resp

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok", "ruleset_version": detector.ruleset_version}

    # --- Static brand assets + crawl/SEO infra (public, off the OpenAPI schema) ---
    def _asset(name: str, media_type: str) -> FileResponse:
        return FileResponse(
            STATIC_DIR / name,
            media_type=media_type,
            headers={"Cache-Control": "public, max-age=86400"},
        )

    @app.get("/favicon.ico", include_in_schema=False)
    def favicon_ico() -> FileResponse:
        return _asset("favicon.ico", "image/x-icon")

    @app.get("/favicon.svg", include_in_schema=False)
    def favicon_svg() -> FileResponse:
        return _asset("favicon.svg", "image/svg+xml")

    @app.get("/favicon-32.png", include_in_schema=False)
    def favicon_png() -> FileResponse:
        return _asset("favicon-32.png", "image/png")

    @app.get("/apple-touch-icon.png", include_in_schema=False)
    def apple_touch_icon() -> FileResponse:
        return _asset("apple-touch-icon.png", "image/png")

    @app.get("/icon-512.png", include_in_schema=False)
    def icon_512() -> FileResponse:
        return _asset("icon-512.png", "image/png")

    @app.get("/og.png", include_in_schema=False)
    def og_png() -> FileResponse:
        return _asset("og.png", "image/png")

    @app.get("/site.webmanifest", include_in_schema=False)
    def site_webmanifest() -> FileResponse:
        return _asset("site.webmanifest", "application/manifest+json")

    @app.get("/robots.txt", include_in_schema=False)
    def robots() -> PlainTextResponse:
        return PlainTextResponse(f"User-agent: *\nAllow: /\nSitemap: {SITE_ORIGIN}/sitemap.xml\n")

    @app.get("/sitemap.xml", include_in_schema=False)
    def sitemap() -> Response:
        # Public routes only; the doc pages (/matrix, /evasions, …) are added in a later phase.
        urls = ["/"]
        locs = "".join(f"<url><loc>{SITE_ORIGIN}{u}</loc></url>" for u in urls)
        xml = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
            f"{locs}</urlset>"
        )
        return Response(content=xml, media_type="application/xml")

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
