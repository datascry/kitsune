# detector/app — FastAPI HTTP boundary (the spine's /ingest).
# Correlates posted signals, scores, persists, returns verdicts; injectable for tests.

"""FastAPI app — the detector's HTTP boundary (the spine's ``/ingest``).

The edge and collector POST contract-valid ``Signal`` envelopes here; the detector correlates,
scores, persists, and returns verdicts. ``create_app`` takes injectable ``Detector``/``Store`` so
the whole surface is testable in-memory with no network.
"""

from __future__ import annotations

import contextlib
import hmac
import html
import json
import os
import re
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
from fastapi import Cookie, Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
)
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.gzip import GZipMiddleware

from .arena_page import CHALLENGES as ARENA_CHALLENGES
from .arena_page import arena_gate_html, arena_index_html
from .arena_relay import (
    _ARENA_CAPTCHAS,
    _ARENA_GATES,
    _QUEUE_HOARD_THRESHOLD,
    _QUEUE_TICKET_TTL,
    ARENA_URL,
    _arena_level,
)
from .coherence.rules import load_registry
from .demo import DEMO_PAGE
from .detector import Detector
from .flow_cadence import _FLOW_TTL, _flow_robotic, _flow_superhuman
from .geo import lookup as geo_lookup
from .models import MISSING, Layer, Session, Signal, Source, Verdict
from .pages import (
    LLMS_TXT,
    SEO_KEYWORDS,
    SITE_ORIGIN,
    bypass_index,
    parse_fleet,
    parse_matrix,
    parse_techniques,
    render_detection_detail,
    render_detections_page,
    render_doc_page,
    render_docs_hub,
    render_evasion_detail,
    render_evasions_page,
    render_how_it_works_page,
    render_markdown_doc,
    render_matrix_page,
    render_not_found,
    render_research_page,
    reverse_index,
)
from .scoring import CONVICTING_CATEGORIES
from .store import Store
from .vendors import PROFILES, challenge_required, challenge_url, shape_checksiteconfig, shape_siteverify
from .webutil import _SAFE_SLUG, _fnv1a

#: Published doc pages: slug -> (markdown file, title, meta description). Internal docs are NOT listed.
DOC_PAGES: dict[str, tuple[str, str, str]] = {
    "matrix": (
        "matrix.md",
        "Detection matrix",
        "Which antidetect tools and bots Kitsune catches — per-evader verdicts and the tells that convict each.",
    ),
    "evasions": (
        "evasion-catalog.md",
        "Evasion catalog",
        "Every evasion technique in the red-team ladder and the anti-detect tools that implement it.",
    ),
    "detections": (
        "detection-catalog.md",
        "Detection catalog",
        "Every detection rule Kitsune runs and the exact signal it exploits, across all layers.",
    ),
    "how-it-works": (
        "architecture.md",
        "How it works",
        "Kitsune's architecture and the cross-layer incoherence thesis behind its bot detection.",
    ),
    "research": (
        "findings.md",
        "Research",
        "Findings from the Kitsune detection-vs-evasion arms race.",
    ),
    "fleet": (
        "fleet.md",
        "Fleet & Skulk",
        "Skulk — Kitsune's fleet adversary-emulation kit — and how the detector catches coordinated bot "
        "fleets by cross-session coherence, the axis per-session spoofing can't cheaply beat.",
    ),
    "frontier": (
        "frontier.md",
        "Frontier",
        "The live state of Kitsune's detection-vs-evasion arms race — what's saturated, what's an open "
        "vein, and what's blocked on external data.",
    ),
}


def _docs_dir() -> Path:
    env = os.environ.get("KITSUNE_DOCS_DIR")
    return Path(env) if env else Path(__file__).resolve().parents[3] / "docs"


#: Static brand assets (favicon set, OG card, web manifest), served at the URL root.
STATIC_DIR = Path(__file__).parent / "static"

#: Self-hosted web fonts (display + body), pre-resolved to constant paths so the request name is only ever
#: a dict key — no user-controlled string is ever joined into a filesystem path (defeats path traversal).
_FONT_PATHS: dict[str, Path] = {
    name: STATIC_DIR / "fonts" / name
    for name in (
        "space-grotesk-400.woff2",
        "space-grotesk-500.woff2",
        "space-grotesk-600.woff2",
        "space-grotesk-700.woff2",
        "jetbrains-mono-400.woff2",
        "jetbrains-mono-500.woff2",
        "jetbrains-mono-700.woff2",
    )
}


def create_app(
    detector: Detector | None = None,
    store: Store | None = None,
    admin_token: str | None = None,
) -> FastAPI:
    detector = detector or Detector()
    store = store or Store(":memory:")
    # The inspection endpoints (/session, /verdict, /scoreboard) expose raw signals — including the
    # client IP — and the full verdict store. On a public host that is operator-data exposure, so when
    # KITSUNE_ADMIN_TOKEN is set they require an `Authorization: Bearer <token>` header. Unset
    # (dev/tests) leaves them open. An explicit admin_token argument overrides the env (used in tests).
    # An empty value counts as unset. (The public API docs at /docs are always served either way.)
    admin_token = admin_token if admin_token is not None else os.environ.get("KITSUNE_ADMIN_TOKEN")

    def require_admin(authorization: str | None = Header(default=None)) -> None:
        if not admin_token:
            return  # gating disabled — no token configured
        expected = f"Bearer {admin_token}"
        if authorization is None or not hmac.compare_digest(authorization, expected):
            raise HTTPException(status_code=401, detail="admin token required")

    # Public API docs: Swagger UI at /api (so /docs is the human documentation hub), schema at /openapi.json.
    # The schema lists only the public API (POST /ingest, /rules.json, /inspect/{id}, the /arena relays); every
    # internal/admin/asset route sets include_in_schema=False, and the admin routes stay token-guarded.
    app = FastAPI(
        title="Kitsune Detector API",
        version="0.1.0",
        docs_url="/api",
        redoc_url=None,
        description=(
            "The **Kitsune** bot-detection API — it flags *incoherence across layers*, not any single bad "
            "signal.\n\n"
            "**Core flow:** a browser-side collector gathers `Signal`s (TLS/JA4 and TCP/IP come from the edge; "
            "canvas/WebGL/audio/fonts and mouse/keystroke behaviour from JavaScript). `POST /ingest` a list of "
            "those signals and get back a `Verdict` per session — `human`, `suspicious`, `bot` or `verified` — "
            "with the exact `contradictions` that fired and a per-layer score.\n\n"
            "**Try it:** the live page at [kitsune.id](https://kitsune.id/) runs the collector and calls "
            "`/ingest` for you; the full rule registry is at "
            "[`/rules.json`](https://kitsune.id/rules.json).\n\n"
            "The token-gated operator endpoints (`/session`, `/verdict`, `/scoreboard`) are intentionally "
            "omitted from this schema."
        ),
        openapi_tags=[
            {
                "name": "Detection",
                "description": "Score collector signals and read a session's verdict/wire fingerprint.",
            },
            {"name": "Reference", "description": "The machine-readable detection-rule registry."},
            {"name": "Ops", "description": "Health and liveness."},
        ],
    )

    # The pages are inline-everything HTML (the homepage is ~149 KB of mostly text); gzip cuts the wire
    # transfer ~70-87% and makes the per-page repeated CSS nearly free. minimum_size skips tiny JSON bodies.
    app.add_middleware(GZipMiddleware, minimum_size=700)

    @app.exception_handler(StarletteHTTPException)
    async def _http_exception(request: Request, exc: StarletteHTTPException) -> Response:
        # A browser hitting a missing URL gets the branded 404 page; API clients (or any non-404 error)
        # keep the JSON {"detail": ...} shape FastAPI returns by default, headers preserved.
        wants_html = "text/html" in request.headers.get("accept", "")
        if exc.status_code == 404 and wants_html:
            return HTMLResponse(render_not_found(request.url.path), status_code=404)
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers=exc.headers)

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
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

    @app.get(
        "/healthz",
        tags=["Ops"],
        summary="Health check",
        description="Liveness probe. Returns `{status: ok}` and the active `ruleset_version`.",
    )
    def healthz() -> dict[str, str]:
        return {"status": "ok", "ruleset_version": detector.ruleset_version}

    def _arena_html(body: str) -> HTMLResponse:
        # The gate pages run inline SubtleCrypto solvers, so they need the home page's permissive CSP. img-src
        # MUST allow data: — the CAPTCHA/slider/rotate images are PNG/SVG data URIs minted by the gate.
        resp = HTMLResponse(body)
        resp.headers["Content-Security-Policy"] = (
            "default-src * data: blob: 'unsafe-inline' 'unsafe-eval'; img-src 'self' data:"
        )
        return resp

    @app.get("/arena", response_class=HTMLResponse, include_in_schema=False)
    def arena() -> HTMLResponse:
        # The arena index: the thesis intro + a card grid linking to every challenge's own page.
        return _arena_html(arena_index_html())

    @app.get("/arena/gate", include_in_schema=False)
    def arena_gate_index() -> RedirectResponse:
        return RedirectResponse("/arena", status_code=308)

    @app.get("/arena/gate/{name}", response_class=HTMLResponse, include_in_schema=False)
    def arena_gate(name: str) -> HTMLResponse:
        # One challenge per page: its widget + the dual (gate vs detector) verdict, on the shared doc shell.
        # Guard the slug at the boundary: a gate slug is a fixed lowercase-kebab token, so reject anything
        # else up front. This whitelists the path param to chars that cannot carry HTML/JS markup before it is
        # ever reflected into the page's canonical URL — defence-in-depth on top of the registry lookup below.
        if not re.fullmatch(r"[a-z0-9-]{1,40}", name):
            raise HTTPException(status_code=404, detail="unknown challenge")
        page = arena_gate_html(name)
        if page is None:
            raise HTTPException(status_code=404, detail="unknown challenge")
        return _arena_html(page)

    # --- Arena relay: forward the challenge/verify protocol to the owned arena gate (KITSUNE_ARENA_URL),
    # so a visitor reaches the gate on the SAME origin (through the edge) and the gate verdict can join the
    # detector verdict on ks_sid. The detector never imports the gate — it speaks HTTP, contracts-only. ---
    # Per-session outstanding virtual-queue tickets, for the position-hoarding tell. ks_sid -> {ticket_id: issued}.
    queue_holdings: dict[str, dict[str, datetime]] = {}

    def _note_queue_ticket(ks_sid: str, ticket_id: str, now: datetime) -> int:
        held = queue_holdings.setdefault(ks_sid, {})
        held[ticket_id] = now
        cutoff = now - _QUEUE_TICKET_TTL
        for tid in [t for t, ts in held.items() if ts < cutoff]:
            del held[tid]  # abandoned/expired positions do not count toward hoarding
        return len(held)

    def _drop_queue_ticket(ks_sid: str, ticket_id: str) -> None:
        held = queue_holdings.get(ks_sid)
        if held is not None:
            held.pop(ticket_id, None)

    # session-intent flow log: the ordered gate-completion timestamps per ks_sid — the multi-step FLOW substrate the
    # arena did not track (each gate was independent). This is where the SESSION-SHAPE tells live.
    flow_log: dict[str, list[datetime]] = {}

    def _record_flow_step(ks_sid: str, now: datetime) -> list[datetime]:
        # Record a gate-completion step and return the session's live step sequence. Steps older than the TTL are
        # pruned so a slow/resumed session never accumulates a false pattern.
        steps = flow_log.setdefault(ks_sid, [])
        cutoff = now - _FLOW_TTL
        steps[:] = [t for t in steps if t >= cutoff]
        steps.append(now)
        return steps

    def _note_flow(ks_sid: str | None) -> None:
        # Call on every arena gate COMPLETION (verify/act). Inject the session-intent tells the flow shape trips:
        # session_flow_superhuman (median inter-step below the floor) and/or session_flow_robotic (near-zero CV,
        # a machine timer) — the multi-step generalizations of the single-step timing tells.
        if not ks_sid:
            return
        now = datetime.now(UTC)
        steps = _record_flow_step(ks_sid, now)
        sigs = []
        if _flow_superhuman(steps):
            sigs.append(
                Signal(
                    session_id=ks_sid,
                    layer=Layer.behavioral,
                    kind="session_flow_superhuman",
                    value=True,
                    source=Source.detector,
                    observed_at=now,
                )
            )
        if _flow_robotic(steps):
            sigs.append(
                Signal(
                    session_id=ks_sid,
                    layer=Layer.behavioral,
                    kind="session_flow_robotic",
                    value=True,
                    source=Source.detector,
                    observed_at=now,
                )
            )
        if sigs:
            _apply_signals(sigs)

    def _join_arena_anomaly(ks_sid: str | None, r: httpx.Response) -> None:
        # A gate /verify response may carry a SERVER-OBSERVED solve-anomaly (a CAPTCHA solved faster than a human,
        # a slider trajectory claiming more drag-time than the whole solve). Map it to a behavioral signal and
        # attach it to ks_sid so a PASSED gate corroborates the coherence verdict instead of clearing it (the arena
        # thesis). Kinds are written as literals so the active-rule drift guard sees this as their live producer.
        if not ks_sid or r.status_code != 200:
            return
        try:
            anomaly = r.json().get("anomaly")
        except ValueError:
            return
        if anomaly == "solved_faster_than_human":
            kind = "arena_captcha_superhuman"
        elif anomaly == "solved_faster_than_audio":
            kind = "arena_audio_superhuman"
        elif anomaly == "solved_before_shuffle":
            kind = "arena_shell_precomputed"
        elif anomaly == "timing_superhuman":
            kind = "arena_timing_superhuman"
        elif anomaly == "typed_without_exploration":
            kind = "arena_keymap_no_exploration"
        elif anomaly == "hold_robotic":
            kind = "arena_hold_robotic"
        elif anomaly == "seqclick_superhuman":
            kind = "arena_seqclick_superhuman"
        elif anomaly == "localize_superhuman":
            kind = "arena_localize_superhuman"
        elif anomaly == "match_superhuman":
            kind = "arena_match_superhuman"
        elif anomaly == "slide_superhuman":
            kind = "arena_slide_superhuman"
        elif anomaly == "pattern_superhuman":
            kind = "arena_pattern_superhuman"
        elif anomaly == "reaction_superhuman":
            kind = "arena_reaction_superhuman"
        elif anomaly == "spotdiff_superhuman":
            kind = "arena_spotdiff_superhuman"
        elif anomaly == "pursuit_superhuman":
            kind = "arena_pursuit_superhuman"
        elif anomaly == "count_superhuman":
            kind = "arena_count_superhuman"
        elif anomaly == "trajectory_exceeds_solve_time":
            kind = "arena_trajectory_forged"
        elif anomaly == "honeypot_filled":
            kind = "arena_honeypot_filled"
        elif anomaly == "acted_faster_than_human":
            kind = "arena_queue_superhuman"
        elif anomaly == "queue_bypass":
            kind = "arena_queue_bypass"
        elif anomaly == "stale_snapshot":
            kind = "arena_stale_snapshot"
        else:
            return
        _apply_signals(
            [
                Signal(
                    session_id=ks_sid,
                    layer=Layer.behavioral,
                    kind=kind,
                    value=True,
                    source=Source.detector,
                    observed_at=datetime.now(UTC),
                )
            ]
        )

    @app.get("/arena/challenge", include_in_schema=False)
    async def arena_challenge(
        gate: str = "hashcash", difficulty: int | None = None, level: str | None = None
    ) -> Response:
        if not ARENA_URL:
            raise HTTPException(status_code=503, detail="arena gate not configured")
        if gate not in _ARENA_GATES:
            raise HTTPException(status_code=400, detail="unknown gate")
        params = {"gate": gate, "level": _arena_level(level)}
        if difficulty is not None:
            params["difficulty"] = str(difficulty)
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.get(f"{ARENA_URL}/arena/challenge", params=params)
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail="arena gate unreachable") from exc
        return Response(content=r.content, media_type="application/json", status_code=r.status_code)

    @app.post("/arena/verify", include_in_schema=False)
    async def arena_verify(request: Request) -> Response:
        if not ARENA_URL:
            raise HTTPException(status_code=503, detail="arena gate not configured")
        body = await request.body()
        if len(body) > 1_048_576:  # bound the relayed body — the gate is owned, but the relay is public
            raise HTTPException(status_code=413, detail="solution too large")
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.post(
                    f"{ARENA_URL}/arena/verify", content=body, headers={"content-type": "application/json"}
                )
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail="arena gate unreachable") from exc
        return Response(content=r.content, media_type="application/json", status_code=r.status_code)

    @app.get("/arena/rate", include_in_schema=False)
    async def arena_rate(request: Request, level: str | None = None) -> Response:
        # Relay the rate-limit gate, forwarding the REAL client IP (X-Forwarded-For) so the gate's per-origin
        # token bucket budgets each visitor, not the detector's aggregate. Returns the gate's 200/429 verbatim.
        if not ARENA_URL:
            raise HTTPException(status_code=503, detail="arena gate not configured")
        client_ip = request.client.host if request.client else "0.0.0.0"
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.get(
                    f"{ARENA_URL}/arena/rate",
                    params={"level": _arena_level(level)},
                    headers={"x-forwarded-for": client_ip},
                )
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail="arena gate unreachable") from exc
        return Response(content=r.content, media_type="application/json", status_code=r.status_code)

    @app.get("/arena/catalog", include_in_schema=False)
    async def arena_catalog() -> Response:
        # Relay the CAPTCHA bench MANIFEST (kinds x levels x fonts/categories) from the owned gate, so a red-teamer
        # iterating the challenge space reaches it on the same origin as the challenges themselves.
        if not ARENA_URL:
            raise HTTPException(status_code=503, detail="arena gate not configured")
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.get(f"{ARENA_URL}/arena/catalog")
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail="arena gate unreachable") from exc
        return Response(content=r.content, media_type="application/json", status_code=r.status_code)

    @app.get("/arena/captcha", include_in_schema=False)
    async def arena_captcha(
        kind: str = "text", level: str | None = None, font: str | None = None, charset: str | None = None
    ) -> Response:
        # Relay a self-hosted CAPTCHA challenge (text/math/honeypot) from the owned gate — same pattern as the
        # PoW relay. Kind whitelisted; the answer is never in the response (the gate keeps it server-side). The
        # optional ?font= selects the text-gate typeface (the OCR bench); the gate falls back to a random pool
        # face for an empty/unknown name, so it is passed through with only a length guard.
        if not ARENA_URL:
            raise HTTPException(status_code=503, detail="arena gate not configured")
        if kind not in _ARENA_CAPTCHAS:
            raise HTTPException(status_code=400, detail="unknown captcha")
        params = {"kind": kind, "level": _arena_level(level)}
        if font and len(font) <= 32:
            params["font"] = font
        if charset and len(charset) <= 32:
            params["charset"] = charset
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.get(f"{ARENA_URL}/arena/captcha", params=params)
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail="arena gate unreachable") from exc
        return Response(content=r.content, media_type="application/json", status_code=r.status_code)

    @app.post("/arena/captcha/verify", include_in_schema=False)
    async def arena_captcha_verify(request: Request, ks_sid: str | None = Cookie(default=None)) -> Response:
        if not ARENA_URL:
            raise HTTPException(status_code=503, detail="arena gate not configured")
        body = await request.body()
        if len(body) > 65536:
            raise HTTPException(status_code=413, detail="answer too large")
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.post(
                    f"{ARENA_URL}/arena/captcha/verify", content=body, headers={"content-type": "application/json"}
                )
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail="arena gate unreachable") from exc
        _join_arena_anomaly(ks_sid, r)
        _note_flow(ks_sid)
        return Response(content=r.content, media_type="application/json", status_code=r.status_code)

    @app.get("/arena/audio", include_in_schema=False)
    async def arena_audio(level: str | None = None) -> Response:
        # Relay a self-hosted spoken-digit AUDIO challenge (the ASR bench) from the owned gate. The clip is a WAV
        # data URI; the answer (digit string) stays server-side, same as the CAPTCHA relay.
        if not ARENA_URL:
            raise HTTPException(status_code=503, detail="arena gate not configured")
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.get(f"{ARENA_URL}/arena/audio", params={"level": _arena_level(level)})
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail="arena gate unreachable") from exc
        return Response(content=r.content, media_type="application/json", status_code=r.status_code)

    @app.post("/arena/audio/verify", include_in_schema=False)
    async def arena_audio_verify(request: Request, ks_sid: str | None = Cookie(default=None)) -> Response:
        if not ARENA_URL:
            raise HTTPException(status_code=503, detail="arena gate not configured")
        body = await request.body()
        if len(body) > 65536:
            raise HTTPException(status_code=413, detail="answer too large")
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.post(
                    f"{ARENA_URL}/arena/audio/verify", content=body, headers={"content-type": "application/json"}
                )
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail="arena gate unreachable") from exc
        _join_arena_anomaly(ks_sid, r)
        _note_flow(ks_sid)
        return Response(content=r.content, media_type="application/json", status_code=r.status_code)

    @app.get("/arena/spatial", include_in_schema=False)
    async def arena_spatial(level: str | None = None) -> Response:
        # Relay a self-hosted 3D spatial-reasoning challenge (isometric cube grid) from the owned gate. The tile
        # images ride in the JSON; the answer (matching indices) stays server-side, same as image-select.
        if not ARENA_URL:
            raise HTTPException(status_code=503, detail="arena gate not configured")
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.get(f"{ARENA_URL}/arena/spatial", params={"level": _arena_level(level)})
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail="arena gate unreachable") from exc
        return Response(content=r.content, media_type="application/json", status_code=r.status_code)

    @app.post("/arena/spatial/verify", include_in_schema=False)
    async def arena_spatial_verify(request: Request, ks_sid: str | None = Cookie(default=None)) -> Response:
        if not ARENA_URL:
            raise HTTPException(status_code=503, detail="arena gate not configured")
        body = await request.body()
        if len(body) > 65536:
            raise HTTPException(status_code=413, detail="answer too large")
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.post(
                    f"{ARENA_URL}/arena/spatial/verify", content=body, headers={"content-type": "application/json"}
                )
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail="arena gate unreachable") from exc
        _join_arena_anomaly(ks_sid, r)
        _note_flow(ks_sid)
        return Response(content=r.content, media_type="application/json", status_code=r.status_code)

    @app.get("/arena/shell", include_in_schema=False)
    async def arena_shell(level: str | None = None) -> Response:
        # Relay the self-hosted shell-game (track-under-occlusion) challenge. The swap sequence rides in the JSON so
        # the client can animate it; the final ball position stays server-side.
        if not ARENA_URL:
            raise HTTPException(status_code=503, detail="arena gate not configured")
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.get(f"{ARENA_URL}/arena/shell", params={"level": _arena_level(level)})
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail="arena gate unreachable") from exc
        return Response(content=r.content, media_type="application/json", status_code=r.status_code)

    @app.post("/arena/shell/verify", include_in_schema=False)
    async def arena_shell_verify(request: Request, ks_sid: str | None = Cookie(default=None)) -> Response:
        if not ARENA_URL:
            raise HTTPException(status_code=503, detail="arena gate not configured")
        body = await request.body()
        if len(body) > 65536:
            raise HTTPException(status_code=413, detail="answer too large")
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.post(
                    f"{ARENA_URL}/arena/shell/verify", content=body, headers={"content-type": "application/json"}
                )
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail="arena gate unreachable") from exc
        _join_arena_anomaly(ks_sid, r)  # solved_before_shuffle -> arena_shell_precomputed
        _note_flow(ks_sid)
        return Response(content=r.content, media_type="application/json", status_code=r.status_code)

    @app.get("/arena/timing", include_in_schema=False)
    async def arena_timing(level: str | None = None) -> Response:
        # Relay the self-hosted motor-timing-precision challenge (hold/release targets); the targets ride in the
        # JSON, the client reports its achieved holds to /verify.
        if not ARENA_URL:
            raise HTTPException(status_code=503, detail="arena gate not configured")
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.get(f"{ARENA_URL}/arena/timing", params={"level": _arena_level(level)})
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail="arena gate unreachable") from exc
        return Response(content=r.content, media_type="application/json", status_code=r.status_code)

    @app.post("/arena/timing/verify", include_in_schema=False)
    async def arena_timing_verify(request: Request, ks_sid: str | None = Cookie(default=None)) -> Response:
        if not ARENA_URL:
            raise HTTPException(status_code=503, detail="arena gate not configured")
        body = await request.body()
        if len(body) > 65536:
            raise HTTPException(status_code=413, detail="answer too large")
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.post(
                    f"{ARENA_URL}/arena/timing/verify", content=body, headers={"content-type": "application/json"}
                )
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail="arena gate unreachable") from exc
        _join_arena_anomaly(ks_sid, r)  # timing_superhuman -> arena_timing_superhuman
        _note_flow(ks_sid)
        return Response(content=r.content, media_type="application/json", status_code=r.status_code)

    @app.get("/arena/keymap", include_in_schema=False)
    async def arena_keymap(level: str | None = None) -> Response:
        # Relay the self-hosted broken/remapped-keyboard challenge; the remap rides in the JSON (the page applies
        # it client-side), the client reports its key trace to /verify.
        if not ARENA_URL:
            raise HTTPException(status_code=503, detail="arena gate not configured")
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.get(f"{ARENA_URL}/arena/keymap", params={"level": _arena_level(level)})
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail="arena gate unreachable") from exc
        return Response(content=r.content, media_type="application/json", status_code=r.status_code)

    @app.post("/arena/keymap/verify", include_in_schema=False)
    async def arena_keymap_verify(request: Request, ks_sid: str | None = Cookie(default=None)) -> Response:
        if not ARENA_URL:
            raise HTTPException(status_code=503, detail="arena gate not configured")
        body = await request.body()
        if len(body) > 65536:
            raise HTTPException(status_code=413, detail="answer too large")
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.post(
                    f"{ARENA_URL}/arena/keymap/verify", content=body, headers={"content-type": "application/json"}
                )
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail="arena gate unreachable") from exc
        _join_arena_anomaly(ks_sid, r)  # typed_without_exploration -> arena_keymap_no_exploration
        _note_flow(ks_sid)
        return Response(content=r.content, media_type="application/json", status_code=r.status_code)

    @app.get("/arena/presshold", include_in_schema=False)
    async def arena_presshold(level: str | None = None) -> Response:
        # Relay the self-hosted press-and-hold challenge (hold one button for the shown duration); the target rides
        # in the JSON, the client reports its achieved hold + held-pointer samples to /verify.
        if not ARENA_URL:
            raise HTTPException(status_code=503, detail="arena gate not configured")
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.get(f"{ARENA_URL}/arena/presshold", params={"level": _arena_level(level)})
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail="arena gate unreachable") from exc
        return Response(content=r.content, media_type="application/json", status_code=r.status_code)

    @app.post("/arena/presshold/verify", include_in_schema=False)
    async def arena_presshold_verify(request: Request, ks_sid: str | None = Cookie(default=None)) -> Response:
        if not ARENA_URL:
            raise HTTPException(status_code=503, detail="arena gate not configured")
        body = await request.body()
        if len(body) > 65536:
            raise HTTPException(status_code=413, detail="answer too large")
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.post(
                    f"{ARENA_URL}/arena/presshold/verify", content=body, headers={"content-type": "application/json"}
                )
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail="arena gate unreachable") from exc
        _join_arena_anomaly(ks_sid, r)  # hold_robotic -> arena_hold_robotic
        _note_flow(ks_sid)
        return Response(content=r.content, media_type="application/json", status_code=r.status_code)

    @app.get("/arena/sequence", include_in_schema=False)
    async def arena_sequence(level: str | None = None) -> Response:
        # Relay the self-hosted ordered click-in-sequence challenge (click N numbered tiles in order); the tiles ride
        # in the JSON, the client reports its click order + timestamps to /verify.
        if not ARENA_URL:
            raise HTTPException(status_code=503, detail="arena gate not configured")
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.get(f"{ARENA_URL}/arena/sequence", params={"level": _arena_level(level)})
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail="arena gate unreachable") from exc
        return Response(content=r.content, media_type="application/json", status_code=r.status_code)

    @app.post("/arena/sequence/verify", include_in_schema=False)
    async def arena_sequence_verify(request: Request, ks_sid: str | None = Cookie(default=None)) -> Response:
        if not ARENA_URL:
            raise HTTPException(status_code=503, detail="arena gate not configured")
        body = await request.body()
        if len(body) > 65536:
            raise HTTPException(status_code=413, detail="answer too large")
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.post(
                    f"{ARENA_URL}/arena/sequence/verify", content=body, headers={"content-type": "application/json"}
                )
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail="arena gate unreachable") from exc
        _join_arena_anomaly(ks_sid, r)  # seqclick_superhuman -> arena_seqclick_superhuman
        _note_flow(ks_sid)
        return Response(content=r.content, media_type="application/json", status_code=r.status_code)

    @app.get("/arena/locate", include_in_schema=False)
    async def arena_locate(level: str | None = None) -> Response:
        # Relay the self-hosted point-localization challenge (click the target's centre on a canvas); the rendered
        # image rides in the JSON, the client reports its click (x,y) to /verify. The target centre stays server-side.
        if not ARENA_URL:
            raise HTTPException(status_code=503, detail="arena gate not configured")
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.get(f"{ARENA_URL}/arena/locate", params={"level": _arena_level(level)})
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail="arena gate unreachable") from exc
        return Response(content=r.content, media_type="application/json", status_code=r.status_code)

    @app.post("/arena/locate/verify", include_in_schema=False)
    async def arena_locate_verify(request: Request, ks_sid: str | None = Cookie(default=None)) -> Response:
        if not ARENA_URL:
            raise HTTPException(status_code=503, detail="arena gate not configured")
        body = await request.body()
        if len(body) > 65536:
            raise HTTPException(status_code=413, detail="answer too large")
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.post(
                    f"{ARENA_URL}/arena/locate/verify", content=body, headers={"content-type": "application/json"}
                )
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail="arena gate unreachable") from exc
        _join_arena_anomaly(ks_sid, r)  # localize_superhuman -> arena_localize_superhuman
        _note_flow(ks_sid)
        return Response(content=r.content, media_type="application/json", status_code=r.status_code)

    @app.get("/arena/match", include_in_schema=False)
    async def arena_match(level: str | None = None) -> Response:
        # Relay the self-hosted orientation-match challenge (click the candidate facing the same way as the
        # reference); the reference + candidate images ride in the JSON, the client reports its clicked index.
        if not ARENA_URL:
            raise HTTPException(status_code=503, detail="arena gate not configured")
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.get(f"{ARENA_URL}/arena/match", params={"level": _arena_level(level)})
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail="arena gate unreachable") from exc
        return Response(content=r.content, media_type="application/json", status_code=r.status_code)

    @app.post("/arena/match/verify", include_in_schema=False)
    async def arena_match_verify(request: Request, ks_sid: str | None = Cookie(default=None)) -> Response:
        if not ARENA_URL:
            raise HTTPException(status_code=503, detail="arena gate not configured")
        body = await request.body()
        if len(body) > 65536:
            raise HTTPException(status_code=413, detail="answer too large")
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.post(
                    f"{ARENA_URL}/arena/match/verify", content=body, headers={"content-type": "application/json"}
                )
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail="arena gate unreachable") from exc
        _join_arena_anomaly(ks_sid, r)  # match_superhuman -> arena_match_superhuman
        _note_flow(ks_sid)
        return Response(content=r.content, media_type="application/json", status_code=r.status_code)

    @app.get("/arena/slide", include_in_schema=False)
    async def arena_slide(level: str | None = None) -> Response:
        # Relay the self-hosted sliding-tile puzzle (slide the 8-puzzle into order); the scrambled board rides in the
        # JSON, the client reports its move sequence (clicked tile indices) to /verify.
        if not ARENA_URL:
            raise HTTPException(status_code=503, detail="arena gate not configured")
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.get(f"{ARENA_URL}/arena/slide", params={"level": _arena_level(level)})
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail="arena gate unreachable") from exc
        return Response(content=r.content, media_type="application/json", status_code=r.status_code)

    @app.post("/arena/slide/verify", include_in_schema=False)
    async def arena_slide_verify(request: Request, ks_sid: str | None = Cookie(default=None)) -> Response:
        if not ARENA_URL:
            raise HTTPException(status_code=503, detail="arena gate not configured")
        body = await request.body()
        if len(body) > 65536:
            raise HTTPException(status_code=413, detail="answer too large")
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.post(
                    f"{ARENA_URL}/arena/slide/verify", content=body, headers={"content-type": "application/json"}
                )
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail="arena gate unreachable") from exc
        _join_arena_anomaly(ks_sid, r)  # slide_superhuman -> arena_slide_superhuman
        _note_flow(ks_sid)
        return Response(content=r.content, media_type="application/json", status_code=r.status_code)

    @app.get("/arena/pattern", include_in_schema=False)
    async def arena_pattern(level: str | None = None) -> Response:
        # Relay the self-hosted trace-the-pattern challenge (draw a stroke through the dots in order); the waypoints
        # ride in the JSON, the client reports its drawn stroke to /verify.
        if not ARENA_URL:
            raise HTTPException(status_code=503, detail="arena gate not configured")
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.get(f"{ARENA_URL}/arena/pattern", params={"level": _arena_level(level)})
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail="arena gate unreachable") from exc
        return Response(content=r.content, media_type="application/json", status_code=r.status_code)

    @app.post("/arena/pattern/verify", include_in_schema=False)
    async def arena_pattern_verify(request: Request, ks_sid: str | None = Cookie(default=None)) -> Response:
        if not ARENA_URL:
            raise HTTPException(status_code=503, detail="arena gate not configured")
        body = await request.body()
        if len(body) > 65536:
            raise HTTPException(status_code=413, detail="answer too large")
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.post(
                    f"{ARENA_URL}/arena/pattern/verify", content=body, headers={"content-type": "application/json"}
                )
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail="arena gate unreachable") from exc
        _join_arena_anomaly(ks_sid, r)  # pattern_superhuman -> arena_pattern_superhuman
        _note_flow(ks_sid)
        return Response(content=r.content, media_type="application/json", status_code=r.status_code)

    @app.get("/arena/reaction", include_in_schema=False)
    async def arena_reaction(level: str | None = None) -> Response:
        # Relay the self-hosted reaction-time challenge (click when the box turns green); the pre-cue delay rides in
        # the JSON, the client reports its click to /verify where the server derives the reaction latency.
        if not ARENA_URL:
            raise HTTPException(status_code=503, detail="arena gate not configured")
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.get(f"{ARENA_URL}/arena/reaction", params={"level": _arena_level(level)})
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail="arena gate unreachable") from exc
        return Response(content=r.content, media_type="application/json", status_code=r.status_code)

    @app.post("/arena/reaction/verify", include_in_schema=False)
    async def arena_reaction_verify(request: Request, ks_sid: str | None = Cookie(default=None)) -> Response:
        if not ARENA_URL:
            raise HTTPException(status_code=503, detail="arena gate not configured")
        body = await request.body()
        if len(body) > 65536:
            raise HTTPException(status_code=413, detail="answer too large")
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.post(
                    f"{ARENA_URL}/arena/reaction/verify", content=body, headers={"content-type": "application/json"}
                )
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail="arena gate unreachable") from exc
        _join_arena_anomaly(ks_sid, r)  # reaction_superhuman -> arena_reaction_superhuman
        _note_flow(ks_sid)
        return Response(content=r.content, media_type="application/json", status_code=r.status_code)

    @app.get("/arena/spotdiff", include_in_schema=False)
    async def arena_spotdiff(level: str | None = None) -> Response:
        # Relay the self-hosted spot-the-difference challenge (two panels differ in K spots); the rendered image
        # rides in the JSON, the client reports its difference clicks. The difference centres stay server-side.
        if not ARENA_URL:
            raise HTTPException(status_code=503, detail="arena gate not configured")
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.get(f"{ARENA_URL}/arena/spotdiff", params={"level": _arena_level(level)})
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail="arena gate unreachable") from exc
        return Response(content=r.content, media_type="application/json", status_code=r.status_code)

    @app.post("/arena/spotdiff/verify", include_in_schema=False)
    async def arena_spotdiff_verify(request: Request, ks_sid: str | None = Cookie(default=None)) -> Response:
        if not ARENA_URL:
            raise HTTPException(status_code=503, detail="arena gate not configured")
        body = await request.body()
        if len(body) > 65536:
            raise HTTPException(status_code=413, detail="answer too large")
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.post(
                    f"{ARENA_URL}/arena/spotdiff/verify", content=body, headers={"content-type": "application/json"}
                )
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail="arena gate unreachable") from exc
        _join_arena_anomaly(ks_sid, r)  # spotdiff_superhuman -> arena_spotdiff_superhuman
        _note_flow(ks_sid)
        return Response(content=r.content, media_type="application/json", status_code=r.status_code)

    @app.get("/arena/pursuit", include_in_schema=False)
    async def arena_pursuit(level: str | None = None) -> Response:
        # Relay the self-hosted smooth-pursuit challenge (keep the cursor on the moving dot); the deterministic path
        # rides in the JSON (the client animates the dot from it), the client reports its cursor samples to /verify.
        if not ARENA_URL:
            raise HTTPException(status_code=503, detail="arena gate not configured")
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.get(f"{ARENA_URL}/arena/pursuit", params={"level": _arena_level(level)})
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail="arena gate unreachable") from exc
        return Response(content=r.content, media_type="application/json", status_code=r.status_code)

    @app.post("/arena/pursuit/verify", include_in_schema=False)
    async def arena_pursuit_verify(request: Request, ks_sid: str | None = Cookie(default=None)) -> Response:
        if not ARENA_URL:
            raise HTTPException(status_code=503, detail="arena gate not configured")
        body = await request.body()
        if len(body) > 65536:
            raise HTTPException(status_code=413, detail="answer too large")
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.post(
                    f"{ARENA_URL}/arena/pursuit/verify", content=body, headers={"content-type": "application/json"}
                )
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail="arena gate unreachable") from exc
        _join_arena_anomaly(ks_sid, r)  # pursuit_superhuman -> arena_pursuit_superhuman
        _note_flow(ks_sid)
        return Response(content=r.content, media_type="application/json", status_code=r.status_code)

    @app.get("/arena/count", include_in_schema=False)
    async def arena_count(level: str | None = None) -> Response:
        # Relay the self-hosted counting challenge (how many <colour> circles?); the rendered scene rides in the JSON,
        # the client reports its counted number. The true count stays server-side.
        if not ARENA_URL:
            raise HTTPException(status_code=503, detail="arena gate not configured")
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.get(f"{ARENA_URL}/arena/count", params={"level": _arena_level(level)})
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail="arena gate unreachable") from exc
        return Response(content=r.content, media_type="application/json", status_code=r.status_code)

    @app.post("/arena/count/verify", include_in_schema=False)
    async def arena_count_verify(request: Request, ks_sid: str | None = Cookie(default=None)) -> Response:
        if not ARENA_URL:
            raise HTTPException(status_code=503, detail="arena gate not configured")
        body = await request.body()
        if len(body) > 65536:
            raise HTTPException(status_code=413, detail="answer too large")
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.post(
                    f"{ARENA_URL}/arena/count/verify", content=body, headers={"content-type": "application/json"}
                )
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail="arena gate unreachable") from exc
        _join_arena_anomaly(ks_sid, r)  # count_superhuman -> arena_count_superhuman
        _note_flow(ks_sid)
        return Response(content=r.content, media_type="application/json", status_code=r.status_code)

    # --- VENDOR PROFILES: reproduce mainstream captcha token/verify protocols vendor-neutrally over the detector.
    # One endpoint family serves every invisible-score/managed vendor (reCAPTCHA v3, Turnstile, hCaptcha, …): GET
    # /vendor/<name> mints a single-use token bound to the collector session (ks_sid); POST /vendor/<name>/siteverify
    # returns THAT vendor's documented response shape, where the score/pass is the detector's coherence verdict.
    _vendor_tokens: dict[str, tuple[str, str, datetime, str]] = {}  # token -> (ks_sid, action, issued, vendor)

    async def _vendor_form(request: Request) -> dict[str, str]:
        # siteverify accepts x-www-form-urlencoded (the vendor default) or JSON; parse both without a multipart dep.
        body = await request.body()
        if "application/json" in request.headers.get("content-type", ""):
            try:
                data = json.loads(body or b"{}")
            except ValueError:
                return {}
            return {k: str(v) for k, v in data.items()} if isinstance(data, dict) else {}
        from urllib.parse import parse_qs

        return {k: v[0] for k, v in parse_qs(body.decode("utf-8", "ignore")).items() if v}

    @app.get("/vendor/{name}", include_in_schema=False)
    async def vendor_mint(
        name: str, action: str = "submit", ks_sid: str | None = Cookie(default=None)
    ) -> dict[str, object]:
        # the invisible "execute" step — mint a single-use token bound to this collector session
        if name not in PROFILES:
            raise HTTPException(status_code=404, detail="unknown vendor")
        profile = PROFILES[name]
        token = os.urandom(18).hex()
        _vendor_tokens[token] = (ks_sid or "", action[:64], datetime.now(UTC), name)
        out: dict[str, object] = {"token": token, "action": action[:64]}
        if profile.mode == "challenge":
            # challenge-ladder: run the invisible pre-check now and, if suspicious (or no session yet), point the
            # widget at the owned escalation gate — the reCAPTCHA-v2 / Arkose "here's an image grid" (or Proton PoW)
            # moment.
            session = store.get_session(ks_sid) if ks_sid else None
            score = detector.score(session).score if session is not None else None
            if challenge_required(profile, score):
                out["challenge_required"] = True
                out["challenge_url"] = challenge_url(profile)
            else:
                out["challenge_required"] = False
        return out

    @app.post("/vendor/{name}/checksiteconfig", include_in_schema=False)
    async def vendor_checksiteconfig(
        name: str,
        sitekey: str = "",
        sc: int = 0,
        swa: int = 0,
        spst: int = 0,
        ks_sid: str | None = Cookie(default=None),
    ) -> dict[str, object]:
        # hCaptcha's widget pre-check (POST checksiteconfig?...&sc=1&swa=1&spst=1): pass silently or escalate to the
        # image challenge behind an hsw proof token. The captured protocol shape, over the detector's verdict.
        if name not in PROFILES or PROFILES[name].name != "hcaptcha":
            raise HTTPException(status_code=404, detail="no checksiteconfig for vendor")
        session = store.get_session(ks_sid) if ks_sid else None
        score = detector.score(session).score if session is not None else None
        return shape_checksiteconfig(PROFILES[name], score, sitekey[:128])

    @app.post("/vendor/{name}/siteverify", include_in_schema=False)
    async def vendor_siteverify(name: str, request: Request) -> dict[str, object]:
        if name not in PROFILES:
            raise HTTPException(status_code=404, detail="unknown vendor")
        profile = PROFILES[name]
        form = await _vendor_form(request)
        if not form.get("secret"):
            return {"success": False, "error-codes": ["missing-input-secret"]}
        response = form.get("response", "")
        if not response:
            return {"success": False, "error-codes": ["missing-input-response"]}
        entry = _vendor_tokens.pop(response, None)  # single-use: no replay
        if entry is None or entry[3] != name:  # token bound to its own vendor
            return {"success": False, "error-codes": ["timeout-or-duplicate"]}
        sid, action, issued, _vendor = entry
        if datetime.now(UTC) - issued > timedelta(seconds=profile.token_ttl_s):
            return {"success": False, "error-codes": ["timeout-or-duplicate"]}
        session = store.get_session(sid) if sid else None
        if session is None:
            return {"success": False, "error-codes": ["invalid-input-response"]}
        return shape_siteverify(
            profile, detector.score(session).score, action, issued.isoformat(), request.url.hostname or "", sid
        )

    @app.get("/arena/slider", include_in_schema=False)
    async def arena_slider(level: str | None = None) -> Response:
        # Relay a self-hosted slider (GeeTest-style) challenge from the owned gate.
        if not ARENA_URL:
            raise HTTPException(status_code=503, detail="arena gate not configured")
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.get(f"{ARENA_URL}/arena/slider", params={"level": _arena_level(level)})
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail="arena gate unreachable") from exc
        return Response(content=r.content, media_type="application/json", status_code=r.status_code)

    @app.post("/arena/slider/verify", include_in_schema=False)
    async def arena_slider_verify(request: Request, ks_sid: str | None = Cookie(default=None)) -> Response:
        if not ARENA_URL:
            raise HTTPException(status_code=503, detail="arena gate not configured")
        body = await request.body()
        if len(body) > 262144:  # a drag trajectory is many points but bounded
            raise HTTPException(status_code=413, detail="trajectory too large")
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.post(
                    f"{ARENA_URL}/arena/slider/verify", content=body, headers={"content-type": "application/json"}
                )
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail="arena gate unreachable") from exc
        _join_arena_anomaly(ks_sid, r)
        _note_flow(ks_sid)
        return Response(content=r.content, media_type="application/json", status_code=r.status_code)

    @app.get("/arena/rotate", include_in_schema=False)
    async def arena_rotate(level: str | None = None) -> Response:
        # Relay a self-hosted rotate (Arkose-style) challenge from the owned gate; verify scores the trajectory.
        if not ARENA_URL:
            raise HTTPException(status_code=503, detail="arena gate not configured")
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.get(f"{ARENA_URL}/arena/rotate", params={"level": _arena_level(level)})
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail="arena gate unreachable") from exc
        return Response(content=r.content, media_type="application/json", status_code=r.status_code)

    @app.post("/arena/rotate/verify", include_in_schema=False)
    async def arena_rotate_verify(request: Request, ks_sid: str | None = Cookie(default=None)) -> Response:
        if not ARENA_URL:
            raise HTTPException(status_code=503, detail="arena gate not configured")
        body = await request.body()
        if len(body) > 262144:
            raise HTTPException(status_code=413, detail="trajectory too large")
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.post(
                    f"{ARENA_URL}/arena/rotate/verify", content=body, headers={"content-type": "application/json"}
                )
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail="arena gate unreachable") from exc
        _join_arena_anomaly(ks_sid, r)
        _note_flow(ks_sid)
        return Response(content=r.content, media_type="application/json", status_code=r.status_code)

    @app.get("/arena/queue", include_in_schema=False)
    async def arena_queue(level: str | None = None, ks_sid: str | None = Cookie(default=None)) -> Response:
        # Relay a virtual waiting-room ticket from the owned gate; the admission->action join happens at /act.
        if not ARENA_URL:
            raise HTTPException(status_code=503, detail="arena gate not configured")
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.get(f"{ARENA_URL}/arena/queue", params={"level": _arena_level(level)})
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail="arena gate unreachable") from exc
        # Position hoarding: one ks_sid holding many concurrent tickets is a scalper maximising admission odds, not a
        # person. Count this session's outstanding tickets server-side; over the threshold, inject a corroborating
        # signal. Experimental — threshold-calibrated, not by-construction.
        if ks_sid and r.status_code == 200:
            try:
                ticket_id = r.json().get("id")
            except ValueError:
                ticket_id = None
            if (
                isinstance(ticket_id, str)
                and ticket_id
                and _note_queue_ticket(ks_sid, ticket_id, datetime.now(UTC)) > _QUEUE_HOARD_THRESHOLD
            ):
                _apply_signals(
                    [
                        Signal(
                            session_id=ks_sid,
                            layer=Layer.behavioral,
                            kind="arena_queue_hoarding",
                            value=True,
                            source=Source.detector,
                            observed_at=datetime.now(UTC),
                        )
                    ]
                )
        return Response(content=r.content, media_type="application/json", status_code=r.status_code)

    @app.get("/arena/queue/status", include_in_schema=False)
    async def arena_queue_status(id: str = "") -> Response:
        if not ARENA_URL:
            raise HTTPException(status_code=503, detail="arena gate not configured")
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.get(f"{ARENA_URL}/arena/queue/status", params={"id": id})
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail="arena gate unreachable") from exc
        return Response(content=r.content, media_type="application/json", status_code=r.status_code)

    @app.post("/arena/queue/act", include_in_schema=False)
    async def arena_queue_act(request: Request, ks_sid: str | None = Cookie(default=None)) -> Response:
        if not ARENA_URL:
            raise HTTPException(status_code=503, detail="arena gate not configured")
        body = await request.body()
        if len(body) > 4096:
            raise HTTPException(status_code=413, detail="body too large")
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.post(
                    f"{ARENA_URL}/arena/queue/act", content=body, headers={"content-type": "application/json"}
                )
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail="arena gate unreachable") from exc
        _join_arena_anomaly(ks_sid, r)
        _note_flow(ks_sid)
        # A ticket that is acted on (or bypass-attempted) is no longer an outstanding held position — drop it from
        # the hoarding count so a session that cycles tickets one-at-a-time is not mistaken for a hoarder.
        if ks_sid:
            try:
                acted_id = json.loads(body).get("id")
            except (ValueError, AttributeError):
                acted_id = None
            if isinstance(acted_id, str):
                _drop_queue_ticket(ks_sid, acted_id)
        return Response(content=r.content, media_type="application/json", status_code=r.status_code)

    @app.get("/arena/track/play", include_in_schema=False)
    async def arena_track_play() -> Response:
        # Relay the rendered moving-target widget page (same origin as /arena/track + /verify, so its fetches ride
        # this relay and the stale-snapshot anomaly joins to ks_sid).
        if not ARENA_URL:
            raise HTTPException(status_code=503, detail="arena gate not configured")
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.get(f"{ARENA_URL}/arena/track/play")
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail="arena gate unreachable") from exc
        return Response(content=r.content, media_type="text/html; charset=utf-8", status_code=r.status_code)

    @app.get("/arena/track", include_in_schema=False)
    async def arena_track(level: str = "") -> Response:
        # Relay the moving-target (stale-snapshot) probe issue: {id, x, y, vx, vy}. The level sets dot speed
        # (difficulty) — forwarded so the rendered widget's ?level reaches the gate.
        if not ARENA_URL:
            raise HTTPException(status_code=503, detail="arena gate not configured")
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.get(f"{ARENA_URL}/arena/track", params={"level": level})
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail="arena gate unreachable") from exc
        return Response(content=r.content, media_type="application/json", status_code=r.status_code)

    @app.get("/arena/track/pos", include_in_schema=False)
    async def arena_track_pos(id: str = "") -> Response:
        # The target's CURRENT position — a client that re-perceives before acting (a human tracking it) reads it.
        if not ARENA_URL:
            raise HTTPException(status_code=503, detail="arena gate not configured")
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.get(f"{ARENA_URL}/arena/track/pos", params={"id": id})
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail="arena gate unreachable") from exc
        return Response(content=r.content, media_type="application/json", status_code=r.status_code)

    @app.post("/arena/track/verify", include_in_schema=False)
    async def arena_track_verify(request: Request, ks_sid: str | None = Cookie(default=None)) -> Response:
        # Verify a click on the moving target; a stale-snapshot click carries anomaly:stale_snapshot, which the
        # join maps to bh.arena_stale_snapshot on the session (the LLM-agent tell that survives a clean fingerprint).
        if not ARENA_URL:
            raise HTTPException(status_code=503, detail="arena gate not configured")
        body = await request.body()
        if len(body) > 4096:
            raise HTTPException(status_code=413, detail="body too large")
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.post(
                    f"{ARENA_URL}/arena/track/verify", content=body, headers={"content-type": "application/json"}
                )
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail="arena gate unreachable") from exc
        _join_arena_anomaly(ks_sid, r)
        _note_flow(ks_sid)
        return Response(content=r.content, media_type="application/json", status_code=r.status_code)

    @app.get("/arena/pact", include_in_schema=False)
    async def arena_pact() -> Response:
        # Relay a self-hosted PACT / Private Access Token (anonymous proof-of-personhood) from the owned issuer.
        if not ARENA_URL:
            raise HTTPException(status_code=503, detail="arena gate not configured")
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.get(f"{ARENA_URL}/arena/pact")
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail="arena gate unreachable") from exc
        return Response(content=r.content, media_type="application/json", status_code=r.status_code)

    @app.post("/arena/pact/verify", include_in_schema=False)
    async def arena_pact_verify(request: Request) -> Response:
        if not ARENA_URL:
            raise HTTPException(status_code=503, detail="arena gate not configured")
        body = await request.body()
        if len(body) > 65536:
            raise HTTPException(status_code=413, detail="token too large")
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.post(
                    f"{ARENA_URL}/arena/pact/verify", content=body, headers={"content-type": "application/json"}
                )
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail="arena gate unreachable") from exc
        return Response(content=r.content, media_type="application/json", status_code=r.status_code)

    @app.get("/arena/managed", include_in_schema=False)
    async def arena_managed(
        step: int = 0, level: str | None = None, ks_sid: str | None = Cookie(default=None)
    ) -> dict[str, object]:
        # The managed-challenge ladder (the Turnstile-style escalation, faithfully): the SILENT first step
        # IS Kitsune's coherence verdict. A coherent client (human/verified) is allowed silently — no puzzle;
        # an incoherent one (suspicious/bot) is STEPPED UP to a non-interactive proof-of-work. Cookie-scoped
        # to the caller's OWN session, so it is public (no admin gate) and exposes only a decision, not the
        # full verdict. This is also the reCAPTCHA-v3-style "score, no challenge" behaviour: the detector AS
        # a gate. Reproduces the documented escalation shape — it is not the branded vendor product.
        session = store.get_session(ks_sid) if ks_sid else None
        if session is None:
            # No edge session / no signals yet → step up (the conservative managed default).
            out: dict[str, object] = {"decision": "challenge", "step": "pow", "label": "unknown", "score": None}
        else:
            verdict = detector.score(session)
            label = verdict.label.value
            allow = label in ("human", "verified")
            out = {
                "decision": "allow" if allow else "challenge",
                "step": "silent" if allow else "pow",
                "label": label,
                "score": round(verdict.score, 3),
            }
        # On a step-up (step=1), relay a non-interactive PoW the client can solve in-browser (the ladder's
        # 2nd rung). The bare call (step=0, used to read the silent verdict) does not mint a puzzle.
        if step and out["decision"] == "challenge" and ARENA_URL:
            params = {"gate": "hashcash", "level": _arena_level(level)}
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    r = await client.get(f"{ARENA_URL}/arena/challenge", params=params)
                if r.status_code == 200:
                    out["challenge"] = r.json()
            except httpx.HTTPError:
                pass  # the gate being down doesn't break the decision; the page just shows the verdict
        return out

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

    @app.get("/home.css", include_in_schema=False)
    def home_css() -> Response:
        # The home page's stylesheet, extracted from the inline HTML into static/home.css + the shared tokens.
        from .demo import HOME_CSS

        return Response(
            HOME_CSS,
            media_type="text/css",
            headers={"Cache-Control": "public, max-age=3600"},
        )

    @app.get("/arena.css", include_in_schema=False)
    def arena_css() -> FileResponse:
        # The arena component stylesheet, extracted from the inline <style> into static/arena.css. The shared
        # design tokens ship with the page's DOC_CSS already, so this file is just the component rules.
        return _asset("arena.css", "text/css")

    @app.get("/home.js", include_in_schema=False)
    def home_js() -> FileResponse:
        # The home page's client script (signal collection + verdict render), extracted from the inline
        # <script> at the end of DEMO_PAGE into static/home.js — a real, cacheable file out of the HTML string.
        return _asset("home.js", "text/javascript")

    @app.get("/arena.js", include_in_schema=False)
    def arena_js() -> FileResponse:
        # The shared arena challenge-gate client, extracted from arena_page.py's inline ARENA_JS into
        # static/arena.js. Loaded per gate after an inline <script> pins window.__ARENA__ = {slug, mode}.
        return _asset("arena.js", "text/javascript")

    @app.get("/docs", response_class=HTMLResponse, include_in_schema=False)
    def docs_hub() -> HTMLResponse:
        # The human documentation hub (the Swagger UI lives at /api). One home for the catalogs, the
        # fleet/coordination work, research and the API reference — so the top nav can stay lean.
        return HTMLResponse(render_docs_hub())

    @app.get("/fonts/{name}", include_in_schema=False)
    def font_asset(name: str) -> FileResponse:
        # Self-hosted display + body fonts (Space Grotesk, JetBrains Mono) — served from our OWN origin so
        # no third-party font CDN ever sees the visitor (the page promises no data leaves the browser). The
        # request name only selects a pre-built constant path (never joined into the FS path) — no traversal.
        path = _FONT_PATHS.get(name)
        if path is None:
            raise HTTPException(status_code=404)
        return FileResponse(
            path,
            media_type="font/woff2",
            headers={"Cache-Control": "public, max-age=31536000, immutable"},
        )

    @app.get("/site.webmanifest", include_in_schema=False)
    def site_webmanifest() -> FileResponse:
        return _asset("site.webmanifest", "application/manifest+json")

    @app.get("/robots.txt", include_in_schema=False)
    def robots() -> PlainTextResponse:
        return PlainTextResponse(f"User-agent: *\nAllow: /\nSitemap: {SITE_ORIGIN}/sitemap.xml\n")

    @app.get("/llms.txt", include_in_schema=False)
    def llms_txt() -> PlainTextResponse:
        # llmstxt.org: a link-first site map for LLM agents. Markdown served as text/plain per the convention.
        return PlainTextResponse(LLMS_TXT, media_type="text/markdown; charset=utf-8")

    @app.get("/sitemap.xml", include_in_schema=False)
    def sitemap() -> Response:
        urls = ["/", "/docs"] + [f"/{slug}" for slug in DOC_PAGES]
        urls += ["/arena"] + [f"/arena/gate/{c['slug']}" for c in ARENA_CHALLENGES]
        urls += [f"/detections/{rid}" for rid in rules_by_id]
        urls += [f"/evasions/{s}" for s in dict.fromkeys([*evaders, *fleet])]
        locs = "".join(f"<url><loc>{SITE_ORIGIN}{u}</loc></url>" for u in urls)
        xml = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
            f"{locs}</urlset>"
        )
        return Response(content=xml, media_type="application/xml")

    # The evaluable rule registry, so the live page can group detections by layer and list the checks a
    # browser PASSED (not just the ones that fired). Built once at startup; the same rules-as-data the
    # engine scores with. Convicting = coherence/automation/artifact (only these make a `bot`).
    rules_list: list[dict[str, object]] = []
    rules_by_id: dict[str, dict[str, object]] = {}  # full fields, for the per-rule drill-down pages
    ruleset_version = detector.ruleset_version
    try:
        _ruleset = load_registry()
        ruleset_version = _ruleset.ruleset_version
        for r in _ruleset.evaluable_rules:
            rules_by_id[r.id] = {
                "id": r.id,
                "title": r.title,
                "layers": [str(ly) for ly in r.layers],
                "category": str(r.category),
                "weight": r.weight,
                "status": str(r.status),
                "convicting": r.category in CONVICTING_CATEGORIES,
                "source": r.source,
                "reads": list(r.reads),
                "predicate": r.predicate,
                "threshold": r.threshold,
            }
        _lean = ("id", "title", "layers", "category", "weight", "status", "convicting")
        rules_list = [{k: rd[k] for k in _lean} for rd in rules_by_id.values()]
    except Exception:  # pragma: no cover - registry always loads in practice; defensive only
        pass
    rules_payload: dict[str, object] = {"ruleset_version": ruleset_version, "rules": rules_list}

    @app.get(
        "/rules.json",
        tags=["Reference"],
        summary="Detection-rule registry",
        description=(
            "The full, machine-readable registry of every detection rule: `id`, `title`, the `layers` it "
            "spans, its `category`, `weight`, `status`, whether it is `convicting` (a coherence / automation "
            "/ artifact rule that can label a session a bot on its own), and its `source`. This is the same "
            "rules-as-data the detector evaluates."
        ),
        response_description="`{ruleset_version, rules[]}`.",
    )
    def rules_json() -> dict[str, object]:
        return rules_payload

    # Doc pages: render selected docs/*.md to themed HTML at request time (cached — the docs are static
    # in the image). Internal planning docs are intentionally NOT published. Built per slug below.
    docs_dir = _docs_dir()
    _doc_cache: dict[str, str] = {}
    # Drill-down data parsed once from the committed docs: per-evader verdicts + per-rule catch counts
    # (matrix.md) and the fleet (evasion-catalog.md). Missing docs degrade to empty (routes 404).
    evaders: dict[str, dict[str, object]] = {}
    rule_catch: dict[str, str] = {}
    fleet: dict[str, dict[str, str]] = {}
    techniques: dict[str, dict[str, object]] = {}
    rule_evaders: dict[str, list[str]] = {}
    rule_bypassed: dict[str, list[str]] = {}
    with contextlib.suppress(OSError):
        evaders, rule_catch = parse_matrix((docs_dir / "matrix.md").read_text(encoding="utf-8"))
    with contextlib.suppress(OSError):
        _ecat = (docs_dir / "evasion-catalog.md").read_text(encoding="utf-8")
        fleet = parse_fleet(_ecat)
        techniques = parse_techniques(_ecat)  # full tell lists + EVADES status
        rule_evaders = reverse_index(techniques)  # rule_id -> evaders it caught
        rule_bypassed = bypass_index(techniques, rules_by_id)  # rule_id -> layer-active evaders it missed

    def _item_list(slugs: list[str], prefix: str, name: str) -> list[dict[str, object]]:
        """A schema.org ItemList of drill-down links — lets crawlers see the catalog's members."""
        return [
            {
                "@type": "ItemList",
                "name": name,
                "numberOfItems": len(slugs),
                "itemListElement": [
                    {"@type": "ListItem", "position": i + 1, "url": f"{SITE_ORIGIN}{prefix}{s}", "name": s}
                    for i, s in enumerate(slugs)
                ],
            }
        ]

    def _make_doc_route(slug: str, filename: str, title: str, desc: str) -> Callable[[], HTMLResponse]:
        def doc_page() -> HTMLResponse:
            if slug not in _doc_cache:
                # Every page is a curated, mobile-first view. detections/how-it-works/research are built
                # from data or hand-authored copy; matrix/evasions parse their committed doc's key table.
                page_type, extra_ld = "WebPage", None
                keywords = SEO_KEYWORDS
                if slug == "detections":
                    body = render_detections_page(rules_list)
                    page_type = "CollectionPage"
                    keywords = f"{SEO_KEYWORDS}, detection rules, coherence engine"
                    extra_ld = _item_list([str(r["id"]) for r in rules_list], "/detections/", "Kitsune detection rules")
                elif slug == "how-it-works":
                    body = render_how_it_works_page()
                    page_type = "TechArticle"
                    keywords = f"{SEO_KEYWORDS}, cross-layer coherence, architecture"
                elif slug == "research":
                    _ev_caught = sum(1 for e in evaders.values() if str(e.get("verdict", "")).strip() == "bot")
                    body = render_research_page(len(rules_list), _ev_caught, len(evaders))
                    page_type = "TechArticle"
                    keywords = f"{SEO_KEYWORDS}, arms-race findings, research"
                elif slug == "evasions":
                    body = render_evasions_page(evaders)  # all 96 configs, from the parsed matrix
                    page_type = "CollectionPage"
                    keywords = f"{SEO_KEYWORDS}, anti-detect tools, stealth browsers"
                    extra_ld = _item_list(sorted(evaders), "/evasions/", "Kitsune evasion catalog")
                elif slug == "matrix":
                    try:
                        text = (docs_dir / filename).read_text(encoding="utf-8")
                    except OSError as exc:
                        raise HTTPException(status_code=404, detail="doc unavailable") from exc
                    body = render_matrix_page(text)
                    page_type = "CollectionPage"
                    keywords = f"{SEO_KEYWORDS}, coverage matrix"
                    extra_ld = _item_list(sorted(evaders), "/evasions/", "Kitsune detection matrix")
                else:
                    # General docs (fleet/Skulk, frontier, …): render the committed markdown as-is.
                    try:
                        text = (docs_dir / filename).read_text(encoding="utf-8")
                    except OSError as exc:
                        raise HTTPException(status_code=404, detail="doc unavailable") from exc
                    body = render_markdown_doc(text)
                    page_type = "TechArticle"
                    keywords = f"{SEO_KEYWORDS}, {title.lower()}"
                _doc_cache[slug] = render_doc_page(
                    title, desc, f"/{slug}", body, page_type=page_type, keywords=keywords, extra_ld=extra_ld
                )
            return HTMLResponse(_doc_cache[slug])

        return doc_page

    for _slug, (_fn, _title, _desc) in DOC_PAGES.items():
        app.add_api_route(
            f"/{_slug}",
            _make_doc_route(_slug, _fn, _title, _desc),
            response_class=HTMLResponse,
            include_in_schema=False,
        )

    @app.get("/detections/{rule_id}", response_class=HTMLResponse, include_in_schema=False)
    def detection_detail(rule_id: str) -> HTMLResponse:
        rule = rules_by_id.get(rule_id)
        if rule is None:
            raise HTTPException(status_code=404, detail="no such detection")
        body = render_detection_detail(
            rule, rule_catch.get(rule_id), rule_evaders.get(rule_id), rule_bypassed.get(rule_id)
        )
        rid = str(rule["id"])  # trusted registry id, not the raw path param
        title = str(rule.get("title") or rid)
        desc = f"{title} — a Kitsune cross-layer bot-detection check."
        noindex = not rule.get("source")  # thin (no provenance) -> keep out of the index
        kw = f"{SEO_KEYWORDS}, {rid}, {rule.get('category', '')} detection"
        return HTMLResponse(
            render_doc_page(
                title, desc, f"/detections/{rid}", body or "", noindex, page_type="TechArticle", keywords=kw
            )
        )

    @app.get("/evasions/{slug}", response_class=HTMLResponse, include_in_schema=False)
    def evasion_detail(slug: str) -> HTMLResponse:
        # Validate the path param to a safe slug charset first — junk 404s. Then route it through
        # html.escape (the recognised HTML sanitizer): a no-op for a validated `[a-z0-9-]` slug, but it
        # provably strips any HTML-significant character before the value reaches the title / description /
        # keywords / canonical URL / JSON-LD sinks.
        if not _SAFE_SLUG.fullmatch(slug):
            raise HTTPException(status_code=404, detail="no such evader")
        body = render_evasion_detail(slug, evaders.get(slug), fleet.get(slug), techniques.get(slug), rules_by_id)
        if body is None:
            raise HTTPException(status_code=404, detail="no such evader")
        safe = html.escape(slug, quote=True)
        desc = f"Is {safe} detectable? Kitsune's verdict and the tells that caught it."
        kw = f"{SEO_KEYWORDS}, {safe}, anti-detect, evasion"
        return HTMLResponse(
            render_doc_page(safe, desc, f"/evasions/{safe}", body, page_type="TechArticle", keywords=kw)
        )

    @app.get(
        "/inspect/{session_id}",
        tags=["Detection"],
        summary="Session wire fingerprint",
        description=(
            "The public, de-identified network/wire view for a session — TLS (JA3/JA4), HTTP-2, QUIC, the "
            "TCP/IP-OS fingerprint, and IP reputation, as read by the edge from the raw connection. "
            "**Cookie-scoped:** you can only inspect the session your own `ks_sid` cookie is bound to."
        ),
    )
    def inspect(session_id: str, ks_sid: str | None = Cookie(default=None)) -> dict[str, object]:
        # The public, de-identified wire view the live page reads. Cookie-scoped: you may only inspect the
        # session your OWN ks_sid cookie names — so it can show you your own IP/JA4/TCP without exposing
        # anyone else's. (/session, which returns raw signals for any id, stays admin-gated.)
        if ks_sid is None or not hmac.compare_digest(ks_sid, session_id):
            raise HTTPException(status_code=403, detail="inspect is limited to your own session")
        session = store.get_session(session_id)
        if session is None:
            raise HTTPException(status_code=404, detail="no session")

        def netval(kind: str) -> object | None:
            v = session.value(Layer.network, kind)
            return None if v is MISSING else v

        wire: dict[str, object | None] = {
            "ja3": netval("ja3"),
            "ja4": netval("ja4"),
            "ja4t": netval("ja4t"),
            "tls_ext_order": netval("tls_ext_order"),
            "tls_cipher_order": netval("tls_cipher_order"),
            "quic_transport_params": netval("quic_transport_params"),
            "http_version": netval("http_version"),
            "tls_extras": netval("tls_extras"),
            "tcp": netval("tcp"),
            "tcp_os": netval("tcp_kernel"),
            "h2": netval("h2"),
            "quic": netval("quic_observed"),
        }
        contradictions: list[dict[str, object]] = []
        verdict = store.get_verdict(session_id)
        if verdict is not None:
            wire_layers = {Layer.network, Layer.reputation}
            for c in verdict.contradictions:
                if any(ly in wire_layers for ly in c.layers):
                    contradictions.append(
                        {
                            "rule_id": c.rule_id,
                            "category": str(c.category),
                            "detail": c.detail,
                            "weight": c.weight,
                            "layers": [str(ly) for ly in c.layers],
                        }
                    )
        basis = "|".join(f"{k}={wire[k]}" for k in sorted(wire) if wire[k])
        ip = netval("observed_ip")
        ip_str = ip if isinstance(ip, str) else None
        return {
            "session_id": session_id,
            "ip": ip,
            "geo": geo_lookup(ip_str),
            "reputation": detector.classify_ip(ip_str) if ip_str else None,
            "wire": wire,
            "wire_fp": _fnv1a(basis) if basis else None,
            "network_contradictions": contradictions,
        }

    def _apply_signals(signals: list[Signal]) -> list[Verdict]:
        # Correlate signals into their sessions, merge with what the store already holds, and re-score. Shared by
        # /ingest (edge/collector signals) and the arena relay's solve-anomaly join (a detector-sourced tell).
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

    @app.post(
        "/ingest",
        response_model=list[Verdict],
        tags=["Detection"],
        summary="Score signals → verdict",
        description=(
            "The core endpoint. POST a list of collector `Signal` envelopes (browser + behavioural signals "
            "from JavaScript; the edge adds the network-layer signals for the session). Signals are "
            "correlated into their session, merged with anything already stored, and re-scored.\n\n"
            "Returns a `Verdict` per session: the `label` (`human` / `suspicious` / `bot` / `verified`), the "
            "`score` and `incoherence_score`, the per-layer `layer_scores`, and the `contradictions` that "
            "fired (each with its `rule_id`, `category`, `weight` and a human `detail`). A session is only "
            "labelled `bot` when a **convicting** contradiction fires — a single odd value never convicts."
        ),
        response_description="One `Verdict` per session found in the posted signals.",
    )
    def ingest(signals: list[Signal]) -> list[Verdict]:
        return _apply_signals(signals)

    @app.get(
        "/session/{session_id}",
        response_model=Session,
        dependencies=[Depends(require_admin)],
        include_in_schema=False,  # operator inspection endpoint — token-gated, kept off the public API docs
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
        include_in_schema=False,  # operator inspection endpoint — token-gated, kept off the public API docs
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
        include_in_schema=False,  # operator inspection endpoint — token-gated, kept off the public API docs
    )
    def scoreboard() -> list[Verdict]:
        return store.list_verdicts()

    return app
