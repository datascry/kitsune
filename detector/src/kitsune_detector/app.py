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
import os
import re
from collections.abc import Callable
from pathlib import Path

import httpx
from fastapi import Cookie, Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse, Response
from starlette.middleware.gzip import GZipMiddleware

from .arena_page import ARENA_PAGE
from .coherence.rules import load_registry
from .demo import DEMO_PAGE
from .detector import Detector
from .geo import lookup as geo_lookup
from .models import MISSING, Layer, RuleCategory, Session, Signal, Verdict
from .pages import (
    bypass_index,
    parse_fleet,
    parse_matrix,
    parse_techniques,
    render_detection_detail,
    render_detections_page,
    render_doc_page,
    render_evasion_detail,
    render_evasions_page,
    render_how_it_works_page,
    render_matrix_page,
    render_research_page,
    reverse_index,
)
from .store import Store

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
}


def _docs_dir() -> Path:
    env = os.environ.get("KITSUNE_DOCS_DIR")
    return Path(env) if env else Path(__file__).resolve().parents[3] / "docs"


#: Categories that can convict a session as a bot (the rest only corroborate).
CONVICTING_CATEGORIES = {RuleCategory.coherence, RuleCategory.automation, RuleCategory.artifact}


def _fnv1a(s: str) -> str:
    """FNV-1a (32-bit) hex — the same hash the client uses, so IDs are comparable across layers."""
    h = 2166136261
    for ch in s:
        h = ((h ^ ord(ch)) * 16777619) & 0xFFFFFFFF
    return format(h, "x")


#: Canonical public origin — used for robots/sitemap absolute URLs and the page's canonical/OG tags.
SITE_ORIGIN = "https://kitsune.id"
#: Base keyword set woven into every doc page's structured data (each page appends its own specifics).
SEO_KEYWORDS = (
    "bot detection, browser fingerprinting, antidetect browser, TLS JA3 JA4, HTTP/2 fingerprint, "
    "QUIC fingerprint, TCP/IP fingerprint, automation detection, headless browser detection"
)
#: /llms.txt — the llmstxt.org convention: a concise, link-first map of the site for LLM agents (H1 +
#: blockquote summary + curated sections). Mirrors the SEO head's structured data in a plain-text form.
LLMS_TXT = """# Kitsune

> Kitsune is a bot detection ⇄ evasion lab: a blue-team detector and a red-team anti-detect evader
> fleet, run against each other to produce a per-layer scoreboard. The live page fingerprints a
> visitor's browser across every layer — TLS/JA4, HTTP/2, QUIC, TCP/IP, the JavaScript runtime and
> behavior — correlated at the edge, and returns a real bot-detection verdict. Its thesis: catch the
> incoherence across layers, not any single signal.

## Live tool
- [Bot-detection & fingerprint test](https://kitsune.id/): fingerprints this browser and returns a live
  verdict (human / suspicious / bot) across every layer.

## Get the result as JSON (programmatic access)
- In the live page: after scoring, the full verdict is embedded as JSON in the
  `<script type="application/json" id="ks-verdict">` tag and mirrored on `window.ksResult` (a
  `kitsune:result` DOM event also fires). It starts as `{"status":"collecting"}`; poll until `status`
  is `"complete"`. Fields: `status`, `label`, `score`, `incoherence_score`, `layer_scores`,
  `contradictions[]` (rule_id, category, weight, detail), `session_id`, and a `wire` block
  (`ja3`, `ja4`, `h2`, `tcp_os`, `quic`, `ip`, `geo`, `reputation`).
- `POST https://kitsune.id/ingest`: send collector signal envelopes; the response is the same verdict JSON.
- [Rule registry (JSON)](https://kitsune.id/rules.json): the full machine-readable detection-rule registry
  (rule id, title, layers, category, and whether each rule can convict).

## Documentation
- [How it works](https://kitsune.id/how-it-works): the cross-layer incoherence thesis and the signal layers.
- [Detection catalog](https://kitsune.id/detections): every detection rule and the exact signal it exploits.
- [Evasion catalog](https://kitsune.id/evasions): every anti-detect tool and technique tested, with verdicts.
- [Coverage matrix](https://kitsune.id/matrix): every detection rule x every evader.
- [Research](https://kitsune.id/research): findings from the detection-vs-evasion arms race.

## Source
- [Source on GitHub](https://github.com/datascry/kitsune): MIT — detector, edge, collector, evader fleet.
"""

#: Static brand assets (favicon set, OG card, web manifest), served at the URL root.
STATIC_DIR = Path(__file__).parent / "static"

#: The public arena challenge-gate (the owned `arena/` Go service). The detector relays /arena/challenge and
#: /arena/verify to it so a visitor hits ONE origin (through the edge) — the gate verdict then joins the
#: detector's coherence verdict client-side on ks_sid. Empty/unset → the arena routes return 503 (the live
#: spine runs fine without it). Gate names are whitelisted; the gate itself only ever talks to itself.
ARENA_URL = os.environ.get("KITSUNE_ARENA_URL", "").rstrip("/")
_ARENA_GATES = frozenset({"hashcash", "many-small", "memory-hard", "cap"})
#: Evader slugs are lowercase-alphanumeric-with-dashes. Validating the path param to this charset before
#: it reaches any HTML/SEO sink both 404s junk URLs and removes the reflected-XSS taint (no <, ", etc.).
_SAFE_SLUG = re.compile(r"[a-z0-9][a-z0-9-]{0,80}")


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

    # The pages are inline-everything HTML (the homepage is ~149 KB of mostly text); gzip cuts the wire
    # transfer ~70-87% and makes the per-page repeated CSS nearly free. minimum_size skips tiny JSON bodies.
    app.add_middleware(GZipMiddleware, minimum_size=700)

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

    @app.get("/arena", response_class=HTMLResponse)
    def arena() -> HTMLResponse:
        # The public arena page: solve an owned PoW gate in-browser, see the gate verdict + the detector's
        # coherence verdict side by side. Same permissive CSP as the home page (inline script + subtle crypto).
        resp = HTMLResponse(ARENA_PAGE)
        resp.headers["Content-Security-Policy"] = (
            "default-src * data: blob: 'unsafe-inline' 'unsafe-eval'; img-src 'self'"
        )
        return resp

    # --- Arena relay: forward the challenge/verify protocol to the owned arena gate (KITSUNE_ARENA_URL),
    # so a visitor reaches the gate on the SAME origin (through the edge) and the gate verdict can join the
    # detector verdict on ks_sid. The detector never imports the gate — it speaks HTTP, contracts-only. ---
    @app.get("/arena/challenge", include_in_schema=False)
    async def arena_challenge(gate: str = "hashcash", difficulty: int | None = None) -> Response:
        if not ARENA_URL:
            raise HTTPException(status_code=503, detail="arena gate not configured")
        if gate not in _ARENA_GATES:
            raise HTTPException(status_code=400, detail="unknown gate")
        params = {"gate": gate}
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

    @app.get("/llms.txt", include_in_schema=False)
    def llms_txt() -> PlainTextResponse:
        # llmstxt.org: a link-first site map for LLM agents. Markdown served as text/plain per the convention.
        return PlainTextResponse(LLMS_TXT, media_type="text/markdown; charset=utf-8")

    @app.get("/sitemap.xml", include_in_schema=False)
    def sitemap() -> Response:
        urls = ["/"] + [f"/{slug}" for slug in DOC_PAGES]
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

    @app.get("/rules.json")
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
                else:
                    try:
                        text = (docs_dir / filename).read_text(encoding="utf-8")
                    except OSError as exc:
                        raise HTTPException(status_code=404, detail="doc unavailable") from exc
                    body = render_matrix_page(text)
                    page_type = "CollectionPage"
                    keywords = f"{SEO_KEYWORDS}, coverage matrix"
                    extra_ld = _item_list(sorted(evaders), "/evasions/", "Kitsune detection matrix")
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

    @app.get("/inspect/{session_id}")
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
