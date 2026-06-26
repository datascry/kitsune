# tests/test_app — detector test module.
# Asserts behaviour and edge cases for the unit under test.

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from kitsune_detector.app import create_app
from kitsune_detector.detector import Detector
from kitsune_detector.store import Store

from .conftest import load_example


@pytest.fixture
def client(fixed_clock) -> TestClient:
    app = create_app(detector=Detector(clock=fixed_clock), store=Store(":memory:"))
    return TestClient(app)


def _signals_from(example: str) -> list[dict]:
    session = load_example(example)
    flat: list[dict] = []
    for layer_signals in session["signals"].values():  # type: ignore[union-attr]
        flat.extend(layer_signals)
    return flat


def test_healthz(client: TestClient) -> None:
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_ingest_then_fetch(client: TestClient) -> None:
    payload = _signals_from("session_bot.json")
    resp = client.post("/ingest", json=payload)
    assert resp.status_code == 200
    verdicts = resp.json()
    assert verdicts[0]["label"] == "bot"

    fetched = client.get("/verdict/bot-001")
    assert fetched.status_code == 200
    assert fetched.json()["session_id"] == "bot-001"

    board = client.get("/scoreboard")
    assert board.status_code == 200
    assert len(board.json()) == 1


def test_verdict_404(client: TestClient) -> None:
    assert client.get("/verdict/nope").status_code == 404


def test_create_app_defaults() -> None:
    # exercise the default Detector()/Store() construction branch
    client = TestClient(create_app())
    assert client.get("/healthz").status_code == 200


def test_admin_token_gates_inspection_endpoints(fixed_clock) -> None:
    # With KITSUNE_ADMIN_TOKEN configured, the inspection endpoints require a bearer token and the
    # interactive docs are hidden; the public surface (/, /healthz, /ingest) stays open.
    app = create_app(detector=Detector(clock=fixed_clock), store=Store(":memory:"), admin_token="s3cret")
    client = TestClient(app)

    # public endpoints stay open
    assert client.get("/healthz").status_code == 200
    assert client.get("/").status_code == 200

    # inspection endpoints reject a missing or wrong token
    for path in ("/scoreboard", "/session/x", "/verdict/x"):
        assert client.get(path).status_code == 401
    assert client.get("/scoreboard", headers={"Authorization": "Bearer wrong"}).status_code == 401

    # with the right token they pass auth (then 200 / 404 on their own merits)
    h = {"Authorization": "Bearer s3cret"}
    assert client.get("/scoreboard", headers=h).status_code == 200
    assert client.get("/session/nope", headers=h).status_code == 404
    assert client.get("/verdict/nope", headers=h).status_code == 404

    # the API docs are hidden on a hardened deployment
    assert client.get("/openapi.json").status_code == 404
    assert client.get("/docs").status_code == 404


def test_index_serves_collector(client: TestClient) -> None:
    resp = client.get("/")
    assert resp.status_code == 200
    assert "navigator.webdriver" in resp.text
    assert "/ingest" in resp.text


def test_index_ships_csp_probe(client: TestClient) -> None:
    # The page must carry a CSP that forbids images, so the collector can detect a bypassed CSP
    # (an automation context that called setBypassCSP). The policy stays permissive for everything else.
    resp = client.get("/")
    csp = resp.headers.get("content-security-policy", "")
    # img-src 'self' (not 'none') so the favicon loads while the probe's data: image is still blocked.
    assert "img-src 'self'" in csp
    assert "default-src *" in csp
    assert "securitypolicyviolation" in resp.text


def test_index_has_seo_head(client: TestClient) -> None:
    html = client.get("/").text
    assert '<link rel="canonical" href="https://kitsune.id/">' in html
    assert 'property="og:image"' in html
    assert "application/ld+json" in html
    assert 'rel="icon" href="/favicon.svg"' in html


def test_static_and_crawl_routes(client: TestClient) -> None:
    assert client.get("/favicon.svg").status_code == 200
    assert client.get("/favicon.ico").status_code == 200
    assert client.get("/apple-touch-icon.png").status_code == 200
    assert client.get("/og.png").status_code == 200
    assert client.get("/site.webmanifest").status_code == 200
    robots = client.get("/robots.txt")
    assert robots.status_code == 200 and "Sitemap:" in robots.text and "/sitemap.xml" in robots.text
    sm = client.get("/sitemap.xml")
    assert sm.status_code == 200 and "<urlset" in sm.text and "<loc>" in sm.text


def test_llms_txt(client: TestClient) -> None:
    # llmstxt.org convention: H1 + blockquote summary + curated link sections, served as markdown.
    r = client.get("/llms.txt")
    assert r.status_code == 200
    assert "text/markdown" in r.headers["content-type"]
    body = r.text
    assert body.startswith("# Kitsune")
    assert "\n> " in body  # the required summary blockquote
    assert "https://kitsune.id/rules.json" in body and "https://kitsune.id/evasions" in body


def test_rules_json(client: TestClient) -> None:
    data = client.get("/rules.json").json()
    assert data["ruleset_version"]
    assert len(data["rules"]) > 50
    rule = data["rules"][0]
    assert {"id", "title", "layers", "category", "convicting"} <= set(rule)


def test_index_has_live_render_containers(client: TestClient) -> None:
    html = client.get("/").text
    for marker in (
        'id="ks-coherence"',
        'id="ks-predict"',
        'id="ks-surfaces"',
        'id="ks-fpid"',
        'id="ks-wire"',
        'id="ks-detections"',
    ):
        assert marker in html


def test_index_enumerates_all_profiled_surfaces(client: TestClient) -> None:
    # The consolidated "Fingerprint surfaces" panel must enumerate every value-bearing surface the collector
    # profiles — not just the sync rawFingerprint() subset. Assert the async-enriched surfaces are wired in.
    html = client.get("/").text
    for surface in ("Client Hints", "WebGPU", "Fonts", "Speech / media"):
        assert surface in html, surface
    assert "enumerateSurfaces" in html  # the async enricher that fills the extra surfaces


def test_index_exposes_machine_readable_result(client: TestClient) -> None:
    # Automated tools can parse the verdict from a JSON <script> tag (filled in client-side once scoring
    # completes) instead of scraping the DOM — plus a window.ksResult global and a "kitsune:result" event.
    html = client.get("/").text
    assert '<script type="application/json" id="ks-verdict">{"status":"collecting"}</script>' in html
    assert "window.ksResult" in html
    assert "kitsune:result" in html


def test_inspect_is_cookie_scoped(client: TestClient) -> None:
    # No cookie -> 403; cookie naming an absent session -> 404.
    assert client.get("/inspect/abc").status_code == 403
    assert client.get("/inspect/abc", cookies={"ks_sid": "abc"}).status_code == 404
    client.post("/ingest", json=_signals_from("session_bot.json"))
    # A cookie for a DIFFERENT session may not inspect this one.
    assert client.get("/inspect/bot-001", cookies={"ks_sid": "other"}).status_code == 403
    # Matching cookie -> the de-identified wire projection.
    d = client.get("/inspect/bot-001", cookies={"ks_sid": "bot-001"}).json()
    assert d["session_id"] == "bot-001"
    assert set(d["wire"].keys()) == {
        "ja3",
        "ja4",
        "ja4t",
        "tls_ext_order",
        "tls_cipher_order",
        "quic_transport_params",
        "http_version",
        "tls_extras",
        "tcp",
        "tcp_os",
        "h2",
        "quic",
    }
    assert "ip" in d and "network_contradictions" in d
    # Geo + IP-reputation projections accompany the wire block (reputation is None only when no IP is known).
    assert "geo" in d and "reputation" in d
    if d["ip"]:
        assert set(d["reputation"].keys()) == {"datacenter", "proxy_exit"}


def test_session_endpoint(client: TestClient) -> None:
    client.post("/ingest", json=_signals_from("session_bot.json"))
    resp = client.get("/session/bot-001")
    assert resp.status_code == 200
    assert resp.json()["session_id"] == "bot-001"
    assert client.get("/session/nope").status_code == 404


def test_ingest_accumulates_across_calls(client: TestClient) -> None:
    net = [
        {
            "schema_version": "0.1",
            "session_id": "acc",
            "layer": "network",
            "kind": "ja4",
            "value": "t13d",
            "source": "edge",
            "observed_at": "2026-06-18T00:00:00Z",
        }
    ]
    web = [
        {
            "schema_version": "0.1",
            "session_id": "acc",
            "layer": "browser",
            "kind": "webdriver",
            "value": True,
            "source": "collector",
            "observed_at": "2026-06-18T00:00:01Z",
        }
    ]
    client.post("/ingest", json=net)
    client.post("/ingest", json=web)  # must NOT clobber the network signal
    sig = client.get("/session/acc").json()["signals"]
    assert len(sig["network"]) == 1
    assert len(sig["browser"]) == 1


def test_arena_unconfigured_returns_503(client: TestClient) -> None:
    # With no KITSUNE_ARENA_URL the relay is inert — the live spine runs fine without the arena gate.
    assert client.get("/arena/challenge").status_code == 503
    assert client.post("/arena/verify", content=b"{}").status_code == 503


def test_arena_unknown_gate_rejected(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    # Gate names are whitelisted at the relay; an arbitrary value is refused before any upstream call.
    monkeypatch.setattr("kitsune_detector.app.ARENA_URL", "http://arena:8095")
    assert client.get("/arena/challenge", params={"gate": "evil"}).status_code == 400
    assert client.get("/arena/challenge", params={"gate": "hashcash"}).status_code in (200, 502)


def test_arena_page_renders(client: TestClient) -> None:
    resp = client.get("/arena")
    assert resp.status_code == 200
    body = resp.text
    assert "The Arena" in body and 'id="ks-run"' in body
    assert "not affiliated with any named vendor" in body  # the vendor-neutral disclaimer ships


def test_arena_managed_steps_up_without_session(client: TestClient) -> None:
    # No edge session / no signals → the managed ladder steps up (the conservative default).
    out = client.get("/arena/managed").json()
    assert out["decision"] == "challenge"
    assert out["label"] == "unknown"


def test_arena_managed_allows_coherent_then_challenges_bot(client: TestClient) -> None:
    # A coherent (human) session is allowed SILENTLY; an incoherent (bot) one is stepped up — the ladder.
    client.post("/ingest", json=_signals_from("session_human.json"))
    human_sid = load_example("session_human.json")["session_id"]
    out = client.get("/arena/managed", headers={"cookie": f"ks_sid={human_sid}"}).json()
    assert out["decision"] == "allow" and out["step"] == "silent" and out["label"] in ("human", "verified")

    client.post("/ingest", json=_signals_from("session_bot.json"))
    bot_sid = load_example("session_bot.json")["session_id"]
    out = client.get("/arena/managed", headers={"cookie": f"ks_sid={bot_sid}"}).json()
    assert out["decision"] == "challenge" and out["label"] == "bot"


def test_arena_captcha_guards(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    # Unconfigured → 503; an unknown captcha kind is refused before any upstream call.
    assert client.get("/arena/captcha?kind=text").status_code == 503
    monkeypatch.setattr("kitsune_detector.app.ARENA_URL", "http://arena:8095")
    assert client.get("/arena/captcha", params={"kind": "evil"}).status_code == 400
    assert client.get("/arena/captcha", params={"kind": "math"}).status_code in (200, 502)


def test_arena_page_lists_captcha_gates(client: TestClient) -> None:
    body = client.get("/arena").text
    assert 'data-gate="text"' in body and 'data-gate="math"' in body and 'data-gate="honeypot"' in body


def test_arena_slider_guards(client: TestClient) -> None:
    assert client.get("/arena/slider").status_code == 503  # unconfigured
    assert client.post("/arena/slider/verify", content=b"{}").status_code == 503
    assert 'data-gate="slider"' in client.get("/arena").text


class _FakeResp:
    def __init__(self, status: int, content: bytes) -> None:
        self.status_code = status
        self.content = content

    def json(self) -> dict:
        import json as _j

        return _j.loads(self.content)


class _FakeClient:
    """Stands in for httpx.AsyncClient so the arena relay paths are exercised without a live gate."""

    def __init__(self, *a: object, **k: object) -> None:
        pass

    async def __aenter__(self) -> _FakeClient:
        return self

    async def __aexit__(self, *a: object) -> bool:
        return False

    async def get(self, url: str, params: dict | None = None) -> _FakeResp:
        if url.endswith("/arena/slider"):
            return _FakeResp(200, b'{"kind":"slider","id":"s1","gap_x":120,"track_w":300,"piece_w":42}')
        if url.endswith("/arena/captcha"):
            return _FakeResp(200, b'{"kind":"math","id":"c1","prompt":"What is 2 + 2?"}')
        return _FakeResp(200, b'{"class":"hashcash","nonce":"abc","difficulty":12}')

    async def post(self, url: str, content: bytes | None = None, headers: dict | None = None) -> _FakeResp:
        return _FakeResp(200, b'{"ok":false}')


def test_arena_relays_forward_to_gate(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    # Mock httpx so the relay's success path (forward + return upstream body) is genuinely exercised.
    monkeypatch.setattr("kitsune_detector.app.ARENA_URL", "http://arena:8095")
    monkeypatch.setattr("kitsune_detector.app.httpx.AsyncClient", _FakeClient)
    assert client.get("/arena/challenge", params={"gate": "hashcash"}).json()["class"] == "hashcash"
    assert client.get("/arena/captcha", params={"kind": "math"}).json()["kind"] == "math"
    assert client.get("/arena/slider").json()["kind"] == "slider"
    assert client.post("/arena/verify", content=b'{"nonce":"abc","counters":[0]}').json()["ok"] is False
    assert client.post("/arena/captcha/verify", content=b'{"kind":"math","id":"c1","answer":"4"}').status_code == 200
    assert client.post("/arena/slider/verify", content=b'{"id":"s1","x":120,"trajectory":[]}').status_code == 200
    # managed step-up relays a challenge for an incoherent (no-session) caller.
    out = client.get("/arena/managed", params={"step": 1}).json()
    assert out["decision"] == "challenge" and "challenge" in out


def test_arena_captcha_new_kinds_whitelisted(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("kitsune_detector.app.ARENA_URL", "http://arena:8095")
    for kind in ("image-select", "rotate"):
        assert client.get("/arena/captcha", params={"kind": kind}).status_code in (200, 502)
    body = client.get("/arena").text
    assert 'data-gate="image-select"' in body and 'data-gate="rotate"' in body
