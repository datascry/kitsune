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
    assert set(d["wire"].keys()) == {"ja3", "ja4", "tcp", "tcp_os", "h2", "quic"}
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
