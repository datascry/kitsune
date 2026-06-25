# tests/test_pages — the markdown-rendered doc pages (/matrix, /evasions, …).
# Covers themed rendering, per-page SEO, the nav, sitemap inclusion, and a missing-doc 404.

from __future__ import annotations

import json
import re

import pytest
from fastapi.testclient import TestClient

from kitsune_detector.app import DOC_PAGES, create_app


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app())


def _ld(html: str) -> dict[str, object]:
    """Parse the page's JSON-LD @graph block (raises if absent or malformed)."""
    m = re.search(r'<script type="application/ld\+json">(.*?)</script>', html, re.S)
    assert m, "no JSON-LD on page"
    return json.loads(m.group(1))


@pytest.mark.parametrize("slug", list(DOC_PAGES))
def test_doc_page_has_full_seo_head(client: TestClient, slug: str) -> None:
    html = client.get(f"/{slug}").text
    # Open Graph + Twitter completeness (site_name, locale, image dims/alt, explicit twitter:image).
    for marker in (
        'property="og:site_name" content="Kitsune"',
        'property="og:locale" content="en_US"',
        'property="og:image:width"',
        'property="og:image:alt"',
        'name="twitter:image"',
        "max-image-preview:large",
    ):
        assert marker in html, f"{slug} missing {marker}"
    # Structured data: a @graph with WebSite + Organization + breadcrumb.
    graph = _ld(html)["@graph"]
    types = {n.get("@type") for n in graph}  # type: ignore[union-attr]
    assert {"WebSite", "Organization", "BreadcrumbList"} <= types


def test_catalog_pages_emit_itemlist(client: TestClient) -> None:
    # The catalog pages enumerate their drill-downs as a schema.org ItemList for crawlers.
    for slug in ("evasions", "detections", "matrix"):
        types = {n.get("@type") for n in _ld(client.get(f"/{slug}").text)["@graph"]}  # type: ignore[union-attr]
        assert "ItemList" in types and "CollectionPage" in types


def test_drilldown_pages_are_techarticles(client: TestClient) -> None:
    for path in ("/evasions/nodriver", "/detections/br.canvas_lie"):
        types = {n.get("@type") for n in _ld(client.get(path).text)["@graph"]}  # type: ignore[union-attr]
        assert "TechArticle" in types and "BreadcrumbList" in types


@pytest.mark.parametrize("slug", list(DOC_PAGES))
def test_doc_page_renders(client: TestClient, slug: str) -> None:
    r = client.get(f"/{slug}")
    assert r.status_code == 200
    html = r.text
    assert f'<link rel="canonical" href="https://kitsune.id/{slug}">' in html
    assert 'class="brand" href="/"' in html  # shared nav
    assert '<main id="main" class="doc">' in html  # main landmark (id is the skip-link target)
    assert 'class="skip-link"' in html  # bypass-blocks skip link (WCAG 2.4.1)
    assert 'aria-current="page"' in html  # active-nav indicator
    assert "<h1" in html  # the doc's title rendered from markdown


def test_doc_pages_are_curated_not_raw_dumps(client: TestClient) -> None:
    matrix = client.get("/matrix").text
    assert 'class="cards"' in matrix and "Per-rule coverage" not in matrix  # cards, not the 5-section dump
    detections = client.get("/detections").text
    assert 'class="lgrp"' in detections and "predicate" not in detections.lower()  # per-layer, no noise cols
    assert 'class="cards"' in client.get("/evasions").text


def test_detection_drilldown(client: TestClient) -> None:
    r = client.get("/detections/br.canvas_lie")
    assert r.status_code == 200
    assert "<h1" in r.text and 'href="/detections"' in r.text  # rendered + back-link
    assert client.get("/detections/nope.not.a.rule").status_code == 404


def test_evasion_drilldown(client: TestClient) -> None:
    r = client.get("/evasions/nodriver")
    assert r.status_code == 200
    assert "<h1" in r.text and "/detections/" in r.text  # tells link to detection pages
    assert client.get("/evasions/nope-not-real").status_code == 404


def test_evasion_drilldown_is_rich(client: TestClient) -> None:
    # Full convicting-tell list (not truncated) linking to detections.
    ev = client.get("/evasions/accept-lang-spoof").text
    assert ev.count('href="/detections/') >= 5
    # Frontier evaders get an EVADES callout.
    assert "evades conviction" in client.get("/evasions/camoufox-hardened").text


def test_evader_descriptions_are_curated(client: TestClient) -> None:
    # Real, hand-authored descriptions, not the terse fleet one-liner.
    assert "successor to undetected-chromedriver" in client.get("/evasions/nodriver").text
    # Mode variants resolve to the base tool's description.
    assert "patches the Gecko" in client.get("/evasions/camoufox-hardened").text


def test_evasions_list_shows_every_config(client: TestClient) -> None:
    # The list shows all matrix configs (combos + technique probes), not just the 22 fleet tools.
    page = client.get("/evasions").text
    assert "/evasions/zendriver-uach-behave" in page  # a mode combo, previously missing
    assert "/evasions/canvas-lie" in page  # a standalone technique probe
    # Every listed config carries a non-empty description (no boilerplate gaps).
    from kitsune_detector.pages import _MODE_NOTES, evader_description

    combo = evader_description("zendriver-uach-behave")
    assert "successor to nodriver" in combo and _MODE_NOTES["uach-behave"] in combo


def test_detection_drilldown_lists_caught_evaders(client: TestClient) -> None:
    d = client.get("/detections/br.headless_ua").text
    assert "Evaders it caught" in d and 'href="/evasions/' in d


def test_detection_drilldown_shows_bypassers(client: TestClient) -> None:
    # The inverse arms-race view: evaders active in the rule's layer that this check does NOT catch.
    # net.tls_ext_order_static_within_session catches only the pinned-order evader, so the many other
    # network-layer evaders (caught by sibling network tells) must appear as bypassers, linking to /evasions/.
    d = client.get("/detections/net.tls_ext_order_static_within_session").text
    assert "Bypassed by" in d
    _, _, tail = d.partition("Bypassed by")
    assert 'href="/evasions/' in tail  # the bypass section lists evader links
    # A bypasser must NOT also be in the caught list (clean partition): go-tls-static-ext is caught, not a bypass.
    assert "go-tls-static-ext" not in tail


def test_bypass_index_is_frontier_only_and_disjoint_from_caught() -> None:
    from kitsune_detector.pages import bypass_index, reverse_index

    rules = {"net.a": {"id": "net.a"}, "net.b": {"id": "net.b"}, "br.c": {"id": "br.c"}}
    tech = {
        "frontier-evades": {"verdict": "suspicious", "evades": True, "tells": ["br.c"]},  # uncaught -> bypasses a/b
        "frontier-flagged-by-a": {"verdict": "suspicious", "evades": True, "tells": ["net.a"]},  # a flags it
        "caught-bot": {"verdict": "bot", "evades": False, "tells": ["net.b"]},  # stopped -> not a bypasser
    }
    caught = reverse_index(tech)
    bypassed = bypass_index(tech, rules)
    # The frontier evader bypasses checks that didn't flag it; the bot-scored one never counts (it was stopped).
    assert bypassed["net.a"] == ["frontier-evades"]
    assert sorted(bypassed["net.b"]) == ["frontier-evades", "frontier-flagged-by-a"]
    assert "caught-bot" not in {s for v in bypassed.values() for s in v}
    # a frontier evader a rule DID flag is excluded from that rule
    assert "frontier-flagged-by-a" not in bypassed.get("net.a", [])
    # disjoint from caught
    for rid in rules:
        assert set(bypassed.get(rid, [])) & set(caught.get(rid, [])) == set()


def test_sitemap_lists_drilldowns(client: TestClient) -> None:
    sm = client.get("/sitemap.xml").text
    assert "/detections/br." in sm and "/evasions/" in sm


def test_sitemap_lists_doc_pages(client: TestClient) -> None:
    xml = client.get("/sitemap.xml").text
    for slug in DOC_PAGES:
        assert f"https://kitsune.id/{slug}" in xml


def test_doc_page_missing_doc_404(monkeypatch: pytest.MonkeyPatch, tmp_path: object) -> None:
    # Point the docs dir at an empty location -> the routes 404 rather than 500.
    monkeypatch.setenv("KITSUNE_DOCS_DIR", str(tmp_path))
    client = TestClient(create_app())
    assert client.get("/matrix").status_code == 404
