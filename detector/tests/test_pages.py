# tests/test_pages — the markdown-rendered doc pages (/matrix, /evasions, …).
# Covers themed rendering, per-page SEO, the nav, sitemap inclusion, and a missing-doc 404.

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from kitsune_detector.app import DOC_PAGES, create_app


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app())


@pytest.mark.parametrize("slug", list(DOC_PAGES))
def test_doc_page_renders(client: TestClient, slug: str) -> None:
    r = client.get(f"/{slug}")
    assert r.status_code == 200
    html = r.text
    assert f'<link rel="canonical" href="https://kitsune.id/{slug}">' in html
    assert 'class="brand" href="/"' in html  # shared nav
    assert '<main class="doc">' in html
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
