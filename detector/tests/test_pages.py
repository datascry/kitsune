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


def test_sitemap_lists_doc_pages(client: TestClient) -> None:
    xml = client.get("/sitemap.xml").text
    for slug in DOC_PAGES:
        assert f"https://kitsune.id/{slug}" in xml


def test_doc_page_missing_doc_404(monkeypatch: pytest.MonkeyPatch, tmp_path: object) -> None:
    # Point the docs dir at an empty location -> the routes 404 rather than 500.
    monkeypatch.setenv("KITSUNE_DOCS_DIR", str(tmp_path))
    client = TestClient(create_app())
    assert client.get("/matrix").status_code == 404
