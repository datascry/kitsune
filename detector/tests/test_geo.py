# tests/test_geo — City+ASN MMDB enrichment (DB-IP Lite default, GeoLite2 fallback).
# Covers record formatting, the DB-backed lookup path, and graceful degradation with no DB configured.

from __future__ import annotations

from pathlib import Path

import pytest

from kitsune_detector import geo


def test_format_geo_shapes_records() -> None:
    city = {"country": {"names": {"en": "Canada"}}, "city": {"names": {"en": "Toronto"}}}
    asn = {"autonomous_system_number": 13335, "autonomous_system_organization": "Cloudflare"}
    assert geo.format_geo(city, asn) == {
        "country": "Canada",
        "city": "Toronto",
        "asn": "AS13335",
        "asn_org": "Cloudflare",
    }


def test_format_geo_empty_is_none() -> None:
    assert geo.format_geo(None, None) is None
    assert geo.format_geo({}, {}) is None


def test_lookup_without_db_is_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("KITSUNE_GEOIP_DIR", raising=False)
    geo._readers.clear()
    assert geo.lookup("1.1.1.1") is None
    assert geo.lookup(None) is None
    geo._readers.clear()


def test_lookup_with_db(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    (tmp_path / "GeoLite2-City.mmdb").write_bytes(b"x")
    (tmp_path / "GeoLite2-ASN.mmdb").write_bytes(b"x")

    class FakeReader:
        def __init__(self, rec: dict) -> None:
            self.rec = rec

        def get(self, ip: str) -> dict:
            return self.rec

    def fake_open(path: str) -> FakeReader:
        if "City" in path:
            return FakeReader({"country": {"names": {"en": "Canada"}}, "city": {"names": {"en": "Toronto"}}})
        return FakeReader({"autonomous_system_number": 13335, "autonomous_system_organization": "Cloudflare"})

    monkeypatch.setenv("KITSUNE_GEOIP_DIR", str(tmp_path))
    monkeypatch.setattr(geo.maxminddb, "open_database", fake_open)
    geo._readers.clear()
    g = geo.lookup("1.1.1.1")
    assert g is not None and g["country"] == "Canada" and g["asn"] == "AS13335"
    geo._readers.clear()


def test_lookup_reads_dbip_filenames(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # The keyless deploy default: geo.geo_refresh writes dbip-city-lite.mmdb / dbip-asn-lite.mmdb, and
    # lookup resolves them (DB-IP records share the GeoLite2 schema, so format_geo is unchanged).
    (tmp_path / "dbip-city-lite.mmdb").write_bytes(b"x")
    (tmp_path / "dbip-asn-lite.mmdb").write_bytes(b"x")

    class FakeReader:
        def __init__(self, rec: dict) -> None:
            self.rec = rec

        def get(self, ip: str) -> dict:
            return self.rec

    def fake_open(path: str) -> FakeReader:
        if "city" in path:
            return FakeReader({"country": {"names": {"en": "Germany"}}, "city": {"names": {"en": "Berlin"}}})
        return FakeReader({"autonomous_system_number": 3320, "autonomous_system_organization": "Deutsche Telekom"})

    monkeypatch.setenv("KITSUNE_GEOIP_DIR", str(tmp_path))
    monkeypatch.setattr(geo.maxminddb, "open_database", fake_open)
    geo._readers.clear()
    g = geo.lookup("84.0.0.1")
    assert g == {"country": "Germany", "city": "Berlin", "asn": "AS3320", "asn_org": "Deutsche Telekom"}
    geo._readers.clear()
