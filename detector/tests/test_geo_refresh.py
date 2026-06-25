# detector/tests/test_geo_refresh — verify the keyless DB-IP Lite geo-database refresh.
# Offline: an injected fetcher returns canned gzipped MMDB blobs; asserts month fallback, validation, drift.

from __future__ import annotations

import gzip
from datetime import date

import pytest

from kitsune_detector.geo_refresh import (
    GeoSourceDriftError,
    decompress_and_validate,
    edition_url,
    month_candidates,
    refresh,
)

# A minimal blob that passes the validator: >= the size floor and ending in the MaxMind metadata marker.
_VALID_MMDB = b"\x00" * 1_000_001 + b"\xab\xcd\xefMaxMind.com"
_VALID_GZ = gzip.compress(_VALID_MMDB)


def test_month_candidates_current_then_previous() -> None:
    assert month_candidates(date(2026, 6, 15)) == ["2026-06", "2026-05"]


def test_month_candidates_january_rolls_back_a_year() -> None:
    assert month_candidates(date(2026, 1, 3)) == ["2026-01", "2025-12"]


def test_edition_url() -> None:
    assert edition_url("dbip-asn-lite", "2026-06") == ("https://download.db-ip.com/free/dbip-asn-lite-2026-06.mmdb.gz")


def test_decompress_and_validate_accepts_a_real_mmdb() -> None:
    assert decompress_and_validate(_VALID_GZ) == _VALID_MMDB


@pytest.mark.parametrize(
    "gz",
    [
        b"",  # failed/empty fetch
        b"not gzip at all",  # an HTML error page served in place of the .gz
        gzip.compress(b"too small"),  # below the size floor
        gzip.compress(b"\x00" * 1_000_001),  # big enough but missing the MaxMind marker
    ],
)
def test_decompress_and_validate_rejects_bad_blobs(gz: bytes) -> None:
    assert decompress_and_validate(gz) is None


def test_refresh_uses_current_month_when_available() -> None:
    seen: list[str] = []

    def fetch(url: str) -> bytes:
        seen.append(url)
        return _VALID_GZ  # every URL serves a valid DB

    out = refresh(fetch, today=date(2026, 6, 10))
    assert set(out) == {"dbip-city-lite.mmdb", "dbip-asn-lite.mmdb"}
    assert all(v == _VALID_MMDB for v in out.values())
    # current month is tried first, and since it succeeds the previous month is never fetched
    assert all("2026-06" in u for u in seen)
    assert not any("2026-05" in u for u in seen)


def test_refresh_falls_back_to_previous_month() -> None:
    def fetch(url: str) -> bytes:
        return _VALID_GZ if "2026-05" in url else b""  # current month 404s, previous is live

    out = refresh(fetch, today=date(2026, 6, 1))
    assert out["dbip-city-lite.mmdb"] == _VALID_MMDB
    assert out["dbip-asn-lite.mmdb"] == _VALID_MMDB


def test_refresh_raises_when_no_month_has_a_valid_db() -> None:
    def fetch(url: str) -> bytes:
        return b"<html>404</html>"  # every candidate serves an error page

    with pytest.raises(GeoSourceDriftError):
        refresh(fetch, today=date(2026, 6, 10))


def test_refresh_survives_a_fetch_exception_then_falls_back() -> None:
    def fetch(url: str) -> bytes:
        if "2026-06" in url:
            raise TimeoutError("boom")  # a thrown fetch must not abort — try the next month
        return _VALID_GZ

    out = refresh(fetch, today=date(2026, 6, 10))
    assert out["dbip-asn-lite.mmdb"] == _VALID_MMDB
