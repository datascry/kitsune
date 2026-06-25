# detector/geo_refresh — refresh the geo/ASN MMDB pair from DB-IP Lite (keyless, CC BY 4.0).
# Fetches dbip-city-lite + dbip-asn-lite at deploy into KITSUNE_GEOIP_DIR; output not committed.

"""Refresh the geo databases :mod:`kitsune_detector.geo` reads (``dbip-city-lite.mmdb`` / ``dbip-asn-lite.mmdb``).

The geo enrichment is purely additive and ships with NO database (size + licence), so without a refresh the
wire panel's geo row stays blank. This is the documented, keyless refresh path: at deploy time an operator
runs ``python -m kitsune_detector.geo_refresh`` to pull DB-IP's free **Lite** City + ASN databases —
MaxMind-format MMDBs, GeoLite2-schema-compatible (so :func:`kitsune_detector.geo.format_geo` reads them
unchanged), distributed under **CC BY 4.0** with no licence key — into ``KITSUNE_GEOIP_DIR``. This mirrors
:mod:`kitsune_detector.ip_reputation_refresh`: a self-contained, no-paid-API pull whose output is stale-prone
and large, so it is intentionally NOT committed.

The download URL embeds the month (``dbip-city-lite-YYYY-MM.mmdb.gz``); the new month publishes on the 1st,
so the refresh tries the current month then falls back to the previous one. The fetch is injectable (a
:data:`Fetcher` returning the raw ``.gz`` bytes) so the gunzip + validation is unit-tested hermetically; only
the thin network shell touches the wire. Each decompressed MMDB is validated against the MaxMind metadata
marker + a size floor, so a drifted URL / HTML error page fails LOUD rather than writing a corrupt DB.

Attribution (CC BY 4.0): "IP Geolocation by DB-IP" (https://db-ip.com) — shown in the page footer.
"""

from __future__ import annotations

import gzip
import os
import sys
from collections.abc import Callable
from datetime import date
from pathlib import Path

#: DB-IP free Lite editions: (URL edition slug, output filename geo.py reads). City carries country+city,
#: ASN carries the autonomous-system number/org — the same City+ASN pair geo.lookup resolves.
_EDITIONS = (
    ("dbip-city-lite", "dbip-city-lite.mmdb"),
    ("dbip-asn-lite", "dbip-asn-lite.mmdb"),
)
_BASE_URL = "https://download.db-ip.com/free"

#: A real MaxMind-format DB ends with this metadata marker; DB-IP Lite MMDBs carry it too. Checking for it
#: (plus a size floor) catches an HTML error page / truncated download that would otherwise write a corrupt DB.
_MMDB_MARKER = b"\xab\xcd\xefMaxMind.com"
#: Conservative floor: the smallest Lite DB (ASN) is ~9 MB decompressed; 1 MB sits far below real data yet
#: well above any error page, so a drifted source trips it instead of silently shipping a near-empty DB.
_SIZE_FLOOR = 1_000_000

_DATA_ENV = "KITSUNE_GEOIP_DIR"

#: A function that fetches a URL and returns the raw response BYTES (the gzipped MMDB). Injected so tests
#: stay offline. Returns ``b""`` on a failed fetch (the orchestration treats that as "try the next month").
Fetcher = Callable[[str], bytes]


class GeoSourceDriftError(RuntimeError):
    """A geo source produced no valid MMDB for any candidate month — its URL or format likely drifted.

    The deploy path (:func:`main`) raises this rather than writing a corrupt/empty database, so a drifted
    DB-IP URL (or an error page served in place of the ``.gz``) fails loud instead of blanking the geo row.
    """


def month_candidates(today: date) -> list[str]:
    """``[current, previous]`` ``YYYY-MM`` tags — the new month's DB publishes on the 1st, so we try the
    current month first and fall back to the previous one early in the month before it lands."""
    cur = f"{today.year:04d}-{today.month:02d}"
    py, pm = (today.year - 1, 12) if today.month == 1 else (today.year, today.month - 1)
    prev = f"{py:04d}-{pm:02d}"
    return [cur, prev]


def edition_url(edition: str, month: str) -> str:
    """Build the DB-IP Lite download URL for an edition + ``YYYY-MM`` month tag."""
    return f"{_BASE_URL}/{edition}-{month}.mmdb.gz"


def decompress_and_validate(gz: bytes) -> bytes | None:
    """Gunzip ``gz`` and return the MMDB bytes iff they look like a real MaxMind DB (marker + size floor),
    else ``None`` (a failed/empty fetch, a non-gzip error page, or a truncated/corrupt download)."""
    if not gz:
        return None
    try:
        raw = gzip.decompress(gz)
    except (OSError, EOFError):
        return None
    if len(raw) < _SIZE_FLOOR or _MMDB_MARKER not in raw[-200000:]:
        return None
    return raw


def refresh(fetch: Fetcher, *, today: date) -> dict[str, bytes]:
    """Fetch every edition via ``fetch`` and return ``{filename: mmdb_bytes}``.

    Pure but for ``fetch``. For each edition the current then previous month is tried; the first candidate
    that gunzips to a valid MMDB wins. An edition that yields no valid DB for any month raises
    :class:`GeoSourceDriftError` — so a drifted URL/format fails loud instead of shipping a corrupt DB.
    """
    months = month_candidates(today)
    out: dict[str, bytes] = {}
    for edition, filename in _EDITIONS:
        mmdb: bytes | None = None
        for month in months:
            url = edition_url(edition, month)
            try:
                gz = fetch(url)
            except Exception as exc:  # a single month's fetch failing just tries the next month
                print(f"warning: geo source fetch failed: {url} ({exc})", file=sys.stderr)
                continue
            mmdb = decompress_and_validate(gz)
            if mmdb is not None:
                break
        if mmdb is None:
            raise GeoSourceDriftError(
                f"{edition}: no valid MMDB for months {months} — its DB-IP URL or format likely drifted"
            )
        out[filename] = mmdb
    return out


def _http_get(url: str) -> bytes:  # pragma: no cover - network IO shell
    import urllib.request

    # A browser-like User-Agent: DB-IP's CDN 403s the default `Python-urllib/x` agent. These are public,
    # freely-downloadable Lite databases; the UA just clears the default-agent block.
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
            )
        },
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        return bytes(resp.read())


def main(  # pragma: no cover - IO wrapper
    fetch: Fetcher = _http_get, out_dir: Path | None = None, *, today: date | None = None
) -> None:
    """Deploy path: pull the City + ASN Lite DBs into ``KITSUNE_GEOIP_DIR`` (or ``out_dir``)."""
    target = out_dir or Path(os.environ.get(_DATA_ENV, "."))
    target.mkdir(parents=True, exist_ok=True)
    for name, content in refresh(fetch, today=today or date.today()).items():
        (target / name).write_bytes(content)
        print(f"wrote {target / name} ({len(content)} bytes)")


if __name__ == "__main__":  # pragma: no cover
    main()
