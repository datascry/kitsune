# detector/geo — optional City+ASN geo enrichment for the wire panel (DB-IP Lite, GeoLite2-compatible).
# Reads MMDBs from KITSUNE_GEOIP_DIR when present; degrades to None otherwise.

"""Optional geo/ASN lookup over a MaxMind-format MMDB pair (City + ASN).

The wire panel shows the visitor their own IP; with a City + ASN MMDB pair mounted at
``KITSUNE_GEOIP_DIR`` it also resolves city/country/ASN. The default databases are DB-IP Lite
(``dbip-city-lite.mmdb`` / ``dbip-asn-lite.mmdb``), which :mod:`kitsune_detector.geo_refresh` pulls
keyless at deploy time; MaxMind's ``GeoLite2-City.mmdb`` / ``GeoLite2-ASN.mmdb`` are also read as a
fallback so an operator-mounted GeoLite2 pair still works. Both follow the same record schema, so the
parser below is source-agnostic. The databases are NOT committed (size + licence); without them every
lookup degrades to ``None`` so the feature is purely additive. Attribution is required when geo is
displayed: DB-IP Lite is CC BY 4.0 ("IP Geolocation by DB-IP"), shown in the page footer.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

try:
    import maxminddb
except ImportError:  # pragma: no cover - maxminddb is a declared dependency; guarded for safety
    maxminddb = None  # type: ignore[assignment]

#: Reader cache (one entry per filename; value None means "unavailable", so we never re-stat).
_readers: dict[str, Any] = {}

#: Candidate DB filenames per edition, tried in order: DB-IP Lite (the keyless default the refresh writes)
#: first, then MaxMind GeoLite2 (so an operator-mounted GeoLite2 pair still resolves). Same record schema.
_CITY_DBS = ("dbip-city-lite.mmdb", "GeoLite2-City.mmdb")
_ASN_DBS = ("dbip-asn-lite.mmdb", "GeoLite2-ASN.mmdb")


def _first_reader(filenames: tuple[str, ...]) -> Any:
    """First openable reader among ``filenames`` (DB-IP name preferred, GeoLite2 fallback), or None."""
    for filename in filenames:
        reader = _reader(filename)
        if reader is not None:
            return reader
    return None


def _reader(filename: str) -> Any:
    if filename in _readers:
        return _readers[filename]
    reader: Any = None
    base = os.environ.get("KITSUNE_GEOIP_DIR")
    if base and maxminddb is not None:
        path = Path(base) / filename
        if path.is_file():
            try:
                reader = maxminddb.open_database(str(path))
            except Exception:  # pragma: no cover - corrupt DB; degrade gracefully
                reader = None
    _readers[filename] = reader
    return reader


def format_geo(city: Any, asn: Any) -> dict[str, str] | None:
    """Shape raw City/ASN MMDB records (DB-IP Lite or GeoLite2) into the wire panel's geo dict, or None."""
    out: dict[str, str] = {}
    if isinstance(city, dict):
        country = ((city.get("country") or {}).get("names") or {}).get("en")
        city_name = ((city.get("city") or {}).get("names") or {}).get("en")
        if country:
            out["country"] = str(country)
        if city_name:
            out["city"] = str(city_name)
    if isinstance(asn, dict):
        num = asn.get("autonomous_system_number")
        org = asn.get("autonomous_system_organization")
        if num is not None:
            out["asn"] = f"AS{num}"
        if org:
            out["asn_org"] = str(org)
    return out or None


def lookup(ip: str | None) -> dict[str, str] | None:
    """Resolve an IP to {country, city, asn, asn_org} via the City+ASN MMDB pair, or None when unavailable."""
    if not ip or maxminddb is None:
        return None
    try:
        city_db = _first_reader(_CITY_DBS)
        asn_db = _first_reader(_ASN_DBS)
        if city_db is None and asn_db is None:
            return None
        city = city_db.get(ip) if city_db is not None else None
        asn = asn_db.get(ip) if asn_db is not None else None
        return format_geo(city, asn)
    except Exception:  # pragma: no cover - malformed IP / lookup error
        return None
