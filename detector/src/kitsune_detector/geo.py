# detector/geo — optional GeoLite2 City+ASN enrichment for the wire panel.
# Reads MaxMind GeoLite2 DBs from KITSUNE_GEOIP_DIR when present; degrades to None otherwise.

"""Optional GeoLite2 geo/ASN lookup.

The wire panel shows the visitor their own IP; with MaxMind's GeoLite2 City + ASN databases mounted
(``KITSUNE_GEOIP_DIR`` pointing at a dir holding ``GeoLite2-City.mmdb`` / ``GeoLite2-ASN.mmdb``) it
also resolves city/country/ASN. The databases are NOT committed (size + MaxMind licence); without them
every lookup degrades to ``None`` so the feature is purely additive. Attribution is required when geo is
displayed: "This product includes GeoLite2 data created by MaxMind" (shown in the page footer).
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
    """Shape raw GeoLite2 City/ASN records into the wire panel's geo dict, or None if empty."""
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
    """Resolve an IP to {country, city, asn, asn_org} via GeoLite2, or None when unavailable."""
    if not ip or maxminddb is None:
        return None
    try:
        city_db = _reader("GeoLite2-City.mmdb")
        asn_db = _reader("GeoLite2-ASN.mmdb")
        if city_db is None and asn_db is None:
            return None
        city = city_db.get(ip) if city_db is not None else None
        asn = asn_db.get(ip) if asn_db is not None else None
        return format_geo(city, asn)
    except Exception:  # pragma: no cover - malformed IP / lookup error
        return None
