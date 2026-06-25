# 0007. Keyless deploy-time geo enrichment via DB-IP Lite

- Status: Accepted
- Date: 2026-06-26

> Supersedes the manual MaxMind GeoLite2 licence-key path for the default geo databases. GeoLite2 is
> retained as a filename **fallback**, not as the primary source.

## Context and Problem Statement

The detector's wire panel enriches a session's origin IP with country/city/ASN from an MMDB pair
(`detector/.../geo.py`). The original path read MaxMind's `GeoLite2-City.mmdb` / `GeoLite2-ASN.mmdb`,
which require a (free) MaxMind account and a **licence key** to download. That key gate meant the
databases were never actually fetched in any reproducible deploy — geo enrichment shipped **dark**:
the code was present and tested, but the panel never resolved a real city/ASN because no keyed
download step could run unattended in CI or a fresh environment.

## Decision Drivers

- **Reproducibility** — a fresh deploy must populate the geo DBs with no human obtaining/pasting a
  licence key, the same bar as the rest of the harness.
- **Schema compatibility** — keep the MaxMind MMDB record schema so `geo.py` and its tests are
  unchanged, and an operator who *does* mount a GeoLite2 pair still works.
- **Licence honesty** — any third-party data must carry its required attribution, surfaced in the UI.

## Considered Options

- **A. Keep GeoLite2 + automate the keyed download.** Rejected: still needs an account + licence key
  in the environment; can't run keyless in CI or a clean clone.
- **B. Drop geo enrichment** until a key is provisioned. Rejected: the panel feature and its tests
  already exist; the only missing piece is a keyless data source.
- **C. Keyless DB-IP Lite, GeoLite2 as fallback.** Chosen — see below.

## Decision Outcome

Chosen: **Option C.** A new `detector/.../geo_refresh.py` (`python -m kitsune_detector.geo_refresh`,
run by the `geo-refresh` compose companion at deploy) pulls **DB-IP's free Lite** City + ASN editions —
**keyless**, no account, no licence key — into `KITSUNE_GEOIP_DIR` as `dbip-city-lite.mmdb` /
`dbip-asn-lite.mmdb` (output is not committed). `geo.py` tries the DB-IP filenames **first**, then
falls back to `GeoLite2-City.mmdb` / `GeoLite2-ASN.mmdb`, so an operator-mounted GeoLite2 pair still
resolves. Both editions share the MaxMind MMDB record schema, so the reader and its tests are
unchanged. DB-IP Lite is **CC BY 4.0**; the required attribution — *"IP Geolocation by DB-IP"* — is
shown in the page footer.

### Consequences

- Good: geo enrichment goes **live** in any deploy/CI with no key handling; the keyed MaxMind path
  becomes an optional, operator-mounted fallback rather than a hard prerequisite.
- Bad / cost: **attribution is mandatory** — the CC BY 4.0 *"IP Geolocation by DB-IP"* credit must
  stay in the footer; removing it breaks the licence.
- Bad / cost: **monthly refresh** — DB-IP Lite republishes on the 1st of each month and the download
  URL embeds the month (`dbip-city-lite-YYYY-MM.mmdb.gz`), so the refresh must re-run to stay current;
  a stale DB silently ages.
- Bad / cost: **footprint** — the Lite City database is roughly ~130 MB on disk, materially larger than
  the prior dark/no-data state; it is fetched at deploy and not committed.
