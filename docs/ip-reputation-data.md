# ip-reputation/data — the producer for the reputation layer

IP reputation (datacenter ASN, proxy/VPN/Tor exit) is the commercial anti-bot *backbone* (see
`docs/landscape.md`), and it was Kitsune's thinnest layer: the rules existed but nothing produced their
signals. This is the feed — a pure-stdlib CIDR classifier (`detector/ip_reputation.py`) that matches the
observed source IP against curated public lists and emits `reputation.asn_is_datacenter` /
`reputation.is_proxy_exit` at score time. No paid API, in keeping with the self-contained lab.

## Sources (curation targets)

| List | Role | Source / license | Wired? |
|---|---|---|---|
| Cloud / hosting ranges | `datacenter` | AWS `ip-ranges.json` + GCP `cloud.json` (public, authoritative) | ✅ refresh |
| Datacenter / hosting (broad) | `datacenter` | [X4BNet/lists_vpn](https://github.com/X4BNet/lists_vpn) `output/datacenter/ipv4.txt` (**MIT**, ~42k CIDRs — hosting beyond AWS/GCP) | ✅ refresh |
| Oracle Cloud (OCI) ranges | `datacenter` | Oracle `public_ip_ranges.json` (public, authoritative) — additive, **best-effort / floor-free** | ✅ refresh |
| DigitalOcean ranges | `datacenter` | DigitalOcean `geo/google.csv` (public; fetched with a browser UA, the default agent gets a 403) — additive, **best-effort / floor-free** | ✅ refresh |
| Cloudflare ranges | `datacenter` | Cloudflare `ips-v4` + `ips-v6` (public, authoritative) — additive, **best-effort / floor-free** | ✅ refresh |
| Fastly ranges | `datacenter` | Fastly `public-ip-list` (public, authoritative) — additive, **best-effort / floor-free** | ✅ refresh |
| VPN / proxy egress | `proxy_exit` | [X4BNet/lists_vpn](https://github.com/X4BNet/lists_vpn) `output/vpn/ipv4.txt` (**MIT**, ~11k CIDRs) | ✅ refresh |
| Tor exit nodes | `proxy_exit` | [Tor bulk exit list](https://check.torproject.org/torbulkexitlist) (public, refreshed hourly) | ✅ refresh |
| Open proxies / anonymizers (broader) | `proxy_exit` | [firehol blocklist-ipsets](https://github.com/firehol/blocklist-ipsets) `firehol_proxies`/`firehol_anonymous` (GPLv2 **aggregate of mixed-license upstreams** — per-source vetting required before redistribution) | ⏳ candidate (license-vet first) |
| GreyNoise actor enrichment | `datacenter` / `proxy_exit` (actor/intent) | [GreyNoise GNQL](https://docs.greynoise.io/) per-IP `classification`/`actor`/`tag`/`spoofable` (radar **X8**) — richer than static CIDRs; needs an API key + deploy-time egress | ⏳ external candidate (needs key) |

X4BNet's MIT licence is stated in the repo README and explicitly covers "the list itself (source files and
generated output)", so it is safe to fetch and redistribute — unlike the FireHOL aggregate, whose component
feeds carry mixed (some non-redistributable) upstream licences and so stay a documented candidate, not a
wired source, until per-source vetting clears them.

The four additive cloud/CDN datacenter feeds (Oracle / DigitalOcean / Cloudflare / Fastly) widen the
`datacenter` slice past AWS+GCP+X4BNet but are **best-effort, floor-free**: a client connecting *from* these
is provider-side egress (a bot on the provider's compute), never a real eyeball, so they fold in FP-safely,
and unlike the load-bearing core sources they carry **no** `_PRODUCTION_FLOORS` entry — a single one being
down/403 is skipped without aborting the refresh (the datacenter list is already large without them). Azure
is intentionally omitted: its Service-Tags JSON URL rotates weekly behind a portal redirect and needs a
discovery step (tracked in `docs/research-radar.md`). The GreyNoise X8 row is an external candidate — an
actor/intent feed that would ground the otherwise-synthetic `rep.*` rules — gated on an API key + egress.

## What's committed vs fetched

- **Committed seeds** (`detector/src/kitsune_detector/data/*.txt`): a small, non-exhaustive set of
  well-known hosting CIDRs (`datacenter_cidrs.txt`) so the producer works out of the box; the proxy list
  (`proxy_exit_cidrs.txt`) ships **empty** — real Tor/VPN exits are dynamic public IPs that go stale within
  hours, and RFC 5737 test ranges can't stand in (they're `is_private`). One CIDR per line; `#` comments.
- **Never committed:** the full multi-thousand-CIDR lists. The refresh tool
  `python -m kitsune_detector.ip_reputation_refresh`
  (`detector/src/kitsune_detector/ip_reputation_refresh.py`) fetches them from the sources above into the
  same seed format — run it at deploy time, not at commit (the operator-facing `iprep-refresh` companion
  and its monthly cron are in [`deploy.md`](deploy.md)). The classifier is list-agnostic: populate and
  it just works. The fetch is injectable so the parse/normalise logic is unit-tested offline against the
  real AWS/GCP/Tor/X4BNet payload shapes; a live run pulls ~11.6k cloud datacenter (AWS + GCP, 2026-06-19)
  plus ~42k X4BNet datacenter and ~11k X4BNet VPN + ~1.2k Tor CIDRs (X4BNet validated 2026-06-21). Output
  stays uncommitted (stale-prone, large); the curated seeds remain the documented fallback.
- **Fail-loud on source drift.** The offline parser tests use fixed sample payloads, so a live source
  silently changing its URL or JSON shape would pass CI yet make the parse collapse to ~0 — quietly writing
  a near-empty seed and degrading `rep.*` with no error. To catch exactly that, the deploy path
  (`main`) enforces conservative per-source floors (`_PRODUCTION_FLOORS` = Tor ≥ 100, AWS ≥ 1000, GCP ≥ 100,
  X4BNet VPN ≥ 1000, X4BNet datacenter ≥ 1000 — ~10× below the live counts) and raises `SourceDriftError`
  naming the drifted source rather than degrading silently. The pure `refresh()` keeps its floor-free
  signature (`min_counts` opt-in) for the offline tests.

## Behaviour & guarantees

- `IPReputation.classify(ip)` → `(is_datacenter, is_proxy_exit)`. Private/loopback/link-local and invalid
  IPs short-circuit to `(False, False)` — a LAN/container address (the lab's own `172.x`) is never flagged,
  so the local corpus shows these rules quiet; they fire on a real public datacenter/exit IP.
- Wired in `Detector._with_derived`: enriches any session carrying `network.observed_ip`, so
  `rep.datacenter_asn` and `rep.known_proxy_exit` (both `status: active` — see the generated
  [`detection-catalog.md`](detection-catalog.md) / `contracts/rules/registry.yaml`) fire like any other tell.
- The cross-layer payoff: a datacenter/proxy source IP combined with the WebRTC real-IP leak
  (`net.webrtc_ip_vs_observed`) and the coordination scorer's residential-proxy-fleet signal is the
  distributed-botnet picture — now with a live reputation input instead of a dormant rule.

Linear CIDR scan is fine for a seed; a production-scale list would swap in a prefix trie behind the same
`classify` interface.
