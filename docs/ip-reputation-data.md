# ip-reputation/data — the producer for the reputation layer

IP reputation (datacenter ASN, proxy/VPN/Tor exit) is the commercial anti-bot *backbone* (see
`docs/landscape.md`), and it was Kitsune's thinnest layer: the rules existed but nothing produced their
signals. This is the feed — a pure-stdlib CIDR classifier (`detector/ip_reputation.py`) that matches the
observed source IP against curated public lists and emits `reputation.asn_is_datacenter` /
`reputation.is_proxy_exit` at score time. No paid API, in keeping with the self-contained lab.

## Sources (curation targets)

| List | Role | Source / license |
|---|---|---|
| Cloud / hosting ranges | `datacenter` | AWS/GCP/Azure publish their ranges; [client9/ipcat](https://github.com/client9/ipcat) + [firehol datacenters](https://github.com/firehol/blocklist-ipsets) aggregate them (public) |
| Tor exit nodes | `proxy_exit` | [Tor bulk exit list](https://check.torproject.org/torbulkexitlist) (public, refreshed hourly) |
| VPN / proxy egress | `proxy_exit` | [X4BNet/lists_vpn](https://github.com/X4BNet/lists_vpn), firehol anonymizers (public) |

## What's committed vs fetched

- **Committed seeds** (`detector/src/kitsune_detector/data/*.txt`): a small, non-exhaustive set of
  well-known hosting CIDRs (`datacenter_cidrs.txt`) so the producer works out of the box; the proxy list
  (`proxy_exit_cidrs.txt`) ships **empty** — real Tor/VPN exits are dynamic public IPs that go stale within
  hours, and RFC 5737 test ranges can't stand in (they're `is_private`). One CIDR per line; `#` comments.
- **Never committed:** the full multi-thousand-CIDR lists. The refresh tool
  `python -m kitsune_detector.ip_reputation_refresh`
  (`detector/src/kitsune_detector/ip_reputation_refresh.py`) fetches them from the sources above into the
  same seed format — run it at deploy time, not at commit. The classifier is list-agnostic: populate and
  it just works. The fetch is injectable so the parse/normalise logic is unit-tested offline against the
  real AWS/GCP/Tor payload shapes; a live run (re-validated 2026-06-19 against the current sources) pulls
  ~11.6k datacenter (AWS + GCP) and ~1.2k Tor CIDRs. Output stays uncommitted (stale-prone, large); the
  curated seeds remain the documented fallback.
- **Fail-loud on source drift.** The offline parser tests use fixed sample payloads, so a live source
  silently changing its URL or JSON shape would pass CI yet make the parse collapse to ~0 — quietly writing
  a near-empty seed and degrading `rep.*` with no error. To catch exactly that, the deploy path
  (`main`) enforces conservative per-source floors (`_PRODUCTION_FLOORS` = Tor ≥ 100, AWS ≥ 1000, GCP ≥ 100,
  ~10× below the live counts) and raises `SourceDriftError` naming the drifted source rather than degrading
  silently. The pure `refresh()` keeps its floor-free signature (`min_counts` opt-in) for the offline tests.

## Behaviour & guarantees

- `IPReputation.classify(ip)` → `(is_datacenter, is_proxy_exit)`. Private/loopback/link-local and invalid
  IPs short-circuit to `(False, False)` — a LAN/container address (the lab's own `172.x`) is never flagged,
  so the local corpus shows these rules quiet; they fire on a real public datacenter/exit IP.
- Wired in `Detector._with_derived`: enriches any session carrying `network.observed_ip`, so
  `rep.datacenter_asn` and `rep.known_proxy_exit` (now **active**, v0.48.0) fire like any other tell.
- The cross-layer payoff: a datacenter/proxy source IP combined with the WebRTC real-IP leak
  (`net.webrtc_ip_vs_observed`) and the coordination scorer's residential-proxy-fleet signal is the
  distributed-botnet picture — now with a live reputation input instead of a dormant rule.

Linear CIDR scan is fine for a seed; a production-scale list would swap in a prefix trie behind the same
`classify` interface.
