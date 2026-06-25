# Architecture Decision Records

Significant design decisions are captured here as [MADR](https://adr.github.io/madr/) records —
short, immutable documents stating the context, the options weighed, and the decision made. They
explain *why* the code is the way it is. For the system overview those decisions add up to, start
with [`docs/architecture.md`](../architecture.md).

| ADR | Title | Status | Date |
|---|---|---|---|
| [0001](0001-session-correlation-pipeline.md) | Session-correlation pipeline as the architectural keystone | Accepted | 2026-06-17 |
| [0002](0002-polyglot-with-contracts.md) | Polyglot components coupled only by versioned contracts | Accepted | 2026-06-17 |
| [0003](0003-rules-as-data-coherence.md) | Coherence rules as data, not code | Accepted | 2026-06-17 |
| [0004](0004-tiered-coverage.md) | Tiered test-coverage gates | Accepted | 2026-06-17 |
| [0005](0005-per-connection-quic-attribution.md) | Per-connection QUIC/HTTP-3 attribution for within-session coherence | Accepted | 2026-06-21 |
| [0006](0006-web-bot-auth-verified-agents.md) | Web Bot Auth: cryptographic conviction and a `verified` outcome class | Accepted | 2026-06-26 |
| [0007](0007-keyless-geo-dbip.md) | Keyless deploy-time geo enrichment via DB-IP Lite | Accepted | 2026-06-26 |

- **0001** — Bot signals live at different layers; incoherence can only be computed if they are
  joined to one interaction. Every layer emits `Signal`s tagged with a `session_id` (minted by the
  edge); the detector joins them into a `Session` and scores coherence. Correlation is the keystone,
  built and tested first.
- **0002** — Each layer wants its own ecosystem (Go for TLS, Python for scoring, TS in-browser).
  Components are polyglot and coupled *only* by the versioned `contracts/` JSON Schemas over HTTP —
  they never import each other, so any one can be rewritten behind the same schema.
- **0003** — Detection signals decay fast, so the checks churn constantly. Rules live as data in
  `contracts/rules/registry.yaml`, evaluated by a small generic engine over a fixed predicate
  vocabulary; retiring a decayed signal is a one-line `status` change, not a refactor.
- **0004** — A flat ≥95% coverage gate forces brittle mocking of inherently-IO code. Tiered gates
  instead: ≥95% on the algorithmic core (contracts, scoring, coherence, fingerprint parsing),
  integration/e2e tests at a lower gate on IO components (proxy, browser glue, evaders). See
  `docs/architecture.md` §11.
- **0005** — QUIC is the last gap in the within-session coherence axis. The edge attributed QUIC
  fingerprints *per source IP* (elicit-and-close capture), which is NAT-confounded, single-shot, and
  ungroundable — so the QUIC rules were retired and a rotation rule couldn't ship. Decision: serve H3
  and key the captured Initial by *connection ID* (`ks_sid`-attributed, migration-safe). The plumbing
  is **shipped in-sandbox** (`edge/internal/proxy/quicserver.go`'s `http3.Server` + DCID-keyed tee, the
  detector accumulator); rule promotion stays **externally gated** on out-of-sandbox GROUNDED-LIVE
  evidence (a browser-trusted cert + a QUIC rotation evader), so no QUIC rule has shipped yet.
- **0006** — Web Bot Auth (RFC 9421 HTTP Message Signatures) gives the lab its first *cryptographic*
  conviction: `net.web_bot_auth_invalid` fires only on a definitive forgery (a known key whose
  signature fails verification), FP-safe by construction. A *valid* signature instead yields a new
  outcome class `Label.verified` that allow-lists a proven good bot — sound **only** under signing-key
  secrecy, which the seeded public RFC test key deliberately demonstrates bypassing in-sandbox.
- **0007** — The manual MaxMind GeoLite2 licence-key path meant geo enrichment never went live.
  Decision: pull keyless DB-IP Lite (CC BY 4.0) City+ASN MMDBs at deploy via `geo_refresh`, with
  GeoLite2 kept as a filename fallback. Costs: mandatory *"IP Geolocation by DB-IP"* attribution,
  monthly refresh, and a ~130 MB city database.

## Writing a new ADR

- New decision → copy [`0000-adr-template.md`](0000-adr-template.md), number it next in sequence, set
  status `Accepted`, and add a row + a one-line summary above.
- Superseding a decision → add a new ADR and mark the old one `Superseded by ADR-XXXX` (don't delete;
  the history is the point).
