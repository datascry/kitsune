# Privacy — Kitsune captures no visitor data

Kitsune is a bot-detection ⇄ evasion **research lab**. The public site exists to show *you* a live verdict
on *your* browser — not to collect anything about you. This page states exactly what happens to your data,
and why the claim is structurally true rather than a promise.

## The one-line version

**Nothing you send is captured.** When you load the public site, Kitsune's detector reads the signals your
browser and connection already expose (TLS/JA4, HTTP/2, TCP/IP, canvas/WebGL/audio/fonts/Client-Hints, mouse
& keystroke dynamics, your IP), scores them **in memory**, shows you the verdict, and **forgets them**. They
are never written to disk, never retained after the response, never sold, never shared, and never used to
track you across visits. There are no third-party trackers, ads, or analytics on the page.

## Why this is true, not just stated

The public deploy runs the detector with an **in-memory store** — `KITSUNE_DB=:memory:`, set in
[`docker-compose.prod.yml`](../docker-compose.prod.yml). SQLite's `:memory:` database lives in process RAM
and has **no disk file at all**; it is empty again the moment the process restarts. There is no
`detector-data` volume mounted on a public host, so there is no place for a visitor fingerprint to land even
in principle. The session a visit creates exists only long enough to correlate that visit's own signals into
one verdict and return it.

- **Detector default:** the store defaults to `:memory:` (`Store.__init__(path=":memory:")`,
  `create_app(store=Store(":memory:"))`). Persistence is strictly opt-in via `KITSUNE_DB=/path` and a volume.
- **Public overlay:** the prod overlay pins `:memory:` and declares **no** persistence volume for the
  detector — the only volume is `letsencrypt` (the TLS cert). See [deploy.md](deploy.md).
- **No client-side tracking:** the page sets a single first-party `ks_sid` cookie so repeated *re-scores
  within one visit* attach to one session; it is not a cross-site identifier and nothing is stored server-side
  past the response. No third-party scripts.

## What the detector reads (and immediately discards)

The verdict is computed from the signals listed on the page itself — the same data any website's anti-bot
already sees on every request. Kitsune just makes them visible to you and scores their **coherence**. None of
it is logged, persisted, or forwarded. Your IP is used only to look up coarse public **geo/ASN** and
**datacenter/proxy** reputation for *your* verdict (additive enrichment of the IP the connection already
carries); the lookup is in-memory and the result is shown to you, not stored.

## IP-reputation and geo data are *inbound reference lists*, not your data

The geo/ASN and IP-reputation enrichment uses **public, pre-published reference datasets** (DB-IP Lite under
CC BY 4.0; aggregated datacenter/proxy/Tor CIDR lists). These are read-only lists *about networks*, refreshed
on the operator's host — they contain **no visitor data**. They flow *in*, never out.

## Operator / research data (a separate thing, never your data)

Tier-3 grounding — evaluating edge rules on real traffic, building a real-traffic prevalence prior — is done
**only on a private research instance**, scored against the **operator's own red-team evader fleet**, on a
host that serves no real users. That is the operator deliberately persisting *their own* traffic, not the
public site retaining visitors'. Even then, only **de-identified aggregates** (a rebuilt prior, IP-reputation
counts, verdict reports) are ever committed or shared — never raw captures. This is the project's standing
data rule. See [deploy.md](deploy.md) §Tier-3 and [grounding.md](grounding.md).

## Self-hosting

Everything above is enforced by configuration you can read and run yourself. If you self-host, keep
`KITSUNE_DB=:memory:` on any instance that serves real visitors. Persistence exists for private red⇄blue
research only — turning it on for a public site would retain visitor fingerprints and is explicitly not a
supported use.

Kitsune is open source: <https://github.com/datascry/kitsune>.
