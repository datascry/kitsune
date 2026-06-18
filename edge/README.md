# edge/ — network capture (Go)

The first hop. Terminates/inspects TLS, computes the **JA3/JA4** fingerprint from the raw
ClientHello, mints the **`session_id`** that threads every layer, and forwards network `Signal`s to
the detector's `/ingest`. Go is the right tool here (the whole TLS-fingerprinting ecosystem is Go)
and is the project's deliberate Go ramp.

## Layout

| Package | Role |
|---|---|
| `internal/fingerprint` | Raw ClientHello parser + **JA3** (MD5) and **JA4** (FoxIO spec) computation; GREASE filtering; pluggable JA4→browser/OS hint table. |
| `internal/signal` | Build contract-shaped network `Signal` envelopes (JSON the detector accepts). |
| `internal/session` | Mint the correlation id; name the `ks_sid` cookie. |
| `internal/proxy` | HTTP handler: fingerprint a posted ClientHello, forward signals to the detector. |
| `cmd/edge` | Service entrypoint. |

## Develop

```sh
go test ./... -cover      # fingerprint 97% · proxy 97% · signal 100%
go vet ./... && gofmt -l .
KITSUNE_DETECTOR=http://127.0.0.1:8080 go run ./cmd/edge
```

## Scope (honest)

- **Done:** byte-accurate ClientHello parsing → JA3/JA4, session correlation, signal emission, and a
  `/fingerprint` HTTP endpoint that forwards to the detector. Fully unit-tested.
- **Deferred (M1):** the transparent **TCP peek-and-proxy** that captures the ClientHello off a live
  socket and reverse-proxies to the app (the [`read-tls-client-hello`](https://github.com/httptoolkit/read-tls-client-hello)
  / [`utls`](https://github.com/refraction-networking/utls) technique), plus the **HTTP/2 (Akamai)**
  fingerprint. The JA4→browser/OS **hint table** is loaded by `hintdb.go` (embedded seed +
  `KITSUNE_JA4_HINTS` file override) and is now seeded with **real captured fingerprints** (go-tls's
  forged Chrome, httpx) — so the network layer recognises them live (`ja4_browser_hint` /
  `ja4_os_hint` populate, enabling the cross-layer coherence rules). Capture more by observing known
  clients via the detector's `GET /session/{id}`. (Nice property observed: JA3 varies with GREASE
  between runs; JA4 is stable — which is why JA4 is the better signal.)

### Known limitation

Network capture works for non-browser clients (httpx, uTLS/go-tls handshake cleanly through the
peek-proxy). Real **Chromium** currently sends a `certificate_unknown` TLS alert to the self-signed
edge (the page still loads via Playwright's `ignoreHTTPSErrors`, so browser/behavioral signals are
captured, but the **network** signals for browser sessions are not). Fixing the edge cert/handshake
for browsers is a tracked follow-up; it does not affect the non-browser network path.

This is **tier-2** coverage per the testing strategy (network IO), gated lower than the core logic;
the fingerprint engine itself is held to the core ≥95% bar.
