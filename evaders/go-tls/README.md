# evaders/go-tls — forged-TLS evader (Go + uTLS)

Forges a real-browser **TLS ClientHello** with [uTLS](https://github.com/refraction-networking/utls)
so the handshake's JA3/JA4 parrots Chrome or Firefox — the network-layer attack on the detector, and
the project's Go ramp.

## What it does

`Client(helloID)` returns an `http.Client` whose HTTPS handshakes use a forged browser fingerprint
(via a custom `DialTLSContext` wrapping `utls.UClient`). `ChromeClient()` / `FirefoxClient()` are the
presets.

## Verified

`go test` spins a TLS server, captures the offered cipher suites, and asserts the forged handshake
arrives **browser-like** (>10 ciphers vs the stdlib's handful) and that Chrome ≠ Firefox fingerprints.

```sh
go mod tidy && go test ./... -cover
KITSUNE_EDGE=https://localhost:8443/healthz go run ./cmd/go-tls
```

## Note

uTLS parrots only the **ClientHello** — it does not by itself align the HTTP/2 or TCP/IP layers.
That residual is exactly the cross-layer incoherence the detector is built to flag (see
`docs/architecture.md` §2, `docs/catalog.md` §9). Tier-2 coverage (network IO).

**uTLS is pinned to v1.6.7 on purpose.** Its `HelloChrome_Auto` profile predates Chrome's post-quantum
key share, so this evader represents a real, common case — a scraper on months-old pinned deps — and keeps
a live demonstration of `net.tls_pq_keyshare_vs_ua` catching a genuine library. Current uTLS (v1.8.2) sends
`X25519MLKEM768` and evades that tell; the rule catches the lag window, not uTLS in perpetuity (see
`docs/findings.md`, "The arms race, measured").
