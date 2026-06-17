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
  fingerprint. The JA4→browser/OS **hint table** ships empty; production loads a JA4 fingerprint DB.
  Until then, coherence rules that read hints simply don't fire (no data ≠ contradiction) — see
  `docs/architecture.md` §6.

This is **tier-2** coverage per the testing strategy (network IO), gated lower than the core logic;
the fingerprint engine itself is held to the core ≥95% bar.
