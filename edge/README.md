# edge/ — network-layer fingerprinter + session minter (Go)

The first hop. The edge **terminates TLS, captures the raw ClientHello and the lower-layer
fingerprints _below_ the application layer**, mints the `ks_sid` session id that threads every
layer, forwards `network.*` signals to the detector's `/ingest`, and reverse-proxies the request to
the app. The point: these are client-_stack_ choices (TLS handshake bytes, the HTTP/2 preface, the
TCP SYN, the QUIC Initial) that a JS/UA spoofer running in the page **cannot change** — so an h2 or
TLS fingerprint that contradicts the User-Agent is a coherence break the detector can score.

Go is the right tool here: the TLS-fingerprinting ecosystem (utls, the JA4 spec) is Go-native.

## What it fingerprints, per layer

| Layer | Captured | Computed |
|---|---|---|
| **TLS** | raw ClientHello off the live socket (peek-and-replay, `internal/peek`) | **JA3** (MD5, `ja3.go`) · **JA4** (FoxIO spec, `ja4.go`) · GREASE presence (`grease.go`, RFC 8701) · post-quantum key share — X25519MLKEM768 `0x11EC` / Kyber768-draft `0x6399` (`keyshare.go`) |
| **HTTP/2** | connection preface — SETTINGS, WINDOW_UPDATE, PRIORITY, pseudo- and regular-header order (`h2.go`/`h2parse.go`) | Akamai h2 fingerprint string · engine from pseudo-header order (Chrome `m,a,s,p` · Firefox `m,p,a,s` · Safari `m,s,p,a`) · independent SETTINGS-profile engine · JA4H regular-header order (Sec-CH-UA-before-user-agent ⇒ Chromium) |
| **TCP/IP** | client SYN, where capturable (`internal/tcpfp`, needs `CAP_NET_RAW`) | p0f-style OS-kernel family from TCP option order — `linux`/`darwin`/`windows` (`tcpip.go`); keys on option order, not the trivially-mangled TTL |
| **QUIC / HTTP-3** | client Initial datagram, drawn by an `Alt-Svc: h3` advert (`internal/proxy/quiccapture.go`) | RFC 9001 Initial decrypt → the carried TLS 1.3 ClientHello (`quic.go`); reassembles multi-packet CRYPTO frames |
| **HTTP/2 DoS** | live frame-type counts over the connection (`h2frames.go`) | rapid-reset (CVE-2023-44487) · CONTINUATION flood (CVE-2024-27316) · control-frame floods (CVE-2019-9515/9512) |

The TLS, HTTP/2 and QUIC parsers are fed raw bytes off arbitrary client sockets, so they are
strictly bounds-checked: malformed input returns `ErrMalformed`, never a panic.

## Signals it emits

Everything is emitted as contract-shaped `network`-layer `Signal` envelopes (`internal/signal`,
mirroring `contracts/signal.schema.json`), keyed by `session_id`, `source: "edge"`, and POSTed as a
JSON array to `<detector>/ingest`. Beyond the raw fingerprints (`ja3`, `ja4`, `h2`, the
`*_browser_hint`/`*_settings_hint`/`*_os_hint` classifications), the proxy derives cross-layer
**tells** that pair a spoofable claim against an unspoofable observation, for example:

- `tls_no_grease`, `tls_no_pq_keyshare` — a modern-browser UA over a handshake missing GREASE / the
  post-quantum group a current Chrome (≥131) ships.
- `h2_engine_unknown`, `h2_header_order_non_chromium` — a browser UA over an HTTP/2 stack matching no
  known engine, or a Chromium UA whose header order isn't Chromium-shaped.
- `quic_observed`, `quic_no_grease`, `quic_no_pq_keyshare` — the QUIC analogs of the TLS tells.
- `tcp_kernel` + `ua_kernel` — the SYN-revealed OS kernel vs. the kernel the UA claims.
- `h2_rapid_reset`, `h2_continuation_flood`, `h2_control_flood` — DoS attribution, flagged for the
  session the abusing connection carries.
- HTTP-header tells: `sec_fetch_missing`, `accept_encoding_no_brotli`, `accept_language_primary`,
  `observed_ip`, and the Sec-CH-UA group (`ch_platform_header`, `ch_ua_browser`,
  `ch_ua_version_mismatch`, `ch_ua_mobile_mismatch`, `ch_ua_no_grease_brand`).
- Raw wire-order + micro-tell fingerprints JA4 sorts away: `tls_cipher_order`, `tls_ext_order` (the
  raw ClientHello extension/cipher order, GREASE normalized to `g` so placement survives — a pinned
  TLS template emits a fixed/Chrome-impossible order), `tls_extras` (ECH/ALPS/padding presence,
  cert-compression, key_share groups actually sent), `ja4t` (the SYN-derived TCP-options fingerprint
  from the kernel store), and `quic_transport_params` (the QUIC Initial's transport-parameter set).

The edge only emits these facts; the coherence rules that score them live in the detector.

### Declared-identity verification

A few signals don't fingerprint the stack — they check a client's _declared_ identity against an
unforgeable proof, so a known-key failure is a definitive impostor rather than a probabilistic tell:

- `fake_declared_crawler` — a UA claiming Googlebot/Bingbot/etc. whose connecting IP does **not**
  forward-confirm (FCrDNS) to that crawler's official domain. This is the crawlers' own documented
  verification method, so a real crawler always confirms; a transient DNS failure abstains.
- `web_bot_auth_verified` / `web_bot_auth_invalid` — Web Bot Auth (RFC 9421 HTTP Message Signatures,
  Ed25519) verification by `internal/webbotauth`. A request that **presents** a `web-bot-auth`
  signature verifying against a key we hold marks a verified benign agent (`_verified`); one whose
  signature **fails** against a held key — forged, tampered, or replayed past its `expires` window —
  is a definitive forgery (`_invalid`). An unknown keyid is unjudgeable and never convicts, keeping
  the tell FP-safe against legit agents whose JWKS directories the edge doesn't hold. (The lab seeds
  the RFC 9421 Ed25519 test key; production wires the real fetched agent directories.)

## How it runs

`cmd/edge` has two modes, chosen by env:

- **Transparent reverse proxy** (`KITSUNE_BACKEND` set): terminates TLS with an ephemeral
  self-signed cert (CN/SAN `localhost`,`edge`), peeks the ClientHello, mints/keeps `ks_sid` (Secure,
  SameSite=Lax, _not_ HttpOnly so the in-page collector can read it), serves HTTP/2 via its own ALPN
  handler (so the ClientHello + h2 fingerprint survive onto each request), best-effort starts the
  TCP-SYN sniffer and the QUIC capturer, forwards signals, and proxies to the backend. Missing
  `CAP_NET_RAW` or a UDP-bind failure degrades gracefully — those signals are simply omitted.
- **Fingerprint API** (no `KITSUNE_BACKEND`): an HTTP handler that fingerprints a posted ClientHello
  and forwards signals (`internal/proxy/handler.go`).

Config: `KITSUNE_EDGE_ADDR` (default `127.0.0.1:8081`), `KITSUNE_DETECTOR`, `KITSUNE_BACKEND`,
`KITSUNE_JA4_HINTS` (path to a JA4→browser/OS hint DB overriding the embedded seed; `hintdb.go`).

```sh
KITSUNE_DETECTOR=http://127.0.0.1:8080 KITSUNE_BACKEND=http://127.0.0.1:8080 go run ./cmd/edge
```

## Build & test

```sh
go vet ./... && gofmt -l .
go test ./... -cover        # internal/fingerprint ~97%
```

CI additionally smoke-fuzzes every adversarial-input parser (ClientHello, h2 preface, h2 frame
scanner, SYN, QUIC Initial) for 20s each, so a regression that lets malformed client bytes panic the
edge — itself a DoS — is caught before it ships.

Go (1.26) may not be installed locally; build/test in `docker run --rm golang:1.26-alpine`.

## Layout

| Package | Role |
|---|---|
| `internal/fingerprint` | All the parsers + fingerprint math: ClientHello → JA3/JA4, GREASE, PQ key share, HTTP/2 preface + JA4H, TCP SYN, QUIC Initial decrypt, h2 DoS frame scanner. Also holds `slowhttp.go`'s `SlowLorisScanner` (HTTP/1.1 partial-header / slowloris timing) — **built and tested but not yet wired into the h1 read path**. |
| `internal/peek` | Capture-and-replay listener that reads the ClientHello off the socket before the TLS server handshakes. |
| `internal/proxy` | TLS-terminating reverse proxy + ALPN h2 serving, QUIC capture, signal derivation/forwarding; the fingerprint-API handler. |
| `internal/signal` | Build contract-shaped `network` signal envelopes; POST them to `/ingest`. |
| `internal/webbotauth` | Verify Web Bot Auth request signatures (RFC 9421 HTTP Message Signatures, Ed25519) against a keyid→public-key directory; RFC 7638 JWK thumbprints. Emits `web_bot_auth_verified` / `web_bot_auth_invalid`. |
| `internal/session` | Mint the 128-bit correlation id; name the `ks_sid` cookie. |
| `internal/tcpfp` | Linux raw-socket SYN sniffer + a TTL-windowed source-IP→kernel store. |
| `cmd/edge` | Service entrypoint (proxy mode / fingerprint-API mode). |
