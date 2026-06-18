# primp evader

A red-team client built on [`primp`](https://github.com/deedy5/primp) — Python bindings over a Rust
`rquest`/BoringSSL core that impersonates a current Chrome's **TLS + HTTP/2 fingerprint** (GREASE, the
`X25519MLKEM768` post-quantum key share, the full `Sec-*` / client-hint header set) while running **no JS
engine**. It is the 2026 successor to `curl-impersonate` and the high-fidelity end of the network-only
impersonation family.

## What it demonstrates

`primp` wins the *fingerprint* arms race outright: its JA4 reproduces a real Chrome prefix and every
per-layer / network-coherence rule stays silent — including `net.tls_grease_vs_ua` and
`net.tls_pq_keyshare_vs_ua` (it sends both GREASE and the PQ group, so it is **not** a stale template).
It is convicted only on the two axes outside that race:

- `net.no_js_execution` — it never executes the served challenge page (there is no browser).
- `net.tcp_os_vs_ua` — its UA claims a Windows Chrome while the container's kernel is Linux.

This is the thesis end-to-end: a tool that perfectly mimics the network layers is still caught above and
below them, on properties that are not part of the fingerprint it copies.

## Run

```sh
docker compose up -d --build detector edge
docker compose --profile evaders run --rm primp
# override the impersonation profile: -e KS_IMPERSONATE=chrome_148
```

Only ever points at Kitsune's own edge/detector (see `harness/.../allowlist.py`); never a third party.
