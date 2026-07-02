# os-spoof — forge the TCP SYN option order (a spoofed kernel) with a userspace TCP stack + uTLS

`net.tcp_os_vs_ua` is the one OS-coherence tell a UA/navigator spoof can't touch: the edge sniffs the client's
TCP SYN and classifies the kernel family from its **option order** (`mss,sack…`→linux, `…nop,ws,nop,nop,sack`
→windows), which the kernel's TCP stack sets. uTLS forges the TLS ClientHello but runs *over* the kernel's
TCP, so it can't change the SYN — grounded: the go-tls (uTLS) evader gets a forged Chrome JA4 but
`tcp_kernel=linux`, the same JA4T as curl.

This tool crosses that wall. It hand-rolls a **userspace TCP stack** over `AF_PACKET` (gopacket) that emits a
caller-chosen SYN option order, layers **uTLS** on top (uTLS accepts any `net.Conn`), and makes an HTTP/1.1
request — so the edge sees a **Windows** SYN under a Windows UA. Needs `NET_RAW` (raw frames) + `NET_ADMIN`
(drop the kernel's RSTs, since userspace owns the flow).

```
docker run --rm --network kitsune_default --cap-add NET_RAW --cap-add NET_ADMIN kitsune-os-spoof
```

## Grounded result (2026-07-02)

| client | `tcp_kernel` (JA4T) | `net.tcp_os_vs_ua` |
|---|---|---|
| normal kernel TCP + Windows UA | `linux` (`64240_2-4-8-1-3_1460_7`) | **fires** — caught |
| **this tool** (forged Windows SYN + uTLS + Windows UA) | **`windows`** (`64240_2-1-3-1-1-4_1460_8`) | **silent** — beaten |

So **uTLS + a userspace TCP stack** forges the kernel the SYN reveals — the SYN forge is the userspace stack,
not uTLS. It is a raw HTTP client, so it still trips the no-browser tells (`net.no_js_execution`,
`sec_fetch_vs_ua`, `accept_encoding_vs_ua`); a *coherent* full OS spoof routes a real browser (camoufox's
Windows profile + `KS_PROVISION`) through this stack, so the kernel, network, browser and behavioral layers all
tell one OS story. The blue residual is deeper TCP *behavior* (window dynamics, retransmit timers) that a
happy-path userspace stack doesn't reproduce — a much harder fingerprint than the SYN option order.

Targets the allow-listed edge only. A red-team artifact for the OS-coherence arms race, run against Kitsune's
own detector.
