# os-spoof — forge the TCP SYN option order (a spoofed kernel) with a userspace TCP stack + uTLS

`net.tcp_os_vs_ua` is the one OS-coherence tell a UA/navigator spoof can't touch: the edge sniffs the client's
TCP SYN and classifies the kernel family from its **option order** (`mss,sack…`→linux, `…nop,ws,nop,nop,sack`
→windows), which the kernel's TCP stack sets. uTLS forges the TLS ClientHello but runs *over* the kernel's
TCP, so it can't change the SYN — grounded: the go-tls (uTLS) evader gets a forged Chrome JA4 but
`tcp_kernel=linux`, the same JA4T as curl.

This tool crosses that wall. It hand-rolls a **userspace TCP stack** over `AF_PACKET` (gopacket) that emits a
chosen SYN option order, layers **uTLS** on top (uTLS accepts any `net.Conn`), and makes an HTTP/1.1 request —
so the edge sees the OS *you* pick. Needs `NET_RAW` (raw frames) + `NET_ADMIN` (drop the kernel's RSTs, since
userspace owns the flow).

## Profiles — pick or randomize; a fleet morphs into any shape

`KS_PROFILE` selects a **coherent OS profile** — a kernel SYN fingerprint (option order + TTL + window) with a
matching uTLS ClientHello and UA, so `tcp_kernel`, TLS engine, and UA all tell one OS story:

| profile | kernel (JA4T) | TLS | UA |
|---|---|---|---|
| `windows-chrome` / `windows-edge` | windows (`64240_2-1-3-1-1-4_…`) | Chrome | Windows Chrome / Edge |
| `macos-safari` / `macos-chrome` | darwin (`65535_2-1-3-1-1-8-4-0_…`) | Safari / Chrome | macOS |
| `linux-firefox` | linux (`64240_2-4-8-1-3_…`) | Firefox | Linux Firefox |
| `ios-safari` | darwin | iOS | iPhone Safari |

`KS_PROFILE=random` (the default) picks one per node, so a fleet of identical containers **morphs into any
mix of OSes** — each node coherent, the population diverse. `KS_PROFILE=list` prints the menu.

```
docker run --rm --network kitsune_default --cap-add NET_RAW --cap-add NET_ADMIN -e KS_PROFILE=windows-chrome kitsune-os-spoof
# a morphing fleet: N containers, each -e KS_PROFILE=random -> a diverse multi-OS cohort
```

## Proxy mode — route a REAL browser through the forged kernel (not camoufox-only)

`KS_MODE=proxy` runs a SOCKS5 front end (a **concurrent** userspace stack — one manager demuxes many flows).
Point any browser at it (`--proxy-server=socks5://<host>:1080`) and every flow rides the forged kernel while
the browser's OWN real TLS + JS run end to end — a fully coherent morphing node. The kernel forge is at the TCP
layer, BELOW the browser, so it is **engine-agnostic**; each profile's `Engine` names the family that pairs
coherently:

- **chromium** — nodriver / zendriver / stealth / patchright → `windows-chrome`, `macos-chrome`, …
- **firefox** — camoufox → `linux-firefox`, `macos-firefox`, `windows-firefox`
- **webkit** — Safari/iOS → `ios-safari`, `macos-safari` — now driven by `stealth`'s `KS_ENGINE=webkit` path
  (Playwright's real WebKit build); `KS_ENGINE=webkit KS_DEVICE="iPhone 15" KS_PROXY=socks5://<proxy>:1080`

Grounded: a Chromium browser (stealth) through a `windows-chrome` proxy routed with the collector running and
`tcp_kernel=windows`; camoufox through a `macos-firefox` proxy came through with `tcp_kernel=darwin` matching
its macOS-Firefox UA and `net.tcp_os_vs_ua` **silent**. Both browser families route — os-spoof is not tied to
camoufox.

**WebKit iOS composition (2026-07-02).** A real WebKit `iPhone 15` (stealth `KS_ENGINE=webkit`) routed through an
`ios-safari` proxy: `tcp_kernel=darwin`, `req_count=122` (the proxy carried WebKit's FULL session — TLS + h2 +
the collector's worker/fetch), and **`net.tcp_os_vs_ua` cleared** (kernel now matches the iOS UA). Residual:
`net.tls_grease_vs_ua` — proxy mode passes the browser's OWN TLS end-to-end, and Playwright's Linux WebKit
ClientHello ≠ real iOS Safari's GREASE/JA4. Clearing it needs a uTLS `HelloIOS` re-origination in front (the
`chain-mitm` front), not just the kernel forge. So the composed iOS node is coherent at kernel + browser +
screen/DPR/touch; the last network residual is the TLS fingerprint, which the kernel-only proxy can't reach.

**Residual:** the hand-rolled TCP is happy-path (no retransmit, static flow control) — robust enough for a
Chromium page load, but camoufox's collector POST didn't always land through it. A production morphing node
swaps this stack for a robust userspace TCP (gVisor `netstack`); the SYN-forge design is unchanged.

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
