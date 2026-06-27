# Coordinating a fleet without correlation — the evasion frontier

> How an adversary coordinates a large fleet while evading Kitsune's coordination detection — and why doing it
> at scale costs as much as N genuinely independent real users. Grounded against the live detector.

Kitsune convicts a fleet only on a **binding a real diverse cohort cannot produce** (see
[`harness/coordination.py`](../harness/src/kitsune_harness/coordination.py) and the conviction gate). Per-session
detection is beatable; the coordination thesis is that a *coordinated* fleet must share **something** — unless it
pays for genuine per-node diversity at every layer, which removes its economic advantage.

## The bindings, and how to remove each

| Layer | Convicting binding | Evasion | Kitsune's reach |
|---|---|---|---|
| Fingerprint | `fp_collision` (cloned fp); `template_similarity` (one generator) | diverse, coherent fps per node | catches cloned + one-model; **real diverse-hardware fps are external-data-bound** |
| TLS / JA4 | JA4-prefix cluster | distinct JA4 per node (uTLS / mixed *builds*) | rotation alone fails — `_collision_clusters` recovers shared fp/trace/origin across rotated JA4 |
| Behavior | `trace_collision` (replay); `template_similarity` (one humanizer) | a *distinct* behavioral model per node | catches replay + one-model; **diverse generative models / real humans are the frontier** |
| Network | `shared_origin` (WebRTC leak); `ticket_reuse`; datacenter IP-rep | distinct residential proxy per node, no STUN leak, fresh TLS tickets | catches origin/ticket leaks; **real residential egress is external-data-bound** |
| Timing | lockstep / burst severity | stagger arrivals | corroborating only — never changes the conviction |

NB browser evaders (zendriver/nodriver/pydoll/camoufox) emit the **real browser JA4** (BoringSSL/NSS), shared
across a same-tool fleet — they do **not** use uTLS (that is the Go TLS-client tools: go-tls, azuretls). So a
cloned-browser fleet shares a JA4 by construction; rotating it needs different real builds or a non-browser stack.

## Grounded: the maximal in-sandbox evasion already evades conviction

The `sybil-farmer` archetype is the maximal in-sandbox correlation-evasion: camoufox ×N, each randomizing its
fingerprint per launch (distinct fps → no `fp_collision`), distinct behavioral seeds (distinct traces → no
`trace_collision` / `template_similarity`), distinct source IPs, no shared WebRTC origin or TLS ticket. The live
detector grades it (`task archetype-validate`):

```
candidate score 1.00 — "shared JA4 + JS divergence / IP spread but NO convicting coordination signal
(per-launch TLS randomization, cloned-profile collision, or shared WebRTC origin) — a real diverse cohort
on one browser build produces this shape, so capped at candidate"
```

Every convicting binding is gone. The only shared signal left is the **JA4 cipher prefix** (one browser build),
which is ambiguous (a real cohort shares it), plus corroborating-only signals (the TLS/JS paradox, IP spread,
lockstep). It **evades conviction**.

## What would still convict it — the external-data frontier

1. **IP reputation.** Those nodes ran on private container IPs (no rep flag). On real **datacenter/proxy**
   egress the `reputation.asn_is_datacenter` / `is_proxy_exit` flag corroborates the ambiguous signals →
   convicted. Beating it needs **clean residential IPs** = real residential-proxy egress (expensive, external).
2. **The JA4 prefix.** Removing the one-build cluster needs genuinely **different browser builds** per node
   (different cipher suites), not one camoufox.
3. **Fingerprints that survive `template_similarity`** need **real distinct hardware** (the real-GPU gap) or N
   distinct high-fidelity generators — not one model sampled N times.

## The bind

To do all of the above at scale is to give each node a real distinct device/GPU, a real residential IP, a
distinct build, and a distinct behavioral model — i.e. to reconstruct **N genuinely independent real users**, at
N× the cost. The fleet's economic advantage (one cloned profile behind cheap proxies) is exactly what creates a
shared binding. Kitsune does not make coordination impossible; it forces it to cost as much as N real users.

**Coordination detection is therefore an economic / external-data frontier, not an in-sandbox-solvable one.**
In-sandbox it is saturated: the diversified fleet already evades to `candidate`, and the conviction that closes
it is bound to data the lab cannot self-generate (real IP reputation, real-GPU fingerprints, real residential
egress). See [`docs/research-radar.md`](research-radar.md) for the external-data queue.
