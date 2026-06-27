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

## The distinct-builds lever (grounded)

The one remaining shared signal above is the **JA4 cipher prefix** — one browser build. The lever to drop it is
**distinct builds**: put nodes on different engines/builds so the fleet spans multiple JA4 prefixes and no single
cluster binds it. The fleet manager now reports this fragmentation (`fragmented`, per-cluster breakdown).

GROUNDED live: a mixed-engine fleet (camoufox ×2 [Firefox] + zendriver ×2 [Chrome]) **fragmented into two JA4
clusters** — and both graded `candidate`:

```
fragmented: True | outcome: evaded
  cluster candidate 1.00  members [camoufox-linux-0, camoufox-linux-1]   (Firefox JA4)
  cluster candidate 0.42  members [zendriver-uach-0, zendriver-uach-1]   (Chrome JA4)
```

So distinct builds works as a lever — the JA4 prefix no longer binds the whole fleet, and each sub-cluster is
small + uncorroborated → evades. Its in-sandbox LIMIT: real browsers give only a few engine families (Firefox /
Chrome), and a same-engine sub-fleet still collides on fp if its tool is deterministic (a Chromium clone). Full
PER-NODE distinct builds (a unique JA4 per node) needs uTLS (the Go TLS-client tools — non-browser) or many real
builds; Skulk's `fuzzy-rotate` strategy models that synthetically, and the cross-JA4 `_collision_clusters`
recovery still catches it IF any binding (fp/trace/origin/ticket) leaks. A fleet that rotates JA4 AND leaks no
binding is the pure cross-JA4 case — ungradeable in-sandbox, and external-data-bound to convict (see below).

## IPv6: the origin is the /64, not the /128

JA4 is **transport-agnostic** — the TLS ClientHello is byte-identical over IPv4 and IPv6, so every JA4/JA4H/JA4T
binding carries over unchanged. The IPv6 implication is one layer down, in the **IP-keyed** logic. Every convicting
binding above gates on ">= 2 **distinct** source IPs" (one machine over many sessions is one IP — it can't collide
with itself), and the arena rate gate keys its token bucket per IP. On IPv6 the *address* is the wrong unit: a
subscriber is handed a whole **/64** (often a /56), and a host mints unlimited **/128s** for free (SLAAC + RFC 4941
privacy addresses rotate hourly).

So the detector folds every source IP to its **origin** — the IPv4 address, or the IPv6 **/64** prefix
(`coordination._ip_origin`, applied at every distinct-IP counting site; the arena rate gate keys per /64 via
`ipOrigin`). "Distinct source IPs" means distinct origins. This closes both failure modes at once:

| | raw /128 counting (wrong) | /64 origin fold (correct) |
|---|---|---|
| **FP** — one real user, RFC 4941 privacy rotation within their /64 | N "distinct IPs" → looks like an N-node cloned fleet | 1 origin → one machine over many sessions, no collision |
| **Evasion** — rate-limit bypass / faked spread by spraying /128s in one /64 | N buckets / N apparent origins for free | 1 bucket / 1 origin — the spray buys nothing |

Grounded live (Skulk `ipv6-rotate` → live detector): a cloned fleet spraying **6 /128s across 2 /64s** scores
`fleet 1.00` with `distinct_observed_ips=2` (folded from 6 — the spray adds no apparent spread) and convicts on the
fp-collision across the two origins; the same cloned profile confined to **one /64** folds to a single origin,
fires no collision, and caps at `candidate` (the FP boundary — a single subscriber is not a coordinated fleet). The
lesson is the same economic bind as the rest of this doc: real IP spread costs **genuinely distinct /64
subscriptions** — IPv6 abundance does not hand a fleet free origins.

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
