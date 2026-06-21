# 0005. Per-connection QUIC/HTTP-3 attribution for within-session coherence

- Status: Proposed
- Date: 2026-06-21

## Context and Problem Statement

The within-session coherence axis (see `docs/architecture.md`) catches a
client that rotates a session-invariant identity mid-session: TLS engine (`net.ja4_unstable_within_session`),
HTTP/2 stack (`net.h2_unstable_within_session`, v0.74.49), origin IP (`net.ip_rotation_within_session`), UA
string (`net.ua_rotation_within_session`), browser fingerprint (`br.fingerprint_unstable_within_session`), and
pointer trace (`bh.trace_replay_within_session`). The axis is complete across network, browser, and behavioural
layers **except for one transport: QUIC/HTTP-3.** There is no `net.quic_unstable_within_session`, and the two
QUIC *cross-layer* rules that did exist — `net.quic_grease_vs_ua` and `net.quic_pq_keyshare_vs_ua` — were
**retired** (v0.74.32 / v0.74.34) as FP-prone.

The root cause is not the rules and not the parser — it is **how the edge attributes a QUIC fingerprint to a
session.** Today (`edge/internal/proxy/quiccapture.go` + `reverseproxy.go`):

1. `reverseproxy.go` advertises `Alt-Svc: h3=":<port>"; ma=86400`, so browsers attempt QUIC.
2. `quicInitialTee.ReadFrom` captures the client's Initial packet, **keyed by source `addr.String()`**.
3. `QUICCapturer.acceptLoop` accepts the connection and **immediately closes it** ("we only wanted the
   handshake") — the edge never serves H3.
4. The browser falls back to TCP. On that TCP request `prepare()` reads/mints `ks_sid` from the cookie, then
   `FingerprintByIP(observed_ip)` retrieves the QUIC hello captured **from the same IP** and emits the `quic_*`
   signals against that `ks_sid`.

So a QUIC fingerprint reaches a session **only by matching source IP** between the (closed) QUIC attempt and a
later TCP request. This has three consequences that make any QUIC-derived conviction — including a within-session
rotation rule — unsafe:

- **NAT cross-attribution.** Two QUIC fingerprints from one IP are indistinguishable between *one client rotating
  its QUIC stack* and *two clients behind one NAT/CGNAT*. A rotation rule would convict the NAT. This is exactly
  the confound cited when the two cross-layer QUIC rules were retired.
- **Single-shot capture.** Because the connection is closed after the Initial, a real flow yields at most **one**
  QUIC hello — within-session *rotation* cannot even be elicited from a genuine browser.
- **No grounding.** Real browsers only attempt h3 on a second connection after the Alt-Svc advert, and forced-QUIC
  over the edge's **self-signed** cert has never produced a usable captured hello in-sandbox — browsers silently
  refuse h3 over an untrusted cert (no click-through interstitial as there is for TLS). So neither a real-browser
  zero-FP negative nor an evader rotation positive can be produced, and the project's GROUNDED-LIVE bar (an evader
  positive **and** a zero-FP fleet sweep before a net rule ships) is unreachable.

The QUIC *parser* is not the problem: `fingerprint.ParseQUICInitials` already reassembles a multi-packet Initial
(it stitches CRYPTO fragments sharing a DCID, handling the post-quantum-keyshare-exceeds-one-packet case).

## Decision Drivers

- **Per-session, not per-IP, attribution** — the within-session rules are FP-safe precisely because they key on
  `ks_sid`; QUIC must do the same to join the axis.
- **GROUNDED-LIVE discipline** — no net rule ships without an evader positive and a zero-FP fleet sweep
  (ADR-0001/0003 culture). A QUIC rule that cannot be grounded must not ship, regardless of how plausible.
- **QUIC connection migration** — a client may change source address mid-connection; address-keying silently
  breaks, connection-ID-keying survives.
- **Reuse, don't rebuild** — the multi-packet parser and the TCP path's session-minting/forwarding logic already
  exist; the rework should reuse them.
- **Leverage** — fixing attribution unblocks three rules at once: revive `net.quic_grease_vs_ua` and
  `net.quic_pq_keyshare_vs_ua`, and add `net.quic_unstable_within_session`.

## Considered Options

- **A. Status quo (per-IP bridge).** Keep eliciting-and-closing; attribute by `FingerprintByIP`. Rejected: the
  NAT confound, single-shot capture, and ungroundability are intrinsic to it — the reason the QUIC rules are
  already retired.
- **B. Tighten the IP bridge** (shorter tee TTL, exact host:port match instead of IP-only). Rejected: narrows the
  window but does not remove the NAT confound (clients behind one NAT share host, vary port) and still yields a
  single hello per flow — rotation remains unobservable.
- **C. Per-connection attribution: serve H3 and key the Initial by connection ID.** Chosen — see below.

## Decision Outcome

Chosen: **Option C — per-connection QUIC attribution.** The edge serves HTTP/3 for real (rather than
elicit-and-close) so the `ks_sid` cookie arrives *on the QUIC connection itself*, and the captured Initial is
keyed by **QUIC connection ID (DCID)** rather than source address.

Implementation outline (edge, Go; detector, Python):

1. **Serve H3.** Replace `acceptLoop`'s immediate-close with an `http3.Server` reverse-proxying to the backend —
   H3 parity with the TCP path in `reverseproxy.go`. Reuse `prepare()`'s session-mint/cookie/forward logic; the
   ClientHello peek is replaced by the connection's captured Initial fingerprint.
2. **Key the tee by DCID.** Re-key `quicInitialTee` from `addr.String()` to the client-chosen DCID (already
   present in the Initial). Correlate it to the quic-go connection via the `quic.Config.Tracer` ODCID hook, and
   stash the fingerprint on the connection context. This also makes attribution **migration-safe**.
3. **Emit per request.** On each H3 request, recover the connection's Initial fingerprint and emit `quic_*`
   signals against the request's `ks_sid` (via the existing `quicTells`).
4. **Detector accumulator + rule.** Add a collapse-surviving `quic_seen` set in `ingest` (mirroring `h2_seen`) →
   `network.quic_unstable` → a sticky `net.quic_unstable_within_session` rule (≥2 distinct QUIC fingerprints under
   one `ks_sid`). Per-connection attribution then also lets `net.quic_grease_vs_ua` / `net.quic_pq_keyshare_vs_ua`
   be revived without the NAT FP.

**This ADR does not authorise shipping any QUIC rule.** Rule promotion stays gated on GROUNDED-LIVE evidence,
which is **out-of-sandbox** and is the binding precondition:

- a **browser-trusted certificate** (mkcert local CA in the trust store, or a real domain cert) so a real
  Chromium actually completes an h3 handshake and sends `ks_sid` over QUIC — the zero-FP negative; and
- a **QUIC rotation evader** — a uTLS/quic-go analog of `go-tls KS_H2ROTATE` that opens ≥2 QUIC connections under
  one `ks_sid` with distinct QUIC stacks — the positive.

What is buildable and gradable in-sandbox (Docker `golang:1.26-alpine`): the plumbing (DCID-keyed tee,
`http3.Server` proxy, Initial↔connection correlation, the ingest accumulator + rule) with **synthetic-packet unit
tests** (craft Initials as `quic_test.go` does, drive two connections, assert correlation + rotation). That proves
the code correct but is **not** grounding; the rule must not be promoted from `experimental` until grounded on a
trusted-cert host with real QUIC traffic.

### Consequences

- Good: QUIC becomes a first-class transport — `ks_sid`-attributed, migration-safe — closing the last
  within-session-axis gap and reviving two retired cross-layer rules; removes the NAT cross-attribution FP class.
- Good: the parser is already done, so the work is attribution + serving, not fingerprinting.
- Bad / cost: multi-day Go effort, not one iteration; the edge now *serves* H3 (new attack/maintenance surface and
  a coupling to quic-go's tracer API and connection-migration semantics) rather than only sniffing it.
- Bad / cost: grounding is gated on a browser-trusted cert and real QUIC traffic — unavailable in the headless
  sandbox — so the rule cannot ship from CI/sandbox alone; it requires a dev host or a real-traffic capture, the
  same external boundary as the Tier-3 frontiers.
