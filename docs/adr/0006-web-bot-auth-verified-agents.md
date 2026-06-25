# 0006. Web Bot Auth: cryptographic conviction and a `verified` outcome class

- Status: Accepted
- Date: 2026-06-26

## Context and Problem Statement

Every Kitsune conviction so far is **inferential**: a coherence rule fires because two layers disagree
in a way no honest client should produce. There is no rule whose firing is *proven* rather than
argued. Separately, the only outcome labels are on the human↔bot axis — a session is scored toward
`human` or `bot`. But a class of automation is **welcome**: declared, well-behaved agents
(GPTBot/ClaudeBot/Operator/Perplexity/Google/CommonCrawl). Web Bot Auth (IETF
`draft-meunier-web-bot-auth-architecture`; Cloudflare edge-live 2026-03) lets such an agent
cryptographically **sign** its requests via RFC 9421 HTTP Message Signatures over Ed25519 — covering
`@authority` (+ `signature-agent`), `tag="web-bot-auth"`, with `created`/`expires` and a `keyid` that
is the RFC 7638 JWK SHA-256 thumbprint.

This raises two questions the existing model can't express:

- Can the lab make a conviction that is a **cryptographic proof of forgery** rather than an inference?
- What happens to a session that presents a *valid* signature — i.e. proves it is a known good bot?

## Decision Drivers

- A cryptographic conviction is FP-safe **by construction** — a real signer holding the private key
  always produces a valid, in-window signature, so only an impostor can fail verification. This is the
  cleanest possible analog of `net.fake_declared_crawler`.
- A valid signature is orthogonal to the human↔bot axis: the session *is* automation, but a verified,
  welcome one — a verdict the binary score cannot represent.
- The lab is an in-sandbox demonstrator; its honesty bar requires that any "allow-list" be visibly
  contingent on its security assumption (here, signing-key secrecy) rather than presented as absolute.

## Considered Options

- **A. Treat Web Bot Auth as just another declared-identity tell**, reusing the inferential
  `fake_declared_crawler` shape (header present but UA/behaviour incoherent). Rejected: it discards the
  cryptographic proof and re-introduces the FP surface that signing exists to remove.
- **B. Cryptographic conviction only** — emit `net.web_bot_auth_invalid` on a definitive forgery, but
  keep mapping a valid signature onto the existing axis (slightly more `human`-leaning). Rejected:
  loses the orthogonal good-bot verdict and can't model an allow-list.
- **C. Cryptographic conviction *and* a new `verified` outcome class.** Chosen — see below.

## Decision Outcome

Chosen: **Option C.** The edge (`edge/internal/webbotauth`) reconstructs the RFC 9421 signature base
and verifies the Ed25519 signature against the public key the `keyid` resolves to, then:

- emits **`network.web_bot_auth_invalid`** ONLY on a **definitive forgery** — a signature that is
  *present*, whose `keyid` resolves to a key the lab *holds*, but that *fails* verification (bad/tampered
  signature, wrong `@authority`, or replay past `expires`). This drives the convicting coherence rule
  `net.web_bot_auth_invalid` (registry; lead G25). An **unknown** `keyid` is unjudgeable and never
  convicts; a real browser sends no such headers and so can never fire it.
- emits **`network.web_bot_auth_verified`** on a *valid* signature, which the detector maps to a new
  outcome label **`Label.verified`** (`detector/.../models.py`). `scoring.verified_agent` allow-lists
  such a session as a declared good bot — automation, but not convicted — **overriding** the bot
  verdict it would otherwise receive.

This is the lab's **first cryptographic conviction** (proof, not inference) and its **first non-human↔bot
outcome class**.

### Soundness boundary — only as strong as the signing key's secrecy

`Label.verified` is an **allow-list**, and an allow-list is only as strong as the secret that gates it.
`scoring.verified_agent` is sound **iff** the agent's Ed25519 *private* key stays secret: a real signer
holds it and signs live, so it alone can mint a valid, in-window signature for its `keyid`. The lab
deliberately seeds the **public** RFC 9421 test key, so in-sandbox **any** client can mint a `verified`
agent — the `go-tls KS_WEBBOTAUTH=valid` evader demonstrates exactly this **bypass**. That is a
feature: it makes the allow-list's security assumption *visible and exploitable on purpose*, rather than
asserting an allow-list is unconditionally safe. **Production** wires each agent's real fetched
directory (`/.well-known/http-message-signatures-directory` JWKS) where the private key is genuinely
secret; the lab seeds only the test key.

### Consequences

- Good: a conviction (`net.web_bot_auth_invalid`) that is FP-safe by construction — grounded in-process
  against the draft's own Appendix A.2.2 Ed25519 test vector (`edge/.../webbotauth_test.go`) and red⇄blue
  by the `go-tls KS_WEBBOTAUTH` evader (a faithful signer = verified/no-fire; a replayed stale signature
  = `web_bot_auth_invalid`).
- Good: a `verified` outcome class lets the lab model the welcome-automation verdict that the human↔bot
  axis can't express; browserforge calibration carries no network layer, so promotion can't raise the
  legit flag rate.
- Bad / cost: `Label.verified` introduces an *override* path whose safety rests entirely on key
  secrecy — explicitly demonstrated as bypassable in-sandbox via the seeded public test key. The
  allow-list is only as trustworthy as the directory/key-distribution it is wired to; that trust
  boundary must be re-examined for any production deployment.
