// arena/pact — model the PACT / Private Access Token mechanism (Privacy Pass): skip the challenge for a
// valid, anonymous proof-of-personhood token. Self-hosted issuer + verifier (Ed25519); owned infra only.

// PACT (Private Access Control Tokens — Cloudflare + Chrome/Edge/Firefox, 2026) and the Apple Private Access
// Token before it are the frontier DEFENSE: a trusted issuer that has strong knowledge of "personhood" mints
// an anonymous token; an origin then SKIPS the CAPTCHA for traffic carrying a valid one. This models the
// mechanism — an Ed25519-signed, expiring, single-use token — as the human-personhood twin of Web Bot Auth's
// good-bot identity (the two halves of "claimed identity vs cryptographic proof"). HONEST CAVEAT, as with Web
// Bot Auth: the bypass is only as strong as the issuer's personhood-proof + key secrecy. In-sandbox the issuer
// mints freely (no real attestation), so ANY client can obtain a token and skip — the documented bypass — and
// the detector still convicts the no-JS client on coherence. Real PACT issuers gate on device attestation
// (secure enclave), which is external to the lab.

package arena

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
)

// pactToken is the signed, anonymous personhood claim. It carries no identity — only a nonce (single-use) and
// an expiry — which is the privacy property: the origin learns "a trusted issuer vouched for a person", nothing more.
type pactToken struct {
	Nonce   string `json:"nonce"`
	Expires int64  `json:"expires"` // unix seconds
}

// PACTIssuer mints + verifies tokens with one Ed25519 keypair (the issuer's). Real issuers keep the private
// key secret and require proof-of-personhood before minting; this models the token mechanism, not the proof.
type PACTIssuer struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

// NewPACTIssuer generates a fresh issuer keypair.
func NewPACTIssuer() *PACTIssuer {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return &PACTIssuer{pub: pub, priv: priv}
}

// Issue mints a token valid until `expires` (unix seconds), as base64(json).base64(sig).
func (p *PACTIssuer) Issue(nonce string, expires int64) string {
	body, _ := json.Marshal(pactToken{Nonce: nonce, Expires: expires})
	sig := ed25519.Sign(p.priv, body)
	return base64.RawURLEncoding.EncodeToString(body) + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// Verify checks the signature + the expiry against `now` (unix seconds). Returns (ok, nonce, reason). It does
// NOT consume the nonce — the caller redeems it for single-use (so a token cannot be replayed).
func (p *PACTIssuer) Verify(token string, now int64) (bool, string, string) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return false, "", "malformed token"
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false, "", "bad body encoding"
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false, "", "bad signature encoding"
	}
	if !ed25519.Verify(p.pub, body, sig) {
		return false, "", "signature does not verify"
	}
	var t pactToken
	if err := json.Unmarshal(body, &t); err != nil {
		return false, "", "bad token json"
	}
	if now > t.Expires {
		return false, t.Nonce, "token expired"
	}
	return true, t.Nonce, "ok"
}
