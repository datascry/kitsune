// edge/webbotauth — verify Web Bot Auth request signatures (RFC 9421 HTTP Message Signatures, Ed25519).
// The web-bot-auth tag profile: a legitimate agent signs ("@authority"[,"signature-agent"]); we verify it.

package webbotauth

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Tag is the RFC 9421 signature tag a Web Bot Auth signature carries.
const Tag = "web-bot-auth"

// clockSkew tolerates a created timestamp slightly in the future (clock drift between agent and edge).
const clockSkew = 300 * time.Second

// Result reports whether a request carried a Web Bot Auth signature and whether it verified.
type Result struct {
	Present  bool   // a Signature-Input carrying tag="web-bot-auth" was found
	Valid    bool   // the signature verified: Ed25519 OK over the RFC 9421 base AND within the created/expires window
	KnownKey bool   // the claimed keyid resolved to a public key we hold (so a failure IS a forgery, not "we can't tell")
	KeyID    string // the claimed keyid (RFC 7638 JWK SHA-256 thumbprint)
	Nonce    string // the signature's nonce (RFC 9421 — unique per validity window); "" when absent
	Expires  int64  // the signature's expires (unix seconds); 0 when absent — bounds the replay window
	Reason   string // for diagnostics when !Valid: bad-signature / expired / future / unknown-key / malformed
}

// KeyDir resolves a keyid (RFC 7638 JWK thumbprint) to an Ed25519 public key; ok=false when unknown.
type KeyDir func(keyid string) (ed25519.PublicKey, bool)

var (
	reEntry  = regexp.MustCompile(`^([A-Za-z0-9_-]+)=(\(.*)$`) // label=(components);params...
	reKeyid  = regexp.MustCompile(`;keyid="([^"]*)"`)
	reNonce  = regexp.MustCompile(`;nonce="([^"]*)"`)
	reExpire = regexp.MustCompile(`;expires=(\d+)`)
	reCreate = regexp.MustCompile(`;created=(\d+)`)
	reInList = regexp.MustCompile(`\(([^)]*)\)`)
)

// Verify checks the request's Web Bot Auth signature. authority is the request's :authority / Host (lower-case,
// default port stripped). Returns Present=false when there is no web-bot-auth signature at all. A Present
// result with KnownKey && !Valid is a definitive forgery (a real signer always produces a valid, fresh
// signature for its own key) — the only FP-safe convicting condition.
func Verify(authority string, h http.Header, keys KeyDir, now time.Time) Result {
	si, sh := h.Get("Signature-Input"), h.Get("Signature")
	if si == "" || sh == "" {
		return Result{}
	}
	for _, raw := range strings.Split(si, ",") { // commas only separate signatures (no commas inside values)
		m := reEntry.FindStringSubmatch(strings.TrimSpace(raw))
		if m == nil {
			continue
		}
		label, params := m[1], m[2] // params == the @signature-params value verbatim: "(...)...;tag=..."
		if !strings.Contains(params, `tag="`+Tag+`"`) {
			continue
		}
		res := Result{
			Present: true,
			KeyID:   submatch(reKeyid, params),
			Nonce:   submatch(reNonce, params),
			Expires: submatchInt(reExpire, params),
		}
		comps := componentList(params)
		if comps == nil {
			res.Reason = "malformed"
			return res
		}
		// Resolve the key FIRST so KnownKey is set before any rejection: an expired/forged signature for a key
		// we HOLD is a definitive replay/forgery (the caller convicts it), whereas an unknown keyid stays
		// unjudgeable and never convicts.
		pub, ok := keys(res.KeyID)
		if !ok {
			res.Reason = "unknown-key" // we cannot judge — NOT a forgery; caller must not convict on this
			return res
		}
		res.KnownKey = true
		if res.Expires > 0 && now.Unix() > res.Expires {
			res.Reason = "expired" // a real agent signs live; a stale signature is a replay
			return res
		}
		if cre := submatchInt(reCreate, params); cre > 0 && now.Add(clockSkew).Unix() < cre {
			res.Reason = "future"
			return res
		}
		sig, ok := decodeSignature(sh, label)
		if !ok {
			res.Reason = "malformed"
			return res
		}
		base, ok := signatureBase(authority, h, comps, params)
		if !ok {
			res.Reason = "malformed"
			return res
		}
		if ed25519.Verify(pub, []byte(base), sig) {
			res.Valid = true
		} else {
			res.Reason = "bad-signature"
		}
		return res
	}
	return Result{}
}

// signatureBase reconstructs the RFC 9421 signing string for the web-bot-auth profile. Only "@authority" and
// "signature-agent" components are supported (the profile's covered set); any other component is rejected.
func signatureBase(authority string, h http.Header, comps []string, params string) (string, bool) {
	lines := make([]string, 0, len(comps)+1)
	for _, c := range comps {
		switch c {
		case "@authority":
			lines = append(lines, `"@authority": `+authority)
		case "signature-agent":
			lines = append(lines, `"signature-agent": `+h.Get("Signature-Agent"))
		default:
			return "", false
		}
	}
	lines = append(lines, `"@signature-params": `+params)
	return strings.Join(lines, "\n"), true
}

// componentList parses the leading ("a" "b") inner-list into its member names (quotes stripped).
func componentList(params string) []string {
	m := reInList.FindStringSubmatch(params)
	if m == nil {
		return nil
	}
	var out []string
	for _, f := range strings.Fields(m[1]) {
		out = append(out, strings.Trim(f, `"`))
	}
	return out
}

// decodeSignature pulls the base64 signature for label out of a Signature header (label=:<base64>:).
func decodeSignature(sigHeader, label string) ([]byte, bool) {
	for _, raw := range strings.Split(sigHeader, ",") {
		raw = strings.TrimSpace(raw)
		pre := label + "=:"
		if !strings.HasPrefix(raw, pre) || !strings.HasSuffix(raw, ":") {
			continue
		}
		b, err := base64.StdEncoding.DecodeString(raw[len(pre) : len(raw)-1])
		if err != nil || len(b) != ed25519.SignatureSize {
			return nil, false
		}
		return b, true
	}
	return nil, false
}

// Thumbprint computes the RFC 7638 JWK SHA-256 thumbprint (base64url, no padding) of an Ed25519 public key —
// the keyid form Web Bot Auth uses. x is the base64url (no padding) public key, as it appears in the JWK.
func Thumbprint(x string) string {
	// Canonical JWK per RFC 7638: members sorted, no whitespace.
	jwk := `{"crv":"Ed25519","kty":"OKP","x":"` + x + `"}`
	sum := sha256.Sum256([]byte(jwk))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// PublicKeyFromX decodes a base64url (no padding) Ed25519 JWK x parameter into a public key.
func PublicKeyFromX(x string) (ed25519.PublicKey, bool) {
	b, err := base64.RawURLEncoding.DecodeString(x)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, false
	}
	return ed25519.PublicKey(b), true
}

// seedKeys is the lab's key directory: the RFC 9421 Ed25519 test key — also the key Web Bot Auth's own test
// agent (signature-agent.test) signs with. PRODUCTION wires the REAL fetched agent directories (GPTBot /
// ClaudeBot / … JWKS at each agent's /.well-known/http-message-signatures-directory); the lab uses this seed
// to ground the rule against a faithful signed/replayed evader without external fetches.
var seedKeys = func() map[string]ed25519.PublicKey {
	const x = "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"
	m := map[string]ed25519.PublicKey{}
	if pub, ok := PublicKeyFromX(x); ok {
		m[Thumbprint(x)] = pub
	}
	return m
}()

// DefaultKeyDir resolves keyids against the seed directory (see seedKeys).
func DefaultKeyDir() KeyDir {
	return func(keyid string) (ed25519.PublicKey, bool) { p, ok := seedKeys[keyid]; return p, ok }
}

func submatch(re *regexp.Regexp, s string) string {
	if m := re.FindStringSubmatch(s); m != nil {
		return m[1]
	}
	return ""
}

func submatchInt(re *regexp.Regexp, s string) int64 {
	if v, err := strconv.ParseInt(submatch(re, s), 10, 64); err == nil {
		return v
	}
	return 0
}
