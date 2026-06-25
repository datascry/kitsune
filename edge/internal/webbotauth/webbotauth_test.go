// edge/webbotauth_test — verifier correctness against the official Web Bot Auth / RFC 9421 test vector.
// Proves the signature base + Ed25519 verify are spec-exact, and that forged/expired/tampered sigs fail.

package webbotauth

import (
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"testing"
	"time"
)

// The RFC 9421 Appendix B.1.4 Ed25519 test key, as Web Bot Auth uses it (draft Appendix A.2.2).
const (
	testX     = "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs" // JWK x (public)
	testD     = "n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU" // JWK d (private seed)
	testKeyID = "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U" // RFC 7638 thumbprint of the public key
	vectorSI  = `sig2=("@authority" "signature-agent");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=1735693200;nonce="e8N7S2MFd/qrd6T2R3tdfAuuANngKI7LFtKYI/vowzk4lAZYadIX6wW25MwG7DCT9RUKAJ0qVkU0mEeLElW1qg==";tag="web-bot-auth"`
	vectorSig = `sig2=:jdq0SqOwHdyHr9+r5jw3iYZH6aNGKijYp/EstF4RQTQdi5N5YYKrD+mCT1HA1nZDsi6nJKuHxUi/5Syp3rLWBA==:`
	vectorWin = 1735690000 // a unix time inside the vector's created..expires window
)

func testKeys(t *testing.T) KeyDir {
	t.Helper()
	pub, ok := PublicKeyFromX(testX)
	if !ok {
		t.Fatal("decode test public key")
	}
	return func(keyid string) (ed25519.PublicKey, bool) {
		if keyid == testKeyID {
			return pub, true
		}
		return nil, false
	}
}

func vectorHeader() http.Header {
	h := http.Header{}
	h.Set("Signature-Agent", `"https://signature-agent.test"`)
	h.Set("Signature-Input", vectorSI)
	h.Set("Signature", vectorSig)
	return h
}

// TestThumbprintMatchesVector grounds the RFC 7638 keyid derivation against the published thumbprint.
func TestThumbprintMatchesVector(t *testing.T) {
	if got := Thumbprint(testX); got != testKeyID {
		t.Errorf("Thumbprint = %q, want the published keyid %q", got, testKeyID)
	}
}

// TestVerifyOfficialVector is the spec-correctness anchor: the draft's own Ed25519 signature must verify.
func TestVerifyOfficialVector(t *testing.T) {
	r := Verify("example.com", vectorHeader(), testKeys(t), time.Unix(vectorWin, 0))
	if !r.Present || !r.Valid || !r.KnownKey {
		t.Fatalf("official vector must verify: %+v", r)
	}
	if r.KeyID != testKeyID {
		t.Errorf("KeyID = %q, want %q", r.KeyID, testKeyID)
	}
}

func TestVerifyExpiredFails(t *testing.T) {
	r := Verify("example.com", vectorHeader(), testKeys(t), time.Unix(1735693201, 0)) // 1s past expires
	if !r.Present || r.Valid || r.Reason != "expired" {
		t.Errorf("expired signature must fail with reason=expired: %+v", r)
	}
}

func TestVerifyTamperedSignatureFails(t *testing.T) {
	h := vectorHeader()
	// Flip a byte of the signature: a known-key signature that no longer verifies = a forgery.
	sig := h.Get("Signature")
	h.Set("Signature", sig[:10]+"X"+sig[11:])
	r := Verify("example.com", h, testKeys(t), time.Unix(vectorWin, 0))
	if !r.Present || r.Valid {
		t.Errorf("tampered signature must NOT verify: %+v", r)
	}
}

func TestVerifyWrongAuthorityFails(t *testing.T) {
	// The vector signs @authority=example.com; presenting it on another authority breaks the base.
	r := Verify("evil.example", vectorHeader(), testKeys(t), time.Unix(vectorWin, 0))
	if !r.Present || r.Valid || r.Reason != "bad-signature" {
		t.Errorf("authority mismatch must fail bad-signature: %+v", r)
	}
}

func TestVerifyUnknownKeyIsNotAForgery(t *testing.T) {
	none := func(string) (ed25519.PublicKey, bool) { return nil, false }
	r := Verify("example.com", vectorHeader(), none, time.Unix(vectorWin, 0))
	if !r.Present || r.Valid || r.KnownKey || r.Reason != "unknown-key" {
		t.Errorf("unknown key must be Present but not-known, not a forgery: %+v", r)
	}
}

func TestVerifyNoSignatureAbsent(t *testing.T) {
	if r := Verify("example.com", http.Header{}, testKeys(t), time.Now()); r.Present {
		t.Errorf("a request with no Signature headers must be Present=false: %+v", r)
	}
}

// TestRoundTripFreshSignature signs a fresh request with the test private key and verifies it — the path the
// faithful signed-agent evader exercises (valid, in-window → benign/verified).
func TestRoundTripFreshSignature(t *testing.T) {
	seed, err := base64.RawURLEncoding.DecodeString(testD)
	if err != nil {
		t.Fatal(err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	now := time.Unix(2000000000, 0)
	params := `("@authority");created=2000000000;keyid="` + testKeyID + `";alg="ed25519";expires=2000003600;tag="web-bot-auth"`
	base, ok := signatureBase("agent.test", http.Header{}, []string{"@authority"}, params)
	if !ok {
		t.Fatal("build base")
	}
	sig := ed25519.Sign(priv, []byte(base))
	h := http.Header{}
	h.Set("Signature-Input", "sig1="+params)
	h.Set("Signature", "sig1=:"+base64.StdEncoding.EncodeToString(sig)+":")
	r := Verify("agent.test", h, testKeys(t), now)
	if !r.Present || !r.Valid || !r.KnownKey {
		t.Fatalf("fresh round-trip signature must verify: %+v base=%q", r, base)
	}
}
