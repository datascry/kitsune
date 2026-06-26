// arena/pact_test — assert the PACT issuer mints a verifiable token, rejects a forged/expired/tampered one,
// and that the HTTP flow skips the challenge for a valid token and is single-use.

package arena

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPACTIssueVerify(t *testing.T) {
	iss := NewPACTIssuer()
	now := time.Now().Unix()
	tok := iss.Issue("n1", now+300)

	if ok, nonce, _ := iss.Verify(tok, now); !ok || nonce != "n1" {
		t.Fatal("a fresh token failed to verify")
	}
	if ok, _, reason := iss.Verify(tok, now+600); ok || reason != "token expired" {
		t.Fatalf("an expired token verified: %s", reason)
	}
	if ok, _, _ := iss.Verify(tok+"x", now); ok {
		t.Fatal("a tampered token verified")
	}
	// a token from a DIFFERENT issuer must not verify here (forged key).
	other := NewPACTIssuer()
	if ok, _, _ := iss.Verify(other.Issue("n2", now+300), now); ok {
		t.Fatal("a foreign-issuer token verified")
	}
}

func TestPACTHTTPSkipsChallengeAndIsSingleUse(t *testing.T) {
	srv := httptest.NewServer(NewMux([]byte("test-secret-32-bytes-long-padxxx")))
	defer srv.Close()

	// obtain a personhood token from the (freely-minting) issuer
	resp, err := http.Get(srv.URL + "/arena/pact")
	if err != nil {
		t.Fatal(err)
	}
	var issued struct {
		Token string `json:"token"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&issued)
	resp.Body.Close()
	if issued.Token == "" {
		t.Fatal("issuer minted no token")
	}

	verify := func() map[string]any {
		body, _ := json.Marshal(map[string]any{"token": issued.Token})
		r, err := http.Post(srv.URL+"/arena/pact/verify", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(r.Body).Decode(&out)
		return out
	}

	out := verify()
	if out["ok"] != true || out["decision"] != "allow" {
		t.Fatalf("a valid personhood token did not skip the challenge: %v", out)
	}
	// single-use: the token cannot be replayed.
	if verify()["ok"] != false {
		t.Fatal("a replayed PACT token was accepted")
	}
}
