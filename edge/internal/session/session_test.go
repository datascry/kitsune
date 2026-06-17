// edge/session/session_test — tests for correlation id minting.
// Asserts id length, hex encoding, and uniqueness across calls.

package session

import (
	"encoding/hex"
	"testing"
)

func TestNewID(t *testing.T) {
	a, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 32 {
		t.Errorf("want 32 hex chars, got %d", len(a))
	}
	if _, err := hex.DecodeString(a); err != nil {
		t.Errorf("not hex: %v", err)
	}
	b, _ := NewID()
	if a == b {
		t.Error("ids should be unique")
	}
}

func TestCookieName(t *testing.T) {
	if CookieName != "ks_sid" {
		t.Errorf("CookieName=%q", CookieName)
	}
}
