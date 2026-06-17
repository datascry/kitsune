// edge/session — mint and carry the correlation id that threads every layer.
// Generates a random session id and names the cookie the collector reads it from.

package session

import (
	"crypto/rand"
	"encoding/hex"
)

// CookieName is the cookie the edge sets and the collector reads to tag its telemetry.
const CookieName = "ks_sid"

// NewID returns a fresh 128-bit correlation id as 32 lowercase hex chars.
func NewID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
