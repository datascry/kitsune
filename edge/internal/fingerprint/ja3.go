// edge/fingerprint/ja3 — compute the JA3 TLS client fingerprint (legacy/MD5).
// Builds the JA3 string (version,ciphers,exts,curves,formats) and returns its MD5 hex digest.

package fingerprint

import (
	"crypto/md5"
	"encoding/hex"
	"strconv"
	"strings"
)

// JA3String returns the canonical JA3 string (GREASE values filtered out).
func (c *ClientHello) JA3String() string {
	fields := []string{
		strconv.Itoa(int(c.Version)),
		joinU16(filterGREASE(c.CipherSuites), "-"),
		joinU16(filterGREASE(c.Extensions), "-"),
		joinU16(filterGREASE(c.SupportedGroups), "-"),
		joinU8(c.PointFormats, "-"),
	}
	return strings.Join(fields, ",")
}

// JA3 returns the MD5 hex digest of the JA3 string.
func (c *ClientHello) JA3() string {
	sum := md5.Sum([]byte(c.JA3String()))
	return hex.EncodeToString(sum[:])
}

func joinU16(in []uint16, sep string) string {
	parts := make([]string, len(in))
	for i, v := range in {
		parts[i] = strconv.Itoa(int(v))
	}
	return strings.Join(parts, sep)
}

func joinU8(in []uint8, sep string) string {
	parts := make([]string, len(in))
	for i, v := range in {
		parts[i] = strconv.Itoa(int(v))
	}
	return strings.Join(parts, sep)
}
