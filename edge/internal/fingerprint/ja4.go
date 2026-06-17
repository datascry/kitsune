// edge/fingerprint/ja4 — compute the JA4 TLS client fingerprint (FoxIO spec).
// Emits ja4_a_ja4_b_ja4_c: header counts, then truncated SHA-256 of sorted ciphers / extensions.

package fingerprint

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// JA4 returns the JA4 fingerprint string: "<a>_<b>_<c>".
func (c *ClientHello) JA4() string {
	return strings.Join([]string{c.ja4a(), c.ja4b(), c.ja4c()}, "_")
}

func (c *ClientHello) ja4a() string {
	ciphers := filterGREASE(c.CipherSuites)
	// Extensions count for JA4_a includes all non-GREASE extensions (SNI/ALPN are counted here).
	exts := filterGREASE(c.Extensions)

	sni := "i"
	if c.HasSNI {
		sni = "d"
	}
	return fmt.Sprintf("%s%s%s%s%s%s",
		c.Transport,
		ja4Version(c.Version),
		sni,
		twoDigit(len(ciphers)),
		twoDigit(len(exts)),
		ja4ALPN(c.ALPN),
	)
}

// ja4b: truncated SHA-256 of the sorted, comma-joined cipher list (hex, GREASE removed).
func (c *ClientHello) ja4b() string {
	return hash12(hexSortedJoin(filterGREASE(c.CipherSuites)))
}

// ja4c: truncated SHA-256 of sorted extensions (SNI/ALPN removed) + "_" + sig algs (in order).
func (c *ClientHello) ja4c() string {
	exts := make([]uint16, 0, len(c.Extensions))
	for _, e := range filterGREASE(c.Extensions) {
		if e == extServerName || e == extALPN {
			continue
		}
		exts = append(exts, e)
	}
	sig := hexJoin(filterGREASE(c.SignatureAlgorithms)) // signature algorithms stay in order
	return hash12(hexSortedJoin(exts) + "_" + sig)
}

func ja4Version(v uint16) string {
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	default:
		return "00"
	}
}

func ja4ALPN(alpn []string) string {
	if len(alpn) == 0 || alpn[0] == "" {
		return "00"
	}
	a := alpn[0]
	return string(a[0]) + string(a[len(a)-1])
}

func twoDigit(n int) string {
	if n > 99 {
		n = 99
	}
	return fmt.Sprintf("%02d", n)
}

func hexJoin(in []uint16) string {
	parts := make([]string, len(in))
	for i, v := range in {
		parts[i] = fmt.Sprintf("%04x", v)
	}
	return strings.Join(parts, ",")
}

func hexSortedJoin(in []uint16) string {
	sorted := append([]uint16(nil), in...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return hexJoin(sorted)
}

func hash12(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}
