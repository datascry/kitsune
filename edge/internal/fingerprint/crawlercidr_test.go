// edge/fingerprint/crawlercidr_test — tests for DNS-free declared-crawler verification + the feed refresh.
// Covers prefix parsing, the in/out-of-range verdict, CIDR-then-FCrDNS fallback, and the refresh floor guard.

package fingerprint

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
)

const googFeed = `{"creationTime":"t","prefixes":[{"ipv4Prefix":"66.249.64.0/19"},{"ipv6Prefix":"2001:4860:4801::/48"}]}`
const bingFeed = `{"prefixes":[{"ipv4Prefix":"157.55.39.0/24"}]}`

func TestParseCrawlerPrefixesSkipsJunk(t *testing.T) {
	nets := parseCrawlerPrefixes([]byte(`{"prefixes":[{"ipv4Prefix":"1.2.3.0/24"},{"ipv4Prefix":"bad"},{}]}`))
	if len(nets) != 1 || nets[0].String() != "1.2.3.0/24" {
		t.Fatalf("got %v", nets)
	}
	if parseCrawlerPrefixes([]byte("<html>error</html>")) != nil {
		t.Error("an HTML error page must parse to nil (→ feed empty → abstain)")
	}
}

func TestCrawlerCIDRVerdict(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "google.json"), []byte(googFeed), 0o644); err != nil {
		t.Fatal(err)
	}
	c := LoadCrawlerCIDR(dir)
	if got := c.Verdict("google", "66.249.66.1"); got != CrawlerConfirmed {
		t.Errorf("real Googlebot IP: got %v, want confirmed", got)
	}
	if got := c.Verdict("google", "203.0.113.7"); got != CrawlerFake {
		t.Errorf("non-Google IP claiming Googlebot: got %v, want fake (DNS-free conviction)", got)
	}
	if got := c.Verdict("google", "2001:4860:4801::1234"); got != CrawlerConfirmed {
		t.Errorf("real Googlebot IPv6: got %v, want confirmed", got)
	}
	// An unloaded feed (bing here) and an unparseable IP both abstain → FCrDNS fallback.
	if got := c.Verdict("bing", "1.2.3.4"); got != CrawlerUnchecked {
		t.Errorf("unloaded feed: got %v, want unchecked", got)
	}
	if got := c.Verdict("google", "not-an-ip"); got != CrawlerUnchecked {
		t.Errorf("bad ip: got %v, want unchecked", got)
	}
	// An empty dir loads nothing → every feed abstains (the ship-empty, FCrDNS-fallback default).
	if LoadCrawlerCIDR("").Verdict("google", "66.249.66.1") != CrawlerUnchecked {
		t.Error("empty dir must abstain")
	}
}

func TestCrawlerVerifierPrefersCIDRThenFallsBackToDNS(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "google.json"), []byte(googFeed), 0o644)
	googlebotUA := "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"

	// CIDR feed present for Google: a non-Google IP is fake DNS-FREE (resolver nil — proves no DNS was needed).
	v := &CrawlerVerifier{CIDR: LoadCrawlerCIDR(dir)}
	if got := v.Verify(context.Background(), googlebotUA, "203.0.113.7"); got != CrawlerFake {
		t.Errorf("CIDR-miss with no resolver: got %v, want fake (DNS-free)", got)
	}
	if got := v.Verify(context.Background(), googlebotUA, "66.249.66.1"); got != CrawlerConfirmed {
		t.Errorf("CIDR-hit: got %v, want confirmed", got)
	}

	// No CIDR feed (bing absent) → falls back to the resolver (FCrDNS). A no-PTR IP is fake via DNS.
	vDNS := &CrawlerVerifier{
		Resolver: stubResolver{addrErr: &net.DNSError{IsNotFound: true}},
		CIDR:     LoadCrawlerCIDR(dir), // has google, not bing
	}
	if got := vDNS.Verify(context.Background(), "Mozilla/5.0 (compatible; bingbot/2.0)", "203.0.113.7"); got != CrawlerFake {
		t.Errorf("bing has no CIDR feed → FCrDNS fallback: got %v, want fake", got)
	}
	// A non-crawler UA always abstains.
	if got := v.Verify(context.Background(), "Mozilla/5.0 Chrome/131", "203.0.113.7"); got != CrawlerUnchecked {
		t.Errorf("non-crawler UA: got %v, want unchecked", got)
	}
}

func TestDeclaredCrawlerFeed(t *testing.T) {
	if DeclaredCrawlerFeed("Googlebot/2.1") != "google" || DeclaredCrawlerFeed("bingbot/2.0") != "bing" {
		t.Error("Googlebot→google, bingbot→bing")
	}
	if DeclaredCrawlerFeed("YandexBot/3.0") != "" || DeclaredCrawlerFeed("Chrome/131") != "" {
		t.Error("a crawler with no published feed (or a non-crawler) → empty feed")
	}
}

func TestRefreshCrawlerCIDRFloorGuard(t *testing.T) {
	// Healthy: both feeds parse above their floors → returns both files.
	good := func(url string) ([]byte, error) {
		if url == GooglebotRangesURL {
			return []byte(manyPrefixes(25)), nil
		}
		return []byte(manyPrefixes(15)), nil
	}
	files, err := RefreshCrawlerCIDR(good)
	if err != nil || len(files["google.json"]) == 0 || len(files["bing.json"]) == 0 {
		t.Fatalf("healthy refresh: err=%v files=%v", err, len(files))
	}
	// Drift: Google serves an HTML error page → 0 prefixes < floor → hard error (don't overwrite with empty).
	drift := func(url string) ([]byte, error) {
		if url == GooglebotRangesURL {
			return []byte("<html>503</html>"), nil
		}
		return []byte(manyPrefixes(15)), nil
	}
	if _, err := RefreshCrawlerCIDR(drift); err == nil {
		t.Error("a drifted Google feed must fail loud, not write an empty file")
	}
	// A fetch error propagates.
	boom := func(string) ([]byte, error) { return nil, errors.New("network down") }
	if _, err := RefreshCrawlerCIDR(boom); err == nil {
		t.Error("a fetch failure must error")
	}
}

// manyPrefixes builds a feed JSON with n distinct /24 prefixes (to clear the refresh floors in tests).
func manyPrefixes(n int) string {
	s := `{"prefixes":[`
	for i := 0; i < n; i++ {
		if i > 0 {
			s += ","
		}
		s += `{"ipv4Prefix":"10.` + itoa(i) + `.0.0/24"}`
	}
	return s + `]}`
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
