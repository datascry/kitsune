// edge/fingerprint/crawlercidr — DNS-free declared-crawler verification against published official IP ranges.
// Loads Google/Bing crawler CIDR feeds (deploy-refreshed); a declared crawler outside its feed is a fake.

package fingerprint

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
)

// CrawlerCIDR holds the official IP prefixes each crawler publishes (keyed by feed name: "google"/"bing").
// Google and Bing publish these RANGES specifically so verifiers can confirm a crawler WITHOUT a DNS
// round-trip — the documented DNS-free alternative to FCrDNS. A feed with no loaded prefixes yields a
// CrawlerUnchecked verdict so the caller falls back to FCrDNS (the feeds ship empty; a deploy refresh fills
// them — an empty/stale snapshot must never convict a real new crawler IP, hence empty-means-abstain).
type CrawlerCIDR struct {
	feeds map[string][]*net.IPNet
}

// Verdict classifies ip against the named feed: CrawlerConfirmed if ip is in a published prefix,
// CrawlerFake if the feed is loaded but ip is in NONE of its prefixes (the crawlers guarantee a real
// instance is within their published ranges, so an outside IP claiming the crawler is an impostor), and
// CrawlerUnchecked when the feed is empty/absent or ip is unparseable — abstain, let FCrDNS decide.
func (c CrawlerCIDR) Verdict(feed, ip string) CrawlerVerdict {
	nets := c.feeds[feed]
	if len(nets) == 0 {
		return CrawlerUnchecked
	}
	addr := net.ParseIP(ip)
	if addr == nil {
		return CrawlerUnchecked
	}
	for _, n := range nets {
		if n.Contains(addr) {
			return CrawlerConfirmed
		}
	}
	return CrawlerFake
}

// parseCrawlerPrefixes parses the Google/Bing `{"prefixes":[{"ipv4Prefix"|"ipv6Prefix": "..."}]}` shape
// (identical to GCP's cloud.json) into networks. Malformed entries are skipped, so an HTML error page parses
// to 0 → the feed reads empty → Verdict abstains (never a stale-snapshot false conviction).
func parseCrawlerPrefixes(data []byte) []*net.IPNet {
	var doc struct {
		Prefixes []struct {
			IPv4Prefix string `json:"ipv4Prefix"`
			IPv6Prefix string `json:"ipv6Prefix"`
		} `json:"prefixes"`
	}
	if json.Unmarshal(data, &doc) != nil {
		return nil
	}
	var out []*net.IPNet
	for _, p := range doc.Prefixes {
		cidr := p.IPv4Prefix
		if cidr == "" {
			cidr = p.IPv6Prefix
		}
		if cidr == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(cidr); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// LoadCrawlerCIDR loads each feed's prefixes from `dir/<feed>.json` (google.json, bing.json). An empty dir,
// a missing file, or a parse failure leaves that feed empty (→ FCrDNS fallback). Safe to call with "".
func LoadCrawlerCIDR(dir string) CrawlerCIDR {
	c := CrawlerCIDR{feeds: map[string][]*net.IPNet{}}
	if dir == "" {
		return c
	}
	for _, feed := range []string{"google", "bing"} {
		data, err := os.ReadFile(filepath.Join(dir, feed+".json"))
		if err != nil {
			continue
		}
		if nets := parseCrawlerPrefixes(data); len(nets) > 0 {
			c.feeds[feed] = nets
		}
	}
	return c
}

// CrawlerVerifier verifies a declared crawler: the DNS-free CIDR check first, falling back to FCrDNS only
// when no CIDR feed covers the crawler. Bundling the two lets the hot path treat verification as one call;
// a nil verifier (or one with neither a feed nor a Resolver) simply abstains.
type CrawlerVerifier struct {
	Resolver Resolver    // for the FCrDNS fallback; nil disables it
	CIDR     CrawlerCIDR // published official ranges; empty feeds → FCrDNS
}

// Verify returns the crawler verdict for the IP behind a request claiming `ua`'s crawler. Non-crawler UAs
// and inconclusive lookups return CrawlerUnchecked (abstain — never convict a real crawler).
func (v *CrawlerVerifier) Verify(ctx context.Context, ua, ip string) CrawlerVerdict {
	suffixes := DeclaredCrawler(ua)
	if suffixes == nil {
		return CrawlerUnchecked
	}
	if feed := DeclaredCrawlerFeed(ua); feed != "" {
		switch v.CIDR.Verdict(feed, ip) { // DNS-free fast path
		case CrawlerConfirmed:
			return CrawlerConfirmed
		case CrawlerFake:
			return CrawlerFake
		}
		// CrawlerUnchecked (feed not loaded) → fall through to FCrDNS
	}
	if v.Resolver != nil {
		return VerifyCrawler(ctx, v.Resolver, ip, suffixes)
	}
	return CrawlerUnchecked
}
