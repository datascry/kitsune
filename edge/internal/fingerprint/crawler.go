// edge/fingerprint/crawler — forward-confirmed reverse DNS (FCrDNS) verification of declared crawlers.
// Catches a non-crawler IP wearing a Googlebot/Bingbot UA; abstains on transient DNS failure (FP-safe).

package fingerprint

import (
	"context"
	"errors"
	"net"
	"strings"
)

// Resolver is the subset of *net.Resolver that crawler verification needs, so tests can inject a fake.
type Resolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// declaredCrawlers maps a User-Agent token to the rDNS host suffixes a LEGITIMATE instance of that crawler
// must resolve to. Google and Bing publish forward-confirmed reverse DNS as their OFFICIAL verification
// method, so a real crawler always confirms — the carve-outs make a fake one (a datacenter IP wearing the
// UA) the only thing that fails. Suffixes are matched case-insensitively against the trailing label group.
var declaredCrawlers = []struct {
	token    string
	suffixes []string
}{
	{"Googlebot", []string{".googlebot.com", ".google.com"}},
	{"AdsBot-Google", []string{".googlebot.com", ".google.com"}},
	{"APIs-Google", []string{".google.com"}},
	{"Storebot-Google", []string{".googlebot.com", ".google.com"}},
	{"bingbot", []string{".search.msn.com"}},
	{"BingPreview", []string{".search.msn.com"}},
	{"Applebot", []string{".applebot.apple.com"}},
	{"DuckDuckBot", []string{".duckduckgo.com"}},
	{"YandexBot", []string{".yandex.com", ".yandex.net", ".yandex.ru"}},
	{"Baiduspider", []string{".baidu.com", ".baidu.jp"}},
}

// DeclaredCrawler returns the official rDNS suffixes the UA claims to belong to, or nil if it names no
// known crawler. The check is a substring match on the canonical token (the same way the crawlers' own
// verification docs describe their UAs).
func DeclaredCrawler(ua string) []string {
	for _, c := range declaredCrawlers {
		if strings.Contains(ua, c.token) {
			return c.suffixes
		}
	}
	return nil
}

// CrawlerVerdict is the FCrDNS outcome for a declared crawler.
type CrawlerVerdict int

const (
	CrawlerUnchecked CrawlerVerdict = iota // not a declared crawler, or an inconclusive lookup → abstain
	CrawlerConfirmed                       // rDNS forward-confirms an official crawler host
	CrawlerFake                            // declared a crawler but rDNS definitively does not confirm it
)

// VerifyCrawler runs forward-confirmed reverse DNS for an IP claiming to be `suffixes`' crawler:
// PTR(ip) must yield a host under one of the official suffixes whose forward A/AAAA records include `ip`.
// A definitive non-match (PTR NXDOMAIN, PTR under no official suffix, or a matching host that does not
// forward-confirm) is CrawlerFake. A resolver/transport error (SERVFAIL, timeout) is CrawlerUnchecked —
// abstain, never convict a real crawler on a transient DNS failure. This mirrors Google's and Bing's own
// documented verification procedure, so a genuine crawler always returns CrawlerConfirmed.
func VerifyCrawler(ctx context.Context, res Resolver, ip string, suffixes []string) CrawlerVerdict {
	names, err := res.LookupAddr(ctx, ip)
	if err != nil {
		if dnsNotFound(err) {
			return CrawlerFake // a legitimate crawler has a PTR record; its absence is a spoof
		}
		return CrawlerUnchecked // SERVFAIL / timeout — inconclusive, abstain
	}
	matchedSuffix := false
	for _, name := range names {
		host := strings.TrimSuffix(strings.ToLower(name), ".")
		if !hasAnySuffix(host, suffixes) {
			continue
		}
		matchedSuffix = true
		addrs, err := res.LookupHost(ctx, host)
		if err != nil {
			return CrawlerUnchecked // cannot forward-confirm right now — abstain
		}
		for _, a := range addrs {
			if a == ip {
				return CrawlerConfirmed
			}
		}
	}
	// PTR resolved, but either to no official-suffix host (impersonator) or to one that does not
	// forward-confirm this IP (stale/forged PTR). Both are definitive fakes.
	_ = matchedSuffix
	return CrawlerFake
}

func hasAnySuffix(host string, suffixes []string) bool {
	for _, s := range suffixes {
		if strings.HasSuffix(host, s) {
			return true
		}
	}
	return false
}

func dnsNotFound(err error) bool {
	var de *net.DNSError
	if errors.As(err, &de) {
		return de.IsNotFound
	}
	return false
}
