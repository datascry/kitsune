// edge/fingerprint/crawler_test — tests for forward-confirmed reverse DNS crawler verification.
// Covers confirm, impersonator (wrong domain), missing PTR, no-forward-confirm, and transient-error abstain.

package fingerprint

import (
	"context"
	"net"
	"testing"
)

type stubResolver struct {
	addr    map[string][]string // ip -> PTR names
	host    map[string][]string // host -> forward A/AAAA
	addrErr error
	hostErr error
}

func (s stubResolver) LookupAddr(_ context.Context, ip string) ([]string, error) {
	if s.addrErr != nil {
		return nil, s.addrErr
	}
	return s.addr[ip], nil
}

func (s stubResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	if s.hostErr != nil {
		return nil, s.hostErr
	}
	return s.host[host], nil
}

func TestDeclaredCrawler(t *testing.T) {
	if DeclaredCrawler("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)") == nil {
		t.Error("a Googlebot UA should be a declared crawler")
	}
	if DeclaredCrawler("Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36") != nil {
		t.Error("a plain Chrome UA is not a declared crawler")
	}
}

func TestVerifyCrawler(t *testing.T) {
	const ip = "66.249.66.1"
	g := DeclaredCrawler("Googlebot/2.1")
	cases := []struct {
		name string
		res  stubResolver
		want CrawlerVerdict
	}{
		{
			"confirmed",
			stubResolver{addr: map[string][]string{ip: {"crawl-66-249-66-1.googlebot.com."}}, host: map[string][]string{"crawl-66-249-66-1.googlebot.com": {ip}}},
			CrawlerConfirmed,
		},
		{
			"impersonator-wrong-domain",
			stubResolver{addr: map[string][]string{ip: {"host.evil.example."}}},
			CrawlerFake,
		},
		{
			"no-ptr-record",
			stubResolver{addrErr: &net.DNSError{IsNotFound: true}},
			CrawlerFake,
		},
		{
			"suffix-matches-but-no-forward-confirm",
			stubResolver{addr: map[string][]string{ip: {"crawl-x.googlebot.com."}}, host: map[string][]string{"crawl-x.googlebot.com": {"9.9.9.9"}}},
			CrawlerFake,
		},
		{
			"transient-dns-error-abstains",
			stubResolver{addrErr: &net.DNSError{IsTimeout: true}},
			CrawlerUnchecked,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := VerifyCrawler(context.Background(), c.res, ip, g); got != c.want {
				t.Errorf("VerifyCrawler = %v, want %v", got, c.want)
			}
		})
	}
}
