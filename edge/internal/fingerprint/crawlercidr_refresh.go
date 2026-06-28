// edge/fingerprint/crawlercidr_refresh — fetch the published Google/Bing crawler IP-range feeds at deploy.
// The edge-side analog of the detector's ip_reputation_refresh; output written to KITSUNE_CRAWLER_CIDR_DIR.

package fingerprint

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

// Published official crawler IP-range feeds (the documented DNS-free verification source). Google's Googlebot
// list and Bing's bingbot list share the `{"prefixes":[{"ipv4Prefix"|"ipv6Prefix"}]}` shape.
const (
	GooglebotRangesURL = "https://developers.google.com/static/search/apis/ipranges/googlebot.json"
	BingbotRangesURL   = "https://www.bing.com/toolbox/bingbot.json"
)

// crawlerFeedFloors guards against a source URL/format drift silently emptying a feed: the live lists carry
// dozens-to-hundreds of prefixes (2026-06: Googlebot ~190, bingbot ~60), so a parse collapsing to ~0 means
// drift and the refresh fails loud rather than shipping a feed that would let every impostor through.
var crawlerFeedFloors = map[string]int{"google": 20, "bing": 10}

// CrawlerFetcher fetches a URL and returns the body; injected so RefreshCrawlerCIDR is unit-tested offline.
type CrawlerFetcher func(url string) ([]byte, error)

// RefreshCrawlerCIDR fetches each feed, validates it parses above its floor, and returns
// {"google.json": bytes, "bing.json": bytes} to write into the deploy dir. A feed failing its floor is a
// hard error (drift) — better to keep the prior file than overwrite it with an empty one.
func RefreshCrawlerCIDR(fetch CrawlerFetcher) (map[string][]byte, error) {
	out := map[string][]byte{}
	for _, src := range []struct {
		feed, url string
	}{
		{"google", GooglebotRangesURL},
		{"bing", BingbotRangesURL},
	} {
		body, err := fetch(src.url)
		if err != nil {
			return nil, fmt.Errorf("fetch %s feed (%s): %w", src.feed, src.url, err)
		}
		got := len(parseCrawlerPrefixes(body))
		if floor := crawlerFeedFloors[src.feed]; got < floor {
			return nil, fmt.Errorf("%s feed parsed %d prefixes (< %d floor) — URL/format likely drifted", src.feed, got, floor)
		}
		out[src.feed+".json"] = body
	}
	return out, nil
}

// HTTPCrawlerFetch is the production fetcher: a plain GET with a browser-ish UA (some endpoints 403 the
// default Go agent), used by the crawler-refresh command at deploy.
func HTTPCrawlerFetch(url string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}
