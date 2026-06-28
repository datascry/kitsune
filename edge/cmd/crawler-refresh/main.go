// edge/cmd/crawler-refresh — deploy-time refresh of the Google/Bing crawler IP-range feeds.
// Fetches the published official ranges into KITSUNE_CRAWLER_CIDR_DIR; the edge loads them for DNS-free verify.

package main

import (
	"log"
	"os"
	"path/filepath"

	"github.com/datascry/kitsune/edge/internal/fingerprint"
)

func main() {
	dir := os.Getenv("KITSUNE_CRAWLER_CIDR_DIR")
	if dir == "" {
		log.Fatal("KITSUNE_CRAWLER_CIDR_DIR is required (the dir the edge loads crawler CIDR feeds from)")
	}
	files, err := fingerprint.RefreshCrawlerCIDR(fingerprint.HTTPCrawlerFetch)
	if err != nil {
		log.Fatalf("crawler-refresh: %v", err)
	}
	for name, body := range files {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, body, 0o644); err != nil {
			log.Fatalf("write %s: %v", path, err)
		}
		log.Printf("wrote %s (%d bytes)", path, len(body))
	}
}
