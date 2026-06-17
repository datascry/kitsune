// edge/cmd/edge — the edge service entrypoint.
// Serves the fingerprint HTTP handler; config via KITSUNE_DETECTOR / KITSUNE_EDGE_ADDR env.

package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/datascry/kitsune/edge/internal/fingerprint"
	"github.com/datascry/kitsune/edge/internal/proxy"
	"github.com/datascry/kitsune/edge/internal/session"
)

func main() {
	addr := getenv("KITSUNE_EDGE_ADDR", "127.0.0.1:8081")
	detectorURL := os.Getenv("KITSUNE_DETECTOR") // e.g. http://127.0.0.1:8080

	h := proxy.New(detectorURL, fingerprint.HintTable{}, session.NewID, time.Now)
	log.Printf("kitsune edge listening on %s (detector=%q)", addr, detectorURL)
	if err := http.ListenAndServe(addr, h); err != nil {
		log.Fatal(err)
	}
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
