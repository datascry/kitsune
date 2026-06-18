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
	detectorURL := os.Getenv("KITSUNE_DETECTOR") // e.g. http://detector:8080
	backendURL := os.Getenv("KITSUNE_BACKEND")   // e.g. http://detector:8080

	hints := fingerprint.HintTable{}

	// Transparent TLS reverse-proxy mode when a backend is set; else the fingerprint HTTP service.
	if backendURL != "" {
		rp, err := proxy.NewReverseProxy(backendURL, detectorURL, hints)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("kitsune edge (https proxy) on %s -> %s (detector=%q)", addr, backendURL, detectorURL)
		log.Fatal(rp.ListenAndServe(addr))
	}

	h := proxy.New(detectorURL, hints, session.NewID, time.Now)
	log.Printf("kitsune edge (fingerprint api) on %s (detector=%q)", addr, detectorURL)
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
