// evaders/go-tls/cmd — drive the forged-TLS evader against the live edge.
// Makes one HTTPS request with a Chrome fingerprint; KITSUNE_EDGE selects the target.

package main

import (
	"io"
	"log"
	"os"

	gotls "github.com/datascry/kitsune/evaders/go-tls"
)

func main() {
	target := os.Getenv("KITSUNE_EDGE")
	if target == "" {
		target = "https://localhost:8443/healthz"
	}
	resp, err := gotls.ChromeClient().Get(target)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	log.Printf("go-tls (chrome fingerprint) -> %s : %s [%d bytes]", target, resp.Status, len(body))
}
