// arena/cmd/arena-gate — the public arena challenge-gate as an HTTP service (owned infra only).
// Serves /arena/challenge + /arena/verify; the detector relays to it so a visitor hits one origin.

package main

import (
	"crypto/rand"
	"log"
	"net/http"
	"os"

	"github.com/datascry/kitsune/arena"
)

func main() {
	addr := os.Getenv("ARENA_ADDR")
	if addr == "" {
		addr = "0.0.0.0:8095"
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		log.Fatal(err)
	}
	log.Printf("arena-gate listening on %s", addr)
	srv := &http.Server{Addr: addr, Handler: arena.NewMux(secret)}
	log.Fatal(srv.ListenAndServe())
}
