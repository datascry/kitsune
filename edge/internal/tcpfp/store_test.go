// edge/tcpfp/store_test — assert the source-IP -> (OS, JA4T) store stores, expires, and overwrites.
// Covers put/get, TTL expiry with an injected clock, and last-SYN-wins overwrite.

package tcpfp

import (
	"fmt"
	"testing"
	"time"
)

func TestStorePutGet(t *testing.T) {
	s := NewStore(time.Minute)
	if _, _, ok := s.Get("1.2.3.4"); ok {
		t.Fatal("empty store should miss")
	}
	s.Put("1.2.3.4", "linux", "64240_2-4-8-1-3_1460_7")
	os, ja4t, ok := s.Get("1.2.3.4")
	if !ok || os != "linux" || ja4t != "64240_2-4-8-1-3_1460_7" {
		t.Fatalf("got os=%q ja4t=%q ok=%v", os, ja4t, ok)
	}
}

func TestStoreExpires(t *testing.T) {
	now := time.Unix(1000, 0)
	s := NewStore(30 * time.Second)
	s.now = func() time.Time { return now }
	s.Put("1.2.3.4", "windows", "65535_2-1-3-1-1-4_1460_8")
	now = now.Add(31 * time.Second)
	if _, _, ok := s.Get("1.2.3.4"); ok {
		t.Error("entry past its TTL must expire")
	}
}

func TestStoreOverwrites(t *testing.T) {
	s := NewStore(time.Minute)
	s.Put("1.2.3.4", "linux", "a")
	s.Put("1.2.3.4", "darwin", "b")
	if os, ja4t, _ := s.Get("1.2.3.4"); os != "darwin" || ja4t != "b" {
		t.Errorf("latest SYN should win, got os=%q ja4t=%q", os, ja4t)
	}
}

// TestStoreSweepsExpiredOnPut pins GAP-7: the map must not grow without bound as distinct source IPs arrive
// (the NET_RAW edge's flood/scan threat model). After a TTL passes, the next Put's amortised sweep evicts
// every expired entry, leaving only the fresh one.
func TestStoreSweepsExpiredOnPut(t *testing.T) {
	now := time.Unix(1000, 0)
	s := NewStore(time.Minute)
	s.now = func() time.Time { return now }
	for i := range 1000 {
		s.Put(fmt.Sprintf("10.0.%d.%d", i/256, i%256), "linux", "x")
	}
	now = now.Add(2 * time.Minute) // every entry above is now past its TTL
	s.Put("1.2.3.4", "linux", "x") // triggers the amortised sweep
	s.mu.Lock()
	n := len(s.m)
	s.mu.Unlock()
	if n != 1 {
		t.Fatalf("after TTL + a Put, only the fresh entry should remain; got %d", n)
	}
}
