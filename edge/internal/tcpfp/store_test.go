// edge/tcpfp/store_test — assert the source-IP -> OS store stores, expires, and overwrites.
// Covers put/get, TTL expiry with an injected clock, and last-SYN-wins overwrite.

package tcpfp

import (
	"testing"
	"time"
)

func TestStorePutGet(t *testing.T) {
	s := NewStore(time.Minute)
	if _, ok := s.Get("1.2.3.4"); ok {
		t.Fatal("empty store should miss")
	}
	s.Put("1.2.3.4", "linux")
	if os, ok := s.Get("1.2.3.4"); !ok || os != "linux" {
		t.Fatalf("got %q ok=%v", os, ok)
	}
}

func TestStoreExpires(t *testing.T) {
	now := time.Unix(1000, 0)
	s := NewStore(30 * time.Second)
	s.now = func() time.Time { return now }
	s.Put("1.2.3.4", "windows")
	now = now.Add(31 * time.Second)
	if _, ok := s.Get("1.2.3.4"); ok {
		t.Error("entry past its TTL must expire")
	}
}

func TestStoreOverwrites(t *testing.T) {
	s := NewStore(time.Minute)
	s.Put("1.2.3.4", "linux")
	s.Put("1.2.3.4", "darwin")
	if os, _ := s.Get("1.2.3.4"); os != "darwin" {
		t.Errorf("latest SYN should win, got %q", os)
	}
}
