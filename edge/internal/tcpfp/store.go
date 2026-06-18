// edge/tcpfp/store — short-lived map of source IP -> observed TCP/IP OS kernel family.
// The SYN sniffer fills it; the proxy reads it by the connection's remote IP to tag the session.

package tcpfp

import (
	"sync"
	"time"
)

type entry struct {
	os string
	at time.Time
}

// Store maps a client source IP to the OS kernel family classified from its TCP SYN. Entries expire
// after a TTL so a stale SYN from a long-closed connection can't mislabel a later one on the same IP.
type Store struct {
	mu  sync.Mutex
	m   map[string]entry
	ttl time.Duration
	now func() time.Time
}

// NewStore returns a Store whose entries live for ttl.
func NewStore(ttl time.Duration) *Store {
	return &Store{m: make(map[string]entry), ttl: ttl, now: time.Now}
}

// Put records the OS kernel family observed for a source IP.
func (s *Store) Put(ip, os string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[ip] = entry{os: os, at: s.now()}
}

// Get returns the OS family for an IP if one was observed within the TTL.
func (s *Store) Get(ip string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[ip]
	if !ok || s.now().Sub(e.at) > s.ttl {
		return "", false
	}
	return e.os, true
}
