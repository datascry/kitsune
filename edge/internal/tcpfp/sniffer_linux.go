// edge/tcpfp/sniffer_linux — raw AF_PACKET sniffer that classifies the OS of each client SYN.
// Observe-only: reads inbound IP packets, fingerprints bare SYNs, and fills the Store keyed by source IP.

//go:build linux

package tcpfp

import (
	"net"
	"syscall"

	"github.com/datascry/kitsune/edge/internal/fingerprint"
)

func htons(h uint16) uint16 { return h<<8 | h>>8 }

// Sniff opens a raw packet socket and records the OS kernel family of every client SYN into store until
// stop is closed. SOCK_DGRAM strips the link-layer header, so each read is an IP packet straight into
// fingerprint.ParseSYN. Best-effort: it needs CAP_NET_RAW; if the socket cannot be opened the caller
// runs without TCP/IP fingerprints rather than failing. // pragma: integration
func Sniff(store *Store, win *WindowTracker, stop <-chan struct{}) error {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM, int(htons(syscall.ETH_P_IP)))
	if err != nil {
		return err
	}
	go func() {
		<-stop
		_ = syscall.Close(fd)
	}()
	buf := make([]byte, 65535)
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			return err // socket closed (stop) or a fatal read error
		}
		if n < 20 {
			continue
		}
		srcIP := net.IP(buf[12:16]).String() // IPv4 source (bytes 12-16); validated by the parsers below
		if syn, ok := fingerprint.ParseSYN(buf[:n]); ok {
			// Store the JA4T fingerprint for every parsed SYN (always meaningful) + the OS family when classified.
			store.Put(srcIP, fingerprint.ClassifyTCPOS(syn), syn.JA4T())
			continue
		}
		// Non-SYN (established) segment: track the client's advertised receive window. A real kernel auto-tunes
		// it across the flow; a happy-path userspace stack holds it constant (WindowTracker.Static catches that).
		if win != nil {
			if _, window, ok := fingerprint.ParseTCPWindow(buf[:n]); ok {
				win.Observe(srcIP, window)
			}
		}
	}
}
