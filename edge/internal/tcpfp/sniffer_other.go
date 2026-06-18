// edge/tcpfp/sniffer_other — non-Linux stub: raw SYN capture is a Linux AF_PACKET feature.
// Lets the cross-platform edge build everywhere; TCP/IP fingerprinting is simply absent off Linux.

//go:build !linux

package tcpfp

import "errors"

// Sniff is unsupported off Linux; the edge runs without TCP/IP fingerprints. // pragma: integration
func Sniff(_ *Store, _ <-chan struct{}) error {
	return errors.New("tcpfp: raw SYN capture is only supported on linux")
}
