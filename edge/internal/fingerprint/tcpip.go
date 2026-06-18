// edge/fingerprint/tcpip — classify the client OS kernel family from its TCP SYN (p0f-style).
// The kernel stack (initial TTL + TCP option order) can't be changed by a UA spoof — an OS tell below TLS.

package fingerprint

import "strings"

// TCPSyn captures the OS-revealing fields of a client's TCP SYN packet.
type TCPSyn struct {
	TTL         uint8  // observed IP TTL (the initial value minus router hops)
	WindowSize  uint16 // advertised TCP receive window
	OptionOrder string // comma-joined TCP option kinds in order, e.g. "mss,sack,ts,nop,ws"
}

// initialTTL rounds an observed TTL up to the nearest standard initial value. Routers decrement TTL per
// hop, so a SYN seen with TTL 52 started at 64; one seen with 113 started at 128.
func initialTTL(ttl uint8) int {
	switch {
	case ttl <= 64:
		return 64
	case ttl <= 128:
		return 128
	default:
		return 255
	}
}

// ClassifyTCPOS returns the kernel family ("windows", "linux", "darwin") implied by a SYN, or "" when
// the signature is not confidently one of them. Windows is the only common stack with initial TTL 128;
// Linux and Darwin both start at 64 and are told apart by their distinctive TCP option order — Linux
// leads with SACK_PERMITTED (mss,sack,ts,nop,ws), Darwin places window-scale early and trails with a
// timestamp/SACK/EOL run (mss,nop,ws,nop,nop,ts,sack,eol). The kernel family is a property of the OS the
// client actually runs on; a spoofed User-Agent or navigator.platform cannot change it. Android reports
// "linux" (its stack *is* Linux) and iOS reports "darwin" — the caller maps the claimed platform
// accordingly before comparing.
func ClassifyTCPOS(syn TCPSyn) string {
	opts := strings.ToLower(syn.OptionOrder)
	switch initialTTL(syn.TTL) {
	case 128:
		// Windows is by far the dominant initial-TTL-128 stack; its option order confirms it.
		if strings.HasPrefix(opts, "mss,nop,ws") || strings.HasPrefix(opts, "mss,nop,nop") || opts == "" {
			return "windows"
		}
	case 64:
		switch {
		case strings.HasPrefix(opts, "mss,sack"):
			return "linux"
		case strings.HasPrefix(opts, "mss,nop,ws"):
			return "darwin"
		}
	}
	return ""
}
