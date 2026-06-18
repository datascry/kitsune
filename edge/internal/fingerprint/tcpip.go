// edge/fingerprint/tcpip — classify the client OS kernel family from its TCP SYN (p0f-style).
// The kernel stack (initial TTL + TCP option order) can't be changed by a UA spoof — an OS tell below TLS.

package fingerprint

import (
	"encoding/binary"
	"strings"
)

// tcpOptionNames maps TCP option kinds to the short tokens used in OptionOrder (the discriminating
// feature). NOP/EOL padding is kept because its placement is part of each stack's signature.
var tcpOptionNames = map[byte]string{0: "eol", 1: "nop", 2: "mss", 3: "ws", 4: "sack", 5: "sackblk", 8: "ts"}

// ParseSYN reads an IPv4 packet and, if it is a bare client SYN (SYN set, ACK clear), returns the
// OS-revealing fields. Best-effort and bounds-checked: any malformed or non-IPv4/non-TCP/non-SYN input
// yields ok=false, never a panic — it is fed raw bytes off an arbitrary client's socket.
func ParseSYN(ip []byte) (TCPSyn, bool) {
	if len(ip) < 20 || ip[0]>>4 != 4 {
		return TCPSyn{}, false // not IPv4
	}
	ihl := int(ip[0]&0x0f) * 4
	if ihl < 20 || len(ip) < ihl+20 || ip[9] != 6 {
		return TCPSyn{}, false // bad header length or not TCP
	}
	ttl := ip[8]
	tcp := ip[ihl:]
	flags := tcp[13]
	if flags&0x02 == 0 || flags&0x10 != 0 {
		return TCPSyn{}, false // not a bare SYN (SYN set, ACK clear)
	}
	window := binary.BigEndian.Uint16(tcp[14:16])
	dataOffset := int(tcp[12]>>4) * 4
	syn := TCPSyn{TTL: ttl, WindowSize: window}
	if dataOffset > 20 && dataOffset <= len(tcp) {
		syn.OptionOrder = parseTCPOptions(tcp[20:dataOffset])
	}
	return syn, true
}

// parseTCPOptions walks the TCP option bytes and returns the option kinds, in order, as short tokens.
func parseTCPOptions(opts []byte) string {
	order := make([]string, 0, 8)
	for i := 0; i < len(opts); {
		kind := opts[i]
		name, known := tcpOptionNames[kind]
		if name == "" || !known {
			name = "x" // unknown option kind — keep a placeholder so the order/count is preserved
		}
		order = append(order, name)
		if kind == 0 { // EOL ends the option list
			break
		}
		if kind == 1 { // NOP is a single byte
			i++
			continue
		}
		if i+1 >= len(opts) || int(opts[i+1]) < 2 {
			break // malformed length — stop rather than loop
		}
		i += int(opts[i+1])
	}
	return strings.Join(order, ",")
}

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
