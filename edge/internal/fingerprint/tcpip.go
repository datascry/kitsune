// edge/fingerprint/tcpip — classify the client OS kernel family from its TCP SYN (p0f-style).
// The kernel stack (initial TTL + TCP option order) can't be changed by a UA spoof — an OS tell below TLS.

package fingerprint

import (
	"encoding/binary"
	"fmt"
	"strconv"
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
	syn := TCPSyn{
		TTL:        ttl,
		WindowSize: window,
		DF:         ip[6]&0x40 != 0,                      // IPv4 Don't-Fragment flag
		ECN:        tcp[13]&0xc0 != 0 || ip[1]&0x03 != 0, // TCP ECE/CWR (ECN setup) or IP ToS ECT/CE
	}
	if dataOffset > 20 && dataOffset <= len(tcp) {
		syn.parseOptions(tcp[20:dataOffset])
	}
	return syn, true
}

// parseOptions walks the TCP option bytes, filling the OS-token order (legacy classifier) plus the raw
// option kinds and the value-carrying options (MSS, window scale, SACK-permitted, timestamps) that JA4T and
// MTU/tunnel detection need. Best-effort: a malformed length stops the walk rather than looping.
func (s *TCPSyn) parseOptions(opts []byte) {
	order := make([]string, 0, 8)
	kinds := make([]uint8, 0, 8)
	for i := 0; i < len(opts); {
		kind := opts[i]
		kinds = append(kinds, kind)
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
		if i+1 >= len(opts) || int(opts[i+1]) < 2 || i+int(opts[i+1]) > len(opts) {
			break // malformed length — stop rather than loop
		}
		olen := int(opts[i+1])
		switch {
		case kind == 2 && olen == 4: // MSS (kind 2): 2-byte value
			s.MSS = binary.BigEndian.Uint16(opts[i+2 : i+4])
		case kind == 3 && olen == 3: // window scale (kind 3): 1-byte shift count
			s.WindowScale = opts[i+2]
			s.WindowScalePresent = true
		case kind == 4: // SACK-permitted (kind 4)
			s.SACKPermitted = true
		case kind == 8: // timestamps (kind 8)
			s.Timestamps = true
		}
		i += olen
	}
	s.OptionOrder = strings.Join(order, ",")
	s.OptionKinds = kinds
}

// TCPSyn captures the OS- and stack-revealing fields of a client's TCP SYN packet.
type TCPSyn struct {
	TTL                uint8   // observed IP TTL (the initial value minus router hops)
	WindowSize         uint16  // advertised TCP receive window
	OptionOrder        string  // comma-joined TCP option kinds in order, e.g. "mss,sack,ts,nop,ws"
	OptionKinds        []uint8 // raw TCP option kinds in order (for JA4T)
	MSS                uint16  // maximum segment size (option kind 2); 0 if absent
	WindowScale        uint8   // window-scale shift count (option kind 3); valid only if WindowScalePresent
	WindowScalePresent bool
	SACKPermitted      bool // SACK-permitted option (kind 4) present
	Timestamps         bool // TCP timestamps option (kind 8) present
	DF                 bool // IPv4 Don't-Fragment flag set
	ECN                bool // TCP ECN setup (ECE/CWR) or IP ECN bits present
}

// JA4T returns the FoxIO JA4T fingerprint: window_size "_" option-kinds(hyphen-joined) "_" MSS "_"
// window-scale ("00" when absent). A stack/tunnel fingerprint below the TLS layer, complementary to the
// OS-family classifier — usable as a within-session/coordination key and cross-referenceable against ja4db.
func (s TCPSyn) JA4T() string {
	kinds := make([]string, 0, len(s.OptionKinds))
	for _, k := range s.OptionKinds {
		kinds = append(kinds, strconv.Itoa(int(k)))
	}
	scale := "00"
	if s.WindowScalePresent {
		scale = strconv.Itoa(int(s.WindowScale))
	}
	return fmt.Sprintf("%d_%s_%d_%s", s.WindowSize, strings.Join(kinds, "-"), s.MSS, scale)
}

// initialTTL rounds an observed TTL up to the nearest standard initial value. Routers decrement TTL per
// hop, so a SYN seen with TTL 52 started at 64; one seen with 113 started at 128.
// ClassifyTCPOS returns the kernel family ("windows", "linux", "darwin") implied by a SYN, or "" when
// the signature is not confidently one of them. Classification keys on the TCP *option order*, not the
// TTL: the order is set by the kernel's network stack and forging it needs a custom raw-socket client,
// whereas the TTL is trivially mangled (`sysctl net.ipv4.ip_default_ttl=128` to fake Windows). So options
// are primary and the mangle is defeated. Linux leads with SACK_PERMITTED (mss,sack,…); Darwin and
// Windows both put window-scale early after two NOPs, then diverge — Darwin trails with a timestamp run
// (…,ts,sack,eol), Windows with SACK and no timestamp (…,sack). The kernel family is a property of the
// OS the client runs on; a spoofed UA / navigator.platform cannot change it. Android reports "linux" (its
// stack *is* Linux) and iOS reports "darwin" — the caller maps the claimed platform before comparing.
func ClassifyTCPOS(syn TCPSyn) string {
	opts := strings.ToLower(syn.OptionOrder)
	switch {
	case strings.HasPrefix(opts, "mss,sack"):
		return "linux"
	case strings.HasPrefix(opts, "mss,nop,ws,nop,nop,ts"):
		return "darwin"
	case strings.HasPrefix(opts, "mss,nop,ws,nop,nop,sack"):
		return "windows"
	}
	return ""
}
