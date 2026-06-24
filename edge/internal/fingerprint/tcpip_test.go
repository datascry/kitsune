// edge/fingerprint/tcpip_test — assert the p0f-style kernel-family classifier on documented SYN profiles.
// Real initial TTLs and TCP option orders for Linux, Windows, and Darwin (macOS/iOS).

package fingerprint

import (
	"encoding/binary"
	"testing"
)

// buildSYN assembles a minimal IPv4+TCP SYN packet with the given TTL, window, and raw TCP option bytes.
func buildSYN(ttl uint8, window uint16, opts []byte) []byte {
	ip := make([]byte, 20)
	ip[0] = 0x45 // IPv4, IHL 5 (20 bytes)
	ip[8] = ttl
	ip[9] = 6 // TCP
	tcp := make([]byte, 20+len(opts))
	tcp[12] = byte((20 + len(opts)) / 4 << 4) // data offset
	tcp[13] = 0x02                            // SYN
	binary.BigEndian.PutUint16(tcp[14:16], window)
	copy(tcp[20:], opts)
	return append(ip, tcp...)
}

// real-stack TCP option byte sequences (kind[,len,...value])
var (
	linuxOpts   = []byte{2, 4, 0x05, 0xb4, 4, 2, 8, 10, 0, 0, 0, 0, 0, 0, 0, 0, 1, 3, 3, 7} // mss,sack,ts,nop,ws
	windowsOpts = []byte{2, 4, 0x05, 0xb4, 1, 3, 3, 8, 1, 1, 4, 2}                          // mss,nop,ws,nop,nop,sack
)

func TestParseSYNLinux(t *testing.T) {
	syn, ok := ParseSYN(buildSYN(64, 64240, linuxOpts))
	if !ok {
		t.Fatal("expected a parsed SYN")
	}
	if syn.TTL != 64 || syn.WindowSize != 64240 || syn.OptionOrder != "mss,sack,ts,nop,ws" {
		t.Fatalf("got %+v", syn)
	}
	if ClassifyTCPOS(syn) != "linux" {
		t.Errorf("classify=%q want linux", ClassifyTCPOS(syn))
	}
}

func TestParseSYNWindows(t *testing.T) {
	syn, ok := ParseSYN(buildSYN(128, 64240, windowsOpts))
	if !ok || syn.OptionOrder != "mss,nop,ws,nop,nop,sack" {
		t.Fatalf("ok=%v syn=%+v", ok, syn)
	}
	if ClassifyTCPOS(syn) != "windows" {
		t.Errorf("classify=%q want windows", ClassifyTCPOS(syn))
	}
}

func TestParseSYNExtractsValuesAndJA4T(t *testing.T) {
	// linuxOpts = mss(1460), sack-permitted, timestamps, nop, window-scale(7).
	syn, ok := ParseSYN(buildSYN(64, 64240, linuxOpts))
	if !ok {
		t.Fatal("expected a parsed SYN")
	}
	if syn.MSS != 1460 {
		t.Errorf("MSS=%d want 1460", syn.MSS)
	}
	if !syn.WindowScalePresent || syn.WindowScale != 7 {
		t.Errorf("window scale present=%v val=%d want 7", syn.WindowScalePresent, syn.WindowScale)
	}
	if !syn.SACKPermitted {
		t.Error("SACK-permitted should be detected")
	}
	if !syn.Timestamps {
		t.Error("timestamps should be detected")
	}
	want := "64240_2-4-8-1-3_1460_7"
	if got := syn.JA4T(); got != want {
		t.Errorf("JA4T=%q want %q", got, want)
	}
}

func TestParseSYNDFAndECN(t *testing.T) {
	pkt := buildSYN(64, 64240, linuxOpts)
	pkt[6] |= 0x40 // set the IPv4 Don't-Fragment flag
	pkt[1] |= 0x01 // set an IP ECN (ECT) bit
	syn, ok := ParseSYN(pkt)
	if !ok || !syn.DF || !syn.ECN {
		t.Fatalf("ok=%v DF=%v ECN=%v — want DF+ECN", ok, syn.DF, syn.ECN)
	}
	// A SYN without those bits must report them false.
	plain, _ := ParseSYN(buildSYN(64, 64240, windowsOpts))
	if plain.DF || plain.ECN {
		t.Errorf("plain SYN should have DF=ECN=false, got DF=%v ECN=%v", plain.DF, plain.ECN)
	}
	if plain.WindowScale != 8 || plain.MSS != 1460 {
		t.Errorf("windows SYN ws/mss = %d/%d want 8/1460", plain.WindowScale, plain.MSS)
	}
}

func TestParseSYNRejectsNonSYN(t *testing.T) {
	// A SYN-ACK (server side) must be ignored — only bare client SYNs are fingerprinted.
	pkt := buildSYN(64, 64240, linuxOpts)
	pkt[20+13] = 0x12 // SYN|ACK on the TCP flags byte
	if _, ok := ParseSYN(pkt); ok {
		t.Error("SYN-ACK should not parse as a client SYN")
	}
}

func TestParseSYNRejectsMalformed(t *testing.T) {
	for _, b := range [][]byte{nil, {0x45}, {0x60, 0, 0, 0}, make([]byte, 19)} {
		if _, ok := ParseSYN(b); ok {
			t.Errorf("malformed input %v should not parse", b)
		}
	}
}

func FuzzParseSYN(f *testing.F) {
	f.Add(buildSYN(64, 64240, linuxOpts))
	f.Add([]byte{0x45, 0, 0, 0})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		// Raw bytes off an arbitrary client's socket must never panic.
		if syn, ok := ParseSYN(data); ok {
			_ = ClassifyTCPOS(syn)
		}
	})
}

func TestClassifyTCPOS(t *testing.T) {
	cases := []struct {
		name string
		syn  TCPSyn
		want string
	}{
		{"linux", TCPSyn{TTL: 64, WindowSize: 64240, OptionOrder: "mss,sack,ts,nop,ws"}, "linux"},
		{"linux after hops", TCPSyn{TTL: 52, WindowSize: 29200, OptionOrder: "mss,sack,ts,nop,ws"}, "linux"},
		{"windows", TCPSyn{TTL: 128, WindowSize: 64240, OptionOrder: "mss,nop,ws,nop,nop,sack"}, "windows"},
		{"windows after hops", TCPSyn{TTL: 113, WindowSize: 8192, OptionOrder: "mss,nop,ws,nop,nop,sack"}, "windows"},
		{"macos/darwin", TCPSyn{TTL: 64, WindowSize: 65535, OptionOrder: "mss,nop,ws,nop,nop,ts,sack,eol"}, "darwin"},
		{"option order case-insensitive", TCPSyn{TTL: 64, OptionOrder: "MSS,SACK,TS,NOP,WS"}, "linux"},
		// Options are authoritative: an unusual or mangled TTL does not change the verdict.
		{"odd ttl, linux options", TCPSyn{TTL: 250, OptionOrder: "mss,sack,ts,nop,ws"}, "linux"},
		{"ttl mangled to windows, linux options -> still linux", TCPSyn{TTL: 128, OptionOrder: "mss,sack,ts,nop,ws"}, "linux"},
		{"unrecognised options", TCPSyn{TTL: 64, OptionOrder: "mss,ts"}, ""},
		{"empty", TCPSyn{}, ""},
	}
	for _, c := range cases {
		if got := ClassifyTCPOS(c.syn); got != c.want {
			t.Errorf("%s: ClassifyTCPOS=%q want %q", c.name, got, c.want)
		}
	}
}

// Linux and Darwin both start at TTL 64; the classifier must not conflate them.
func TestClassifyTCPOSDistinguishesTTL64Stacks(t *testing.T) {
	linux := ClassifyTCPOS(TCPSyn{TTL: 64, OptionOrder: "mss,sack,ts,nop,ws"})
	darwin := ClassifyTCPOS(TCPSyn{TTL: 64, OptionOrder: "mss,nop,ws,nop,nop,ts,sack,eol"})
	if linux == darwin || linux != "linux" || darwin != "darwin" {
		t.Errorf("TTL-64 stacks conflated: linux=%q darwin=%q", linux, darwin)
	}
}
