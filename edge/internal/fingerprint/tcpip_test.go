// edge/fingerprint/tcpip_test — assert the p0f-style kernel-family classifier on documented SYN profiles.
// Real initial TTLs and TCP option orders for Linux, Windows, and Darwin (macOS/iOS).

package fingerprint

import "testing"

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
		{"unknown ttl (router/255)", TCPSyn{TTL: 250, OptionOrder: "mss,sack,ts,nop,ws"}, ""},
		{"ttl64 but unrecognised options", TCPSyn{TTL: 64, OptionOrder: "mss,ts"}, ""},
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
