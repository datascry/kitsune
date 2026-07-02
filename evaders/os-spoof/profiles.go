// evaders/os-spoof/profiles — coherent OS profiles: a kernel SYN fingerprint + matching uTLS hello + UA.
// Pick one (KS_PROFILE=<name>) or randomize (KS_PROFILE=random) so a fleet morphs into any mix of OSes.

package main

import (
	"crypto/rand"
	"math/big"

	"github.com/google/gopacket/layers"
	utls "github.com/refraction-networking/utls"
)

// Profile is one coherent OS identity across the layers the edge cross-checks: the kernel the TCP SYN reveals
// (option order + TTL + window), the TLS engine (uTLS ClientHello), and the UA. All three tell one OS story,
// so net.tcp_os_vs_ua / tls-vs-ua stay coherent — the network+kernel half of a full OS spoof.
type Profile struct {
	Name   string
	Kernel string // the OS family the SYN forges: windows | darwin | linux
	Engine string // the browser engine that pairs COHERENTLY when routed through this profile (proxy mode):
	//                chromium (nodriver/zendriver/stealth/patchright) | firefox (camoufox) | webkit (Safari/iOS)
	TTL     uint8
	Window  uint16
	synOpts func() []layers.TCPOption
	Hello   utls.ClientHelloID
	UA      string
}

func (p Profile) SYN() []layers.TCPOption { return p.synOpts() }

// --- TCP option builders (gopacket) ---

func mss(v uint16) layers.TCPOption {
	return layers.TCPOption{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{byte(v >> 8), byte(v)}}
}
func nop() layers.TCPOption { return layers.TCPOption{OptionType: layers.TCPOptionKindNop} }
func sackPerm() layers.TCPOption {
	return layers.TCPOption{OptionType: layers.TCPOptionKindSACKPermitted, OptionLength: 2}
}
func eol() layers.TCPOption { return layers.TCPOption{OptionType: layers.TCPOptionKindEndList} }
func wscale(s byte) layers.TCPOption {
	return layers.TCPOption{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{s}}
}
func timestamps() layers.TCPOption {
	return layers.TCPOption{OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10, OptionData: []byte{0, 0, 0, 1, 0, 0, 0, 0}}
}

// SYN option ORDERS the edge's ClassifyTCPOS keys on: linux leads with sack right after mss; windows and
// darwin put window-scale early after a nop, then diverge (darwin trails with a timestamp run, windows with sack).
func synLinux() []layers.TCPOption {
	return []layers.TCPOption{mss(1460), sackPerm(), timestamps(), nop(), wscale(7)} // mss,sack,ts,nop,ws
}
func synWindows() []layers.TCPOption {
	return []layers.TCPOption{mss(1460), nop(), wscale(8), nop(), nop(), sackPerm()} // mss,nop,ws,nop,nop,sack
}
func synDarwin() []layers.TCPOption {
	// wscale 4 (not 6): p0f shows every real macOS/iOS SYN uses a small window scale (<=4) — using a realistic
	// value evades net.tcp_syn_anomaly, the value-vs-order coherence check. The faithful forge.
	return []layers.TCPOption{mss(1460), nop(), wscale(4), nop(), nop(), timestamps(), sackPerm(), eol()} // mss,nop,ws,nop,nop,ts,sack,eol
}

const (
	uaWinChrome  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
	uaWinEdge    = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0"
	uaMacSafari  = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15"
	uaMacChrome  = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
	uaLinFirefox = "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0"
	uaMacFirefox = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:125.0) Gecko/20100101 Firefox/125.0"
	uaWinFirefox = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0"
	uaIOSSafari  = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1"
)

// profiles is the morph menu: each entry is coherent across kernel/TLS/UA.
var profiles = []Profile{
	{"windows-chrome", "windows", "chromium", 128, 64240, synWindows, utls.HelloChrome_Auto, uaWinChrome},
	{"windows-edge", "windows", "chromium", 128, 64240, synWindows, utls.HelloChrome_Auto, uaWinEdge},
	{"macos-safari", "darwin", "webkit", 64, 65535, synDarwin, utls.HelloSafari_Auto, uaMacSafari},
	{"macos-chrome", "darwin", "chromium", 64, 65535, synDarwin, utls.HelloChrome_Auto, uaMacChrome},
	{"linux-firefox", "linux", "firefox", 64, 64240, synLinux, utls.HelloFirefox_Auto, uaLinFirefox},
	{"macos-firefox", "darwin", "firefox", 64, 65535, synDarwin, utls.HelloFirefox_Auto, uaMacFirefox},
	{"windows-firefox", "windows", "firefox", 128, 64240, synWindows, utls.HelloFirefox_Auto, uaWinFirefox},
	{"ios-safari", "darwin", "webkit", 64, 65535, synDarwin, utls.HelloIOS_Auto, uaIOSSafari},
}

// pickProfile resolves KS_PROFILE: a name, or "random"/"" for a uniform random pick (per-node morphing).
func pickProfile(name string) (Profile, bool) {
	if name == "" || name == "random" {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(profiles))))
		return profiles[n.Int64()], true
	}
	for _, p := range profiles {
		if p.Name == name {
			return p, true
		}
	}
	return Profile{}, false
}

func profileNames() []string {
	out := make([]string, len(profiles))
	for i, p := range profiles {
		out[i] = p.Name
	}
	return out
}
