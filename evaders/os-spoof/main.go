// evaders/os-spoof/main — forge the TCP SYN option order (a Windows kernel) via a userspace TCP stack + uTLS.
// Hand-rolls a happy-path TCP over AF_PACKET so the edge's SYN sniffer sees a Windows option order, not Linux.

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"

	"github.com/google/gopacket/layers"
	utls "github.com/refraction-networking/utls"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// winSYNOptions returns TCP options in WINDOWS order (mss, nop, ws, nop, nop, sack-permitted) — the prefix
// the edge's ClassifyTCPOS maps to "windows". Linux leads with sack-permitted right after mss; this does not.
func winSYNOptions() []layers.TCPOption {
	return []layers.TCPOption{
		{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xb4}}, // MSS 1460
		{OptionType: layers.TCPOptionKindNop},
		{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{8}},
		{OptionType: layers.TCPOptionKindNop},
		{OptionType: layers.TCPOptionKindNop},
		{OptionType: layers.TCPOptionKindSACKPermitted, OptionLength: 2},
	}
}

func main() {
	edgeHost := env("KS_EDGE_HOST", "edge")
	edgePortStr := env("KS_EDGE_PORT", "8443")
	// A Windows-Chrome UA: the OS story the forged SYN must corroborate at the kernel layer.
	ua := env("KS_UA", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")

	// Drop the kernel's RSTs to the edge: since WE (userspace) own this TCP flow, the kernel sees the edge's
	// replies for a socket it never opened and would RST them, killing our connection. NET_ADMIN required.
	_ = exec.Command("sh", "-c", "iptables -A OUTPUT -p tcp --tcp-flags RST RST -d "+resolveIP(edgeHost)+" -j DROP").Run()

	st, err := newStack(edgeHost, edgePortStr)
	if err != nil {
		fail("stack: %v", err)
	}
	defer st.close()

	fmt.Fprintf(os.Stderr, "os-spoof: userspace TCP %s:%s (src %s:%d) forging a WINDOWS SYN option order\n",
		st.dstIP, edgePortStr, st.srcIP, st.srcPort)
	if err := st.handshake(); err != nil {
		fail("handshake: %v", err)
	}
	fmt.Fprintln(os.Stderr, "os-spoof: TCP handshake complete (Windows-shaped SYN sent)")

	// uTLS ClientHello (forged Chrome), but with ALPN pinned to http/1.1 so the edge routes to serveH1 (its h2
	// path speaks the frame protocol, which our simple userspace HTTP client does not). HelloChrome_Auto bakes
	// Chrome's ALPN (h2 first), so we rebuild the spec and rewrite the ALPN extension before the handshake.
	cfg := &utls.Config{ServerName: edgeHost, InsecureSkipVerify: true} //nolint:gosec
	tconn := utls.UClient(st, cfg, utls.HelloCustom)
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
	if err != nil {
		fail("spec: %v", err)
	}
	for _, ext := range spec.Extensions {
		if alpn, ok := ext.(*utls.ALPNExtension); ok {
			alpn.AlpnProtocols = []string{"http/1.1"}
		}
	}
	if err := tconn.ApplyPreset(&spec); err != nil {
		fail("apply preset: %v", err)
	}
	if err := tconn.Handshake(); err != nil {
		fail("tls: %v", err)
	}
	fmt.Fprintln(os.Stderr, "os-spoof: TLS handshake complete (forged Chrome ClientHello over the userspace stack)")

	req, _ := http.NewRequest("GET", "https://"+edgeHost+":"+edgePortStr+"/", nil)
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Encoding", "identity")
	if err := req.Write(tconn); err != nil {
		fail("http write: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tconn), req)
	if err != nil {
		fail("http read: %v", err)
	}
	sid := ""
	for _, c := range resp.Cookies() {
		if c.Name == "ks_sid" {
			sid = c.Value
		}
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	out, _ := json.Marshal(map[string]any{"mode": "os-spoof", "status": resp.StatusCode, "ks_sid": sid, "forged_syn": "windows"})
	fmt.Println("__KS__" + string(out))
}

func fail(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "os-spoof ERROR: "+f+"\n", a...)
	os.Exit(1)
}

// resolveIP resolves a hostname to its first IPv4 string (best-effort; "" on failure).
func resolveIP(host string) string {
	ips, err := net.LookupIP(host)
	if err != nil {
		return host
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return v4.String()
		}
	}
	return host
}
