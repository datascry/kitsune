// evaders/os-spoof/main — morph the client's OS: a userspace TCP stack forges a chosen kernel's SYN options,
// with a matching uTLS hello + UA. KS_PROFILE=<name>|random|list; a fleet of random nodes morphs into any mix.

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
	"strings"

	utls "github.com/refraction-networking/utls"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	sel := env("KS_PROFILE", "random")
	if sel == "list" {
		fmt.Println(strings.Join(profileNames(), "\n"))
		return
	}
	prof, ok := pickProfile(sel)
	if !ok {
		fail("unknown KS_PROFILE %q (try one of: %s, or random)", sel, strings.Join(profileNames(), ", "))
	}
	edgeHost := env("KS_EDGE_HOST", "edge")
	edgePortStr := env("KS_EDGE_PORT", "8443")
	ua := env("KS_UA", prof.UA) // the profile's UA (overridable) — the OS story the forged SYN corroborates

	// Drop the kernel's RSTs to the edge: since WE (userspace) own this TCP flow, the kernel sees the edge's
	// replies for a socket it never opened and would RST them, killing our connection. NET_ADMIN required.
	_ = exec.Command("sh", "-c", "iptables -A OUTPUT -p tcp --tcp-flags RST RST -d "+resolveIP(edgeHost)+" -j DROP").Run()

	st, err := newStack(edgeHost, edgePortStr, prof)
	if err != nil {
		fail("stack: %v", err)
	}
	defer st.close()

	fmt.Fprintf(os.Stderr, "os-spoof: profile=%s kernel=%s (src %s:%d -> %s:%s)\n",
		prof.Name, prof.Kernel, st.srcIP, st.srcPort, st.dstIP, edgePortStr)
	if err := st.handshake(); err != nil {
		fail("handshake: %v", err)
	}
	fmt.Fprintf(os.Stderr, "os-spoof: TCP handshake complete (%s-shaped SYN sent)\n", prof.Kernel)

	// uTLS ClientHello (the profile's engine), ALPN pinned to http/1.1 so the edge routes to serveH1 (its h2
	// path speaks the frame protocol our simple userspace HTTP client does not). Presets bake in their own ALPN
	// (h2 first), so rebuild the spec and rewrite the ALPN extension before the handshake.
	cfg := &utls.Config{ServerName: edgeHost, InsecureSkipVerify: true} //nolint:gosec
	tconn := utls.UClient(st, cfg, utls.HelloCustom)
	spec, err := utls.UTLSIdToSpec(prof.Hello)
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
	fmt.Fprintln(os.Stderr, "os-spoof: TLS handshake complete (forged "+prof.Name+" ClientHello over the userspace stack)")

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
	out, _ := json.Marshal(map[string]any{
		"mode": "os-spoof", "profile": prof.Name, "kernel": prof.Kernel, "status": resp.StatusCode, "ks_sid": sid,
	})
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
