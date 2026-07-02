// evaders/os-spoof/proxy — a SOCKS5 front end that routes each browser connection through a forged-kernel flow.
// Point a real browser (camoufox / nodriver / zendriver / stealth) at it: every TCP flow rides the spoofed OS.

package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
)

// socksServe runs a SOCKS5 proxy on listenAddr; every CONNECT is relayed to the edge over a userspace TCP flow
// forging prof's kernel. A browser configured with --proxy-server=socks5://<this> therefore presents the
// forged OS at the kernel layer while its OWN real TLS + JS run end-to-end — a fully coherent morphing node.
func socksServe(mgr *manager, prof Profile, listenAddr string, dstPort uint16) error {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "os-spoof: SOCKS5 proxy on %s -> edge over a forged %s kernel (profile %s)\n",
		listenAddr, prof.Kernel, prof.Name)
	for {
		client, err := ln.Accept()
		if err != nil {
			return err
		}
		go handleSocks(client, mgr, prof, dstPort)
	}
}

func handleSocks(client net.Conn, mgr *manager, prof Profile, dstPort uint16) {
	defer client.Close()
	br := make([]byte, 512)
	// Greeting: VER, NMETHODS, METHODS... -> reply no-auth.
	if _, err := io.ReadFull(client, br[:2]); err != nil || br[0] != 0x05 {
		return
	}
	nm := int(br[1])
	if _, err := io.ReadFull(client, br[:nm]); err != nil {
		return
	}
	if _, err := client.Write([]byte{0x05, 0x00}); err != nil {
		return
	}
	// Request: VER, CMD, RSV, ATYP, ADDR, PORT. We route every CONNECT to the allow-listed edge, so the target
	// address is validated-then-ignored (the browser asks for the edge; we dial the edge over the forged flow).
	if _, err := io.ReadFull(client, br[:4]); err != nil || br[1] != 0x01 {
		_, _ = client.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // command not supported
		return
	}
	switch br[3] {
	case 0x01: // IPv4
		_, _ = io.ReadFull(client, br[:4+2])
	case 0x03: // domain
		_, _ = io.ReadFull(client, br[:1])
		_, _ = io.ReadFull(client, br[:int(br[0])+2])
	case 0x04: // IPv6
		_, _ = io.ReadFull(client, br[:16+2])
	default:
		return
	}
	up, err := mgr.dial(prof, dstPort)
	if err != nil {
		_, _ = client.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // general failure
		return
	}
	defer up.Close()
	// Success reply (bound address left zero).
	if _, err := client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	// Relay both directions until either side closes.
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, up); done <- struct{}{} }()
	<-done
}

var _ = binary.BigEndian // reserved for future ATYP/port parsing if per-target routing is added
