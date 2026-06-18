// edge/peek/peek_test — tests for ClientHello capture + transparent replay.
// Uses net.Pipe to assert the wrapped conn parses the hello and replays every byte downstream.

package peek

import (
	"bytes"
	"io"
	"net"
	"testing"
)

// minimalClientHello is a valid extension-less ClientHello record.
func minimalClientHello() []byte {
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00)                   // session id len
	body = append(body, 0x00, 0x02, 0x13, 0x01) // ciphers
	body = append(body, 0x01, 0x00)             // compression
	hs := append([]byte{0x01, 0x00, byte(len(body) >> 8), byte(len(body))}, body...)
	return append([]byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}, hs...)
}

func TestWrapCapturesAndReplays(t *testing.T) {
	record := minimalClientHello()
	client, server := net.Pipe()
	defer client.Close()

	go func() {
		client.Write(record)
		client.Write([]byte("application-data"))
		client.Close()
	}()

	conn := Wrap(server)
	if conn.ClientHello() == nil {
		t.Fatal("expected a parsed ClientHello")
	}
	if len(conn.ClientHello().JA3()) != 32 {
		t.Errorf("ja3 = %q", conn.ClientHello().JA3())
	}

	// The handshake bytes must replay verbatim, then live data flows through.
	replayed := make([]byte, len(record))
	if _, err := io.ReadFull(conn, replayed); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(replayed, record) {
		t.Error("replayed bytes do not match the original ClientHello record")
	}
	rest, _ := io.ReadAll(conn)
	if string(rest) != "application-data" {
		t.Errorf("passthrough = %q", rest)
	}
}

func TestWrapShortReadPassesThrough(t *testing.T) {
	client, server := net.Pipe()
	go func() {
		client.Write([]byte{0x16, 0x03}) // truncated header
		client.Close()
	}()
	conn := Wrap(server)
	if conn.ClientHello() != nil {
		t.Error("expected nil ClientHello on short read")
	}
}

func TestListenerWrapsAccept(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer inner.Close()
	ln := NewListener(inner)

	record := minimalClientHello()
	go func() {
		c, _ := net.Dial("tcp", inner.Addr().String())
		c.Write(record)
		c.Close()
	}()

	c, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if pc, ok := c.(*Conn); !ok || pc.ClientHello() == nil {
		t.Errorf("accept did not wrap with a parsed ClientHello: ok=%v", ok)
	}
}
