// evaders/os-spoof/stack — a minimal happy-path userspace TCP over AF_PACKET, exposed as a net.Conn.
// It emits a caller-chosen SYN option order so the edge's SYN sniffer classifies a forged kernel family.

package main

import (
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/sys/unix"
)

type stack struct {
	fd       int
	ifIndex  int
	srcMAC   net.HardwareAddr
	dstMAC   net.HardwareAddr
	srcIP    net.IP
	dstIP    net.IP
	srcPort  uint16
	dstPort  uint16
	seq      uint32 // our next send sequence number
	ack      uint32 // next expected sequence number from the peer
	inbuf    []byte
	deadline time.Time
}

// newStack resolves the egress interface (MAC/IP), the destination IP + MAC (via the kernel ARP cache after a
// ping), and opens an AF_PACKET raw socket. dstPortStr is the edge TCP port.
func newStack(host, dstPortStr string) (*stack, error) {
	dstIP := net.ParseIP(resolveIP(host)).To4()
	if dstIP == nil {
		return nil, fmt.Errorf("cannot resolve %s to IPv4", host)
	}
	iface, srcIP, err := routeIface(dstIP)
	if err != nil {
		return nil, err
	}
	// Populate the kernel ARP cache, then read the peer MAC from it (docker bridge = one L2 segment).
	_ = exec.Command("ping", "-c", "1", "-W", "1", dstIP.String()).Run()
	dstMAC, err := arpLookup(dstIP)
	if err != nil {
		// Fall back to the default gateway MAC (routed egress) if the peer is not directly ARP-resolvable.
		if gw, gerr := defaultGateway(); gerr == nil {
			_ = exec.Command("ping", "-c", "1", "-W", "1", gw.String()).Run()
			dstMAC, err = arpLookup(gw)
		}
		if err != nil {
			return nil, fmt.Errorf("arp %s: %w", dstIP, err)
		}
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, htons(unix.ETH_P_ALL))
	if err != nil {
		return nil, fmt.Errorf("AF_PACKET socket (need NET_RAW): %w", err)
	}
	var dp uint16
	fmt.Sscanf(dstPortStr, "%d", &dp)
	return &stack{
		fd: fd, ifIndex: iface.Index, srcMAC: iface.HardwareAddr, dstMAC: dstMAC,
		srcIP: srcIP.To4(), dstIP: dstIP, srcPort: uint16(20000 + rand.Intn(40000)), dstPort: dp,
		seq: rand.Uint32(),
	}, nil
}

func (s *stack) close() error { return unix.Close(s.fd) }

// send serializes Eth/IP/TCP(+payload) with the given flags and options and writes one frame.
func (s *stack) send(flags tcpFlags, opts []layers.TCPOption, payload []byte) error {
	eth := &layers.Ethernet{SrcMAC: s.srcMAC, DstMAC: s.dstMAC, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 128, Id: uint16(rand.Intn(65535)), Protocol: layers.IPProtocolTCP,
		SrcIP: s.srcIP, DstIP: s.dstIP, Flags: layers.IPv4DontFragment,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(s.srcPort), DstPort: layers.TCPPort(s.dstPort),
		Seq: s.seq, Ack: s.ack, Window: 64240, Options: opts,
		SYN: flags.syn, ACK: flags.ack, PSH: flags.psh, FIN: flags.fin, RST: flags.rst,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		return err
	}
	buf := gopacket.NewSerializeBuffer()
	sopts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, sopts, eth, ip, tcp, gopacket.Payload(payload)); err != nil {
		return err
	}
	addr := &unix.SockaddrLinklayer{Ifindex: s.ifIndex, Halen: 6}
	copy(addr.Addr[:], s.dstMAC)
	return unix.Sendto(s.fd, buf.Bytes(), 0, addr)
}

type tcpFlags struct{ syn, ack, psh, fin, rst bool }

// recv reads frames until one belongs to our flow, returning its TCP layer. Honors the read deadline.
func (s *stack) recv() (*layers.TCP, error) {
	buf := make([]byte, 65536)
	for {
		if !s.deadline.IsZero() {
			tv := unix.NsecToTimeval(time.Until(s.deadline).Nanoseconds())
			_ = unix.SetsockoptTimeval(s.fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
		}
		n, _, err := unix.Recvfrom(s.fd, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
				return nil, os.ErrDeadlineExceeded
			}
			return nil, err
		}
		pkt := gopacket.NewPacket(buf[:n], layers.LayerTypeEthernet, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
		ipl, _ := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		tcpl, _ := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
		if ipl == nil || tcpl == nil {
			continue
		}
		if !ipl.SrcIP.Equal(s.dstIP) || uint16(tcpl.SrcPort) != s.dstPort || uint16(tcpl.DstPort) != s.srcPort {
			continue
		}
		return tcpl, nil
	}
}

// handshake performs SYN (with a WINDOWS option order) -> SYN-ACK -> ACK.
func (s *stack) handshake() error {
	s.deadline = time.Now().Add(5 * time.Second)
	if err := s.send(tcpFlags{syn: true}, winSYNOptions(), nil); err != nil {
		return err
	}
	for {
		tcp, err := s.recv()
		if err != nil {
			return err
		}
		if tcp.SYN && tcp.ACK {
			s.seq++             // our SYN consumed one sequence number
			s.ack = tcp.Seq + 1 // ack their SYN
			return s.send(tcpFlags{ack: true}, nil, nil)
		}
	}
}

// Read delivers reassembled in-order payload to the caller (TLS/HTTP), ACKing each received data segment.
func (s *stack) Read(p []byte) (int, error) {
	for len(s.inbuf) == 0 {
		tcp, err := s.recv()
		if err != nil {
			return 0, err
		}
		if tcp.RST {
			return 0, errors.New("peer reset the connection")
		}
		if len(tcp.Payload) > 0 && tcp.Seq == s.ack {
			s.inbuf = append(s.inbuf, tcp.Payload...)
			s.ack += uint32(len(tcp.Payload))
			_ = s.send(tcpFlags{ack: true}, nil, nil) // acknowledge the data so the peer sends more
		}
		if tcp.FIN {
			s.ack++
			_ = s.send(tcpFlags{ack: true}, nil, nil)
			if len(s.inbuf) == 0 {
				return 0, io.EOF
			}
		}
	}
	n := copy(p, s.inbuf)
	s.inbuf = s.inbuf[n:]
	return n, nil
}

// Write segments the payload into <=MSS PSH-ACK packets (happy path: no retransmit; docker bridge is lossless).
func (s *stack) Write(p []byte) (int, error) {
	const mss = 1400
	total := len(p)
	for len(p) > 0 {
		chunk := p
		if len(chunk) > mss {
			chunk = chunk[:mss]
		}
		if err := s.send(tcpFlags{psh: true, ack: true}, nil, chunk); err != nil {
			return 0, err
		}
		s.seq += uint32(len(chunk))
		p = p[len(chunk):]
	}
	return total, nil
}

func (s *stack) Close() error {
	_ = s.send(tcpFlags{fin: true, ack: true}, nil, nil)
	return nil
}
func (s *stack) LocalAddr() net.Addr                { return &net.TCPAddr{IP: s.srcIP, Port: int(s.srcPort)} }
func (s *stack) RemoteAddr() net.Addr               { return &net.TCPAddr{IP: s.dstIP, Port: int(s.dstPort)} }
func (s *stack) SetDeadline(t time.Time) error      { s.deadline = t; return nil }
func (s *stack) SetReadDeadline(t time.Time) error  { s.deadline = t; return nil }
func (s *stack) SetWriteDeadline(t time.Time) error { return nil }

// --- host networking helpers ---

func htons(v uint16) int { return int((v<<8)&0xff00 | v>>8) }

// routeIface returns the interface + source IP the kernel would use to reach dst (best-effort via a UDP dial).
func routeIface(dst net.IP) (*net.Interface, net.IP, error) {
	c, err := net.Dial("udp", dst.String()+":9")
	if err != nil {
		return nil, nil, err
	}
	src := c.LocalAddr().(*net.UDPAddr).IP
	_ = c.Close()
	ifaces, _ := net.Interfaces()
	for i := range ifaces {
		addrs, _ := ifaces[i].Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.Equal(src) {
				return &ifaces[i], src, nil
			}
		}
	}
	return nil, nil, fmt.Errorf("no interface for src %s", src)
}

// arpLookup reads the kernel ARP cache (/proc/net/arp) for ip's MAC.
func arpLookup(ip net.IP) (net.HardwareAddr, error) {
	data, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(data), "\n")[1:] {
		f := strings.Fields(line)
		if len(f) >= 4 && f[0] == ip.String() && f[3] != "00:00:00:00:00:00" {
			return net.ParseMAC(f[3])
		}
	}
	return nil, fmt.Errorf("no ARP entry for %s", ip)
}

// defaultGateway returns the default route's gateway IP (from /proc/net/route).
func defaultGateway() (net.IP, error) {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(data), "\n")[1:] {
		f := strings.Fields(line)
		if len(f) >= 3 && f[1] == "00000000" {
			var b [4]byte
			fmt.Sscanf(f[2], "%02x%02x%02x%02x", &b[3], &b[2], &b[1], &b[0])
			return net.IPv4(b[0], b[1], b[2], b[3]), nil
		}
	}
	return nil, errors.New("no default gateway")
}
