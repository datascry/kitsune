// evaders/os-spoof/stack — a concurrent happy-path userspace TCP over AF_PACKET. One manager owns the raw
// socket and demuxes frames to per-flow net.Conns, each emitting a chosen SYN option order (a forged kernel).

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
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/sys/unix"
)

// manager owns the AF_PACKET socket and a single read loop that demultiplexes inbound frames to the flow
// (by destination port) that owns them, so many userspace connections share one raw socket concurrently.
type manager struct {
	fd      int
	ifIndex int
	srcMAC  net.HardwareAddr
	dstMAC  net.HardwareAddr
	srcIP   net.IP
	dstIP   net.IP
	mu      sync.Mutex
	conns   map[uint16]*flowConn
}

// newManager resolves the egress interface + the edge IP/MAC (via the kernel ARP cache), opens the raw socket,
// and starts the demux loop. All flows target the same edge (the single allow-listed upstream).
func newManager(host string) (*manager, error) {
	dstIP := net.ParseIP(resolveIP(host)).To4()
	if dstIP == nil {
		return nil, fmt.Errorf("cannot resolve %s to IPv4", host)
	}
	iface, srcIP, err := routeIface(dstIP)
	if err != nil {
		return nil, err
	}
	_ = exec.Command("ping", "-c", "1", "-W", "1", dstIP.String()).Run()
	dstMAC, err := arpLookup(dstIP)
	if err != nil {
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
	m := &manager{
		fd: fd, ifIndex: iface.Index, srcMAC: iface.HardwareAddr, dstMAC: dstMAC,
		srcIP: srcIP.To4(), dstIP: dstIP, conns: map[uint16]*flowConn{},
	}
	go m.readLoop()
	return m, nil
}

func (m *manager) close() error { return unix.Close(m.fd) }

// readLoop reads frames and dispatches each to the flow that owns its destination port (best-effort; a full
// inbox drops — the happy-path stack assumes a lossless docker bridge).
func (m *manager) readLoop() {
	buf := make([]byte, 65536)
	for {
		n, _, err := unix.Recvfrom(m.fd, buf, 0)
		if err != nil {
			return
		}
		pkt := gopacket.NewPacket(buf[:n], layers.LayerTypeEthernet, gopacket.DecodeOptions{Lazy: true})
		ipl, _ := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		tcpl, _ := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
		if ipl == nil || tcpl == nil || !ipl.SrcIP.Equal(m.dstIP) {
			continue
		}
		m.mu.Lock()
		c := m.conns[uint16(tcpl.DstPort)]
		m.mu.Unlock()
		if c != nil {
			select {
			case c.inbox <- tcpl:
			default:
			}
		}
	}
}

// dial opens a userspace TCP flow to the edge on dstPort, forging prof's SYN option order + TTL + window.
func (m *manager) dial(prof Profile, dstPort uint16) (*flowConn, error) {
	c := &flowConn{
		m: m, srcPort: uint16(20000 + rand.Intn(40000)), dstPort: dstPort,
		seq: rand.Uint32(), ttl: prof.TTL, window: prof.Window, syn: prof.SYN,
		inbox: make(chan *layers.TCP, 256),
	}
	m.mu.Lock()
	m.conns[c.srcPort] = c
	m.mu.Unlock()
	if err := c.handshake(); err != nil {
		m.mu.Lock()
		delete(m.conns, c.srcPort)
		m.mu.Unlock()
		return nil, err
	}
	return c, nil
}

// flowConn is one userspace TCP connection, exposed as a net.Conn (so uTLS or a raw relay can ride it).
type flowConn struct {
	m        *manager
	srcPort  uint16
	dstPort  uint16
	seq      uint32
	ack      uint32
	ttl      uint8
	window   uint16
	syn      func() []layers.TCPOption
	inbox    chan *layers.TCP
	inbuf    []byte
	deadline time.Time
}

type tcpFlags struct{ syn, ack, psh, fin, rst bool }

func (c *flowConn) send(flags tcpFlags, opts []layers.TCPOption, payload []byte) error {
	eth := &layers.Ethernet{SrcMAC: c.m.srcMAC, DstMAC: c.m.dstMAC, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: c.ttl, Id: uint16(rand.Intn(65535)), Protocol: layers.IPProtocolTCP,
		SrcIP: c.m.srcIP, DstIP: c.m.dstIP, Flags: layers.IPv4DontFragment,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(c.srcPort), DstPort: layers.TCPPort(c.dstPort),
		Seq: c.seq, Ack: c.ack, Window: c.window, Options: opts,
		SYN: flags.syn, ACK: flags.ack, PSH: flags.psh, FIN: flags.fin, RST: flags.rst,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		return err
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		eth, ip, tcp, gopacket.Payload(payload)); err != nil {
		return err
	}
	addr := &unix.SockaddrLinklayer{Ifindex: c.m.ifIndex, Halen: 6}
	copy(addr.Addr[:], c.m.dstMAC)
	return unix.Sendto(c.m.fd, buf.Bytes(), 0, addr)
}

// recv pulls the next frame for this flow from its inbox, honoring the read deadline.
func (c *flowConn) recv() (*layers.TCP, error) {
	var timer <-chan time.Time
	if !c.deadline.IsZero() {
		timer = time.After(time.Until(c.deadline))
	}
	select {
	case tcp := <-c.inbox:
		return tcp, nil
	case <-timer:
		return nil, os.ErrDeadlineExceeded
	}
}

func (c *flowConn) handshake() error {
	c.deadline = time.Now().Add(5 * time.Second)
	if err := c.send(tcpFlags{syn: true}, c.syn(), nil); err != nil {
		return err
	}
	for {
		tcp, err := c.recv()
		if err != nil {
			return err
		}
		if tcp.SYN && tcp.ACK {
			c.seq++
			c.ack = tcp.Seq + 1
			return c.send(tcpFlags{ack: true}, nil, nil)
		}
	}
}

func (c *flowConn) Read(p []byte) (int, error) {
	for len(c.inbuf) == 0 {
		tcp, err := c.recv()
		if err != nil {
			return 0, err
		}
		if tcp.RST {
			return 0, errors.New("peer reset")
		}
		if len(tcp.Payload) > 0 && tcp.Seq == c.ack {
			c.inbuf = append(c.inbuf, tcp.Payload...)
			c.ack += uint32(len(tcp.Payload))
			_ = c.send(tcpFlags{ack: true}, nil, nil)
		}
		if tcp.FIN {
			c.ack++
			_ = c.send(tcpFlags{ack: true}, nil, nil)
			if len(c.inbuf) == 0 {
				return 0, io.EOF
			}
		}
	}
	n := copy(p, c.inbuf)
	c.inbuf = c.inbuf[n:]
	return n, nil
}

func (c *flowConn) Write(p []byte) (int, error) {
	const mss = 1400
	total := len(p)
	for len(p) > 0 {
		chunk := p
		if len(chunk) > mss {
			chunk = chunk[:mss]
		}
		if err := c.send(tcpFlags{psh: true, ack: true}, nil, chunk); err != nil {
			return 0, err
		}
		c.seq += uint32(len(chunk))
		p = p[len(chunk):]
	}
	return total, nil
}

func (c *flowConn) Close() error {
	_ = c.send(tcpFlags{fin: true, ack: true}, nil, nil)
	c.m.mu.Lock()
	delete(c.m.conns, c.srcPort)
	c.m.mu.Unlock()
	return nil
}
func (c *flowConn) LocalAddr() net.Addr                { return &net.TCPAddr{IP: c.m.srcIP, Port: int(c.srcPort)} }
func (c *flowConn) RemoteAddr() net.Addr               { return &net.TCPAddr{IP: c.m.dstIP, Port: int(c.dstPort)} }
func (c *flowConn) SetDeadline(t time.Time) error      { c.deadline = t; return nil }
func (c *flowConn) SetReadDeadline(t time.Time) error  { c.deadline = t; return nil }
func (c *flowConn) SetWriteDeadline(t time.Time) error { return nil }

// --- host networking helpers ---

func htons(v uint16) int { return int((v<<8)&0xff00 | v>>8) }

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
