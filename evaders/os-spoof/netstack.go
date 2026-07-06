// evaders/os-spoof/netstack — robust userspace TCP via gVisor netstack over a bound AF_PACKET link (PARKED).
// Blocked on a go-build-clean gVisor pin: upstream ships a broken pkg/tcpip/stack/bridge_test.go; enable when fixed.

//go:build ignore

package main

import (
	"context"
	"fmt"
	"net"
	"os/exec"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

const gvisorNIC tcpip.NICID = 1

// gvisorStack is a gVisor netstack whose link layer is a raw AF_PACKET socket on the egress interface, targeting
// the single allow-listed edge. gonet gives net.Conns with a real TCP implementation over the same wire.
type gvisorStack struct {
	stk *stack.Stack
	dst tcpip.Address
	fd  int
}

// boundRawSocket opens an AF_PACKET SOCK_RAW socket BOUND to ifIndex, so fdbased's write() emits on that interface.
func boundRawSocket(ifIndex int) (int, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return -1, fmt.Errorf("AF_PACKET socket (need NET_RAW): %w", err)
	}
	ll := &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: ifIndex}
	if err := unix.Bind(fd, ll); err != nil {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("bind AF_PACKET: %w", err)
	}
	return fd, nil
}

// newGvisorStack resolves the egress iface + the edge's next-hop MAC (reusing the kernel ARP cache), binds a raw
// socket, and stands up a netstack (ipv4+tcp+arp) on it. A static neighbor for the edge skips in-stack ARP.
func newGvisorStack(host string) (*gvisorStack, error) {
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
		gw, gerr := defaultGateway()
		if gerr != nil {
			return nil, fmt.Errorf("arp %s: %w", dstIP, err)
		}
		_ = exec.Command("ping", "-c", "1", "-W", "1", gw.String()).Run()
		if dstMAC, err = arpLookup(gw); err != nil {
			return nil, fmt.Errorf("arp gateway: %w", err)
		}
	}
	fd, err := boundRawSocket(iface.Index)
	if err != nil {
		return nil, err
	}
	ep, err := fdbased.New(&fdbased.Options{
		FDs:            []int{fd},
		MTU:            1500,
		EthernetHeader: true,
		Address:        tcpip.LinkAddress(iface.HardwareAddr),
	})
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("fdbased: %w", err)
	}
	stk := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, arp.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	if e := stk.CreateNIC(gvisorNIC, ep); e != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("CreateNIC: %v", e)
	}
	src := tcpip.AddrFromSlice(srcIP.To4())
	if e := stk.AddProtocolAddress(gvisorNIC, tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber, AddressWithPrefix: src.WithPrefix(),
	}, stack.AddressProperties{}); e != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("AddProtocolAddress: %v", e)
	}
	dst := tcpip.AddrFromSlice(dstIP)
	stk.AddStaticNeighbor(gvisorNIC, dst, tcpip.LinkAddress(dstMAC))
	stk.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: gvisorNIC}})
	return &gvisorStack{stk: stk, dst: dst, fd: fd}, nil
}

// dialTCP opens a robust TCP flow to edge:dstPort via netstack, returning a net.Conn (a drop-in for flowConn).
func (g *gvisorStack) dialTCP(ctx context.Context, dstPort uint16) (net.Conn, error) {
	return gonet.DialContextTCP(
		ctx, g.stk, tcpip.FullAddress{NIC: gvisorNIC, Addr: g.dst, Port: dstPort}, ipv4.ProtocolNumber,
	)
}

func (g *gvisorStack) close() {
	g.stk.Close()
	_ = unix.Close(g.fd)
}
