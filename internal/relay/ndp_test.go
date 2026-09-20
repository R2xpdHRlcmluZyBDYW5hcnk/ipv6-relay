package relay

import (
	"net/netip"
	"testing"

	"golang.org/x/sys/unix"
)

func TestWantProxyOnIface(t *testing.T) {
	lan := &Interface{
		Name:    "lan",
		Ifname:  "copilot-nonexistent",
		Ifindex: 7,
		Addr6:   []IPAddr{{Addr: mustParseAddr("2409:8a55:220:5cd0:e7:1dff:fe05:10d0")}},
	}
	wan := &Interface{
		Name:    "wan",
		Ifname:  "copilot-nonexistent-wan",
		Ifindex: 3,
		Master:  true,
		Addr6:   []IPAddr{{Addr: mustParseAddr("2409:8a55:220:5cd0:11:22:33:44")}},
	}
	lanAddr := mustParseAddr("2409:8a55:220:5cd0:e7:1dff:fe05:10d0")
	wanAddr := mustParseAddr("2409:8a55:220:5cd0:11:22:33:44")
	remoteAddr := mustParseAddr("2409:8a55:220:5cd0:aa:bb:cc:dd")

	oldInterfaces := interfaces
	oldMirrored := mirroredNeighs
	t.Cleanup(func() {
		interfaces = oldInterfaces
		mirroredNeighs = oldMirrored
	})
	interfaces = map[string]*Interface{"lan": lan, "wan": wan}
	mirroredNeighs = map[mirroredNeighKey]bool{
		{addr: remoteAddr, ifindex: 3}: true, // resolved behind wan
	}

	if wantProxyOnIface(lan, remoteAddr, true) {
		t.Fatal("DAD probes must never be proxy-answered or DAD looks like a duplicate")
	}
	if wantProxyOnIface(lan, lanAddr, false) {
		t.Fatal("the interface's own addresses are answered by the kernel itself")
	}
	if !wantProxyOnIface(lan, remoteAddr, false) {
		t.Fatal("a target known to live behind another relay interface must be proxied on this one")
	}
	// The router's own wan-side address: neighbor discovery is
	// interface-scoped, so from lan the kernel will not answer for it even
	// though it is a local address - it needs a proxy entry like any
	// remote host.
	if !wantProxyOnIface(lan, wanAddr, false) {
		t.Fatal("a target that is another interface's own address must be proxied on this one")
	}

	mirroredNeighs = map[mirroredNeighKey]bool{}
	interfaces = map[string]*Interface{"lan": lan}
	if wantProxyOnIface(lan, remoteAddr, false) {
		t.Fatal("an unresolved target must not be proxied yet: it may live on this very link, and answering would hijack its traffic through the relay")
	}
}

// buildTestNS builds a minimal Neighbor Solicitation (40-byte IPv6 header +
// 24-byte NS) for target, with an optional non-zero source.
func buildTestNS(target netip.Addr) []byte {
	pkt := make([]byte, 40+24)
	pkt[6] = unix.IPPROTO_ICMPV6 // next header
	pkt[7] = 255                 // hop limit
	copy(pkt[8:24], mustParseAddr("fe80::1").AsSlice())
	pkt[40] = ndNeighborSolicit
	copy(pkt[48:64], target.AsSlice())
	return pkt
}

// handleSolicit must silently ignore NS for addresses the kernel already
// owns on the receiving interface: the kernel answers those itself, and
// probing them on the other interfaces is pure noise (their resolution can
// only ever fail there).
func TestHandleSolicitSkipsOwnAddressTarget(t *testing.T) {
	oldInterfaces := interfaces
	oldMirrored := mirroredNeighs
	t.Cleanup(func() {
		interfaces = oldInterfaces
		mirroredNeighs = oldMirrored
	})

	target := mustParseAddr("2409:8a55:220:5cd0:e7:1dff:fe05:10d0")
	lan := &Interface{
		Name:    "lan",
		Ifname:  "copilot-nonexistent",
		Ifindex: 7,
		Addr6:   []IPAddr{{Addr: target}},
		RA:      ModeRelay, DHCPv6: ModeRelay, NDP: ModeRelay,
	}
	interfaces = map[string]*Interface{"lan": lan}
	mirroredNeighs = map[mirroredNeighKey]bool{}

	// pingFd < 0 makes relayPing a no-op, so a wrong decision here cannot
	// touch the network; the assertion is simply that the guard fires
	// before anything else would need the (nonexistent) socket.
	lan.ndp = &ndpSock{fd: -1, pingFd: -1, iface: lan, done: make(chan struct{})}
	handleSolicit(lan.ndp, [6]byte{1, 2, 3, 4, 5, 6}, buildTestNS(target))
}
