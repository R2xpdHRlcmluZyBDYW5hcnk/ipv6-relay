package relay

import (
	"net"
	"net/netip"
	"os"
	"testing"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// Run in a disposable Linux network namespace with IPV6_RELAY_NETNS_TEST=1.
func TestSweepKernelRoutesAndProxyNeighbors(t *testing.T) {
	if os.Getenv("IPV6_RELAY_NETNS_TEST") != "1" {
		t.Skip("requires an isolated network namespace with CAP_NET_ADMIN")
	}
	oldInterfaces, oldMirrored := interfaces, mirroredNeighs
	interfaces, mirroredNeighs = make(map[string]*Interface), make(map[mirroredNeighKey]bool)
	t.Cleanup(func() { interfaces, mirroredNeighs = oldInterfaces, oldMirrored })

	link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "relaytest0"}}
	if err := netlink.LinkAdd(link); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(link) })
	if err := netlink.LinkSetUp(link); err != nil {
		t.Fatal(err)
	}
	iface := &Interface{Ifname: link.Name, Ifindex: link.Index, NDP: ModeRelay, LearnRoutes: true}
	foreign := netip.MustParseAddr("2001:db8::1")
	orphan := netip.MustParseAddr("2001:db8::2")
	live := netip.MustParseAddr("2001:db8::3")

	foreignRoute := relayHostRoute(foreign, link.Index, ourRouteMetric)
	foreignRoute.Protocol = unix.RTPROT_STATIC
	if err := netlink.RouteAdd(foreignRoute); err != nil {
		t.Fatal(err)
	}
	ndpMirrorAddr(foreign, iface, true)  // do not replace the existing route
	ndpMirrorAddr(foreign, iface, false) // do not delete it either
	ndpMirrorAddr(orphan, iface, true)
	ndpMirrorAddr(live, iface, true)

	neighbor := &netlink.Neigh{
		LinkIndex: link.Index, Family: unix.AF_INET6, State: unix.NUD_PERMANENT,
		IP: net.IP(live.AsSlice()), HardwareAddr: net.HardwareAddr{2, 0, 0, 0, 0, 1},
	}
	if err := netlink.NeighAdd(neighbor); err != nil {
		t.Fatal(err)
	}
	if err := setupProxyNeigh(orphan, link.Index, true); err != nil {
		t.Fatal(err)
	}
	if err := setupProxyNeigh(live, link.Index, true); err != nil {
		t.Fatal(err)
	}
	interfaces["remote"] = &Interface{Ifindex: link.Index + 1, Addr6: []IPAddr{{Addr: live}}}

	sweepIfaceFailedAndOrphans(iface)

	routes, err := netlink.RouteList(link, unix.AF_INET6)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]netlink.RouteProtocol{
		foreign.String() + "/128": unix.RTPROT_STATIC,
		live.String() + "/128":    relayRouteProtocol,
	}
	for _, route := range routes {
		if route.Dst == nil || route.Priority != ourRouteMetric {
			continue
		}
		dst := route.Dst.String()
		if protocol, ok := want[dst]; !ok || protocol != route.Protocol {
			t.Errorf("unexpected host route after sweep: %s", route)
		}
		delete(want, dst)
	}
	if len(want) != 0 {
		t.Errorf("sweep deleted expected routes: %v", want)
	}

	proxies, err := netlink.NeighProxyList(link.Index, unix.AF_INET6)
	if err != nil {
		t.Fatal(err)
	}
	if len(proxies) != 1 || proxies[0].IP.String() != live.String() {
		t.Errorf("proxy neighbors after sweep = %v, want only the live proxy", proxies)
	}
}

func TestRefreshLinkLocalStateWithMultipleAddresses(t *testing.T) {
	iface := &Interface{
		Ifindex: 1,
		Addr6: []IPAddr{
			{Addr: mustParseAddr("fe80::1")},
			{Addr: mustParseAddr("fe80::2")},
		},
		cachedLL:      mustParseAddr("fe80::1"),
		cachedLLValid: true,
		HaveLinkLocal: true,
	}

	iface.Addr6 = iface.Addr6[1:]
	updateLinkLocalState(iface)

	if !iface.HaveLinkLocal {
		t.Fatal("removing one link-local address hid the remaining address")
	}
	if iface.cachedLLValid {
		t.Fatal("link-local source cache was not invalidated")
	}
}

func TestRelayLinkAddressSkipsTentativeAddress(t *testing.T) {
	iface := &Interface{Addr6: []IPAddr{
		{Addr: mustParseAddr("2001:db8::1"), Tentative: true},
		{Addr: mustParseAddr("2001:db8::2")},
	}}

	got, ok := relayLinkAddress(iface)
	if !ok || got != mustParseAddr("2001:db8::2") {
		t.Fatalf("relayLinkAddress() = %v, %v; want 2001:db8::2, true", got, ok)
	}
}

// RFC 8415 expects a global/site address in the Relay-Forw link-address
// field; a link-local address is never usable there, and with nothing else
// available the caller must fall back to ::.
func TestRelayLinkAddressSkipsLinkLocal(t *testing.T) {
	iface := &Interface{Addr6: []IPAddr{
		{Addr: mustParseAddr("fe80::1")},
		{Addr: mustParseAddr("2001:db8::2")},
	}}

	got, ok := relayLinkAddress(iface)
	if !ok || got != mustParseAddr("2001:db8::2") {
		t.Fatalf("relayLinkAddress() = %v, %v; want 2001:db8::2, true", got, ok)
	}

	iface = &Interface{Addr6: []IPAddr{{Addr: mustParseAddr("fe80::1")}}}
	if got, ok := relayLinkAddress(iface); ok {
		t.Fatalf("relayLinkAddress() = %v, %v with only a link-local address; want false", got, ok)
	}
}

// A config that cannot be parsed must be rejected as an error without
// touching relay state - Reload relies on that to keep the running relay
// alive when a SIGHUP lands on a broken/truncated config file.
func TestApplyConfigJSONErrorKeepsState(t *testing.T) {
	oldInterfaces := interfaces
	t.Cleanup(func() { interfaces = oldInterfaces })

	iface := &Interface{Name: "wan", Ifname: "wan0", Master: true}
	interfaces = map[string]*Interface{"wan": iface}

	if err := applyConfigJSON([]byte(`{"interfaces": {`)); err == nil {
		t.Fatal("applyConfigJSON() accepted truncated JSON")
	}
	if interfaces["wan"] != iface || !iface.Master || len(interfaces) != 1 {
		t.Fatal("failed parse mutated relay state")
	}
}

func TestDeletedLinkClearsInterfaceState(t *testing.T) {
	oldInterfaces := interfaces
	oldMirrored := mirroredNeighs
	t.Cleanup(func() {
		interfaces = oldInterfaces
		mirroredNeighs = oldMirrored
	})

	iface := &Interface{
		Name:          "test",
		Ifname:        "copilot-nonexistent",
		Ifindex:       42,
		Running:       true,
		HaveLinkLocal: true,
		Addr6:         []IPAddr{{Addr: mustParseAddr("fe80::1")}},
		RA:            ModeDisabled,
		DHCPv6:        ModeDisabled,
		NDP:           ModeDisabled,
	}
	interfaces = map[string]*Interface{"test": iface}
	mirroredNeighs = map[mirroredNeighKey]bool{}

	link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{
		Index: 42,
		Name:  iface.Ifname,
	}}
	handleLinkEvent(netlink.LinkUpdate{
		IfInfomsg: nl.IfInfomsg{IfInfomsg: unix.IfInfomsg{Index: 42}},
		Header:    unix.NlMsghdr{Type: unix.RTM_DELLINK},
		Link:      link,
	})

	if iface.Ifindex != 0 || iface.Running {
		t.Fatalf("deleted interface still active: index=%d running=%v", iface.Ifindex, iface.Running)
	}
	if len(iface.Addr6) != 0 || iface.HaveLinkLocal || iface.cachedLLValid {
		t.Fatal("deleted interface retained stale IPv6 address state")
	}
}

func TestStaleSocketPacketsAreIgnored(t *testing.T) {
	iface := &Interface{RA: ModeRelay, DHCPv6: ModeRelay, NDP: ModeRelay}

	currentRouter := &routerSock{iface: iface}
	iface.router = currentRouter
	handleICMPv6(&routerSock{iface: iface}, []byte{ndRouterSolicit, 0, 0, 0})
	if iface.raSent != 0 {
		t.Fatal("packet from stale router socket was handled")
	}

	currentDHCP := &dhcpSock{iface: iface}
	iface.dhcp = currentDHCP
	handleDHCPv6(&dhcpSock{iface: iface}, mustParseAddr("fe80::1"), []byte{dhcpMsgSolicit, 0})

	currentNDP := &ndpSock{iface: iface}
	iface.ndp = currentNDP
	handleSolicit(&ndpSock{iface: iface}, [6]byte{}, make([]byte, 64))
}
