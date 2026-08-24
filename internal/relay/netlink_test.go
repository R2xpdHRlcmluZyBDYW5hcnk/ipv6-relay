package relay

import (
	"testing"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

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
