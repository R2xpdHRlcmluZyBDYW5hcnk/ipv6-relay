package relay

import (
	"fmt"
	"net"
	"net/netip"
	"time"
)

// Mode represents the operational mode of an interface in the relay daemon.
// This daemon only ever relays, so the only real states are "disabled"
// (interface currently torn down, e.g. because its link is down or there is no
// peer to relay with) and "relay".
type Mode int

const (
	ModeDisabled Mode = iota
	ModeRelay
)

// IPAddr represents one address assigned to an interface, with its prefix length
// and (absolute, wall-clock) lifetimes.
type IPAddr struct {
	Addr        netip.Addr
	PrefixLen   uint8
	PreferredLT uint32 // absolute unix time, or 0 = infinite
	ValidLT     uint32 // absolute unix time, or 0 = infinite
	Tentative   bool
}

// Interface represents a network interface. All fields are only ever read or
// written from the single Engine goroutine (see engine.go), so no locking
// is required here.
type Interface struct {
	Name    string // config key, e.g. "wan"
	Ifname  string // real netdev name, e.g. "eth0"
	Ifindex int
	Running bool // IFF_RUNNING (carrier up)
	Master  bool

	LearnRoutes      bool
	NdpFromLinkLocal bool
	Inuse            bool

	Addr6 []IPAddr

	cachedLL      netip.Addr
	cachedLLValid bool
	HaveLinkLocal bool

	RA     Mode
	DHCPv6 Mode
	NDP    Mode

	router *routerSock
	dhcp   *dhcpSock
	ndp    *ndpSock

	raSent   int
	rsTimer  *time.Timer
	rsTimerN int // generation counter to invalidate stale timers after reload

	// knownWANPrefixes/missCounts/wanPrefixSeeded back trackWANPrefixSnooping
	// (see prefixwatch.go): real-time snooping of the actual Router
	// Advertisements received on this master interface determines which
	// ULA/GUA prefixes are currently "live" - an RA can legitimately carry
	// several such prefixes at once. Deliberately NOT cross-checked
	// against the interface's own kernel address list (see prefixwatch.go's
	// package doc comment for why). A previously-known prefix is only
	// dropped as dead after prefixMismatchThreshold consecutive real RAs
	// in which it's absent from that RA's PIOs. knownWANPrefixes is also
	// read by checkForOrphanedLANNeighbors as the reference set for
	// spotting a LAN neighbor stuck on a prefix this process never
	// personally watched die (e.g. after a restart).
	knownWANPrefixes map[netip.Prefix]bool
	missCounts       map[netip.Prefix]int
	wanPrefixSeeded  bool

	// lastRA* caches the fixed header of the last real Router Advertisement
	// relayed on this master interface, so a synthesized prefix-deprecation
	// RA (see sendPrefixDeprecationRA) can copy its Cur Hop Limit/Flags/
	// Router Lifetime/Reachable Time/Retrans Timer instead of guessing
	// values that could otherwise affect default-router selection on
	// downstream hosts.
	haveLastRA           bool
	lastRAHopLimit       uint8
	lastRAFlags          uint8
	lastRARouterLifetime uint16
	lastRAReachableTime  uint32
	lastRARetransTimer   uint32
}

// interfaces holds every configured interface keyed by its config name.
// Only ever touched from the Engine goroutine.
var interfaces = map[string]*Interface{}

func ifaceByIndex(idx int) *Interface {
	for _, i := range interfaces {
		if i.Ifindex == idx {
			return i
		}
	}
	return nil
}

func ifaceByIfname(name string) *Interface {
	for _, i := range interfaces {
		if i.Ifname == name {
			return i
		}
	}
	return nil
}

// setInterfaceDefaults resets the service configuration of an interface:
// this daemon relays everything by default.
func setInterfaceDefaults(i *Interface) {
	i.RA = ModeRelay
	i.DHCPv6 = ModeRelay
	i.NDP = ModeRelay
	i.LearnRoutes = true
	i.NdpFromLinkLocal = true
	i.cachedLLValid = false
}

// getMAC returns the hardware (MAC) address of the interface.
func getMAC(iface *Interface) (net.HardwareAddr, error) {
	nif, err := net.InterfaceByName(iface.Ifname)
	if err != nil {
		return nil, err
	}
	if len(nif.HardwareAddr) < 6 {
		return nil, fmt.Errorf("interface %s has no hardware address", iface.Ifname)
	}
	return nif.HardwareAddr, nil
}

// getLinkLocalAddr returns (and caches) the interface's link-local address,
// used as relay source address for RFC 4861 compliant sends.
func getLinkLocalAddr(iface *Interface) (netip.Addr, bool) {
	if iface.cachedLLValid {
		return iface.cachedLL, true
	}

	for _, a := range iface.Addr6 {
		if !a.Tentative && a.Addr.Is6() && a.Addr.IsLinkLocalUnicast() {
			iface.cachedLL = a.Addr
			iface.cachedLLValid = true
			return a.Addr, true
		}
	}

	return netip.Addr{}, false
}

// relayLinkAddress picks an appropriate address for relaying:
// prefer an address that is both valid and preferred; fall back to
// whichever valid address has the longest remaining valid lifetime.
func relayLinkAddress(iface *Interface) (netip.Addr, bool) {
	now := uint32(nowMono())
	var best *IPAddr

	for idx := range iface.Addr6 {
		a := &iface.Addr6[idx]

		if a.Tentative || (a.ValidLT != 0 && a.ValidLT <= now) {
			continue // expired
		}

		if a.PreferredLT == 0 || a.PreferredLT > now {
			best = a
			break
		}

		if best == nil || (a.ValidLT == 0) || (best.ValidLT != 0 && a.ValidLT > best.ValidLT) {
			best = a
		}
	}

	if best == nil {
		return netip.Addr{}, false
	}
	return best.Addr, true
}
