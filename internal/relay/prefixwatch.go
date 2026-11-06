package relay

import (
	"encoding/binary"
	"net/netip"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

var (
	sendPrefixDeprecation         = true
	prefixMismatchThreshold       = 3
	sendPrefixDeprecationInterval = 300 * time.Second
)

// isULA reports whether addr is a Unique Local Address (fc00::/7, RFC 4193).
func isULA(addr netip.Addr) bool {
	if !addr.Is6() {
		return false
	}
	b := addr.As16()
	return b[0]&0xfe == 0xfc
}

// trackablePrefixAddr reports whether addr should ever participate in WAN
// prefix-deprecation tracking: only globally routable unicast addresses -
// never link-local, multicast, loopback or ULA (those are never a "prefix"
// worth comparing/tracking here).
func trackablePrefixAddr(addr netip.Addr) bool {
	if !addr.Is6() || addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsLoopback() || isULA(addr) {
		return false
	}
	return true
}

// isGlobalUnicast reports whether addr is a globally routable unicast
// address, i.e. not link-local/multicast/loopback/ULA.
func isGlobalUnicast(addr netip.Addr) bool {
	return trackablePrefixAddr(addr)
}

// parsePIOPrefixes returns the advertised Valid Lifetime for each usable PIO.
// A nil map means the RA header or option framing was invalid.
func parsePIOPrefixes(data []byte) map[netip.Prefix]uint32 {
	const raHdrLen = 16
	const pioOptLen = 32

	if len(data) < raHdrLen {
		return nil
	}

	prefixes := make(map[netip.Prefix]uint32)
	for off := raHdrLen; off < len(data); {
		if len(data)-off < 2 {
			return nil
		}
		optLen := int(data[off+1]) * 8
		if optLen == 0 || optLen > len(data)-off {
			return nil
		}
		if data[off] == ndOptPrefixInfo && optLen == pioOptLen {
			opt := data[off : off+optLen]
			valid := binary.BigEndian.Uint32(opt[4:8])
			preferred := binary.BigEndian.Uint32(opt[8:12])
			addr := netip.AddrFrom16([16]byte(opt[16:32]))
			if opt[2] <= 128 && preferred <= valid && trackablePrefixAddr(addr.Unmap()) {
				prefixes[netip.PrefixFrom(addr, int(opt[2])).Masked()] = valid
			}
		}
		off += optLen
	}
	return prefixes
}

type wanPrefixState struct {
	validUntil time.Time // zero means infinite
	misses     int
}

func (p wanPrefixState) validAt(now time.Time) bool {
	return p.validUntil.IsZero() || now.Before(p.validUntil)
}

// trackWANPrefixSnooping uses the last advertised Valid Lifetime. An omitted
// PIO can count toward the miss threshold, but cannot shorten that lifetime.
func trackWANPrefixSnooping(iface *Interface, data []byte, now time.Time) {
	advertised := parsePIOPrefixes(data)
	if advertised == nil {
		return
	}
	if iface.knownWANPrefixes == nil {
		iface.knownWANPrefixes = make(map[netip.Prefix]wanPrefixState)
	}

	for prefix, lifetime := range advertised {
		if lifetime == 0 {
			continue
		}
		state := wanPrefixState{}
		if lifetime != 0xffffffff {
			state.validUntil = now.Add(time.Duration(lifetime) * time.Second)
		}
		iface.knownWANPrefixes[prefix] = state
		cancelPrefixDeprecationWatch(prefix)
	}

	for prefix, state := range iface.knownWANPrefixes {
		lifetime, present := advertised[prefix]
		if present && lifetime != 0 {
			continue
		}
		if !present {
			if state.misses < prefixMismatchThreshold {
				state.misses++
			}
			if state.misses < prefixMismatchThreshold || state.validAt(now) {
				iface.knownWANPrefixes[prefix] = state
				continue
			}
		}

		delete(iface.knownWANPrefixes, prefix)
		if !prefixIsLive(prefix, now) {
			startPrefixDeprecationWatch(iface, prefix)
		}
	}
}

func prefixIsLive(prefix netip.Prefix, now time.Time) bool {
	for _, iface := range interfaces {
		if state, ok := iface.knownWANPrefixes[prefix]; iface.Master && ok && state.validAt(now) {
			return true
		}
	}
	return false
}

func resetWANPrefixes(iface *Interface) {
	iface.knownWANPrefixes = nil
	iface.haveLastRA = false
	for prefix, watch := range activePrefixWatches {
		if watch.master == iface {
			cancelPrefixDeprecationWatch(prefix)
		}
	}
}

// activePrefixWatches tracks, per dead prefix, the periodic notifier
// started by trackWANPrefixSnooping. Only ever touched from the Engine
// goroutine.
var activePrefixWatches = map[netip.Prefix]*prefixDeprecationWatch{}

type prefixDeprecationWatch struct {
	master *Interface
	timer  *time.Timer
}

func cancelPrefixDeprecationWatch(prefix netip.Prefix) {
	if w := activePrefixWatches[prefix]; w != nil {
		if w.timer != nil {
			w.timer.Stop()
		}
		delete(activePrefixWatches, prefix)
	}
}

// startPrefixDeprecationWatch begins (if not already running, and if not
// disabled by global.send_prefix_deprecation) repeatedly notifying LAN
// neighbors still using an address under prefix that it is dead, every
// sendPrefixDeprecationInterval, until no such neighbor remains.
func startPrefixDeprecationWatch(masterIface *Interface, prefix netip.Prefix) {
	if _, exists := activePrefixWatches[prefix]; exists {
		return
	}
	if !sendPrefixDeprecation {
		Noticef("Prefix deprecation notifications disabled by config, not notifying LAN for %s", prefix)
		return
	}

	w := &prefixDeprecationWatch{master: masterIface}
	activePrefixWatches[prefix] = w
	firePrefixDeprecationWatch(prefix, w)
}

// firePrefixDeprecationWatch sends one round of the deprecation RA and
// either reschedules itself in sendPrefixDeprecationInterval, or - once no LAN
// neighbor remains under prefix - stops and forgets this watch.
func firePrefixDeprecationWatch(prefix netip.Prefix, w *prefixDeprecationWatch) {
	if activePrefixWatches[prefix] != w {
		return // the timer callback may already have been queued when canceled
	}
	if !sendPrefixDeprecation || prefixIsLive(prefix, time.Now()) {
		cancelPrefixDeprecationWatch(prefix)
		return
	}

	remaining := sendPrefixDeprecationRA(w.master, prefix)
	if remaining == 0 {
		delete(activePrefixWatches, prefix)
		Noticef("No LAN neighbors remain under deprecated WAN prefix %s, stopping notifications", prefix)
		return
	}

	w.timer = time.AfterFunc(sendPrefixDeprecationInterval, func() {
		Eng.Post(func() { firePrefixDeprecationWatch(prefix, w) })
	})
}

// sendPrefixDeprecationRA sends a synthesized zero-lifetime PIO RA for
// prefix to every LAN (non-master) relay interface that currently has at
// least one real (non-proxy) neighbor-cache entry under it, and returns the
// total number of such neighbors found across all LAN interfaces (0 means
// the caller should stop repeating).
func sendPrefixDeprecationRA(masterIface *Interface, prefix netip.Prefix) int {
	pkt := buildPrefixDeprecationRAPacket(masterIface, prefix)

	total := 0
	for _, c := range interfaces {
		if c.Master || c.RA != ModeRelay || c.router == nil {
			continue
		}

		n := countNeighborsUnderPrefix(c, prefix)
		if n == 0 {
			continue
		}
		total += n

		if pkt != nil {
			sendICMP6(c, allIPv6Nodes, c.Ifindex, netip.Addr{}, pkt)
		}
	}
	return total
}

// countNeighborsUnderPrefix returns how many of iface's real (non-proxy)
// IPv6 neighbor-cache entries are GUA addresses falling under prefix.
func countNeighborsUnderPrefix(iface *Interface, prefix netip.Prefix) int {
	link, err := netlink.LinkByIndex(iface.Ifindex)
	if err != nil {
		return 0
	}

	neighs, err := netlink.NeighList(link.Attrs().Index, unix.AF_INET6)
	if err != nil {
		return 0
	}

	count := 0
	for _, n := range neighs {
		if n.Flags&unix.NTF_PROXY != 0 {
			continue // our own proxy-NDP entries, not real neighbors
		}

		addr, ok := netip.AddrFromSlice(n.IP.To16())
		if !ok {
			continue
		}
		addr = addr.Unmap()

		if !trackablePrefixAddr(addr) || !prefix.Contains(addr) {
			continue
		}
		count++
	}
	return count
}

// buildPrefixDeprecationRAPacket synthesizes a Router Advertisement whose
// only content of interest is a single Prefix Information Option for prefix
// with both Valid and Preferred Lifetime set to 0 (RFC 4861 withdrawal).
// Every other RA header field is copied from masterIface's last real RA
// (see captureLastRAHeader in router.go) so this doesn't affect default-
// router selection on downstream hosts; if no real RA has been seen yet on
// masterIface, nil is returned (the caller still counts neighbors, but
// skips the actual send until a real header is available to copy).
func buildPrefixDeprecationRAPacket(masterIface *Interface, prefix netip.Prefix) []byte {
	if !masterIface.haveLastRA {
		return nil
	}

	const raHdrLen = 16
	const pioLen = 32
	pkt := make([]byte, raHdrLen+pioLen)

	pkt[0] = ndRouterAdvert
	pkt[1] = 0 // code
	// pkt[2:4] checksum left 0 - computed by the kernel (IPV6_CHECKSUM sockopt)
	pkt[4] = masterIface.lastRAHopLimit
	pkt[5] = masterIface.lastRAFlags
	binary.BigEndian.PutUint16(pkt[6:8], masterIface.lastRARouterLifetime)
	binary.BigEndian.PutUint32(pkt[8:12], masterIface.lastRAReachableTime)
	binary.BigEndian.PutUint32(pkt[12:16], masterIface.lastRARetransTimer)

	opt := pkt[raHdrLen:]
	opt[0] = ndOptPrefixInfo
	opt[1] = pioLen / 8
	opt[2] = uint8(prefix.Bits())
	opt[3] = pioFlagOnLink | pioFlagAutonomous
	binary.BigEndian.PutUint32(opt[4:8], 0)  // Valid Lifetime = 0
	binary.BigEndian.PutUint32(opt[8:12], 0) // Preferred Lifetime = 0
	// opt[12:16] reserved2 = 0
	copy(opt[16:32], prefix.Addr().AsSlice())

	return pkt
}

const (
	ndOptPrefixInfo = 3

	pioFlagOnLink     = 0x80
	pioFlagAutonomous = 0x40
)
