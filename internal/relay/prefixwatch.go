package relay

import (
	"encoding/binary"
	"net/netip"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// sendPrefixDeprecation/prefixMismatchThreshold/sendPrefixDeprecationInterval
// are the global tunables the user gets for this feature (config.json's
// global.send_prefix_deprecation / global.prefix_mismatch_packet_threshold
// / global.send_prefix_deprecation_interval_seconds - see config.go's
// loadConfigJSON). Deliberately package vars with sane defaults rather than
// requiring config: this is a mitigation for upstream routers that
// renumber a delegated prefix without ever sending a proper RFC 4861
// zero-lifetime withdrawal for the old one, left on by default.
//
// *Detection* is driven entirely by real-time snooping of the actual
// Router Advertisements received on each master (WAN) interface - not by a
// timer, and deliberately NOT cross-checked against the interface's own
// kernel address list: this feature exists specifically to cover upstream
// routers that never send a proper RFC 4861 zero-lifetime withdrawal for a
// dead prefix, in which case the kernel's own SLAAC address for it also
// just lingers (counting down whatever valid_lft the last real RA gave it)
// instead of disappearing promptly - falling back to "does the interface
// still have an address under it" would defeat the whole point and mask
// real detections. An RA can legitimately carry several prefixes at once,
// so any prefix present in the just-received RA is never a mismatch. A
// previously-known prefix is only declared dead once it is absent from
// prefixMismatchThreshold consecutive real RAs. Once dead, *notifying* LAN
// neighbors still using it IS periodic/timer-based (see
// startPrefixDeprecationWatch), repeating every sendPrefixDeprecationInterval
// until none remain. If the user doesn't want this automatic notification
// at all, they can turn it off entirely via global.send_prefix_deprecation
// - that is the intended off switch, not silently disabling detection via
// an address-list fallback.
//
// Detection alone would still miss one case: knownWANPrefixes is purely
// in-memory, so a (re)start silently reseeds it from scratch (see
// trackWANPrefixSnooping) - if the WAN had already renumbered before the
// restart, the daemon never personally observes the old prefix's mismatch
// streak run out, and a LAN host that hadn't yet dropped its old address
// would otherwise be left stranded forever. checkForOrphanedLANNeighbors
// is the backstop for exactly that: after every real RA, it also checks
// every LAN neighbor's address against the union of every seeded master's
// currently-known prefixes and starts notifying any address that doesn't
// fall under any of them, regardless of whether this process ever
// personally watched that prefix die.
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

// parsePIOPrefixes walks a Router Advertisement's options (data must start
// at the ICMPv6 header, i.e. include the fixed 16-byte RA header) and
// returns every Prefix Information Option's prefix that is globally
// routable unicast, masked to its advertised prefix length.
func parsePIOPrefixes(data []byte) []netip.Prefix {
	const raHdrLen = 16
	const pioOptType = 3
	const pioOptLen = 32 // 4 * 8 bytes

	if len(data) < raHdrLen {
		return nil
	}

	var out []netip.Prefix
	opt := raHdrLen
	for opt+2 <= len(data) {
		optType := data[opt]
		optLen := int(data[opt+1]) * 8
		if optLen == 0 || opt+optLen > len(data) {
			break
		}

		if optType == pioOptType && optLen >= pioOptLen {
			prefixLen := int(data[opt+2])
			addr, ok := netip.AddrFromSlice(data[opt+16 : opt+32])
			if ok && prefixLen >= 0 && prefixLen <= 128 {
				a := addr.Unmap()
				if isGlobalUnicast(a) {
					if p, err := a.Prefix(prefixLen); err == nil {
						out = append(out, p.Masked())
					}
				}
			}
		}

		opt += optLen
	}
	return out
}

// trackWANPrefixSnooping is called for every real Router Advertisement
// received on a master interface (see handleICMPv6/captureLastRAHeader in
// router.go). It maintains iface.knownWANPrefixes, the set of GUA
// prefixes currently considered "live" on this interface, purely from
// real-time packet snooping (see the package doc comment above for why
// this deliberately does NOT fall back to the kernel's own address list):
// every prefix carried by this RA is (re)confirmed known immediately - an
// RA can legitimately carry several at once. A previously-known prefix
// absent from prefixMismatchThreshold consecutive real RAs is declared
// dead and handed off to startPrefixDeprecationWatch. The very first real
// RA observed on an interface only silently seeds knownWANPrefixes (so a
// fresh (re)start never misjudges an already-legitimate prefix as dead
// just because it hasn't been observed before). Must run on the Engine
// goroutine.
func trackWANPrefixSnooping(iface *Interface, data []byte) {
	raPrefixes := parsePIOPrefixes(data)

	confirmed := map[netip.Prefix]bool{}
	for _, p := range raPrefixes {
		confirmed[p] = true
	}

	if iface.knownWANPrefixes == nil {
		iface.knownWANPrefixes = map[netip.Prefix]bool{}
	}

	if !iface.wanPrefixSeeded {
		iface.wanPrefixSeeded = true
		for p := range confirmed {
			iface.knownWANPrefixes[p] = true
		}
		checkForOrphanedLANNeighbors(iface)
		return
	}

	// Anything carried by this RA is confirmed live: add it (if new) and
	// clear any accumulated miss count.
	for p := range confirmed {
		iface.knownWANPrefixes[p] = true
		delete(iface.missCounts, p)
	}

	// Anything previously known but absent from this RA accumulates a
	// miss; only declared dead after prefixMismatchThreshold consecutive
	// misses.
	for p := range iface.knownWANPrefixes {
		if confirmed[p] {
			continue
		}

		if iface.missCounts == nil {
			iface.missCounts = map[netip.Prefix]int{}
		}
		iface.missCounts[p]++
		if iface.missCounts[p] < prefixMismatchThreshold {
			continue
		}

		delete(iface.knownWANPrefixes, p)
		delete(iface.missCounts, p)

		Noticef("WAN prefix %s on %s missing from %d consecutive RAs, notifying LAN neighbors under it",
			p, iface.Ifname, prefixMismatchThreshold)

		startPrefixDeprecationWatch(iface, p)
	}

	checkForOrphanedLANNeighbors(iface)
}

// checkForOrphanedLANNeighbors is the restart-safety backstop for this
// feature: trackWANPrefixSnooping's own knownWANPrefixes is purely
// in-memory and gets silently reseeded from scratch on every (re)start, so
// if the WAN had already renumbered before a restart, the daemon never
// personally observes the old prefix's mismatch streak run out - it just
// starts fresh, already only knowing the new prefix. Without this check, a
// LAN host that hadn't yet dropped its old-prefix address before the
// restart (RFC 4862 5.5.3(e) alone can keep one usable for up to ~2h after
// a real deprecation, and indefinitely if no deprecation was ever sent at
// all) would keep trying to use it and fail, with nothing left to ever
// tell it otherwise. So, alongside comparing this RA against the WAN
// prefix set, also enumerate every LAN neighbor's address and check it
// against the same set: any GUA neighbor address not covered by any
// currently-known WAN prefix (from any seeded master) is orphaned and gets
// a deprecation watch started for its /64 - the real neighbor cache
// doesn't record the prefix length a host actually configured, so /64 (the
// de-facto standard SLAAC length) is the best grouping key available.
func checkForOrphanedLANNeighbors(masterIface *Interface) {
	known := map[netip.Prefix]bool{}
	anySeeded := false
	for _, iface := range interfaces {
		if !iface.Master || !iface.wanPrefixSeeded {
			continue
		}
		anySeeded = true
		for p := range iface.knownWANPrefixes {
			known[p] = true
		}
	}
	if !anySeeded {
		return
	}

	orphaned := map[netip.Prefix]bool{}
	for _, c := range interfaces {
		if c.Master || c.RA != ModeRelay {
			continue
		}

		link, err := netlink.LinkByIndex(c.Ifindex)
		if err != nil {
			continue
		}
		neighs, err := netlink.NeighList(link.Attrs().Index, unix.AF_INET6)
		if err != nil {
			continue
		}

		for _, n := range neighs {
			if n.Flags&unix.NTF_PROXY != 0 {
				continue // our own proxy-NDP entries, not real neighbors
			}

			addr, ok := netip.AddrFromSlice(n.IP.To16())
			if !ok {
				continue
			}
			addr = addr.Unmap()
			if !trackablePrefixAddr(addr) {
				continue
			}

			covered := false
			for p := range known {
				if p.Contains(addr) {
					covered = true
					break
				}
			}
			if covered {
				continue
			}

			orphaned[netip.PrefixFrom(addr, 64).Masked()] = true
		}
	}

	for p := range orphaned {
		if activePrefixWatches[p] != nil {
			continue
		}

		Noticef("LAN neighbor address under %s doesn't fall under any currently-known WAN prefix (restart backstop), notifying it", p)
		startPrefixDeprecationWatch(masterIface, p)
	}
}

// activePrefixWatches tracks, per dead prefix, the periodic notifier
// started by trackWANPrefixSnooping. Only ever touched from the Engine
// goroutine.
var activePrefixWatches = map[netip.Prefix]*prefixDeprecationWatch{}

type prefixDeprecationWatch struct {
	timer *time.Timer
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

	w := &prefixDeprecationWatch{}
	activePrefixWatches[prefix] = w
	firePrefixDeprecationWatch(masterIface, prefix, w)
}

// firePrefixDeprecationWatch sends one round of the deprecation RA and
// either reschedules itself in sendPrefixDeprecationInterval, or - once no LAN
// neighbor remains under prefix - stops and forgets this watch.
func firePrefixDeprecationWatch(masterIface *Interface, prefix netip.Prefix, w *prefixDeprecationWatch) {
	remaining := sendPrefixDeprecationRA(masterIface, prefix)
	if remaining == 0 {
		delete(activePrefixWatches, prefix)
		Noticef("No LAN neighbors remain under deprecated WAN prefix %s, stopping notifications", prefix)
		return
	}

	w.timer = time.AfterFunc(sendPrefixDeprecationInterval, func() {
		Eng.Post(func() { firePrefixDeprecationWatch(masterIface, prefix, w) })
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
