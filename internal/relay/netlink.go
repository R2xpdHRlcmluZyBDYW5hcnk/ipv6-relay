package relay

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// mirroredNeighKey tracks a downstream neighbor we have already mirrored
// (proxy-NDP entry + host route): we only want to touch the kernel on a real
// appear/disappear transition, not on every NUD reconfirmation cycle.
type mirroredNeighKey struct {
	addr    netip.Addr
	ifindex int
}

var mirroredNeighs = map[mirroredNeighKey]bool{}

// StartNetlinkMonitor subscribes to link/address/neighbor changes and
// forwards them to the Engine. It additionally subscribes to route changes:
// they are the event that lets the daemon self-heal after an external network
// manager - notably systemd-networkd driven by `netplan apply` - flushes the
// /128 host routes we install and, in the same reconfigure pass, resets
// net.ipv6.conf.<if>.proxy_ndp back to 0. See handleRouteEvent.
func StartNetlinkMonitor(done <-chan struct{}) error {
	linkCh := make(chan netlink.LinkUpdate, 64)
	if err := netlink.LinkSubscribe(linkCh, done); err != nil {
		return err
	}

	addrCh := make(chan netlink.AddrUpdate, 64)
	if err := netlink.AddrSubscribe(addrCh, done); err != nil {
		return err
	}

	neighCh := make(chan netlink.NeighUpdate, 64)
	if err := netlink.NeighSubscribe(neighCh, done); err != nil {
		return err
	}

	// A flush (e.g. ManageForeignRoutes on `netplan apply`) deletes every one
	// of our host routes in a single burst, so give this channel plenty of
	// slack to avoid dropping updates before the reader drains them.
	routeCh := make(chan netlink.RouteUpdate, 256)
	if err := netlink.RouteSubscribe(routeCh, done); err != nil {
		return err
	}

	go func() {
		for {
			select {
			case u, ok := <-linkCh:
				if !ok {
					return
				}
				Eng.Post(func() { handleLinkEvent(u) })
			case u, ok := <-addrCh:
				if !ok {
					return
				}
				Eng.Post(func() { handleAddrEvent(u) })
			case u, ok := <-neighCh:
				if !ok {
					return
				}
				Eng.Post(func() { handleNeighEvent(u) })
			case u, ok := <-routeCh:
				if !ok {
					return
				}
				Eng.Post(func() { handleRouteEvent(u) })
			case <-done:
				return
			}
		}
	}()

	// Deferred to the first Reload() (see mirrorSweepOnce/scheduleMirrorSweep)
	// rather than started here: at this point config.json hasn't been loaded
	// yet, so staleClientSweepInterval would still be the built-in default even
	// if the config overrides it via global.stale_client_sweep_interval_seconds.
	mirrorSweepDone = done

	return nil
}

// mirrorSweepDone is StartNetlinkMonitor's done channel, stashed here so
// scheduleMirrorSweep (called from Reload, once config is loaded) can start
// the periodic sweep with the correct configured interval from the start.
var mirrorSweepDone <-chan struct{}

// mirrorSweepOnce ensures the periodic sweep is only ever started once,
// regardless of how many times Reload() runs (SIGHUP).
var mirrorSweepOnce sync.Once

// scheduleMirrorSweep starts the periodic mirror sweep on its first call
// (a no-op on subsequent calls), using whatever staleClientSweepInterval is
// in effect at that point. Must be called after loadConfigJSON so a
// configured global.stale_client_sweep_interval_seconds is already applied.
func scheduleMirrorSweep() {
	mirrorSweepOnce.Do(func() {
		if mirrorSweepDone != nil {
			startMirrorSweep(mirrorSweepDone)
		}
	})
}

// ourRouteMetric is the priority the daemon installs its persistent downstream
// /128 host routes with (see ndpMirrorAddr). relay_ping's throwaway route uses
// a different metric, so filtering on this value keeps that churn from
// triggering reconciliation.
const ourRouteMetric = 1024

// staleClientSweepInterval is how often sweepFailedAndOrphans runs as a
// periodic backstop, in addition to the event-driven cleanup in
// handleNeighEvent/
// handleRouteEvent. It exists to catch things a purely event-driven
// mechanism can never notice: a real neighbor-cache entry that was already
// sitting in NUD_FAILED before this process's netlink subscription began
// (so no fresh event ever arrives for it), and an owned /128 host route/
// proxy-NDP entry whose neighbor-cache entry has since disappeared from the
// kernel entirely (not just gone FAILED) - either left over from a previous
// run of the daemon or from this one. It also actively probes any real
// neighbor entry currently sitting in NUD_STALE by asking the kernel to
// re-verify it (probeNeighbor sets NUD_PROBE, which makes the kernel itself
// send a real unicast Neighbor Solicitation per RFC 4861 7.3.1 and drive the
// NUD state machine from the reply, or lack of one) so a genuinely-dead
// host actually gets pushed to NUD_FAILED - a host that's simply gone
// silent otherwise stays STALE indefinitely and would never reach the
// FAILED reap below on its own. Deliberately NOT an ICMPv6 echo probe: NS is
// mandatory Neighbor Discovery traffic a host cannot selectively firewall
// off without breaking its own reachability to us, unlike echo requests
// which many hosts/firewalls silently drop, which would misclassify a live-
// but-ping-blocking host as dead. The probe result lands asynchronously, so
// a host pushed to FAILED by this pass is picked up on the *next* sweep (or
// immediately by handleNeighEvent, since that also watches for it).
//
// Overridable via global.stale_client_sweep_interval_seconds in config.json
// (see config.go's loadConfigJSON) - a package var rather than a const for
// that reason, default unchanged.
var staleClientSweepInterval = 300 * time.Second

// startMirrorSweep arranges for sweepFailedAndOrphans to run every
// staleClientSweepInterval until done is closed.
func startMirrorSweep(done <-chan struct{}) {
	var tick func()
	tick = func() {
		select {
		case <-done:
			return
		default:
		}
		Eng.Post(sweepFailedAndOrphans)
		time.AfterFunc(staleClientSweepInterval, tick)
	}
	time.AfterFunc(staleClientSweepInterval, tick)
}

// sweepFailedAndOrphans is the periodic backstop counterpart to
// handleNeighEvent/handleRouteEvent (see staleClientSweepInterval). It applies
// uniformly to every configured relay interface, master/WAN and slave/LAN
// alike - deliberately not restricted to any particular address type (GUA
// vs ULA), since an upstream WAN can itself be addressed out of ULA space;
// routes are already never created for loopback/multicast/link-local
// destinations in the first place (see ndpMirrorAddr), so no extra
// address-class filtering is needed here beyond that. Runs on the Engine
// goroutine.
func sweepFailedAndOrphans() {
	for _, iface := range interfaces {
		if iface.NDP != ModeRelay {
			continue
		}
		sweepIfaceFailedAndOrphans(iface)
	}
}

// sweepIfaceFailedAndOrphans lists iface's current real (non-proxy) IPv6
// neighbor-cache entries and this daemon's own /128 host routes on iface,
// then (a) reaps any real neighbor entry already sitting in NUD_FAILED and
// (b) tears down (route + proxy-NDP mirror on every other master interface)
// any owned /128 route whose destination no longer has a matching real
// neighbor-cache entry at all - regardless of whether either was created by
// this process instance or a previous run.
func sweepIfaceFailedAndOrphans(iface *Interface) {
	link, err := netlink.LinkByIndex(iface.Ifindex)
	if err != nil {
		return
	}

	neighs, err := netlink.NeighList(link.Attrs().Index, unix.AF_INET6)
	if err != nil {
		Debugf("sweep: list neighbors on %s: %v", iface.Ifname, err)
		return
	}

	live := map[netip.Addr]bool{}

	for _, n := range neighs {
		if n.Flags&unix.NTF_PROXY != 0 {
			continue // our own proxy-NDP entries, not real neighbors
		}

		addr, ok := netip.AddrFromSlice(n.IP.To16())
		if !ok {
			continue
		}
		addr = addr.Unmap()

		if addr.IsLoopback() || addr.IsMulticast() {
			continue
		}

		if n.State&unix.NUD_FAILED != 0 {
			key := mirroredNeighKey{addr: addr, ifindex: iface.Ifindex}
			if mirroredNeighs[key] {
				delete(mirroredNeighs, key)
				ndpMirrorAddr(addr, iface, false)
			}
			deleteFailedNeigh(addr, iface.Ifindex)
			continue
		}

		if addr.IsLinkLocalUnicast() {
			continue
		}

		live[addr] = true

		if n.State&unix.NUD_STALE != 0 {
			// Actively probe: a genuinely-dead host would otherwise sit in
			// STALE forever (the kernel only re-confirms on next actual
			// traffic), so it would never reach NUD_FAILED for the reap
			// above to ever catch. The probe's outcome lands
			// asynchronously - a resulting FAILED transition is reaped on
			// the next sweep (or sooner via handleNeighEvent).
			probeNeighbor(addr, iface.Ifindex)
		}
	}

	routes, err := netlink.RouteList(link, unix.AF_INET6)
	if err != nil {
		Debugf("sweep: list routes on %s: %v", iface.Ifname, err)
		return
	}

	for _, r := range routes {
		if r.LinkIndex != iface.Ifindex || r.Priority != ourRouteMetric || r.Dst == nil {
			continue
		}
		if ones, bits := r.Dst.Mask.Size(); bits != 128 || ones != 128 {
			continue
		}

		addr, ok := netip.AddrFromSlice(r.Dst.IP.To16())
		if !ok {
			continue
		}
		addr = addr.Unmap()

		if live[addr] {
			continue
		}

		delete(mirroredNeighs, mirroredNeighKey{addr: addr, ifindex: iface.Ifindex})
		Noticef("Removing orphaned host route/proxy-NDP entry %s on %s (no matching neighbor left)", addr, iface.Ifname)
		ndpMirrorAddr(addr, iface, false)
	}
}

// reconcileDebounce coalesces the burst of RTM_DELROUTE events an external
// flush produces into a single re-assertion pass, and lets the flush finish
// before we re-add so our routes stick instead of racing the deleter.
const reconcileDebounce = 2 * time.Second

// reconcileScheduled guards against stacking debounce timers. Only ever
// touched from the Engine goroutine.
var reconcileScheduled bool

// handleRouteEvent watches for deletion of the host routes the daemon owns.
// systemd-networkd (on `netplan apply`, with its default ManageForeignRoutes)
// flushes them and, in the same pass, resets proxy_ndp to 0 - neither of which
// produces a link/address/neighbor event and neither of which the
// mirroredNeighs cache notices. The route deletion is the one observable
// signal, so a single (debounced) reconcile off it restores proxy_ndp, the
// proxy-NDP entries and the host routes together. Runs on the Engine goroutine.
func handleRouteEvent(u netlink.RouteUpdate) {
	if u.Type != unix.RTM_DELROUTE || u.Priority != ourRouteMetric || u.Dst == nil {
		return
	}
	if ones, bits := u.Dst.Mask.Size(); bits != 128 || ones != 128 {
		return // only our /128 host routes
	}
	if iface := ifaceByIndex(u.LinkIndex); iface == nil || iface.NDP != ModeRelay {
		return
	}
	scheduleReconcile()
}

// scheduleReconcile arranges for exactly one reconcileKernelState() to run
// reconcileDebounce from now, collapsing a flush's event burst into a single
// pass. Runs on (and only touches state from) the Engine goroutine.
func scheduleReconcile() {
	if reconcileScheduled {
		return
	}
	reconcileScheduled = true
	time.AfterFunc(reconcileDebounce, func() {
		Eng.Post(func() {
			reconcileScheduled = false
			reconcileKernelState()
		})
	})
}

// reconcileKernelState re-applies the proxy_ndp sysctl, proxy-NDP neighbor
// entries and host routes the daemon is responsible for. Every underlying
// operation (sysctl write, NeighSet, RouteReplace) is idempotent, so on the
// steady-state happy path this is a cheap no-op; it only actually changes
// anything when something external removed our state. Runs on the Engine
// goroutine.
func reconcileKernelState() {
	for _, iface := range interfaces {
		if iface.NDP != ModeRelay || iface.ndp == nil {
			continue
		}
		if err := setProxyNDP(iface.Ifname, true); err != nil {
			Debugf("reconcile proxy_ndp on %s: %v", iface.Ifname, err)
		}
	}

	// Re-assert the mirror for every non-master interface's own downstream
	// addresses. Master (WAN) interface addresses are for the upstream link
	// only and have no neighbor entry — mirroring them creates an orphaned
	// /128 route that the sweep deletes and this reconcile re-adds in a loop.
	for _, iface := range interfaces {
		if iface.NDP != ModeRelay || iface.Master {
			continue
		}
		for _, a := range iface.Addr6 {
			addr := a.Addr
			if addr.IsLoopback() || addr.IsMulticast() || addr.IsLinkLocalUnicast() || isULA(addr) {
				continue
			}
			ndpMirrorAddr(addr, iface, true)
		}
	}

	// Re-assert the mirror for every downstream host we have learned.
	for key := range mirroredNeighs {
		iface := ifaceByIndex(key.ifindex)
		if iface == nil {
			continue
		}
		ndpMirrorAddr(key.addr, iface, true)
	}
}

// handleLinkEvent reacts to a real carrier up/down transition (IFF_RUNNING
// toggling) on a tracked interface by (re)enabling or tearing down its relay services.
func handleLinkEvent(u netlink.LinkUpdate) {
	ifname := u.Attrs().Name

	iface := ifaceByIfname(ifname)
	if iface == nil {
		return
	}

	if u.Header.Type == unix.RTM_DELLINK {
		if iface.Ifindex != int(u.Index) {
			return
		}

		disableServices(iface)
		clearMirroredState(iface)
		iface.Ifindex = 0
		iface.Running = false
		iface.Addr6 = nil
		iface.cachedLLValid = false
		iface.HaveLinkLocal = false
		return
	}

	nowRunning := u.IfInfomsg.Flags&unix.IFF_RUNNING != 0

	if iface.Ifindex == int(u.Index) {
		wasRunning := iface.Running
		iface.Running = nowRunning

		if wasRunning != nowRunning {
			if nowRunning {
				refreshInterfaceAddresses(iface)
			}
			reloadServices(iface)
		}
		return
	}

	// A same-name interface can come back with a new ifindex. Sockets,
	// multicast memberships, routes, and mirrored-neighbor bookkeeping all
	// refer to the old index and must be replaced as one lifecycle change.
	disableServices(iface)
	clearMirroredState(iface)
	iface.Ifindex = int(u.Index)
	iface.Running = nowRunning
	refreshInterfaceAddresses(iface)
	reloadServices(iface)
}

// handleAddrEvent refreshes the cached address list for the interface,
// and mirrors the changed address into proxy-NDP/host-route state.
func handleAddrEvent(u netlink.AddrUpdate) {
	if u.LinkAddress.IP.To4() != nil {
		return // IPv4, irrelevant to this daemon
	}

	iface := ifaceByIndex(u.LinkIndex)
	if iface == nil {
		return
	}

	refreshInterfaceAddresses(iface)

	addr, ok := netip.AddrFromSlice(u.LinkAddress.IP.To16())
	if !ok {
		return
	}
	addr = addr.Unmap()

	// Master (WAN) interface addresses are for the upstream link only
	// and have no neighbor entry on the interface itself; mirroring them
	// would create an orphaned /128 route that the sweep deletes and
	// reconcile re-adds, causing a permanent add/delete cycle.
	// Link-local addresses are never valid cross-interface; ULA addresses
	// are locally-assigned and meaningless to relay.
	if iface.NDP == ModeRelay && !iface.Master &&
		!addr.IsLoopback() && !addr.IsMulticast() &&
		!addr.IsLinkLocalUnicast() && !isULA(addr) {
		ndpMirrorAddr(addr, iface, u.NewAddr)
	}

	if addr.IsLinkLocalUnicast() {
		// refreshInterfaceAddresses derives this from the complete current
		// list, so removing one of multiple link-local addresses stays correct.
		iface.cachedLLValid = false
	}
}

func clearMirroredState(iface *Interface) {
	for _, cached := range iface.Addr6 {
		addr := cached.Addr
		if iface.NDP == ModeRelay && !addr.IsLoopback() && !addr.IsMulticast() &&
			!addr.IsLinkLocalUnicast() {
			ndpMirrorAddr(addr, iface, false)
		}
	}

	for key := range mirroredNeighs {
		if key.ifindex != iface.Ifindex {
			continue
		}
		ndpMirrorAddr(key.addr, iface, false)
		delete(mirroredNeighs, key)
	}
}

// handleNeighEvent handles neighbor resolution events: once the kernel
// resolves a downstream host's address (NUD_REACHABLE/STALE/DELAY/PROBE/
// PERMANENT/NOARP), mirror it into proxy-NDP + a host route; only an explicit
// NUD_FAILED reaps that mirror again. A plain deletion (idle STALE GC)
// intentionally leaves the mirror in place so idle-but-present hosts are not blackholed.
//
// A NUD_FAILED entry is also reaped from the kernel's neighbor cache
// unconditionally, not just when it was mirrored. relay_ping's speculative
// probes (see relayPing) create a real neighbor entry on every relay
// interface other than the one the target actually lives behind; on those
// "wrong" interfaces resolution can never succeed, so the entry just sits
// there FAILED forever - the kernel does not otherwise age these out under
// normal gc thresholds. Left alone, this is exactly what accumulates as a
// growing pile of stale FAILED entries in `ip -6 neigh show`.
func handleNeighEvent(u netlink.NeighUpdate) {
	if u.Type != unix.RTM_NEWNEIGH {
		return
	}

	iface := ifaceByIndex(u.LinkIndex)
	if iface == nil || iface.NDP != ModeRelay {
		return
	}

	ip4 := u.IP.To4()
	if ip4 != nil {
		return
	}

	addr, ok := netip.AddrFromSlice(u.IP.To16())
	if !ok {
		return
	}
	addr = addr.Unmap()

	if addr.IsLoopback() || addr.IsMulticast() {
		return
	}

	key := mirroredNeighKey{addr: addr, ifindex: iface.Ifindex}
	mirrored := mirroredNeighs[key]

	const resolvedMask = unix.NUD_REACHABLE | unix.NUD_STALE | unix.NUD_DELAY |
		unix.NUD_PROBE | unix.NUD_PERMANENT | unix.NUD_NOARP

	resolved := u.State&resolvedMask != 0
	failed := u.State&unix.NUD_FAILED != 0

	if resolved && !mirrored && !addr.IsLinkLocalUnicast() {
		mirroredNeighs[key] = true
		ndpMirrorAddr(addr, iface, true)
	} else if failed {
		if mirrored {
			delete(mirroredNeighs, key)
			ndpMirrorAddr(addr, iface, false)
		}
		deleteFailedNeigh(addr, iface.Ifindex)
	}
}

// probeNeighbor asks the kernel to re-verify a real (non-proxy) neighbor-
// cache entry by setting it to NUD_PROBE: the kernel itself then sends a
// real unicast Neighbor Solicitation (RFC 4861 7.3.1) and drives the entry
// to REACHABLE (NA reply) or FAILED (no reply after retries) accordingly -
// see sweepIfaceFailedAndOrphans. ESRCH/ENOENT just means the entry is
// already gone (raced with the kernel's own GC) and isn't worth logging.
func probeNeighbor(addr netip.Addr, ifindex int) {
	n := &netlink.Neigh{
		LinkIndex: ifindex,
		Family:    unix.AF_INET6,
		State:     unix.NUD_PROBE,
		IP:        net.IP(addr.AsSlice()),
	}
	if err := netlink.NeighSet(n); err != nil &&
		!errors.Is(err, syscall.ENOENT) && !errors.Is(err, syscall.ESRCH) {
		Debugf("probe neigh %s on ifindex %d: %v", addr, ifindex, err)
	}
}

// deleteFailedNeigh removes a real (non-proxy) NUD_FAILED neighbor cache
// entry so it doesn't linger indefinitely; see handleNeighEvent. ESRCH/ENOENT
// just means it's already gone (e.g. raced with the kernel's own GC) and
// isn't worth logging.
func deleteFailedNeigh(addr netip.Addr, ifindex int) {
	n := &netlink.Neigh{
		LinkIndex: ifindex,
		Family:    unix.AF_INET6,
		IP:        net.IP(addr.AsSlice()),
	}
	if err := netlink.NeighDel(n); err != nil &&
		!errors.Is(err, syscall.ENOENT) && !errors.Is(err, syscall.ESRCH) {
		Debugf("delete failed neigh %s on ifindex %d: %v", addr, ifindex, err)
	}
}

// ndpMirrorAddr installs (or removes) a proxy-NDP entry on every other master/relay
// interface, plus a host route pointing back at the interface the address
// actually lives behind.
func ndpMirrorAddr(addr netip.Addr, iface *Interface, add bool) {
	for _, c := range interfaces {
		if c.Ifindex == iface.Ifindex || !c.Master || c.NDP != ModeRelay {
			continue
		}
		// A proxy-NDP entry is inert unless proxy_ndp is enabled on its
		// interface, so re-assert it here: this keeps proxy_ndp correct even
		// after an external reset (e.g. `netplan apply`) for which no host
		// route existed to trigger handleRouteEvent.
		if add {
			if err := setProxyNDP(c.Ifname, true); err != nil {
				Debugf("proxy_ndp on %s: %v", c.Ifname, err)
			}
		}
		if err := setupProxyNeigh(addr, c.Ifindex, add); err != nil {
			Warnf("proxy neigh %s on %s: %v", addr, c.Ifname, err)
		}
	}

	if !iface.LearnRoutes || addr.IsLinkLocalUnicast() {
		return
	}

	if err := setupRoute(addr, 128, iface.Ifindex, nil, ourRouteMetric, add); err != nil {
		Warnf("route %s/128 via %s: %v", addr, iface.Ifname, err)
	}
}

// setupRoute adds or removes a route via netlink.
func setupRoute(addr netip.Addr, prefixlen int, ifindex int, gw *netip.Addr, metric int, add bool) error {
	dst := &net.IPNet{IP: net.IP(addr.AsSlice()), Mask: net.CIDRMask(prefixlen, 128)}

	route := &netlink.Route{
		LinkIndex: ifindex,
		Dst:       dst,
		Priority:  metric,
		Table:     unix.RT_TABLE_MAIN,
		Scope:     netlink.SCOPE_LINK,
	}

	if gw != nil {
		gwIP := net.IP(gw.AsSlice())
		route.Gw = gwIP
		route.Scope = netlink.SCOPE_UNIVERSE
	}

	if add {
		route.Protocol = unix.RTPROT_STATIC
		return netlink.RouteReplace(route)
	}

	// ESRCH ("no such process") from RouteDel just means the route is
	// already gone (e.g. the kernel/network stack flushed it itself when
	// the delegated prefix changed and the address was removed). The
	// desired end state - no route - already holds, so this isn't a real
	// error and shouldn't be logged as one.
	if err := netlink.RouteDel(route); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	return nil
}

// setupProxyNeigh adds or removes a proxy neighbor entry via netlink.
func setupProxyNeigh(addr netip.Addr, ifindex int, add bool) error {
	n := &netlink.Neigh{
		LinkIndex: ifindex,
		Family:    unix.AF_INET6,
		Flags:     unix.NTF_PROXY,
		IP:        net.IP(addr.AsSlice()),
	}

	if add {
		return netlink.NeighSet(n)
	}
	if err := netlink.NeighDel(n); err != nil &&
		!errors.Is(err, syscall.ENOENT) && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	return nil
}

// seedMirroredNeighbors walks the kernel's existing neighbor table after
// (re)enabling NDP relay on an interface so hosts resolved before the daemon
// (re)started are mirrored immediately instead of only on their next NUD transition.
func seedMirroredNeighbors(iface *Interface) {
	link, err := netlink.LinkByIndex(iface.Ifindex)
	if err != nil {
		return
	}

	neighs, err := netlink.NeighList(link.Attrs().Index, unix.AF_INET6)
	if err != nil {
		return
	}

	const resolvedMask = unix.NUD_REACHABLE | unix.NUD_STALE | unix.NUD_DELAY |
		unix.NUD_PROBE | unix.NUD_PERMANENT | unix.NUD_NOARP

	for _, n := range neighs {
		if n.State&resolvedMask == 0 {
			continue
		}

		addr, ok := netip.AddrFromSlice(n.IP.To16())
		if !ok {
			continue
		}
		addr = addr.Unmap()

		if addr.IsLoopback() || addr.IsMulticast() || addr.IsLinkLocalUnicast() {
			continue
		}

		key := mirroredNeighKey{addr: addr, ifindex: iface.Ifindex}
		if mirroredNeighs[key] {
			continue
		}

		mirroredNeighs[key] = true
		ndpMirrorAddr(addr, iface, true)
	}
}
