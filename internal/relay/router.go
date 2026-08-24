package relay

import (
	"encoding/binary"
	"net/netip"
	"time"

	"golang.org/x/sys/unix"
)

// RFC 4861 host constants, (ab)used on the master (upstream-facing) relay
// interface: after (re)start or link-up we proactively solicit an RA
// instead of passively waiting for the next unsolicited one.
const (
	maxRtrSolicitations     = 3
	rtrSolicitationInterval = 4 * time.Second
)

const (
	ndRouterSolicit = 133
	ndRouterAdvert  = 134

	ndOptSourceLinkAddr = 1
)

type routerSock struct {
	fd    int
	iface *Interface
	done  chan struct{}
}

// routerSetup opens (or tears down) the raw ICMPv6 socket used to relay
// Router Solicitations/Advertisements between interfaces.
func routerSetup(iface *Interface, enable bool) error {
	enable = enable && iface.RA != ModeDisabled

	if iface.router != nil {
		close(iface.router.done)
		closeFD(iface.router.fd)
		iface.router = nil
	}

	if !enable {
		if iface.rsTimer != nil {
			iface.rsTimer.Stop()
			iface.rsTimer = nil
		}
		return nil
	}

	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_ICMPV6)
	if err != nil {
		Errorf("socket(AF_INET6) for router relay on %s: %v", iface.Ifname, err)
		return err
	}

	ok := false
	defer func() {
		if !ok {
			closeFD(fd)
		}
	}()

	if err := bindToDevice(fd, iface.Ifname); err != nil {
		Errorf("SO_BINDTODEVICE(%s): %v", iface.Ifname, err)
		return err
	}
	if err := setsockoptInt(fd, unix.IPPROTO_RAW, unix.IPV6_CHECKSUM, 2); err != nil {
		Errorf("IPV6_CHECKSUM: %v", err)
		return err
	}
	if err := setsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_MULTICAST_HOPS, 255); err != nil {
		Errorf("IPV6_MULTICAST_HOPS: %v", err)
		return err
	}
	if err := setsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, 255); err != nil {
		Errorf("IPV6_UNICAST_HOPS: %v", err)
		return err
	}
	if err := setsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_RECVPKTINFO, 1); err != nil {
		Errorf("IPV6_RECVPKTINFO: %v", err)
		return err
	}
	if err := setsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_RECVHOPLIMIT, 1); err != nil {
		Errorf("IPV6_RECVHOPLIMIT: %v", err)
		return err
	}
	if err := setsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_MULTICAST_LOOP, 0); err != nil {
		Errorf("IPV6_MULTICAST_LOOP: %v", err)
		return err
	}

	filt := icmp6FilterBlockAll()
	icmp6FilterSetPass(&filt, ndRouterAdvert)
	icmp6FilterSetPass(&filt, ndRouterSolicit)
	if err := unix.SetsockoptICMPv6Filter(fd, unix.IPPROTO_ICMPV6, icmpv6FilterOpt, &filt); err != nil {
		Errorf("ICMP6_FILTER: %v", err)
		return err
	}

	group := allIPv6Routers
	if iface.Master {
		group = allIPv6Nodes
	}
	if err := joinMulticast6(fd, group, iface.Ifindex, true); err != nil {
		Errorf("IPV6_ADD_MEMBERSHIP: %v", err)
		return err
	}

	rs := &routerSock{fd: fd, iface: iface, done: make(chan struct{})}
	iface.router = rs
	iface.raSent = 0
	ok = true

	go routerReadLoop(rs)

	if iface.Master {
		iface.rsTimerN++
		gen := iface.rsTimerN
		iface.rsTimer = time.AfterFunc(100*time.Millisecond, func() {
			Eng.Post(func() { solicitTimerFire(iface, gen) })
		})
	}

	return nil
}

func solicitTimerFire(iface *Interface, gen int) {
	if iface.rsTimerN != gen || iface.router == nil || !iface.Master || iface.RA != ModeRelay {
		return
	}

	// A link-up event can precede IPv6 link-local address assignment. Sending
	// before the address exists fails with EADDRNOTAVAIL; wait without
	// consuming one of the three actual solicitation attempts.
	if _, ok := getLinkLocalAddr(iface); !ok {
		iface.rsTimer = time.AfterFunc(rtrSolicitationInterval, func() {
			Eng.Post(func() { solicitTimerFire(iface, gen) })
		})
		return
	}

	if !sendRouterSolicitation(iface) {
		iface.rsTimer = time.AfterFunc(rtrSolicitationInterval, func() {
			Eng.Post(func() { solicitTimerFire(iface, gen) })
		})
		return
	}

	iface.raSent++
	if iface.raSent < maxRtrSolicitations {
		iface.rsTimer = time.AfterFunc(rtrSolicitationInterval, func() {
			Eng.Post(func() { solicitTimerFire(iface, gen) })
		})
	}
}

// sendRouterSolicitation sends an RS to the all-routers multicast address,
// including a Source Link-Layer Address option per RFC 4861 4.1 whenever we know
// our own MAC.
func sendRouterSolicitation(iface *Interface) bool {
	if iface.router == nil {
		return false
	}

	pkt := make([]byte, 8)
	pkt[0] = ndRouterSolicit // type
	// code=0, checksum computed by kernel, reserved=0

	if mac, err := getMAC(iface); err == nil {
		opt := make([]byte, 8)
		opt[0] = ndOptSourceLinkAddr
		opt[1] = 1 // length in units of 8 bytes
		copy(opt[2:], mac[:6])
		pkt = append(pkt, opt...)
	}

	return sendICMP6(iface, allIPv6Routers, iface.Ifindex, netip.Addr{}, pkt) == nil
}

// forwardRouterSolicitation resends an RS out every other master interface's
// own socket.
func forwardRouterSolicitation(iface *Interface) {
	for _, c := range interfaces {
		if c.Ifindex == iface.Ifindex || !c.Master || c.RA != ModeRelay {
			continue
		}
		sendRouterSolicitation(c)
	}
}

// fixSourceLinkAddrOption rewrites the Source Link-Layer Address option (if
// present) of a Router Advertisement in place to carry mac. Without it,
// downstream hosts learn the upstream router's MAC for what is now our own
// (rewritten-source) RA, breaking Neighbor Unreachability Detection
// intermittently.
func fixSourceLinkAddrOption(data []byte, mac [6]byte) {
	const raHdrLen = 16 // sizeof(struct nd_router_advert)
	if len(data) < raHdrLen {
		return
	}

	opt := raHdrLen
	for opt+2 <= len(data) {
		optType := data[opt]
		optLen := int(data[opt+1]) * 8
		if optLen == 0 || opt+optLen > len(data) {
			break
		}

		if optType == ndOptSourceLinkAddr {
			addrLen := optLen - 2
			n := addrLen
			if n > 6 {
				n = 6
			}
			copy(data[opt+2:opt+2+n], mac[:n])
		}

		opt += optLen
	}
}

// forwardRouterAdvertisement relays an RA received on the master interface to
// every slave interface, with a private copy of the packet so each slave gets
// the SLLA option patched to its own MAC.
func forwardRouterAdvertisement(iface *Interface, data []byte) {
	for _, c := range interfaces {
		if c.Ifindex == iface.Ifindex || c.Master || c.RA != ModeRelay {
			continue
		}

		out := data
		if mac, err := getMAC(c); err == nil {
			buf := make([]byte, len(data))
			copy(buf, data)
			fixSourceLinkAddrOption(buf, hwAddrBytes6(mac))
			out = buf
		}

		sendICMP6(c, allIPv6Nodes, c.Ifindex, netip.Addr{}, out)
	}
}

// sendICMP6 sends an ICMPv6 packet on iface's router socket toward dest
// (the kernel picks the source address).
func sendICMP6(iface *Interface, dest netip.Addr, ifindex int, _ netip.Addr, payload []byte) error {
	if iface.router == nil {
		return unix.EBADF
	}
	return sendICMP6FD(iface.router.fd, iface, dest, ifindex, netip.Addr{}, payload)
}

// routerReadLoop reads ICMPv6 packets from a router socket and posts them
// to the Engine.
func routerReadLoop(rs *routerSock) {
	buf := make([]byte, 8192)
	oob := make([]byte, 256)

	for {
		select {
		case <-rs.done:
			return
		default:
		}

		n, oobn, _, _, err := unix.Recvmsg(rs.fd, buf, oob, 0)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			select {
			case <-rs.done:
				return
			default:
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		if n == 0 {
			continue
		}

		_, hoplimit, hasHL := parseCmsgs(oob[:oobn])
		if hasHL && hoplimit != 255 {
			continue
		}

		data := make([]byte, n)
		copy(data, buf[:n])

		Eng.Post(func() { handleICMPv6(rs, data) })
	}
}

// handleICMPv6 validates and relays RS/RA between interfaces.
func handleICMPv6(rs *routerSock, data []byte) {
	iface := rs.iface
	if iface.router != rs || iface.RA != ModeRelay {
		return
	}
	if len(data) < 4 {
		return
	}

	icmpType := data[0]
	icmpCode := data[1]
	if icmpCode != 0 {
		return
	}

	switch icmpType {
	case ndRouterSolicit:
		forwardRouterSolicitation(iface)
	case ndRouterAdvert:
		if iface.Master {
			captureLastRAHeader(iface, data)
			trackWANPrefixSnooping(iface, data)
		}
		forwardRouterAdvertisement(iface, data)
	}
}

// captureLastRAHeader remembers the fixed header fields of a real Router
// Advertisement received on a master interface, so a later synthesized
// prefix-deprecation RA (see prefixwatch.go) can reuse them instead of
// guessing values that could otherwise affect default-router selection.
func captureLastRAHeader(iface *Interface, data []byte) {
	const raHdrLen = 16 // sizeof(struct nd_router_advert)
	if len(data) < raHdrLen {
		return
	}
	iface.haveLastRA = true
	iface.lastRAHopLimit = data[4]
	iface.lastRAFlags = data[5]
	iface.lastRARouterLifetime = binary.BigEndian.Uint16(data[6:8])
	iface.lastRAReachableTime = binary.BigEndian.Uint32(data[8:12])
	iface.lastRARetransTimer = binary.BigEndian.Uint32(data[12:16])
}
