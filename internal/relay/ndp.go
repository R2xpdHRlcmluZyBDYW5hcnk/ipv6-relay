package relay

import (
	"bytes"
	"net/netip"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

const (
	ndNeighborSolicit = 135
	icmp6EchoRequest  = 128
)

// bpfDropAll / bpfNSFilter are classic-BPF programs installed on the
// AF_PACKET capture socket: first a drop-all filter (to avoid a startup race
// where stray frames slip through before the real filter is attached), then
// a filter that only passes IPv6 Neighbor Solicitations.
var bpfDropAll = []unix.SockFilter{
	{Code: 0x06, Jt: 0, Jf: 0, K: 0}, // BPF_RET | BPF_K, 0
}

var bpfNSFilter = []unix.SockFilter{
	{Code: 0x30, Jt: 0, Jf: 0, K: 6},                   // BPF_LD|BPF_B|BPF_ABS, offsetof(ip6_hdr, ip6_nxt)
	{Code: 0x15, Jt: 0, Jf: 3, K: unix.IPPROTO_ICMPV6}, // BPF_JMP|BPF_JEQ|BPF_K
	{Code: 0x30, Jt: 0, Jf: 0, K: 40},                  // BPF_LD|BPF_B|BPF_ABS, sizeof(ip6_hdr)+offsetof(icmp6_hdr,icmp6_type)
	{Code: 0x15, Jt: 0, Jf: 1, K: ndNeighborSolicit},   // BPF_JMP|BPF_JEQ|BPF_K
	{Code: 0x06, Jt: 0, Jf: 0, K: 0xffffffff},          // BPF_RET|BPF_K, pass
	{Code: 0x06, Jt: 0, Jf: 0, K: 0},                   // BPF_RET|BPF_K, drop
}

type ndpSock struct {
	fd     int
	pingFd int
	iface  *Interface
	done   chan struct{}
}

func attachFilter(fd int, prog []unix.SockFilter) error {
	fprog := unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	return unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &fprog)
}

// setProxyNDP toggles net.ipv6.conf.<ifname>.proxy_ndp. Without proxy_ndp=1
// the kernel silently ignores every NTF_PROXY neighbor entry we install, so
// this must stay enabled for the whole lifetime of the relay - see
// reconcileKernelState() for why it is periodically re-asserted.
//
// The sysctl is read before writing so a re-assert that finds the value
// already correct (the common case on a debounced reconcile) is a pure read
// with no write - it never touches the value unless it actually differs.
func setProxyNDP(ifname string, enable bool) error {
	path := "/proc/sys/net/ipv6/conf/" + ifname + "/proxy_ndp"
	want := byte('0')
	if enable {
		want = '1'
	}
	if cur, err := os.ReadFile(path); err == nil {
		if c := bytes.TrimSpace(cur); len(c) == 1 && c[0] == want {
			return nil
		}
	}
	return os.WriteFile(path, []byte{want, '\n'}, 0)
}

// ndpSetup toggles the proxy_ndp sysctl and (de)configures the AF_PACKET
// capture socket + ping socket used to relay Neighbor Solicitations and
// actively resolve targets on other interfaces.
func ndpSetup(iface *Interface, enable bool) error {
	enable = enable && iface.NDP != ModeDisabled

	if iface.ndp != nil {
		close(iface.ndp.done)
		closeFD(iface.ndp.fd)
		closeFD(iface.ndp.pingFd)
		iface.ndp = nil
	}

	if !enable {
		return setProxyNDP(iface.Ifname, false)
	}

	pingFd, err := unix.Socket(unix.AF_INET6, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_ICMPV6)
	if err != nil {
		Errorf("socket(AF_INET6) for ndp ping on %s: %v", iface.Ifname, err)
		return err
	}
	okPing := false
	defer func() {
		if !okPing {
			closeFD(pingFd)
		}
	}()

	if err := bindToDevice(pingFd, iface.Ifname); err != nil {
		Errorf("SO_BINDTODEVICE(%s): %v", iface.Ifname, err)
		return err
	}
	if err := setsockoptInt(pingFd, unix.IPPROTO_RAW, unix.IPV6_CHECKSUM, 2); err != nil {
		Errorf("IPV6_CHECKSUM: %v", err)
		return err
	}
	if err := setsockoptInt(pingFd, unix.IPPROTO_IPV6, unix.IPV6_MULTICAST_HOPS, 255); err != nil {
		Errorf("IPV6_MULTICAST_HOPS: %v", err)
		return err
	}
	if err := setsockoptInt(pingFd, unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, 255); err != nil {
		Errorf("IPV6_UNICAST_HOPS: %v", err)
		return err
	}
	blockAll := icmp6FilterBlockAll()
	if err := unix.SetsockoptICMPv6Filter(pingFd, unix.IPPROTO_ICMPV6, icmpv6FilterOpt, &blockAll); err != nil {
		Errorf("ICMP6_FILTER: %v", err)
		return err
	}

	captureFd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, int(swap16(uint16(unix.ETH_P_ALL))))
	if err != nil {
		Errorf("socket(AF_PACKET) for ndp capture on %s: %v", iface.Ifname, err)
		return err
	}
	okCapture := false
	defer func() {
		if !okCapture {
			closeFD(captureFd)
		}
	}()

	if err := setProxyNDP(iface.Ifname, true); err != nil {
		Errorf("proxy_ndp(%s): %v", iface.Ifname, err)
		return err
	}

	// Drop everything until the real filter is attached, to avoid a
	// startup race where stray frames slip through first.
	if err := attachFilter(captureFd, bpfDropAll); err != nil {
		Errorf("SO_ATTACH_FILTER(drop-all): %v", err)
		return err
	}
	drainSocket(captureFd)

	if err := attachFilter(captureFd, bpfNSFilter); err != nil {
		Errorf("SO_ATTACH_FILTER(ns-filter): %v", err)
		return err
	}

	sll := &unix.SockaddrLinklayer{Protocol: swap16(uint16(unix.ETH_P_ALL)), Ifindex: iface.Ifindex}
	if err := unix.Bind(captureFd, sll); err != nil {
		Errorf("bind(AF_PACKET): %v", err)
		return err
	}
	if err := setRecvTimeout(captureFd); err != nil {
		Errorf("SO_RCVTIMEO: %v", err)
		return err
	}

	mreq := unix.PacketMreq{Ifindex: int32(iface.Ifindex), Type: unix.PACKET_MR_ALLMULTI, Alen: 6}
	if err := unix.SetsockoptPacketMreq(captureFd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &mreq); err != nil {
		Errorf("PACKET_ADD_MEMBERSHIP: %v", err)
		return err
	}

	ns := &ndpSock{fd: captureFd, pingFd: pingFd, iface: iface, done: make(chan struct{})}
	iface.ndp = ns
	okPing, okCapture = true, true

	go ndpReadLoop(ns)

	seedMirroredNeighbors(iface)

	return nil
}

// swap16 converts a host-order uint16 into big-endian (network) order.
// Needed because AF_PACKET's sll_protocol/socket()
// protocol argument are always network byte order regardless of host
// endianness.
func swap16(v uint16) uint16 {
	return v>>8 | v<<8
}

func drainSocket(fd int) {
	buf := make([]byte, 2048)
	for {
		_, _, err := unix.Recvfrom(fd, buf, unix.MSG_DONTWAIT|unix.MSG_TRUNC)
		if err != nil {
			return
		}
	}
}

func ndpReadLoop(ns *ndpSock) {
	buf := make([]byte, 2048)

	for {
		select {
		case <-ns.done:
			return
		default:
		}

		n, from, err := unix.Recvfrom(ns.fd, buf, 0)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				continue
			}
			select {
			case <-ns.done:
				return
			default:
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		if n == 0 {
			continue
		}

		sll, ok := from.(*unix.SockaddrLinklayer)
		if !ok {
			continue
		}

		data := make([]byte, n)
		copy(data, buf[:n])

		var srcMAC [6]byte
		copy(srcMAC[:], sll.Addr[:6])

		Eng.Post(func() { handleSolicit(ns, srcMAC, data) })
	}
}

// handleSolicit validates a captured Neighbor Solicitation and, unless it is our
// own self-sent probe looping back on a non-master interface, actively resolves
// the target on every other relay interface so whichever one the target actually
// sits behind learns it and triggers the proxy/host-route mirror.
func handleSolicit(ns *ndpSock, srcMAC [6]byte, data []byte) {
	iface := ns.iface
	if iface.ndp != ns || iface.NDP != ModeRelay {
		return
	}

	// ip6_hdr (40 bytes) + nd_neighbor_solicit (icmp6_hdr 8 bytes + target 16 bytes)
	if len(data) < 40+24 {
		return
	}

	hopLimit := data[7]
	src, ok := netip.AddrFromSlice(data[8:24])
	if !ok {
		return
	}
	nsCode := data[41]
	target, ok := netip.AddrFromSlice(data[48:64])
	if !ok {
		return
	}
	target = target.Unmap()

	nsIsDAD := src.Unmap().IsUnspecified()

	if hopLimit != 255 || nsCode != 0 {
		return
	}

	if target.IsLinkLocalUnicast() || target.IsLoopback() || target.IsMulticast() {
		return
	}

	mac, err := getMAC(iface)
	if err == nil && hwAddrBytes6(mac) == srcMAC && !iface.Master {
		return // our own probe looping back on a non-master interface
	}

	// The kernel answers Neighbor Solicitations for this interface's own
	// addresses natively; probing them on other interfaces is pure noise.
	for _, a := range iface.Addr6 {
		if a.Addr == target {
			return
		}
	}

	// A host already resolved on this very link answers for itself -
	// proxy-answering or probing here would only hijack its traffic through
	// us, and for two hosts on the same downstream segment the hairpinned
	// packet would blackhole (no route to hand it back out with).
	if neighResolvedOn(iface.Ifindex, target) {
		return
	}

	// This is the LAN→WAN half of the relay. The relayed RA carries the
	// upstream's on-link (L) flag verbatim, so downstream hosts treat the
	// whole relayed prefix as on-link and resolve WAN-side destinations
	// with a link-local NS. ndpMirrorAddr only installs proxy entries on
	// master interfaces, so unless the kernel also has one for the target
	// on THIS interface, nobody ever answers and the NS times out - the
	// direction that has no default route to fall back on is exactly the
	// one that breaks. Once the target is known to live behind another
	// relay interface, install the proxy entry here and let the kernel
	// answer; the soliciting host's next retransmission gets served. DAD
	// probes must never be answered this way, or the address being
	// configured looks duplicated to its owner.
	if wantProxyOnIface(iface, target, nsIsDAD) {
		if err := setupProxyNeigh(target, iface.Ifindex, true); err != nil {
			Debugf("proxy neigh %s on %s: %v", target, iface.Ifname, err)
		}
	}

	for _, c := range interfaces {
		if c != iface && c.NDP == ModeRelay {
			relayPing(target, c)
		}
	}
}

// wantProxyOnIface decides whether the kernel needs a proxy entry for target
// on the interface an NS was just heard on: never for DAD (that would make
// the probed address look in-use to its owner), never for the interface's
// own addresses (the kernel answers those itself), but yes once the target
// is known to live elsewhere - either behind a different relay interface
// (mirrored remote host) or as another interface's own address (neighbor
// discovery is interface-scoped: the kernel does not answer on lan1 for an
// address assigned to wan). Without the proxy, a downstream host that
// learned the relayed prefix as on-link resolves such targets with a
// link-local NS that nobody answers. Answering for a same-segment host that
// just hasn't been resolved yet is deliberately excluded: it would hijack
// the host's traffic through the relay instead of letting it answer
// directly.
func wantProxyOnIface(iface *Interface, target netip.Addr, nsIsDAD bool) bool {
	if nsIsDAD {
		return false
	}
	for _, a := range iface.Addr6 {
		if a.Addr == target {
			return false
		}
	}
	return mirroredOnOtherIface(target, iface.Ifindex) ||
		localOnOtherIface(target, iface.Ifindex)
}

// relayPing sends an ICMPv6 echo request to target out iface, pinned there
// via a temporary high-priority /128 route, purely to make the kernel resolve
// (and thus learn) the neighbor.
func relayPing(target netip.Addr, iface *Interface) {
	if iface.ndp == nil || iface.ndp.pingFd < 0 {
		return
	}

	_ = setupRoute(target, 128, iface.Ifindex, nil, 128, true)

	payload := make([]byte, 8)
	payload[0] = icmp6EchoRequest

	sendICMP6WithLLSrc(iface.ndp.pingFd, iface, target, iface.Ifindex, payload)

	_ = setupRoute(target, 128, iface.Ifindex, nil, 128, false)
}
