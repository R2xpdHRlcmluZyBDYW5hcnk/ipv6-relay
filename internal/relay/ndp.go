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

	_ = nsIsDAD

	for _, c := range interfaces {
		if c != iface && c.NDP == ModeRelay {
			relayPing(target, c)
		}
	}
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
