package relay

import (
	"fmt"
	"net"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/unix"
)

// cmsgPktinfo builds an IPV6_PKTINFO ancillary message selecting the
// outgoing interface (and, optionally, source address) for a send.
func cmsgPktinfo(ifindex int, src netip.Addr) []byte {
	var pi unix.Inet6Pktinfo
	pi.Ifindex = uint32(ifindex)
	if src.Is6() {
		pi.Addr = src.As16()
	}

	space := unix.CmsgSpace(int(unsafe.Sizeof(pi)))
	buf := make([]byte, space)

	h := (*unix.Cmsghdr)(unsafe.Pointer(&buf[0]))
	h.Level = unix.IPPROTO_IPV6
	h.Type = unix.IPV6_PKTINFO
	h.SetLen(unix.CmsgLen(int(unsafe.Sizeof(pi))))

	*(*unix.Inet6Pktinfo)(unsafe.Pointer(&buf[unix.CmsgLen(0)])) = pi

	return buf
}

// parseCmsgs extracts the destination ifindex (from IPV6_PKTINFO) and hop
// limit (from IPV6_HOPLIMIT) ancillary data.
func parseCmsgs(oob []byte) (ifindex int, hoplimit int, hasHoplimit bool) {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return 0, 0, false
	}

	for _, m := range msgs {
		if m.Header.Level == unix.IPPROTO_IPV6 && m.Header.Type == unix.IPV6_PKTINFO &&
			len(m.Data) >= int(unsafe.Sizeof(unix.Inet6Pktinfo{})) {
			pi := (*unix.Inet6Pktinfo)(unsafe.Pointer(&m.Data[0]))
			ifindex = int(pi.Ifindex)
		} else if m.Header.Level == unix.IPPROTO_IPV6 && m.Header.Type == unix.IPV6_HOPLIMIT &&
			len(m.Data) >= 4 {
			hoplimit = int(*(*int32)(unsafe.Pointer(&m.Data[0])))
			hasHoplimit = true
		}
	}

	return ifindex, hoplimit, hasHoplimit
}

// sockaddrIn6 builds a unix.SockaddrInet6 for dest, setting the scope ID to
// ifindex when dest is link-local/multicast.
func sockaddrIn6(dest netip.Addr, port int, ifindex int) *unix.SockaddrInet6 {
	sa := &unix.SockaddrInet6{Port: port, Addr: dest.As16()}
	if dest.IsLinkLocalUnicast() || dest.IsLinkLocalMulticast() {
		sa.ZoneId = uint32(ifindex)
	}
	return sa
}

// icmpv6FilterOpt is Linux's ICMPV6_FILTER sockopt value (1). Not exposed
// by golang.org/x/sys/unix for linux (only for BSD-family OSes, where its
// numeric value differs), so it is hardcoded here.
const icmpv6FilterOpt = 1

// icmp6FilterBlockAll returns a filter that passes nothing.
func icmp6FilterBlockAll() unix.ICMPv6Filter {
	var f unix.ICMPv6Filter
	for i := range f.Data {
		f.Data[i] = 0xffffffff
	}
	return f
}

// icmp6FilterSetPass clears the bit for icmpType.
func icmp6FilterSetPass(f *unix.ICMPv6Filter, icmpType int) {
	f.Data[icmpType>>5] &^= 1 << (uint(icmpType) & 31)
}

// bindToDevice performs SO_BINDTODEVICE to scope raw/UDP sockets to a single interface.
func bindToDevice(fd int, ifname string) error {
	return unix.BindToDevice(fd, ifname)
}

// setsockoptInt is a small readability wrapper.
func setsockoptInt(fd, level, opt, val int) error {
	return unix.SetsockoptInt(fd, level, opt, val)
}

// joinMulticast6 joins or leaves an IPv6 multicast group.
func joinMulticast6(fd int, group netip.Addr, ifindex int, join bool) error {
	mreq := &unix.IPv6Mreq{Multiaddr: group.As16(), Interface: uint32(ifindex)}
	opt := unix.IPV6_ADD_MEMBERSHIP
	if !join {
		opt = unix.IPV6_DROP_MEMBERSHIP
	}
	return unix.SetsockoptIPv6Mreq(fd, unix.IPPROTO_IPV6, opt, mreq)
}

// sendICMP6FD sends an ICMPv6 packet on an arbitrary fd toward dest out
// ifindex: if tryLinkLocalSrc is a valid address it is used as the explicit
// IPV6_PKTINFO source (RFC 4861 compliant source); otherwise the kernel picks the source.
func sendICMP6FD(fd int, iface *Interface, dest netip.Addr, ifindex int, tryLinkLocalSrc netip.Addr, payload []byte) error {
	sa := sockaddrIn6(dest, unix.IPPROTO_ICMPV6, ifindex)
	oob := cmsgPktinfo(ifindex, tryLinkLocalSrc)

	if err := unix.Sendmsg(fd, payload, oob, sa, 0); err != nil {
		Errorf("Failed to send ICMPv6 to %s%%%s@%s: %v", dest, iface.Name, iface.Ifname, err)
		return err
	} else {
		Debugf("Sent %d bytes ICMPv6 to %s%%%s@%s", len(payload), dest, iface.Name, iface.Ifname)
	}
	return nil
}

// sendICMP6WithLLSrc prefers the interface's link-local source address when
// iface.NdpFromLinkLocal is set and one is known, otherwise falls back to a
// plain send.
func sendICMP6WithLLSrc(fd int, iface *Interface, dest netip.Addr, ifindex int, payload []byte) {
	src := netip.Addr{}
	if iface.NdpFromLinkLocal {
		if ll, ok := getLinkLocalAddr(iface); ok {
			src = ll
		}
	}
	_ = sendICMP6FD(fd, iface, dest, ifindex, src, payload)
}

func mustParseAddr(s string) netip.Addr {
	a, err := netip.ParseAddr(s)
	if err != nil {
		panic(fmt.Sprintf("invalid address literal %q: %v", s, err))
	}
	return a
}

// closeFD closes a raw fd, ignoring errors on an already-closed/invalid fd.
func closeFD(fd int) {
	if fd >= 0 {
		_ = unix.Close(fd)
	}
}

var (
	allIPv6Nodes    = mustParseAddr("ff02::1")
	allIPv6Routers  = mustParseAddr("ff02::2")
	allDHCPv6Relays = mustParseAddr("ff02::1:2")
	allDHCPv6Server = mustParseAddr("ff05::1:3")
)

// hwAddrBytes6 returns the first 6 bytes of a MAC address as a fixed array.
func hwAddrBytes6(hw net.HardwareAddr) [6]byte {
	var out [6]byte
	copy(out[:], hw)
	return out
}
