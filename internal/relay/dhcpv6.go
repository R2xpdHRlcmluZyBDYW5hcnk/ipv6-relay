package relay

import (
	"encoding/binary"
	"net/netip"
	"time"

	"golang.org/x/sys/unix"
)

const (
	dhcpv6ClientPort = 546
	dhcpv6ServerPort = 547
	dhcpv6HopLimit   = 32

	dhcpMsgSolicit            = 1
	dhcpMsgAdvertise          = 2
	dhcpMsgRequest            = 3
	dhcpMsgConfirm            = 4
	dhcpMsgRenew              = 5
	dhcpMsgRebind             = 6
	dhcpMsgReply              = 7
	dhcpMsgRelease            = 8
	dhcpMsgDecline            = 9
	dhcpMsgReconfigure        = 10
	dhcpMsgInformationRequest = 11
	dhcpMsgRelayForw          = 12
	dhcpMsgRelayRepl          = 13

	dhcpOptRelayMsg    = 9
	dhcpOptInterfaceID = 18
)

type dhcpSock struct {
	fd    int
	iface *Interface
	done  chan struct{}
}

// dhcpv6Setup opens (or tears down) a UDP/547 socket joined to the
// All_DHCP_Relay_Agents_and_Servers multicast group on the given interface.
func dhcpv6Setup(iface *Interface, enable bool) error {
	enable = enable && iface.DHCPv6 != ModeDisabled

	if iface.dhcp != nil {
		close(iface.dhcp.done)
		closeFD(iface.dhcp.fd)
		iface.dhcp = nil
	}

	if !enable {
		return nil
	}

	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.IPPROTO_UDP)
	if err != nil {
		Errorf("socket(AF_INET6) for dhcpv6 relay on %s: %v", iface.Ifname, err)
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
	if err := setsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 1); err != nil {
		Errorf("IPV6_V6ONLY: %v", err)
		return err
	}
	if err := setsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		Errorf("SO_REUSEADDR: %v", err)
		return err
	}
	if err := setsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_RECVPKTINFO, 1); err != nil {
		Errorf("IPV6_RECVPKTINFO: %v", err)
		return err
	}
	if err := setsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_MULTICAST_HOPS, dhcpv6HopLimit); err != nil {
		Errorf("IPV6_MULTICAST_HOPS: %v", err)
		return err
	}
	if err := setsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_MULTICAST_LOOP, 0); err != nil {
		Errorf("IPV6_MULTICAST_LOOP: %v", err)
		return err
	}

	if err := unix.Bind(fd, &unix.SockaddrInet6{Port: dhcpv6ServerPort}); err != nil {
		Errorf("bind(:%d): %v", dhcpv6ServerPort, err)
		return err
	}

	if err := joinMulticast6(fd, allDHCPv6Relays, iface.Ifindex, true); err != nil {
		Errorf("IPV6_ADD_MEMBERSHIP: %v", err)
		return err
	}

	ds := &dhcpSock{fd: fd, iface: iface, done: make(chan struct{})}
	iface.dhcp = ds
	ok = true

	go dhcpReadLoop(ds)

	return nil
}

func dhcpReadLoop(ds *dhcpSock) {
	buf := make([]byte, 8192)
	oob := make([]byte, 256)

	for {
		select {
		case <-ds.done:
			return
		default:
		}

		n, oobn, _, from, err := unix.Recvmsg(ds.fd, buf, oob, 0)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			select {
			case <-ds.done:
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

		var src netip.Addr
		if sa6, ok := from.(*unix.SockaddrInet6); ok {
			src = netip.AddrFrom16(sa6.Addr)
		}

		data := make([]byte, n)
		copy(data, buf[:n])

		Eng.Post(func() { handleDHCPv6(ds, src, data) })
	}
}

// handleDHCPv6 processes incoming DHCPv6 packets.
func handleDHCPv6(ds *dhcpSock, src netip.Addr, data []byte) {
	iface := ds.iface
	if iface.dhcp != ds || iface.DHCPv6 != ModeRelay {
		return
	}

	if iface.Master {
		relayServerResponse(data)
	} else {
		relayClientRequest(src, data, iface, netip.Addr{})
	}
}

// relayServerResponse unwraps a Relay-Reply received from the server on the
// master interface and forwards the enclosed message to whichever slave interface
// the interface-id option names.
func relayServerResponse(data []byte) {
	Debugf("Got a DHCPv6-relay-reply")

	const hdrLen = 34 // msg_type(1) + hop_count(1) + link_address(16) + peer_address(16)
	if len(data) < hdrLen || data[0] != dhcpMsgRelayRepl {
		return
	}

	var (
		ifaceidx    int32
		haveIface   bool
		payload     []byte
		havePayload bool
	)

	off := hdrLen
	for off+4 <= len(data) {
		otype := binary.BigEndian.Uint16(data[off : off+2])
		olen := int(binary.BigEndian.Uint16(data[off+2 : off+4]))
		odata := data[off+4:]
		if olen > len(odata) {
			break
		}
		odata = odata[:olen]

		switch otype {
		case dhcpOptInterfaceID:
			if olen == 4 {
				ifaceidx = int32(binary.LittleEndian.Uint32(odata))
				haveIface = true
			}
		case dhcpOptRelayMsg:
			payload = odata
			havePayload = true
		}

		off += 4 + olen
	}

	if !haveIface || !havePayload || len(payload) < 4 {
		return
	}

	iface := ifaceByIndex(int(ifaceidx))
	if iface == nil || iface.Master || iface.dhcp == nil {
		return
	}

	targetPort := dhcpv6ClientPort
	if payload[0] == dhcpMsgRelayRepl {
		targetPort = dhcpv6ServerPort
	}

	peer := netip.AddrFrom16([16]byte(data[2:18]))

	Debugf("Sending a DHCPv6-reply on %s", iface.Name)
	sendDHCPv6(iface, peer, targetPort, payload)
}

// relayLinkAddressOrZero returns the address relayLinkAddress() would pick,
// or the unspecified address if none is available (per RFC 8415 18.2.1):
// never borrow an address from a different link.
func relayLinkAddressOrZero(iface *Interface) netip.Addr {
	if a, ok := relayLinkAddress(iface); ok {
		return a
	}
	return netip.IPv6Unspecified()
}

// relayClientRequest wraps a client message received on a slave interface in a
// Relay-Forward envelope and sends it to every master interface.
func relayClientRequest(source netip.Addr, data []byte, iface *Interface, dest netip.Addr) {
	if len(data) < 2 {
		return
	}

	msgType := data[0]

	switch msgType {
	case dhcpMsgSolicit, dhcpMsgRequest, dhcpMsgConfirm, dhcpMsgRenew, dhcpMsgRebind,
		dhcpMsgRelease, dhcpMsgDecline, dhcpMsgInformationRequest, dhcpMsgRelayForw:
		// valid client message types, fall through
	case dhcpMsgAdvertise, dhcpMsgReply, dhcpMsgReconfigure, dhcpMsgRelayRepl:
		return // these only ever come from a server
	}

	Debugf("Got a DHCPv6-request on %s", iface.Name)

	hopCount := byte(0)
	if msgType == dhcpMsgRelayForw {
		if data[1] >= dhcpv6HopLimit {
			return
		}
		hopCount = data[1] + 1
	}

	linkAddr := relayLinkAddressOrZero(iface)

	envelope := make([]byte, 0, 46)
	envelope = append(envelope, dhcpMsgRelayForw, hopCount)
	linkAddrBytes := linkAddr.As16()
	envelope = append(envelope, linkAddrBytes[:]...)
	sourceBytes := source.As16()
	envelope = append(envelope, sourceBytes[:]...)

	ifaceIDHdr := make([]byte, 8)
	binary.BigEndian.PutUint16(ifaceIDHdr[0:2], dhcpOptInterfaceID)
	binary.BigEndian.PutUint16(ifaceIDHdr[2:4], 4)
	binary.LittleEndian.PutUint32(ifaceIDHdr[4:8], uint32(iface.Ifindex))
	envelope = append(envelope, ifaceIDHdr...)

	relayHdr := make([]byte, 4)
	binary.BigEndian.PutUint16(relayHdr[0:2], dhcpOptRelayMsg)
	binary.BigEndian.PutUint16(relayHdr[2:4], uint16(len(data)))
	envelope = append(envelope, relayHdr...)

	envelope = append(envelope, data...)

	target := dest
	if !target.IsValid() {
		target = allDHCPv6Server
	}

	for _, c := range interfaces {
		if !c.Master || c.DHCPv6 != ModeRelay || c.dhcp == nil {
			continue
		}
		Debugf("Sending a DHCPv6-relay-forward on %s", c.Name)
		sendDHCPv6(c, target, dhcpv6ServerPort, envelope)
	}
}

// sendDHCPv6 sends payload out iface's DHCPv6 socket toward dest:port.
func sendDHCPv6(iface *Interface, dest netip.Addr, port int, payload []byte) {
	if iface.dhcp == nil {
		return
	}

	sa := sockaddrIn6(dest, port, iface.Ifindex)
	oob := cmsgPktinfo(iface.Ifindex, netip.Addr{})

	if err := unix.Sendmsg(iface.dhcp.fd, payload, oob, sa, 0); err != nil {
		Errorf("Failed to send DHCPv6 to %s%%%s@%s: %v", dest, iface.Name, iface.Ifname, err)
	} else {
		Debugf("Sent %d bytes DHCPv6 to %s%%%s@%s", len(payload), dest, iface.Name, iface.Ifname)
	}
}
