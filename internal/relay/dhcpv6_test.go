package relay

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestDHCPv6RelayReplyPeerOffset(t *testing.T) {
	// RFC 8415 Section 9: Relay-reply Message Format:
	// msg-type: 1 byte (13)
	// hop-count: 1 byte
	// link-address: 16 bytes (offsets 2..17)
	// peer-address: 16 bytes (offsets 18..33)
	// options: remainder

	wantLink := netip.MustParseAddr("2001:db8::1")
	wantPeer := netip.MustParseAddr("fe80::1234:5678:9abc:def0")

	data := make([]byte, 34+8+8)
	data[0] = dhcpMsgRelayRepl
	data[1] = 0

	linkBytes := wantLink.As16()
	copy(data[2:18], linkBytes[:])

	peerBytes := wantPeer.As16()
	copy(data[18:34], peerBytes[:])

	// Option 18: Interface-ID (4 bytes)
	binary.BigEndian.PutUint16(data[34:36], dhcpOptInterfaceID)
	binary.BigEndian.PutUint16(data[36:38], 4)
	binary.LittleEndian.PutUint32(data[38:42], 1)

	// Option 9: Relay-Message (4 bytes payload)
	binary.BigEndian.PutUint16(data[42:44], dhcpOptRelayMsg)
	binary.BigEndian.PutUint16(data[44:46], 4)
	copy(data[46:50], []byte{dhcpMsgReply, 0x1, 0x2, 0x3})

	gotLink := netip.AddrFrom16([16]byte(data[2:18]))
	gotPeer := netip.AddrFrom16([16]byte(data[18:34]))

	if gotLink != wantLink {
		t.Fatalf("link-address parsed as %v, want %v", gotLink, wantLink)
	}
	if gotPeer != wantPeer {
		t.Fatalf("peer-address parsed as %v, want %v", gotPeer, wantPeer)
	}
}
