package relay

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

func TestIsULAAndIsGlobalUnicast(t *testing.T) {
	cases := []struct {
		addr       string
		wantULA    bool
		wantGlobal bool
	}{
		{"fc00::1", true, false},
		{"fd12:3456:789a::1", true, false},
		{"2001:db8::1", false, true},
		{"fe80::1", false, false},
		{"ff02::1", false, false},
		{"::1", false, false},
	}

	for _, c := range cases {
		addr := mustParseAddr(c.addr)
		if got := isULA(addr); got != c.wantULA {
			t.Errorf("isULA(%s) = %v, want %v", c.addr, got, c.wantULA)
		}
		if got := isGlobalUnicast(addr); got != c.wantGlobal {
			t.Errorf("isGlobalUnicast(%s) = %v, want %v", c.addr, got, c.wantGlobal)
		}
	}
}

// buildTestRA constructs a minimal Router Advertisement (16-byte fixed
// header, all zero except what's needed) carrying a single Prefix
// Information Option for prefix.
func buildTestRA(prefix netip.Prefix) []byte {
	pkt := make([]byte, 16+32)
	pkt[0] = ndRouterAdvert
	opt := pkt[16:]
	opt[0] = ndOptPrefixInfo
	opt[1] = 32 / 8
	opt[2] = uint8(prefix.Bits())
	binary.BigEndian.PutUint32(opt[4:8], 3600)
	binary.BigEndian.PutUint32(opt[8:12], 1800)
	copy(opt[16:32], prefix.Addr().AsSlice())
	return pkt
}

func TestParsePIOPrefixes(t *testing.T) {
	prefix := netip.MustParsePrefix("2001:db8:1::/64")
	data := buildTestRA(prefix)
	data = append(data, buildTestRA(netip.MustParsePrefix("fd00:1::/64"))[16:]...)
	got := parsePIOPrefixes(data)
	if len(got) != 1 || got[prefix] != 3600 {
		t.Fatalf("parsePIOPrefixes() = %v, want one GUA PIO with lifetime 3600", got)
	}
	if got := parsePIOPrefixes(append(data, 1, 0)); got != nil {
		t.Fatalf("accepted invalid option framing: %v", got)
	}
}

// withCleanPrefixWatchState resets the package-level state
// trackWANPrefixSnooping/startPrefixDeprecationWatch touch, and restores it
// after the test.
func withCleanPrefixWatchState(t *testing.T) {
	t.Helper()

	oldInterfaces := interfaces
	oldWatches := activePrefixWatches
	oldEnabled := sendPrefixDeprecation
	oldThreshold := prefixMismatchThreshold

	interfaces = map[string]*Interface{}
	activePrefixWatches = map[netip.Prefix]*prefixDeprecationWatch{}
	sendPrefixDeprecation = true
	prefixMismatchThreshold = 3

	t.Cleanup(func() {
		interfaces = oldInterfaces
		activePrefixWatches = oldWatches
		sendPrefixDeprecation = oldEnabled
		prefixMismatchThreshold = oldThreshold
	})
}

func TestOmittedPrefixRemainsLiveUntilAdvertisedLifetimeExpires(t *testing.T) {
	withCleanPrefixWatchState(t)
	wan := &Interface{Master: true}
	interfaces["wan"] = wan
	now := time.Now()
	prefix := netip.MustParsePrefix("2001:db8:1::/64")
	other := netip.MustParsePrefix("2001:db8:2::/64")
	trackWANPrefixSnooping(wan, buildTestRA(prefix), now)

	for i := 0; i < prefixMismatchThreshold; i++ {
		trackWANPrefixSnooping(wan, buildTestRA(other), now.Add(time.Minute))
		trackWANPrefixSnooping(wan, buildTestRA(other)[:16], now.Add(time.Minute))
	}
	if !prefixIsLive(prefix, now.Add(time.Minute)) || activePrefixWatches[prefix] != nil {
		t.Fatal("omitting a PIO shortened its advertised lifetime")
	}
	trackWANPrefixSnooping(wan, buildTestRA(other), now.Add(time.Hour))
	if _, found := wan.knownWANPrefixes[prefix]; found {
		t.Fatal("expired prefix was kept after the miss threshold")
	}
}

func TestExplicitZeroLifetimeWithdrawsKnownPrefix(t *testing.T) {
	withCleanPrefixWatchState(t)
	wan := &Interface{Master: true}
	interfaces["wan"] = wan
	now := time.Now()
	prefix := netip.MustParsePrefix("2001:db8:1::/64")
	packet := buildTestRA(prefix)
	binary.BigEndian.PutUint32(packet[20:24], 0xffffffff)
	trackWANPrefixSnooping(wan, packet, now)

	for i := 0; i < prefixMismatchThreshold; i++ {
		trackWANPrefixSnooping(wan, packet[:16], now.Add(200*365*24*time.Hour))
	}
	if !prefixIsLive(prefix, now.Add(200*365*24*time.Hour)) {
		t.Fatal("omission expired an infinite lifetime")
	}

	clear(packet[20:28])
	trackWANPrefixSnooping(wan, packet, now.Add(time.Second))
	if _, found := wan.knownWANPrefixes[prefix]; found {
		t.Fatal("zero lifetime did not withdraw the prefix")
	}
}

func TestRenewedPrefixCancelsQueuedWithdrawal(t *testing.T) {
	withCleanPrefixWatchState(t)
	wan := &Interface{Master: true}
	interfaces["wan"] = wan
	prefix := netip.MustParsePrefix("2001:db8:1::/64")
	timer := time.NewTimer(time.Hour)
	t.Cleanup(func() { timer.Stop() })
	previous := &prefixDeprecationWatch{master: wan, timer: timer}
	activePrefixWatches[prefix] = previous

	trackWANPrefixSnooping(wan, buildTestRA(prefix), time.Now())
	if activePrefixWatches[prefix] != nil || timer.Stop() {
		t.Fatal("a live advertisement must cancel the pending withdrawal")
	}

	newWatch := &prefixDeprecationWatch{master: wan}
	activePrefixWatches[prefix] = newWatch
	firePrefixDeprecationWatch(prefix, previous)
	if activePrefixWatches[prefix] != newWatch {
		t.Fatal("the stale timer callback changed the replacement watch")
	}
}
