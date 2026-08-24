package relay

import (
	"encoding/binary"
	"net/netip"
	"testing"
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

func TestParsePIOPrefixesFiltersToULAAndGlobalUnicast(t *testing.T) {
	cases := []struct {
		prefix string
		want   bool
	}{
		{"2001:db8:1::/64", true},
		{"fd00:1::/64", false},
		{"fe80::/64", false},
	}

	for _, c := range cases {
		p := netip.MustParsePrefix(c.prefix)
		got := parsePIOPrefixes(buildTestRA(p))
		if c.want && (len(got) != 1 || got[0] != p.Masked()) {
			t.Errorf("parsePIOPrefixes(%s) = %v, want [%s]", c.prefix, got, p.Masked())
		}
		if !c.want && len(got) != 0 {
			t.Errorf("parsePIOPrefixes(%s) = %v, want empty", c.prefix, got)
		}
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

func TestTrackWANPrefixSnoopingSeedsSilentlyOnFirstRA(t *testing.T) {
	withCleanPrefixWatchState(t)

	wan := &Interface{Name: "wan", Ifname: "wan0", Master: true}
	interfaces["wan"] = wan

	want := netip.MustParsePrefix("2001:db8:1::/64")
	trackWANPrefixSnooping(wan, buildTestRA(want))

	if !wan.knownWANPrefixes[want] {
		t.Fatalf("knownWANPrefixes = %v, want %v present", wan.knownWANPrefixes, want)
	}
	if len(activePrefixWatches) != 0 {
		t.Fatalf("first (seeding) RA must not start any deprecation watch, got %v", activePrefixWatches)
	}
}

func TestTrackWANPrefixSnoopingAddsNewPrefixImmediately(t *testing.T) {
	withCleanPrefixWatchState(t)

	wan := &Interface{Name: "wan", Ifname: "wan0", Master: true}
	interfaces["wan"] = wan

	oldPrefix := netip.MustParsePrefix("2001:db8:1::/64")
	newPrefix := netip.MustParsePrefix("2001:db8:2::/64")

	trackWANPrefixSnooping(wan, buildTestRA(oldPrefix)) // seed

	// An RA can carry a brand new prefix without withdrawing the old one -
	// it must be trusted right away (no threshold needed to *add* a
	// prefix), and the old one must not be dropped after just one RA that
	// happens not to repeat it.
	trackWANPrefixSnooping(wan, buildTestRA(newPrefix))

	if !wan.knownWANPrefixes[newPrefix] {
		t.Fatalf("newly-seen prefix %s should be known immediately, got %v", newPrefix, wan.knownWANPrefixes)
	}
	if !wan.knownWANPrefixes[oldPrefix] {
		t.Fatalf("old prefix %s should not be dropped after a single miss, got %v", oldPrefix, wan.knownWANPrefixes)
	}
}

func TestTrackWANPrefixSnoopingDropsPrefixAfterThresholdConsecutiveMisses(t *testing.T) {
	withCleanPrefixWatchState(t)

	wan := &Interface{Name: "wan", Ifname: "wan0", Master: true}
	interfaces["wan"] = wan

	oldPrefix := netip.MustParsePrefix("2001:db8:1::/64")
	newPrefix := netip.MustParsePrefix("2001:db8:2::/64")

	trackWANPrefixSnooping(wan, buildTestRA(oldPrefix)) // seed

	for i := 0; i < prefixMismatchThreshold-1; i++ {
		trackWANPrefixSnooping(wan, buildTestRA(newPrefix))
	}
	if !wan.knownWANPrefixes[oldPrefix] {
		t.Fatalf("old prefix %s dropped too early, got %v", oldPrefix, wan.knownWANPrefixes)
	}

	// The threshold-th consecutive RA missing oldPrefix (from both the RA
	// itself and the interface's own address list) confirms it dead.
	trackWANPrefixSnooping(wan, buildTestRA(newPrefix))
	if wan.knownWANPrefixes[oldPrefix] {
		t.Fatalf("old prefix %s should have been dropped after %d consecutive misses, got %v", oldPrefix, prefixMismatchThreshold, wan.knownWANPrefixes)
	}
}

func TestTrackWANPrefixSnoopingResetsMissCountOnMatch(t *testing.T) {
	withCleanPrefixWatchState(t)

	wan := &Interface{Name: "wan", Ifname: "wan0", Master: true}
	interfaces["wan"] = wan

	oldPrefix := netip.MustParsePrefix("2001:db8:1::/64")
	newPrefix := netip.MustParsePrefix("2001:db8:2::/64")

	trackWANPrefixSnooping(wan, buildTestRA(oldPrefix)) // seed

	trackWANPrefixSnooping(wan, buildTestRA(newPrefix))
	trackWANPrefixSnooping(wan, buildTestRA(newPrefix))
	// A real RA re-carrying oldPrefix in between resets its miss streak.
	trackWANPrefixSnooping(wan, buildTestRA(oldPrefix))
	trackWANPrefixSnooping(wan, buildTestRA(newPrefix))
	trackWANPrefixSnooping(wan, buildTestRA(newPrefix))

	if !wan.knownWANPrefixes[oldPrefix] {
		t.Fatalf("old prefix %s should still be known (miss streak was reset), got %v", oldPrefix, wan.knownWANPrefixes)
	}
}

func TestTrackWANPrefixSnoopingDropsPrefixEvenIfKernelAddressLingers(t *testing.T) {
	withCleanPrefixWatchState(t)

	oldPrefix := netip.MustParsePrefix("2001:db8:1::/64")
	newPrefix := netip.MustParsePrefix("2001:db8:2::/64")

	wan := &Interface{Name: "wan", Ifname: "wan0", Master: true, Addr6: []IPAddr{
		// The interface's own kernel address list still shows an address
		// under oldPrefix (typical of an upstream that never sent a
		// proper RFC 4861 withdrawal - the address just lingers, counting
		// down its old valid_lft) - this must NOT prevent detection, since
		// that's exactly the scenario this feature exists to catch.
		{Addr: mustParseAddr("2001:db8:1::1"), PrefixLen: 64},
	}}
	interfaces["wan"] = wan

	trackWANPrefixSnooping(wan, buildTestRA(oldPrefix)) // seed

	for i := 0; i < prefixMismatchThreshold; i++ {
		trackWANPrefixSnooping(wan, buildTestRA(newPrefix))
	}

	if wan.knownWANPrefixes[oldPrefix] {
		t.Fatalf("prefix %s should have been dropped after %d consecutive RAs missing it, regardless of the lingering kernel address, got %v",
			oldPrefix, prefixMismatchThreshold, wan.knownWANPrefixes)
	}
}

// TestTrackWANPrefixSnoopingSeedsWithNewPrefixAfterRestart is a regression
// test for the exact restart scenario the orphaned-LAN-neighbor backstop
// (checkForOrphanedLANNeighbors) exists for: the WAN renumbers, the daemon
// restarts, and the very first real RA it sees after that already carries
// only the new prefix - so knownWANPrefixes gets silently seeded with just
// the new one and never personally observes the old prefix dying.
func TestTrackWANPrefixSnoopingSeedsWithNewPrefixAfterRestart(t *testing.T) {
	withCleanPrefixWatchState(t)

	wan := &Interface{Name: "wan", Ifname: "wan0", Master: true}
	interfaces["wan"] = wan

	oldPrefix := netip.MustParsePrefix("2001:db8:1::/64")
	newPrefix := netip.MustParsePrefix("2001:db8:2::/64")

	// Simulates the daemon starting up fresh after the WAN already
	// renumbered: the first real RA it ever sees only carries newPrefix.
	// (checkForOrphanedLANNeighbors also runs here, but is a no-op since
	// no LAN interfaces are registered in this test.)
	trackWANPrefixSnooping(wan, buildTestRA(newPrefix))

	if wan.knownWANPrefixes[oldPrefix] {
		t.Fatalf("a fresh start must never know about a prefix it never observed, got %v", wan.knownWANPrefixes)
	}
	if !wan.knownWANPrefixes[newPrefix] {
		t.Fatalf("newPrefix should be seeded as known, got %v", wan.knownWANPrefixes)
	}
}
