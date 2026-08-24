package relay

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Config holds global configuration flags.
type Config struct {
	ConfigFile      string
	LogLevelCmdline bool
}

var Cfg = Config{}

type jsonGlobal struct {
	LogLevel                             *int  `json:"log_level"`
	NotifyPrefixDeprecation              *bool `json:"send_prefix_deprecation"`
	PrefixMismatchPacketThreshold        *int  `json:"prefix_mismatch_packet_threshold"`
	SendPrefixDeprecationIntervalSeconds *int  `json:"send_prefix_deprecation_interval_seconds"`
	StaleClientSweepIntervalSeconds      *int  `json:"stale_client_sweep_interval_seconds"`
}

type jsonIface struct {
	Ifname           *string `json:"ifname"`
	Master           *bool   `json:"master"`
	NdproxyRouting   *bool   `json:"ndproxy_routing"`
	NdpFromLinkLocal *bool   `json:"ndp_from_link_local"`
}

type jsonRoot struct {
	Global     *jsonGlobal          `json:"global"`
	Interfaces map[string]jsonIface `json:"interfaces"`
}

// fetchAddr6 refreshes an interface's cached IPv6 address list from the kernel.
func fetchAddr6(ifindex int) []IPAddr {
	link, err := netlink.LinkByIndex(ifindex)
	if err != nil {
		return nil
	}

	addrs, err := netlink.AddrList(link, unix.AF_INET6)
	if err != nil {
		return nil
	}

	now := uint32(nowMono())
	out := make([]IPAddr, 0, len(addrs))
	for _, a := range addrs {
		ip, ok := netip.AddrFromSlice(a.IP.To16())
		if !ok {
			continue
		}
		ip = ip.Unmap()
		ones, _ := a.Mask.Size()

		pref := lifetimeAbs(a.PreferedLft, now)
		valid := lifetimeAbs(a.ValidLft, now)

		out = append(out, IPAddr{
			Addr:        ip,
			PrefixLen:   uint8(ones),
			PreferredLT: pref,
			ValidLT:     valid,
			Tentative:   a.Flags&unix.IFA_F_TENTATIVE != 0,
		})
	}
	return out
}

func refreshInterfaceAddresses(iface *Interface) {
	iface.Addr6 = fetchAddr6(iface.Ifindex)
	updateLinkLocalState(iface)
}

func updateLinkLocalState(iface *Interface) {
	iface.cachedLLValid = false
	iface.HaveLinkLocal = false
	for _, addr := range iface.Addr6 {
		if addr.Addr.IsLinkLocalUnicast() {
			iface.HaveLinkLocal = true
			break
		}
	}
}

// lifetimeAbs converts a netlink lft (seconds remaining, or
// math.MaxUint32/-1 for "forever") into the daemon's absolute-time
// convention (0 = infinite).
func lifetimeAbs(lft int, now uint32) uint32 {
	if lft < 0 || uint32(lft) == 0xffffffff {
		return 0
	}
	l := uint32(lft)
	if l > 0xffffffff-now {
		return 0xffffffff
	}
	return l + now
}

// findOrCreateInterface returns an existing interface or initializes a new one.
func findOrCreateInterface(name string) *Interface {
	if i, ok := interfaces[name]; ok {
		return i
	}

	i := &Interface{Name: name}
	setInterfaceDefaults(i)
	interfaces[name] = i
	return i
}

// parseInterfaceJSON parses configuration for an interface.
func parseInterfaceJSON(name string, obj jsonIface) error {
	iface := findOrCreateInterface(name)

	if iface.Ifname == "" && obj.Ifname == nil {
		return fmt.Errorf("interface %q has no ifname configured", name)
	}

	if obj.Ifname != nil {
		newIfname := *obj.Ifname
		link, err := netlink.LinkByName(newIfname)
		if err != nil {
			return fmt.Errorf("interface %q (%s): %w", name, newIfname, err)
		}

		if iface.Ifindex != 0 &&
			(iface.Ifname != newIfname || iface.Ifindex != link.Attrs().Index) {
			disableServices(iface)
			clearMirroredState(iface)
		}

		iface.Ifname = newIfname
		iface.Ifindex = link.Attrs().Index
		iface.Running = link.Attrs().RawFlags&unix.IFF_RUNNING != 0
		refreshInterfaceAddresses(iface)
	}

	iface.Inuse = true

	if obj.Master != nil {
		iface.Master = *obj.Master
	}
	if obj.NdproxyRouting != nil {
		iface.LearnRoutes = *obj.NdproxyRouting
	}
	if obj.NdpFromLinkLocal != nil {
		iface.NdpFromLinkLocal = *obj.NdpFromLinkLocal
	}

	return nil
}

// loadConfigJSON reads and parses the JSON configuration file.
func loadConfigJSON(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		Errorf("Failed to read JSON config from %s: %v", path, err)
		return
	}

	var root jsonRoot
	if err := json.Unmarshal(data, &root); err != nil {
		Errorf("Failed to parse JSON config from %s: %v", path, err)
		return
	}

	if root.Global != nil && root.Global.LogLevel != nil && !Cfg.LogLevelCmdline {
		SetLogLevel(*root.Global.LogLevel)
		Noticef("Log level set to %d", LogLevel())
	}

	if root.Global != nil && root.Global.NotifyPrefixDeprecation != nil {
		sendPrefixDeprecation = *root.Global.NotifyPrefixDeprecation
	}
	if root.Global != nil && root.Global.PrefixMismatchPacketThreshold != nil &&
		*root.Global.PrefixMismatchPacketThreshold > 0 {
		prefixMismatchThreshold = *root.Global.PrefixMismatchPacketThreshold
	}
	if root.Global != nil && root.Global.SendPrefixDeprecationIntervalSeconds != nil &&
		*root.Global.SendPrefixDeprecationIntervalSeconds > 0 {
		sendPrefixDeprecationInterval = time.Duration(*root.Global.SendPrefixDeprecationIntervalSeconds) * time.Second
	}
	if root.Global != nil && root.Global.StaleClientSweepIntervalSeconds != nil &&
		*root.Global.StaleClientSweepIntervalSeconds > 0 {
		staleClientSweepInterval = time.Duration(*root.Global.StaleClientSweepIntervalSeconds) * time.Second
	}

	for name, ifaceObj := range root.Interfaces {
		if err := parseInterfaceJSON(name, ifaceObj); err != nil {
			Warnf("%v", err)
		}
	}
}

// closeInterface tears down and forgets an interface that is no longer
// present in the config.
func closeInterface(i *Interface) {
	delete(interfaces, i.Name)

	routerSetup(i, false)
	dhcpv6Setup(i, false)
	ndpSetup(i, false)

	if i.rsTimer != nil {
		i.rsTimer.Stop()
		i.rsTimer = nil
	}
}

// reloadServices (re)enables or tears down the three relay services for
// one interface based on its current link state.
func reloadServices(i *Interface) {
	if i.Running {
		Debugf("Enabling services with %s running", i.Ifname)
		_ = routerSetup(i, i.RA != ModeDisabled)
		_ = dhcpv6Setup(i, i.DHCPv6 != ModeDisabled)
		_ = ndpSetup(i, i.NDP != ModeDisabled)
	} else {
		Debugf("Disabling services with %s not running", i.Ifname)
		_ = routerSetup(i, false)
		_ = dhcpv6Setup(i, false)
		_ = ndpSetup(i, false)
	}
}

func disableServices(i *Interface) {
	_ = routerSetup(i, false)
	_ = dhcpv6Setup(i, false)
	_ = ndpSetup(i, false)
}

// Reload re-reads the config file from scratch and applies it, including the
// "disable master relay if there is no slave" logic. Must run on the Engine goroutine.
func Reload() {
	for _, i := range interfaces {
		setInterfaceDefaults(i)
		i.Inuse = false
	}

	loadConfigJSON(Cfg.ConfigFile)

	// Only after config.json has been loaded (so a configured
	// global.stale_client_sweep_interval_seconds already took effect) - see
	// scheduleMirrorSweep's doc comment.
	scheduleMirrorSweep()

	anyDHCPv6Slave, anyRASlave, anyNDPSlave := false, false, false
	for _, i := range interfaces {
		if i.Master {
			continue
		}
		if i.DHCPv6 == ModeRelay {
			anyDHCPv6Slave = true
		}
		if i.RA == ModeRelay {
			anyRASlave = true
		}
		if i.NDP == ModeRelay {
			anyNDPSlave = true
		}
	}

	for _, i := range interfaces {
		if !i.Master {
			continue
		}
		if i.DHCPv6 == ModeRelay && !anyDHCPv6Slave {
			i.DHCPv6 = ModeDisabled
		}
		if i.RA == ModeRelay && !anyRASlave {
			i.RA = ModeDisabled
		}
		if i.NDP == ModeRelay && !anyNDPSlave {
			i.NDP = ModeDisabled
		}
	}

	// Only drop interfaces that are no longer present in the reloaded
	// config at all; one that is merely not IFF_RUNNING yet must stay
	// registered so a later link-up netlink event can find and enable it.
	for _, i := range copyIfaceList() {
		if i.Inuse {
			reloadServices(i)
		} else {
			closeInterface(i)
		}
	}
}

func copyIfaceList() []*Interface {
	out := make([]*Interface, 0, len(interfaces))
	for _, i := range interfaces {
		out = append(out, i)
	}
	return out
}
