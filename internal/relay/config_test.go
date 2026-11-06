package relay

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReloadWithMissingDeviceKeepsConfiguration(t *testing.T) {
	oldInterfaces, oldConfig := interfaces, Cfg
	oldLevel := LogLevel()
	t.Cleanup(func() {
		interfaces, Cfg = oldInterfaces, oldConfig
		SetLogLevel(oldLevel)
	})
	iface := &Interface{Name: "wan", Ifname: "lo", Master: true, RA: ModeRelay}
	socket := &routerSock{iface: iface}
	iface.router = socket
	interfaces = map[string]*Interface{"wan": iface}

	Cfg = Config{ConfigFile: filepath.Join(t.TempDir(), "config.json")}
	data := []byte(`{
		"global": {"log_level": 7},
		"interfaces": {"wan": {"ifname": "relay-missing"}, "lan": {"ifname": "lo"}}
	}`)
	if err := os.WriteFile(Cfg.ConfigFile, data, 0600); err != nil {
		t.Fatal(err)
	}
	Reload()
	if len(interfaces) != 1 || interfaces["wan"] != iface || !iface.Master ||
		iface.router != socket || iface.RA != ModeRelay || LogLevel() != oldLevel {
		t.Fatal("reload changed the running configuration after device validation failed")
	}
}

func TestOmittedMasterRestoresDefault(t *testing.T) {
	oldInterfaces := interfaces
	t.Cleanup(func() { interfaces = oldInterfaces })
	interfaces = make(map[string]*Interface)
	if err := applyConfigJSON([]byte(`{"interfaces":{"wan":{"ifname":"lo","master":true}}}`)); err != nil {
		t.Fatal(err)
	}
	iface := interfaces["wan"]
	if !iface.Master {
		t.Fatal("configured master was ignored")
	}
	if err := applyConfigJSON([]byte(`{"interfaces":{"wan":{"ifname":"lo"}}}`)); err != nil {
		t.Fatal(err)
	}
	if interfaces["wan"] != iface || iface.Master {
		t.Fatal("omitting master must restore false on the existing interface")
	}
}

func TestSweepTimerAndConfigReloadUseEngineState(t *testing.T) {
	oldEngine, oldInterval, oldInterfaces := Eng, staleClientSweepInterval, interfaces
	Eng, staleClientSweepInterval, interfaces = NewEngine(), time.Millisecond, nil
	t.Cleanup(func() {
		Eng, staleClientSweepInterval, interfaces = oldEngine, oldInterval, oldInterfaces
	})
	done := make(chan struct{})
	defer close(done)
	startMirrorSweep(done)
	var sweep func()
	select {
	case sweep = <-Eng.events:
	case <-time.After(5 * time.Second):
		t.Fatal("sweep was not posted")
	}
	if err := applyConfigJSON([]byte(`{"global":{"stale_client_sweep_interval_seconds":1}}`)); err != nil {
		t.Fatal(err)
	}
	sweep()
	select {
	case <-Eng.events:
	case <-time.After(5 * time.Second):
		t.Fatal("sweep did not rearm")
	}
}
