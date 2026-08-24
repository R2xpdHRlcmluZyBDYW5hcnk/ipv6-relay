// Command ipv6-relay is a lightweight IPv6 DHCPv6/RA/NDP relay daemon.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"os/user"
	"syscall"

	"golang.org/x/sys/unix"

	"gitee.com/Y2FuYXJ5/ipv6-relay/internal/relay"
)

func ipv6Enabled() bool {
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, 0)
	if err != nil {
		return false
	}
	unix.Close(fd)
	return true
}

func printUsage(app string, exitCode int) {
	fmt.Fprintf(os.Stderr, "== %s Usage ==\n"+
		"Lightweight IPv6 Relay Daemon (DHCPv6/RA/ND relay)\n\n"+
		"	-c <file>	Read JSON configuration from <file>\n"+
		"	-l <int>	Specify log level 0..7 (default %d)\n"+
		"	-f		Log to stderr instead of syslog\n"+
		"	-h		Print this help text and exit\n",
		app, relay.LogWarning)
	os.Exit(exitCode)
}

func main() {
	// Running with no arguments at all is almost always a mistake (the
	// user just double-checking how to invoke it), not an attempt to run
	// with implicit defaults - show the usage text instead of a bare
	// "no config file" error.
	if len(os.Args) == 1 {
		printUsage(os.Args[0], 1)
	}

	configFile := flag.String("c", "", "JSON configuration file")
	logLevel := flag.Int("l", relay.LogWarning, "log level 0..7")
	foreground := flag.Bool("f", false, "log to stderr instead of syslog")
	help := flag.Bool("h", false, "print usage")

	flag.Usage = func() { printUsage(os.Args[0], 0) }
	flag.Parse()

	if *help {
		printUsage(os.Args[0], 0)
	}

	logLevelSet := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "l" {
			logLevelSet = true
		}
	})

	if logLevelSet {
		relay.SetLogLevel(*logLevel)
		relay.Cfg.LogLevelCmdline = true
		fmt.Fprintf(os.Stderr, "Log level set to %d\n", relay.LogLevel())
	}

	toSyslog := !*foreground
	if !toSyslog {
		fmt.Fprintln(os.Stderr, "Logging to stderr")
	}
	if err := relay.SetLogSyslog(toSyslog, "ipv6-relay"); err != nil {
		fmt.Fprintf(os.Stderr, "openlog: %v\n", err)
	}

	// Raw sockets, netlink route operations and privileged UDP ports
	// (DHCPv6 547) are required. Running as root is the simplest way to
	// get them, but an unprivileged user also works as long as it has
	// been granted CAP_NET_RAW, CAP_NET_ADMIN and CAP_NET_BIND_SERVICE
	// (e.g. via systemd AmbientCapabilities=). Individual socket/bind/
	// setsockopt failures are already reported by their call sites, so we
	// only warn here instead of hard-failing on non-root uid.
	if u, err := user.Current(); err != nil || u.Uid != "0" {
		relay.Errorf("Not running as root - relying on CAP_NET_RAW/CAP_NET_ADMIN/CAP_NET_BIND_SERVICE")
	}

	if *configFile == "" {
		relay.Errorf("No configuration file specified. Use -c <file>")
		os.Exit(2)
	}
	relay.Cfg.ConfigFile = *configFile

	if !ipv6Enabled() {
		relay.Errorf("IPv6 is not enabled on this system")
		os.Exit(4)
	}

	done := make(chan struct{})
	if err := relay.StartNetlinkMonitor(done); err != nil {
		relay.Errorf("Unable to start netlink monitor: %v", err)
		os.Exit(4)
	}

	sigCh := make(chan os.Signal, 4)
	signal.Notify(sigCh, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for sig := range sigCh {
			switch sig {
			case syscall.SIGHUP:
				relay.Eng.Post(relay.Reload)
			case syscall.SIGINT, syscall.SIGTERM:
				close(done)
				os.Exit(0)
			}
		}
	}()

	relay.Eng.Post(relay.Reload)
	relay.Eng.Run()
}
