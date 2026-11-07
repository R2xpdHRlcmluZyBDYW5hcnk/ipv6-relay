# ipv6-relay

A Linux IPv6 relay daemon supporting DHCPv6, Router Advertisements (RA), and Neighbor Discovery (NDP). Written in Go, it includes a sample JSON configuration and a systemd service unit.

## Build

The project and release workflow use Go 1.27.3. The module requires Go 1.25.0 or later.

```bash
git clone https://gitee.com/Y2FuYXJ5/ipv6-relay.git
cd ipv6-relay
go build -o ipv6-relay ./cmd/ipv6-relay
sudo install -m 755 ipv6-relay /usr/sbin/ipv6-relay
```

## Cross-compilation

Build a static binary for an ARM64 Linux router:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o ipv6-relay-arm64 ./cmd/ipv6-relay
```

Copy it to the target router. Replace `router.example` with the router's hostname or IP address.

```bash
scp ipv6-relay-arm64 root@router.example:/usr/sbin/ipv6-relay
```

## Usage

### 1. Prepare the configuration file

```bash
sudo mkdir -p /etc/ipv6-relay
sudo cp config.json.example /etc/ipv6-relay/config.json
sudo editor /etc/ipv6-relay/config.json
```

The systemd service runs as a temporary user that needs read access to the configuration file.

```bash
sudo chmod 755 /etc/ipv6-relay
sudo chmod 644 /etc/ipv6-relay/config.json
```

[`config.json.example`](config.json.example) includes all configuration fields. Keys under `interfaces` are interface identifiers; `ifname` specifies the actual network interface name. Configure at least one upstream interface with `"master": true` and one downstream interface. Each configured interface relays DHCPv6, RA, and NDP.

| Field | Required / default | Description |
|------|----------|------|
| `ifname` | Required | Actual network interface name on the system, such as `eth0` |
| `master` | Optional; default: `false` | Marks the interface as upstream (WAN) |
| `ndproxy_routing` | Optional; default: `true` | Installs `/128` host routes for neighbors mirrored on this interface. When `false`, only proxy neighbor entries are installed |
| `ndp_from_link_local` | Optional; default: `true` | Prefers this interface's link-local address when sending active NDP probes |

Global configuration (`global`):

| Field | Required / default | Description |
|------|----------|------|
| `log_level` | Optional; default: 4 | Log level from 0 to 7, as with the `-l` command-line option. An explicitly supplied `-l` takes precedence over the configuration file |
| `send_prefix_deprecation` | Optional; default: `true` | Sends synthetic withdrawal advertisements to downstream interfaces that still have neighbors using a prefix once it is confirmed invalid |
| `prefix_mismatch_packet_threshold` | Optional; default: 3 | Number of consecutive absences required in addition to prefix lifetime expiry |
| `send_prefix_deprecation_interval_seconds` | Optional; default: 300 | Interval in seconds between repeated synthetic prefix withdrawal advertisements |
| `stale_client_sweep_interval_seconds` | Optional; default: 300 | Neighbor sweep interval in seconds. Removes mirrored entries for neighbors that have disappeared or entered `NUD_FAILED`, and probes neighbors in `NUD_STALE` |

Each `master` interface tracks public IPv6 prefixes and their valid lifetimes from PIOs (Prefix Information Options) in upstream RAs.
A single RA may contain multiple PIOs and may omit a PIO whose prefix is still valid. A prefix is considered invalid only after its valid lifetime expires and its consecutive absences reach
`prefix_mismatch_packet_threshold`. An explicit upstream advertisement with a zero valid lifetime records a withdrawal immediately.
Before generating a withdrawal advertisement, the daemon checks the prefix's valid lifetime on other upstream interfaces.

Once a prefix is confirmed invalid, the daemon sends PIOs with both Valid Lifetime and Preferred Lifetime
set to zero to LAN interfaces that still have neighbors using that prefix. It repeats these advertisements every `send_prefix_deprecation_interval_seconds` until the neighbors disappear or the prefix becomes valid again.
These records are kept in memory. After a restart, the daemon rebuilds them from new upstream RAs. Clients continue to manage prefixes without historical records according to the lifetimes originally advertised.

### 2. Run the daemon

```bash
# Write debug logs to standard error
sudo ipv6-relay -c /etc/ipv6-relay/config.json -f -l 7

# Run with the configuration file
sudo ipv6-relay -c /etc/ipv6-relay/config.json
```

Command-line options:

| Option | Description |
|------|------|
| `-c <file>` | Required; path to the JSON configuration file |
| `-l <level>` | Log level from 0 to 7; default: 4 |
| `-f` | Write logs to standard error |
| `-v` | Show the version |
| `-h` | Show help |

Send `SIGHUP` to reload the configuration without restarting the process (`systemctl reload ipv6-relay`). If the JSON cannot be parsed, an interface name is invalid, or the same interface is configured more than once, the service keeps its current configuration and logs an error.

### 3. Manage with systemd (recommended)

```bash
sudo cp ipv6-relay.service /usr/lib/systemd/system/ipv6-relay.service
sudo systemctl daemon-reload
sudo systemctl enable --now ipv6-relay.service
sudo systemctl status ipv6-relay.service
sudo journalctl -u ipv6-relay -f
```

### Notes

- Enable kernel IPv6 forwarding (`net.ipv6.conf.all.forwarding=1`) and allow ICMPv6 and DHCPv6 through the firewall. The daemon checks the IPv6 forwarding setting at startup.
- The relay preserves the RA on-link (L) flag. When a downstream host sends a Neighbor Solicitation for a target known to be on another interface, the relay installs a proxy entry so the kernel can answer subsequent solicitations. DAD probes do not trigger proxy entry installation.
- IPv6 host routes created by the relay are tagged with protocol number 196. Periodic cleanup removes only relay routes with this tag. Existing `proto static` routes from before an upgrade are preserved. The relay manages the proxy-NDP table on downstream relay interfaces.
- On exit, the service preserves installed proxy neighbor entries, host routes, and `proxy_ndp` settings so forwarding can continue during a restart. The service synchronizes relay state when it starts again. When decommissioning the service, clean up these kernel settings and entries as needed.
- With `DynamicUser=yes`, systemd assigns the service a temporary UID/GID and grants `CAP_NET_RAW`, `CAP_NET_ADMIN`, and `CAP_NET_BIND_SERVICE` for raw sockets, network configuration, and DHCPv6 port 547. When running manually, use root or grant the same capabilities with `setcap`.

## Regression tests

Run in a Linux environment that allows user and network namespaces. The tests create temporary interfaces, routes, and proxy neighbors in an isolated network.

```bash
unshare -Urn env IPV6_RELAY_NETNS_TEST=1 go test -race ./...
go vet ./...
```

## Project structure

```
├── cmd/ipv6-relay/     # Main entry point (main.go, CLI argument parsing)
├── internal/relay/     # Core: config/engine/log and router (RA)/dhcpv6/ndp relay subsystems
├── config.json.example # Sample configuration
├── ipv6-relay.service  # systemd service unit
├── go.mod / go.sum
└── LICENSE
```

## License

[MIT](LICENSE)
