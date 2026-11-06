# ipv6-relay

Linux IPv6 中继守护进程，支持 DHCPv6、路由通告（RA）和邻居发现（NDP）。项目使用 Go，提供 JSON 配置示例和 systemd 服务。

## 编译

项目和发布流程使用 Go 1.27.3，模块最低要求 Go 1.25.0。

```bash
git clone https://gitee.com/Y2FuYXJ5/ipv6-relay.git
cd ipv6-relay
go build -o ipv6-relay ./cmd/ipv6-relay
sudo install -m 755 ipv6-relay /usr/sbin/ipv6-relay
```

## 交叉编译

为 ARM64 Linux 路由器构建静态二进制文件。

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o ipv6-relay-arm64 ./cmd/ipv6-relay
```

复制到目标路由器。将 `router.example` 替换为路由器的主机名或 IP 地址。

```bash
scp ipv6-relay-arm64 root@router.example:/usr/sbin/ipv6-relay
```

## 使用

### 1. 准备配置文件

```bash
sudo mkdir -p /etc/ipv6-relay
sudo cp config.json.example /etc/ipv6-relay/config.json
sudo editor /etc/ipv6-relay/config.json
```

systemd 服务以临时用户运行，该用户需要能读取配置文件。

```bash
sudo chmod 755 /etc/ipv6-relay
sudo chmod 644 /etc/ipv6-relay/config.json
```

[`config.json.example`](config.json.example) 包含所有配置字段。`interfaces` 下的键是接口标识，实际网卡名由 `ifname` 指定。配置至少一个 `"master": true` 的上游接口和一个下游接口。每个已配置的接口同时中继 DHCPv6、RA 和 NDP。

| 字段 | 是否必选 | 说明 |
|------|----------|------|
| `ifname` | 必选 | 系统上真实的网卡名（如 `eth0`） |
| `master` | 可选，默认 `false` | 标记这是上游（WAN）接口 |
| `ndproxy_routing` | 可选，默认 `true` | 为此接口的镜像邻居安装 `/128` 主机路由。设为 `false` 时仅安装代理邻居条目 |
| `ndp_from_link_local` | 可选，默认 `true` | 发送 NDP 主动探测报文时优先使用本接口的链路本地地址 |

全局配置（`global`）

| 字段 | 是否必选 | 说明 |
|------|----------|------|
| `log_level` | 可选，默认 4 | 日志级别 0-7（同 `-l` 命令行参数，配置文件优先级低于显式传入的 `-l`） |
| `send_prefix_deprecation` | 可选，默认 `true` | 确认前缀失效后，向仍有该前缀邻居的下游接口发送合成撤销通告 |
| `prefix_mismatch_packet_threshold` | 可选，默认 3 | 已过有效期的前缀还需满足的连续缺席次数 |
| `send_prefix_deprecation_interval_seconds` | 可选，默认 300 | 合成前缀撤销通告的重发间隔，单位为秒 |
| `stale_client_sweep_interval_seconds` | 可选，默认 300 | 邻居扫描间隔，单位为秒。清理已消失或处于 `NUD_FAILED` 的邻居镜像，探测处于 `NUD_STALE` 的邻居 |

每个 `master` 接口会从上游 RA 的 PIO（Prefix Information Option）记录公网 IPv6 前缀及其有效期。
同一份 RA 可以携带多个 PIO，也可以省略仍有效的 PIO。程序仅在前缀有效期届满、且连续缺席达到
`prefix_mismatch_packet_threshold` 时判定前缀失效。上游明确通告零有效期时立即记录撤销。
合成撤销通告前，程序会检查其他上游对该前缀的有效期。

确认失效后，程序会向仍有该前缀邻居的 LAN 接口发送 Valid Lifetime 和 Preferred Lifetime
均为零的 PIO，并按 `send_prefix_deprecation_interval_seconds` 重发，直到邻居消失或前缀重新有效。
该记录保存在内存中。重启后，程序从新的上游 RA 建立记录，缺少历史记录的前缀继续由客户端按原通告的有效期管理。

### 2. 运行

```bash
# 将调试日志输出到标准错误
sudo ipv6-relay -c /etc/ipv6-relay/config.json -f -l 7

# 使用配置文件运行
sudo ipv6-relay -c /etc/ipv6-relay/config.json
```

命令行选项

| 选项 | 说明 |
|------|------|
| `-c <file>` | 必选，JSON 配置文件路径 |
| `-l <level>` | 日志级别 0-7，默认 4 |
| `-f` | 将日志输出到标准错误 |
| `-v` | 显示版本 |
| `-h` | 显示帮助 |

发送 `SIGHUP` 可以在不重启进程的情况下重新加载配置文件（`systemctl reload ipv6-relay`）。JSON 无法解析、网卡名无效或同一网卡重复配置时，服务会保留当前配置并在日志中记录错误。

### 3. 用 systemd 管理（推荐）

```bash
sudo cp ipv6-relay.service /usr/lib/systemd/system/ipv6-relay.service
sudo systemctl daemon-reload
sudo systemctl enable --now ipv6-relay.service
sudo systemctl status ipv6-relay.service
sudo journalctl -u ipv6-relay -f
```

### 注意事项

- 启用内核 IPv6 转发（`net.ipv6.conf.all.forwarding=1`），并在防火墙放行 ICMPv6 和 DHCPv6。程序启动时会检查 IPv6 转发设置。
- 中继保留 RA 的 on-link（L）标志。下游主机发送邻居请求时，中继会为已知位于其他接口的目标安装代理条目，由内核应答后续请求。DAD 探测不会触发代理条目安装。
- 中继创建的 IPv6 主机路由标记为协议号 196。周期清理仅删除带此标记的中继路由。升级前已有的 `proto static` 路由会保留。下游中继接口上的 proxy-NDP 表由中继管理。
- 服务退出时保留已安装的代理邻居条目、主机路由和 `proxy_ndp` 设置，以便重启期间继续转发。重新启动后，服务会同步中继状态。停用服务时，按需清理这些内核状态。
- systemd 通过 `DynamicUser=yes` 为服务分配临时 UID/GID，并授予 `CAP_NET_RAW`、`CAP_NET_ADMIN` 和 `CAP_NET_BIND_SERVICE`，用于原始套接字、网络配置和 DHCPv6 端口 547。手动运行时，以 root 执行或使用 `setcap` 授予相同权限。

## 回归测试

在允许创建用户和网络命名空间的 Linux 环境中运行。测试会在隔离网络里创建临时接口、路由和代理邻居。

```bash
unshare -Urn env IPV6_RELAY_NETNS_TEST=1 go test -race ./...
go vet ./...
```

## 项目结构

```
├── cmd/ipv6-relay/      # 主程序入口 (main.go, CLI 参数解析)
├── internal/relay/      # 核心实现：config/engine/log + router(RA)/dhcpv6/ndp 三个中继子系统
├── config.json.example  # 配置示例
├── ipv6-relay.service   # systemd 服务文件
├── go.mod / go.sum
└── LICENSE
```

## 许可证

[MIT](LICENSE)
