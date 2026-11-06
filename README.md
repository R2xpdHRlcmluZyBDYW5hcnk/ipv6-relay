# ipv6-relay

轻量级 IPv6 中继守护进程，支持 DHCPv6 / RA / NDP 中继。

基于 Go 实现，采用单文件静态链接编译，跨平台交叉编译非常简单，不依赖任何外部 C 运行库。支持 JSON 配置与基于 Linux capabilities（`AmbientCapabilities`）的非 root 部署模型。

## 功能

- DHCPv6 中继
- 路由通告中继（RA Relay）
- 邻居发现中继（NDP Relay）
- JSON 配置文件
- 自带 systemd 服务文件

## 编译

构建只需要 Go 工具链。项目和发布流程使用 Go 1.27.3，模块最低要求 Go 1.25.0：

```bash
git clone https://gitee.com/Y2FuYXJ5/ipv6-relay.git
cd ipv6-relay
go build -o ipv6-relay ./cmd/ipv6-relay
sudo install -m 755 ipv6-relay /usr/sbin/ipv6-relay
```

## 交叉编译

Go 自带交叉编译支持，例如给 arm64 路由器编译：

```bash
GOOS=linux GOARCH=arm64 go build -o ipv6-relay-arm64 ./cmd/ipv6-relay
```

产物是静态链接的二进制（`CGO_ENABLED=0` 是 Go 交叉编译时的默认值），可以直接拷贝到目标机
运行，不需要在目标机上安装任何运行库：

```bash
scp ipv6-relay-arm64 root@<router>:/usr/sbin/ipv6-relay
```

## 使用

### 1. 准备配置文件

```bash
sudo mkdir -p /etc/ipv6-relay
sudo cp config.json.example /etc/ipv6-relay/config.json
sudo editor /etc/ipv6-relay/config.json
```

配置文件本身不包含任何密钥/凭据，只有接口名和开关，所以给普通用户读权限没有安全风险：

```bash
sudo chmod 755 /etc/ipv6-relay
sudo chmod 644 /etc/ipv6-relay/config.json
```

配置文件示例：见 [`config.json.example`](config.json.example)（里面列出了每个可配置字段，没有隐藏参数）。

`interfaces` 下每个条目的键名（示例里的 `wan`/`lan`）只是自己起的标识名，随便叫什么都行，程序只认里面的字段：

| 字段 | 是否必选 | 说明 |
|------|----------|------|
| `ifname` | 必选 | 系统上真实的网卡名（如 `eth0`） |
| `master` | 可选，默认 `false` | 标记这是上游（WAN）接口 |
| `ndproxy_routing` | 可选，默认 `true` | 是否为这个接口上镜像的邻居地址安装 `/128` 主机路由（配合 proxy-NDP 一起生效，关掉后只装 proxy-NDP 代理表项、不装路由） |
| `ndp_from_link_local` | 可选，默认 `true` | 主动探测/中继报文（如邻居探测、路由器请求）发送时是否优先使用本接口的 link-local 地址作为源地址，而不是回退到默认的发送方式 |

`global` 下目前有以下字段：

| 字段 | 是否必选 | 说明 |
|------|----------|------|
| `log_level` | 可选，默认 4 | 日志级别 0-7（同 `-l` 命令行参数，配置文件优先级低于显式传入的 `-l`） |
| `send_prefix_deprecation` | 可选，默认 `true` | 是否在检测到 WAN 口某个前缀确实已经消失时，向 LAN 侧仍在使用该前缀地址的邻居发送 lifetime=0 的终结通告（见下方说明）——如果不想要这个自动发送终结通告的行为，直接关掉这个开关即可 |
| `prefix_mismatch_packet_threshold` | 可选，默认 3 | 已过有效期的前缀还需满足的连续缺席次数 |
| `send_prefix_deprecation_interval_seconds` | 可选，默认 300 | 确认前缀消失后，终结通告的重发间隔（秒），直到 LAN 侧不再有使用该前缀地址的邻居或前缀恢复有效 |
| `stale_client_sweep_interval_seconds` | 可选，默认 300 | 周期性兜底扫描的间隔（秒）：清理已经 `NUD_FAILED` 或邻居表项已消失的镜像（proxy-NDP + `/128` 主机路由），并主动探测处于 `NUD_STALE` 的邻居 |

每个 `master` 接口会从上游 RA 的 PIO（Prefix Information Option）记录公网 IPv6 前缀及其有效期。
同一份 RA 可以携带多个 PIO，也可以省略仍有效的 PIO。程序仅在前缀有效期届满、且连续缺席达到
`prefix_mismatch_packet_threshold` 时判定前缀失效。上游明确通告零有效期时立即记录撤销。
若其他上游仍通告该前缀有效，程序会保留其有效状态。

确认失效后，程序会向仍有该前缀邻居的 LAN 接口发送 Valid Lifetime 和 Preferred Lifetime
均为零的 PIO，并按 `send_prefix_deprecation_interval_seconds` 重发，直到邻居消失或前缀重新有效。
该记录保存在内存中。重启后，程序从新的上游 RA 建立记录，缺少历史记录的前缀继续由客户端按原通告的有效期管理。

本项目只做 relay，不支持其他模式，所以**只要接口出现在配置里，就会同时中继 DHCPv6 / RA / NDP 三种服务**，不需要（也无法）单独开关；不想中继某个接口，直接把它从配置里删掉即可。`master` 用来标记哪一侧是上游：至少要有一个接口设为 `"master": true`，其余不带 `master` 的接口视为下游（LAN 侧）。

### 2. 运行

```bash
# 前台运行，方便调试
sudo ipv6-relay -c /etc/ipv6-relay/config.json -f -l 7

# 直接运行（生产环境推荐用 systemd，见下）
sudo ipv6-relay -c /etc/ipv6-relay/config.json
```

命令行选项：

| 选项 | 说明 |
|------|------|
| `-c <file>` | 必选，JSON 配置文件路径 |
| `-l <level>` | 日志级别 0-7，默认 4 |
| `-f` | 日志输出到 stderr，而不是 syslog |
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

- **必须启用内核 IPv6 转发**（`net.ipv6.ip_forward=1` / `net.ipv6.conf.all.forwarding=1`）。中继的数据面就是内核自己的转发：NDP/RA/DHCPv6 中继在没有 forwarding 时看起来一切正常，但实际流量会被丢弃，看起来像中继的 bug。程序启动时会检测该开关并告警。
- 转发的 RA 原样保留上游的 on-link（L）标志，下游主机会认为整个前缀在链路上、直接对 WAN 侧目标发 Neighbor Solicitation。本程序会在下游接口上为已知位于其他中继接口背后的目标安装 proxy-NDP 表项，让内核代答这些 NS（DAD 探测除外，避免干扰地址配置）；目标首次被解析期间的重传可能需要 1–2 秒才得到应答。
- 中继创建的 IPv6 主机路由标记为协议号 196。周期清理仅删除带此标记的中继路由。升级前已有的 `proto static` 路由会保留。下游中继接口上的 proxy-NDP 表由中继管理。
- 进程退出（SIGTERM/SIGINT）时**有意不清除**已安装的 proxy-NDP 表项、/128 主机路由和 `proxy_ndp` sysctl：这样 daemon 重启/升级的窗口期内下游连通性不受影响，再次启动时会自动重建并回收这些状态。如需彻底清理，重新开关接口或重启网络即可。
- 进程本身不再强制要求以 UID 0 运行；`systemd` 单元通过 `DynamicUser=yes` 在启动时为它分配一个专属的临时系统 UID/GID（服务停止后回收），再通过 `AmbientCapabilities`（`CAP_NET_RAW` + `CAP_NET_ADMIN` + `CAP_NET_BIND_SERVICE`）获得操作原始套接字、netlink 路由表和绑定 DHCPv6 547 端口所需的权限，不需要完整 root。
- 如果不通过 systemd、而是手动在命令行执行 `ipv6-relay`，仍然需要 root（或者自行用 `setcap` 给二进制加上同样三个 capability 后再以非 root 用户运行）。
- 已在测试路由器上验证：`DynamicUser` 分配的临时用户 + 上述三个 capability 可以正常完成 DHCPv6 中继（绑定 547 端口）、RA 中继（原始套接字）、NDP 中继（写 `/proc/sys/net/ipv6/conf/<if>/proxy_ndp` 需要 `CAP_NET_ADMIN`）。
- 相比让服务以 `nobody` 这种所有服务共用的账户运行（systemd 会警告 `Special user nobody configured, this is not safe!`，因为多个服务共用同一 UID 存在互相干扰的风险），`DynamicUser` 为每个服务分配独占的临时 UID，隔离性更好，也不需要像 `useradd -r -s /sbin/nologin ipv6-relay` 那样手动创建专用系统账户。
- 确保内核已启用 IPv6。
- 检查防火墙是否放行 ICMPv6 / DHCPv6 流量。

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
