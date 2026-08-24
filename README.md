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

只需要 Go 工具链（1.22+），没有其他系统依赖：

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
| `prefix_mismatch_packet_threshold` | 可选，默认 3 | 实时 snoop WAN 口收到的真实 RA 报文时，一个已记录的前缀连续多少次没有出现在 RA 里，才判定它确实消失（防止上游把多个仍然有效的前缀分散在不同 RA 里发送时被误判） |
| `send_prefix_deprecation_interval_seconds` | 可选，默认 300 | 确认前缀消失后，终结通告的重发间隔（秒），直到 LAN 侧不再有使用该前缀地址的邻居为止才停止 |
| `stale_client_sweep_interval_seconds` | 可选，默认 300 | 周期性兜底扫描的间隔（秒）：清理已经 `NUD_FAILED` 或邻居表项已消失的镜像（proxy-NDP + `/128` 主机路由），并主动探测处于 `NUD_STALE` 的邻居 |

本项目会对每个 `master` 接口实时 snoop 收到的真实 RA 报文，解析其中的 PIO（Prefix Information
Option），只关心 ULA（`fc00::/7`）或公网可路由的前缀（不含 link-local、组播），并且是**一个集合**
而不是单一前缀——RA 本来就可以同时携带多个前缀，只要某个前缀出现在这次收到的 RA 里，就算它仍然
有效，不会当成过时。判断前缀是否消失**只看实时收到的 RA 报文本身**，故意不去看 WAN 口内核当前的
地址列表——这个功能本来就是为了应对上游路由器前缀过期后不发送正确的 `valid_lft=0`/
`preferred_lft=0` 撤回通告的情况，这种情况下 WAN 口自己的内核地址本来就会因为拿着旧的
`valid_lft` 继续倒计时、迟迟不消失，如果拿它来做保护，等于直接把这个功能废掉了。只有一个已记录
的前缀连续 `prefix_mismatch_packet_threshold` 次都没有出现在收到的 RA 里，才判定它确实消失了
（例如上游重新编号/更换了前缀）——这样即使上游把多个仍然有效的前缀分散在不同 RA 里发送，也不会
被误判成前缀消失。接口刚启动收到的第一个真实 RA 只会静默记录当前的前缀集合，不会触发通告，避免
把重启前就已存在的合法前缀误判为"过时"。一旦确认某个前缀消失了，就会向所有下游
（非 `master`）接口里仍有该前缀下地址的邻居，发送一份只带有该前缀 PIO（Valid/Preferred
Lifetime 均为 0）的合成 RA，之后每隔 `send_prefix_deprecation_interval_seconds` 重发一次，直到 LAN
侧的邻居表里再也找不到该前缀下的地址为止。

这套前缀集合本身只在内存里，进程重启后会清空重新静默记录，所以还有一种情况需要额外处理：如果
WAN 口在重启前就已经悄悄换了前缀，重启后进程只会记住新前缀，永远不会"亲眼"观察到旧前缀消失的
过程——这时如果 LAN 侧某台设备还没放弃使用旧前缀的地址，就会一直用坏地址尝试连接，没人再通知它。
所以每处理完一个真实 RA，除了比对 WAN 口自己的前缀集合，也会顺便枚举一遍所有下游接口邻居表里的
ULA/公网地址，跟同一份前缀集合做比对——只要某个邻居地址不属于集合里任何一个前缀，就立刻（不需要
再等待 `prefix_mismatch_packet_threshold` 次确认，因为这份集合本身已经是确认过的）向它发送终结
通告并按同样的重发/停止规则处理。

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

发送 `SIGHUP` 可以在不重启进程的情况下重新加载配置文件（`systemctl reload ipv6-relay`）。

### 3. 用 systemd 管理（推荐）

```bash
sudo cp ipv6-relay.service /usr/lib/systemd/system/ipv6-relay.service
sudo systemctl daemon-reload
sudo systemctl enable --now ipv6-relay.service
sudo systemctl status ipv6-relay.service
sudo journalctl -u ipv6-relay -f
```

### 注意事项

- 进程本身不再强制要求以 UID 0 运行；`systemd` 单元通过 `DynamicUser=yes` 在启动时为它分配一个专属的临时系统 UID/GID（服务停止后回收），再通过 `AmbientCapabilities`（`CAP_NET_RAW` + `CAP_NET_ADMIN` + `CAP_NET_BIND_SERVICE`）获得操作原始套接字、netlink 路由表和绑定 DHCPv6 547 端口所需的权限，不需要完整 root。
- 如果不通过 systemd、而是手动在命令行执行 `ipv6-relay`，仍然需要 root（或者自行用 `setcap` 给二进制加上同样三个 capability 后再以非 root 用户运行）。
- 已在测试路由器上验证：`DynamicUser` 分配的临时用户 + 上述三个 capability 可以正常完成 DHCPv6 中继（绑定 547 端口）、RA 中继（原始套接字）、NDP 中继（写 `/proc/sys/net/ipv6/conf/<if>/proxy_ndp` 需要 `CAP_NET_ADMIN`）。
- 相比让服务以 `nobody` 这种所有服务共用的账户运行（systemd 会警告 `Special user nobody configured, this is not safe!`，因为多个服务共用同一 UID 存在互相干扰的风险），`DynamicUser` 为每个服务分配独占的临时 UID，隔离性更好，也不需要像 `useradd -r -s /sbin/nologin ipv6-relay` 那样手动创建专用系统账户。
- 确保内核已启用 IPv6。
- 检查防火墙是否放行 ICMPv6 / DHCPv6 流量。

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
