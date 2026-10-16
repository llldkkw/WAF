# WAF Gateway · 自托管 Web 应用防火墙

部署在自己的跳板机/网关上，作为所有服务器的统一入口：网站流量经 WAF 检查后转发到内网后端，运维流量（SSH、管理面板）只能通过 WireGuard VPN 进入。

```
                    公网
                     │
       ┌─────────────▼──────────────┐  网关 / 跳板机
       │ nftables   只开放 80/443/51820│
       │ WAF 数据面  反向代理 + CRS 规则 │ ← 单个 Go 二进制
       │ 管理面板    仅 WireGuard 内网   │
       │ WireGuard  运维通道            │
       └──────┬──────────┬──────────┬──┘
              │ 内网     │          │
          服务器 A    服务器 B    服务器 C   ← 只接受网关 IP 的连接
```

## 功能

**防护**
- OWASP Core Rule Set（Coraza 引擎）：SQL 注入、XSS、命令执行、文件包含、Log4Shell、扫描器识别等
- 每个站点独立策略：拦截 / 观察（只记录）/ 关闭，防护等级 PL1–PL4，异常分数阈值
- 误报处理：在日志里点「这是误报」，按规则 + 路径前缀排除，2 秒内热加载
- CC 防护：单 IP 限流，超限自动封禁
- 攻击者自动封禁：5 分钟内被拦截 N 次的 IP 自动拉黑（专治扫描器）
- IP 黑白名单（支持网段、有效期、全局或单站点），白名单优先级最高
- 地区封禁（GeoIP）、路径访问控制（如 `/admin` 只允许 VPN 网段）
- 自动 HTTPS（Let's Encrypt），强制跳转
- 多后端轮询负载均衡 + 健康检查，自动摘除故障节点

**可视化控制台**
- 总览大屏：请求/拦截趋势、实时 QPS、攻击来源世界地图、攻击类型分布、Top IP / 路径 / 规则、实时事件流、后端健康
- 攻击日志：多条件检索，完整的命中规则详情，一键封禁 / 加白
- 深色 / 浅色主题，手机可用

**推送通知**（Telegram、企业微信、钉钉、飞书、Bark、邮件、Webhook）

| 等级 | 事件 |
|---|---|
| 🔴 严重 | 后端宕机、管理后台新 IP 登录、高危攻击（命令执行 / Java / PHP / RFI）、配置加载失败 |
| 🟠 警告 | 攻击量突增、IP 被自动封禁、高危等级攻击、后台登录多次失败 |
| 🔵 通知 | 配置变更、后端恢复、网关启动 |

同类事件 5 分钟内只推一次，之后汇总；每个渠道可设推送级别和免打扰时段（严重告警不受免打扰影响）。

**平台自身安全**
- 管理面板只监听 VPN 内网地址，并有来源网段白名单双重限制
- 强制两步验证（TOTP），验证码防重放；登录失败 5 次锁定 15 分钟
- 密码 bcrypt；会话令牌只存哈希；HttpOnly + Secure + SameSite=Strict Cookie；空闲 30 分钟自动登出
- CSRF 防护、严格 CSP、安全响应头
- 通知密钥、TOTP 种子用 AES-256-GCM 加密存储
- 管理员 / 只读两种角色；所有登录和配置变更写入审计日志
- systemd 沙箱运行：非 root，只保留绑定 80/443 的能力，文件系统只读
- 配置错误不会生效（旧配置继续运行）；命令行应急加白，防止把自己锁在外面

## 部署

以下以一台 Debian/Ubuntu 网关为例：公网网卡 `eth0`，内网网卡 `eth1`（`10.0.0.0/24`），VPN 网段 `10.8.0.0/24`。

### 1. 构建

在任意有 Go 1.26+ 和 Node 22+ 的机器上：

```bash
git clone https://github.com/llldkkw/WAF.git && cd WAF
make release          # 生成 dist/waf-linux-amd64 和 dist/waf-linux-arm64
```

把整个目录（或 `dist/`、`deploy/`、`waf.example.yaml`）上传到网关。

### 2. WireGuard（运维通道）

```bash
apt install wireguard
cd /etc/wireguard && umask 077
wg genkey | tee server.key | wg pubkey > server.pub
cat > wg0.conf <<EOF
[Interface]
Address = 10.8.0.1/24
ListenPort = 51820
PrivateKey = $(cat server.key)

# 你的电脑/手机，每个设备一段
[Peer]
PublicKey = <客户端公钥>
AllowedIPs = 10.8.0.2/32
EOF
echo net.ipv4.ip_forward=1 > /etc/sysctl.d/99-forward.conf && sysctl --system
systemctl enable --now wg-quick@wg0
```

客户端配置：

```ini
[Interface]
PrivateKey = <客户端私钥>
Address = 10.8.0.2/32

[Peer]
PublicKey = <server.pub 内容>
Endpoint = <网关公网IP>:51820
AllowedIPs = 10.8.0.0/24, 10.0.0.0/24   # VPN + 内网服务器
PersistentKeepalive = 25
```

**先确认 VPN 能连通、能通过 `ssh root@10.8.0.1` 登录，再进行下一步。**

### 3. 防火墙

```bash
apt install nftables
cp deploy/nftables.conf /etc/nftables.conf
vi /etc/nftables.conf             # 修改网卡名和网段
nft -c -f /etc/nftables.conf      # 先检查语法
nft -f /etc/nftables.conf && systemctl enable nftables
```

应用后公网 SSH 会被关闭，只能通过 VPN 登录。建议操作时保持一个已登录的 SSH 会话，确认无误后再断开。

SSH 加固（`/etc/ssh/sshd_config`）：`PasswordAuthentication no`、`PermitRootLogin prohibit-password`。

### 4. 安装 WAF

```bash
sudo sh deploy/install.sh dist/waf-linux-amd64
vi /etc/waf/waf.yaml                       # admin.listen 填 10.8.0.1:9443；需要 HTTPS 就打开 acme
sudo -u waf WAF_CONFIG=/etc/waf/waf.yaml waf user add -name admin
systemctl enable --now waf
journalctl -u waf -f
```

`waf user add` 会在终端打印二维码，用手机验证器 App（Google Authenticator、Microsoft Authenticator、1Password 等）扫描。

连上 VPN 后打开 `https://10.8.0.1:9443`（自签名证书，浏览器提示时选择继续）。

### 5. 接入站点

1. 控制台 → 站点防护 → 新建站点：填域名和后端内网地址（如 `http://10.0.0.11:8080`）
2. 新站点建议先用 **观察模式** 跑几天，在攻击日志里确认没有误报，再切换到 **拦截模式**
3. 把域名 DNS 解析到网关公网 IP
4. 推送通知 → 添加渠道 → 点「测试」确认能收到

### 6. 锁定后端服务器

在每台后端服务器上运行，只允许网关访问，防止攻击者绕过 WAF 直连源站：

```bash
GATEWAY_IP=10.0.0.1 APP_PORTS="80,443,8080" sh deploy/backend-firewall.sh
```

如果后端在云上，同样要在云厂商安全组里只放行网关 IP。

## 日常运维

```bash
waf ip list                         # 查看 IP 规则
waf ip allow 1.2.3.4 -note 办公室    # 应急加白（被自己的规则挡住时），2 秒内生效
waf ip deny 5.6.7.0/24 -minutes 1440
waf ip del 1.2.3.4
waf user reset -name admin          # 忘记密码或手机丢失：重置密码和两步验证
```

在服务器上执行时加 `sudo -u waf WAF_CONFIG=/etc/waf/waf.yaml` 前缀，保证文件属主正确。

**备份**：`/var/lib/waf/` 整个目录，尤其是 `master.key`。丢失它，已保存的通知密钥和两步验证密钥将无法解密。

**地区识别**：从 MaxMind 免费下载 `GeoLite2-Country.mmdb`，放到 `/var/lib/waf/`，在配置里设置 `geoip_db` 后重启。之后攻击地图和地区封禁才会生效。

## 开发

```bash
# 后端（dev.yaml: admin.tls: "off", admin.listen: 127.0.0.1:9443, proxy.http_listen: 127.0.0.1:8080）
go run ./cmd/waf user add -c dev.yaml -name admin
go run ./cmd/waf serve -c dev.yaml

# 前端热更新（另开终端），/api 自动代理到 127.0.0.1:9443
cd web && npm install && npm run dev

make test
```

| 目录 | 内容 |
|---|---|
| `cmd/waf` | 命令行入口（serve / user / ip） |
| `internal/proxy` | 数据面：反向代理、IP 名单、限流、自动封禁、健康检查 |
| `internal/engine` | Coraza + OWASP CRS 规则生成与检测 |
| `internal/admin` | 管理 API、登录认证、WebSocket 实时推送 |
| `internal/notify` | 推送渠道、告警聚合与免打扰 |
| `internal/events` | 事件记录、流量统计、突增检测 |
| `internal/store` | SQLite 存储 |
| `web/` | React + TypeScript + Tailwind + ECharts 控制台 |
| `deploy/` | systemd、nftables、安装脚本、Docker Compose |

## 路线图

- [ ] 告警消息中的一键封禁 / 加白链接（签名的一次性链接）
- [ ] 每日 / 每周安全报告推送
- [ ] 手动上传 HTTPS 证书、泛域名证书（DNS-01）
- [ ] 人机验证（JS 挑战）
- [ ] 面板内管理 nftables L4 规则、WireGuard 客户端
- [ ] 日志接入 ClickHouse，多网关集群
- [ ] 接入 CrowdSec 社区 IP 信誉库
