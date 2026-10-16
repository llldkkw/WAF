# WAF Gateway · 自托管 Web 应用防火墙

[![License: CC BY-NC-SA 4.0](https://img.shields.io/badge/License-CC_BY--NC--SA_4.0-lightgrey.svg)](LICENSE)

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
- **地区策略**：封禁指定地区，或「仅允许」指定地区（国家白名单）；支持国家 `CN`、省份 `CN-GD`、城市 `CN/深圳`
- **人机验证**：内置 JS 工作量证明（访客无感知，通常 < 1 秒），或接入 **Cloudflare Turnstile**、**Google reCAPTCHA**（v2 / v3，默认经 recaptcha.net 加载，国内可用）；可对所有访问或仅对可疑访问开启，API 路径可免验证
- 路径访问控制（如 `/admin` 只允许 VPN 网段）
- **HTTPS 证书**：上传自己的证书（支持泛域名 `*.example.com`），未上传的域名用 Let's Encrypt 自动签发；到期前 14 天提醒
- 多后端轮询负载均衡 + 健康检查，自动摘除故障节点

**可视化控制台**
- 总览大屏：请求/拦截趋势、实时 QPS、攻击来源世界地图、攻击类型分布、Top IP / 路径 / 规则、实时事件流、后端健康
- 攻击日志：多条件检索，完整的命中规则详情，一键封禁 / 加白
- 深色 / 浅色主题，手机可用

**推送通知**（Telegram、Slack、Microsoft Teams、企业微信、钉钉、飞书、Bark、邮件、Webhook）

| 等级 | 事件 |
|---|---|
| 🔴 严重 | 后端宕机、管理后台新 IP 登录、高危攻击（命令执行 / Java / PHP / RFI）、配置加载失败 |
| 🟠 警告 | 攻击量突增、IP 被自动封禁、高危等级攻击、后台登录多次失败 |
| 🔵 通知 | 配置变更、后端恢复、网关启动 |

同类事件 5 分钟内只推一次，之后汇总；每个渠道可设推送级别和免打扰时段（严重告警不受免打扰影响）。

- **一键操作**：攻击和封禁告警附带「封禁 24 小时 / 永久封禁 / 解除封禁 / 加入白名单」按钮。链接经签名、只能用一次、7 天过期，点开后需登录并确认才执行。
- **安全报告**：每日 / 每周定时推送（请求量、拦截率、攻击类型、Top 攻击 IP / 地区 / 路径，并与上期对比），也可随时手动发送。

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

## 通知渠道配置

| 渠道 | 获取方式 |
|---|---|
| Slack | Slack App → Incoming Webhooks → Add New Webhook，复制 `https://hooks.slack.com/services/...` |
| Microsoft Teams | 频道 → 工作流 →「收到 Webhook 请求时发布到频道」，复制生成的 URL（旧版 Office 365 Connector 已被微软停用） |
| 邮件 | 任意 SMTP，见下方 Oracle Cloud 示例 |

**Oracle Cloud（OCI）Email Delivery 邮件**

1. OCI 控制台 → 开发者服务 → Email Delivery → **Approved Senders**，添加发件地址（如 `alerts@你的域名`），建议同时配置 SPF / DKIM。
2. 身份 → 用户 → 你的用户 → **SMTP 凭据** → 生成，记下用户名（`ocid1.user...` 开头的长字符串）和密码（只显示一次）。
3. 在 Email Delivery → Configuration 查看你所在区域的 SMTP 端点，例如 `smtp.email.ap-tokyo-1.oci.oraclecloud.com`。
4. 控制台 → 推送通知 → 添加渠道 → 邮件：主机填上面的端点，端口 `587`，加密方式 `STARTTLS`，用户名 / 密码填 SMTP 凭据，发件人填已批准的地址。保存后点「测试」。

## 地区策略

需要 GeoIP 数据库（见配置文件 `geoip_db`）。按省份或城市匹配需要 **GeoLite2-City**。

| 规则 | 含义 |
|---|---|
| `CN` | 中国（ISO 国家代码） |
| `CN-GD` | 广东省（ISO 3166-2 省级代码：BJ 北京、SH 上海、GD 广东、ZJ 浙江…） |
| `CN/深圳` 或 `CN/Shenzhen` | 深圳市 |
| `CN-GD/深圳` | 广东省深圳市 |

「仅允许」模式下，内网和 VPN 地址始终放行；数据库查不到位置的公网 IP 默认拒绝（可在站点设置中改为放行）。

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

**地区识别**：从 MaxMind 免费下载 `GeoLite2-City.mmdb`（只需国家级时可用 Country 版），放到 `/var/lib/waf/`，在配置里设置 `geoip_db` 后重启。之后攻击地图和地区策略才会生效。MaxMind 每周更新数据库，可用官方 `geoipupdate` 工具定期更新。

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

## 文档

| 文档 | 内容 |
|---|---|
| [架构说明](docs/architecture.md) | 模块划分、请求处理流程、热加载、**安全设计** |
| [配置参考](docs/configuration.md) | `waf.yaml` 全部配置项、站点设置、命令行 |
| [管理 API](docs/api.md) | REST 接口、WebSocket、Webhook 格式 |
| [常见问题](docs/faq.md) | 误报、被锁在外面、地区策略、邮件、证书等 |

## 参与贡献

欢迎提交 Issue 和 Pull Request，请先阅读 [贡献指南](CONTRIBUTING.md) 和 [行为准则](CODE_OF_CONDUCT.md)。

发现安全漏洞请**不要**公开提交，按 [安全策略](SECURITY.md) 私密报告。

## 路线图

- [x] 告警消息中的一键封禁 / 加白链接
- [x] 每日 / 每周安全报告推送
- [x] 手动上传 HTTPS 证书（含泛域名）
- [x] 人机验证（内置 JS 挑战、Cloudflare Turnstile、Google reCAPTCHA）
- [x] 国家白名单、按省份 / 城市拦截
- [x] Slack、Microsoft Teams 通知；兼容 Oracle Cloud 的邮件发送
- [ ] 泛域名证书自动签发（DNS-01，需对接 DNS 服务商 API）
- [ ] 面板内管理 nftables L4 规则、WireGuard 客户端
- [ ] 日志接入 ClickHouse，多网关集群
- [ ] 接入 CrowdSec 社区 IP 信誉库

## 许可证

Copyright (C) 2026 llldkkw

本项目以 **[知识共享 署名-非商业性使用-相同方式共享 4.0 国际许可协议（CC BY-NC-SA 4.0）](https://creativecommons.org/licenses/by-nc-sa/4.0/deed.zh-hans)** 授权，完整条款见 [LICENSE](LICENSE)。

| 你可以 | 条件 |
|---|---|
| 免费使用、学习、研究 | 仅限**非商业用途** |
| 修改源码 | 修改版必须同样以 CC BY-NC-SA 4.0 发布 |
| 分享、再分发（包括修改版） | 必须**署名**原作者并附上许可协议链接，注明是否做了修改；不得商用 |

**禁止商业用途**，包括但不限于：

- 出售本项目或其修改版，或以其为主要部分的产品
- 基于本项目提供收费服务（托管 WAF、SaaS、付费部署或运维服务等）
- 用于营利性组织的业务系统

如需商业使用，请联系作者另行取得书面授权。

**说明：**

- 提交 `b41169f` 至 `cd086eb` 曾以 GNU AGPL-3.0-or-later 发布，已按该许可证获得的这些版本仍适用 AGPL-3.0；此后的版本适用 CC BY-NC-SA 4.0。
- 本项目使用的第三方组件（Coraza、OWASP CRS、React、ECharts 等）仍按其各自的许可证授权，不受本协议限制，见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
- 由于包含非商业限制，本项目属于「源码公开」（source-available）项目，不是 OSI 定义的开源软件。
