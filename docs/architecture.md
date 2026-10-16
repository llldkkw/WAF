# 架构说明

## 整体结构

WAF Gateway 是一个 Go 单二进制程序，同时运行两个服务：

```
              公网 80/443                         VPN 内网 :9443
                  │                                     │
        ┌─────────▼─────────┐                ┌──────────▼──────────┐
        │  数据面 (proxy)    │ ←── 配置版本 ── │  控制面 (admin)      │
        │  反向代理 + 检测   │   轮询 2 秒     │  REST API + 面板     │
        └──┬──────────┬─────┘                └──────────┬──────────┘
           │          │ 事件                             │
           │   ┌──────▼──────┐   WebSocket 实时推送        │
           │   │  events     │ ─────────────────────────►│
           │   │  记录/统计   │                            │
           │   └──────┬──────┘                            │
           │          │ 告警                              │
           │   ┌──────▼──────┐   ┌──────────┐            │
           │   │  notify     │◄──│  report  │ 定时报告    │
           │   └─────────────┘   └──────────┘            │
           ▼                                              ▼
       后端服务器                              SQLite (data/waf.db)
```

| 包 | 职责 |
|---|---|
| `cmd/waf` | 命令行入口：`serve`、`user`、`ip` |
| `internal/proxy` | 数据面：路由、IP 名单、地区策略、路径规则、限流、人机验证、WAF 检测、负载均衡、健康检查、TLS 证书选择 |
| `internal/engine` | 为每个站点生成 SecLang 指令并编译 Coraza WAF（相同配置复用编译结果） |
| `internal/events` | 事件批量入库、每分钟流量统计、攻击突增检测、GeoIP 查询、WebSocket 广播 |
| `internal/notify` | 推送渠道、告警聚合（5 分钟窗口）、免打扰、邮件发送 |
| `internal/actions` | 告警中一键操作链接的签名与校验 |
| `internal/report` | 日报 / 周报的生成与调度 |
| `internal/admin` | 管理 API、登录认证、会话、审计、内嵌前端 |
| `internal/store` | SQLite 存储（WAL 模式） |
| `internal/secure` | AES-256-GCM 加密、HMAC、随机令牌 |
| `web/` | React + TypeScript + Tailwind + ECharts 管理面板，构建后嵌入二进制 |

## 请求处理流程

每个进入网关的请求依次经过：

```
1. 按 Host 找到站点（未知域名 → 404）
2. 强制 HTTPS 跳转
3. 识别真实客户端 IP（仅信任 trusted_proxies 中的 X-Forwarded-For）
4. IP 白名单 → 直接转发（跳过以下所有检查）
   IP 黑名单 / 自动封禁 → 403
5. 地区策略（block / allow，内网地址豁免）→ 403
6. 路径访问规则 → 403
7. 人机验证提交入口 /.waf/challenge
8. 限流 → 429（超阈值自动封禁）
9. 人机验证（无有效 Cookie → 验证页）
10. WAF 规则检测（OWASP CRS）→ 403（拦截模式）或仅记录（观察模式）
11. 负载均衡转发到健康的后端
```

拦截事件异步写入数据库并通过 WebSocket 推送到面板，不阻塞请求。

## 配置热加载

所有运行时配置（站点、IP 规则、证书）存在数据库中。每次修改都会递增 `config_version`，数据面每 2 秒检查一次，发现变化就在后台重建路由表，然后原子替换。

- 新配置构建失败时，**继续使用旧配置**，并推送「配置加载失败」告警
- WAF 规则编译结果按指令内容缓存，修改与规则无关的设置不会重新编译
- 命令行（`waf ip allow`）也是写数据库，所以对运行中的网关同样 2 秒内生效

## 安全设计

### 管理面板

| 措施 | 实现 |
|---|---|
| 网络隔离 | 监听地址应为 VPN 内网 IP；另有 `allowed_cidrs` 来源白名单，不在名单内的请求返回 404 |
| 传输加密 | 默认自签名 TLS；可换成自己的证书 |
| 登录 | bcrypt（cost 12）密码 + 强制 TOTP；同一验证码 2 分钟内不能重复使用 |
| 防暴力破解 | 同一 IP 或同一用户名 15 分钟内失败 5 次即锁定；不存在的用户也做 bcrypt 比较，防止通过响应时间探测用户名 |
| 会话 | 32 字节随机令牌，数据库只存 SHA-256；Cookie 为 HttpOnly + Secure + SameSite=Strict；绝对有效期 12 小时，空闲 30 分钟登出；后台自动刷新不算活动 |
| CSRF | 写操作必须带 `X-Requested-With: waf` 头且 Origin 同源 |
| 浏览器安全头 | 严格 CSP（禁止内联脚本）、X-Frame-Options、HSTS、Referrer-Policy 等 |
| 权限 | 管理员 / 只读两种角色；至少保留一个启用的管理员 |
| 审计 | 登录、失败登录、所有配置变更写入审计日志（保留 365 天） |
| 告警 | 新 IP 登录（严重）、多次登录失败（警告） |

### 密钥存储

首次启动生成 32 字节主密钥 `data/master.key`（权限 600，权限不对会拒绝启动）。以下数据用 AES-256-GCM 加密后存入数据库：

- 通知渠道的 Token、Webhook 地址、SMTP 密码
- 用户的 TOTP 种子
- 上传证书的私钥

主密钥还用于派生 HMAC，签名人机验证 Cookie 和一键操作链接。**丢失 `master.key` 后这些数据都无法解密，务必备份。**

### 一键操作链接

告警中的「封禁 / 解封 / 加白」链接：

- 载荷（操作、IP、时长、过期时间、随机 nonce）经 HMAC-SHA256 签名，不可篡改
- 7 天过期；nonce 入库，**每个链接只能执行一次**
- 打开链接只显示确认页，需要已登录（含两步验证）的管理员点击「确认执行」才生效
- 链接指向 VPN 内的面板地址，公网无法打开

### 人机验证

三种方式共用同一套令牌和 Cookie 机制：

- **内置**：浏览器计算工作量证明（见下）
- **Cloudflare Turnstile / Google reCAPTCHA**：页面加载对应组件，提交后网关在服务端调用 siteverify 接口校验，并核对返回的域名（reCAPTCHA v3 还核对分数和 action）；第三方不可达时校验失败，不会放行

内置验证的细节：

- 服务器下发签名令牌（站点、客户端网段、5 分钟过期、难度），浏览器计算 `SHA-256(token:counter)` 直到前 N 位为 0
- 服务端校验签名、过期、网段和工作量后，签发 Cookie：`HMAC(站点 | /24 或 /64 网段 | User-Agent 摘要 | 过期时间)`
- Cookie 换网段或换浏览器标识即失效；验证页使用带 nonce 的 CSP

### 数据面

- 未知域名一律 404，不暴露后端信息；删除后端的 `Server`、`X-Powered-By` 等响应头
- 自动 HTTPS 只为已配置的域名申请证书，防止随意 SNI 耗尽 Let's Encrypt 额度
- `X-Forwarded-For` 只在直连方属于 `trusted_proxies` 时采信，并取最右侧不受信任的地址
- WAF 引擎出错时默认拒绝请求（`fail_open: false`）
- 请求头读取超时、请求头大小、空闲连接等均有上限

### 运行环境

systemd 单元（`deploy/waf.service`）：非 root 用户、仅保留 `CAP_NET_BIND_SERVICE`、`ProtectSystem=strict`（只有数据目录可写）、系统调用过滤、`MemoryDenyWriteExecute` 等。

## 数据存储

SQLite 单文件 `data/waf.db`（WAL 模式）。主要表：

| 表 | 内容 |
|---|---|
| `sites` | 站点配置（JSON） |
| `ip_rules` | IP 黑白名单（含自动封禁，到期自动清理） |
| `events` | 攻击事件（按 `log_retention_days` 清理） |
| `stats_minute` | 每分钟每站点的请求数和拦截数 |
| `users` / `sessions` | 用户与会话 |
| `channels` | 通知渠道（配置加密） |
| `certs` | 上传的证书（私钥加密） |
| `audit` | 审计日志 |
| `meta` | 配置版本、报告设置等键值 |

单台网关每天千万级请求以内，SQLite 足够。更大规模可考虑把事件日志迁到 ClickHouse（见路线图）。
