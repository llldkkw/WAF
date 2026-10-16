# 配置参考

## 配置文件 `waf.yaml`

只包含启动参数，修改后需重启（`systemctl restart waf`）。站点、IP 规则、证书、通知等都在面板中修改，实时生效。

配置文件路径：`-c` 参数，或环境变量 `WAF_CONFIG`，默认 `./waf.yaml`。完整示例见 [`waf.example.yaml`](../waf.example.yaml)。

| 键 | 默认值 | 说明 |
|---|---|---|
| `data_dir` | `./data` | 数据目录：数据库、`master.key`、证书缓存、面板自签名证书 |
| `geoip_db` | 空 | MaxMind `.mmdb` 文件路径。Country 库只能按国家匹配；City 库可按省份 / 城市匹配 |
| `timezone` | `Asia/Shanghai` | 安全报告和免打扰时段使用的时区（IANA 名称） |
| `log_retention_days` | `30` | 攻击事件和流量统计保留天数 |
| **`proxy`** | | |
| `proxy.http_listen` | `:80` | HTTP 监听地址 |
| `proxy.https_listen` | `:443` | HTTPS 监听地址；设为空字符串则不监听 |
| `proxy.trusted_proxies` | `[]` | 网关前的 CDN / 负载均衡网段，只有它们的 `X-Forwarded-For` 会被采信 |
| `proxy.fail_open` | `false` | WAF 引擎出错时：`false` 拒绝请求，`true` 放行 |
| `proxy.max_body_bytes` | `10485760` | 请求体最多检查多少字节（超出部分不检查但照常转发） |
| **`admin`** | | |
| `admin.listen` | `127.0.0.1:9443` | 管理面板监听地址，应设为 VPN 内网 IP，如 `10.8.0.1:9443` |
| `admin.tls` | `self-signed` | `self-signed`（自动生成）/ `file`（使用下面两项）/ `off`（仅限本地开发） |
| `admin.cert_file` / `admin.key_file` | 空 | `tls: file` 时的证书和私钥路径 |
| `admin.allowed_cidrs` | 本机 + 私有网段 | 允许访问面板的来源网段 |
| `admin.session_hours` | `12` | 会话最长有效期 |
| `admin.idle_minutes` | `30` | 无操作自动登出 |
| `admin.public_url` | 空 | 面板访问地址，如 `https://10.8.0.1:9443`。设置后告警推送附带一键操作链接 |
| **`acme`** | | |
| `acme.enabled` | `false` | 启用 Let's Encrypt 自动证书 |
| `acme.email` | 空 | 启用时必填，用于证书到期通知 |
| `acme.directory_url` | Let's Encrypt 正式环境 | 可改为测试环境 `https://acme-staging-v02.api.letsencrypt.org/directory` |

## 站点设置（面板 → 站点防护）

| 设置 | 说明 |
|---|---|
| 域名 | 每行一个，支持 `*.example.com`（只匹配一级子域名） |
| 后端地址 | `http://` 或 `https://` 开头，多个时轮询 |
| 保留原始 Host | 后端按域名区分虚拟主机时开启 |
| 跳过后端证书校验 | 后端是自签名 HTTPS 时开启 |
| 健康检查 | 路径、间隔；连续 3 次失败摘除并告警 |
| HTTPS / 强制跳转 | 证书优先用上传的，没有则用 Let's Encrypt |
| 防护模式 | 拦截 / 观察（只记录）/ 关闭 |
| 防护等级 | CRS Paranoia Level 1–4 |
| 异常分数阈值 | 默认 5，越低越严格 |
| 误报排除 | 规则 ID + 可选路径前缀 |
| 单 IP 限流 | 每秒请求、突发上限、1 分钟内超限多少次后封禁、封禁时长 |
| 攻击者自动封禁 | 5 分钟内被拦截多少次后封禁、封禁时长 |
| 人机验证 | 关闭 / 仅可疑访问 / 所有访问；验证方式：内置 / Cloudflare Turnstile / Google reCAPTCHA；内置验证难度 14–20；有效期；免验证路径 |
| 地区策略 | 不限制 / 封禁以下地区 / 仅允许以下地区；规则格式见 README |
| 路径访问规则 | 路径前缀 + 仅允许指定网段 / 禁止访问 |

## 系统设置（面板 → 系统设置）

第三方人机验证服务的密钥，全局配置、加密存储，各站点自行选择是否使用。

| 服务 | 字段 | 获取方式 |
|---|---|---|
| Cloudflare Turnstile | Site Key、Secret Key | Cloudflare 控制台 → Turnstile → 添加站点（域名无需托管在 Cloudflare） |
| Google reCAPTCHA | 版本（v2 复选框 / v3 评分）、Site Key、Secret Key、加载域名、v3 最低分数 | reCAPTCHA 管理后台（已归入 Google Cloud）创建密钥 |

- reCAPTCHA 默认通过 `www.recaptcha.net` 加载和校验，中国大陆可访问；也可改为 `www.google.com`。
- 校验时会核对服务返回的域名与访问的域名一致；v3 还会核对分数和 action。
- 第三方服务不可达时验证失败（不会放行）；站点选择的服务未配置密钥时，自动改用内置验证。

## 命令行

```bash
waf serve      [-c waf.yaml]
waf user add   [-c waf.yaml] -name NAME [-role admin|viewer]   # 交互输入密码，输出 TOTP 二维码
waf user reset [-c waf.yaml] -name NAME                        # 重置密码和两步验证
waf ip list    [-c waf.yaml]
waf ip allow   [-c waf.yaml] [-note TEXT] IP/CIDR
waf ip deny    [-c waf.yaml] [-note TEXT] [-minutes N] IP/CIDR
waf ip del     [-c waf.yaml] IP/CIDR
waf version
```

非交互环境可以用环境变量 `WAF_PASSWORD` 传入密码（会留在 shell 历史中，慎用）。

在服务器上执行时请以服务用户运行，避免生成 root 属主的文件：

```bash
sudo -u waf WAF_CONFIG=/etc/waf/waf.yaml waf ip list
```
