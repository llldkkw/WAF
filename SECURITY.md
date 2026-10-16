# 安全策略

WAF Gateway 本身就是安全基础设施，它的漏洞可能让攻击者绕过防护，甚至控制所有后端服务器。我们非常重视安全问题的报告。

## 报告漏洞

**请不要在公开的 Issue、讨论区或社交媒体上披露漏洞。**

请通过 GitHub 私密漏洞报告提交：仓库页面 → **Security** → **Report a vulnerability**（[直达链接](https://github.com/llldkkw/WAF/security/advisories/new)）。

报告中请尽量包含：

- 受影响的版本或提交（`waf version` 输出）
- 漏洞类型（例如：WAF 规则绕过、认证绕过、命令注入、信息泄露）
- 复现步骤或概念验证（PoC）
- 你评估的影响范围

## 处理流程

| 阶段 | 目标时间 |
|---|---|
| 确认收到 | 3 个工作日内 |
| 初步评估（是否成立、严重程度） | 7 个工作日内 |
| 修复发布 | 严重 / 高危：30 天内；中低危：下一个版本 |

修复发布后，我们会发布安全公告（GitHub Security Advisory），并在征得同意后致谢报告者。请在公告发布前不要公开细节。

## 支持的版本

只对最新发布版本和主分支提供安全修复。请及时升级。

## 范围说明

**属于安全漏洞：**
- 管理面板的认证、会话、两步验证、CSRF、权限（只读用户越权）问题
- 一键操作链接、人机验证 Cookie 的签名可被伪造或重放
- 网关可被用于攻击后端（如请求走私、SSRF）
- 敏感信息泄露（通知密钥、证书私钥、TOTP 种子、会话令牌）
- 导致网关崩溃或资源耗尽的请求

**通常不属于本项目的漏洞（请向上游报告）：**
- 某个攻击载荷能绕过 OWASP CRS 规则 → 请报告给 [OWASP CRS](https://github.com/coreruleset/coreruleset/security)
- Coraza 引擎本身的问题 → 请报告给 [Coraza](https://github.com/corazawaf/coraza/security)
- 由不安全部署导致的问题（例如把管理面板暴露在公网、关闭了 TLS）

## 安全设计概要

部署前建议阅读 [docs/architecture.md](docs/architecture.md#安全设计) 中的安全设计说明。核心原则：

1. 管理面板只监听 VPN 内网地址，并有来源网段白名单
2. 强制两步验证，验证码防重放，登录失败锁定
3. 所有密钥（通知凭据、TOTP 种子、证书私钥）用 AES-256-GCM 加密存储，主密钥 `master.key` 权限必须为 600
4. 服务以非 root 用户运行，systemd 沙箱隔离
5. 后端服务器只接受网关 IP 的连接
