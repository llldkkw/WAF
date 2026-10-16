# 管理 API

管理面板通过以下 REST API 工作，也可以用于脚本自动化。所有接口都在管理面板地址下（如 `https://10.8.0.1:9443`）。

## 认证与约定

- 先调用 `POST /api/login` 获取会话 Cookie `waf_session`，之后的请求带上该 Cookie。
- **所有非 GET 请求**必须带请求头 `X-Requested-With: waf`，否则返回 403（CSRF 防护）。
- 请求和响应均为 JSON；错误格式为 `{"error": "说明"}`。
- 权限：🔓 登录即可（含只读用户），🔒 仅管理员。

```bash
A=https://10.8.0.1:9443
curl -sk -c jar -H 'X-Requested-With: waf' -H 'Content-Type: application/json' \
  -X POST $A/api/login -d '{"username":"admin","password":"...","code":"123456"}'
curl -sk -b jar $A/api/overview?range=24h
```

## 接口列表

### 账号

| 方法 | 路径 | 权限 | 说明 |
|---|---|---|---|
| POST | `/api/login` | 公开 | `{username, password, code}`，code 为 6 位 TOTP |
| POST | `/api/logout` | 公开 | 注销当前会话 |
| GET | `/api/me` | 🔓 | 当前用户 |
| POST | `/api/me/password` | 🔓 | `{current, new}`；成功后所有会话失效 |

### 总览与状态

| 方法 | 路径 | 权限 | 说明 |
|---|---|---|---|
| GET | `/api/overview?range=1h\|24h\|7d\|30d&site=ID` | 🔓 | 统计数据、时间序列、Top 排行 |
| GET | `/api/status` | 🔓 | 版本、运行时间、后端健康、GeoIP 状态、缺少证书的域名 |
| GET | `/api/ws` | 🔓 | WebSocket：`{"type":"event"\|"tick","data":...}` 实时事件和每秒流量 |

### 站点

| 方法 | 路径 | 权限 | 说明 |
|---|---|---|---|
| GET | `/api/sites` | 🔓 | 站点列表 |
| GET | `/api/sites/{id}` | 🔓 | 单个站点 |
| POST | `/api/sites` | 🔒 | 新建，请求体为完整站点对象 |
| PUT | `/api/sites/{id}` | 🔒 | 修改 |
| DELETE | `/api/sites/{id}` | 🔒 | 删除 |
| POST | `/api/sites/{id}/exclusions` | 🔒 | 添加误报排除 `{rule_id, path, note}` |

### IP 规则

| 方法 | 路径 | 权限 | 说明 |
|---|---|---|---|
| GET | `/api/ip-rules` | 🔓 | 有效的规则 |
| POST | `/api/ip-rules` | 🔒 | `{cidr, action: "allow"\|"deny", site_id, note, minutes}`，site_id 为 0 表示全局，minutes 为 0 表示永久 |
| DELETE | `/api/ip-rules/{id}` | 🔒 | 删除 |

### 事件与审计

| 方法 | 路径 | 权限 | 说明 |
|---|---|---|---|
| GET | `/api/events` | 🔓 | 参数：`from`、`to`（Unix 秒）、`site`、`ip`、`action`、`category`、`q`、`limit`（≤500）、`offset` |
| GET | `/api/audit?limit=&offset=` | 🔒 | 审计日志 |

`action` 取值：`blocked`、`detected`、`rate_limited`、`ip_denied`、`geo_denied`、`path_denied`。

### 证书

| 方法 | 路径 | 权限 | 说明 |
|---|---|---|---|
| GET | `/api/certs` | 🔒 | 证书列表（不含私钥） |
| POST | `/api/certs` | 🔒 | `{name, cert, key}`，PEM 格式 |
| PUT | `/api/certs/{id}` | 🔒 | 替换证书 |
| DELETE | `/api/certs/{id}` | 🔒 | 删除 |

### 通知与报告

| 方法 | 路径 | 权限 | 说明 |
|---|---|---|---|
| GET | `/api/channel-types` | 🔓 | 支持的渠道及字段定义 |
| GET | `/api/channels` | 🔒 | 渠道列表（密钥字段显示为 `••••••`） |
| POST | `/api/channels` | 🔒 | `{name, type, config, min_level, enabled}`；config 中 `reports: "1"` 订阅报告，`quiet_hours: "23:00-07:00"` 免打扰 |
| PUT | `/api/channels/{id}` | 🔒 | 修改；值为 `••••••` 的字段保持不变 |
| DELETE | `/api/channels/{id}` | 🔒 | 删除 |
| POST | `/api/channels/{id}/test` | 🔒 | 发送测试消息 |
| GET | `/api/settings/reports` | 🔒 | 报告设置 |
| PUT | `/api/settings/reports` | 🔒 | `{daily, daily_time, weekly, weekly_day, weekly_time}` |
| POST | `/api/reports/send` | 🔒 | `{period: "daily"\|"weekly"}` 立即发送并返回预览 |

### 一键操作

| 方法 | 路径 | 权限 | 说明 |
|---|---|---|---|
| GET | `/api/actions?t=TOKEN` | 🔒 | 查看链接内容和是否已使用 |
| POST | `/api/actions` | 🔒 | `{token}` 执行；每个令牌只能执行一次 |

### 用户

| 方法 | 路径 | 权限 | 说明 |
|---|---|---|---|
| GET | `/api/users` | 🔒 | 用户列表 |
| POST | `/api/users` | 🔒 | `{username, password, role}`，返回一次性的 TOTP 密钥和二维码 URL |
| PUT | `/api/users/{id}` | 🔒 | `{role, disabled}` |
| DELETE | `/api/users/{id}` | 🔒 | 删除 |
| POST | `/api/users/{id}/reset` | 🔒 | `{password}`，同时重置两步验证并注销该用户所有会话 |

## 通用 Webhook 格式

通知渠道类型为「通用 Webhook」时，网关会 POST：

```json
{
  "level": "warning",
  "kind": "ban",
  "title": "IP 已自动封禁: 203.0.113.9",
  "body": "IP: 203.0.113.9 (CN-GD 深圳)\n站点: 官网\n...",
  "actions": [{"label": "解除封禁", "url": "https://10.8.0.1:9443/actions?t=..."}],
  "ts": 1792143157
}
```

`kind` 取值：`attack`、`ban`、`spike`、`upstream`、`login`、`config`、`cert`、`report`、`system`、`test`。

设置了签名密钥时，请求头 `X-WAF-Signature: sha256=<hex>` 为请求体的 HMAC-SHA256，接收方应校验。
