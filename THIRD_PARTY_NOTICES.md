# 第三方组件声明

WAF Gateway 的发行版（二进制文件、Docker 镜像）中包含以下第三方组件。它们的版权归各自作者所有，并按各自的许可证分发。完整许可证文本见各项目仓库，或 Go 模块缓存 / `web/node_modules` 中对应目录下的 LICENSE 文件。

所有组件均为宽松许可证（Apache-2.0、MIT、BSD、ISC），与本项目的许可证兼容。

## 核心规则与引擎

| 组件 | 许可证 | 说明 |
|---|---|---|
| [OWASP Core Rule Set](https://github.com/coreruleset/coreruleset)（经 [coraza-coreruleset](https://github.com/corazawaf/coraza-coreruleset) 嵌入） | Apache-2.0 | WAF 检测规则。Copyright OWASP CRS project |
| [OWASP Coraza](https://github.com/corazawaf/coraza) | Apache-2.0 | WAF 规则引擎 |
| [libinjection-go](https://github.com/corazawaf/libinjection-go) | BSD-3-Clause | SQL 注入 / XSS 检测 |

## 后端（Go）

| 组件 | 许可证 |
|---|---|
| modernc.org/sqlite、libc、mathutil、memory | BSD-3-Clause |
| golang.org/x/crypto、net、sync、sys、term、text、time | BSD-3-Clause |
| google.golang.org/protobuf | BSD-3-Clause |
| github.com/google/uuid | BSD-3-Clause |
| github.com/remyoudompheng/bigfft | BSD-3-Clause |
| github.com/gotnospirit/makeplural、messageformat | BSD-3-Clause |
| rsc.io/qr、rsc.io/binaryregexp | BSD-3-Clause |
| github.com/pquerna/otp | Apache-2.0 |
| github.com/valllabh/ocsf-schema-golang | Apache-2.0 |
| github.com/oschwald/geoip2-golang、maxminddb-golang | ISC |
| github.com/coder/websocket | ISC |
| github.com/mdp/qrterminal、github.com/dustin/go-humanize | MIT |
| github.com/boombuler/barcode | MIT |
| github.com/goccy/go-json、go-yaml | MIT |
| github.com/kaptinlin/go-i18n、jsonschema | MIT |
| github.com/petar-dambovaliev/aho-corasick | MIT |
| github.com/tidwall/gjson、match、pretty | MIT |
| gopkg.in/yaml.v3 | MIT / Apache-2.0 |

仅用于测试、不进入发行版：github.com/maxmind/mmdbwriter（Apache-2.0）。

## 前端（打包进管理面板）

| 组件 | 许可证 |
|---|---|
| [Apache ECharts](https://echarts.apache.org) | Apache-2.0 |
| ZRender | BSD-3-Clause |
| React、React DOM、React Router | MIT |
| i18n-iso-countries | MIT |
| qrcode | MIT |
| Lucide Icons（lucide-react） | ISC |
| topojson-client | ISC |
| world-atlas（地图数据源自 Natural Earth，公有领域） | ISC |
| tslib | 0BSD |

## 不随本项目分发的数据

- **MaxMind GeoLite2 数据库**：由用户自行从 MaxMind 下载，受 [GeoLite2 EULA](https://www.maxmind.com/en/geolite2/eula)（CC BY-SA 4.0）约束。使用时请遵守其署名要求："This product includes GeoLite2 data created by MaxMind, available from https://www.maxmind.com"。

## 可选的第三方服务

启用后，访客浏览器会从以下服务加载脚本，网关会调用其校验接口；使用时需遵守各自的服务条款与隐私政策：

- Cloudflare Turnstile — https://www.cloudflare.com/turnstile-privacy-policy/
- Google reCAPTCHA — https://policies.google.com/privacy 、https://policies.google.com/terms

## 商标

OWASP、Coraza 为其各自所有者的商标。本项目与 OWASP、MaxMind、Oracle、Slack、Microsoft 等公司或组织无隶属关系。
