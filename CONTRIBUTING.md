# 参与贡献

感谢你愿意改进 WAF Gateway！无论是报告问题、改进文档还是提交代码，都非常欢迎。

## 行为准则

参与本项目即表示你同意遵守 [行为准则](CODE_OF_CONDUCT.md)。

## 报告问题

- **安全漏洞**：请勿公开提交，按 [SECURITY.md](SECURITY.md) 私密报告。
- **Bug**：使用 Issue 的「Bug 报告」模板，附上版本号、配置（去掉敏感信息）、日志（`journalctl -u waf`）和复现步骤。
- **误报 / 漏报**：先确认是本项目的问题还是 OWASP CRS 规则本身的问题。规则问题请到 [coreruleset](https://github.com/coreruleset/coreruleset) 反馈；误报可以先用控制台「这是误报」功能临时排除。
- **新功能**：先开 Issue 讨论，避免做了不被合并的工作。

## 开发环境

需要 Go 1.26+、Node.js 22+。

```bash
git clone https://github.com/llldkkw/WAF.git && cd WAF

# 开发配置
cat > dev.yaml <<EOF
data_dir: ./data
proxy:
  http_listen: 127.0.0.1:8080
  https_listen: ""
admin:
  listen: 127.0.0.1:9443
  tls: "off"
EOF

go run ./cmd/waf user add -c dev.yaml -name admin   # 用验证器 App 扫码
go run ./cmd/waf serve -c dev.yaml

# 另开终端：前端热更新，/api 自动代理到 127.0.0.1:9443
cd web && npm install && npm run dev
```

## 提交代码

1. Fork 仓库，从默认分支新建功能分支。
2. 保持改动聚焦：一个 PR 只做一件事。
3. 提交前运行全部检查：
   ```bash
   gofmt -l .        # 应无输出
   go vet ./...
   go test -race ./...
   cd web && npm run typecheck && npm run build
   ```
4. 新功能和 Bug 修复请附带测试：
   - 代理行为：`internal/proxy/*_test.go`（可参考 `setup()`、`do()` 辅助函数）
   - WAF 规则：`internal/engine/engine_test.go`
   - 地区相关测试可用 `writeCityDB()` 生成测试用 GeoIP 数据库
5. 界面改动请在 PR 中附上深色 / 浅色 / 手机宽度的截图。
6. 提交信息用英文祈使句，第一行不超过 72 字符，例如 `Add per-site challenge exemptions`。

## 代码约定

- **Go**：遵循 `gofmt` 和标准库风格；错误返回而不是 panic；面向用户的错误信息使用中文。
- **安全优先**：任何进入 SecLang 指令、HTML、SQL、邮件头的用户输入都必须先校验或转义。新增配置项请在 `Normalize()` 中校验。
- **失败要安全**：配置无效时保留旧配置运行，不要让网关因为一条坏规则停止服务。
- **前端**：TypeScript 严格模式；颜色使用 `index.css` 中的主题变量，不要写死颜色值；同时检查深色和浅色主题。
- **不要提交**：`waf.yaml`、`data/`、`master.key`、数据库、证书私钥、`web/dist/` 构建产物。

## 项目结构

见 [docs/architecture.md](docs/architecture.md)。

## 许可证

提交贡献即表示你同意你的贡献按本项目的 [LICENSE](LICENSE) 授权。
