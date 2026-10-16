#!/bin/sh
# 在网关服务器上安装 WAF（需 root）。
# 用法: sudo sh install.sh ./waf-linux-amd64
set -eu
BIN="${1:-./waf}"
[ "$(id -u)" = 0 ] || { echo "请用 root 运行"; exit 1; }
[ -f "$BIN" ] || { echo "找不到二进制 $BIN（先运行 make release 或下载）"; exit 1; }
HERE=$(cd "$(dirname "$0")" && pwd)

id waf >/dev/null 2>&1 || useradd --system --home /var/lib/waf --shell /usr/sbin/nologin waf
install -m 0755 "$BIN" /usr/local/bin/waf
install -d -m 0750 -o root -g waf /etc/waf
install -d -m 0700 -o waf -g waf /var/lib/waf
if [ ! -f /etc/waf/waf.yaml ]; then
	install -m 0640 -o root -g waf "$HERE/../waf.example.yaml" /etc/waf/waf.yaml
	echo "已生成 /etc/waf/waf.yaml，请按需修改（admin.listen、acme 等）"
fi
install -m 0644 "$HERE/waf.service" /etc/systemd/system/waf.service
systemctl daemon-reload

cat <<MSG

安装完成。接下来：
  1. 编辑配置:        vi /etc/waf/waf.yaml
  2. 创建管理员:      sudo -u waf WAF_CONFIG=/etc/waf/waf.yaml waf user add -name admin
                     （用手机验证器 App 扫描输出的二维码）
  3. 启动:            systemctl enable --now waf
  4. 查看日志:        journalctl -u waf -f
  5. 连上 WireGuard 后打开 https://10.8.0.1:9443

应急：被自己的规则挡住时，在服务器上执行
  sudo -u waf WAF_CONFIG=/etc/waf/waf.yaml waf ip allow 你的IP
MSG
