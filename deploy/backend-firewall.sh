#!/bin/sh
# 在每台【后端服务器】上运行：只允许网关访问，阻止攻击者绕过 WAF 直连源站。
# 用法: GATEWAY_IP=10.0.0.1 APP_PORTS="80,443,8080" sh backend-firewall.sh
set -eu
: "${GATEWAY_IP:?需要设置 GATEWAY_IP（网关的内网 IP）}"
APP_PORTS="${APP_PORTS:-80,443,8080}"

nft -f - <<NFT
flush ruleset
table inet filter {
	chain input {
		type filter hook input priority 0; policy drop;
		iif lo accept
		ct state established,related accept
		ct state invalid drop
		meta l4proto { icmp, ipv6-icmp } accept
		# 业务端口和 SSH 只接受来自网关的连接
		ip saddr ${GATEWAY_IP} tcp dport { ${APP_PORTS}, 22 } accept
	}
}
NFT
echo "已应用。确认能从网关 SSH 进来后，执行 nft list ruleset > /etc/nftables.conf 并 systemctl enable nftables 持久化。"
