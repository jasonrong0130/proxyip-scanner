#!/usr/bin/env bash
set -euo pipefail
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then echo "请用 root 执行"; exit 1; fi
TOKEN="${CLOUDFLARE_TUNNEL_TOKEN:-}"
if [[ -z "$TOKEN" ]]; then read -r -s -p "Cloudflare Tunnel Token: " TOKEN; echo; fi
if [[ -z "$TOKEN" ]]; then echo "Token 不能为空"; exit 1; fi
ARCH="$(dpkg --print-architecture)"
case "$ARCH" in amd64|arm64) ;; *) echo "暂不支持架构: $ARCH"; exit 1;; esac
TMP="$(mktemp)"
curl -fsSL "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${ARCH}.deb" -o "$TMP"
dpkg -i "$TMP" || apt-get -f install -y
rm -f "$TMP"
umask 077
printf 'TUNNEL_TOKEN=%q\n' "$TOKEN" > /etc/proxyip-scanner-tunnel.env
cat >/etc/systemd/system/proxyip-scanner-tunnel.service <<'EOF'
[Unit]
Description=Cloudflare Tunnel for ProxyIP Scanner
After=network-online.target proxyip-scanner.service
Wants=network-online.target
Requires=proxyip-scanner.service

[Service]
Type=simple
EnvironmentFile=/etc/proxyip-scanner-tunnel.env
ExecStart=/usr/bin/cloudflared tunnel --no-autoupdate run --token ${TUNNEL_TOKEN}
Restart=always
RestartSec=5
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now proxyip-scanner-tunnel
systemctl status proxyip-scanner-tunnel --no-pager -l
