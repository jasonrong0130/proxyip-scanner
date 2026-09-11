#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then echo "请用 root 执行 install.sh"; exit 1; fi

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/proxyip-scanner"
DATA_DIR="/var/lib/proxyip-scanner"
LOG_DIR="/var/log/proxyip-scanner"
ENV_FILE="/etc/proxyip-scanner.env"
SERVICE_FILE="/etc/systemd/system/proxyip-scanner.service"

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y python3 python3-venv python3-pip git curl ca-certificates

mkdir -p "$INSTALL_DIR" "$DATA_DIR" "$LOG_DIR"
if [[ "$SRC_DIR" != "$INSTALL_DIR" ]]; then
  rsync_available=0; command -v rsync >/dev/null 2>&1 && rsync_available=1 || true
  if [[ $rsync_available -eq 1 ]]; then
    rsync -a --delete --exclude data --exclude logs --exclude .venv "$SRC_DIR/" "$INSTALL_DIR/"
  else
    find "$INSTALL_DIR" -mindepth 1 -maxdepth 1 ! -name data ! -name logs -exec rm -rf {} +
    cp -a "$SRC_DIR/." "$INSTALL_DIR/"
    rm -rf "$INSTALL_DIR/data" "$INSTALL_DIR/logs" "$INSTALL_DIR/.venv"
  fi
fi

python3 -m venv "$INSTALL_DIR/.venv"
"$INSTALL_DIR/.venv/bin/pip" install --upgrade pip wheel
"$INSTALL_DIR/.venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt"

ADMIN_USER_VALUE="${ADMIN_USER:-admin}"
if [[ -z "${ADMIN_PASSWORD:-}" ]]; then
  read -r -p "管理员用户名 [admin]: " input_user || true
  [[ -n "${input_user:-}" ]] && ADMIN_USER_VALUE="$input_user"
  while true; do
    read -r -s -p "设置管理密码（至少 10 位）: " p1; echo
    read -r -s -p "再次输入管理密码: " p2; echo
    [[ "$p1" == "$p2" && ${#p1} -ge 10 ]] && ADMIN_PASSWORD="$p1" && break
    echo "两次密码不一致或长度不足 10 位，请重试。"
  done
fi

PASSWORD_HASH="$(ADMIN_PASSWORD="$ADMIN_PASSWORD" python3 - <<'PY'
import base64, hashlib, os, secrets
p=os.environ['ADMIN_PASSWORD'].encode()
s=secrets.token_bytes(16)
d=hashlib.scrypt(p,salt=s,n=2**14,r=8,p=1,dklen=32)
e=lambda b: base64.urlsafe_b64encode(b).decode().rstrip('=')
print('scrypt$'+e(s)+'$'+e(d))
PY
)"
SESSION_SECRET_VALUE="$(python3 - <<'PY'
import secrets; print(secrets.token_urlsafe(48))
PY
)"
EDT_TOKEN_VALUE="${EDT_API_TOKEN:-$(python3 - <<'PY'
import secrets; print(secrets.token_urlsafe(36))
PY
)}"

DEFAULT_SNI_VALUE="${DEFAULT_PROBE_SNI:-}"
if [[ -z "$DEFAULT_SNI_VALUE" ]]; then
  read -r -p "默认检测 SNI（可先留空，EDT 调用时可动态传入）: " DEFAULT_SNI_VALUE || true
fi

umask 077
cat > "$ENV_FILE" <<EOF
ADMIN_USER=$ADMIN_USER_VALUE
ADMIN_PASSWORD_HASH=$PASSWORD_HASH
SESSION_SECRET=$SESSION_SECRET_VALUE
EDT_API_TOKEN=$EDT_TOKEN_VALUE
COOKIE_SECURE=1
PROXY_SCANNER_DATA_DIR=$DATA_DIR
DEFAULT_PROBE_SNI=$DEFAULT_SNI_VALUE
DEFAULT_PROBE_PATH=/cdn-cgi/trace
DEFAULT_SPEED_SNI=speed.cloudflare.com
DEFAULT_SPEED_PATH=/__down?bytes={bytes}
CHECK_CONCURRENCY=50
SPEED_CONCURRENCY=3
PROBE_TIMEOUT=7
SPEED_BYTES=5242880
SPEED_REPEATS=3
EDT_VERIFY_MODE=local
EDT_REMOTE_URL=
EDT_REMOTE_TOKEN=
EDT_REMOTE_TIMEOUT=15
EDT_RUNTIME_WORKER_URL=
EDT_PROBE_UUID=
EDT_RUNTIME_PATH_TEMPLATE=/forceproxyip={proxyip}
EDT_RUNTIME_TARGET_HOST=www.google.com
EDT_RUNTIME_TARGET_PORT=443
EDT_RUNTIME_TARGET_SNI=www.google.com
EDT_RUNTIME_TARGET_PATH=/generate_204
EDT_RUNTIME_EXPECT_STATUS=204
EDT_RUNTIME_TIMEOUT=10
EDT_RUNTIME_CONCURRENCY=10
EOF
chmod 600 "$ENV_FILE"

cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=ProxyIP Scanner
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=$ENV_FILE
Environment=PYTHONDONTWRITEBYTECODE=1
ExecStart=$INSTALL_DIR/.venv/bin/uvicorn app:app --host 127.0.0.1 --port 8788 --workers 1 --proxy-headers --forwarded-allow-ips=127.0.0.1,::1
Restart=on-failure
RestartSec=3
User=root
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$DATA_DIR $LOG_DIR

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now proxyip-scanner
sleep 1
if ! curl -fsS http://127.0.0.1:8788/health >/dev/null; then
  systemctl status proxyip-scanner --no-pager -l || true
  echo "安装完成但健康检查失败，请查看上方日志。"; exit 1
fi

echo
echo "=============================================="
echo "ProxyIP Scanner 安装完成"
echo "本机监听: http://127.0.0.1:8788"
echo "服务: proxyip-scanner.service"
echo "配置: $ENV_FILE"
echo "数据: $DATA_DIR"
echo "EDT API Token（请妥善保存）: $EDT_TOKEN_VALUE"
echo "=============================================="
echo "公网访问请使用 Cloudflare Tunnel 或 SSH 隧道，不要开放 8788。"
