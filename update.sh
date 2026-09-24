#!/usr/bin/env bash
set -euo pipefail
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then echo "请用 root 执行 update.sh"; exit 1; fi
DIR="/opt/proxyip-scanner"
if [[ ! -d "$DIR/.git" ]]; then echo "$DIR 不是 Git 工作区；请从仓库重新拉取或覆盖代码。"; exit 1; fi

git -C "$DIR" fetch origin main --prune
git -C "$DIR" reset --hard origin/main
git -C "$DIR" checkout -B main origin/main
"$DIR/.venv/bin/pip" install -r "$DIR/requirements.txt"
python3 -m py_compile \
  "$DIR/app.py" \
  "$DIR/candidate_pool.py" \
  "$DIR/edt_runtime.py" \
  "$DIR/edt_verify.py" \
  "$DIR/geoip.py" \
  "$DIR/purity.py"

# Verify the checked-out code itself exposes the candidate-pool routes before
# touching the running service.
route_check="$(
  cd "$DIR"
  PROXY_SCANNER_DATA_DIR=/tmp/proxyip-scanner-update-check \
  ADMIN_PASSWORD_HASH=x SESSION_SECRET=x \
  "$DIR/.venv/bin/python" - <<'PY'
import app
paths = {getattr(route, "path", "") for route in app.app.routes}
required = {"/api/candidate-pool", "/api/candidate-sources"}
missing = sorted(required - paths)
if missing:
    raise SystemExit("missing routes: " + ", ".join(missing))
print("routes-ok")
PY
)"
[[ "$route_check" == *"routes-ok"* ]] || { echo "候选池路由自检失败"; exit 1; }

# Always rewrite the systemd unit to the canonical installation directory.
# Older installs may still point at a retired checkout, which makes git update
# succeed while the live service keeps serving old UI/API code.
SERVICE_FILE="/etc/systemd/system/proxyip-scanner.service"
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=ProxyIP Scanner
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$DIR
EnvironmentFile=/etc/proxyip-scanner.env
Environment=PYTHONDONTWRITEBYTECODE=1
ExecStart=$DIR/.venv/bin/uvicorn app:app --host 127.0.0.1 --port 8788 --workers 1 --proxy-headers --forwarded-allow-ips=127.0.0.1,::1
Restart=on-failure
RestartSec=3
User=root
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/proxyip-scanner /var/log/proxyip-scanner

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl unmask proxyip-scanner >/dev/null 2>&1 || true
systemctl enable proxyip-scanner >/dev/null 2>&1 || true
systemctl restart proxyip-scanner

main_pid="$(systemctl show -p MainPID --value proxyip-scanner)"
if [[ -z "$main_pid" || "$main_pid" == "0" ]]; then
  echo "错误：proxyip-scanner 没有有效 MainPID"
  systemctl status proxyip-scanner --no-pager -l || true
  exit 1
fi
live_cwd="$(readlink -f "/proc/$main_pid/cwd" 2>/dev/null || true)"
if [[ "$live_cwd" != "$DIR" ]]; then
  echo "错误：运行中的服务目录不是 $DIR，而是 ${live_cwd:-未知}"
  ps -fp "$main_pid" || true
  exit 1
fi

for i in {1..30}; do
  if curl -fsS http://127.0.0.1:8788/health >/tmp/proxyip-scanner-health.json; then
    root_html="$(curl -fsS http://127.0.0.1:8788/ || true)"
    pool_code="$(curl -sS -o /dev/null -w '%{http_code}' 'http://127.0.0.1:8788/api/candidate-pool?region=HK' || true)"
    sources_code="$(curl -sS -o /dev/null -w '%{http_code}' 'http://127.0.0.1:8788/api/candidate-sources' || true)"
    if [[ "$root_html" == *"已验证 ProxyIP 池"* ]]; then
      echo "错误：服务仍在返回旧版前端页面。"
      exit 1
    fi
    if [[ "$pool_code" == "404" ]]; then
      echo "错误：候选池 API 仍为 404，运行代码与 main 不一致。"
      exit 1
    fi
    if [[ "$sources_code" == "404" ]]; then
      echo "错误：候选源 API 仍为 404，运行代码与 main 不一致。"
      exit 1
    fi
    version="$("$DIR/.venv/bin/python" - <<'PY'
import json
with open("/tmp/proxyip-scanner-health.json", "r", encoding="utf-8") as fh:
    print(json.load(fh).get("version", ""))
PY
)"
    if [[ "$version" != "1.2.1" ]]; then
      echo "错误：运行版本为 ${version:-未知}，预期 1.2.1。"
      exit 1
    fi
    cat /tmp/proxyip-scanner-health.json
    echo
    echo "运行目录: $live_cwd"
    git -C "$DIR" log -1 --oneline
    exit 0
  fi
  sleep 1
done

echo "服务重启后 30 秒内未通过健康检查："
systemctl status proxyip-scanner --no-pager -l || true
journalctl -u proxyip-scanner -n 80 --no-pager || true
exit 1
