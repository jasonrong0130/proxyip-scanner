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

# OOM rescue may have replaced the service with /dev/null and moved the original to /root.
if [[ -L /etc/systemd/system/proxyip-scanner.service ]] && [[ "$(readlink /etc/systemd/system/proxyip-scanner.service || true)" == "/dev/null" ]] && [[ -f /root/proxyip-scanner.service.bak ]]; then
  rm -f /etc/systemd/system/proxyip-scanner.service
  mv /root/proxyip-scanner.service.bak /etc/systemd/system/proxyip-scanner.service
fi
systemctl daemon-reload
systemctl enable proxyip-scanner >/dev/null 2>&1 || true
systemctl restart proxyip-scanner

for i in {1..30}; do
  if curl -fsS http://127.0.0.1:8788/health >/tmp/proxyip-scanner-health.json; then
    root_html="$(curl -fsS http://127.0.0.1:8788/ || true)"
    pool_code="$(curl -sS -o /dev/null -w '%{http_code}' 'http://127.0.0.1:8788/api/candidate-pool?region=HK' || true)"
    if [[ "$root_html" == *"已验证 ProxyIP 池"* ]]; then
      echo "错误：服务仍在返回旧版前端页面。"
      exit 1
    fi
    if [[ "$pool_code" == "404" ]]; then
      echo "错误：候选池 API 仍为 404，运行代码与 main 不一致。"
      exit 1
    fi
    cat /tmp/proxyip-scanner-health.json
    echo
    git -C "$DIR" log -1 --oneline
    exit 0
  fi
  sleep 1
done

echo "服务重启后 30 秒内未通过健康检查："
systemctl status proxyip-scanner --no-pager -l || true
journalctl -u proxyip-scanner -n 80 --no-pager || true
exit 1
