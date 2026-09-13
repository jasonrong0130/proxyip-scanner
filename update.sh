#!/usr/bin/env bash
set -euo pipefail
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then echo "请用 root 执行 update.sh"; exit 1; fi
DIR="/opt/proxyip-scanner"
if [[ ! -d "$DIR/.git" ]]; then echo "$DIR 不是 Git 工作区；请从仓库重新拉取或覆盖代码。"; exit 1; fi

git -C "$DIR" pull --ff-only
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
  if curl -fsS http://127.0.0.1:8788/health; then
    echo
    exit 0
  fi
  sleep 1
done

echo "服务重启后 30 秒内未通过健康检查："
systemctl status proxyip-scanner --no-pager -l || true
journalctl -u proxyip-scanner -n 80 --no-pager || true
exit 1
