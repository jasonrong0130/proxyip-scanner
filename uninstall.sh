#!/usr/bin/env bash
set -euo pipefail
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then echo "请用 root 执行 uninstall.sh"; exit 1; fi
systemctl disable --now proxyip-scanner 2>/dev/null || true
rm -f /etc/systemd/system/proxyip-scanner.service
systemctl daemon-reload
read -r -p "是否同时删除配置、扫描历史和代码？输入 DELETE 确认: " answer
if [[ "$answer" == "DELETE" ]]; then
  rm -rf /opt/proxyip-scanner /var/lib/proxyip-scanner /var/log/proxyip-scanner
  rm -f /etc/proxyip-scanner.env
  echo "已完整删除。"
else
  echo "服务已移除，代码/数据/配置保留。"
fi
