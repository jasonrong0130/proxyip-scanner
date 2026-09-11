# 安装与部署

本文档说明如何在 Ubuntu / Debian 系 Linux VPS 上安装、升级和卸载 ProxyIP Scanner。

## 1. 系统要求

推荐环境：

- Ubuntu 24.04 LTS 或 Debian 系 Linux
- Python 3.10+
- systemd
- Git
- 可正常访问 GitHub 与 Python 软件源

默认服务仅监听：

```text
127.0.0.1:8788
```

不建议直接把 8788 暴露到公网。

## 2. 安装

```bash
sudo -i
git clone https://github.com/jasonrong0130/proxyip-scanner.git /opt/proxyip-scanner
cd /opt/proxyip-scanner
bash install.sh
```

安装脚本会自动：

- 安装运行依赖
- 创建 Python 虚拟环境
- 安装 `requirements.txt`
- 生成本机 Session Secret 与 EDT API Token
- 创建并启用 systemd 服务
- 执行健康检查

安装完成后检查：

```bash
systemctl status proxyip-scanner
curl -s http://127.0.0.1:8788/health
```

正常返回示例：

```json
{"ok":true,"name":"ProxyIP Scanner","version":"1.0.0"}
```

## 3. 服务管理

```bash
systemctl restart proxyip-scanner
systemctl stop proxyip-scanner
systemctl start proxyip-scanner
systemctl status proxyip-scanner
journalctl -u proxyip-scanner -f
```

## 4. 升级

```bash
cd /opt/proxyip-scanner
bash update.sh
```

`update.sh` 会同步当前分支、安装依赖、校验运行模块并重启服务。

如使用正式发布版，建议部署前先切换到对应 tag 或 release 版本，再执行安装或升级。

## 5. 卸载

```bash
cd /opt/proxyip-scanner
bash uninstall.sh
```

卸载前建议先备份：

```text
/var/lib/proxyip-scanner
/etc/proxyip-scanner.env
```

## 6. Cloudflare Tunnel

如需从公网访问 Web 控制台，推荐使用 Cloudflare Tunnel 或其他受控反向代理。

在 Cloudflare Zero Trust 中把公共主机名指向：

```text
http://127.0.0.1:8788
```

然后执行：

```bash
cd /opt/proxyip-scanner
bash install-cloudflare-tunnel.sh
```

Tunnel Token 只应保存在服务器本机环境文件中，不要提交到 Git。

## 7. 运行时数据位置

```text
/opt/proxyip-scanner              程序代码
/var/lib/proxyip-scanner          扫描任务与历史结果
/var/log/proxyip-scanner          本地日志目录
/etc/proxyip-scanner.env          本机账号、密钥与运行参数
/etc/proxyip-scanner-tunnel.env   Tunnel Token（如启用）
```

## 8. 常见检查

```bash
systemctl is-active proxyip-scanner
curl -s http://127.0.0.1:8788/health
journalctl -u proxyip-scanner -n 100 --no-pager
```

服务重启后短时间内出现连接拒绝通常只是应用尚未完成启动；应以最终健康检查结果为准。
