# ProxyIP Scanner v1.0.0

ProxyIP Scanner v1.0.0 is the first public release of the self-hosted scanning and validation platform.

## Highlights

- VPS-direct ProxyIP scanning without Cloudflare Worker raw TCP dependency
- TCP → TLS/SNI → HTTP staged validation
- Multi-port scanning and candidate-pool filtering
- Cloudflare exit IP / country / Colo parsing
- EDT local and remote validation modes
- Speed tests, GeoIP and purity helper information
- Task pause/resume, cancellation and interrupted-job recovery
- Large-job memory optimization and seven-day default history retention
- TXT / CSV export
- systemd installation, update and uninstall scripts

## Installation

```bash
sudo -i
git clone https://github.com/jasonrong0130/proxyip-scanner.git /opt/proxyip-scanner
cd /opt/proxyip-scanner
bash install.sh
```

After installation:

```bash
systemctl status proxyip-scanner
curl -s http://127.0.0.1:8788/health
```

For complete deployment instructions, see `INSTALL.md`.

## Upgrade

```bash
cd /opt/proxyip-scanner
bash update.sh
```

## Notes

- The service listens on `127.0.0.1:8788` by default.
- Use Cloudflare Tunnel or another protected reverse proxy if remote Web access is required.
- Keep runtime credentials and deployment-specific values outside Git.
- Before opening Issues or sharing screenshots/logs, remove tokens, private hostnames, IP addresses and other sensitive deployment data.

## License

MIT License.
