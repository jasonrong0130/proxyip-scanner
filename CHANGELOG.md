# Changelog

All notable changes to ProxyIP Scanner are documented here.

## [1.0.0] - 2026-09-11

First public release candidate.

### Added

- Self-hosted ProxyIP scanning and validation service for Linux VPS
- Batch import for IP, CIDR and `IP:PORT` targets
- Multi-port scanning with explicit-port preservation
- TCP, TLS/SNI and HTTP staged validation
- Cloudflare trace parsing, exit IP/country/Colo detection
- Entry/exit IP comparison
- Candidate pool with region/source filtering
- EDT local and remote real-connection validation modes
- Speed testing and repeated speed testing
- GeoIP and IP purity helper information
- Task history, pause/resume, cancellation and interrupted-task recovery
- TXT/CSV export
- Admin authentication and basic web security controls
- systemd install/update/uninstall scripts
- Cloudflare Tunnel helper installer

### Improved

- Bounded-memory processing for large jobs
- Fixed worker pools for EDT batch checks and Geo enrichment
- Lazy large-job history loading and checkpoint recovery
- Default seven-day retention for completed/interrupted/failed tasks
- Runtime-module validation during updates

### Security / privacy

- Runtime secrets remain outside Git
- Default bind address is `127.0.0.1:8788`
- Private, loopback and reserved scan targets are rejected
- Public README and source tree no longer contain deployment-specific VPS/domain information

### License

- Public source is licensed for personal, non-commercial use only under the ProxyIP Scanner Personal Non-Commercial License 1.0.
- Commercial use, paid hosting/SaaS, paid deployment/support, commercial product integration, and use for for-profit business operations require separate written authorization.
