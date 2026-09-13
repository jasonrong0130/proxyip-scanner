# Changelog

All notable changes to ProxyIP Scanner are documented here.

## [1.1.0] - 2026-09-13

### Added

- Per-job deletion directly from task history
- One-click cleanup for all inactive history jobs
- Destructive cleanup removes task JSON, metadata and checkpoint files together

### Fixed

- Primary scan cancellation now waits for the cancelled asyncio task to finish
- Cancelled and interrupted primary scans release full in-memory target/result payloads
- EDT-stage cancellation no longer leaves hydrated jobs resident in the global job registry
- Unified history purge removes job registry references and associated runtime task references

### Improved

- Completed/cancelled/interrupted jobs are reduced to lightweight lazy stubs after execution
- CI now validates the main web console JavaScript and job lifecycle cleanup tests
- History cleanup keeps currently running or paused jobs intact
- Service startup skips checkpoint replay and metadata rewrites for stable completed/cancelled history
- Upgrade health checks now allow up to 30 seconds for service readiness

## [1.0.0] - 2026-09-11

First public release.

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
- Public README and source tree do not contain deployment-specific VPS/domain information

### License

- Public source is licensed for personal, non-commercial use only under the ProxyIP Scanner Personal Non-Commercial License 1.0.
- Commercial use, paid hosting/SaaS, paid deployment/support, commercial product integration, and use for for-profit business operations require separate written authorization.
