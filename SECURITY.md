# Security Policy

## Supported versions

The latest published release and the current `main` branch receive security fixes.

## Reporting a vulnerability

Please do not publish exploitable security issues, credentials, private deployment details, or sensitive logs in a public issue.

When reporting a problem, include only the minimum information required to reproduce it. Remove or mask:

- VPS IP addresses and hostnames
- private domains and internal URLs
- API tokens and Tunnel tokens
- cookies, session secrets, passwords and environment files
- personal email addresses or other identifying deployment information

If a report requires sensitive material, contact the repository maintainer through a private channel available on GitHub rather than posting secrets publicly.

## Deployment guidance

- Keep the scanner bound to `127.0.0.1:8788` unless you intentionally place it behind a protected reverse proxy or tunnel.
- Protect `/etc/proxyip-scanner.env` and tunnel environment files with restrictive permissions.
- Do not commit runtime data or credentials to Git.
- Review scan targets and ensure you have authorization to access them.
