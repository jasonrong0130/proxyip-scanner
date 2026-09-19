# ProxyIP Scanner v1.2.0

Released: 2026-09-19

## Highlights

- Incremental candidate validation replaces full-pool rescans for normal candidate-pool jobs.
- Newly discovered endpoints are checked first; known-good endpoints are retained and rechecked on a slower cadence.
- Failed endpoints use bounded exponential retry backoff instead of being retried on every source refresh.
- Verified endpoints persist across source refreshes.
- Candidate quality is scored internally from availability, latency, speed, purity/risk and source diversity without changing the existing UI.
- Low-quality and stale candidates are removed first when configured pool limits are reached.
- Bounded ASN discovery expands sources from verified entry ASNs using announced IPv4 prefixes and a limited address/port sample.
- The v1.1 split-per-region candidate storage and memory-release behavior are preserved.

## Default lifecycle bounds

- Candidate source refresh: 6 hours.
- Known-good recheck: 7 days.
- Failed retry base: 24 hours with exponential backoff, capped at 7 days.
- Candidate retention for stale non-verified entries: 14 days.
- Candidate pool limit: 30,000 per region.
- Verified pool limit: 5,000 per region.
- ASN discovery ports: 443, 2053 and 8443.

All limits are configurable through the corresponding `CANDIDATE_*` environment variables.

## Validation

The release was rebased onto the latest main branch candidate-storage and scan-lifecycle hardening changes. The complete Python unittest suite passes, including candidate pool storage, incremental lifecycle, pause/resume, crash recovery and large-job memory lifecycle tests.
