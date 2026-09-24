# ProxyIP Scanner V4 candidate-pool acceptance

V4 keeps the stable EDT scanner and adds:

- server-persisted custom URL/DNS candidate sources;
- automatic candidate-source refresh every 6 hours with incremental validation instead of full-pool rescans;
- persistent lifecycle state: newly discovered endpoints scan first, known-good endpoints default to a 7-day recheck, and repeated failures back off exponentially;
- backend-only quality scoring and stale/low-quality lifecycle cleanup without a per-region count cap;
- bounded ASN discovery from successful regional candidate records using RIPEstat announced prefixes;
- regional pools for HK/JP/SG/KR/IN/US/DE;
- final-available GeoIP, ASN, provider and VPS/IDC/Cloudflare classification;
- Chinese location and Cloudflare colo labels;
- entry/exit region filtering and region sorting;
- filtered/selected CSV export;
- copyable `/forceproxyip=IP:port` paths for V2RayN/Shadowrocket temporary switching;
- source failure tracking and automatic disable after 3 consecutive failures;
- server-side URL-source SSRF checks including redirects and response-size cap.

The scanner keeps candidate lifecycle and quality metadata in each regional pool. Regional candidate counts are not capped; source rows are deduplicated before contribution statistics are calculated. Background rechecks remain bounded by `CANDIDATE_SCAN_BATCH_LIMIT` so scheduled maintenance cannot monopolize resources.

ASN discovery is deliberately bounded: it starts from ASNs observed on successful regional entry IPs, reads their announced IPv4 prefixes, samples a limited number of addresses/ports, and feeds only those candidates back into the normal validation lifecycle. It does not attempt to exhaustively scan every address in an ASN.
