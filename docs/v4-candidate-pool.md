# ProxyIP Scanner V4 candidate-pool acceptance

V4 keeps the stable EDT scanner and adds:

- server-persisted custom URL/DNS candidate sources;
- automatic candidate-source refresh every 6 hours with incremental validation instead of full-pool rescans;
- persistent lifecycle state: newly discovered endpoints scan first, known-good endpoints default to a 7-day recheck, and repeated failures back off exponentially;
- persistent verified pools that keep working endpoints across source refreshes;
- backend-only quality scoring and low-quality/stale-first cleanup when pool limits are reached;
- bounded ASN discovery from verified entry ASNs using RIPEstat announced prefixes;
- regional pools for HK/JP/SG/KR/IN/US/DE;
- final-available GeoIP, ASN, provider and VPS/IDC/Cloudflare classification;
- Chinese location and Cloudflare colo labels;
- entry/exit region filtering and region sorting;
- filtered/selected CSV export;
- copyable `/forceproxyip=IP:port` paths for V2RayN/Shadowrocket temporary switching;
- source failure tracking and automatic disable after 3 consecutive failures;
- server-side URL-source SSRF checks including redirects and response-size cap.

The scanner keeps candidate lifecycle and quality metadata server-side; the existing browser UI remains unchanged. Default safety bounds are 30,000 candidates and 5,000 verified endpoints per region, with background validation limited to bounded batches. These values can be adjusted through `CANDIDATE_POOL_MAX_PER_REGION`, `CANDIDATE_VERIFIED_MAX_PER_REGION`, `CANDIDATE_SCAN_BATCH_LIMIT`, and related environment variables.

ASN discovery is deliberately bounded: it starts from ASNs observed on verified entry IPs, reads their announced IPv4 prefixes, samples a limited number of addresses/ports, and feeds only those candidates back into the normal validation lifecycle. It does not attempt to exhaustively scan every address in an ASN.
