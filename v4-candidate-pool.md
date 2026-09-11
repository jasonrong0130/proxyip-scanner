# ProxyIP Scanner V4 candidate-pool acceptance

V4 keeps the stable EDT scanner and adds:

- server-persisted custom URL/DNS candidate sources;
- automatic candidate refresh every 6 hours and EDT recheck every 24 hours;
- regional pools for HK/JP/SG/KR/IN/US/DE;
- final-available GeoIP, ASN, provider and VPS/IDC/Cloudflare classification;
- Chinese location and Cloudflare colo labels;
- entry/exit region filtering and region sorting;
- filtered/selected CSV export;
- copyable `/forceproxyip=IP:port` paths for V2RayN/Shadowrocket temporary switching;
- source failure tracking and automatic disable after 3 consecutive failures;
- server-side URL-source SSRF checks including redirects and response-size cap.

The regional automatic pool deliberately excludes the global EDT dynamic-domain group to avoid presenting unverified global candidates as a selected region. Global/dynamic sources can still be added explicitly as custom sources.
