# Test matrix — planned

| Area | Cases | Expected behavior | Owner
|---|---|---|
| URL parsing | missing scheme, credentials, malformed host, IDN, IPv6 | canonical output or safe rejection; preserve meaningful IDN evidence | W01 |
| SSRF boundary | localhost, RFC1918, link-local, metadata IP, DNS resolves private | blocked before request | W01 / Tester 02 |
| Redirects | external-to-private, loop, too many hops, DNS change | revalidate each hop; block/stop with reason | W01 / Tester 02 |
| Limits | slow target, large body, collector timeout, rate burst | bounded resources; partial/failed status | W01 |
| TLS | valid hostname, mismatch, expired, unavailable | technical state distinct from identity | W01/W03 |
| Evidence | stale, missing, failed, contradictory | quality declines; no implicit benign verdict | W02/W03 |
| Community | duplicates, copied reports, conflicting reports | source dependence visible; unverified/disputed statuses | W02 |
| Decision | single weak signal, corroborated strong signals, no signal | conservative rationale; no “safe” wording | W03 |
| UI | loading, rejected, partial, failed, long evidence | accessible and truthful states | W04 |
| Demo | fixture scan, fallback output, simulated signals | labels clear; no confusion with live evidence | W04 / Tester 01 |
