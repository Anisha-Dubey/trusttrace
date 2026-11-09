# worker_01 Phase 01 report — 01 URL policy and safe scan boundary

**Status: COMPLETED & VERIFIED.**

- **Owner**: worker_01
- **Commit/build**: Verified with automated test suite (`run_tests.py`, 16 unit/integration tests + 8 schema invariant checks).
- **Environment**: Python 3.14 on Windows (win_amd64), isolated intake boundary.
- **Scope**: 01 URL policy and safe scan boundary (URL canonicalization, credential blocking, IDNA normalization, query token redaction, SSRF defense, DNS rebinding mitigation, redirect policies, and canonical schema-compliant rejection reporting).

## Files Changed / Added
- `src/trusttrace/__init__.py`: Package entrypoint.
- `src/trusttrace/intake/__init__.py`: Intake module exports.
- `src/trusttrace/intake/url_policy.py`: URL parsing, scheme whitelisting, credential blocker, IDNA/punycode preservation, and token redactor (`URL-001`, `URL-002`, `URL-003`, `URL-004`, `URL-005`, `DATA-001`).
- `src/trusttrace/intake/ip_classifier.py`: IPv4 and IPv6 classification against loopback, RFC1918, ULA, link-local, cloud metadata, multicast, broadcast, and reserved networks (`SSRF-001`, `SSRF-002`, `SSRF-003`).
- `src/trusttrace/intake/dns_resolver.py`: Safe DNS resolver verifying every resolved IP address before connection and connection-time revalidation against DNS rebinding (`SSRF-004`, `SSRF-005`).
- `src/trusttrace/intake/redirect_policy.py`: Hop-capped redirect evaluator blocking prohibited destinations, loops, and unsupported schemes, with cross-origin sensitive header stripping (`REDIR-001`, `REDIR-002`, `REDIR-003`).
- `src/trusttrace/intake/boundary.py`: High-level intake boundary with automated canonical rejection report builder adhering 100% to `scan_report.schema.json`.
- `tests/test_url_policy.py`: Unit tests for URL parsing and redaction.
- `tests/test_ssrf_boundary.py`: Unit tests for IP classification, mock DNS resolution, and rebinding simulation.
- `tests/test_redirect_boundary.py`: Unit tests for redirect safety and header filtering.
- `tests/test_fixtures_integration.py`: JSON schema validation for generated reports and fixtures.
- `run_tests.py`: Root test suite runner.

## Commands & Test Cases
- `python run_tests.py`
  - 16/16 unit and integration tests passed.
  - 8/8 contract & fixture cross-record invariant checks passed.

### Test Matrix Verification
| Case ID | Area | Status | Evidence |
|---|---|---|---|
| `URL-001` | URL parsing | TESTED | `test_url_001_normal_https`: Normalized host and accepted scheme verified. |
| `URL-002` | URL parsing | TESTED | `test_url_002_reject_embedded_credentials`: URLs with user/password rejected with zero network egress. |
| `URL-003` | URL parsing | TESTED | `test_url_003_redact_sensitive_query_tokens`: API tokens, passwords, and JWTs redacted to `[REDACTED]`. |
| `URL-004` | URL parsing | TESTED | `test_url_004_unicode_idna_confusable`: Punycode and Unicode display preserved as contextual evidence without false classification. |
| `URL-005` | URL parsing | TESTED | `test_url_005_reject_unsupported_schemes`: `file:`, `javascript:`, `data:`, `ftp:` rejected before resolver call. |
| `SSRF-001` | Egress | TESTED | `test_ssrf_001_loopback_prohibited`: `127.0.0.1` and `::1` blocked. |
| `SSRF-002` | Egress | TESTED | `test_ssrf_002_private_rfc1918_and_ipv6_ula`: RFC1918 IPv4 and IPv6 ULA (`fc00::/7`) blocked. |
| `SSRF-003` | Egress | TESTED | `test_ssrf_003_link_local_and_cloud_metadata`: Link-local and cloud metadata (`169.254.169.254`, `fd00:ec2::254`, etc.) blocked. |
| `SSRF-004` | Egress | TESTED | `test_ssrf_004_hostname_resolves_to_prohibited_ip`: Hostname resolving to prohibited IP blocked before connection. |
| `SSRF-005` | Egress | TESTED | `test_ssrf_005_dns_rebinding_simulation`: Pinned IP validation rejects altered destination IP at connection time. |
| `REDIR-001` | Redirect | TESTED | `test_redir_001_redirect_to_prohibited_target`: Redirect to loopback/private target blocked. |
| `REDIR-002` | Redirect | TESTED | `test_redir_002_excessive_redirect_hops`: Hops exceeding limit (5) terminated with `excessive_redirect_hops`. |
| `REDIR-003` | Redirect | TESTED | `test_redir_003_redirect_to_unsupported_scheme`: Redirect to non-HTTP/HTTPS schemes blocked. |
| `DATA-001` | Privacy | TESTED | Query secrets and authorization tokens stripped from redacted output and logs. |

## Acceptance Criteria Met
- [x] Input validation strictly enforces `http` and `https`.
- [x] Embedded credentials rejected immediately with zero network egress.
- [x] Strict IP destination classification rejects loopback, RFC1918, ULA, link-local, and cloud metadata.
- [x] DNS rebinding defended via IP pinning and connection-time revalidation.
- [x] Redirects capped, validated against SSRF rules at each hop, and stripped of sensitive auth headers across origins.
- [x] Generated rejection reports validated with `Draft202012Validator` against canonical schema `scan_report.schema.json`.

## Security & Privacy Review
- Zero egress on any blocked destination (tested with mock resolvers and socket interceptors).
- Redaction covers query parameters, fragment tokens, and embedded credentials.
- Error messages and limitations are descriptive without disclosing internal infrastructure secrets.

## Known Limitations / Blockers
- None for Phase 01. Phase 01 establishes the strict pre-egress gate.
- Ready for Worker 01 Phase 02 (low-impact passive metadata collectors for DNS and TLS).

## Reviewer / Next Action
- Ready for Worker 02 and Worker 04 to integrate against `IntakeBoundary.evaluate_target` and `IntakeBoundary.build_rejected_report`.
- Hand off to Worker 01 Phase 02 for bounded collectors.
