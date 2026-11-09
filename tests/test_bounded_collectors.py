"""Unit and integration tests for Bounded Collectors & Partial-Result Semantics (Worker 01 Phase 02).

Covers cases:
- LIMIT-001: Timeout budget enforcement and graceful partial result
- LIMIT-002: Bounded body/header response cap
- LIMIT-003: Rate and concurrency limits on burst submissions
- LIMIT-004: In-flight scan cancellation
- TLS-001: Valid TLS certificate marks certificate=valid_for_hostname, identity=unverified
- TLS-002: Certificate expiry/mismatch is technical warning; not proof of phishing
- EVID-001: Partial/inconclusive report when a collector fails
"""

import unittest
from pathlib import Path
import json
from jsonschema import Draft202012Validator, FormatChecker

from trusttrace.collectors.dns_collector import DNSCollector
from trusttrace.collectors.tls_collector import TLSCollector
from trusttrace.collectors.http_collector import BoundedHTTPCollector
from trusttrace.collectors.rate_limiter import RateLimiter
from trusttrace.collectors.orchestrator import ScanOrchestrator, CancellationToken
from trusttrace.intake.boundary import IntakeBoundary
from trusttrace.intake.dns_resolver import SafeDNSResolver


class TestBoundedCollectors(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]
        schema_path = cls.root / ".brain/.work/contracts/v1/scan_report.schema.json"
        schema_data = json.loads(schema_path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema_data)
        cls.report_validator = Draft202012Validator(schema_data, format_checker=FormatChecker())

    def test_limit_001_timeout_budget_and_partial_result(self):
        """LIMIT-001: Slow response -> timeout within configured budget and partial result."""
        # Mock TLS collector that simulates timeout
        mock_tls = TLSCollector(
            timeout=1.5,
            mock_cert_fn=lambda h, p: {"simulate_timeout": True}
        )
        mock_dns = DNSCollector(
            mock_lookup_fn=lambda h: {"value": {"resolved_ips": ["93.184.216.34"]}}
        )
        mock_http = BoundedHTTPCollector(
            mock_http_fn=lambda u: {
                "headers_value": {"status_code": 200, "headers": {"Server": "MockServer"}},
                "redirect_value": {"chain": [u], "hop_count": 0}
            }
        )
        mock_resolver = SafeDNSResolver(custom_lookup_fn=lambda h, p: ["93.184.216.34"])
        boundary = IntakeBoundary(resolver=mock_resolver)

        orchestrator = ScanOrchestrator(
            intake_boundary=boundary,
            dns_collector=mock_dns,
            tls_collector=mock_tls,
            http_collector=mock_http
        )

        report = orchestrator.run_scan("https://slow-tls.example.test/")

        # Verify schema
        errors = list(self.report_validator.iter_errors(report))
        self.assertEqual(len(errors), 0, f"Schema error: {errors}")

        # EVID-001 & LIMIT-001 invariants
        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["decision"], "inconclusive")
        self.assertEqual(report["coverage"]["checks_failed"], 1)
        self.assertGreater(report["coverage"]["checks_observed"], 0)
        self.assertEqual(
            report["coverage"]["checks_total"],
            report["coverage"]["checks_observed"] + report["coverage"]["checks_failed"] + report["coverage"]["checks_not_run"]
        )
        self.assertTrue(any("timed out" in lim.lower() or "timeout" in lim.lower() for lim in report["limitations"]))

    def test_limit_002_oversized_response_capped(self):
        """LIMIT-002: Oversized response -> body capped; no unbounded allocation."""
        max_bytes = 1024  # 1 KB for test
        mock_http = BoundedHTTPCollector(
            max_bytes=max_bytes,
            mock_http_fn=lambda u: {"simulate_oversized": True, "headers": {"Content-Length": "50000000"}}
        )

        results = mock_http.collect("https://oversized.example.test/bigfile.bin")
        self.assertEqual(len(results), 1)
        res = results[0]
        self.assertEqual(res.kind, "http_headers")
        self.assertEqual(res.value["bytes_read"], max_bytes)
        self.assertTrue(res.value["body_truncated"])
        self.assertIn("truncated at 1024 bytes ceiling", res.limitations[0])

    def test_limit_003_rate_and_concurrency_limits(self):
        """LIMIT-003: Burst submissions -> rate/concurrency cap enforced."""
        limiter = RateLimiter(max_requests=3, window_seconds=60.0, max_concurrency=2)
        client_id = "test-client"

        # First 2 acquire slots: OK
        ok1, _ = limiter.acquire(client_id)
        ok2, _ = limiter.acquire(client_id)
        self.assertTrue(ok1)
        self.assertTrue(ok2)

        # 3rd acquire hits concurrency limit
        ok3, reason3 = limiter.acquire(client_id)
        self.assertFalse(ok3)
        self.assertIn("concurrency_limit_exceeded", reason3)

        # Release one concurrency slot
        limiter.release(client_id)

        # 3rd request now passes concurrency, hits total 3 requests
        ok3_retry, _ = limiter.acquire(client_id)
        self.assertTrue(ok3_retry)

        # 4th request exceeds rate limit of 3
        limiter.release(client_id)
        ok4, reason4 = limiter.acquire(client_id)
        self.assertFalse(ok4)
        self.assertIn("rate_limit_exceeded", reason4)

        # Verify orchestrator builds valid rejected report for rate limit
        orchestrator = ScanOrchestrator(rate_limiter=limiter)
        report = orchestrator.run_scan("https://example.com/", client_id=client_id)
        self.assertEqual(report["status"], "rejected")
        errors = list(self.report_validator.iter_errors(report))
        self.assertEqual(len(errors), 0, f"Schema error: {errors}")

    def test_limit_004_cancel_in_flight_scan(self):
        """LIMIT-004: Cancel in-flight scan -> worker stops and state is truthful."""
        cancel_token = CancellationToken()
        cancel_token.cancel()  # Pre-cancelled

        mock_resolver = SafeDNSResolver(custom_lookup_fn=lambda h, p: ["93.184.216.34"])
        boundary = IntakeBoundary(resolver=mock_resolver)
        orchestrator = ScanOrchestrator(intake_boundary=boundary)

        report = orchestrator.run_scan("https://example.com/", cancel_token=cancel_token)
        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["decision"], "inconclusive")
        self.assertTrue(any("cancelled" in lim.lower() for lim in report["limitations"]))
        errors = list(self.report_validator.iter_errors(report))
        self.assertEqual(len(errors), 0, f"Schema error: {errors}")

    def test_tls_001_valid_cert_unverified_identity(self):
        """TLS-001: Valid hostname certificate -> certificate valid_for_hostname; identity remains unverified absent authorization."""
        mock_tls = TLSCollector(
            mock_cert_fn=lambda h, p: {
                "value": {
                    "is_valid": True,
                    "hostname_match": True,
                    "is_expired": False,
                    "sans": ["example.test", "www.example.test"]
                },
                "limitations": ["Valid TLS certificate verifies channel encryption only; it does not prove organizational legitimacy."]
            }
        )
        mock_dns = DNSCollector(
            mock_lookup_fn=lambda h: {"value": {"resolved_ips": ["93.184.216.34"]}}
        )
        mock_http = BoundedHTTPCollector(
            mock_http_fn=lambda u: {
                "headers_value": {"status_code": 200, "headers": {"Strict-Transport-Security": "max-age=31536000"}}
            }
        )
        mock_resolver = SafeDNSResolver(custom_lookup_fn=lambda h, p: ["93.184.216.34"])
        boundary = IntakeBoundary(resolver=mock_resolver)

        orchestrator = ScanOrchestrator(
            intake_boundary=boundary,
            dns_collector=mock_dns,
            tls_collector=mock_tls,
            http_collector=mock_http
        )

        report = orchestrator.run_scan("https://example.test/")
        self.assertEqual(report["status"], "completed")
        self.assertEqual(report["dimensions"]["certificate"], "valid_for_hostname")
        # Invariant TLS-001 check: Identity must NOT be "supported" purely from TLS!
        self.assertEqual(report["dimensions"]["identity"], "unverified")
        self.assertEqual(report["decision"], "no_threat_observed")

        errors = list(self.report_validator.iter_errors(report))
        self.assertEqual(len(errors), 0, f"Schema error: {errors}")

    def test_tls_002_certificate_technical_error_not_sole_proof(self):
        """TLS-002: Expired or hostname-mismatched certificate -> technical warning; not sole proof of phishing."""
        mock_tls = TLSCollector(
            mock_cert_fn=lambda h, p: {
                "value": {
                    "is_valid": False,
                    "hostname_match": False,
                    "is_expired": True,
                    "sans": ["other-host.test"]
                },
                "limitations": ["TLS technical anomaly (certificate is expired, hostname mismatch); technical failure is not sole proof of malicious activity."]
            }
        )
        mock_dns = DNSCollector(
            mock_lookup_fn=lambda h: {"value": {"resolved_ips": ["93.184.216.34"]}}
        )
        mock_http = BoundedHTTPCollector(
            mock_http_fn=lambda u: {
                "headers_value": {"status_code": 200, "headers": {}}
            }
        )
        mock_resolver = SafeDNSResolver(custom_lookup_fn=lambda h, p: ["93.184.216.34"])
        boundary = IntakeBoundary(resolver=mock_resolver)

        orchestrator = ScanOrchestrator(
            intake_boundary=boundary,
            dns_collector=mock_dns,
            tls_collector=mock_tls,
            http_collector=mock_http
        )

        report = orchestrator.run_scan("https://mismatched.example.test/")
        self.assertEqual(report["dimensions"]["certificate"], "invalid_or_expired")
        # Ensure it does not falsely declare high_risk without malicious evidence
        self.assertNotEqual(report["decision"], "high_risk")

        errors = list(self.report_validator.iter_errors(report))
        self.assertEqual(len(errors), 0, f"Schema error: {errors}")


if __name__ == "__main__":
    unittest.main()
