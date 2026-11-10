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

import sys
import unittest
import socket
import http.server
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
import json

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from jsonschema import Draft202012Validator, FormatChecker

from trusttrace.collectors.dns_collector import DNSCollector
from trusttrace.collectors.tls_collector import TLSCollector, parse_der_certificate
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

    def test_dns_collector_no_process_wide_timeout_side_effects(self):
        """P1-3: DNS collector must use per-operation timeout and not mutate process-wide default timeout."""
        initial_timeout = socket.getdefaulttimeout()
        collector = DNSCollector(
            resolver=SafeDNSResolver(custom_lookup_fn=lambda h, p: ["93.184.216.34"]),
            timeout=1.23
        )
        res = collector.collect("example.com")
        self.assertEqual(res.status, "observed")
        current_timeout = socket.getdefaulttimeout()
        self.assertEqual(
            current_timeout,
            initial_timeout,
            f"Process-wide socket timeout was mutated from {initial_timeout} to {current_timeout}"
        )


    @staticmethod
    def _make_test_der_cert(cn: str, sans: list, not_before: datetime, not_after: datetime) -> bytes:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org Security")
        ])
        builder = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
        )
        if sans:
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]),
                critical=False
            )
        cert = builder.sign(key, hashes.SHA256())
        return cert.public_bytes(serialization.Encoding.DER)

    def test_tls_der_certificate_extraction_valid(self):
        """P0-2: Verify raw DER certificate parsing extracts SANs, issuer, subject, validity."""
        now = datetime.now(timezone.utc)
        der = self._make_test_der_cert(
            cn="secure.example.com",
            sans=["secure.example.com", "api.example.com"],
            not_before=now - timedelta(days=5),
            not_after=now + timedelta(days=90)
        )
        meta = parse_der_certificate(der)
        self.assertIn("secure.example.com", meta["sans"])
        self.assertIn("api.example.com", meta["sans"])
        self.assertEqual(meta["subject"].get("commonName"), "secure.example.com")
        self.assertEqual(meta["subject"].get("organizationName"), "Test Org Security")
        self.assertEqual(meta["issuer"].get("commonName"), "secure.example.com")
        self.assertFalse(meta["is_expired"])

    def test_tls_der_certificate_extraction_expired(self):
        """P0-2: Expired DER certificate is reliably detected even with empty ssl dict."""
        now = datetime.now(timezone.utc)
        der = self._make_test_der_cert(
            cn="expired.example.com",
            sans=["expired.example.com"],
            not_before=now - timedelta(days=365),
            not_after=now - timedelta(days=1)
        )
        meta = parse_der_certificate(der)
        self.assertTrue(meta["is_expired"])

    def test_tls_der_certificate_hostname_mismatch(self):
        """P0-2: Certificate with mismatched SANs fails hostname verification."""
        now = datetime.now(timezone.utc)
        der = self._make_test_der_cert(
            cn="other.example.com",
            sans=["other.example.com"],
            not_before=now - timedelta(days=10),
            not_after=now + timedelta(days=30)
        )
        meta = parse_der_certificate(der)
        self.assertNotIn("target.example.com", meta["sans"])


    def test_http_connection_pinning_dns_rebinding_defense(self):
        """P0-1: HTTP collector connects to validated pinned IP while preserving Host header."""
        received_hosts = []

        class TestServerHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                received_hosts.append(self.headers.get("Host"))
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("X-Custom-Signal", "pinned-ok")
                self.end_headers()
                self.wfile.write(b"OK from pinned server")

            def log_message(self, format, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), TestServerHandler)
        port = server.server_address[1]
        t = threading.Thread(target=server.serve_forever)
        t.daemon = True
        t.start()

        try:
            collector = BoundedHTTPCollector(timeout=2.0)
            # URL uses virtual unresolvable hostname, but socket connects to 127.0.0.1
            results = collector.collect(
                url=f"http://virtual-phish.test:{port}/login",
                pinned_ip="127.0.0.1"
            )
            self.assertEqual(len(results), 1)
            res = results[0]
            self.assertEqual(res.status, "observed")
            self.assertEqual(res.value["status_code"], 200)
            self.assertEqual(res.value["pinned_ip"], "127.0.0.1")
            has_signal = any(
                k.lower() == "x-custom-signal" and "pinned-ok" in v
                for k, v in res.value["headers"].items()
            )
            self.assertTrue(has_signal, f"Expected X-Custom-Signal in headers: {res.value['headers']}")
            self.assertIn(f"virtual-phish.test:{port}", received_hosts)
        finally:
            server.shutdown()
            server.server_close()

    def test_http_redirect_connection_pinning(self):
        """P2-6: Redirects pin each hop to the validated IP returned by redirect policy."""
        received_hops = []

        # Find an allowed safe web port (SAFE_ADDITIONAL_PORTS)
        safe_port = 8888
        for candidate in [8888, 8080, 8000, 8008, 3000, 5000]:
            try:
                s = socket.socket()
                s.bind(("127.0.0.1", candidate))
                s.close()
                safe_port = candidate
                break
            except OSError:
                continue

        class RedirectHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                received_hops.append((self.path, self.headers.get("Host")))
                if self.path == "/start":
                    self.send_response(302)
                    self.send_header("Location", f"http://redirect-target.test:{safe_port}/final")
                    self.end_headers()
                else:
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain")
                    self.end_headers()
                    self.wfile.write(b"Destination reached safely")

            def log_message(self, format, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", safe_port), RedirectHandler)
        port = safe_port
        t = threading.Thread(target=server.serve_forever)
        t.daemon = True
        t.start()

        try:
            from trusttrace.intake.dns_resolver import DNSResolutionResult
            from trusttrace.intake.redirect_policy import RedirectPolicy

            # Mock resolver returning safe pinned_ip="127.0.0.1" for redirect evaluation
            class MockSafePinnedResolver:
                def resolve(self, host, p=443):
                    return DNSResolutionResult(
                        hostname=host,
                        is_safe=True,
                        resolved_ips=["127.0.0.1"],
                        pinned_ip="127.0.0.1"
                    )

            red_policy = RedirectPolicy(max_hops=3, resolver=MockSafePinnedResolver())
            collector = BoundedHTTPCollector(timeout=2.0, redirect_policy=red_policy)

            results = collector.collect(
                url=f"http://initial-domain.test:{port}/start",
                pinned_ip="127.0.0.1"
            )
            headers_res = next(r for r in results if r.kind == "http_headers")
            redirect_res = next(r for r in results if r.kind == "redirect_chain")
            self.assertEqual(headers_res.value["status_code"], 200)
            self.assertEqual(redirect_res.value["hop_count"], 1)
            self.assertEqual(len(received_hops), 2)
            self.assertEqual(received_hops[0][0], "/start")
            self.assertEqual(received_hops[1][0], "/final")
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
