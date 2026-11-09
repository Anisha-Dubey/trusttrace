"""Unit and integration tests for SSRF destination classification and DNS rebinding defense.

Covers cases:
- SSRF-001: Loopback blocked (127.0.0.1 / ::1)
- SSRF-002: RFC1918 IPv4 and IPv6 ULA blocked
- SSRF-003: Link-local and cloud metadata blocked
- SSRF-004: Hostname resolving to prohibited IP blocked before connect
- SSRF-005: DNS rebinding blocked at connection-time revalidation
"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from trusttrace.intake.ip_classifier import classify_ip, IPStatus
from trusttrace.intake.dns_resolver import SafeDNSResolver, DNSResolutionResult
from trusttrace.intake.boundary import IntakeBoundary


class TestSSRFBoundary(unittest.TestCase):

    def test_ssrf_001_loopback_prohibited(self):
        """SSRF-001: 127.0.0.1 / ::1 blocked before connection."""
        loopbacks = ["127.0.0.1", "127.0.1.1", "127.255.255.254", "::1"]
        for ip in loopbacks:
            res = classify_ip(ip)
            self.assertFalse(res.is_safe, f"Loopback {ip} must not be safe")
            self.assertEqual(res.status, IPStatus.LOOPBACK)
            self.assertEqual(res.rejection_reason, "loopback_target")

        # Boundary test on full URL
        boundary = IntakeBoundary()
        url_res = boundary.evaluate_target("http://127.0.0.1:8080/metrics")
        self.assertFalse(url_res.is_safe)
        self.assertEqual(url_res.rejection_reason, "loopback_target")

    def test_ssrf_002_private_rfc1918_and_ipv6_ula(self):
        """SSRF-002: RFC1918 IPv4 / IPv6 ULA blocked before connection."""
        privates = [
            "10.0.0.1", "10.254.12.3",
            "172.16.0.1", "172.31.255.255",
            "192.168.1.1", "192.168.100.254",
            "fc00::1", "fd12:3456:789a:1::1"
        ]
        for ip in privates:
            res = classify_ip(ip)
            self.assertFalse(res.is_safe, f"Private IP {ip} must be blocked")
            self.assertIn(res.status, (IPStatus.PRIVATE_RFC1918, IPStatus.IPV6_ULA))

        boundary = IntakeBoundary()
        for ip in ("10.1.2.3", "192.168.0.50"):
            url_res = boundary.evaluate_target(f"https://{ip}/admin")
            self.assertFalse(url_res.is_safe)
            self.assertEqual(url_res.rejection_reason, "private_network_target")

    def test_ssrf_003_link_local_and_cloud_metadata(self):
        """SSRF-003: link-local and metadata IP ranges blocked before connection."""
        metadata_targets = [
            "169.254.169.254",          # AWS / GCP / Azure IMDS
            "169.254.1.1",              # General link-local
            "fe80::1",                  # IPv6 link-local
            "100.100.100.200",          # Alibaba Cloud metadata
            "fd00:ec2::254"             # AWS IMDSv2 IPv6
        ]
        for target in metadata_targets:
            res = classify_ip(target)
            self.assertFalse(res.is_safe, f"Target {target} must be blocked")
            self.assertIn(res.status, (IPStatus.LINK_LOCAL, IPStatus.CLOUD_METADATA))

        boundary = IntakeBoundary()
        url_res = boundary.evaluate_target("http://169.254.169.254/latest/meta-data/")
        self.assertFalse(url_res.is_safe)
        self.assertEqual(url_res.rejection_reason, "cloud_metadata_target")

    def test_ssrf_004_hostname_resolves_to_prohibited_ip(self):
        """SSRF-004: hostname resolves to prohibited IP -> blocked after resolution before connect."""
        # Mock lookup function where evil-internal.test resolves to 192.168.1.100
        mock_table = {
            "evil-internal.test": ["192.168.1.100"],
            "cloud-meta.test": ["169.254.169.254"],
            "safe-public.test": ["93.184.216.34"],
            "mixed-resolution.test": ["93.184.216.34", "10.0.0.1"]
        }
        mock_resolver = SafeDNSResolver(custom_lookup_fn=lambda host, port: mock_table.get(host, []))
        boundary = IntakeBoundary(resolver=mock_resolver)

        # Case 1: evil-internal.test resolves to private
        res1 = boundary.evaluate_target("https://evil-internal.test/status")
        self.assertFalse(res1.is_safe)
        self.assertEqual(res1.rejection_reason, "private_network_target")

        # Case 2: cloud-meta.test resolves to metadata
        res2 = boundary.evaluate_target("https://cloud-meta.test/credentials")
        self.assertFalse(res2.is_safe)
        self.assertEqual(res2.rejection_reason, "cloud_metadata_target")

        # Case 3: mixed resolution (one public, one private) must block the entire request
        res3 = boundary.evaluate_target("https://mixed-resolution.test/")
        self.assertFalse(res3.is_safe)
        self.assertEqual(res3.rejection_reason, "private_network_target")

        # Case 4: safe public host succeeds
        res4 = boundary.evaluate_target("https://safe-public.test/")
        self.assertTrue(res4.is_safe)

    def test_ssrf_005_dns_rebinding_simulation(self):
        """SSRF-005: public first resolution then prohibited second resolution -> blocked by connection-time validation."""
        # Rebinding simulation: first lookup returns public, second lookup returns loopback
        lookup_counter = 0

        def rebinding_mock(host, port):
            nonlocal lookup_counter
            lookup_counter += 1
            if lookup_counter == 1:
                return ["93.184.216.34"]  # Public IP at phase 1
            else:
                return ["127.0.0.1"]      # Loopback IP at phase 2 (rebinding attempt)

        resolver = SafeDNSResolver(custom_lookup_fn=rebinding_mock)

        # 1. Initial resolution succeeds and pins 93.184.216.34
        init_res = resolver.resolve("rebind.attacker.test")
        self.assertTrue(init_res.is_safe)
        self.assertEqual(init_res.pinned_ip, "93.184.216.34")

        # 2. Connection-time check with attempted second IP 127.0.0.1
        attempted_connect_ip = "127.0.0.1"
        is_allowed = resolver.validate_connection_ip(init_res, attempted_connect_ip)
        self.assertFalse(is_allowed, "Connection-time rebinding to 127.0.0.1 must be rejected")


if __name__ == "__main__":
    unittest.main()

