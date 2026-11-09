"""Unit tests for safe redirect handling policy.

Covers cases:
- REDIR-001: Public host redirects to prohibited address -> blocked before subsequent egress
- REDIR-002: Redirect loop or excessive hops -> capped with explicit limit reason
- REDIR-003: HTTPS redirects to unsupported scheme -> blocked with explicit limitation
"""

import sys
import unittest
from pathlib import Path

# Ensure src is in sys.path when running standalone
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from trusttrace.intake.dns_resolver import SafeDNSResolver
from trusttrace.intake.redirect_policy import RedirectPolicy


class TestRedirectBoundary(unittest.TestCase):

    def setUp(self):
        mock_dns = {
            "public-site.test": ["93.184.216.34"],
            "internal-vault.test": ["10.0.0.5"],
            "another-public.test": ["198.51.100.1"]  # In real life documentation network, but let's test specific
        }
        self.resolver = SafeDNSResolver(custom_lookup_fn=lambda host, port: mock_dns.get(host, ["127.0.0.1"]))
        self.policy = RedirectPolicy(max_hops=5, resolver=self.resolver)

    def test_redir_001_redirect_to_prohibited_target(self):
        """REDIR-001: public host redirects to prohibited address -> redirect blocked and scan partial/rejected."""
        # Hop 1: https://public-site.test/ redirects to http://127.0.0.1:8080/admin
        res1 = self.policy.evaluate_hop(
            current_url="https://public-site.test/login",
            redirect_target="http://127.0.0.1:8080/admin",
            current_hop_count=0
        )
        self.assertFalse(res1.is_safe)
        self.assertEqual(res1.rejection_reason, "redirect_loopback_target")
        self.assertIn("prohibited target", res1.limitations[0])

        # Hop 2: redirects to internal host resolving to 10.0.0.5
        res2 = self.policy.evaluate_hop(
            current_url="https://public-site.test/login",
            redirect_target="https://internal-vault.test/secret",
            current_hop_count=0
        )
        self.assertFalse(res2.is_safe)
        self.assertEqual(res2.rejection_reason, "redirect_private_network_target")

    def test_redir_002_excessive_redirect_hops(self):
        """REDIR-002: redirect loop or excessive hops -> stops at configured cap with reason."""
        current_url = "https://public-site.test/step1"
        for hop in range(1, 6):
            res = self.policy.evaluate_hop(
                current_url=current_url,
                redirect_target=f"/step{hop+1}",
                current_hop_count=hop - 1
            )
            self.assertTrue(res.is_safe)
            current_url = res.target_url

        # Hop 6 exceeds max_hops=5
        overflow_res = self.policy.evaluate_hop(
            current_url=current_url,
            redirect_target="/step7",
            current_hop_count=5
        )
        self.assertFalse(overflow_res.is_safe)
        self.assertEqual(overflow_res.rejection_reason, "excessive_redirect_hops")
        self.assertIn("Redirect limit exceeded", overflow_res.limitations[0])

    def test_redir_003_redirect_to_unsupported_scheme(self):
        """REDIR-003: HTTPS redirects to unsupported scheme -> blocked with explicit limitation."""
        dangerous_targets = [
            "javascript:stealCookie()",
            "data:text/html,<script>evil()</script>",
            "file:///etc/hosts",
            "ftp://files.example.com/",
        ]
        for target in dangerous_targets:
            res = self.policy.evaluate_hop(
                current_url="https://public-site.test/index",
                redirect_target=target,
                current_hop_count=0
            )
            self.assertFalse(res.is_safe, f"Target {target} should be blocked")
            self.assertEqual(res.rejection_reason, "redirect_unsupported_scheme")
            self.assertIn("prohibited", res.limitations[0])

    def test_sensitive_header_stripping_on_cross_origin_redirect(self):
        """Verify Authorization/Cookie headers are stripped when origin changes across redirect."""
        headers = {
            "Authorization": "Bearer super-secret-token",
            "Cookie": "session_id=12345",
            "Accept": "text/html",
            "User-Agent": "TrustTrace-Scanner/1.0"
        }
        filtered = self.policy.filter_headers_for_redirect(
            source_url="https://auth.example.com/oauth",
            destination_url="https://other-domain.org/callback",
            headers=headers
        )
        self.assertNotIn("Authorization", filtered)
        self.assertNotIn("Cookie", filtered)
        self.assertIn("Accept", filtered)
        self.assertIn("User-Agent", filtered)


if __name__ == "__main__":
    unittest.main()

