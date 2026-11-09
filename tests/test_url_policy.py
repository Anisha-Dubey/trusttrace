"""Unit tests for URL intake policy.

Covers cases:
- URL-001: Normalization and accepted scheme
- URL-002: Credentials rejection without egress
- URL-003: Sensitive query token redaction
- URL-004: IDNA & Unicode preservation
- URL-005: Unsupported scheme rejection
"""

import unittest
from trusttrace.intake.url_policy import parse_and_validate_url, redact_sensitive_tokens


class TestURLPolicy(unittest.TestCase):

    def test_url_001_normal_https(self):
        """URL-001: https URL with normal hostname -> normalized host and accepted scheme."""
        url = "https://Example.COM:443/path/index.html?param=value."
        res = parse_and_validate_url(url)
        self.assertTrue(res.is_valid)
        self.assertEqual(res.scheme, "https")
        self.assertEqual(res.normalized_host, "example.com")
        self.assertEqual(res.port, 443)
        self.assertFalse(res.is_idna)

    def test_url_002_reject_embedded_credentials(self):
        """URL-002: URL contains username and password -> rejected without network call."""
        urls_with_creds = [
            "https://admin:secretPass123@example.com/dashboard",
            "http://user@evil.test/login",
            "https://user:password@10.0.0.1/",
        ]
        for url in urls_with_creds:
            res = parse_and_validate_url(url)
            self.assertFalse(res.is_valid, f"Expected rejection for {url}")
            self.assertEqual(res.rejection_reason, "credentials_in_url")
            self.assertIn("Credentials embedded in URL are prohibited", res.limitations[0])
            self.assertNotIn("secretPass123", res.submitted_url_redacted)

    def test_url_003_redact_sensitive_query_tokens(self):
        """URL-003: URL query contains token -> token redacted from logs and report export."""
        url = "https://example.org/verify?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9&user_id=42&api_key=SECRET999&next=/home"
        res = parse_and_validate_url(url)
        self.assertTrue(res.is_valid)
        redacted = res.submitted_url_redacted
        self.assertNotIn("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", redacted)
        self.assertNotIn("SECRET999", redacted)
        self.assertIn("user_id=42", redacted)
        self.assertIn("next=%2Fhome", redacted)
        self.assertIn("token=%5BREDACTED%5D", redacted)

    def test_url_004_unicode_idna_confusable(self):
        """URL-004: Unicode confusable hostname -> IDNA and display form preserved as evidence; no malicious verdict from feature alone."""
        # Cyrillic 'а' in google: gооgle.com
        confusable_url = "https://g\u043e\u043egle.com/login"
        res = parse_and_validate_url(confusable_url)
        self.assertTrue(res.is_valid)
        self.assertTrue(res.is_idna)
        self.assertTrue(res.normalized_host.startswith("xn--"))
        self.assertEqual(res.unicode_host, "gооgle.com")
        self.assertTrue(len(res.evidence) > 0)
        self.assertEqual(res.evidence[0]["kind"], "idna_confusable_feature")
        self.assertIn("not treated as malicious by itself", res.evidence[0]["limitations"][0])

    def test_url_005_reject_unsupported_schemes(self):
        """URL-005: unsupported file/javascript/data schemes -> rejected before resolution."""
        unsupported = [
            "javascript:alert(document.domain)",
            "file:///etc/passwd",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
            "ftp://ftp.example.com/file.zip",
            "gopher://gopher.floodgap.com/",
            "ws://socket.example.com/chat",
        ]
        for url in unsupported:
            res = parse_and_validate_url(url)
            self.assertFalse(res.is_valid, f"Expected {url} to be rejected")
            self.assertEqual(res.rejection_reason, "unsupported_scheme")
            self.assertIn("is prohibited", res.limitations[0])


if __name__ == "__main__":
    unittest.main()

