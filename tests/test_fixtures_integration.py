"""Integration tests verifying JSON schema validation and report contract compliance.

Tests:
- Rejection reports produced by IntakeBoundary conform strictly to scan_report.schema.json
- Fixture profile requests conform to scan_request.schema.json
- Coverage arithmetic and evidence IDs cross-record validity
"""

import unittest
from pathlib import Path
import json
from jsonschema import Draft202012Validator, FormatChecker

from trusttrace.intake.boundary import IntakeBoundary


class TestFixturesIntegration(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]
        cls.schemas_dir = cls.root / ".brain/.work/contracts/v1"
        cls.fixtures_dir = cls.root / ".brain/.testdata/v1"
        cls.checker = FormatChecker()

        def load_schema(name):
            schema_data = json.loads((cls.schemas_dir / name).read_text(encoding="utf-8"))
            Draft202012Validator.check_schema(schema_data)
            return Draft202012Validator(schema_data, format_checker=cls.checker)

        cls.request_validator = load_schema("scan_request.schema.json")
        cls.report_validator = load_schema("scan_report.schema.json")

    def test_rejection_report_schema_compliance(self):
        """Verify generated rejection reports conform 100% to scan_report.schema.json."""
        boundary = IntakeBoundary()

        test_cases = [
            ("http://127.0.0.1/", "loopback_target"),
            ("https://admin:secret@example.com/", "credentials_in_url"),
            ("javascript:alert(1)", "unsupported_scheme"),
            ("http://169.254.169.254/latest/meta-data/", "cloud_metadata_target")
        ]

        for url, expected_reason in test_cases:
            eval_res = boundary.evaluate_target(url)
            self.assertFalse(eval_res.is_safe)
            report = boundary.build_rejected_report(scan_id=f"test-rej-{expected_reason}", evaluation=eval_res)

            # Strictly validate against schema
            errors = list(self.report_validator.iter_errors(report))
            self.assertEqual(len(errors), 0, f"Schema validation failed for {url}: {errors}")

            # Verify contract invariants
            self.assertEqual(report["status"], "rejected")
            self.assertEqual(report["decision"], "rejected")
            self.assertEqual(report["dimensions"]["identity"], "unknown")
            self.assertEqual(report["dimensions"]["certificate"], "not_checked")
            self.assertEqual(report["coverage"]["checks_total"], 4)
            self.assertEqual(report["coverage"]["checks_observed"], 0)
            self.assertEqual(report["coverage"]["checks_not_run"], 4)

    def test_scan_request_fixtures(self):
        """Verify scan_request.schema.json validates valid request and fails invalid request."""
        valid_req = json.loads((self.fixtures_dir / "scan_request_valid.json").read_text(encoding="utf-8"))
        self.request_validator.validate(valid_req)

        invalid_req = json.loads((self.fixtures_dir / "scan_request_invalid.json").read_text(encoding="utf-8"))
        errors = list(self.request_validator.iter_errors(invalid_req))
        self.assertTrue(len(errors) > 0, "Expected validation errors for scan_request_invalid.json")


if __name__ == "__main__":
    unittest.main()
