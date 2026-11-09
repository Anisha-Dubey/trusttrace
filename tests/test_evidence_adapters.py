"""Tests for Worker 02 Adapters and Worker 01 Decoupling."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from trusttrace.evidence.persistence.database import DatabaseManager
from trusttrace.evidence.services.evidence_service import EvidenceService
from trusttrace.evidence.adapters.fixture_adapter import FixtureEvidenceAdapter
from trusttrace.evidence.adapters.worker01_adapter import Worker01EvidenceAdapter
from trusttrace.evidence.domain.enums import EvidenceStatus


class TestEvidenceAdapters(unittest.TestCase):
    """Verify adapter boundary, decoupling, and fixture consumption."""

    def setUp(self):
        self.db = DatabaseManager("sqlite:///:memory:")
        self.service = EvidenceService(db_manager=self.db)

    def test_fixture_adapter_works_without_worker_01(self):
        """Verify FixtureEvidenceAdapter loads deterministic fixtures independently."""
        adapter = FixtureEvidenceAdapter()
        self.assertEqual(adapter.get_provider_name(), "fixture_adapter")

        # Load complete report fixture
        batch_complete = adapter.fetch_evidence("fixture-complete-001")
        self.assertEqual(batch_complete.scan_id, "fixture-complete-001")
        self.assertEqual(len(batch_complete.items), 1)
        self.assertEqual(batch_complete.items[0].evidence_id, "ev-tls-001")
        self.assertTrue(any("fixture" in lim.lower() for lim in batch_complete.items[0].limitations))

        # Ingest into service
        res = self.service.ingest_batch(batch_complete)
        self.assertEqual(res.inserted_count, 1)

        # Load partial report fixture
        batch_partial = adapter.fetch_evidence("fixture-partial-001")
        self.assertEqual(batch_partial.items[0].status, EvidenceStatus.FAILED)
        res_partial = self.service.ingest_batch(batch_partial)
        self.assertEqual(res_partial.inserted_count, 1)

        # Load rejected report fixture
        batch_rejected = adapter.fetch_evidence("fixture-rejected-001")
        self.assertEqual(batch_rejected.items[0].status, EvidenceStatus.BLOCKED)
        res_rejected = self.service.ingest_batch(batch_rejected)
        self.assertEqual(res_rejected.inserted_count, 1)

    def test_worker01_adapter_accepts_valid_contract_payloads(self):
        """Verify Worker01EvidenceAdapter translates intake results into EvidenceBatches."""
        adapter = Worker01EvidenceAdapter()
        simulated_w01_output = {
            "submitted_url_redacted": "http://127.0.0.1/",
            "normalized_host": "127.0.0.1",
            "status": "rejected",
            "decision": "rejected",
            "evidence": [
                {
                    "evidence_id": "ev-target-block-001",
                    "kind": "target_policy",
                    "value": {"reason": "loopback_target"},
                    "source": "url_safety_policy",
                    "observed_at": "2026-11-09T09:15:00Z",
                    "status": "blocked",
                    "reliability": "direct_observation",
                    "limitations": ["No network request was made."],
                }
            ],
            "limitations": ["Loopback target rejected before network access."],
        }
        batch = adapter.adapt_payload("scan-w01-001", simulated_w01_output)
        self.assertEqual(batch.scan_id, "scan-w01-001")
        self.assertEqual(len(batch.items), 1)
        item = batch.items[0]
        self.assertEqual(item.status, EvidenceStatus.BLOCKED)
        self.assertEqual(item.kind, "target_policy")
        self.assertEqual(item.source_type, "worker_01_intake")

        res = self.service.ingest_batch(batch)
        self.assertEqual(res.inserted_count, 1)

    def test_worker01_adapter_handles_partial_and_failure_states(self):
        """Verify Worker01EvidenceAdapter safely handles missing, unavailable, or failed observations."""
        adapter = Worker01EvidenceAdapter()
        failing_payload = {
            "submitted_url_redacted": "https://failing.example.test/",
            "status": "failed",
            "evidence": [
                {
                    "evidence_id": "ev-fail-001",
                    "kind": "dns_lookup",
                    "value": None,
                    "source": "dns_collector",
                    "status": "failed",
                    "limitations": ["DNS timeout."],
                },
                {
                    "evidence_id": "ev-unavail-001",
                    "kind": "tls_hostname_validation",
                    "value": None,
                    "source": "tls_collector",
                    "status": "unavailable",
                    "limitations": ["Could not connect to host."],
                },
            ],
        }
        batch = adapter.adapt_payload("scan-fail-001", failing_payload)
        self.assertEqual(len(batch.items), 2)
        statuses = {item.status for item in batch.items}
        self.assertEqual(statuses, {EvidenceStatus.FAILED, EvidenceStatus.UNAVAILABLE})

        res = self.service.ingest_batch(batch)
        self.assertEqual(res.inserted_count, 2)
        self.assertEqual(res.coverage.checks_failed, 1)
        self.assertEqual(res.coverage.checks_not_run, 3)  # 1 unavailable + 2 unexecuted

    def test_no_worker01_internal_modules_imported_in_worker02(self):
        """Crucial Architectural Boundary Test: Worker 02 must NOT import Worker 01 internal modules."""
        evidence_dir = Path(__file__).resolve().parents[1] / "src/trusttrace/evidence"
        prohibited_modules = [
            "trusttrace.intake.dns_resolver",
            "trusttrace.intake.ip_classifier",
            "trusttrace.intake.redirect_policy",
            "trusttrace.intake.boundary",
        ]

        violations = []
        for py_file in evidence_dir.rglob("*.py"):
            content = py_file.read_text(encoding="utf-8")
            for mod in prohibited_modules:
                if mod in content or f"from {mod}" in content or f"import {mod}" in content:
                    violations.append((str(py_file), mod))

        self.assertEqual(
            violations,
            [],
            f"Worker 02 violates architectural isolation by importing Worker 01 internal modules: {violations}",
        )


if __name__ == "__main__":
    unittest.main()
