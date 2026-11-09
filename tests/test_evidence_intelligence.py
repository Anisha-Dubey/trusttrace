"""Tests for Worker 02 Evidence Intelligence, Persistence, and Linkage."""

import unittest
from datetime import datetime, timezone
from pydantic import ValidationError

from trusttrace.evidence.persistence.database import DatabaseManager
from trusttrace.evidence.persistence.repository import EvidenceRepository
from trusttrace.evidence.services.evidence_service import EvidenceService
from trusttrace.evidence.services.provenance import ProvenanceEngine, ReferentialIntegrityError
from trusttrace.evidence.domain.models import EvidenceModel, FindingModel, CoverageModel
from trusttrace.evidence.domain.enums import (
    EvidenceStatus,
    Reliability,
    FindingSeverity,
)


class TestEvidenceIntelligence(unittest.TestCase):
    """Unit and integration tests for evidence ingestion, persistence, and integrity."""

    def setUp(self):
        # Use an isolated in-memory SQLite database for each test
        self.db = DatabaseManager("sqlite:///:memory:")
        self.repo = EvidenceRepository(db_manager=self.db)
        self.repo.init_tables()
        self.service = EvidenceService(repository=self.repo, db_manager=self.db)
        self.provenance_engine = ProvenanceEngine(db_manager=self.db)

    def test_valid_evidence_ingestion_and_retrieval(self):
        """Verify valid evidence record can be ingested, persisted, and retrieved."""
        payload = {
            "evidence_id": "ev-test-001",
            "kind": "tls_hostname_validation",
            "value": {"subject_alt_names": ["example.test"], "valid": True},
            "source": "tls_inspector",
            "source_type": "internal_collector",
            "observed_at": "2026-11-09T10:00:00Z",
            "status": "observed",
            "reliability": "direct_observation",
            "limitations": ["Valid TLS does not verify organizational identity."],
        }
        model, was_created = self.service.ingest_single_observation("scan-001", payload)
        self.assertTrue(was_created)
        self.assertEqual(model.evidence_id, "ev-test-001")
        self.assertEqual(model.status, EvidenceStatus.OBSERVED)
        self.assertEqual(model.reliability, Reliability.DIRECT_OBSERVATION)

        # Retrieve by scan
        with self.db.session_scope() as session:
            ev_list = self.repo.get_evidence_by_scan(session, "scan-001")
            self.assertEqual(len(ev_list), 1)
            self.assertEqual(ev_list[0].evidence_id, "ev-test-001")

        # Retrieve by ID
        with self.db.session_scope() as session:
            fetched = self.repo.get_evidence_by_id(session, "ev-test-001")
            self.assertIsNotNone(fetched)
            self.assertEqual(fetched.kind, "tls_hostname_validation")

    def test_missing_required_fields_rejection(self):
        """Verify rejection when required fields like kind, source, or status are missing."""
        # Missing kind
        with self.assertRaises((ValidationError, KeyError)):
            self.service.ingest_single_observation(
                "scan-002",
                {
                    "source": "dns",
                    "observed_at": "2026-11-09T10:00:00Z",
                    "status": "observed",
                },
            )

        # Missing status
        with self.assertRaises((ValidationError, ValueError)):
            self.service.ingest_single_observation(
                "scan-002",
                {
                    "kind": "dns_lookup",
                    "source": "dns",
                    "observed_at": "2026-11-09T10:00:00Z",
                },
            )

    def test_invalid_timestamps_rejection(self):
        """Verify invalid timestamp formats are rejected."""
        with self.assertRaises(ValueError):
            EvidenceModel(
                evidence_id="ev-bad-time",
                kind="dns",
                source="test",
                observed_at="invalid-date-string",
                status=EvidenceStatus.OBSERVED,
            )

    def test_unknown_schema_version_rejection(self):
        """Verify unknown schema version is rejected at ingestion."""
        with self.assertRaises(ValueError):
            self.service.ingest_single_observation(
                "scan-003",
                {
                    "kind": "dns",
                    "source": "dns",
                    "observed_at": "2026-11-09T10:00:00Z",
                    "status": "observed",
                    "schema_version": "9.9",
                },
            )

    def test_duplicate_ingestion_idempotency(self):
        """Verify duplicate ingestion returns existing record without creating duplicate rows."""
        payload = {
            "evidence_id": "ev-idempotent-001",
            "kind": "dns_lookup",
            "value": {"ips": ["93.184.216.34"]},
            "source": "resolver",
            "observed_at": "2026-11-09T10:00:00Z",
            "status": "observed",
        }
        model1, created1 = self.service.ingest_single_observation("scan-dup", payload)
        self.assertTrue(created1)

        # Ingest again with same payload
        model2, created2 = self.service.ingest_single_observation("scan-dup", payload)
        self.assertFalse(created2)
        self.assertEqual(model1.evidence_id, model2.evidence_id)

        # Verify only 1 record in database
        with self.db.session_scope() as session:
            records = self.repo.get_evidence_by_scan(session, "scan-dup")
            self.assertEqual(len(records), 1)

    def test_all_five_evidence_states(self):
        """Verify handling of observed, unavailable, failed, not_run, and blocked states."""
        states = [
            EvidenceStatus.OBSERVED,
            EvidenceStatus.UNAVAILABLE,
            EvidenceStatus.FAILED,
            EvidenceStatus.NOT_RUN,
            EvidenceStatus.BLOCKED,
        ]
        for idx, st in enumerate(states):
            payload = {
                "evidence_id": f"ev-st-{idx}",
                "kind": f"check_{st.value}",
                "source": "test_collector",
                "observed_at": "2026-11-09T10:00:00Z",
                "status": st.value,
            }
            model, created = self.service.ingest_single_observation(f"scan-state-{idx}", payload)
            self.assertTrue(created)
            self.assertEqual(model.status, st)

    def test_coverage_arithmetic_invariant(self):
        """Enforce checks_total == checks_observed + checks_failed + checks_not_run."""
        # Valid coverage
        cov = CoverageModel(
            checks_total=4,
            checks_observed=2,
            checks_failed=1,
            checks_not_run=1,
        )
        self.assertEqual(cov.checks_total, 4)

        # Invalid coverage sum must raise ValidationError
        with self.assertRaises(ValidationError):
            CoverageModel(
                checks_total=4,
                checks_observed=3,
                checks_failed=2,
                checks_not_run=0,  # 3 + 2 = 5 != 4
            )

        # Dynamic calculation test
        items = [
            EvidenceModel(
                evidence_id="ev-1",
                kind="k1",
                source="s",
                observed_at="2026-11-09T10:00:00Z",
                status=EvidenceStatus.OBSERVED,
            ),
            EvidenceModel(
                evidence_id="ev-2",
                kind="k2",
                source="s",
                observed_at="2026-11-09T10:00:00Z",
                status=EvidenceStatus.FAILED,
            ),
            EvidenceModel(
                evidence_id="ev-3",
                kind="k3",
                source="s",
                observed_at="2026-11-09T10:00:00Z",
                status=EvidenceStatus.BLOCKED,
            ),
        ]
        computed = self.service.calculate_coverage(items, expected_total_checks=4)
        self.assertEqual(computed.checks_total, 4)
        self.assertEqual(computed.checks_observed, 1)
        self.assertEqual(computed.checks_failed, 1)
        self.assertEqual(computed.checks_not_run, 2)  # 1 blocked + 1 unexecuted check
        self.assertEqual(
            computed.checks_total,
            computed.checks_observed + computed.checks_failed + computed.checks_not_run,
        )

    def test_evidence_to_finding_linkage_and_orphan_rejection(self):
        """Verify finding references valid evidence and rejects orphan evidence IDs."""
        # Ingest supporting evidence
        self.service.ingest_single_observation(
            "scan-link",
            {
                "evidence_id": "ev-support-001",
                "kind": "tls_check",
                "source": "tls_inspector",
                "observed_at": "2026-11-09T10:00:00Z",
                "status": "observed",
            },
        )

        # Valid finding
        finding = self.service.add_finding(
            "scan-link",
            {
                "finding_id": "f-link-001",
                "kind": "tls_status",
                "severity": "info",
                "summary": "Valid certificate observed",
                "evidence_ids": ["ev-support-001"],
                "rule_id": "rule-tls-01",
                "rule_version": "1.0",
            },
        )
        self.assertEqual(finding.finding_id, "f-link-001")
        self.assertEqual(finding.evidence_ids, ["ev-support-001"])

        # Orphan reference (evidence_id does not exist)
        with self.assertRaises(ValueError) as ctx:
            self.service.add_finding(
                "scan-link",
                {
                    "finding_id": "f-orphan-001",
                    "kind": "tls_status",
                    "severity": "high",
                    "summary": "Dangling reference finding",
                    "evidence_ids": ["ev-non-existent-999"],
                    "rule_id": "rule-tls-01",
                    "rule_version": "1.0",
                },
            )
        self.assertIn("Referential integrity violation", str(ctx.exception))

    def test_provenance_freshness_and_source_attribution(self):
        """Verify provenance analysis accurately tracks sources, latency, and freshness."""
        ev = EvidenceModel(
            evidence_id="ev-prov-001",
            scan_id="scan-prov",
            kind="tls_hostname_validation",
            source="fixture_adapter",
            source_type="fixture",
            observed_at="2026-11-09T09:00:00Z",
            ingested_at="2026-11-09T09:00:02Z",
            status=EvidenceStatus.OBSERVED,
            reliability=Reliability.DIRECT_OBSERVATION,
            limitations=["Fixture evidence"],
        )
        prov = self.provenance_engine.analyze_provenance(ev)
        self.assertEqual(prov.latency_seconds, 2.0)
        self.assertTrue(prov.is_fixture)
        self.assertEqual(prov.reliability, "direct_observation")
        self.assertEqual(prov.freshness_state, "fresh")

    def test_historical_observation_preservation(self):
        """Verify multiple observations for domain/scan are preserved chronologically."""
        # Observation 1 at T1
        payload1 = {
            "evidence_id": "ev-hist-001",
            "kind": "dns_lookup",
            "value": {"ip": "1.1.1.1"},
            "source": "dns",
            "observed_at": "2026-11-09T08:00:00Z",
            "status": "observed",
        }
        # Observation 2 at T2 with different IP
        payload2 = {
            "evidence_id": "ev-hist-002",
            "kind": "dns_lookup",
            "value": {"ip": "1.1.1.2"},
            "source": "dns",
            "observed_at": "2026-11-09T09:00:00Z",
            "status": "observed",
        }

        self.service.ingest_single_observation("scan-hist", payload1)
        self.service.ingest_single_observation("scan-hist", payload2)

        with self.db.session_scope() as session:
            history = self.repo.get_evidence_by_scan(session, "scan-hist")
            self.assertEqual(len(history), 2)
            # Ensure both exist and were not overwritten
            ids = {h.evidence_id for h in history}
            self.assertEqual(ids, {"ev-hist-001", "ev-hist-002"})


if __name__ == "__main__":
    unittest.main()
