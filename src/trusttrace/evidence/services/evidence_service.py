"""Evidence Ingestion, Coverage, and Provenance Service for Worker 02."""

from dataclasses import dataclass, field
import json
from typing import Dict, Any, List, Optional, Tuple, Sequence
import uuid

from ..domain.models import (
    EvidenceModel,
    FindingModel,
    CoverageModel,
    utc_now_iso,
)
from ..domain.enums import (
    EvidenceStatus,
    Reliability,
    normalize_reliability,
    FindingSeverity,
)
from ..adapters.base import EvidenceBatch
from ..persistence.repository import EvidenceRepository
from ..persistence.database import DatabaseManager, default_db
from ...policy.triage_engine import TriageEngine, TriageResult
from ...policy.integrity_auditor import ReportIntegrityAuditor, ReportAuditResult, AuditSeverity
from ...policy.policy_input import PolicyInput


@dataclass
class IngestionResult:
    """Summary of an evidence ingestion run."""
    scan_id: str
    total_received: int
    inserted_count: int
    deduplicated_count: int
    items: List[EvidenceModel] = field(default_factory=list)
    coverage: Optional[CoverageModel] = None


def classify_check_category(kind: str, source: str) -> str:
    """Map evidence kind or source to canonical named collector check categories."""
    k = (kind or "").strip().lower()
    s = (source or "").strip().lower()

    if any(term in k for term in ("intake", "url_policy", "canonical", "ssrf", "target_policy")) or \
       any(term in s for term in ("intake", "url_policy", "ssrf")):
        return "url_intake"

    if any(term in k for term in ("dns", "resolver", "nameserver")) or \
       any(term in s for term in ("dns",)):
        return "dns_resolution"

    if any(term in k for term in ("tls", "ssl", "cert", "cipher")) or \
       any(term in s for term in ("tls", "ssl")):
        return "tls_certificate"

    if any(term in k for term in ("header", "http_status", "response_header")) or \
       any(term in s for term in ("http_header", "bounded_http")):
        return "http_headers"

    if any(term in k for term in ("redirect",)) or \
       any(term in s for term in ("redirect",)):
        return "redirect_chain"

    if k:
        return k
    return s or "unknown_check"


class EvidenceService:
    """Service handling evidence ingestion pipeline, provenance tracking, coverage, and triage integration."""

    def __init__(
        self,
        repository: Optional[EvidenceRepository] = None,
        db_manager: Optional[DatabaseManager] = None,
        triage_engine: Optional[TriageEngine] = None,
        integrity_auditor: Optional[ReportIntegrityAuditor] = None,
    ):
        self.db = db_manager or default_db
        self.repo = repository or EvidenceRepository(db_manager=self.db)
        self.repo.init_tables()
        self.triage_engine = triage_engine if triage_engine is not None else TriageEngine()
        self.integrity_auditor = integrity_auditor if integrity_auditor is not None else (
            self.triage_engine.integrity_auditor if hasattr(self.triage_engine, "integrity_auditor") else ReportIntegrityAuditor()
        )

    def calculate_coverage(
        self,
        evidence_items: List[EvidenceModel],
        expected_total_checks: int = 4,
    ) -> CoverageModel:
        """Calculate coverage metrics distinguishing named collector checks from raw evidence-record count.

        Enforces the mathematical invariant: checks_total == checks_observed + checks_failed + checks_not_run.

        Policy:
        - Groups evidence records by named check category (url_intake, dns_resolution, tls_certificate,
          http_headers, redirect_chain, etc.).
        - Evaluates each named check's composite status:
          * If any record in category is FAILED -> check state is FAILED
          * Else if any record is OBSERVED -> check state is OBSERVED
          * Else if any record is BLOCKED -> check state is BLOCKED
          * Else if any record is UNAVAILABLE -> check state is UNAVAILABLE
          * Else -> check state is NOT_RUN
        - Counts distinct checks observed vs failed vs not_run.
        - If distinct checks evaluated < expected_total_checks (e.g. 4 for standard profile),
          the unexecuted remainder is accounted for in checks_not_run.
        """
        check_categories: Dict[str, List[EvidenceStatus]] = {}
        for ev in evidence_items:
            cat = classify_check_category(ev.kind, ev.source)
            check_categories.setdefault(cat, []).append(ev.status)

        observed = 0
        failed = 0
        not_run = 0

        for cat, statuses in check_categories.items():
            if any(s == EvidenceStatus.FAILED for s in statuses):
                failed += 1
            elif any(s == EvidenceStatus.OBSERVED for s in statuses):
                observed += 1
            else:
                # BLOCKED, UNAVAILABLE, NOT_RUN
                not_run += 1

        total_tracked = observed + failed + not_run
        if total_tracked < expected_total_checks:
            not_run += (expected_total_checks - total_tracked)
            total = expected_total_checks
        else:
            total = total_tracked

        return CoverageModel(
            checks_total=total,
            checks_observed=observed,
            checks_failed=failed,
            checks_not_run=not_run,
        )

    def ingest_batch(self, batch: EvidenceBatch) -> IngestionResult:
        """Execute the transactional evidence ingestion pipeline for a batch.

        1. Ensures scan record exists.
        2. Validates and persists each evidence item idempotently.
        3. Recomputes scan coverage.
        4. Evaluates evidence via Worker 03 TriageEngine:
           - Constructs canonical PolicyInput.from_components().
           - Persists decision, policy version, and updated scan status.
           - Persists generated findings referencing persisted evidence idempotently.
        """
        with self.db.session_scope() as session:
            # Step 1: Ensure scan record exists
            self.repo.ensure_scan(
                session,
                scan_id=batch.scan_id,
                submitted_url_redacted=batch.metadata.get("submitted_url_redacted", "https://unspecified.test/"),
                normalized_host=batch.metadata.get("normalized_host"),
                status=batch.metadata.get("status", "validating"),
                decision=batch.metadata.get("decision", "inconclusive"),
                policy_version=batch.metadata.get("policy_version", "1.0"),
                limitations=batch.limitations,
            )

            inserted = 0
            deduped = 0
            persisted_models: List[EvidenceModel] = []

            # Step 2: Validate and persist each evidence item idempotently
            for item in batch.items:
                model, was_created = self.repo.save_evidence(
                    session=session,
                    scan_id=batch.scan_id,
                    evidence=item,
                )
                persisted_models.append(model)
                if was_created:
                    inserted += 1
                else:
                    deduped += 1

            # Fetch all evidence for this scan (including prior batches)
            all_scan_evidence = self.repo.get_evidence_by_scan(session, batch.scan_id)

            # Step 3: Recompute and update scan coverage
            coverage = batch.suggested_coverage or self.calculate_coverage(all_scan_evidence)
            self.repo.update_scan(
                session,
                scan_id=batch.scan_id,
                coverage=coverage,
            )

            # Step 4: Worker 03 Triage Evaluation & Findings Persistence
            decision = batch.metadata.get("decision", "inconclusive")
            policy_version = batch.metadata.get("policy_version", "1.0")
            merged_limitations = list(batch.limitations)

            if self.triage_engine is not None:
                norm_host = batch.metadata.get("normalized_host")
                community_reports: List[Any] = []
                if norm_host:
                    try:
                        raw_reports = self.repo.get_reports_by_domain(session, norm_host)
                        community_reports = [r.to_v1_contract_dict() for r in raw_reports]
                    except Exception:
                        pass

                try:
                    policy_input = PolicyInput.from_components(
                        scan_id=batch.scan_id,
                        target=norm_host or "target-unspecified",
                        evidence=all_scan_evidence,
                        coverage=coverage,
                        community_reports=community_reports,
                        strict=False,
                    )
                    triage_result = self.triage_engine.evaluate_evidence(policy_input)

                    decision = triage_result.decision
                    policy_version = triage_result.policy_version

                    # Merge triage limitations
                    for lim in triage_result.limitations:
                        if lim not in merged_limitations:
                            merged_limitations.append(lim)

                    # Determine scan status
                    scan_status = "completed"
                    if decision == "inconclusive":
                        scan_status = "partial" if coverage.checks_failed > 0 else "completed"
                    elif decision == "failed":
                        scan_status = "failed"

                    # Persist generated findings idempotently
                    persisted_evidence_ids = {e.evidence_id for e in all_scan_evidence}
                    for f_dict in triage_result.findings:
                        raw_eids = f_dict.get("evidence_ids", [])
                        valid_eids = [eid for eid in raw_eids if eid in persisted_evidence_ids]
                        if not valid_eids:
                            continue

                        severity_val = f_dict.get("severity", "info")
                        try:
                            finding_severity = FindingSeverity(severity_val)
                        except ValueError:
                            finding_severity = FindingSeverity.INFO

                        finding_model = FindingModel(
                            finding_id=f_dict["finding_id"],
                            scan_id=batch.scan_id,
                            kind=f_dict.get("kind", "security_finding"),
                            severity=finding_severity,
                            summary=f_dict.get("summary", ""),
                            evidence_ids=valid_eids,
                            rule_id=f_dict.get("rule_id", "triage_rule"),
                            rule_version=f_dict.get("rule_version", policy_version),
                            created_at=f_dict.get("created_at") or utc_now_iso(),
                            limitations=f_dict.get("limitations", []),
                        )
                        self.repo.save_finding(session, batch.scan_id, finding_model)

                    # Update scan with evaluated decision, policy version, and status
                    self.repo.update_scan(
                        session,
                        scan_id=batch.scan_id,
                        status=scan_status,
                        decision=decision,
                        policy_version=policy_version,
                        completed_at=utc_now_iso(),
                        limitations=merged_limitations,
                    )

                except Exception as ex:
                    # In case of triage engine exception, preserve evidence and record diagnostic
                    merged_limitations.append(f"Triage evaluation error: {str(ex)}")
                    self.repo.update_scan(
                        session,
                        scan_id=batch.scan_id,
                        decision="inconclusive",
                        limitations=merged_limitations,
                    )

            return IngestionResult(
                scan_id=batch.scan_id,
                total_received=len(batch.items),
                inserted_count=inserted,
                deduplicated_count=deduped,
                items=persisted_models,
                coverage=coverage,
            )

    def ingest_single_observation(
        self,
        scan_id: str,
        payload: Dict[str, Any],
    ) -> Tuple[EvidenceModel, bool]:
        """Ingest a single evidence record payload with validation."""
        schema_version = payload.get("schema_version", "1.0")
        if schema_version != "1.0":
            raise ValueError(f"Unsupported schema version: {schema_version}")

        ev_id = payload.get("evidence_id") or f"ev-{uuid.uuid4().hex[:8]}"
        observed_at = payload.get("observed_at") or utc_now_iso()
        
        status_val = payload.get("status")
        if not status_val:
            raise ValueError("Evidence status is required.")
        status = EvidenceStatus(status_val)

        rel_val = payload.get("reliability")
        reliability = normalize_reliability(rel_val)

        model = EvidenceModel(
            evidence_id=ev_id,
            scan_id=scan_id,
            kind=payload["kind"],
            value=payload.get("value"),
            source=payload["source"],
            source_type=payload.get("source_type", "internal_collector"),
            observed_at=observed_at,
            status=status,
            reliability=reliability,
            limitations=payload.get("limitations", []),
            schema_version=schema_version,
        )

        with self.db.session_scope() as session:
            persisted, was_created = self.repo.save_evidence(session, scan_id, model)
            
            # Recalculate coverage
            all_evidence = self.repo.get_evidence_by_scan(session, scan_id)
            cov = self.calculate_coverage(all_evidence)
            self.repo.update_scan(session, scan_id, coverage=cov)

            return persisted, was_created

    def add_finding(self, scan_id: str, finding_payload: Dict[str, Any]) -> FindingModel:
        """Create a finding referencing existing evidence records with referential validation."""
        finding = FindingModel(
            finding_id=finding_payload.get("finding_id") or f"f-{uuid.uuid4().hex[:8]}",
            scan_id=scan_id,
            kind=finding_payload["kind"],
            severity=FindingSeverity(finding_payload["severity"]),
            summary=finding_payload["summary"],
            evidence_ids=finding_payload["evidence_ids"],
            rule_id=finding_payload["rule_id"],
            rule_version=finding_payload["rule_version"],
            created_at=finding_payload.get("created_at") or utc_now_iso(),
            limitations=finding_payload.get("limitations", []),
        )

        with self.db.session_scope() as session:
            return self.repo.save_finding(session, scan_id, finding)

    def audit_scan_report(self, scan_id: str) -> Optional[ReportAuditResult]:
        """Audit a persisted scan report against safety and integrity invariants."""
        report = self.get_scan_report(scan_id, enforce_audit=False)
        if not report:
            return None
        return self.integrity_auditor.audit_report(report)

    def get_scan_report(
        self,
        scan_id: str,
        enforce_audit: bool = True,
        include_audit: bool = False,
    ) -> Optional[Dict[str, Any]]:
        """Assemble a complete report conforming to scan_report.schema.json, audited prior to publication."""
        with self.db.session_scope() as session:
            scan = self.repo.get_scan(session, scan_id)
            if not scan:
                return None

            evidence_items = self.repo.get_evidence_by_scan(session, scan_id)
            findings = self.repo.get_findings_by_scan(session, scan_id)

            coverage = CoverageModel(
                checks_total=scan.coverage_total,
                checks_observed=scan.coverage_observed,
                checks_failed=scan.coverage_failed,
                checks_not_run=scan.coverage_not_run,
            )

            # Determine dimension states or fallback
            has_failed = any(e.status == EvidenceStatus.FAILED for e in evidence_items)
            has_blocked = any(e.status == EvidenceStatus.BLOCKED for e in evidence_items)

            evidence_quality = "unavailable"
            if coverage.checks_observed > 0 and not has_failed:
                evidence_quality = "strong" if coverage.checks_not_run == 0 else "partial"
            elif coverage.checks_observed > 0 and has_failed:
                evidence_quality = "weak"

            certificate_dim = "not_checked"
            for ev in evidence_items:
                if ev.kind == "tls_hostname_validation":
                    certificate_dim = "valid_for_hostname" if ev.status == EvidenceStatus.OBSERVED else "invalid_or_expired"
                elif ev.kind == "tls_certificate" and certificate_dim == "not_checked":
                    certificate_dim = "valid_for_hostname" if ev.status == EvidenceStatus.OBSERVED else "invalid_or_expired"

            identity_dim = "unverified"
            if has_blocked:
                identity_dim = "unknown"

            behavior_dim = "unknown"
            if scan.decision == "no_threat_observed":
                behavior_dim = "no_threat_observed"
            elif scan.decision in ("high_risk", "caution"):
                behavior_dim = "suspicious"

            # Refine dimensions through TriageEngine evaluation if available
            if self.triage_engine is not None:
                try:
                    policy_input = PolicyInput.from_components(
                        scan_id=scan.scan_id,
                        target=scan.normalized_host or "target-unspecified",
                        evidence=evidence_items,
                        coverage=coverage,
                        strict=False,
                    )
                    triage_result = self.triage_engine.evaluate_evidence(policy_input)
                    if triage_result and triage_result.dimensions:
                        identity_dim = triage_result.dimensions.get("identity", identity_dim)
                        certificate_dim = triage_result.dimensions.get("certificate", certificate_dim)
                        behavior_dim = triage_result.dimensions.get("behavior", behavior_dim)
                        evidence_quality = triage_result.dimensions.get("evidence_quality", evidence_quality)
                except Exception:
                    pass

            scan_limitations = json.loads(scan.limitations_json) if scan.limitations_json else []

            # Invariant COV-001: Disclose partial coverage when decision is no_threat_observed
            if (coverage.checks_failed > 0 or coverage.checks_not_run > 0) and scan.decision == "no_threat_observed":
                has_cov_disclosure = any(
                    any(term in lim.lower() for term in ("partial", "not executed", "limited scope", "unexecuted", "failed check"))
                    for lim in scan_limitations
                )
                if not has_cov_disclosure:
                    scan_limitations.append(
                        f"Partial coverage disclosure (INV-COV-001): {coverage.checks_failed} failed and {coverage.checks_not_run} unexecuted checks; scan scope was limited."
                    )

            candidate_report: Dict[str, Any] = {
                "schema_version": "1.0",
                "scan_id": scan.scan_id,
                "submitted_url_redacted": scan.submitted_url_redacted,
                "normalized_host": scan.normalized_host,
                "status": scan.status,
                "decision": scan.decision,
                "created_at": scan.created_at,
                "completed_at": scan.completed_at,
                "policy_version": scan.policy_version,
                "dimensions": {
                    "identity": identity_dim,
                    "certificate": certificate_dim,
                    "behavior": behavior_dim,
                    "evidence_quality": evidence_quality,
                },
                "coverage": coverage.to_v1_contract_dict(),
                "evidence": [e.to_v1_contract_dict() for e in evidence_items],
                "findings": [f.to_v1_contract_dict() for f in findings],
                "limitations": scan_limitations,
            }

            # DEF-04: Report Integrity Pre-Publication Audit
            if enforce_audit and self.integrity_auditor is not None:
                audit_result = self.integrity_auditor.audit_report(candidate_report)
                if not audit_result.is_valid:
                    # Report fails safety invariants: withhold report publication
                    candidate_report["status"] = "withheld"
                    candidate_report["decision"] = "inconclusive"
                    candidate_report["audit_passed"] = False
                    candidate_report["audit_errors"] = [
                        issue.to_dict() for issue in audit_result.issues if issue.severity == AuditSeverity.ERROR
                    ]
                    candidate_report["audit_warnings"] = [
                        issue.to_dict() for issue in audit_result.issues if issue.severity == AuditSeverity.WARNING
                    ]
                    candidate_report["limitations"].append(
                        f"REPORT INTEGRITY AUDIT FAILED ({audit_result.error_count} error violations): Publication withheld."
                    )
                else:
                    if include_audit:
                        candidate_report["audit"] = audit_result.to_dict()

            return candidate_report
