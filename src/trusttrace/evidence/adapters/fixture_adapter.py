"""Deterministic fixture adapter for Worker 02."""

import json
from pathlib import Path
from typing import Optional, Dict, Any, List

from .base import EvidenceProvider, EvidenceBatch
from ..domain.models import EvidenceModel, CoverageModel
from ..domain.enums import EvidenceStatus, Reliability


class FixtureEvidenceAdapter(EvidenceProvider):
    """Provides deterministic evidence batches from controlled v1 test fixtures."""

    def __init__(self, fixtures_dir: Optional[Path] = None):
        if fixtures_dir is None:
            # Default to repo root / .brain/.testdata/v1
            # Current file is in src/trusttrace/evidence/adapters
            repo_root = Path(__file__).resolve().parents[4]
            fixtures_dir = repo_root / ".brain/.testdata/v1"
        self.fixtures_dir = fixtures_dir

    def get_provider_name(self) -> str:
        return "fixture_adapter"

    def _load_json(self, filename: str) -> Dict[str, Any]:
        path = self.fixtures_dir / filename
        if not path.exists():
            raise FileNotFoundError(f"Fixture file not found: {path}")
        return json.loads(path.read_text(encoding="utf-8"))

    def fetch_evidence(self, scan_id: str) -> EvidenceBatch:
        """Fetch evidence for a known fixture scan ID or default to complete report."""
        filename_map = {
            "fixture-complete-001": "complete_report.json",
            "fixture-partial-001": "partial_report.json",
            "fixture-rejected-001": "rejected_report.json",
        }
        filename = filename_map.get(scan_id, "complete_report.json")
        data = self._load_json(filename)

        evidence_items: List[EvidenceModel] = []
        for raw_ev in data.get("evidence", []):
            reliability_val = raw_ev.get("reliability")
            ev_model = EvidenceModel(
                evidence_id=raw_ev["evidence_id"],
                scan_id=data.get("scan_id", scan_id),
                kind=raw_ev["kind"],
                value=raw_ev.get("value"),
                source=raw_ev["source"],
                source_type="fixture",
                observed_at=raw_ev["observed_at"],
                status=EvidenceStatus(raw_ev["status"]),
                reliability=Reliability(reliability_val) if reliability_val else None,
                limitations=list(raw_ev.get("limitations", [])) + ["Synthetic fixture; demo evidence only."],
                schema_version="1.0",
            )
            evidence_items.append(ev_model)

        raw_cov = data.get("coverage", {})
        coverage = None
        if raw_cov:
            coverage = CoverageModel(
                checks_total=raw_cov["checks_total"],
                checks_observed=raw_cov["checks_observed"],
                checks_failed=raw_cov["checks_failed"],
                checks_not_run=raw_cov["checks_not_run"],
            )

        return EvidenceBatch(
            scan_id=data.get("scan_id", scan_id),
            items=evidence_items,
            metadata={
                "submitted_url_redacted": data.get("submitted_url_redacted"),
                "normalized_host": data.get("normalized_host"),
                "status": data.get("status"),
                "decision": data.get("decision"),
                "policy_version": data.get("policy_version", "demo-v1"),
            },
            limitations=data.get("limitations", []),
            suggested_coverage=coverage,
        )
