"""Worker 01 Evidence Adapter.

Consumes validated observations from Worker 01 via contract payloads WITHOUT
importing any internal Worker 01 network/socket/SSRF modules.
"""

from typing import Dict, Any, List, Optional
import uuid

from .base import EvidenceProvider, EvidenceBatch
from ..domain.models import EvidenceModel, CoverageModel, utc_now_iso
from ..domain.enums import EvidenceStatus, Reliability, normalize_reliability


class Worker01EvidenceAdapter(EvidenceProvider):
    """Translates Worker 01 intake & collector contract payloads into EvidenceBatches."""

    def __init__(self, payload: Optional[Dict[str, Any]] = None):
        """Optionally initialize with a pre-supplied payload or configure as a factory."""
        self._payload = payload

    def get_provider_name(self) -> str:
        return "worker_01_adapter"

    def adapt_payload(self, scan_id: str, payload: Dict[str, Any]) -> EvidenceBatch:
        """Convert a Worker 01 result payload (e.g. rejection report, collector output) to EvidenceBatch."""
        raw_evidence = payload.get("evidence", [])
        evidence_items: List[EvidenceModel] = []

        for item in raw_evidence:
            ev_id = item.get("evidence_id") or f"ev-w01-{uuid.uuid4().hex[:6]}"
            kind = item.get("kind", "unknown_collector")
            value = item.get("value")
            source = item.get("source", "worker_01_intake")
            observed_at = item.get("observed_at") or utc_now_iso()
            status_str = item.get("status", "observed")
            try:
                status = EvidenceStatus(status_str)
            except ValueError:
                status = EvidenceStatus.UNAVAILABLE

            rel_str = item.get("reliability")
            reliability = normalize_reliability(rel_str)

            limitations = list(item.get("limitations", []))

            evidence_items.append(
                EvidenceModel(
                    evidence_id=ev_id,
                    scan_id=scan_id,
                    kind=kind,
                    value=value,
                    source=source,
                    source_type="worker_01_intake",
                    observed_at=observed_at,
                    status=status,
                    reliability=reliability,
                    limitations=limitations,
                    schema_version="1.0",
                )
            )

        # Coverage calculation or extraction
        raw_cov = payload.get("coverage")
        coverage = None
        if raw_cov and isinstance(raw_cov, dict):
            try:
                coverage = CoverageModel(
                    checks_total=raw_cov["checks_total"],
                    checks_observed=raw_cov["checks_observed"],
                    checks_failed=raw_cov["checks_failed"],
                    checks_not_run=raw_cov["checks_not_run"],
                )
            except Exception:
                pass

        metadata = {
            "submitted_url_redacted": payload.get("submitted_url_redacted", ""),
            "normalized_host": payload.get("normalized_host"),
            "status": payload.get("status", "validating"),
            "decision": payload.get("decision", "inconclusive"),
            "policy_version": payload.get("policy_version", "1.0"),
        }

        return EvidenceBatch(
            scan_id=scan_id,
            items=evidence_items,
            metadata=metadata,
            limitations=payload.get("limitations", []),
            suggested_coverage=coverage,
        )

    def fetch_evidence(self, scan_id: str) -> EvidenceBatch:
        """Fetch evidence using the configured payload."""
        if self._payload is None:
            # Return an empty batch if no payload provided yet
            return EvidenceBatch(
                scan_id=scan_id,
                items=[],
                metadata={"status": "not_run"},
                limitations=["No Worker 01 payload configured for adapter."],
            )
        return self.adapt_payload(scan_id, self._payload)
