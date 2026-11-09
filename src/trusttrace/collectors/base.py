"""Base Collector Interface and Result Dataclass for Bounded Collectors.

Conforms to scan_report.schema.json evidence specification.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
import uuid


@dataclass
class CollectorResult:
    kind: str
    value: Dict[str, Any]
    source: str
    observed_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    )
    status: str = "observed"  # "observed" | "unavailable" | "failed" | "not_run" | "blocked"
    reliability: str = "direct_observation"  # "direct_observation" | "corroborated" | "unverified_third_party" | "heuristic"
    limitations: List[str] = field(default_factory=list)
    evidence_id: str = field(
        default_factory=lambda: f"ev-{uuid.uuid4().hex[:8]}"
    )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dict matching scan_report.schema.json evidence item."""
        return {
            "evidence_id": self.evidence_id,
            "kind": self.kind,
            "value": self.value,
            "source": self.source,
            "observed_at": self.observed_at,
            "status": self.status,
            "reliability": self.reliability,
            "limitations": self.limitations
        }
