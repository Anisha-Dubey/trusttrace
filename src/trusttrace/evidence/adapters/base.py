"""Abstract base interface and protocol for Evidence Providers."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

from ..domain.models import EvidenceModel, CoverageModel


@dataclass
class EvidenceBatch:
    """A collection of normalized evidence items for a given scan."""
    scan_id: str
    items: List[EvidenceModel]
    metadata: Dict[str, Any] = field(default_factory=dict)
    limitations: List[str] = field(default_factory=list)
    suggested_coverage: Optional[CoverageModel] = None


class EvidenceProvider(ABC):
    """Protocol defining external or internal evidence sources."""

    @abstractmethod
    def get_provider_name(self) -> str:
        """Return the unique provider name."""
        pass

    @abstractmethod
    def fetch_evidence(self, scan_id: str) -> EvidenceBatch:
        """Fetch or generate an evidence batch for the given scan_id."""
        pass
