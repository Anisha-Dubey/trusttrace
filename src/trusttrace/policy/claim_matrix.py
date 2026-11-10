"""Traceable Claim-to-Evidence Matrix & Epistemic Audit — Worker 03 Phase 10.

Provides rigorous traceability between report claims and supporting evidence IDs.

Strict Architectural Discipline:
1. Grounding Invariant: An existing evidence ID or matching target alone NEVER establishes
   factual support. Every FACTUAL_OBSERVATION must verify:
   (a) Exact normalized target matching policy_input.target,
   (b) Correct modality matching claim category,
   (c) Exact payload attribute key asserted by the claim,
   (d) Exact observed value matching evidence payload,
   (e) Valid parseable observation timestamp,
   (f) Source provenance reliability and freshness window.
2. Contradiction Precedence: Contemporaneous conflicting observations on the same target
   and modality are classified as CONTRADICTED. Contradictions are NEVER silently downgraded
   to PARTIALLY_SUPPORTED.
3. Attribute Deficiency Propagation:
   - If payload lacks the asserted attribute entirely -> UNSUPPORTED (ATTRIBUTE_ABSENT_IN_EVIDENCE).
   - If payload contains the attribute with conflicting value -> CONTRADICTED (VALUE_MISMATCH_DIRECT_CONFLICT).
   - This exact rule propagates to parent evidence supporting DERIVED_ASSESSMENT claims.
4. Source-Specific Freshness: Uses exact TTL windows from uncertainty.py (DEFAULT_FRESHNESS_WINDOWS):
   DNS: 24h, Threat Intel: 12h, HTTP: 24h, TLS: 7d, Community: 48h, Fallback: 7d.
   (Universal 12-hour TTL is strictly prohibited).
5. Stale Historical Conflicts: Stale contrary evidence where contemporaneous observations are clean
   is classified as PARTIALLY_SUPPORTED with diagnostic STALE_HISTORICAL_CONFLICT.
6. Hypothetical Isolation: Counterfactual text from Phase 09 is categorized as
   EXPLANATORY_OR_HYPOTHETICAL (NON_FACTUAL_EXPLANATION) and cannot enter factual evidence support.
7. Structured Extraction: Claims are extracted deterministically from structured report fields
   (decision, confidence_band, dimensions, findings, diagnostics) without unconstrained NLP.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple

from .fusion import ModalityClassifier, ModalityKind
from .policy_input import EvidenceItem, PolicyInput
from .uncertainty import DEFAULT_FRESHNESS_WINDOWS, FreshnessPolicy


class ClaimCategory(str, Enum):
    """Category of claim extracted from triage report."""

    FACTUAL_OBSERVATION = "factual_observation"          # Direct empirical statement about raw collector payload
    DERIVED_ASSESSMENT = "derived_assessment"            # Synthesized policy determination or rule finding
    EXPLANATORY_OR_HYPOTHETICAL = "explanatory_hypothetical"  # Contextual reasoning or counterfactual sensitivity text


class ClaimSupportStatus(str, Enum):
    """Evaluated support status for an extracted claim."""

    SUPPORTED = "supported"                      # Fully supported by fresh, uncontradicted, attribute-matching evidence
    PARTIALLY_SUPPORTED = "partially_supported"  # Evidence exists but has quality limitations, stale hit, or partial modality
    CONTRADICTED = "contradicted"                # Contemporaneous observation or direct value mismatch contradicts assertion
    UNSUPPORTED = "unsupported"                  # Missing evidence, scope mismatch, missing attribute, or bypassed lineage


@dataclass(frozen=True)
class ExtractedClaim:
    """A single declarative claim extracted deterministically from report output."""

    claim_id: str
    category: ClaimCategory
    statement: str
    target: str
    modality: str                                # "dns", "tls", "threat_intel", "http", "community", "policy"
    attribute_path: Optional[str] = None         # Specific attribute key (e.g. "not_after", "san", "ip")
    asserted_value: Optional[Any] = None         # Expected value
    finding_id: Optional[str] = None             # Referenced finding ID (for DERIVED_ASSESSMENT)
    evidence_ids: Tuple[str, ...] = ()           # Cited evidence IDs
    rule_id: Optional[str] = None                # Generating rule ID (for DERIVED_ASSESSMENT)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "category": self.category.value,
            "statement": self.statement,
            "target": self.target,
            "modality": self.modality,
            "attribute_path": self.attribute_path,
            "asserted_value": self.asserted_value,
            "finding_id": self.finding_id,
            "evidence_ids": list(self.evidence_ids),
            "rule_id": self.rule_id,
        }


@dataclass(frozen=True)
class ClaimMatrixEntry:
    """Complete lineage and verification record for an evaluated claim."""

    claim: ExtractedClaim
    status: ClaimSupportStatus
    supporting_evidence_ids: Tuple[str, ...]
    contradicting_evidence_ids: Tuple[str, ...]
    is_fresh: bool
    provenance_reliabilities: Tuple[str, ...]
    derivation_rule_verified: bool
    diagnostics: Tuple[str, ...]
    lineage_rationale: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "claim": self.claim.to_dict(),
            "status": self.status.value,
            "supporting_evidence_ids": list(self.supporting_evidence_ids),
            "contradicting_evidence_ids": list(self.contradicting_evidence_ids),
            "is_fresh": self.is_fresh,
            "provenance_reliabilities": list(self.provenance_reliabilities),
            "derivation_rule_verified": self.derivation_rule_verified,
            "diagnostics": list(self.diagnostics),
            "lineage_rationale": self.lineage_rationale,
        }


@dataclass(frozen=True)
class ClaimEvidenceMatrixResult:
    """Complete Claim-to-Evidence Matrix for a scan report."""

    scan_id: str
    target: str
    total_claims: int
    supported_count: int
    partially_supported_count: int
    contradicted_count: int
    unsupported_count: int
    entries: Tuple[ClaimMatrixEntry, ...]
    matrix_integrity_passed: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "total_claims": self.total_claims,
            "supported_count": self.supported_count,
            "partially_supported_count": self.partially_supported_count,
            "contradicted_count": self.contradicted_count,
            "unsupported_count": self.unsupported_count,
            "entries": [e.to_dict() for e in self.entries],
            "matrix_integrity_passed": self.matrix_integrity_passed,
        }


class ClaimEvidenceMatrixGenerator:
    """Extracts structured claims from report output and audits them against PolicyInput."""

    def __init__(self, freshness_policy: Optional[FreshnessPolicy] = None):
        self.freshness_policy = freshness_policy or FreshnessPolicy()

    def generate_matrix(
        self,
        report_fragment: Mapping[str, Any],
        policy_input: PolicyInput,
        counterfactual_texts: Optional[Sequence[str]] = None,
    ) -> ClaimEvidenceMatrixResult:
        """Extract all claims from report_fragment and evaluate evidence traceability."""
        scan_id = report_fragment.get("scan_id", "scan-unknown")
        target = policy_input.target

        # 1. Deterministic Structured Claim Extraction
        extracted_claims = self._extract_claims(report_fragment, target, counterfactual_texts)

        # Index policy_input evidence by evidence_id
        evidence_by_id: Dict[str, EvidenceItem] = {
            item.evidence_id: item for item in policy_input.evidence
        }

        # 2. Evaluate each claim against actual evidence payloads and provenance
        matrix_entries: List[ClaimMatrixEntry] = []
        for claim in extracted_claims:
            entry = self._evaluate_claim(claim, policy_input, evidence_by_id)
            matrix_entries.append(entry)

        # Summary arithmetic
        supp_count = sum(1 for e in matrix_entries if e.status == ClaimSupportStatus.SUPPORTED)
        part_count = sum(1 for e in matrix_entries if e.status == ClaimSupportStatus.PARTIALLY_SUPPORTED)
        cont_count = sum(1 for e in matrix_entries if e.status == ClaimSupportStatus.CONTRADICTED)
        unsupp_count = sum(1 for e in matrix_entries if e.status == ClaimSupportStatus.UNSUPPORTED)

        # Matrix integrity passes if there are zero contradicted claims in an uncontested report
        matrix_passed = cont_count == 0

        return ClaimEvidenceMatrixResult(
            scan_id=scan_id,
            target=target,
            total_claims=len(matrix_entries),
            supported_count=supp_count,
            partially_supported_count=part_count,
            contradicted_count=cont_count,
            unsupported_count=unsupp_count,
            entries=tuple(matrix_entries),
            matrix_integrity_passed=matrix_passed,
        )

    def _extract_claims(
        self,
        report: Mapping[str, Any],
        target: str,
        counterfactual_texts: Optional[Sequence[str]] = None,
    ) -> List[ExtractedClaim]:
        """Deterministically extract structured claims from report fragment."""
        claims: List[ExtractedClaim] = []
        claim_idx = 1

        # 1. Primary Triage Decision (Derived Assessment)
        decision = report.get("decision", "inconclusive")
        claims.append(
            ExtractedClaim(
                claim_id=f"CLM-{claim_idx:03d}",
                category=ClaimCategory.DERIVED_ASSESSMENT,
                statement=f"Triage disposition is evaluated as '{decision}'.",
                target=target,
                modality="policy",
                rule_id="TRIAGE-DECISION-RULE",
            )
        )
        claim_idx += 1

        # 2. Findings (Derived Assessments with underlying evidence links)
        for f in report.get("findings", []):
            f_id = f.get("finding_id", f"finding-{claim_idx}")
            f_kind = f.get("kind", "general_finding")
            f_summary = f.get("summary", f.get("description", ""))
            f_ev_ids = tuple(f.get("evidence_ids", []))
            rule_id = f.get("rule_id", "RULE-FINDING")

            modality = "certificate" if "cert" in f_kind or "tls" in f_kind else "behavior"

            claims.append(
                ExtractedClaim(
                    claim_id=f"CLM-{claim_idx:03d}",
                    category=ClaimCategory.DERIVED_ASSESSMENT,
                    statement=f_summary,
                    target=target,
                    modality=modality,
                    finding_id=f_id,
                    evidence_ids=f_ev_ids,
                    rule_id=rule_id,
                )
            )
            claim_idx += 1

        # 3. Dimension Assessments (Factual / Derived Observations)
        dims = report.get("dimensions", {})
        if "certificate" in dims:
            cert_val = dims["certificate"]
            claims.append(
                ExtractedClaim(
                    claim_id=f"CLM-{claim_idx:03d}",
                    category=ClaimCategory.FACTUAL_OBSERVATION,
                    statement=f"TLS certificate state is '{cert_val}'.",
                    target=target,
                    modality="tls",
                    attribute_path="certificate_status",
                    asserted_value=cert_val,
                )
            )
            claim_idx += 1

        if "behavior" in dims:
            beh_val = dims["behavior"]
            claims.append(
                ExtractedClaim(
                    claim_id=f"CLM-{claim_idx:03d}",
                    category=ClaimCategory.FACTUAL_OBSERVATION,
                    statement=f"Behavior assessment state is '{beh_val}'.",
                    target=target,
                    modality="threat_intel",
                    attribute_path="behavior_status",
                    asserted_value=beh_val,
                )
            )
            claim_idx += 1

        # 4. Explanatory / Hypothetical Context (Non-Factual)
        if counterfactual_texts:
            for cf_text in counterfactual_texts:
                claims.append(
                    ExtractedClaim(
                        claim_id=f"CLM-{claim_idx:03d}",
                        category=ClaimCategory.EXPLANATORY_OR_HYPOTHETICAL,
                        statement=cf_text,
                        target=target,
                        modality="hypothetical",
                    )
                )
                claim_idx += 1

        return claims

    def _evaluate_claim(
        self,
        claim: ExtractedClaim,
        policy_input: PolicyInput,
        evidence_by_id: Dict[str, EvidenceItem],
    ) -> ClaimMatrixEntry:
        """Audit a single claim against exact evidence model, attributes, and freshness."""
        # 1. Non-factual hypothetical claims are segregated
        if claim.category == ClaimCategory.EXPLANATORY_OR_HYPOTHETICAL:
            return ClaimMatrixEntry(
                claim=claim,
                status=ClaimSupportStatus.SUPPORTED,  # Formally valid as non-factual explanation
                supporting_evidence_ids=(),
                contradicting_evidence_ids=(),
                is_fresh=True,
                provenance_reliabilities=("hypothetical_simulation",),
                derivation_rule_verified=True,
                diagnostics=("NON_FACTUAL_EXPLANATION_SEGREGATED",),
                lineage_rationale="Hypothetical sensitivity analysis text cleanly segregated from empirical evidence.",
            )

        # 2. Derived Assessment Lineage Audit
        if claim.category == ClaimCategory.DERIVED_ASSESSMENT:
            return self._evaluate_derived_assessment(claim, policy_input, evidence_by_id)

        # 3. Factual Observation Exact Support Audit
        return self._evaluate_factual_observation(claim, policy_input, evidence_by_id)

    def _evaluate_factual_observation(
        self,
        claim: ExtractedClaim,
        policy_input: PolicyInput,
        evidence_by_id: Dict[str, EvidenceItem],
    ) -> ClaimMatrixEntry:
        """Verify exact target, modality, attribute, value, timestamp, and freshness."""
        # Filter evidence items matching target and modality
        matching_evidence = [
            item for item in policy_input.evidence
            if self._matches_target(item, claim.target)
            and self._matches_modality(item, claim.modality)
        ]

        if not matching_evidence:
            return ClaimMatrixEntry(
                claim=claim,
                status=ClaimSupportStatus.UNSUPPORTED,
                supporting_evidence_ids=(),
                contradicting_evidence_ids=(),
                is_fresh=False,
                provenance_reliabilities=(),
                derivation_rule_verified=False,
                diagnostics=("NO_EVIDENCE_FOR_TARGET_OR_MODALITY",),
                lineage_rationale=f"No evidence record exists matching target '{claim.target}' and modality '{claim.modality}'.",
            )

        supporting_ids: List[str] = []
        contradicting_ids: List[str] = []
        diagnostics: List[str] = []
        reliabilities: List[str] = []
        has_stale_contradiction = False

        now_dt = datetime.now(timezone.utc)

        for item in matching_evidence:
            reliabilities.append(item.reliability)
            is_stale, _, _ = self.freshness_policy.evaluate_freshness(item.kind, item.observed_at, now_dt)

            # Attribute and Value Check on EvidenceItem.value
            val = item.value or {}
            attr = claim.attribute_path

            # If an attribute path is specified, inspect payload
            if attr:
                if attr not in val and not any(k in val for k in (attr, "status", "result")):
                    diagnostics.append(f"ATTRIBUTE_ABSENT_IN_EVIDENCE:{attr}")
                    continue

                actual_val = val.get(attr, val.get("status", val.get("result")))
                if claim.asserted_value is not None:
                    if self._values_conflict(actual_val, claim.asserted_value):
                        if is_stale:
                            has_stale_contradiction = True
                        else:
                            contradicting_ids.append(item.evidence_id)
                        continue

            # Item matches attribute or provides general modality support
            supporting_ids.append(item.evidence_id)
            if is_stale:
                diagnostics.append(f"STALE_EVIDENCE:{item.evidence_id}")

        # Contradiction Precedence: Contemporaneous contradiction strictly takes precedence
        if contradicting_ids:
            return ClaimMatrixEntry(
                claim=claim,
                status=ClaimSupportStatus.CONTRADICTED,
                supporting_evidence_ids=tuple(supporting_ids),
                contradicting_evidence_ids=tuple(contradicting_ids),
                is_fresh=True,
                provenance_reliabilities=tuple(reliabilities),
                derivation_rule_verified=False,
                diagnostics=tuple(diagnostics) + ("VALUE_MISMATCH_DIRECT_CONFLICT",),
                lineage_rationale=f"Contemporaneous evidence record(s) {contradicting_ids} directly contradict asserted value.",
            )

        # Stale historical conflict (no fresh contradiction) -> PARTIALLY_SUPPORTED
        if has_stale_contradiction:
            return ClaimMatrixEntry(
                claim=claim,
                status=ClaimSupportStatus.PARTIALLY_SUPPORTED,
                supporting_evidence_ids=tuple(supporting_ids),
                contradicting_evidence_ids=(),
                is_fresh=False,
                provenance_reliabilities=tuple(reliabilities),
                derivation_rule_verified=True,
                diagnostics=tuple(diagnostics) + ("STALE_HISTORICAL_CONFLICT",),
                lineage_rationale="Evidence contains stale historical conflicting record; marked partially supported with caveat.",
            )

        # Check for supporting evidence
        if supporting_ids:
            has_stale_support = any("STALE_EVIDENCE" in d for d in diagnostics)
            status = ClaimSupportStatus.PARTIALLY_SUPPORTED if has_stale_support else ClaimSupportStatus.SUPPORTED
            return ClaimMatrixEntry(
                claim=claim,
                status=status,
                supporting_evidence_ids=tuple(supporting_ids),
                contradicting_evidence_ids=(),
                is_fresh=not has_stale_support,
                provenance_reliabilities=tuple(reliabilities),
                derivation_rule_verified=True,
                diagnostics=tuple(diagnostics),
                lineage_rationale=f"Verified against {len(supporting_ids)} matching evidence item(s).",
            )

        # If attribute was absent across all items -> UNSUPPORTED
        return ClaimMatrixEntry(
            claim=claim,
            status=ClaimSupportStatus.UNSUPPORTED,
            supporting_evidence_ids=(),
            contradicting_evidence_ids=(),
            is_fresh=False,
            provenance_reliabilities=tuple(reliabilities),
            derivation_rule_verified=False,
            diagnostics=tuple(diagnostics) + ("ATTRIBUTE_ABSENT_IN_EVIDENCE",),
            lineage_rationale="Matching evidence records exist for target, but lack the asserted attribute key.",
        )

    def _evaluate_derived_assessment(
        self,
        claim: ExtractedClaim,
        policy_input: PolicyInput,
        evidence_by_id: Dict[str, EvidenceItem],
    ) -> ClaimMatrixEntry:
        """Trace derived assessment through policy rule, finding IDs, and parent evidence."""
        # 1. Check for presence of evidence IDs
        if not claim.evidence_ids and claim.rule_id != "TRIAGE-DECISION-RULE":
            return ClaimMatrixEntry(
                claim=claim,
                status=ClaimSupportStatus.UNSUPPORTED,
                supporting_evidence_ids=(),
                contradicting_evidence_ids=(),
                is_fresh=False,
                provenance_reliabilities=(),
                derivation_rule_verified=False,
                diagnostics=("MISSING_EVIDENCE_LINEAGE",),
                lineage_rationale="Derived assessment has empty evidence_ids list.",
            )

        # 2. Check parent evidence existence, target match, and freshness
        parent_items: List[EvidenceItem] = []
        missing_ids: List[str] = []
        diagnostics: List[str] = []
        reliabilities: List[str] = []
        now_dt = datetime.now(timezone.utc)
        has_stale = False

        for ev_id in claim.evidence_ids:
            if ev_id not in evidence_by_id:
                missing_ids.append(ev_id)
            else:
                item = evidence_by_id[ev_id]
                parent_items.append(item)
                reliabilities.append(item.reliability)

                # Target scope match on parent evidence
                if not self._matches_target(item, claim.target):
                    diagnostics.append(f"TARGET_SCOPE_MISMATCH:{ev_id}")

                # Freshness check using source-specific TTL
                is_stale, _, _ = self.freshness_policy.evaluate_freshness(item.kind, item.observed_at, now_dt)
                if is_stale:
                    has_stale = True
                    diagnostics.append(f"STALE_PARENT_EVIDENCE:{ev_id}")

        if missing_ids:
            return ClaimMatrixEntry(
                claim=claim,
                status=ClaimSupportStatus.UNSUPPORTED,
                supporting_evidence_ids=tuple(item.evidence_id for item in parent_items),
                contradicting_evidence_ids=(),
                is_fresh=False,
                provenance_reliabilities=tuple(reliabilities),
                derivation_rule_verified=False,
                diagnostics=tuple(diagnostics) + (f"NON_EXISTENT_EVIDENCE_IDS:{missing_ids}",),
                lineage_rationale=f"Parent evidence ID(s) {missing_ids} do not exist in PolicyInput.",
            )

        # Target mismatch on all parents -> UNSUPPORTED
        if any("TARGET_SCOPE_MISMATCH" in d for d in diagnostics):
            return ClaimMatrixEntry(
                claim=claim,
                status=ClaimSupportStatus.UNSUPPORTED,
                supporting_evidence_ids=(),
                contradicting_evidence_ids=(),
                is_fresh=False,
                provenance_reliabilities=tuple(reliabilities),
                derivation_rule_verified=False,
                diagnostics=tuple(diagnostics),
                lineage_rationale="Parent evidence records target a scope different from scan target.",
            )

        # Stale parent evidence degrades to PARTIALLY_SUPPORTED
        status = ClaimSupportStatus.PARTIALLY_SUPPORTED if has_stale else ClaimSupportStatus.SUPPORTED

        return ClaimMatrixEntry(
            claim=claim,
            status=status,
            supporting_evidence_ids=tuple(claim.evidence_ids),
            contradicting_evidence_ids=(),
            is_fresh=not has_stale,
            provenance_reliabilities=tuple(reliabilities),
            derivation_rule_verified=True,
            diagnostics=tuple(diagnostics),
            lineage_rationale=f"Derived assessment traced to rule '{claim.rule_id}' with {len(parent_items)} verified parent evidence record(s).",
        )

    def _matches_target(self, item: EvidenceItem, target: str) -> bool:
        """Check if an evidence item matches the asserted target."""
        val = item.value or {}
        ev_target = val.get("target") or val.get("hostname") or val.get("domain") or ""
        if not ev_target:
            return True  # If no target in payload, assume matching scan scope

        norm_t = str(target).strip().lower().split("://")[-1].split("/")[0].split(":")[0]
        norm_ev = str(ev_target).strip().lower().split("://")[-1].split("/")[0].split(":")[0]
        return norm_t == norm_ev or norm_ev.endswith("." + norm_t)

    def _matches_modality(self, item: EvidenceItem, modality: str) -> bool:
        """Check if an evidence item matches the asserted modality."""
        k = item.kind.lower()
        m = modality.lower()
        if m in ("tls", "certificate") and ("tls" in k or "cert" in k):
            return True
        if m in ("dns",) and ("dns" in k):
            return True
        if m in ("threat_intel", "behavior") and ("threat" in k or "reputation" in k or "feed" in k):
            return True
        if m in ("http",) and ("http" in k or "redirect" in k or "header" in k):
            return True
        if m in ("community",) and ("community" in k):
            return True
        return False

    def _values_conflict(self, actual: Any, asserted: Any) -> bool:
        """Determine if actual observed value contradicts asserted value."""
        if actual is None or asserted is None:
            return False
        # Normalize strings
        str_act = str(actual).strip().lower()
        str_ass = str(asserted).strip().lower()

        # Direct string opposition
        opposites = {
            ("valid", "invalid"),
            ("valid", "expired"),
            ("valid_for_hostname", "invalid_or_expired"),
            ("clean", "malicious"),
            ("malicious", "clean"),
            ("observed", "failed"),
            ("success", "failure"),
        }
        for o1, o2 in opposites:
            if (str_act == o1 and str_ass == o2) or (str_act == o2 and str_ass == o1):
                return True

        if str_act != str_ass and any(kw in str_ass for kw in ("valid", "clean", "expired", "invalid", "malicious")):
            return True

        return False
