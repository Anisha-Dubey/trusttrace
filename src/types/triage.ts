export type DecisionType = 'no_threat_observed' | 'caution' | 'inconclusive' | 'rejected' | 'high_risk';

export type IdentityStatus = 'unverified' | 'verified_organization' | 'unknown';
export type CertificateStatus = 'valid_for_hostname' | 'invalid_or_expired' | 'not_checked' | 'unobserved';
export type BehaviorStatus = 'no_threat_observed' | 'suspicious' | 'unknown' | 'unobserved';
export type QualityStatus = 'complete' | 'partial' | 'unavailable';

export interface DimensionState {
  identity: IdentityStatus;
  certificate: CertificateStatus;
  behavior: BehaviorStatus;
  evidence_quality: QualityStatus;
}

export interface CoverageStats {
  checks_total: number;
  checks_observed: number;
  checks_failed: number;
  checks_not_run: number;
}

export interface Finding {
  finding_id: string;
  kind: string;
  severity: 'high' | 'caution' | 'info';
  summary: string;
  rule_id: string;
  evidence_ids: string[];
}

export interface EvidenceRecord {
  evidence_id: string;
  kind: string;
  source: string;
  observed_at: string;
  status: 'observed' | 'failed' | 'blocked' | 'unobserved';
  reliability: 'high' | 'medium' | 'low' | 'direct_observation';
  limitations?: string[];
}

export interface PassportRecord {
  schema_version: string;
  scan_id: string;
  submitted_url_redacted: string;
  normalized_host: string;
  status: 'completed' | 'rejected' | 'in_progress' | 'partial' | 'failed';
  decision: DecisionType;
  policy_version: string;
  dimensions: DimensionState;
  coverage: CoverageStats;
  findings: Finding[];
  evidence: EvidenceRecord[];
  limitations: string[];
  cost_assessment?: CostAssessment;
  counterfactual?: CounterfactualResult;
  claim_matrix?: ClaimEvidenceMatrixResult;
}

export interface CostConfig {
  profile_name: string;
  cost_false_negative: number;
  cost_false_positive: number;
  cost_abstain: number;
  cost_true_positive: number;
  cost_true_negative: number;
  raw_theta_threat?: number;
  raw_theta_clean?: number;
  theta_threat_clamped?: number;
  theta_clean_clamped?: number;
}

export interface MinimaxEvaluation {
  optimal_action: 'threat' | 'clean' | 'inconclusive';
  is_tied: boolean;
  tied_actions: string[];
  worst_case_costs: Record<string, number>;
  minimum_cost: number;
  theta_threat_clamped?: number;
  theta_clean_clamped?: number;
  statistical_calibration_active: boolean;
  rationale: string;
}

export interface CostAssessment {
  cost_profile_name: string;
  action_recommendation: 'threat' | 'clean' | 'inconclusive';
  optimal_action?: 'threat' | 'clean' | 'inconclusive';
  disposition_input: string;
  availability_status_vector: Record<string, string>;
  confidence_band: string;
  review_urgency: 'high' | 'normal' | 'low';
  cost_rationale: string;
  worst_case_costs?: Record<string, number>;
  minimum_cost?: number;
  minimax_evaluation?: MinimaxEvaluation;
}

export interface CounterfactualPerturbation {
  rule_name: string;
  action: 'replace_signal' | 'remove_signal' | 'coordinated_mut';
  removed_signals: string[];
  added_signals: string[];
  feasibility: 'mutable_configuration' | 'reputation_dependent' | 'immutable_intrinsic';
  cost_weight: number;
  description: string;
}

export interface CounterfactualResult {
  original_disposition: string;
  target_disposition: string;
  status: 'SUCCESS' | 'UNREACHABLE' | 'NO_PERTURBATION_NEEDED' | 'INVALID_TARGET';
  perturbations: CounterfactualPerturbation[];
  hamming_distance: number;
  feasibility_score: number | null;
  resulting_disposition: string;
  resulting_findings: string[];
  explanation: string;
  disclaimer: string;
}

export interface EpistemicClaim {
  claim_id: string;
  category: 'factual_observation' | 'derived_assessment' | 'negative_finding' | 'counterfactual_assertion';
  statement: string;
  target: string;
  modality: string;
  attribute_path?: string | null;
  asserted_value?: string | null;
  finding_id?: string | null;
  evidence_ids: string[];
  rule_id?: string | null;
}

export interface ClaimMatrixEntry {
  claim: EpistemicClaim;
  status: 'supported' | 'partially_supported' | 'contradicted' | 'unsupported';
  supporting_evidence_ids: string[];
  contradicting_evidence_ids: string[];
  is_fresh: boolean;
  provenance_reliabilities: string[];
  derivation_rule_verified: boolean;
  diagnostics: string[];
  lineage_rationale: string;
}

export interface ClaimEvidenceMatrixResult {
  scan_id: string;
  target: string;
  total_claims: number;
  supported_count: number;
  partially_supported_count: number;
  contradicted_count: number;
  unsupported_count: number;
  entries: ClaimMatrixEntry[];
  matrix_integrity_passed: boolean;
}

export interface CommunityReport {
  report_id: string;
  normalized_domain: string;
  claim_type: 'phishing' | 'credential_harvesting' | 'brand_impersonation' | 'malware_distribution' | 'suspicious_activity';
  verification_state: 'verified' | 'disputed' | 'unverified';
  independent_source_count: number;
  note_sanitized: string;
  submitted_at: string;
}

export interface InvariantDefinition {
  id: string;
  title: string;
  category: 'core' | 'coverage' | 'security' | 'evidence' | 'community';
  summary: string;
  description: string;
  mathematical_rule?: string;
  scenario_target?: string;
}
