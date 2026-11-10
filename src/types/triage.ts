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
  status: 'completed' | 'rejected' | 'in_progress';
  decision: DecisionType;
  policy_version: string;
  dimensions: DimensionState;
  coverage: CoverageStats;
  findings: Finding[];
  evidence: EvidenceRecord[];
  limitations: string[];
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
