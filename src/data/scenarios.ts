import { PassportRecord, CommunityReport } from '../types/triage';

export const CANONICAL_SCENARIOS: Record<string, PassportRecord> = {
  phishing_lookalike: {
    schema_version: "1.0",
    scan_id: "scan-phish-homoglyph-001",
    submitted_url_redacted: "https://bank-secure-lоgin.com",
    normalized_host: "bank-secure-lоgin.com",
    status: "completed",
    decision: "caution",
    policy_version: "w03-v1.0",
    dimensions: {
      identity: "unverified",
      certificate: "valid_for_hostname",
      behavior: "no_threat_observed",
      evidence_quality: "complete"
    },
    coverage: {
      checks_total: 5,
      checks_observed: 4,
      checks_failed: 0,
      checks_not_run: 1
    },
    findings: [
      {
        finding_id: "f-tls-enc-001",
        kind: "tls_encryption_only",
        severity: "caution",
        summary: "Valid DV TLS certificate issued by Let's Encrypt proves transport encryption only, not identity.",
        rule_id: "tls-dv-unverified-identity",
        evidence_ids: ["ev-tls-001"]
      },
      {
        finding_id: "f-idn-002",
        kind: "idn_lookalike_detected",
        severity: "high",
        summary: "Target domain contains Cyrillic homoglyph lookalike character 'о' (U+043E) imitating Latin 'o'.",
        rule_id: "idn-confusable-homoglyph",
        evidence_ids: ["ev-idn-003"]
      }
    ],
    evidence: [
      {
        evidence_id: "ev-tls-001",
        kind: "tls_certificate",
        source: "tls_collector",
        observed_at: "2026-11-10T00:30:00Z",
        status: "observed",
        reliability: "high",
        limitations: ["Valid DV TLS proves transport encryption only, not organizational entity."]
      },
      {
        evidence_id: "ev-rdap-002",
        kind: "rdap_registration",
        source: "rdap_collector",
        observed_at: "2026-11-10T00:30:00Z",
        status: "observed",
        reliability: "medium",
        limitations: ["Privacy guard active; domain registrant is hidden."]
      },
      {
        evidence_id: "ev-idn-003",
        kind: "url_canonicalization",
        source: "url_policy",
        observed_at: "2026-11-10T00:30:00Z",
        status: "observed",
        reliability: "high",
        limitations: ["Unicode confusable homoglyph detected in second-level domain label."]
      },
      {
        evidence_id: "ev-rep-004",
        kind: "reputation_feed",
        source: "threat_intel_feed",
        observed_at: "2026-11-10T00:30:00Z",
        status: "observed",
        reliability: "medium",
        limitations: ["EVID-002: Negative threat match does not imply verified safety."]
      }
    ],
    limitations: [
      "CORE THESIS: Valid DV TLS certificate does NOT verify organizational authenticity.",
      "Zero active browser DOM or JavaScript execution performed."
    ],
    cost_assessment: {
      cost_profile_name: "analyst_triage",
      action_recommendation: "threat",
      optimal_action: "threat",
      disposition_input: "caution",
      availability_status_vector: {
        dns: "observed_complete",
        tls: "observed_complete",
        threat_intel: "observed_complete",
        community: "missing"
      },
      confidence_band: "sufficient_for_scoped_observation",
      review_urgency: "high",
      cost_rationale: "Profile 'analyst_triage': Confusable homoglyph lookalike overrides clean signals to avoid breach penalty C_FN=50.0.",
      worst_case_costs: {
        threat: 10.0,
        inconclusive: 2.0,
        clean: 50.0
      },
      minimum_cost: 2.0
    },
    counterfactual: {
      original_disposition: "caution",
      target_disposition: "no_threat_observed",
      status: "SUCCESS",
      perturbations: [
        {
          rule_name: "threat_feed_delisting",
          action: "replace_signal",
          removed_signals: ["threat_feed_match"],
          added_signals: ["no_threat_match"],
          feasibility: "reputation_dependent",
          cost_weight: 5.0,
          description: "Simulate external third-party delisting from security feed."
        }
      ],
      hamming_distance: 1,
      feasibility_score: 5.0,
      resulting_disposition: "no_threat_observed",
      resulting_findings: [],
      explanation: "Target clean disposition requires 1 feed delisting modification.",
      disclaimer: "Hypothetical scenario based strictly on mathematical decision-boundary sensitivity."
    },
    claim_matrix: {
      scan_id: "scan-phish-homoglyph-001",
      target: "bank-secure-lоgin.com",
      total_claims: 3,
      supported_count: 3,
      partially_supported_count: 0,
      contradicted_count: 0,
      unsupported_count: 0,
      entries: [
        {
          claim: {
            claim_id: "CLM-001",
            category: "derived_assessment",
            statement: "Triage disposition is evaluated as 'caution'.",
            target: "bank-secure-lоgin.com",
            modality: "policy",
            evidence_ids: [],
            rule_id: "TRIAGE-DECISION-RULE"
          },
          status: "supported",
          supporting_evidence_ids: ["ev-tls-001", "ev-idn-003"],
          contradicting_evidence_ids: [],
          is_fresh: true,
          provenance_reliabilities: ["direct_observation"],
          derivation_rule_verified: true,
          diagnostics: [],
          lineage_rationale: "Adjudication derived deterministically through canonical policy rules."
        },
        {
          claim: {
            claim_id: "CLM-002",
            category: "derived_assessment",
            statement: "Target domain contains Cyrillic homoglyph lookalike character 'о' (U+043E) imitating Latin 'o'.",
            target: "bank-secure-lоgin.com",
            modality: "identity",
            finding_id: "f-idn-002",
            evidence_ids: ["ev-idn-003"],
            rule_id: "idn-confusable-homoglyph"
          },
          status: "supported",
          supporting_evidence_ids: ["ev-idn-003"],
          contradicting_evidence_ids: [],
          is_fresh: true,
          provenance_reliabilities: ["direct_observation"],
          derivation_rule_verified: true,
          diagnostics: [],
          lineage_rationale: "Direct observation of Unicode mixed-script confusable in domain label."
        },
        {
          claim: {
            claim_id: "CLM-003",
            category: "derived_assessment",
            statement: "Valid DV TLS certificate issued by Let's Encrypt proves transport encryption only, not identity.",
            target: "bank-secure-lоgin.com",
            modality: "certificate",
            finding_id: "f-tls-enc-001",
            evidence_ids: ["ev-tls-001"],
            rule_id: "tls-dv-unverified-identity"
          },
          status: "supported",
          supporting_evidence_ids: ["ev-tls-001"],
          contradicting_evidence_ids: [],
          is_fresh: true,
          provenance_reliabilities: ["direct_observation"],
          derivation_rule_verified: true,
          diagnostics: [],
          lineage_rationale: "TLS-001 Invariant: Domain-validated cert covers transport cryptography only."
        }
      ],
      matrix_integrity_passed: true
    }
  },

  legitimate: {
    schema_version: "1.0",
    scan_id: "scan-legit-example-002",
    submitted_url_redacted: "https://example.com",
    normalized_host: "example.com",
    status: "completed",
    decision: "no_threat_observed",
    policy_version: "w03-v1.0",
    dimensions: {
      identity: "verified_organization",
      certificate: "valid_for_hostname",
      behavior: "no_threat_observed",
      evidence_quality: "complete"
    },
    coverage: {
      checks_total: 4,
      checks_observed: 4,
      checks_failed: 0,
      checks_not_run: 0
    },
    findings: [
      {
        finding_id: "f-id-001",
        kind: "identity_verified",
        severity: "info",
        summary: "Domain registration and authoritative entity verified through legitimate institutional delegation.",
        rule_id: "identity-entity-verified",
        evidence_ids: ["ev-rdap-001", "ev-tls-002"]
      }
    ],
    evidence: [
      {
        evidence_id: "ev-tls-002",
        kind: "tls_certificate",
        source: "tls_collector",
        observed_at: "2026-11-10T00:30:00Z",
        status: "observed",
        reliability: "high",
        limitations: ["Valid X.509 certificate bound to target hostname."]
      },
      {
        evidence_id: "ev-rdap-001",
        kind: "rdap_registration",
        source: "rdap_collector",
        observed_at: "2026-11-10T00:30:00Z",
        status: "observed",
        reliability: "high",
        limitations: ["Verified institutional organization entity (IANA Benchmark)."]
      }
    ],
    limitations: [
      "Passive trust evaluation only; benign evaluation reflects absence of observed threats."
    ]
  },

  expired_tls: {
    schema_version: "1.0",
    scan_id: "scan-expired-cert-003",
    submitted_url_redacted: "https://legacy-portal.internal-corp.net",
    normalized_host: "legacy-portal.internal-corp.net",
    status: "completed",
    decision: "caution",
    policy_version: "w03-v1.0",
    dimensions: {
      identity: "unverified",
      certificate: "invalid_or_expired",
      behavior: "no_threat_observed",
      evidence_quality: "complete"
    },
    coverage: {
      checks_total: 4,
      checks_observed: 3,
      checks_failed: 1,
      checks_not_run: 0
    },
    findings: [
      {
        finding_id: "f-tls-exp-001",
        kind: "tls_certificate_expired",
        severity: "caution",
        summary: "X.509 certificate expired 5 days ago; browser security warnings active.",
        rule_id: "tls-expired-hygiene-warning",
        evidence_ids: ["ev-tls-exp-01"]
      }
    ],
    evidence: [
      {
        evidence_id: "ev-tls-exp-01",
        kind: "tls_certificate",
        source: "tls_collector",
        observed_at: "2026-11-10T00:30:00Z",
        status: "failed",
        reliability: "high",
        limitations: ["Certificate expired; technical hygiene lapse ≠ malicious intent."]
      }
    ],
    limitations: [
      "TLS-002: Expired certificate alone is an operational failure, not conclusive proof of phishing."
    ]
  },

  conflicting: {
    schema_version: "1.0",
    scan_id: "scan-conflict-dispute-004",
    submitted_url_redacted: "https://disputed-exchange.io",
    normalized_host: "disputed-exchange.io",
    status: "completed",
    decision: "inconclusive",
    policy_version: "w03-v1.0",
    dimensions: {
      identity: "unverified",
      certificate: "valid_for_hostname",
      behavior: "unknown",
      evidence_quality: "partial"
    },
    coverage: {
      checks_total: 5,
      checks_observed: 3,
      checks_failed: 0,
      checks_not_run: 2
    },
    findings: [
      {
        finding_id: "f-conf-001",
        kind: "conflicting_threat_intel",
        severity: "info",
        summary: "Contradictory community claims observed. Policy engine safely abstains to inconclusive.",
        rule_id: "policy-conflict-abstention",
        evidence_ids: ["ev-comm-conflict-01"]
      }
    ],
    evidence: [
      {
        evidence_id: "ev-comm-conflict-01",
        kind: "community_corroboration",
        source: "community_reports",
        observed_at: "2026-11-10T00:30:00Z",
        status: "observed",
        reliability: "low",
        limitations: ["Unverified single reporter; disputed by authoritative maintainers."]
      }
    ],
    limitations: [
      "Contradictory signals prevent authoritative determination; manual investigation recommended."
    ]
  },

  ssrf_blocked: {
    schema_version: "1.0",
    scan_id: "scan-ssrf-metadata-005",
    submitted_url_redacted: "http://169.254.169.254/latest/meta-data",
    normalized_host: "169.254.169.254",
    status: "rejected",
    decision: "rejected",
    policy_version: "w03-v1.0",
    dimensions: {
      identity: "unknown",
      certificate: "not_checked",
      behavior: "unknown",
      evidence_quality: "unavailable"
    },
    coverage: {
      checks_total: 4,
      checks_observed: 0,
      checks_failed: 0,
      checks_not_run: 4
    },
    findings: [],
    evidence: [
      {
        evidence_id: "ev-boundary-block-001",
        kind: "target_policy",
        source: "url_safety_policy",
        observed_at: "2026-11-10T00:30:00Z",
        status: "blocked",
        reliability: "direct_observation",
        limitations: ["Zero network request made. Egress safely halted at intake boundary."]
      }
    ],
    limitations: [
      "SEC-001: Cloud metadata IP (169.254.169.254) blocked by SSRF defense.",
      "Zero egress packets transmitted."
    ]
  }
};

export const INITIAL_COMMUNITY_REPORTS: CommunityReport[] = [
  {
    report_id: "rep-comm-001",
    normalized_domain: "bank-secure-lоgin.com",
    claim_type: "phishing",
    verification_state: "verified",
    independent_source_count: 3,
    note_sanitized: "Credential harvesting form disguised as customer banking login portal with Cyrillic lookalike character.",
    submitted_at: "2026-11-09T22:15:00Z"
  },
  {
    report_id: "rep-comm-002",
    normalized_domain: "disputed-exchange.io",
    claim_type: "brand_impersonation",
    verification_state: "disputed",
    independent_source_count: 1,
    note_sanitized: "Conflicting evidence on whether this is an official decentralized exchange mirror or imitation.",
    submitted_at: "2026-11-10T00:10:00Z"
  },
  {
    report_id: "rep-comm-003",
    normalized_domain: "legacy-portal.internal-corp.net",
    claim_type: "suspicious_activity",
    verification_state: "unverified",
    independent_source_count: 1,
    note_sanitized: "Expired certificate observed during internal portal routine sweep.",
    submitted_at: "2026-11-10T01:05:00Z"
  },
  {
    report_id: "rep-comm-004",
    normalized_domain: "example.com",
    claim_type: "suspicious_activity",
    verification_state: "disputed",
    independent_source_count: 0,
    note_sanitized: "IANA benchmark domain; verified benign entity.",
    submitted_at: "2026-11-08T12:00:00Z"
  }
];

export function escapeHtml(str: string): string {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function evaluateCustomTargetLocally(rawUrl: string): PassportRecord {
  const url = rawUrl.trim();
  if (!url) {
    return buildRejectedReport("https://unknown", "empty_target", "URL must not be empty.");
  }

  // Scheme check
  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    return buildRejectedReport(url, "unsupported_scheme", "Scheme must be http or https.");
  }

  // Embedded credentials check (user:pass@host)
  const afterScheme = url.split("://")[1] || "";
  const authority = afterScheme.split("/")[0] || "";
  if (authority.includes("@")) {
    return buildRejectedReport(url, "embedded_credentials_prohibited", "SEC-002: URLs with embedded credentials prohibited.");
  }

  // Extract host
  const hostPort = authority.toLowerCase();
  const host = hostPort.split(":")[0];

  // SSRF & Loopback check
  const isLoopback = (host === "localhost" || host === "127.0.0.1" || host.startsWith("127."));
  const isMetadata = (host === "169.254.169.254");
  const isPrivateRFC1918 = (
    host.startsWith("10.") ||
    host.startsWith("192.168.") ||
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(host)
  );

  if (isLoopback || isMetadata || isPrivateRFC1918) {
    const reason = isMetadata ? "cloud_metadata_target" : (isLoopback ? "loopback_target" : "rfc1918_private_ip");
    return buildRejectedReport(url, reason, `SEC-001: Target host '${host}' is prohibited by SSRF intake policy.`);
  }

  // Check for homoglyph / Cyrillic in hostname
  const hasCyrillic = /[\u0400-\u04FF]/.test(host);
  if (hasCyrillic) {
    return {
      schema_version: "1.0",
      scan_id: "scan-live-cyrillic-" + Math.floor(Math.random() * 9000 + 1000),
      submitted_url_redacted: url,
      normalized_host: host,
      status: "completed",
      decision: "caution",
      policy_version: "w03-v1.0",
      dimensions: {
        identity: "unverified",
        certificate: "not_checked",
        behavior: "suspicious",
        evidence_quality: "partial"
      },
      coverage: { checks_total: 1, checks_observed: 1, checks_failed: 0, checks_not_run: 0 },
      findings: [
        {
          finding_id: "f-idn-confusable",
          kind: "idn_lookalike_detected",
          severity: "high",
          summary: "IDN homoglyph lookalike character detected in domain name.",
          rule_id: "idn-confusable-homoglyph",
          evidence_ids: ["ev-idn-live"]
        }
      ],
      evidence: [
        {
          evidence_id: "ev-idn-live",
          kind: "url_canonicalization",
          source: "url_policy",
          observed_at: new Date().toISOString(),
          status: "observed",
          reliability: "high",
          limitations: ["Unicode homoglyph spoofing pattern observed."]
        }
      ],
      limitations: [
        "Client-side detection: Cyrillic homoglyph lookalike identified in hostname.",
        "TLS certificate not checked offline; live network probes required for complete telemetry."
      ]
    };
  }

  // Unknown custom target offline fallback:
  // Strictly enforce rules:
  // - Never fabricate evidence, TLS status, coverage, confidence or findings.
  // - For HTTP and unprobed URLs, certificate status must be not_checked.
  // - For unknown custom URLs without sufficient evidence, return inconclusive.
  // - Coverage must count actual executed checks only (1 local syntax check).
  return {
    schema_version: "1.0",
    scan_id: "scan-offline-" + Math.floor(Math.random() * 9000 + 1000),
    submitted_url_redacted: url,
    normalized_host: host,
    status: "partial",
    decision: "inconclusive",
    policy_version: "w03-v1.0",
    dimensions: {
      identity: "unknown",
      certificate: "not_checked",
      behavior: "unknown",
      evidence_quality: "unavailable"
    },
    coverage: { checks_total: 1, checks_observed: 1, checks_failed: 0, checks_not_run: 0 },
    findings: [],
    evidence: [
      {
        evidence_id: "ev-intake-offline",
        kind: "target_policy",
        source: "intake_boundary",
        observed_at: new Date().toISOString(),
        status: "observed",
        reliability: "direct_observation",
        limitations: ["Client-side intake boundary syntax check only; live network probes (DNS, TLS, threat intel) were not executed."]
      }
    ],
    limitations: [
      "Offline / Client-Side Assessment: Zero egress network queries executed.",
      "Disciplined Abstention: Target evaluation is inconclusive due to absence of live DNS, TLS, and threat intelligence evidence.",
      "EVID-002: Negative threat match or absence of evidence does not imply verified safety."
    ]
  };
}

export function buildBackendFailureReport(rawUrl: string, failureReason: string): PassportRecord {
  const url = rawUrl.trim();
  const afterScheme = url.split("://")[1] || url;
  const host = afterScheme.split("/")[0].split(":")[0] || "unresolved-target";
  return {
    schema_version: "1.0",
    scan_id: "scan-err-" + Math.floor(Math.random() * 9000 + 1000),
    submitted_url_redacted: url,
    normalized_host: host,
    status: "partial",
    decision: "inconclusive",
    policy_version: "w03-v1.0",
    dimensions: {
      identity: "unknown",
      certificate: "not_checked",
      behavior: "unknown",
      evidence_quality: "unavailable"
    },
    coverage: {
      checks_total: 4,
      checks_observed: 0,
      checks_failed: 1,
      checks_not_run: 3
    },
    findings: [],
    evidence: [
      {
        evidence_id: "ev-err-backend",
        kind: "target_policy",
        source: "triage_orchestrator",
        observed_at: new Date().toISOString(),
        status: "failed",
        reliability: "direct_observation",
        limitations: [
          `Live backend inspection failed or timed out: ${failureReason}. Live telemetry could not be gathered.`
        ]
      }
    ],
    limitations: [
      `Backend inspection unavailable: ${failureReason}.`,
      "Decision is inconclusive because required live evidence (DNS, TLS, threat intel) could not be retrieved.",
      "EVID-001: Never assume safety upon system failure."
    ]
  };
}

function buildRejectedReport(url: string, reason: string, detail: string): PassportRecord {
  const host = (url.split("://")[1] || url).split("/")[0].split(":")[0];
  return {
    schema_version: "1.0",
    scan_id: "scan-rej-" + Math.floor(Math.random() * 9000 + 1000),
    submitted_url_redacted: url,
    normalized_host: host || "rejected-target",
    status: "rejected",
    decision: "rejected",
    policy_version: "w03-v1.0",
    dimensions: {
      identity: "unknown",
      certificate: "not_checked",
      behavior: "unknown",
      evidence_quality: "unavailable"
    },
    coverage: {
      checks_total: 4,
      checks_observed: 0,
      checks_failed: 0,
      checks_not_run: 4
    },
    findings: [],
    evidence: [
      {
        evidence_id: "ev-block-001",
        kind: "target_policy",
        source: "intake_boundary",
        observed_at: new Date().toISOString(),
        status: "blocked",
        reliability: "direct_observation",
        limitations: [detail, "Zero egress network requests executed."]
      }
    ],
    limitations: [
      `Target rejected at intake boundary: ${reason}.`,
      "Zero egress packets transmitted."
    ]
  };
}
