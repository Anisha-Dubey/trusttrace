import { InvariantDefinition } from '../types/triage';

export const INVARIANTS: InvariantDefinition[] = [
  {
    id: "TLS-001",
    title: "Transport Security ≠ Organizational Identity",
    category: "core",
    summary: "Valid DV TLS certificate proves cryptographic channel encryption only, never institutional legitimacy.",
    description: "Domain Validation (DV) certificates from automated authorities (e.g. Let's Encrypt) only confirm control over DNS or an HTTP challenge at issuance time. Threat actors actively obtain valid TLS certificates for lookalike and homoglyph domains within minutes. Trust triage must decouple transport from entity identity.",
    mathematical_rule: "valid_dv_tls ⇏ verified_organization",
    scenario_target: "phishing_lookalike"
  },
  {
    id: "COV-001",
    title: "Coverage Arithmetic Invariant",
    category: "coverage",
    summary: "checks_total == checks_observed + checks_failed + checks_not_run. Zero unallocated checks permitted.",
    description: "Every verification policy check must be strictly accounted for in the evaluation ledger. No implicit or floating assumptions are allowed. If a check was attempted and timed out, it counts as failed; if bypassed due to intake policy, it is tracked as not_run.",
    mathematical_rule: "C_total = C_observed + C_failed + C_not_run",
    scenario_target: "legitimate"
  },
  {
    id: "SEC-001",
    title: "Zero Egress SSRF & Metadata Guardrail",
    category: "security",
    summary: "RFC1918 private IPs, AWS/GCP cloud metadata (169.254.169.254), and loopback targets are rejected at intake.",
    description: "Before initiating any DNS lookup or TLS handshake, target URLs are parsed at the intake boundary. Any address resolving to local loops, private subnets (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), or cloud metadata services is instantly rejected with 0 outbound network packets.",
    mathematical_rule: "target_ip ∈ (RFC1918 ∪ LinkLocal ∪ Loopback) ⟹ reject(intake_boundary, egress_count=0)",
    scenario_target: "ssrf_blocked"
  },
  {
    id: "SEC-002",
    title: "Embedded Credentials Prohibition",
    category: "security",
    summary: "URLs with embedded userinfo (user:pass@host) are immediately rejected to prevent credential leaks.",
    description: "Phishing kits frequently abuse embedded userinfo to trick users or coerce client scanners into sending stored credentials to an attacker-controlled gateway. TRUSTTRACE treats any URL with an '@' character before the host as an immediate boundary violation.",
    mathematical_rule: "url.has_userinfo == true ⟹ reject(SEC_002)",
    scenario_target: "custom_credentials"
  },
  {
    id: "EVID-002",
    title: "Negative Threat Match ≠ Benign Status",
    category: "evidence",
    summary: "Absence of a blacklist or threat intelligence hit produces no_threat_observed, NOT guaranteed benign.",
    description: "Zero-day phishing campaigns and newly registered attacker domains exist in the wild for hours or days before appearing on public blocklists. TRUSTTRACE explicitly avoids declaring 'safe' or 'benign' solely on the absence of a negative match.",
    mathematical_rule: "feed_match(target) == ∅ ⟹ decision = no_threat_observed ∧ decision ≠ verified_safe",
    scenario_target: "phishing_lookalike"
  },
  {
    id: "SAFE-001",
    title: "Zero Active Browser Risk",
    category: "security",
    summary: "Strictly passive metadata collection. Never executes arbitrary DOM, JavaScript, or flash payloads.",
    description: "Active headless browsers (e.g. Puppeteer/Playwright) expose triage infrastructure to zero-day browser sandbox escapes, drive-by downloads, and client-side fingerprinting. TRUSTTRACE performs isolated protocol handshakes without rendering untrusted web code.",
    mathematical_rule: "dom_execution_depth == 0 ∧ js_engine == disabled",
    scenario_target: "legitimate"
  },
  {
    id: "COMM-001",
    title: "XSS Sanitization & Sybil Resistance",
    category: "community",
    summary: "All analyst submissions are entity-sanitized; repeat reports from single sources do not inflate confidence.",
    description: "Collaborative threat intelligence feeds are vulnerable to poison attacks and spam inflation. Submissions undergo HTML escaping at boundary entry, and corroboration algorithms require distinct authoritative verification before promotion.",
    mathematical_rule: "corroboration_score = count(distinct(authoritative_sources))",
    scenario_target: "conflicting"
  },
  {
    id: "SCH-001",
    title: "Audit Trail Traceability",
    category: "evidence",
    summary: "Every adjudicated finding must link to at least one concrete evidence record ID with source reliability metadata.",
    description: "No finding may appear as an unsubstantiated hallucination. Each finding in the Evidence Passport explicitly binds to an evidence record containing observation timestamp, collector provenance, and technical limitations.",
    mathematical_rule: "∀ finding ∈ Findings: |finding.evidence_ids| ≥ 1 ∧ (finding.evidence_ids ⊆ EvidenceRecords.ids)",
    scenario_target: "legitimate"
  }
];
