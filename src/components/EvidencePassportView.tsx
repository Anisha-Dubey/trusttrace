import { useState, useRef } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import {
  ShieldCheck,
  AlertTriangle,
  HelpCircle,
  Ban,
  Copy,
  Check,
  FileCode,
  IdCard,
  Lock,
  Activity,
  BarChart3,
  ExternalLink,
  Info
} from 'lucide-react';
import { PassportRecord } from '../types/triage';
import { sound } from '../utils/audio';
import ClaimLineageMatrix from './ClaimLineageMatrix';
import CounterfactualPanel from './CounterfactualPanel';
import CostCalibrationPanel from './CostCalibrationPanel';

interface EvidencePassportViewProps {
  report: PassportRecord;
  showJson: boolean;
  setShowJson: (val: boolean) => void;
  onShowToast: (msg: string) => void;
  onOpenInvariants: () => void;
}

export default function EvidencePassportView({
  report,
  showJson,
  setShowJson,
  onShowToast,
  onOpenInvariants,
}: EvidencePassportViewProps) {
  const [copied, setCopied] = useState(false);
  const [activeTab, setActiveTab] = useState<'findings' | 'evidence' | 'claim_matrix' | 'counterfactual' | 'cost_calibration'>('findings');
  const [severityFilter, setSeverityFilter] = useState<'all' | 'high' | 'caution' | 'info'>('all');
  const jsonRef = useRef<HTMLDivElement>(null);

  const handleCopyJson = () => {
    sound.playClick(650);
    const jsonStr = JSON.stringify(report, null, 2);
    navigator.clipboard.writeText(jsonStr).then(() => {
      setCopied(true);
      onShowToast('Canonical Evidence Passport copied to clipboard');
      setTimeout(() => setCopied(false), 2000);
    });
  };

  const total = report.coverage.checks_total || 1;
  const obsPct = Math.round((report.coverage.checks_observed / total) * 100);
  const failPct = Math.round((report.coverage.checks_failed / total) * 100);
  const notRunPct = Math.max(0, 100 - obsPct - failPct);

  const getDecisionBadge = (decision: string) => {
    switch (decision) {
      case 'no_threat_observed':
        return {
          bg: 'bg-[#f6f6f6] border-[#040404] text-[#040404]',
          label: 'No Threat Observed',
          icon: ShieldCheck,
          sub: 'Transport verified & clean telemetry',
        };
      case 'caution':
        return {
          bg: 'bg-[#f6f6f6] border-[#040404] text-[#040404]',
          label: 'Caution Advised',
          icon: AlertTriangle,
          sub: 'Valid TLS but lookalike homoglyph or unverified identity',
        };
      case 'rejected':
      case 'high_risk':
        return {
          bg: 'bg-[#f6f6f6] border-[#040404] text-[#040404]',
          label: 'Intake Rejected',
          icon: Ban,
          sub: 'Boundary security policy violated (zero egress)',
        };
      default:
        return {
          bg: 'bg-[#f6f6f6] border-[rgb(0_0_0/10%)] text-[#040404]',
          label: 'Inconclusive',
          icon: HelpCircle,
          sub: 'Contradictory intelligence signals',
        };
    }
  };

  const decisionBadge = getDecisionBadge(report.decision);
  const DecisionIcon = decisionBadge.icon;

  const filteredFindings = report.findings.filter((f) =>
    severityFilter === 'all' ? true : f.severity === severityFilter
  );

  return (
    <div className="space-y-12">
      {/* Top Passport Header Card */}
      <div className="handdrawn-card border border-[rgb(0_0_0/10%)] bg-[#ffffff] p-6 sm:p-10 space-y-8 shadow-sm">

        {/* Upper Metadata & Decision Banner */}
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 pb-6 border-b border-[#D9D9D9]">
          <div className="space-y-2">
            <div className="flex items-center gap-3 text-xs font-mono text-[#6B6B6B]">
              <span className="px-3 py-1 rounded-full bg-[#040404] text-white text-[10px] font-mono font-bold tracking-wider">
                EVIDENCE PASSPORT
              </span>
              <span aria-hidden="true" className="text-[#CDCDCD]">/</span>
              <span>policy: {report.policy_version}</span>
              <span aria-hidden="true" className="text-[#CDCDCD]">/</span>
              <span className="text-[#040404] font-bold">schema v{report.schema_version}</span>
            </div>

            <div className="text-2xl sm:text-4xl font-serif text-[#040404] break-all tracking-tight">
              {report.submitted_url_redacted}
            </div>

            <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-[#6B6B6B] font-mono">
              <span>Scan ID: <strong className="text-[#040404]">{report.scan_id}</strong></span>
              <span aria-hidden="true" className="text-[#CDCDCD]">&bull;</span>
              <span>Host: <strong className="text-[#040404]">{report.normalized_host}</strong></span>
              <span aria-hidden="true" className="text-[#CDCDCD]">&bull;</span>
              <span>Status: <strong className="text-[#040404] uppercase font-bold">{report.status}</strong></span>
            </div>
          </div>

          {/* Decision Badge & Action Tools */}
          <div className="flex flex-wrap items-center gap-3">
            <div className={`px-4 py-2.5 handdrawn-pill border flex items-center gap-2.5 ${decisionBadge.bg}`}>
              <DecisionIcon className="w-5 h-5 shrink-0 text-[#040404]" />
              <div>
                <div className="font-heading font-bold text-xs uppercase tracking-tight text-[#040404]">{decisionBadge.label}</div>
                <div className="text-[10px] font-mono text-[#6B6B6B]">{decisionBadge.sub}</div>
              </div>
            </div>

            <button
              onClick={() => {
                sound.playClick(600);
                setShowJson(!showJson);
              }}
              data-cursor-text="RAW JSON"
              className="p-2.5 handdrawn-pill bg-[#F6F6F6] border border-[#D9D9D9] hover:border-[#040404] text-[#040404] transition-all text-xs font-mono flex items-center gap-1.5"
            >
              <FileCode className="w-4 h-4 text-[#6B6B6B]" />
              <span>JSON</span>
            </button>

            <button
              onClick={handleCopyJson}
              data-cursor-text="COPY"
              className="p-2.5 handdrawn-pill bg-[#F6F6F6] border border-[#D9D9D9] hover:border-[#040404] text-[#040404] transition-all text-xs font-mono flex items-center gap-1.5"
            >
              {copied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4 text-[#6B6B6B]" />}
              <span>Copy</span>
            </button>
          </div>
        </div>

        {/* 4 Verifiable Dimensions */}
        <div className="space-y-4">
          <div className="flex items-center justify-between text-xs font-mono text-[#6B6B6B]">
            <span className="uppercase tracking-wider font-bold text-[#040404]">4 UNBUNDLED EVIDENCE DIMENSIONS:</span>
            <button
              onClick={() => {
                sound.playClick(600);
                onOpenInvariants();
              }}
              data-cursor-text="GUIDE"
              className="text-[#040404] hover:underline flex items-center gap-1"
            >
              <span>Invariants Guide</span>
              <ExternalLink className="w-3 h-3" />
            </button>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* Dimension 1: Identity */}
            <div
              data-cursor-text="IDENTITY"
              className="p-5 handdrawn-box border border-[#D9D9D9] bg-[#F6F6F6] space-y-2 hover:border-[#040404] transition-colors"
            >
              <div className="flex items-center justify-between text-xs text-[#6B6B6B] font-mono">
                <span className="font-bold uppercase">01 // IDENTITY</span>
                <IdCard className="w-3.5 h-3.5 text-[#6B6B6B]" />
              </div>
              <div className="text-sm font-serif font-bold text-[#040404] leading-snug">
                {report.dimensions.identity}
              </div>
              <div className="text-[11px] font-serif text-[#6B6B6B] pt-1 border-t border-[#D9D9D9]">
                What evidence connects this domain to claimed organization?
              </div>
            </div>

            {/* Dimension 2: Certificate */}
            <div
              data-cursor-text="CERTIFICATE"
              className="p-5 handdrawn-box border border-[#D9D9D9] bg-[#F6F6F6] space-y-2 hover:border-[#040404] transition-colors"
            >
              <div className="flex items-center justify-between text-xs text-[#6B6B6B] font-mono">
                <span className="font-bold uppercase">02 // CERTIFICATE</span>
                <Lock className="w-3.5 h-3.5 text-[#6B6B6B]" />
              </div>
              <div className="text-sm font-serif font-bold text-[#040404] leading-snug">
                {report.dimensions.certificate}
              </div>
              <div className="text-[11px] font-serif text-[#6B6B6B] pt-1 border-t border-[#D9D9D9]">
                What the TLS certificate shows, and what it does not.
              </div>
            </div>

            {/* Dimension 3: Behavior */}
            <div
              data-cursor-text="BEHAVIOR"
              className="p-5 handdrawn-box border border-[#D9D9D9] bg-[#F6F6F6] space-y-2 hover:border-[#040404] transition-colors"
            >
              <div className="flex items-center justify-between text-xs text-[#6B6B6B] font-mono">
                <span className="font-bold uppercase">03 // BEHAVIOUR</span>
                <Activity className="w-3.5 h-3.5 text-[#6B6B6B]" />
              </div>
              <div className="text-sm font-serif font-bold text-[#040404] leading-snug">
                {report.dimensions.behavior}
              </div>
              <div className="text-[11px] font-serif text-[#6B6B6B] pt-1 border-t border-[#D9D9D9]">
                What bounded checks observed about page and redirects.
              </div>
            </div>

            {/* Dimension 4: Evidence Quality */}
            <div
              data-cursor-text="QUALITY"
              className="p-5 handdrawn-box border border-[#D9D9D9] bg-[#F6F6F6] space-y-2 hover:border-[#040404] transition-colors"
            >
              <div className="flex items-center justify-between text-xs text-[#6B6B6B] font-mono">
                <span className="font-bold uppercase">04 // EVIDENCE QUALITY</span>
                <BarChart3 className="w-3.5 h-3.5 text-[#6B6B6B]" />
              </div>
              <div className="text-sm font-serif font-bold text-[#040404] leading-snug">
                {report.dimensions.evidence_quality}
              </div>
              <div className="text-[11px] font-serif text-[#6B6B6B] pt-1 border-t border-[#D9D9D9]">
                How complete, fresh and consistent the evidence is.
              </div>
            </div>
          </div>
        </div>

        {/* Coverage Arithmetic Invariant Bar */}
        <div className="pt-4 border-t border-[rgb(0_0_0/10%)] space-y-2">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between text-xs font-mono text-[#6b6b6b] gap-1">
            <span>
              <strong className="text-[#040404]">COV-001 Invariant:</strong> checks_total == observed + failed + not_run
            </span>
            <span className="text-[#040404] font-bold">
              {report.coverage.checks_total} Total ({report.coverage.checks_observed} Obs, {report.coverage.checks_failed} Fail, {report.coverage.checks_not_run} Not Run)
            </span>
          </div>

          <div className="w-full h-2.5 bg-[#f6f6f6] rounded-full overflow-hidden flex border border-[rgb(0_0_0/10%)]">
            <div style={{ width: `${obsPct}%` }} className="bg-[#101010] h-full" />
            <div style={{ width: `${failPct}%` }} className="bg-[#cdcdcd] h-full" />
            <div style={{ width: `${notRunPct}%` }} className="bg-[#d9d9d9] h-full" />
          </div>
        </div>
      </div>

      {/* Collapsible Canonical Raw JSON Inspector */}
      <AnimatePresence>
        {showJson && (
          <motion.div
            ref={jsonRef}
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="overflow-hidden handdrawn-card border border-[rgb(0_0_0/10%)] bg-[#101010] p-5 space-y-3"
          >
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="text-white font-bold flex items-center gap-2">
                <FileCode className="w-4 h-4 text-[#cdcdcd]" />
                <span>CANONICAL JSON SCHEMA OUTPUT</span>
              </span>
              <button
                onClick={handleCopyJson}
                className="px-3 py-1 bg-[#ffffff]/10 text-white border border-[rgb(255_255_255/20%)] handdrawn-pill hover:bg-[#ffffff]/20 transition-colors"
              >
                Copy JSON
              </button>
            </div>
            <pre className="p-4 handdrawn-box bg-[#131313] border border-[rgb(255_255_255/10%)] text-xs font-mono text-[#f6f6f6] overflow-x-auto max-h-96 leading-relaxed">
              {JSON.stringify(report, null, 2)}
            </pre>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Streamlined Tabbed Records */}
      <div className="handdrawn-card border border-[rgb(0_0_0/10%)] bg-[#ffffff] p-4 sm:p-8 space-y-6 shadow-sm">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-[rgb(0_0_0/10%)] pb-4 gap-3">
          <div className="flex flex-wrap items-center gap-1.5 sm:gap-2">
            <button
              onClick={() => {
                sound.playClick(600);
                setActiveTab('findings');
              }}
              className={`px-3 py-1.5 handdrawn-pill text-xs font-heading transition-colors font-bold ${
                activeTab === 'findings'
                  ? 'bg-[#101010] text-white'
                  : 'bg-[#f6f6f6] text-[#6b6b6b] hover:text-[#040404]'
              }`}
            >
              Adjudicated Findings ({report.findings.length})
            </button>

            <button
              onClick={() => {
                sound.playClick(600);
                setActiveTab('evidence');
              }}
              className={`px-3 py-1.5 handdrawn-pill text-xs font-heading transition-colors font-bold ${
                activeTab === 'evidence'
                  ? 'bg-[#101010] text-white'
                  : 'bg-[#f6f6f6] text-[#6b6b6b] hover:text-[#040404]'
              }`}
            >
              Traceable Evidence ({report.evidence.length})
            </button>

            <button
              onClick={() => {
                sound.playClick(600);
                setActiveTab('claim_matrix');
              }}
              className={`px-3 py-1.5 handdrawn-pill text-xs font-heading transition-colors font-bold ${
                activeTab === 'claim_matrix'
                  ? 'bg-[#101010] text-white'
                  : 'bg-[#f6f6f6] text-[#6b6b6b] hover:text-[#040404]'
              }`}
            >
              Claim Matrix (Phase 10)
            </button>

            <button
              onClick={() => {
                sound.playClick(600);
                setActiveTab('counterfactual');
              }}
              className={`px-3 py-1.5 handdrawn-pill text-xs font-heading transition-colors font-bold ${
                activeTab === 'counterfactual'
                  ? 'bg-[#101010] text-white'
                  : 'bg-[#f6f6f6] text-[#6b6b6b] hover:text-[#040404]'
              }`}
            >
              What-If Boundary (Phase 09)
            </button>

            <button
              onClick={() => {
                sound.playClick(600);
                setActiveTab('cost_calibration');
              }}
              className={`px-3 py-1.5 handdrawn-pill text-xs font-heading transition-colors font-bold ${
                activeTab === 'cost_calibration'
                  ? 'bg-[#101010] text-white'
                  : 'bg-[#f6f6f6] text-[#6b6b6b] hover:text-[#040404]'
              }`}
            >
              Cost Calibration (Phase 08)
            </button>
          </div>

          {activeTab === 'findings' && (
            <div className="flex items-center gap-1 bg-[#f6f6f6] p-1 handdrawn-pill border border-[rgb(0_0_0/10%)] text-[10px] font-mono self-start sm:self-auto">
              {(['all', 'high', 'caution', 'info'] as const).map((sev) => (
                <button
                  key={sev}
                  onClick={() => {
                    sound.playClick(600);
                    setSeverityFilter(sev);
                  }}
                  className={`px-2 py-0.5 rounded uppercase font-medium ${
                    severityFilter === sev ? 'bg-[#101010] text-white font-bold' : 'text-[#6b6b6b] hover:text-[#040404]'
                  }`}
                >
                  {sev}
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Tab Content */}
        <div className="space-y-3 max-h-[600px] overflow-y-auto pr-1">
          {activeTab === 'findings' ? (
            filteredFindings.length === 0 ? (
              <div className="p-8 text-center text-xs text-[#6b6b6b] font-mono border border-dashed border-[rgb(0_0_0/10%)] handdrawn-box">
                No discrete findings for filter '{severityFilter}'. Target passed baseline policies.
              </div>
            ) : (
              filteredFindings.map((finding) => (
                <div
                  key={finding.finding_id}
                  className="p-4 handdrawn-box border border-[rgb(0_0_0/10%)] bg-[#f6f6f6] space-y-2 text-xs"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-heading font-bold text-[#040404] tracking-tight">
                      {finding.kind}
                    </span>
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase font-bold border border-[rgb(0_0_0/10%)] ${
                        finding.severity === 'high'
                          ? 'bg-[#101010] text-white'
                          : finding.severity === 'caution'
                          ? 'bg-[#d9d9d9] text-[#040404]'
                          : 'bg-[#ffffff] text-[#040404]'
                      }`}
                    >
                      {finding.severity}
                    </span>
                  </div>
                  <p className="font-body text-[#040404] leading-relaxed">{finding.summary}</p>
                  <div className="pt-2 border-t border-[rgb(0_0_0/10%)] text-[10px] font-mono text-[#6b6b6b] flex justify-between">
                    <span>Rule: {finding.rule_id}</span>
                    <span>Evidence Lineage: <strong className="text-[#040404]">{finding.evidence_ids.join(', ')}</strong></span>
                  </div>
                </div>
              ))
            )
          ) : activeTab === 'evidence' ? (
            report.evidence.length === 0 ? (
              <div className="p-8 text-center text-xs text-[#6b6b6b] font-mono border border-dashed border-[rgb(0_0_0/10%)] handdrawn-box">
                No external evidence records collected.
              </div>
            ) : (
              report.evidence.map((ev) => (
                <div
                  key={ev.evidence_id}
                  className="p-4 handdrawn-box border border-[rgb(0_0_0/10%)] bg-[#f6f6f6] space-y-2 text-xs font-mono"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-[#040404]">{ev.evidence_id}</span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${ev.status === 'observed' ? 'bg-[#101010] text-white' : 'bg-[#d9d9d9] text-[#040404]'}`}>
                      {ev.status}
                    </span>
                  </div>
                  <div className="text-[#040404]">
                    <span className="text-[#6b6b6b]">Source:</span> <strong className="text-[#040404]">{ev.source}</strong> &bull;{' '}
                    <span className="text-[#6b6b6b]">Reliability:</span> {ev.reliability}
                  </div>
                  {ev.limitations && ev.limitations.length > 0 && (
                    <div className="text-[11px] text-[#6b6b6b] bg-[#ffffff] p-2 handdrawn-box border border-[rgb(0_0_0/10%)]">
                      Limitations: {ev.limitations.join('; ')}
                    </div>
                  )}
                </div>
              ))
            )
          ) : activeTab === 'claim_matrix' ? (
            <ClaimLineageMatrix
              report={report}
              onShowToast={onShowToast}
              onSelectEvidence={(evidenceId) => setActiveTab('evidence')}
            />
          ) : activeTab === 'counterfactual' ? (
            <CounterfactualPanel
              report={report}
              onShowToast={onShowToast}
            />
          ) : (
            <CostCalibrationPanel
              report={report}
              onShowToast={onShowToast}
            />
          )}
        </div>
      </div>

      {/* Quiet Disclosures */}
      <div className="text-center text-xs font-accent italic text-[#6b6b6b] py-2">
        Passive Handshake &bull; Zero DOM / JavaScript Execution &bull; Invariant Compliant (v1.0)
      </div>
    </div>
  );
}
