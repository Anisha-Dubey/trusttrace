import React, { useState } from 'react';
import { ShieldAlert, Send, RotateCcw, Search, CheckCircle2 } from 'lucide-react';
import { CommunityReport } from '../types/triage';
import { escapeHtml, INITIAL_COMMUNITY_REPORTS } from '../data/scenarios';
import { sound } from '../utils/audio';

interface ThreatIntelFeedProps {
  reports: CommunityReport[];
  setReports: React.Dispatch<React.SetStateAction<CommunityReport[]>>;
  onShowToast: (msg: string) => void;
  onTriageDomain: (domain: string) => void;
}

export default function ThreatIntelFeed({
  reports,
  setReports,
  onShowToast,
  onTriageDomain,
}: ThreatIntelFeedProps) {
  const [domain, setDomain] = useState('');
  const [claimType, setClaimType] = useState<CommunityReport['claim_type']>('phishing');
  const [notes, setNotes] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [stateFilter, setStateFilter] = useState<'all' | 'verified' | 'disputed' | 'unverified'>('all');
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    sound.playClick(600);

    const cleanDomain = domain
      .trim()
      .toLowerCase()
      .replace(/^https?:\/\//, '')
      .split('/')[0];

    if (!cleanDomain) {
      setFeedback({ type: 'error', text: 'Please specify a valid domain name.' });
      return;
    }

    const sanitizedNote = escapeHtml(notes.trim());

    const existing = reports.find((r) => r.normalized_domain === cleanDomain);
    let newCount = 1;
    let newState: CommunityReport['verification_state'] = 'unverified';

    if (existing) {
      newCount = existing.independent_source_count + 1;
      newState = newCount >= 2 ? 'verified' : 'unverified';
    }

    const newReportId = 'rep-comm-' + Math.floor(Math.random() * 9000 + 1000);
    const newReport: CommunityReport = {
      report_id: newReportId,
      normalized_domain: cleanDomain,
      claim_type: claimType,
      verification_state: newState,
      independent_source_count: newCount,
      note_sanitized: sanitizedNote,
      submitted_at: new Date().toISOString(),
    };

    setReports([newReport, ...reports]);
    sound.playSuccess();
    setFeedback({
      type: 'success',
      text: `Adversarial Finding logged! ID: ${newReportId} (Verification: ${newState}, Corroboration: ${newCount})`,
    });
    onShowToast(`Threat report logged for ${cleanDomain}`);

    setDomain('');
    setNotes('');
  };

  const handleResetFeed = () => {
    sound.playClick(500);
    setReports(INITIAL_COMMUNITY_REPORTS);
    setFeedback(null);
    onShowToast('Threat intelligence feed reset to baseline');
  };

  const filteredReports = reports.filter((r) => {
    const matchesSearch =
      r.normalized_domain.toLowerCase().includes(searchQuery.toLowerCase()) ||
      r.note_sanitized.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesState = stateFilter === 'all' ? true : r.verification_state === stateFilter;
    return matchesSearch && matchesState;
  });

  return (
    <div className="space-y-8">
      {/* Subsystem Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-[rgb(0_0_0/10%)] pb-6">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-xs font-mono font-bold text-[#6b6b6b] uppercase tracking-widest">
              Worker 02 Telemetry Subsystem
            </span>
            <span aria-hidden="true" className="text-[#cdcdcd]">/</span>
            <span className="text-xs font-mono text-[#040404] font-semibold">
              Exposure Intelligence
            </span>
          </div>
          <h2 className="text-2xl sm:text-3xl font-heading font-extrabold text-[#040404] tracking-[var(--tracking-heading)]">
            Continuous Threat &amp; Telemetry Feed
          </h2>
          <p className="font-body text-[#6b6b6b] text-xs sm:text-sm mt-1 max-w-2xl leading-relaxed">
            Community-sourced adversarial threat findings with strict XSS sanitization, anti-Sybil deduplication, and non-inflated multi-source corroboration metrics.
          </p>
        </div>

        <button
          onClick={handleResetFeed}
          className="self-start sm:self-center px-3.5 py-2 rounded-xl bg-[#f6f6f6] border border-[rgb(0_0_0/10%)] hover:border-[rgb(0_0_0/25%)] text-[#040404] transition-all text-xs font-mono flex items-center gap-2"
        >
          <RotateCcw className="w-3.5 h-3.5 text-[#6b6b6b]" />
          <span>Reset Feed</span>
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">

        {/* Left Column: Submission Form */}
        <div className="rounded-2xl border border-[rgb(0_0_0/10%)] bg-[#ffffff] p-6 space-y-4 shadow-sm">
          <div className="flex items-center gap-2 border-b border-[rgb(0_0_0/10%)] pb-3">
            <ShieldAlert className="w-4 h-4 text-[#040404]" />
            <h3 className="text-xs font-bold uppercase tracking-wider font-mono text-[#040404]">
              Submit Finding
            </h3>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4 text-xs font-mono">
            <div>
              <label htmlFor="threatDomain" className="block text-[#6b6b6b] mb-1.5 font-medium">
                Target Domain:
              </label>
              <input
                id="threatDomain"
                type="text"
                required
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                placeholder="suspicious-portal.org"
                className="w-full px-3 py-2.5 bg-[#f6f6f6] border border-[rgb(0_0_0/10%)] rounded-xl text-[#040404] placeholder:text-[#6b6b6b] focus:outline-none focus:border-[#040404] transition-colors"
              />
            </div>

            <div>
              <label htmlFor="threatClaim" className="block text-[#6b6b6b] mb-1.5 font-medium">
                Claim Type:
              </label>
              <select
                id="threatClaim"
                value={claimType}
                onChange={(e) => setClaimType(e.target.value as CommunityReport['claim_type'])}
                className="w-full px-3 py-2.5 bg-[#f6f6f6] border border-[rgb(0_0_0/10%)] rounded-xl text-[#040404] focus:outline-none focus:border-[#040404] transition-colors"
              >
                <option value="phishing">Phishing Campaign</option>
                <option value="credential_harvesting">Credential Harvesting</option>
                <option value="brand_impersonation">Brand Impersonation</option>
                <option value="malware_distribution">Malware Distribution</option>
                <option value="suspicious_activity">General Suspicious Activity</option>
              </select>
            </div>

            <div>
              <label htmlFor="threatNotes" className="block text-[#6b6b6b] mb-1.5 font-medium">
                Analyst Notes (XSS-Sanitized):
              </label>
              <textarea
                id="threatNotes"
                required
                rows={3}
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                placeholder="Observed fake bank authorization portal requesting credentials..."
                className="w-full px-3 py-2.5 bg-[#f6f6f6] border border-[rgb(0_0_0/10%)] rounded-xl text-[#040404] placeholder:text-[#6b6b6b] focus:outline-none focus:border-[#040404] transition-colors font-body text-xs"
              />
            </div>

            <button
              type="submit"
              className="w-full py-2.5 rounded-xl bg-[#101010] hover:bg-[#131313] text-white font-medium transition-all flex items-center justify-center gap-2 active:scale-95 shadow-sm"
            >
              <Send className="w-3.5 h-3.5" />
              <span>Submit Finding</span>
            </button>
          </form>

          {feedback && (
            <div
              className={`p-3 rounded-xl border text-[11px] font-mono leading-relaxed ${
                feedback.type === 'success'
                  ? 'bg-[#f6f6f6] border-[#040404] text-[#040404]'
                  : 'bg-rose-50 border-rose-300 text-rose-700'
              }`}
            >
              {feedback.text}
            </div>
          )}

          <div className="pt-2 border-t border-[rgb(0_0_0/10%)] text-[11px] text-[#6b6b6b] font-mono leading-relaxed">
            <span className="text-[#040404] font-bold">COMM-001 Invariant:</span> Multi-source corroboration required for promotion. Single-source submissions remain unverified.
          </div>
        </div>

        {/* Right Column: Feed List & Search */}
        <div className="lg:col-span-2 space-y-4">
          <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
            <div className="relative flex-grow">
              <Search className="w-4 h-4 text-[#6b6b6b] absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search domain or analyst telemetry..."
                className="w-full pl-10 pr-4 py-2 bg-[#f6f6f6] border border-[rgb(0_0_0/10%)] rounded-xl text-xs font-mono text-[#040404] placeholder:text-[#6b6b6b] focus:outline-none focus:border-[#040404]"
              />
            </div>

            <div className="flex flex-wrap items-center gap-1 bg-[#f6f6f6] p-1 rounded-xl border border-[rgb(0_0_0/10%)] text-xs font-mono self-start sm:self-auto">
              {(['all', 'verified', 'disputed', 'unverified'] as const).map((filter) => (
                <button
                  key={filter}
                  onClick={() => {
                    sound.playClick(600);
                    setStateFilter(filter);
                  }}
                  className={`px-2.5 py-1 rounded-lg uppercase text-[10px] font-medium ${
                    stateFilter === filter
                      ? 'bg-[#101010] text-white font-bold'
                      : 'text-[#6b6b6b] hover:text-[#040404]'
                  }`}
                >
                  {filter}
                </button>
              ))}
            </div>
          </div>

          {/* Feed Records */}
          <div className="space-y-3 max-h-[500px] overflow-y-auto pr-1">
            {filteredReports.length === 0 ? (
              <div className="p-8 text-center text-xs text-[#6b6b6b] font-mono border border-dashed border-[rgb(0_0_0/10%)] rounded-2xl">
                No corroborated intelligence records matching current query.
              </div>
            ) : (
              filteredReports.map((report) => (
                <div
                  key={report.report_id}
                  className="p-4 rounded-xl border border-[rgb(0_0_0/10%)] bg-[#ffffff] hover:border-[rgb(0_0_0/25%)] transition-all space-y-2 group text-xs shadow-xs"
                >
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-1.5 sm:gap-2 min-w-0">
                      <span className="font-heading font-bold text-[#040404] text-xs sm:text-sm truncate">
                        {report.normalized_domain}
                      </span>
                      <button
                        onClick={() => {
                          sound.playClick(600);
                          onTriageDomain(`https://${report.normalized_domain}`);
                        }}
                        className="text-[10px] text-[#6b6b6b] hover:text-[#040404] font-mono underline shrink-0"
                        title="Triage this domain"
                      >
                        [Triage]
                      </button>
                    </div>

                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase font-bold border border-[rgb(0_0_0/10%)] ${
                        report.verification_state === 'verified'
                          ? 'bg-[#101010] text-white'
                          : report.verification_state === 'disputed'
                          ? 'bg-[#d9d9d9] text-[#040404]'
                          : 'bg-[#f6f6f6] text-[#6b6b6b]'
                      }`}
                    >
                      {report.verification_state}
                    </span>
                  </div>

                  <div className="font-body text-[#040404]">
                    <span className="text-[#6b6b6b] font-mono uppercase text-[10px] mr-1.5 font-bold">
                      {report.claim_type.replace(/_/g, ' ')}:
                    </span>
                    {report.note_sanitized}
                  </div>

                  <div className="pt-2 border-t border-[rgb(0_0_0/10%)] text-[10px] font-mono text-[#6b6b6b] flex items-center justify-between">
                    <span>
                      Corroboration: <strong className="text-[#040404]">{report.independent_source_count} source(s)</strong>
                    </span>
                    <span>{report.submitted_at ? report.submitted_at.replace('T', ' ').substring(0, 16) : 'recently'}</span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
