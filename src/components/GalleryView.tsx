import { useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import {
  LayoutGrid,
  List,
  ArrowUpRight,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  XCircle,
  Sparkles,
  Lock,
  Globe,
  Layers,
  Terminal,
  Activity,
  CheckCircle2
} from 'lucide-react';
import { sound } from '../utils/audio';
import { CANONICAL_SCENARIOS } from '../data/scenarios';
import { PassportRecord } from '../types/triage';

interface GalleryCase {
  id: string;
  scenarioKey: string;
  number: string;
  title: string;
  domain: string;
  category: 'phishing' | 'infrastructure' | 'intel' | 'defense';
  categoryLabel: string;
  decision: 'caution' | 'no_threat_observed' | 'inconclusive' | 'rejected';
  year: string;
  keyFinding: string;
  dimensionBreakdown: {
    transport: string;
    identity: string;
    behavior: string;
  };
  metrics: string;
}

const GALLERY_CASES: GalleryCase[] = [
  {
    id: 'case-01',
    scenarioKey: 'phishing_lookalike',
    number: '01',
    title: 'Financial Lookalike & Cyrillic Homoglyph Spoof',
    domain: 'bank-secure-lоgin.com',
    category: 'phishing',
    categoryLabel: 'Phishing Lookalike',
    decision: 'caution',
    year: '2026',
    keyFinding: "DV TLS certificate valid for hostname; Cyrillic 'о' (U+043E) impersonates Latin 'o'.",
    dimensionBreakdown: {
      transport: '100% Valid (DV TLS)',
      identity: '0% Spoofed Entity',
      behavior: 'Credential Trap',
    },
    metrics: 'Transport Valid ≠ Entity Authenticity',
  },
  {
    id: 'case-02',
    scenarioKey: 'expired_tls',
    number: '02',
    title: 'Enterprise Portal Expired Certificate Hygiene Lapse',
    domain: 'legacy-portal.internal-corp.net',
    category: 'infrastructure',
    categoryLabel: 'Infrastructure Health',
    decision: 'caution',
    year: '2026',
    keyFinding: 'X.509 certificate expired 5 days ago; operational oversight, not active credential harvesting.',
    dimensionBreakdown: {
      transport: 'Failed (Expired)',
      identity: 'Unverified Entity',
      behavior: 'Benign Inactive',
    },
    metrics: 'Hygiene Lapse ≠ Active Attack',
  },
  {
    id: 'case-03',
    scenarioKey: 'conflicting',
    number: '03',
    title: 'Decentralized Exchange Sybil Intel & Dispute',
    domain: 'disputed-exchange.io',
    category: 'intel',
    categoryLabel: 'Adversarial Intelligence',
    decision: 'inconclusive',
    year: '2026',
    keyFinding: 'Conflicting independent community reports; policy engine abstains to inconclusive.',
    dimensionBreakdown: {
      transport: '100% Valid',
      identity: 'Disputed Domain',
      behavior: 'Contradictory',
    },
    metrics: 'Deterministic Abstention Invariant',
  },
  {
    id: 'case-04',
    scenarioKey: 'legitimate',
    number: '04',
    title: 'Institutional Delegation & Verified Organization',
    domain: 'example.com',
    category: 'defense',
    categoryLabel: 'Verified Authority',
    decision: 'no_threat_observed',
    year: '2026',
    keyFinding: 'IANA institutional benchmark with authoritative DNS delegation and verified lineage.',
    dimensionBreakdown: {
      transport: '100% Valid',
      identity: '100% Verified Org',
      behavior: 'No Threat Observed',
    },
    metrics: 'Dual-Dimension Verification',
  },
  {
    id: 'case-05',
    scenarioKey: 'ssrf_blocked',
    number: '05',
    title: 'Cloud Metadata SSRF Ingress Boundary Intercept',
    domain: '169.254.169.254',
    category: 'defense',
    categoryLabel: 'SSRF Defense',
    decision: 'rejected',
    year: '2026',
    keyFinding: 'Link-local cloud metadata IP halted at ingress boundary; zero egress packets transmitted.',
    dimensionBreakdown: {
      transport: 'Not Checked',
      identity: 'Prohibited Target',
      behavior: 'Halted at Boundary',
    },
    metrics: 'Zero Active Browser Risk',
  },
  {
    id: 'case-06',
    scenarioKey: 'phishing_lookalike',
    number: '06',
    title: 'Subdomain Takeover & Dangling SaaS CNAME',
    domain: 'auth-corporate-sso.internal.biz',
    category: 'infrastructure',
    categoryLabel: 'Infrastructure Health',
    decision: 'caution',
    year: '2026',
    keyFinding: 'Dangling CNAME alias pointing to de-provisioned cloud bucket with takeover potential.',
    dimensionBreakdown: {
      transport: '100% Valid',
      identity: 'Dangling DNS Record',
      behavior: 'Exposed SaaS Asset',
    },
    metrics: 'DNS Lineage Audit',
  },
];

interface GalleryViewProps {
  onSelectCase: (scenarioKey: string, domainUrl: string) => void;
  onShowToast: (msg: string) => void;
}

export default function GalleryView({ onSelectCase, onShowToast }: GalleryViewProps) {
  const [viewMode, setViewMode] = useState<'grid' | 'list'>('grid');
  const [filter, setFilter] = useState<string>('all');
  const [hoveredCase, setHoveredCase] = useState<GalleryCase | null>(null);

  const filterCategories = [
    { id: 'all', label: 'All Benchmarks', count: GALLERY_CASES.length },
    { id: 'phishing', label: 'Phishing & Lookalikes', count: 2 },
    { id: 'infrastructure', label: 'Infrastructure Health', count: 2 },
    { id: 'intel', label: 'Threat Intel & Sybil', count: 1 },
    { id: 'defense', label: 'Boundary Defenses', count: 2 },
  ];

  const filteredCases = GALLERY_CASES.filter(
    (c) => filter === 'all' || c.category === filter
  );

  const getDecisionBadge = (decision: GalleryCase['decision']) => {
    switch (decision) {
      case 'caution':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full bg-amber-500/10 text-amber-700 border border-amber-500/30 text-[10px] font-mono font-bold uppercase tracking-wider">
            <AlertTriangle className="w-3 h-3" />
            <span>Caution</span>
          </span>
        );
      case 'no_threat_observed':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full bg-emerald-500/10 text-emerald-800 border border-emerald-500/30 text-[10px] font-mono font-bold uppercase tracking-wider">
            <ShieldCheck className="w-3 h-3" />
            <span>Benign</span>
          </span>
        );
      case 'inconclusive':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full bg-zinc-500/10 text-zinc-700 border border-zinc-500/30 text-[10px] font-mono font-bold uppercase tracking-wider">
            <Activity className="w-3 h-3" />
            <span>Inconclusive</span>
          </span>
        );
      case 'rejected':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full bg-rose-500/10 text-rose-700 border border-rose-500/30 text-[10px] font-mono font-bold uppercase tracking-wider">
            <XCircle className="w-3 h-3" />
            <span>Rejected</span>
          </span>
        );
    }
  };

  return (
    <div className="space-y-12">
      {/* Editorial Header Section in Baseline Agency Style */}
      <div className="border-b border-[rgb(0_0_0/10%)] pb-8 space-y-5">
        <div className="flex items-center justify-between flex-wrap gap-4">
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono font-bold text-[#6b6b6b] uppercase tracking-widest">
              (06) / Case Archive &amp; Gallery
            </span>
            <span aria-hidden="true" className="text-[#cdcdcd]">/</span>
            <span className="text-xs font-mono text-[#040404] font-semibold">
              Adversarial Surface Index
            </span>
          </div>

          {/* Grid vs List View Toggle (Baseline Signature) */}
          <div className="flex items-center p-1 rounded-xl bg-[#f6f6f6] border border-[rgb(0_0_0/10%)]">
            <button
              onClick={() => {
                sound.playClick(600);
                setViewMode('grid');
              }}
              data-cursor-text="GRID"
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono transition-all font-medium ${
                viewMode === 'grid'
                  ? 'bg-[#101010] text-white shadow-xs'
                  : 'text-[#6b6b6b] hover:text-[#040404]'
              }`}
            >
              <LayoutGrid className="w-3.5 h-3.5" />
              <span>Grid</span>
            </button>
            <button
              onClick={() => {
                sound.playClick(600);
                setViewMode('list');
              }}
              data-cursor-text="LIST"
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono transition-all font-medium ${
                viewMode === 'list'
                  ? 'bg-[#101010] text-white shadow-xs'
                  : 'text-[#6b6b6b] hover:text-[#040404]'
              }`}
            >
              <List className="w-3.5 h-3.5" />
              <span>Index</span>
            </button>
          </div>
        </div>

        <div>
          <h1 className="text-2xl sm:text-4xl md:text-5xl font-heading font-extrabold text-[#040404] tracking-[-0.03em] leading-display max-w-3xl">
            Selected Evaluations &amp; Attack Surface Gallery
          </h1>
          <p className="text-[#6b6b6b] text-xs sm:text-base mt-2.5 max-w-2xl leading-relaxed font-body">
            Explore authentic triage passports unbundling deceptive DV TLS locks, Cyrillic lookalikes, expired hygiene failures, and egress boundary guardrails.
          </p>
        </div>

        {/* Filter Category Pills */}
        <div className="flex flex-wrap items-center gap-2 pt-2">
          {filterCategories.map((cat) => (
            <button
              key={cat.id}
              onClick={() => {
                sound.playClick(650);
                setFilter(cat.id);
              }}
              data-cursor-text="FILTER"
              className={`px-3 py-1.5 rounded-lg text-xs font-mono transition-colors font-medium flex items-center gap-1.5 ${
                filter === cat.id
                  ? 'bg-[#101010] text-white border border-[#101010] font-bold shadow-xs'
                  : 'bg-[#ffffff] text-[#6b6b6b] hover:text-[#040404] hover:bg-[#f6f6f6] border border-[rgb(0_0_0/10%)]'
              }`}
            >
              <span>{cat.label}</span>
              <span className={`text-[10px] ${filter === cat.id ? 'text-zinc-400' : 'text-[#6b6b6b]'}`}>
                ({cat.count})
              </span>
            </button>
          ))}
        </div>
      </div>

      {/* Grid View Mode */}
      {viewMode === 'grid' && (
        <motion.div
          key="grid-view"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.3 }}
          className="grid grid-cols-1 md:grid-cols-2 gap-6 sm:gap-8"
        >
          {filteredCases.map((item, idx) => (
            <motion.div
              key={item.id}
              initial={{ opacity: 0, y: 24 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.35, delay: idx * 0.06 }}
              className="group relative rounded-2xl border border-[rgb(0_0_0/10%)] bg-[#ffffff] p-6 sm:p-7 space-y-6 hover:border-[rgb(0_0_0/25%)] hover:shadow-xl transition-all duration-300 flex flex-col justify-between cursor-pointer"
              data-cursor-text="AUDIT CASE"
              onClick={() => {
                sound.playClick(700);
                onSelectCase(item.scenarioKey, `https://${item.domain}`);
              }}
            >
              {/* Top Meta Strip */}
              <div className="flex items-center justify-between text-xs font-mono text-[#6b6b6b]">
                <div className="flex items-center gap-2">
                  <span className="font-bold text-[#040404]">({item.number})</span>
                  <span className="text-[#cdcdcd]">•</span>
                  <span className="uppercase tracking-wider">{item.categoryLabel}</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-[11px] font-mono text-[#6b6b6b]">[{item.year}]</span>
                  {getDecisionBadge(item.decision)}
                </div>
              </div>

              {/* Simulated Interactive Visual Stage (Baseline Gallery Style) */}
              <div className="relative rounded-xl border border-[rgb(0_0_0/8%)] bg-[#f6f6f6] p-5 space-y-3.5 overflow-hidden group-hover:bg-[#f0f0f0] transition-colors">
                {/* Browser-style address preview */}
                <div className="flex items-center justify-between text-xs font-mono pb-2 border-b border-[rgb(0_0_0/8%)]">
                  <div className="flex items-center gap-2">
                    <span className="w-2.5 h-2.5 rounded-full bg-[#d9d9d9]" />
                    <span className="w-2.5 h-2.5 rounded-full bg-[#d9d9d9]" />
                    <span className="w-2.5 h-2.5 rounded-full bg-[#d9d9d9]" />
                  </div>
                  <span className="text-[#6b6b6b] text-[10px] truncate max-w-[200px]">
                    passport://{item.domain}
                  </span>
                </div>

                {/* Main Domain Stage */}
                <div className="py-2 space-y-2">
                  <div className="text-lg sm:text-xl font-heading font-extrabold text-[#040404] tracking-[-0.03em] flex items-center justify-between gap-2">
                    <span className="truncate">{item.domain}</span>
                    <ArrowUpRight className="w-4 h-4 text-[#6b6b6b] group-hover:text-[#040404] group-hover:translate-x-0.5 group-hover:-translate-y-0.5 transition-all shrink-0" />
                  </div>
                  <p className="text-xs text-[#6b6b6b] font-body line-clamp-2">
                    {item.keyFinding}
                  </p>
                </div>

                {/* Dimension Metric Badges */}
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 pt-2 border-t border-[rgb(0_0_0/8%)] text-[10px] font-mono">
                  <div className="space-y-0.5">
                    <span className="text-[#6b6b6b] block">Transport</span>
                    <span className="font-bold text-[#040404] truncate block">{item.dimensionBreakdown.transport}</span>
                  </div>
                  <div className="space-y-0.5">
                    <span className="text-[#6b6b6b] block">Identity</span>
                    <span className="font-bold text-[#040404] truncate block">{item.dimensionBreakdown.identity}</span>
                  </div>
                  <div className="space-y-0.5">
                    <span className="text-[#6b6b6b] block">Thesis Metric</span>
                    <span className="font-bold text-[#040404] truncate block">{item.metrics}</span>
                  </div>
                </div>
              </div>

              {/* Case Title and Action Trigger */}
              <div className="space-y-2">
                <h3 className="text-base sm:text-lg font-heading font-bold text-[#040404] tracking-[-0.03em] group-hover:text-black transition-colors">
                  {item.title}
                </h3>
              </div>

              {/* Bottom Execution Bar */}
              <div className="pt-3 border-t border-[rgb(0_0_0/10%)] flex items-center justify-between text-xs font-mono">
                <span className="text-[#6b6b6b] text-[11px]">
                  Audited Lineage Available
                </span>
                <span className="inline-flex items-center gap-1.5 font-bold text-[#040404] group-hover:underline">
                  <span>Inspect Passport</span>
                  <ArrowUpRight className="w-3.5 h-3.5" />
                </span>
              </div>
            </motion.div>
          ))}
        </motion.div>
      )}

      {/* Index List View Mode (Baseline Agency Iconic Index List) */}
      {viewMode === 'list' && (
        <motion.div
          key="list-view"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.3 }}
          className="border border-[rgb(0_0_0/10%)] rounded-2xl bg-[#ffffff] divide-y divide-[rgb(0_0_0/10%)] overflow-hidden"
        >
          {filteredCases.map((item) => (
            <div
              key={item.id}
              onMouseEnter={() => {
                sound.playHover();
                setHoveredCase(item);
              }}
              onMouseLeave={() => setHoveredCase(null)}
              onClick={() => {
                sound.playClick(700);
                onSelectCase(item.scenarioKey, `https://${item.domain}`);
              }}
              data-cursor-text="OPEN"
              className="group p-5 sm:p-6 hover:bg-[#f6f6f6] transition-colors flex flex-col md:flex-row md:items-center justify-between gap-4 cursor-pointer"
            >
              {/* Left Column: Number & Domain */}
              <div className="flex items-start sm:items-center gap-4">
                <span className="text-xs font-mono font-bold text-[#6b6b6b] group-hover:text-[#040404] transition-colors">
                  ({item.number})
                </span>
                <div>
                  <div className="text-base sm:text-lg font-heading font-bold text-[#040404] tracking-[-0.03em] flex items-center gap-2">
                    <span>{item.domain}</span>
                    <span className="text-xs font-mono font-normal text-[#6b6b6b] hidden lg:inline">
                      — {item.title}
                    </span>
                  </div>
                  <p className="text-xs text-[#6b6b6b] font-body mt-0.5 line-clamp-1">
                    {item.keyFinding}
                  </p>
                </div>
              </div>

              {/* Right Column: Category, Decision, Arrow */}
              <div className="flex items-center gap-4 sm:gap-6 self-end md:self-auto shrink-0 font-mono text-xs">
                <span className="text-[#6b6b6b] text-[11px] uppercase tracking-wider hidden sm:inline">
                  {item.categoryLabel}
                </span>
                <div>{getDecisionBadge(item.decision)}</div>
                <div className="h-8 w-8 rounded-full bg-[#f6f6f6] group-hover:bg-[#101010] text-[#040404] group-hover:text-white flex items-center justify-center transition-colors">
                  <ArrowUpRight className="w-4 h-4" />
                </div>
              </div>
            </div>
          ))}
        </motion.div>
      )}

      {/* Floating Insight Banner */}
      <div className="p-6 rounded-2xl border border-[rgb(0_0_0/10%)] bg-[#f6f6f6] flex flex-col sm:flex-row sm:items-center justify-between gap-4 font-mono text-xs text-[#6b6b6b]">
        <div className="flex items-center gap-2.5">
          <Terminal className="w-4 h-4 text-[#040404] shrink-0" />
          <span>Need to evaluate a bespoke unlisted domain? Run live client-side triage in real time.</span>
        </div>
        <button
          onClick={() => {
            sound.playClick(600);
            onSelectCase('phishing_lookalike', 'https://bank-secure-lоgin.com');
          }}
          data-cursor-text="TRIAGE"
          className="px-4 py-2 rounded-xl bg-[#101010] hover:bg-[#131313] text-white font-medium text-xs transition-colors shadow-xs flex items-center justify-center gap-1.5 shrink-0"
        >
          <span>Launch Target Triage</span>
          <ArrowUpRight className="w-3.5 h-3.5" />
        </button>
      </div>
    </div>
  );
}
