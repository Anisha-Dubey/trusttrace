import { useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { Globe, ArrowRight, ShieldAlert, CheckCircle2, Clock, GitCompare, Ban, Sparkles } from 'lucide-react';
import { PassportRecord } from '../types/triage';
import { CANONICAL_SCENARIOS, evaluateCustomTargetLocally } from '../data/scenarios';
import { sound } from '../utils/audio';

interface TriageStudioProps {
  currentUrl: string;
  setCurrentUrl: (url: string) => void;
  onTriageComplete: (report: PassportRecord) => void;
  onOpenInvariants: () => void;
  onOpenGallery?: () => void;
}

export default function TriageStudio({
  currentUrl,
  setCurrentUrl,
  onTriageComplete,
  onOpenInvariants,
  onOpenGallery,
}: TriageStudioProps) {
  const [isScanning, setIsScanning] = useState(false);
  const [scanStep, setScanStep] = useState(0);
  const [selectedScenarioKey, setSelectedScenarioKey] = useState<string>('phishing_lookalike');

  const scanSteps = [
    { title: 'Intake Boundary Gate', desc: 'Validating RFC1918, SSRF loopback & credentials', code: 'SEC-001' },
    { title: 'Cryptographic TLS Audit', desc: 'Probing X.509 binding, expiration & SAN attributes', code: 'TLS-001' },
    { title: 'RDAP Delegation Lineage', desc: 'Evaluating organizational delegation vs DV-only', code: 'TLS-DV' },
    { title: 'Adversarial Threat Feeds', desc: 'Querying corroborated zero-day signals & homoglyphs', code: 'EVID-002' },
    { title: 'Policy Adjudication', desc: 'Synthesizing 4 dimensions with zero browser execution', code: 'SAFE-001' },
  ];

  const handleRunTriage = (scenarioKey?: string, overrideUrl?: string) => {
    const targetUrl = (overrideUrl !== undefined ? overrideUrl : currentUrl).trim();
    if (!targetUrl) return;

    sound.playClick(550);
    setIsScanning(true);
    setScanStep(0);

    let step = 0;
    const interval = setInterval(() => {
      step++;
      if (step < scanSteps.length) {
        setScanStep(step);
        sound.playScanBlip(step);
      } else {
        clearInterval(interval);
        setTimeout(() => {
          let report: PassportRecord;
          if (scenarioKey && CANONICAL_SCENARIOS[scenarioKey]) {
            report = CANONICAL_SCENARIOS[scenarioKey];
          } else {
            report = evaluateCustomTargetLocally(targetUrl);
          }

          if (report.status === 'rejected' || report.decision === 'rejected') {
            sound.playAlert();
          } else {
            sound.playSuccess();
          }

          setIsScanning(false);
          onTriageComplete(report);
        }, 150);
      }
    }, 120);
  };

  const handleSelectScenario = (key: string, url: string) => {
    sound.playClick(600);
    setSelectedScenarioKey(key);
    setCurrentUrl(url);
    handleRunTriage(key, url);
  };

  const getPreflightStatus = (url: string) => {
    if (!url) return null;
    if (url.includes('@')) return { type: 'danger', label: 'SEC-002: Embedded credentials prohibited' };
    if (url.includes('169.254.169.254') || url.includes('127.0.0.1') || url.includes('localhost')) {
      return { type: 'danger', label: 'SEC-001: Cloud metadata / loopback address rejected at intake' };
    }
    if (/[\u0400-\u04FF]/.test(url)) {
      return { type: 'warning', label: 'Homoglyph Alert: Cyrillic character detected in host label' };
    }
    return { type: 'neutral', label: 'Intake: Passive Handshake Ready' };
  };

  const preflight = getPreflightStatus(currentUrl);

  const scenarioPills = [
    {
      key: 'phishing_lookalike',
      url: 'https://bank-secure-lоgin.com',
      label: 'Phishing Lookalike',
      sub: 'Cyrillic Homoglyph',
      icon: ShieldAlert,
    },
    {
      key: 'legitimate',
      url: 'https://example.com',
      label: 'Legitimate Domain',
      sub: 'Verified Entity',
      icon: CheckCircle2,
    },
    {
      key: 'expired_tls',
      url: 'https://legacy-portal.internal-corp.net',
      label: 'Expired TLS',
      sub: 'Hygiene Warning',
      icon: Clock,
    },
    {
      key: 'conflicting',
      url: 'https://disputed-exchange.io',
      label: 'Conflicting Intel',
      sub: 'Safe Abstention',
      icon: GitCompare,
    },
    {
      key: 'ssrf_blocked',
      url: 'http://169.254.169.254/latest/meta-data',
      label: 'SSRF Target',
      sub: 'Zero Egress Halt',
      icon: Ban,
    },
  ];

  return (
    <div className="space-y-16 sm:space-y-20">
      {/* Editorial Spacious Hero */}
      <div className="text-center space-y-4 pt-4 sm:pt-6">
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          className="inline-flex items-center gap-2 text-xs font-accent italic text-[#6b6b6b]"
        >
          <span>Evidence-First Web Threat &amp; Digital Trust Triage</span>
        </motion.div>

        <motion.h1
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.05 }}
          className="text-3xl sm:text-5xl md:text-6xl lg:text-7xl font-heading font-extrabold text-[#040404] leading-display tracking-[var(--tracking-heading)] text-balance"
        >
          Continuous Web Trust Triage.
        </motion.h1>

        <motion.p
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="font-body text-[#6b6b6b] text-xs sm:text-base max-w-xl mx-auto leading-relaxed text-balance"
        >
          Decomposing web safety into 4 verifiable dimensions with audited evidence lineage and zero client-side browser execution.
        </motion.p>
      </div>

      {/* Floating Triage Console */}
      <div className="max-w-3xl mx-auto space-y-4 sm:space-y-6">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleRunTriage();
          }}
          className="relative flex items-center shadow-xs"
        >
          <div className="absolute left-3.5 sm:left-5 text-[#6b6b6b] pointer-events-none">
            <Globe className="w-4 h-4 sm:w-5 sm:h-5" />
          </div>

          <input
            type="text"
            value={currentUrl}
            onChange={(e) => setCurrentUrl(e.target.value)}
            placeholder="https://example.com/login"
            disabled={isScanning}
            className="w-full pl-10 sm:pl-14 pr-24 sm:pr-36 py-3.5 sm:py-5 bg-[#ffffff] border border-[rgb(0_0_0/10%)] rounded-xl sm:rounded-2xl text-[#040404] text-xs sm:text-base font-mono placeholder:text-[#6b6b6b] focus:outline-none focus:border-[#040404] focus:ring-1 focus:ring-[#040404] transition-all disabled:opacity-50"
          />

          <button
            type="submit"
            disabled={isScanning}
            onMouseEnter={() => sound.playHover()}
            className="absolute right-1.5 sm:right-3 px-3 sm:px-6 py-2 sm:py-3 rounded-lg sm:rounded-xl bg-[#101010] hover:bg-[#131313] text-white font-heading font-medium text-xs sm:text-sm transition-all flex items-center gap-1 sm:gap-1.5 active:scale-95 disabled:opacity-50 cursor-pointer shadow-sm"
          >
            {isScanning ? (
              <>
                <motion.div
                  animate={{ rotate: 360 }}
                  transition={{ repeat: Infinity, duration: 1, ease: 'linear' }}
                  className="w-3 h-3 sm:w-3.5 sm:h-3.5 border-2 border-white border-t-transparent rounded-full"
                />
                <span className="hidden xs:inline">Triaging...</span>
              </>
            ) : (
              <>
                <span>Triage</span>
                <ArrowRight className="w-3 h-3 sm:w-3.5 sm:h-3.5" />
              </>
            )}
          </button>
        </form>

        {/* Preflight Heuristic Status Pill */}
        {preflight && (
          <div className="flex items-center justify-between text-xs font-mono px-2">
            <div className="flex items-center gap-2">
              <span className="text-[#6b6b6b]">Pre-Flight:</span>
              <span
                className={
                  preflight.type === 'danger'
                    ? 'text-rose-600 font-medium'
                    : preflight.type === 'warning'
                    ? 'text-amber-600 font-medium'
                    : 'text-[#6b6b6b]'
                }
              >
                {preflight.label}
              </span>
            </div>
            <button
              onClick={() => {
                sound.playClick(600);
                onOpenInvariants();
              }}
              className="text-[#6b6b6b] hover:text-[#040404] transition-colors flex items-center gap-1"
            >
              <Sparkles className="w-3 h-3 text-[#101010]" />
              <span>8 Invariants</span>
            </button>
          </div>
        )}

        {/* Telemetry Progress Bar */}
        <AnimatePresence>
          {isScanning && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              className="overflow-hidden border border-[rgb(0_0_0/10%)] bg-[#f6f6f6] rounded-2xl p-5 space-y-3"
            >
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="text-[#040404] font-bold flex items-center gap-2">
                  <motion.span
                    animate={{ opacity: [0.3, 1, 0.3] }}
                    transition={{ repeat: Infinity, duration: 0.8 }}
                    className="w-2 h-2 rounded-full bg-[#101010] inline-block"
                  />
                  TELEMETRY PIPELINE: {scanSteps[scanStep]?.title}
                </span>
                <span className="text-[#6b6b6b]">Phase {scanStep + 1} of 5</span>
              </div>

              <div className="grid grid-cols-5 gap-1.5 h-1.5 bg-[#d9d9d9] rounded-full overflow-hidden p-0.5">
                {scanSteps.map((_, i) => (
                  <div
                    key={i}
                    className={`h-full rounded-full transition-all duration-300 ${
                      i <= scanStep ? 'bg-[#101010]' : 'bg-transparent'
                    }`}
                  />
                ))}
              </div>

              <p className="text-xs text-[#040404] font-mono">
                &gt; {scanSteps[scanStep]?.desc} <span className="font-bold">[{scanSteps[scanStep]?.code}]</span>
              </p>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* Sleek Benchmark Scenario Pills */}
      <div className="max-w-4xl mx-auto space-y-4">
        <div className="text-center text-xs font-mono text-[#6b6b6b] uppercase tracking-wider">
          Stage Demonstration Benchmarks:
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-2 sm:gap-2.5">
          {scenarioPills.map((pill, idx) => {
            const Icon = pill.icon;
            const isSelected = selectedScenarioKey === pill.key;
            return (
              <button
                key={pill.key}
                type="button"
                onClick={() => handleSelectScenario(pill.key, pill.url)}
                onMouseEnter={() => sound.playHover()}
                data-cursor-text="AUDIT"
                className={`p-3 rounded-xl border text-left transition-all group flex flex-col justify-between h-20 ${
                  idx === 4 ? 'col-span-2 sm:col-span-1' : ''
                } ${
                  isSelected
                    ? 'border-[#040404] bg-[#ffffff] shadow-sm'
                    : 'border-[rgb(0_0_0/10%)] bg-[#f6f6f6] hover:bg-[#ffffff] hover:border-[rgb(0_0_0/20%)]'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="text-xs font-heading font-bold text-[#040404] tracking-tight">{pill.label}</span>
                  <Icon className="w-3.5 h-3.5 text-[#6b6b6b] group-hover:text-[#040404] transition-colors" />
                </div>
                <div className="text-[10px] font-mono text-[#6b6b6b]">
                  {pill.sub}
                </div>
              </button>
            );
          })}
        </div>

        {/* Gallery Archive Teaser in Baseline Style */}
        <div className="flex flex-col sm:flex-row items-center justify-between p-4 rounded-2xl border border-[rgb(0_0_0/10%)] bg-[#f6f6f6] gap-3">
          <div className="flex items-center gap-2.5 text-left w-full sm:w-auto">
            <span className="font-mono text-xs font-bold text-[#040404]">(06) Gallery Archive</span>
            <span className="text-xs text-[#6b6b6b] hidden sm:inline">&bull; Explore curated attack surface benchmarks</span>
          </div>
          <button
            type="button"
            onClick={() => {
              sound.playClick(600);
              onOpenGallery?.();
            }}
            data-cursor-text="GALLERY"
            className="w-full sm:w-auto inline-flex items-center justify-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-[#ffffff] border border-[rgb(0_0_0/10%)] hover:bg-[#101010] hover:text-white text-xs font-mono text-[#040404] transition-all font-medium shadow-xs"
          >
            <span>Explore Case Gallery</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        {/* Quick Targets */}
        <div className="flex flex-wrap items-center justify-center gap-2 sm:gap-3 pt-2 text-[11px] text-[#6b6b6b] font-mono">
          <span>Edge Cases:</span>
          <button
            type="button"
            onClick={() => {
              setCurrentUrl('http://127.0.0.1:8000/admin');
              handleRunTriage(undefined, 'http://127.0.0.1:8000/admin');
            }}
            data-cursor-text="PROBE"
            className="hover:text-[#040404] underline"
          >
            127.0.0.1
          </button>
          <span>&bull;</span>
          <button
            type="button"
            onClick={() => {
              setCurrentUrl('https://admin:secret@bank-login.com');
              handleRunTriage(undefined, 'https://admin:secret@bank-login.com');
            }}
            data-cursor-text="PROBE"
            className="hover:text-[#040404] underline"
          >
            user:pass@host
          </button>
          <span>&bull;</span>
          <button
            type="button"
            onClick={() => {
              setCurrentUrl('https://github.com');
              handleRunTriage(undefined, 'https://github.com');
            }}
            data-cursor-text="PROBE"
            className="hover:text-[#040404] underline"
          >
            github.com
          </button>
        </div>
      </div>

      {/* Incroy Feature "Hi, Yes?" Interactive Consultation Briefing */}
      <div className="max-w-4xl mx-auto pt-6 border-t border-[rgb(0_0_0/10%)]">
        <div className="rounded-2xl border border-[rgb(0_0_0/10%)] bg-[#f6f6f6] p-6 sm:p-10 space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div>
              <span className="text-[11px] font-mono uppercase tracking-widest text-[#6b6b6b] font-bold">
                Assurance Advisory &bull; Continuous Partnership
              </span>
              <h2 className="text-3xl sm:text-5xl font-heading font-extrabold text-[#040404] tracking-[-0.03em] mt-1">
                Hi, Yes?
              </h2>
            </div>
            <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[#ffffff] border border-[rgb(0_0_0/10%)] text-xs font-mono text-[#040404] shrink-0 self-start sm:self-auto">
              <span className="w-2 h-2 rounded-full bg-emerald-500 inline-block" />
              <span>Certified Partner</span>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 sm:gap-8 pt-4 border-t border-[rgb(0_0_0/8%)]">
            <div className="space-y-3">
              <p className="text-xs sm:text-sm font-body text-[#6b6b6b] leading-relaxed">
                We engineer evidence-first web trust triage platforms that transform ambiguous transport locks into cryptographically provable security passports.
              </p>
              <div className="text-xs font-mono text-[#040404]">
                Adversarial validation with zero client-side browser exposure.
              </div>
            </div>

            <div className="space-y-2.5 font-mono text-xs">
              <div className="flex items-center justify-between py-1 border-b border-[rgb(0_0_0/8%)]">
                <span className="text-[#6b6b6b]">Advisory</span>
                <span className="font-bold text-[#040404]">hello@trusttrace.security</span>
              </div>
              <div className="flex items-center justify-between py-1 border-b border-[rgb(0_0_0/8%)]">
                <span className="text-[#6b6b6b]">Direct</span>
                <span className="font-bold text-[#040404]">+1 800 555-TRUST</span>
              </div>
              <div className="flex items-center justify-between py-1 border-b border-[rgb(0_0_0/8%)]">
                <span className="text-[#6b6b6b]">Signal Channel</span>
                <span className="font-bold text-[#040404]">@trusttrace.hq</span>
              </div>
              <div className="flex items-center justify-between py-1">
                <span className="text-[#6b6b6b]">Inquiries</span>
                <button
                  onClick={() => {
                    sound.playClick(600);
                    onOpenGallery?.();
                  }}
                  className="font-bold text-[#040404] underline hover:text-black flex items-center gap-1"
                >
                  <span>Book Architecture Review</span>
                  <ArrowRight className="w-3 h-3" />
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
