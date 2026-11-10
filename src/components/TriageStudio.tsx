import { useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import {
  Globe,
  ArrowRight,
  ShieldAlert,
  CheckCircle2,
  Clock,
  GitCompare,
  Ban,
  Sparkles,
  Shield,
  FileCheck,
  Check,
  AlertCircle,
  ExternalLink
} from 'lucide-react';
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
    <div className="space-y-20 sm:space-y-28">

      {/* ========================================================================= */}
      {/* SLIDE 01: EDITORIAL TITLE & HERO                                         */}
      {/* ========================================================================= */}
      <section className="text-center space-y-5 pt-4 sm:pt-8">
        <motion.div
          initial={{ opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          className="inline-flex items-center gap-2 text-[11px] sm:text-xs font-mono font-medium tracking-widest uppercase text-[#6B6B6B]"
        >
          <span>HACKATHON 2026 &bull; CYBERSECURITY</span>
        </motion.div>

        <motion.h1
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.05 }}
          className="text-4xl sm:text-6xl md:text-7xl lg:text-8xl font-serif text-[#040404] tracking-tight leading-[1.05]"
        >
          TRUSTRACE
        </motion.h1>

        <motion.p
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="font-serif text-[#6B6B6B] text-base sm:text-xl md:text-2xl max-w-2xl mx-auto leading-relaxed text-balance"
        >
          An evidence-first platform for web-risk triage. See the signals, inspect the evidence, know what remains unknown.
        </motion.p>
      </section>

      {/* ========================================================================= */}
      {/* TRIAGE CONSOLE & TELEMETRY PROGRESS                                       */}
      {/* ========================================================================= */}
      <section className="max-w-3xl mx-auto space-y-4 sm:space-y-6">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleRunTriage();
          }}
          className="relative flex items-center shadow-xs"
        >
          <div className="absolute left-3.5 sm:left-5 text-[#6B6B6B] pointer-events-none">
            <Globe className="w-4 h-4 sm:w-5 sm:h-5" />
          </div>

          <input
            type="text"
            value={currentUrl}
            onChange={(e) => setCurrentUrl(e.target.value)}
            placeholder="https://example.com/login"
            disabled={isScanning}
            className="w-full pl-10 sm:pl-14 pr-24 sm:pr-36 py-4 sm:py-5 bg-[#FFFFFF] border border-[#D9D9D9] rounded-xl sm:rounded-2xl text-[#040404] text-xs sm:text-base font-mono placeholder:text-[#6B6B6B] focus:outline-none focus:border-[#040404] focus:ring-1 focus:ring-[#040404] transition-all disabled:opacity-50"
          />

          <button
            type="submit"
            disabled={isScanning}
            onMouseEnter={() => sound.playHover()}
            className="absolute right-1.5 sm:right-3 px-4 sm:px-6 py-2.5 sm:py-3 rounded-lg sm:rounded-xl bg-[#040404] hover:bg-[#101010] text-white font-mono font-medium text-xs sm:text-sm transition-all flex items-center gap-1.5 active:scale-95 disabled:opacity-50 cursor-pointer shadow-sm"
          >
            {isScanning ? (
              <>
                <motion.div
                  animate={{ rotate: 360 }}
                  transition={{ repeat: Infinity, duration: 1, ease: 'linear' }}
                  className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full"
                />
                <span className="hidden xs:inline">Triaging...</span>
              </>
            ) : (
              <>
                <span>Triage</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </>
            )}
          </button>
        </form>

        {/* Preflight Heuristic Status Pill */}
        {preflight && (
          <div className="flex items-center justify-between text-xs font-mono px-2">
            <div className="flex items-center gap-2">
              <span className="text-[#6B6B6B]">Pre-Flight:</span>
              <span
                className={
                  preflight.type === 'danger'
                    ? 'text-rose-600 font-medium'
                    : preflight.type === 'warning'
                    ? 'text-amber-600 font-medium'
                    : 'text-[#6B6B6B]'
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
              className="text-[#6B6B6B] hover:text-[#040404] transition-colors flex items-center gap-1"
            >
              <Sparkles className="w-3 h-3 text-[#040404]" />
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
              className="overflow-hidden border border-[#D9D9D9] bg-[#F6F6F6] rounded-2xl p-5 space-y-3"
            >
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="text-[#040404] font-bold flex items-center gap-2">
                  <motion.span
                    animate={{ opacity: [0.3, 1, 0.3] }}
                    transition={{ repeat: Infinity, duration: 0.8 }}
                    className="w-2 h-2 rounded-full bg-[#040404] inline-block"
                  />
                  TELEMETRY PIPELINE: {scanSteps[scanStep]?.title}
                </span>
                <span className="text-[#6B6B6B]">Phase {scanStep + 1} of 5</span>
              </div>

              <div className="grid grid-cols-5 gap-1.5 h-1.5 bg-[#D9D9D9] rounded-full overflow-hidden p-0.5">
                {scanSteps.map((_, i) => (
                  <div
                    key={i}
                    className={`h-full rounded-full transition-all duration-300 ${
                      i <= scanStep ? 'bg-[#040404]' : 'bg-transparent'
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
      </section>

      {/* ========================================================================= */}
      {/* SLIDE 06: DEMO BENCHMARK FIXTURES & WALKTHROUGH GUIDE                    */}
      {/* ========================================================================= */}
      <section className="max-w-4xl mx-auto space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-baseline justify-between gap-2 border-b border-[#D9D9D9] pb-3">
          <div className="flex items-center gap-3">
            <span className="font-mono text-xs uppercase tracking-widest text-[#6B6B6B] font-semibold">
              DEMO &bull; 06
            </span>
            <span className="inline-block px-2 py-0.5 rounded-full bg-[#D9D9D9] text-[#040404] text-[10px] font-mono font-bold tracking-wider">
              DEMO FIXTURE
            </span>
          </div>
          <span className="text-xs font-mono text-[#6B6B6B]">Controlled scenario fixtures</span>
        </div>

        <div>
          <h2 className="text-2xl sm:text-4xl font-serif text-[#040404] tracking-tight">
            Lookalike first, then conflict
          </h2>
        </div>

        {/* 5 Scenario Buttons */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-2.5">
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
                className={`p-3.5 rounded-xl border text-left transition-all flex flex-col justify-between h-24 ${
                  idx === 4 ? 'col-span-2 sm:col-span-1' : ''
                } ${
                  isSelected
                    ? 'border-[#040404] bg-[#FFFFFF] shadow-sm ring-1 ring-[#040404]'
                    : 'border-[#D9D9D9] bg-[#F6F6F6] hover:bg-[#FFFFFF] hover:border-[#040404]'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="text-xs font-heading font-bold text-[#040404] tracking-tight">{pill.label}</span>
                  <Icon className="w-3.5 h-3.5 text-[#6B6B6B]" />
                </div>
                <div className="text-[10px] font-mono text-[#6B6B6B]">
                  {pill.sub}
                </div>
              </button>
            );
          })}
        </div>

        {/* Slide 06 Walkthrough Checklist */}
        <div className="rounded-2xl border border-[#D9D9D9] bg-[#F6F6F6] p-6 space-y-4">
          <div className="text-xs font-mono font-bold text-[#040404] uppercase tracking-wider">
            Rehearsed Evaluation Sequence:
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs font-mono text-[#040404]">
            <div className="flex items-start gap-2.5 p-2 rounded-lg bg-[#FFFFFF] border border-[#D9D9D9]">
              <span className="font-bold text-[#6B6B6B]">1.</span>
              <span>Select the IDN lookalike case</span>
            </div>
            <div className="flex items-start gap-2.5 p-2 rounded-lg bg-[#FFFFFF] border border-[#D9D9D9]">
              <span className="font-bold text-[#6B6B6B]">2.</span>
              <span>Show that valid TLS does not prove identity</span>
            </div>
            <div className="flex items-start gap-2.5 p-2 rounded-lg bg-[#FFFFFF] border border-[#D9D9D9]">
              <span className="font-bold text-[#6B6B6B]">3.</span>
              <span>Open a finding: evidence ID, timestamp &amp; coverage</span>
            </div>
            <div className="flex items-start gap-2.5 p-2 rounded-lg bg-[#FFFFFF] border border-[#D9D9D9]">
              <span className="font-bold text-[#6B6B6B]">4.</span>
              <span>Run conflicting-signals case &rarr; show INCONCLUSIVE</span>
            </div>
            <div className="flex items-start gap-2.5 p-2 rounded-lg bg-[#FFFFFF] border border-[#D9D9D9]">
              <span className="font-bold text-[#6B6B6B]">5.</span>
              <span>Run expired-certificate case &rarr; show CAUTION</span>
            </div>
            <div className="flex items-start gap-2.5 p-2 rounded-lg bg-[#FFFFFF] border border-[#D9D9D9]">
              <span className="font-bold text-[#6B6B6B]">6.</span>
              <span>Submit a report and show it remains unverified</span>
            </div>
          </div>
          <div className="text-xs font-mono text-[#6B6B6B] italic pt-2 border-t border-[#D9D9D9]">
            Say it plainly: This run uses controlled fixture evidence, not a live scan. We claim no accuracy figures beyond the fixture set.
          </div>
        </div>
      </section>

      {/* ========================================================================= */}
      {/* SLIDE 02: THE TRUST GAP                                                   */}
      {/* ========================================================================= */}
      <section className="max-w-4xl mx-auto space-y-6 pt-6 border-t border-[#D9D9D9]">
        <div className="flex items-center justify-between border-b border-[#D9D9D9] pb-3">
          <span className="font-mono text-xs uppercase tracking-widest text-[#6B6B6B] font-semibold">
            THE TRUST GAP &bull; 02
          </span>
          <span className="text-xs font-mono text-[#6B6B6B]">Transport vs Identity Breakdown</span>
        </div>

        <div className="space-y-3">
          <h2 className="text-3xl sm:text-5xl font-serif text-[#040404] tracking-tight">
            HTTPS is not proof of identity
          </h2>
          <p className="text-sm sm:text-base font-serif text-[#6B6B6B] leading-relaxed max-w-2xl">
            A padlock means the connection is encrypted. It does not mean the site represents the organisation it claims to be.
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 pt-2">
          <div className="p-6 rounded-2xl border border-[#D9D9D9] bg-[#F6F6F6] space-y-2">
            <div className="text-xs font-mono uppercase tracking-wider text-[#6B6B6B] font-bold">Vector 01</div>
            <h3 className="text-base font-serif font-bold text-[#040404]">Lookalike login</h3>
            <p className="text-xs font-body text-[#6B6B6B] leading-relaxed">
              A bank or college page on a lookalike domain, with a valid certificate.
            </p>
          </div>

          <div className="p-6 rounded-2xl border border-[#D9D9D9] bg-[#F6F6F6] space-y-2">
            <div className="text-xs font-mono uppercase tracking-wider text-[#6B6B6B] font-bold">Vector 02</div>
            <h3 className="text-base font-serif font-bold text-[#040404]">Fake payment link</h3>
            <p className="text-xs font-body text-[#6B6B6B] leading-relaxed">
              A payment request that sends money to the wrong party.
            </p>
          </div>

          <div className="p-6 rounded-2xl border border-[#D9D9D9] bg-[#F6F6F6] space-y-2">
            <div className="text-xs font-mono uppercase tracking-wider text-[#6B6B6B] font-bold">Vector 03</div>
            <h3 className="text-base font-serif font-bold text-[#040404]">Fake recruitment</h3>
            <p className="text-xs font-body text-[#6B6B6B] leading-relaxed">
              A job portal that collects documents, fees and passwords.
            </p>
          </div>
        </div>

        <div className="p-4 rounded-xl border border-[#D9D9D9] bg-[#FFFFFF] text-xs font-mono text-[#040404] text-center font-medium">
          One harm: people hand over credentials, money or documents to the wrong party.
        </div>
      </section>

      {/* ========================================================================= */}
      {/* SLIDE 03: CASE STUDY (eMudhra CA Failure)                                 */}
      {/* ========================================================================= */}
      <section className="max-w-4xl mx-auto space-y-6 pt-6 border-t border-[#D9D9D9]">
        <div className="flex items-center justify-between border-b border-[#D9D9D9] pb-3">
          <span className="font-mono text-xs uppercase tracking-widest text-[#6B6B6B] font-semibold">
            CASE STUDY &bull; 03
          </span>
          <span className="text-xs font-mono text-[#6B6B6B]">Empirical Evidence</span>
        </div>

        <div className="space-y-2">
          <h2 className="text-3xl sm:text-5xl font-serif text-[#040404] tracking-tight">
            eMudhra: a valid chain is not enough
          </h2>
          <p className="text-xs font-mono text-[#6B6B6B]">
            Real-world demonstration of certificate authority trust degradation
          </p>
        </div>

        {/* 3 Metric Callouts */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div className="p-6 rounded-2xl border border-[#D9D9D9] bg-[#F6F6F6] space-y-1">
            <div className="text-3xl sm:text-4xl font-serif font-bold text-[#040404]">8</div>
            <div className="text-xs font-mono text-[#6B6B6B]">intermediates: 6 TLS, 2 code-signing</div>
          </div>
          <div className="p-6 rounded-2xl border border-[#D9D9D9] bg-[#F6F6F6] space-y-1">
            <div className="text-2xl sm:text-3xl font-serif font-bold text-[#040404]">17 Oct 2026</div>
            <div className="text-xs font-mono text-[#6B6B6B]">Mozilla independently recovered the keys</div>
          </div>
          <div className="p-6 rounded-2xl border border-[#D9D9D9] bg-[#F6F6F6] space-y-1">
            <div className="text-3xl sm:text-4xl font-serif font-bold text-[#040404]">~18 mo</div>
            <div className="text-xs font-mono text-[#6B6B6B]">after the 30 April 2025 key ceremony</div>
          </div>
        </div>

        {/* Narrative Box */}
        <div className="p-6 rounded-2xl border border-[#D9D9D9] bg-[#F6F6F6] space-y-3 text-xs font-mono text-[#040404] leading-relaxed">
          <p>&bull; eMudhra says a flaw in that ceremony created a second, weak key set, and that the hierarchy had passed independent audits in two consecutive years.</p>
          <p>&bull; Google says no TLS certificates chaining to the six affected TLS intermediates were in Certificate Transparency logs before its block.</p>
          <p>&bull; Mozilla confirmed the key generation was flawed and shipped a Firefox block-list update within hours of the report.</p>
          <div className="pt-2 font-bold text-sm font-serif border-t border-[#D9D9D9]">
            Lesson: a valid certificate says little about who runs a site.
          </div>
          <div className="text-[10px] text-[#6B6B6B] font-mono">
            Sources: Mozilla Bug 2083449 &bull; eMudhra statement &bull; Google Security &bull; Mozilla Security Blog
          </div>
        </div>
      </section>

      {/* ========================================================================= */}
      {/* SLIDE 04: THE PRODUCT (EVIDENCE PASSPORT)                                  */}
      {/* ========================================================================= */}
      <section className="max-w-4xl mx-auto space-y-6 pt-6 border-t border-[#D9D9D9]">
        <div className="flex items-center justify-between border-b border-[#D9D9D9] pb-3">
          <div className="flex items-center gap-3">
            <span className="font-mono text-xs uppercase tracking-widest text-[#6B6B6B] font-semibold">
              THE PRODUCT &bull; 04
            </span>
            <span className="inline-block px-2.5 py-0.5 rounded-full bg-[#040404] text-white text-[10px] font-mono font-bold tracking-wider">
              IMPLEMENTED
            </span>
          </div>
          <span className="text-xs font-mono text-[#6B6B6B]">Core Architecture</span>
        </div>

        <div className="space-y-3">
          <h2 className="text-3xl sm:text-5xl font-serif text-[#040404] tracking-tight">
            TRUSTRACE: an evidence passport
          </h2>
          <p className="text-sm sm:text-base font-serif text-[#6B6B6B] leading-relaxed max-w-2xl">
            One report per URL that keeps four trust dimensions separate and says what it could not check.
          </p>
        </div>

        {/* 4 Separate Dimensions Bento */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div className="p-6 rounded-2xl border border-[#D9D9D9] bg-[#F6F6F6] space-y-2">
            <div className="text-xs font-mono font-bold text-[#6B6B6B] uppercase">01 // Identity</div>
            <h3 className="text-lg font-serif font-bold text-[#040404]">Organization Lineage</h3>
            <p className="text-xs font-body text-[#6B6B6B]">What evidence connects this domain to the claimed organisation?</p>
          </div>

          <div className="p-6 rounded-2xl border border-[#D9D9D9] bg-[#F6F6F6] space-y-2">
            <div className="text-xs font-mono font-bold text-[#6B6B6B] uppercase">02 // Certificate</div>
            <h3 className="text-lg font-serif font-bold text-[#040404]">Transport Encryption</h3>
            <p className="text-xs font-body text-[#6B6B6B]">What the TLS certificate shows, and what it does not.</p>
          </div>

          <div className="p-6 rounded-2xl border border-[#D9D9D9] bg-[#F6F6F6] space-y-2">
            <div className="text-xs font-mono font-bold text-[#6B6B6B] uppercase">03 // Behaviour</div>
            <h3 className="text-lg font-serif font-bold text-[#040404]">Page &amp; Redirect Dynamics</h3>
            <p className="text-xs font-body text-[#6B6B6B]">What the bounded checks observed about the page and redirects.</p>
          </div>

          <div className="p-6 rounded-2xl border border-[#D9D9D9] bg-[#F6F6F6] space-y-2">
            <div className="text-xs font-mono font-bold text-[#6B6B6B] uppercase">04 // Evidence Quality</div>
            <h3 className="text-lg font-serif font-bold text-[#040404]">Coverage &amp; Provenance</h3>
            <p className="text-xs font-body text-[#6B6B6B]">How complete, fresh and consistent the evidence is.</p>
          </div>
        </div>

        <div className="p-3.5 rounded-xl border border-[#D9D9D9] bg-[#FFFFFF] text-xs font-mono text-[#6B6B6B] text-center">
          Community reports sit alongside, and stay unverified until corroborated.
        </div>
      </section>

      {/* ========================================================================= */}
      {/* SLIDE 05: HOW IT DECIDES                                                  */}
      {/* ========================================================================= */}
      <section className="max-w-4xl mx-auto space-y-6 pt-6 border-t border-[#D9D9D9]">
        <div className="flex items-center justify-between border-b border-[#D9D9D9] pb-3">
          <div className="flex items-center gap-3">
            <span className="font-mono text-xs uppercase tracking-widest text-[#6B6B6B] font-semibold">
              HOW IT DECIDES &bull; 05
            </span>
            <span className="inline-block px-2.5 py-0.5 rounded-full bg-[#040404] text-white text-[10px] font-mono font-bold tracking-wider">
              IMPLEMENTED
            </span>
          </div>
          <span className="text-xs font-mono text-[#6B6B6B]">Deterministic Triage Logic</span>
        </div>

        <h2 className="text-3xl sm:text-5xl font-serif text-[#040404] tracking-tight">
          How a result is produced
        </h2>

        {/* 5 Sequential Steps */}
        <div className="space-y-3">
          <div className="p-4 rounded-xl border border-[#D9D9D9] bg-[#F6F6F6] flex items-center justify-between">
            <div className="flex items-center gap-3">
              <span className="font-mono font-bold text-xs text-[#6B6B6B]">1.</span>
              <div>
                <span className="font-serif font-bold text-sm text-[#040404]">URL safety boundary</span>
                <span className="text-xs font-mono text-[#6B6B6B] ml-2">&mdash; Rejects unsafe targets and guards redirects.</span>
              </div>
            </div>
            <span className="px-2 py-0.5 rounded-full bg-[#040404] text-white text-[9px] font-mono">IMPLEMENTED</span>
          </div>

          <div className="p-4 rounded-xl border border-[#D9D9D9] bg-[#F6F6F6] flex items-center justify-between">
            <div className="flex items-center gap-3">
              <span className="font-mono font-bold text-xs text-[#6B6B6B]">2.</span>
              <div>
                <span className="font-serif font-bold text-sm text-[#040404]">Bounded collectors</span>
                <span className="text-xs font-mono text-[#6B6B6B] ml-2">&mdash; Limited checks, or labelled fixtures in the demo.</span>
              </div>
            </div>
            <span className="px-2 py-0.5 rounded-full bg-[#040404] text-white text-[9px] font-mono">IMPLEMENTED</span>
          </div>

          <div className="p-4 rounded-xl border border-[#D9D9D9] bg-[#F6F6F6] flex items-center justify-between">
            <div className="flex items-center gap-3">
              <span className="font-mono font-bold text-xs text-[#6B6B6B]">3.</span>
              <div>
                <span className="font-serif font-bold text-sm text-[#040404]">Timestamped evidence</span>
                <span className="text-xs font-mono text-[#6B6B6B] ml-2">&mdash; Every finding has an ID and its provenance.</span>
              </div>
            </div>
            <span className="px-2 py-0.5 rounded-full bg-[#040404] text-white text-[9px] font-mono">IMPLEMENTED</span>
          </div>

          <div className="p-4 rounded-xl border border-[#D9D9D9] bg-[#F6F6F6] flex items-center justify-between">
            <div className="flex items-center gap-3">
              <span className="font-mono font-bold text-xs text-[#6B6B6B]">4.</span>
              <div>
                <span className="font-serif font-bold text-sm text-[#040404]">Deterministic rules</span>
                <span className="text-xs font-mono text-[#6B6B6B] ml-2">&mdash; A triage policy, not a trained model.</span>
              </div>
            </div>
            <span className="px-2 py-0.5 rounded-full bg-[#040404] text-white text-[9px] font-mono">IMPLEMENTED</span>
          </div>

          <div className="p-4 rounded-xl border border-[#D9D9D9] bg-[#F6F6F6] flex items-center justify-between">
            <div className="flex items-center gap-3">
              <span className="font-mono font-bold text-xs text-[#6B6B6B]">5.</span>
              <div>
                <span className="font-serif font-bold text-sm text-[#040404]">Passport and report</span>
                <span className="text-xs font-mono text-[#6B6B6B] ml-2">&mdash; Reasons, coverage and stated limitations.</span>
              </div>
            </div>
            <span className="px-2 py-0.5 rounded-full bg-[#040404] text-white text-[9px] font-mono">IMPLEMENTED</span>
          </div>
        </div>

        <div className="p-4 rounded-xl border border-[#D9D9D9] bg-[#FFFFFF] text-xs font-serif text-[#040404] leading-relaxed">
          When evidence conflicts or is missing, the result says so. It stays inconclusive instead of guessing. &ldquo;No threat observed&rdquo; never means &ldquo;safe&rdquo;.
        </div>
      </section>

      {/* ========================================================================= */}
      {/* SLIDE 07: STATUS (IMPLEMENTED VS PLANNED)                                 */}
      {/* ========================================================================= */}
      <section className="max-w-4xl mx-auto space-y-6 pt-6 border-t border-[#D9D9D9]">
        <div className="flex items-center justify-between border-b border-[#D9D9D9] pb-3">
          <span className="font-mono text-xs uppercase tracking-widest text-[#6B6B6B] font-semibold">
            STATUS &bull; 07
          </span>
          <span className="text-xs font-mono text-[#6B6B6B]">Capability Matrix</span>
        </div>

        <h2 className="text-3xl sm:text-5xl font-serif text-[#040404] tracking-tight">
          What exists today, and what does not
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="p-6 rounded-2xl border border-[#D9D9D9] bg-[#F6F6F6] space-y-4">
            <div className="flex items-center gap-2">
              <span className="px-2.5 py-0.5 rounded-full bg-[#040404] text-white text-[10px] font-mono font-bold">
                IMPLEMENTED
              </span>
              <span className="text-xs font-mono text-[#6B6B6B]">Live in Hackathon Build</span>
            </div>
            <ul className="space-y-2 text-xs font-mono text-[#040404]">
              <li className="flex items-center gap-2"><Check className="w-3.5 h-3.5 text-emerald-600 shrink-0" /> Python and FastAPI application</li>
              <li className="flex items-center gap-2"><Check className="w-3.5 h-3.5 text-emerald-600 shrink-0" /> Web UI for the URL-to-report journey</li>
              <li className="flex items-center gap-2"><Check className="w-3.5 h-3.5 text-emerald-600 shrink-0" /> URL safety boundary</li>
              <li className="flex items-center gap-2"><Check className="w-3.5 h-3.5 text-emerald-600 shrink-0" /> Bounded collector modules</li>
              <li className="flex items-center gap-2"><Check className="w-3.5 h-3.5 text-emerald-600 shrink-0" /> Evidence and provenance models</li>
              <li className="flex items-center gap-2"><Check className="w-3.5 h-3.5 text-emerald-600 shrink-0" /> Deterministic triage policy</li>
              <li className="flex items-center gap-2"><Check className="w-3.5 h-3.5 text-emerald-600 shrink-0" /> Community-report workflow</li>
              <li className="flex items-center gap-2"><Check className="w-3.5 h-3.5 text-emerald-600 shrink-0" /> Controlled demo fixtures</li>
            </ul>
          </div>

          <div className="p-6 rounded-2xl border border-[#D9D9D9] bg-[#F6F6F6] space-y-4">
            <div className="flex items-center gap-2">
              <span className="px-2.5 py-0.5 rounded-full bg-[#D9D9D9] text-[#040404] text-[10px] font-mono font-bold">
                PLANNED
              </span>
              <span className="text-xs font-mono text-[#6B6B6B]">Future Roadmap Milestones</span>
            </div>
            <ul className="space-y-2 text-xs font-mono text-[#6B6B6B]">
              <li className="flex items-center gap-2">&bull; Browser extension</li>
              <li className="flex items-center gap-2">&bull; Email-link scanning</li>
              <li className="flex items-center gap-2">&bull; CT, OCSP and CRL monitoring</li>
              <li className="flex items-center gap-2">&bull; Additional collectors</li>
              <li className="flex items-center gap-2">&bull; Shared threat feed</li>
              <li className="flex items-center gap-2">&bull; Research into ML signals</li>
            </ul>
          </div>
        </div>
      </section>

      {/* ========================================================================= */}
      {/* SLIDE 08: EVALUATION & RESPONSIBLE USE                                    */}
      {/* ========================================================================= */}
      <section className="max-w-4xl mx-auto space-y-6 pt-6 border-t border-[#D9D9D9]">
        <div className="flex items-center justify-between border-b border-[#D9D9D9] pb-3">
          <span className="font-mono text-xs uppercase tracking-widest text-[#6B6B6B] font-semibold">
            EVALUATION &amp; RESPONSIBLE USE &bull; 08
          </span>
          <span className="text-xs font-mono text-[#6B6B6B]">Ethical Grounding</span>
        </div>

        <div className="space-y-2">
          <h2 className="text-3xl sm:text-5xl font-serif text-[#040404] tracking-tight">
            Honest about what it can claim
          </h2>
          <p className="text-sm sm:text-base font-serif text-[#6B6B6B]">
            TRUSTRACE explains what the evidence supports&mdash;and what it cannot establish.
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div className="p-6 rounded-2xl border border-[#D9D9D9] bg-[#F6F6F6] space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono text-[#6B6B6B] font-bold">01</span>
              <span className="px-2 py-0.5 rounded-full bg-[#040404] text-white text-[9px] font-mono">NO ACCURACY CLAIM</span>
            </div>
            <h3 className="font-serif font-bold text-base text-[#040404]">Fixture-based evaluation</h3>
            <p className="text-xs font-mono text-[#6B6B6B] leading-relaxed">
              Controlled fixture scenarios support repeatable checks. No accuracy or real-world detection metrics are claimed.
            </p>
          </div>

          <div className="p-6 rounded-2xl border border-[#D9D9D9] bg-[#F6F6F6] space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono text-[#6B6B6B] font-bold">02</span>
              <span className="px-2 py-0.5 rounded-full bg-[#040404] text-white text-[9px] font-mono">SAFETY BOUNDARY</span>
            </div>
            <h3 className="font-serif font-bold text-base text-[#040404]">Safe URL processing</h3>
            <p className="text-xs font-mono text-[#6B6B6B] leading-relaxed">
              The URL safety boundary checks targets before collection. Redirect safeguards restrict where the app can fetch.
            </p>
          </div>

          <div className="p-6 rounded-2xl border border-[#D9D9D9] bg-[#F6F6F6] space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono text-[#6B6B6B] font-bold">03</span>
              <span className="px-2 py-0.5 rounded-full bg-[#040404] text-white text-[9px] font-mono">DISCLOSE LIMITS</span>
            </div>
            <h3 className="font-serif font-bold text-base text-[#040404]">Data transparency</h3>
            <p className="text-xs font-mono text-[#6B6B6B] leading-relaxed">
              A submission may include the URL and analyst notes (if provided). Storage, access, sharing and retention controls are not yet fully defined.
            </p>
          </div>

          <div className="p-6 rounded-2xl border border-[#D9D9D9] bg-[#F6F6F6] space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono text-[#6B6B6B] font-bold">04</span>
              <span className="px-2 py-0.5 rounded-full bg-[#040404] text-white text-[9px] font-mono">CORE PRINCIPLE</span>
            </div>
            <h3 className="font-serif font-bold text-base text-[#040404]">Honest outcomes</h3>
            <p className="text-xs font-mono text-[#6B6B6B] leading-relaxed">
              &ldquo;No threat observed&rdquo; does not mean &ldquo;safe&rdquo;. Missing/conflicting evidence can be inconclusive; reports stay unverified until corroborated.
            </p>
          </div>
        </div>
      </section>

      {/* ========================================================================= */}
      {/* SLIDE 09: NEXT STEP                                                       */}
      {/* ========================================================================= */}
      <section className="max-w-4xl mx-auto space-y-6 pt-6 border-t border-[#D9D9D9]">
        <div className="flex items-center justify-between border-b border-[#D9D9D9] pb-3">
          <span className="font-mono text-xs uppercase tracking-widest text-[#6B6B6B] font-semibold">
            NEXT STEP &bull; 09
          </span>
          <span className="text-xs font-mono text-[#6B6B6B]">Empirical Validation</span>
        </div>

        <h2 className="text-3xl sm:text-5xl font-serif text-[#040404] tracking-tight">
          Validate with real users first
        </h2>

        <div className="p-6 rounded-2xl border border-[#D9D9D9] bg-[#F6F6F6] space-y-3">
          <div className="text-xs font-mono font-bold text-[#6B6B6B] uppercase">Pilot Goal</div>
          <p className="text-sm font-serif text-[#040404] leading-relaxed">
            Test passports with a small group of students and job seekers, and learn whether the reasons and limitations are clear to them.
          </p>
          <p className="text-xs font-mono text-[#6B6B6B] leading-relaxed">
            Designed for everyday users facing lookalike logins, fake payment links and fake recruitment portals. This is intended impact, not measured impact.
          </p>
          <div className="pt-3 border-t border-[#D9D9D9] flex items-center gap-2">
            <span className="px-2 py-0.5 rounded-full bg-[#040404] text-white text-[9px] font-mono">PLANNED</span>
            <span className="text-xs font-mono text-[#6B6B6B]">Only if the pilot supports it: browser extension, email-link scanning &amp; richer certificate monitoring.</span>
          </div>
        </div>
      </section>

      {/* ========================================================================= */}
      {/* SLIDE 10: IN ONE LINE (INK SLIDE CONCLUSION)                              */}
      {/* ========================================================================= */}
      <section className="max-w-4xl mx-auto">
        <div className="rounded-3xl bg-[#101010] text-white p-8 sm:p-14 space-y-6 shadow-xl">
          <div className="flex items-center justify-between border-b border-white/10 pb-4">
            <span className="font-mono text-xs uppercase tracking-widest text-white/50 font-semibold">
              IN ONE LINE
            </span>
            <span className="font-mono text-xs text-white/50">
              TRUSTRACE &bull; 10
            </span>
          </div>

          <div className="space-y-4">
            <h2 className="text-4xl sm:text-6xl md:text-7xl font-serif text-white tracking-tight">
              Trust, explained.
            </h2>
            <p className="text-base sm:text-xl font-serif text-white/70 max-w-xl leading-relaxed">
              See the signals. Inspect the evidence. Know what remains unknown.
            </p>
          </div>

          <div className="pt-4 flex flex-wrap items-center gap-3">
            <button
              type="button"
              onClick={() => {
                sound.playClick(600);
                onOpenGallery?.();
              }}
              className="px-5 py-2.5 rounded-xl bg-white text-[#040404] font-mono text-xs font-bold hover:bg-[#F6F6F6] transition-colors inline-flex items-center gap-2"
            >
              <span>Explore Benchmark Gallery</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
            <button
              type="button"
              onClick={() => {
                sound.playClick(600);
                onOpenInvariants();
              }}
              className="px-5 py-2.5 rounded-xl border border-white/20 text-white font-mono text-xs font-medium hover:bg-white/10 transition-colors"
            >
              View 8 System Invariants
            </button>
          </div>
        </div>
      </section>

    </div>
  );
}
