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
  Layers,
  FileCheck,
  Check,
  AlertTriangle,
  ArrowUpRight
} from 'lucide-react';
import { PassportRecord } from '../types/triage';
import { CANONICAL_SCENARIOS, evaluateCustomTargetLocally } from '../data/scenarios';
import { sound } from '../utils/audio';
import LiquidCard from './LiquidCard';
import LiquidButton from './LiquidButton';
import { triggerLiquidWarp } from './LiquidFilter';
import { useHanddrawnBorder } from '../utils/handdrawn';

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

  // Random hand-drawn border generators for input and telemetry container
  const { style: inputBorder, morphBorder: morphInputBorder } = useHanddrawnBorder('input');
  const { style: telemetryBorder, morphBorder: morphTelemetryBorder } = useHanddrawnBorder('box');

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
    triggerLiquidWarp(14);
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
    sound.playPill(540);
    triggerLiquidWarp(10);
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
      badge: 'HIGH RISK',
      icon: ShieldAlert,
    },
    {
      key: 'legitimate',
      url: 'https://example.com',
      label: 'Legitimate Domain',
      sub: 'Verified Entity',
      badge: 'VERIFIED',
      icon: CheckCircle2,
    },
    {
      key: 'expired_tls',
      url: 'https://legacy-portal.internal-corp.net',
      label: 'Expired TLS',
      sub: 'Hygiene Warning',
      badge: 'CAUTION',
      icon: Clock,
    },
    {
      key: 'conflicting',
      url: 'https://disputed-exchange.io',
      label: 'Conflicting Intel',
      sub: 'Safe Abstention',
      badge: 'INCONCLUSIVE',
      icon: GitCompare,
    },
    {
      key: 'ssrf_blocked',
      url: 'http://169.254.169.254/latest/meta-data',
      label: 'SSRF Target',
      sub: 'Zero Egress Halt',
      badge: 'HALTED',
      icon: Ban,
    },
  ];

  const dimensions = [
    {
      id: '01',
      title: 'Identity & Delegation',
      desc: 'Authoritative WHOIS/RDAP ownership, registrars, and entity corroboration beyond transport domain validation.',
      tag: 'RDAP-AUTH',
    },
    {
      id: '02',
      title: 'Transport Encryption',
      desc: 'Cryptographic X.509 chain validity, SAN attributes, key length, and revocation transparency checks.',
      tag: 'TLS-PROBE',
    },
    {
      id: '03',
      title: 'Passive Behaviour',
      desc: 'Zero-script network observation, redirect hop boundary checks, and HTTP response header classification.',
      tag: 'ZERO-SCRIPT',
    },
    {
      id: '04',
      title: 'Evidence Provenance',
      desc: 'Cryptographic finding IDs, UTC timestamps, observation confidence, and explicit disclosure of unknown signals.',
      tag: 'DETERMINISTIC',
    },
  ];

  return (
    <div className="space-y-16 sm:space-y-24">

      {/* ========================================================================= */}
      {/* WEB APPLICATION HERO                                                      */}
      {/* ========================================================================= */}
      <section className="text-center space-y-5 pt-4 sm:pt-8">
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4 }}
          className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[#F6F6F6] border border-[#D9D9D9] text-[11px] font-mono text-[#6B6B6B]"
        >
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
          <span>PASSIVE WEB-RISK TRIAGE ENGINE</span>
        </motion.div>

        <motion.h1
          initial={{ opacity: 0, y: 14 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.05 }}
          className="text-4xl sm:text-6xl md:text-7xl font-serif text-[#040404] tracking-tight leading-[1.08]"
        >
          Evidence-First Web Trust Triage
        </motion.h1>

        <motion.p
          initial={{ opacity: 0, y: 14 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.1 }}
          className="font-serif text-[#1F2937] text-base sm:text-xl max-w-2xl mx-auto leading-relaxed text-balance font-normal"
        >
          Inspect TLS transport cryptography, authoritative DNS delegation, identity provenance, and adversarial homoglyphs with deterministic boundaries.
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
            onFocus={() => {
              sound.playHover();
              triggerLiquidWarp(6);
              morphInputBorder();
            }}
            style={{
              borderRadius: inputBorder.borderRadius,
              borderWidth: inputBorder.borderWidth,
            }}
            className="w-full pl-10 sm:pl-14 pr-26 sm:pr-38 py-4 sm:py-5 bg-[#FFFFFF] border border-[#D9D9D9] text-[#040404] text-xs sm:text-base font-mono placeholder:text-[#6B6B6B] focus:outline-none focus:border-[#040404] focus:ring-1 focus:ring-[#040404] transition-all disabled:opacity-50 shadow-xs"
          />

          <div className="absolute right-1.5 sm:right-3">
            <LiquidButton
              type="submit"
              disabled={isScanning}
              cursorBadge="TRIAGE"
              className="px-4 sm:px-6 py-2.5 sm:py-3 rounded-lg sm:rounded-xl text-xs sm:text-sm font-medium"
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
            </LiquidButton>
          </div>
        </form>

        {/* Preflight Heuristic Status Pill */}
        {preflight && (
          <div className="flex items-center justify-between text-xs sm:text-sm font-mono px-2">
            <div className="flex items-center gap-2">
              <span className="text-[#374151] font-semibold">Pre-Flight:</span>
              <span
                className={
                  preflight.type === 'danger'
                    ? 'text-rose-700 font-bold'
                    : preflight.type === 'warning'
                    ? 'text-amber-700 font-bold'
                    : 'text-[#1F2937] font-semibold'
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
              className="text-[#040404] hover:underline font-semibold transition-colors flex items-center gap-1 cursor-pointer"
            >
              <Sparkles className="w-3.5 h-3.5 text-[#040404]" />
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
              style={{
                borderRadius: telemetryBorder.borderRadius,
                borderWidth: telemetryBorder.borderWidth,
              }}
              className="overflow-hidden border border-[#D9D9D9] bg-[#F6F6F6] p-5 space-y-3"
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
      {/* CANONICAL SCENARIOS BENCHMARK MATRIX (LIQUID CARDS)                      */}
      {/* ========================================================================= */}
      <section className="max-w-4xl mx-auto space-y-5">
        <div className="flex items-center justify-between border-b border-[#D9D9D9] pb-3">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-[#040404]" />
            <span className="font-mono text-xs uppercase tracking-widest text-[#040404] font-bold">
              Benchmark Scenarios
            </span>
          </div>
          <span className="text-xs font-mono text-[#6B6B6B]">Controlled Security Cases</span>
        </div>

        {/* 5 Scenario Liquid Cards */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3.5">
          {scenarioPills.map((pill, idx) => {
            const Icon = pill.icon;
            const isSelected = selectedScenarioKey === pill.key;

            const badgeBg =
              pill.badge === 'HIGH RISK'
                ? 'bg-[#040404] text-white border border-[#040404]'
                : pill.badge === 'VERIFIED'
                ? 'bg-emerald-800 text-white border border-emerald-900'
                : pill.badge === 'CAUTION'
                ? 'bg-amber-600 text-white border border-amber-700'
                : pill.badge === 'INCONCLUSIVE'
                ? 'bg-zinc-800 text-white border border-zinc-900'
                : 'bg-rose-700 text-white border border-rose-800';

            return (
              <LiquidCard
                key={pill.key}
                onClick={() => handleSelectScenario(pill.key, pill.url)}
                cursorBadge="AUDIT"
                soundType="pill"
                enableTilt={true}
                enableLiquidWarp={false}
                variant="box"
                className={`p-4 sm:p-4.5 border text-left flex flex-col justify-between min-h-[148px] cursor-pointer select-none transition-all ${
                  idx === 4 ? 'col-span-2 sm:col-span-1' : ''
                } ${
                  isSelected
                    ? 'border-[#040404] bg-[#FFFFFF] ring-2 ring-[#040404] shadow-md'
                    : 'border-[#D9D9D9] bg-[#F6F6F6] hover:bg-[#FFFFFF] hover:border-[#040404]'
                }`}
              >
                <div className="flex items-start justify-between gap-1.5">
                  <span className="text-sm font-heading font-extrabold text-[#040404] tracking-tight leading-snug">
                    {pill.label}
                  </span>
                  <Icon className="w-4 h-4 text-[#040404] shrink-0 mt-0.5" />
                </div>
                <div className="space-y-2.5 pt-2">
                  <div className="text-xs sm:text-[13px] font-sans font-semibold text-[#1F2937] leading-snug">
                    {pill.sub}
                  </div>
                  <div>
                    <span className={`inline-block px-2.5 py-1 rounded-full text-[10px] font-mono font-bold tracking-wider shadow-xs ${badgeBg}`}>
                      {pill.badge}
                    </span>
                  </div>
                </div>
              </LiquidCard>
            );
          })}
        </div>
      </section>

      {/* ========================================================================= */}
      {/* 4 UNBUNDLED TRUST DIMENSIONS (LIQUID BENTO GRID)                         */}
      {/* ========================================================================= */}
      <section className="max-w-4xl mx-auto space-y-6">
        <div className="flex items-center justify-between border-b border-[#D9D9D9] pb-3">
          <div className="flex items-center gap-2">
            <Layers className="w-4 h-4 text-[#040404]" />
            <span className="font-mono text-xs uppercase tracking-widest text-[#040404] font-bold">
              Unbundled Trust Dimensions
            </span>
          </div>
          <span className="text-xs font-mono text-[#374151] font-semibold">Deterministic Multi-Signal Triage</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          {dimensions.map((dim) => (
            <LiquidCard
              key={dim.id}
              cursorBadge="EXPLORE"
              soundType="liquid"
              enableTilt={true}
              enableLiquidWarp={false}
              variant="card"
              className="p-6 border border-[#D9D9D9] bg-[#F6F6F6] space-y-3 cursor-pointer hover:border-[#040404] hover:bg-[#FFFFFF]"
            >
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono font-extrabold text-[#040404] uppercase tracking-wider">
                  {dim.id} // {dim.title}
                </span>
                <span className="px-2.5 py-1 rounded-full bg-[#040404] text-white text-[10px] font-mono font-bold tracking-wide">
                  {dim.tag}
                </span>
              </div>
              <h3 className="text-xl font-heading font-extrabold text-[#040404] tracking-tight">
                {dim.title}
              </h3>
              <p className="text-sm font-sans font-medium text-[#1F2937] leading-relaxed">
                {dim.desc}
              </p>
            </LiquidCard>
          ))}
        </div>
      </section>

      {/* ========================================================================= */}
      {/* CORE CAPABILITIES & INVARIANTS CALLOUT                                    */}
      {/* ========================================================================= */}
      <section className="max-w-4xl mx-auto">
        <LiquidCard
          cursorBadge="INVARIANTS"
          soundType="liquid"
          enableTilt={false}
          variant="card"
          className="bg-[#101010] text-white p-8 sm:p-12 space-y-6 shadow-xl"
        >
          <div className="flex items-center justify-between border-b border-white/10 pb-4">
            <span className="font-mono text-xs uppercase tracking-widest text-white/50 font-semibold">
              SYSTEM GUARANTEES
            </span>
            <span className="font-mono text-xs text-white/50">
              8 CONTRACT INVARIANTS
            </span>
          </div>

          <div className="space-y-3">
            <h2 className="text-3xl sm:text-5xl font-serif text-white tracking-tight">
              Deterministic Safety &amp; Evidence Rigor
            </h2>
            <p className="text-sm sm:text-base font-serif text-white/70 max-w-2xl leading-relaxed">
              Every decision is bound by invariant rules: zero browser DOM rendering, mandatory IP pinning against DNS rebinding, unverified community reports, and unambiguous abstention on conflicting evidence.
            </p>
          </div>

          <div className="pt-2 flex flex-wrap items-center gap-3">
            <LiquidButton
              variant="secondary"
              cursorBadge="GALLERY"
              onClick={() => onOpenGallery?.()}
              className="px-5 py-2.5 rounded-xl font-bold text-xs"
            >
              <span>Explore Case Gallery</span>
              <ArrowUpRight className="w-3.5 h-3.5" />
            </LiquidButton>

            <LiquidButton
              variant="ghost"
              cursorBadge="EXPLORE"
              onClick={() => onOpenInvariants()}
              className="px-5 py-2.5 rounded-xl text-white/90 border border-white/20 hover:bg-white/10 text-xs"
            >
              View All 8 Invariants
            </LiquidButton>
          </div>
        </LiquidCard>
      </section>

    </div>
  );
}
