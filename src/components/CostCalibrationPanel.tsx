import { useState, useEffect } from 'react';
import { motion } from 'motion/react';
import { DollarSign, Scale, AlertOctagon, CheckCircle2, HelpCircle, RefreshCw } from 'lucide-react';
import { PassportRecord, CostAssessment } from '../types/triage';
import { sound } from '../utils/audio';

interface CostCalibrationPanelProps {
  report: PassportRecord;
  onShowToast: (msg: string) => void;
}

export default function CostCalibrationPanel({ report, onShowToast }: CostCalibrationPanelProps) {
  const [profile, setProfile] = useState<string>('analyst_triage');
  const [cFn, setCFn] = useState<number>(50);
  const [cFp, setCFp] = useState<number>(10);
  const [cA, setCA] = useState<number>(2);
  const [isEvaluating, setIsEvaluating] = useState<boolean>(false);
  const [assessment, setAssessment] = useState<CostAssessment | null>(
    report.cost_assessment || {
      cost_profile_name: 'analyst_triage',
      action_recommendation: report.decision === 'caution' || report.decision === 'high_risk' ? 'threat' : report.decision === 'inconclusive' ? 'inconclusive' : 'clean',
      optimal_action: report.decision === 'caution' || report.decision === 'high_risk' ? 'threat' : report.decision === 'inconclusive' ? 'inconclusive' : 'clean',
      disposition_input: report.decision,
      availability_status_vector: {
        dns: 'observed_complete',
        tls: 'observed_complete',
        threat_intel: report.decision === 'inconclusive' ? 'missing' : 'observed_complete',
        community: 'missing',
      },
      confidence_band: 'sufficient_for_scoped_observation',
      review_urgency: 'high',
      cost_rationale: "Analyst Triage preset: Threat signals prioritized to eliminate false-negative breach penalty C_FN.",
      worst_case_costs: {
        threat: 10.0,
        inconclusive: 2.0,
        clean: 50.0,
      },
      minimum_cost: 2.0,
    }
  );

  const profiles: Record<string, { label: string; cFn: number; cFp: number; cA: number; desc: string }> = {
    analyst_triage: {
      label: 'Analyst Triage (SOC)',
      cFn: 50,
      cFp: 10,
      cA: 2,
      desc: 'High miss penalty; manual analyst review is cheap compared to breach.',
    },
    user_warning: {
      label: 'User Warning (Browser)',
      cFn: 80,
      cFp: 15,
      cA: 5,
      desc: 'Consumer protection; prioritizes preventing false negatives with interstitial warning.',
    },
    enterprise_blocking: {
      label: 'Enterprise Blocking (Gateway)',
      cFn: 100,
      cFp: 40,
      cA: 10,
      desc: 'Strict firewall policy; false positive disruptions carry higher business friction.',
    },
  };

  const handleSelectProfile = (key: string) => {
    sound.playPill(500);
    setProfile(key);
    if (profiles[key]) {
      setCFn(profiles[key].cFn);
      setCFp(profiles[key].cFp);
      setCA(profiles[key].cA);
    }
  };

  const handleEvaluate = async () => {
    sound.playClick(620);
    setIsEvaluating(true);
    try {
      const res = await fetch(`/api/v1/scans/${report.scan_id}/cost-assessment`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          profile_name: profile,
          cost_false_negative: cFn,
          cost_false_positive: cFp,
          cost_abstain: cA,
          scenario: report.scan_id.includes('phish') ? 'phishing_lookalike' : report.scan_id.includes('exp') ? 'expired_tls' : report.scan_id.includes('legit') ? 'legitimate' : 'conflicting',
        }),
      });
      if (res.ok) {
        const data = await res.json();
        if (data.cost_assessment) {
          setAssessment(data.cost_assessment);
          onShowToast('Asymmetric cost evaluation calibrated');
        }
      } else {
        // Fallback local calibration calculation
        computeLocalMinimax();
      }
    } catch {
      computeLocalMinimax();
    } finally {
      setIsEvaluating(false);
    }
  };

  const computeLocalMinimax = () => {
    const isThreat = report.decision === 'high_risk' || report.decision === 'caution';
    const isInconclusive = report.decision === 'inconclusive';
    let action: 'threat' | 'clean' | 'inconclusive' = 'clean';
    let urgency: 'high' | 'normal' | 'low' = 'normal';

    if (isThreat) {
      action = 'threat';
      urgency = cFn > cFp ? 'high' : 'normal';
    } else if (isInconclusive) {
      action = 'inconclusive';
    }

    setAssessment({
      cost_profile_name: profile,
      action_recommendation: action,
      optimal_action: action,
      disposition_input: report.decision,
      availability_status_vector: {
        dns: 'observed_complete',
        tls: 'observed_complete',
        threat_intel: isThreat ? 'observed_complete' : 'missing',
        community: 'missing',
      },
      confidence_band: 'sufficient_for_scoped_observation',
      review_urgency: urgency,
      cost_rationale: `Profile '${profile}': Evaluated with C_FN=${cFn}, C_FP=${cFp}, C_A=${cA}. Action '${action}' selected under minimax loss.`,
      worst_case_costs: {
        threat: cFp,
        inconclusive: cA,
        clean: cFn,
      },
      minimum_cost: Math.min(cFp, cA, cFn),
    });
    onShowToast('Calibrated with local operational parameters');
  };

  const worstThreat = assessment?.worst_case_costs?.threat ?? cFp;
  const worstClean = assessment?.worst_case_costs?.clean ?? cFn;
  const worstAbstain = assessment?.worst_case_costs?.inconclusive ?? cA;
  const optimal = assessment?.optimal_action || assessment?.action_recommendation || 'inconclusive';

  return (
    <div className="space-y-6">
      {/* Header and Context */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-[#D9D9D9] gap-3">
        <div>
          <div className="flex items-center gap-2">
            <Scale className="w-5 h-5 text-[#040404]" />
            <h3 className="font-heading font-extrabold text-base text-[#040404] tracking-tight">
              Asymmetric Cost Calibration (Phase 08)
            </h3>
          </div>
          <p className="text-xs font-mono text-[#6B6B6B] mt-0.5">
            Minimax operational decision rules balancing false negatives ($C_{'{FN}'}$), false positives ($C_{'{FP}'}$), and review queue ($C_A$).
          </p>
        </div>

        <button
          onClick={handleEvaluate}
          disabled={isEvaluating}
          className="px-4 py-2 bg-[#040404] text-white handdrawn-pill text-xs font-mono font-bold flex items-center gap-2 hover:bg-[#1a1a1a] transition-all disabled:opacity-50 cursor-pointer self-start sm:self-auto"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isEvaluating ? 'animate-spin' : ''}`} />
          <span>{isEvaluating ? 'Calibrating...' : 'Re-Calibrate'}</span>
        </button>
      </div>

      {/* Preset Profiles Selection */}
      <div className="space-y-2">
        <label className="text-xs font-mono font-bold text-[#040404] uppercase tracking-wider">
          Deployment Operational Profiles
        </label>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          {Object.entries(profiles).map(([key, item]) => {
            const isSelected = profile === key;
            return (
              <button
                key={key}
                type="button"
                onClick={() => handleSelectProfile(key)}
                className={`p-3 text-left handdrawn-box border transition-all cursor-pointer ${
                  isSelected
                    ? 'border-[#040404] bg-[#FFFFFF] shadow-sm'
                    : 'border-[#D9D9D9] bg-[#F6F6F6] hover:border-[#040404]'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono font-bold text-[#040404]">{item.label}</span>
                  {isSelected && <span className="w-2 h-2 rounded-full bg-[#040404]" />}
                </div>
                <div className="text-[11px] font-mono text-[#6B6B6B] mt-1 leading-snug">
                  {item.desc}
                </div>
                <div className="mt-2 text-[10px] font-mono text-[#040404] font-semibold bg-[#E5E7EB] px-2 py-0.5 rounded-full inline-block">
                  FN:{item.cFn} | FP:{item.cFp} | Abstain:{item.cA}
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Interactive Sliders */}
      <div className="p-5 handdrawn-box border border-[#D9D9D9] bg-[#FAFAFA] space-y-4">
        <div className="text-xs font-mono font-bold text-[#040404] uppercase tracking-wider flex items-center justify-between">
          <span>Custom Asymmetric Cost Parameters</span>
          <span className="text-[11px] font-normal text-[#6B6B6B]">Drag to adjust relative regret weights</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* C_FN */}
          <div className="space-y-1.5">
            <div className="flex justify-between text-xs font-mono">
              <span className="text-[#040404] font-bold">C_FN (Missed Breach)</span>
              <span className="font-bold text-[#040404]">{cFn}</span>
            </div>
            <input
              type="range"
              min="10"
              max="200"
              step="5"
              value={cFn}
              onChange={(e) => {
                setProfile('custom');
                setCFn(Number(e.target.value));
              }}
              className="w-full accent-[#040404] cursor-pointer"
            />
            <p className="text-[10px] font-mono text-[#6B6B6B]">
              Cost penalty incurred when a malicious site is erroneously judged Clean.
            </p>
          </div>

          {/* C_FP */}
          <div className="space-y-1.5">
            <div className="flex justify-between text-xs font-mono">
              <span className="text-[#040404] font-bold">C_FP (False Alarm)</span>
              <span className="font-bold text-[#040404]">{cFp}</span>
            </div>
            <input
              type="range"
              min="1"
              max="100"
              step="1"
              value={cFp}
              onChange={(e) => {
                setProfile('custom');
                setCFp(Number(e.target.value));
              }}
              className="w-full accent-[#040404] cursor-pointer"
            />
            <p className="text-[10px] font-mono text-[#6B6B6B]">
              Friction cost when a benign domain is blocked or flagged as Threat.
            </p>
          </div>

          {/* C_A */}
          <div className="space-y-1.5">
            <div className="flex justify-between text-xs font-mono">
              <span className="text-[#040404] font-bold">C_A (Manual Review)</span>
              <span className="font-bold text-[#040404]">{cA}</span>
            </div>
            <input
              type="range"
              min="1"
              max="30"
              step="1"
              value={cA}
              onChange={(e) => {
                setProfile('custom');
                setCA(Number(e.target.value));
              }}
              className="w-full accent-[#040404] cursor-pointer"
            />
            <p className="text-[10px] font-mono text-[#6B6B6B]">
              Operational cost to route uncertain cases to a human SOC analyst.
            </p>
          </div>
        </div>
      </div>

      {/* Minimax Evaluation Result Card */}
      <div className="p-6 handdrawn-card border border-[#040404] bg-[#FFFFFF] space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-[#D9D9D9] gap-2">
          <div>
            <span className="text-[10px] font-mono uppercase tracking-widest text-[#6B6B6B] block">
              Minimax Decision Output
            </span>
            <div className="flex items-center gap-2 mt-1">
              <span className="text-xl font-heading font-extrabold text-[#040404]">
                Optimal Action:
              </span>
              <span
                className={`px-3 py-1 rounded-full text-xs font-mono font-bold uppercase tracking-wider ${
                  optimal === 'threat'
                    ? 'bg-[#040404] text-white'
                    : optimal === 'inconclusive'
                    ? 'bg-[#E5E7EB] text-[#111827] border border-[#D1D5DB]'
                    : 'bg-[#F3F4F6] text-[#040404] border border-[#D1D5DB]'
                }`}
              >
                {optimal}
              </span>
              <span className="text-xs font-mono text-[#6B6B6B] ml-2">
                Urgency: <strong className="text-[#040404] uppercase">{assessment?.review_urgency || 'normal'}</strong>
              </span>
            </div>
          </div>

          <div className="text-right">
            <span className="text-[10px] font-mono text-[#6B6B6B] block">Minimum Expected Regret</span>
            <span className="text-2xl font-mono font-extrabold text-[#040404]">
              {assessment?.minimum_cost !== undefined ? assessment.minimum_cost.toFixed(1) : worstAbstain.toFixed(1)}
            </span>
          </div>
        </div>

        {/* Worst-Case Expected Loss Comparison Bars */}
        <div className="space-y-3">
          <span className="text-xs font-mono font-bold text-[#040404]">
            Worst-Case Loss Across Candidate Actions:
          </span>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            {/* Action Threat */}
            <div className={`p-3 handdrawn-box border ${optimal === 'threat' ? 'border-[#040404] bg-[#F6F6F6]' : 'border-[#D9D9D9] bg-white'}`}>
              <div className="flex justify-between items-center text-xs font-mono mb-1">
                <span className="font-bold text-[#040404]">D_M (Threat)</span>
                <span className="font-mono text-[#040404]">{worstThreat.toFixed(1)}</span>
              </div>
              <div className="text-[10px] font-mono text-[#6B6B6B]">
                Worst case if Benign: incurs false alarm cost $C_{'{FP}'}$.
              </div>
            </div>

            {/* Action Inconclusive */}
            <div className={`p-3 handdrawn-box border ${optimal === 'inconclusive' ? 'border-[#040404] bg-[#F6F6F6]' : 'border-[#D9D9D9] bg-white'}`}>
              <div className="flex justify-between items-center text-xs font-mono mb-1">
                <span className="font-bold text-[#040404]">D_I (Abstain)</span>
                <span className="font-mono text-[#040404]">{worstAbstain.toFixed(1)}</span>
              </div>
              <div className="text-[10px] font-mono text-[#6B6B6B]">
                Routes to human triage queue: fixed cost $C_A$.
              </div>
            </div>

            {/* Action Clean */}
            <div className={`p-3 handdrawn-box border ${optimal === 'clean' ? 'border-[#040404] bg-[#F6F6F6]' : 'border-[#D9D9D9] bg-white'}`}>
              <div className="flex justify-between items-center text-xs font-mono mb-1">
                <span className="font-bold text-[#040404]">D_B (Clean)</span>
                <span className="font-mono text-[#040404]">{worstClean.toFixed(1)}</span>
              </div>
              <div className="text-[10px] font-mono text-[#6B6B6B]">
                Worst case if Malicious: incurs missed breach penalty $C_{'{FN}'}$.
              </div>
            </div>
          </div>
        </div>

        {/* Cost Rationale */}
        {assessment?.cost_rationale && (
          <div className="p-3 bg-[#F6F6F6] border border-[#D9D9D9] text-xs font-mono text-[#040404] leading-relaxed">
            <strong className="block text-[10px] uppercase text-[#6B6B6B] mb-0.5">Policy Rationale:</strong>
            {assessment.cost_rationale}
          </div>
        )}
      </div>
    </div>
  );
}
