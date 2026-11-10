import React, { useState } from 'react';
import { motion } from 'motion/react';
import { Play, Sparkles } from 'lucide-react';
import { INVARIANTS } from '../data/invariants';
import { sound } from '../utils/audio';

interface InvariantsExplorerProps {
  onSelectScenario: (scenarioKey: string) => void;
}

export default function InvariantsExplorer({ onSelectScenario }: InvariantsExplorerProps) {
  const [activeCategory, setActiveCategory] = useState<string>('all');

  const categories = [
    { id: 'all', label: 'All 8 Invariants' },
    { id: 'core', label: 'Core Thesis' },
    { id: 'security', label: 'Intake & Security' },
    { id: 'coverage', label: 'Coverage Math' },
    { id: 'evidence', label: 'Evidence & Lineage' },
    { id: 'community', label: 'Community & Sybil' },
  ];

  const filtered = INVARIANTS.filter(
    (inv) => activeCategory === 'all' || inv.category === activeCategory
  );

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="border-b border-[rgb(0_0_0/10%)] pb-6">
        <div className="flex items-center gap-2 mb-1.5">
          <span className="text-xs font-mono font-bold text-[#6b6b6b] uppercase tracking-widest">
            Formal Specifications
          </span>
          <span aria-hidden="true" className="text-[#cdcdcd]">/</span>
          <span className="text-xs font-mono text-[#040404] font-semibold">
            Mathematical &amp; Policy Invariants
          </span>
        </div>
        <h2 className="text-2xl sm:text-3xl font-heading font-extrabold text-[#040404] tracking-[-0.03em] leading-display">
          The 8 Architectural Invariants
        </h2>
        <p className="text-[#6b6b6b] text-xs sm:text-sm mt-2 max-w-2xl leading-relaxed font-body">
          Every evaluation emitted by TRUSTTRACE adheres strictly to immutable mathematical proofs. No untracked checks, no fake authority from transport locks, and zero active browser exploitation surface.
        </p>

        {/* Category Filter Pills */}
        <div className="flex flex-wrap items-center gap-2 mt-5">
          {categories.map((cat) => (
            <button
              key={cat.id}
              onClick={() => {
                sound.playClick(600);
                setActiveCategory(cat.id);
              }}
              data-cursor-text="FILTER"
              className={`px-3 py-1.5 rounded-lg text-xs font-mono transition-colors font-medium ${
                activeCategory === cat.id
                  ? 'bg-[#101010] text-white border border-[#101010] font-bold shadow-xs'
                  : 'bg-[#ffffff] text-[#6b6b6b] hover:text-[#040404] hover:bg-[#f6f6f6] border border-[rgb(0_0_0/10%)]'
              }`}
            >
              {cat.label}
            </button>
          ))}
        </div>
      </div>

      {/* Invariants Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {filtered.map((inv) => (
          <div
            key={inv.id}
            data-cursor-text="INVARIANT"
            className="p-5 rounded-2xl border border-[rgb(0_0_0/10%)] bg-[#f6f6f6] space-y-3 relative group hover:border-[rgb(0_0_0/20%)] hover:bg-[#ffffff] transition-all flex flex-col justify-between"
          >
            <div className="space-y-2.5">
              <div className="flex items-center justify-between">
                <span className="px-2.5 py-1 rounded bg-[#ffffff] border border-[rgb(0_0_0/10%)] text-xs font-mono font-bold text-[#040404]">
                  {inv.id}
                </span>
                <span className="text-[10px] font-mono uppercase tracking-wider text-[#6b6b6b] font-bold">
                  {inv.category}
                </span>
              </div>

              <h3 className="text-base font-bold text-[#040404] tracking-[-0.03em] font-heading">
                {inv.title}
              </h3>

              <p className="text-xs text-[#6b6b6b] leading-relaxed font-body">
                {inv.summary}
              </p>

              {inv.mathematical_rule && (
                <div className="p-2.5 rounded-xl bg-[#ffffff] border border-[rgb(0_0_0/10%)] text-[11px] font-mono text-[#040404] overflow-x-auto">
                  <code>{inv.mathematical_rule}</code>
                </div>
              )}

              <p className="text-[11px] text-[#6b6b6b] leading-relaxed font-body pt-1">
                {inv.description}
              </p>
            </div>

            {inv.scenario_target && (
              <div className="pt-3 border-t border-[rgb(0_0_0/10%)] flex items-center justify-between">
                <span className="text-[10px] font-mono text-[#6b6b6b]">
                  Target: <strong className="text-[#040404]">{inv.scenario_target}</strong>
                </span>

                <button
                  onClick={() => {
                    sound.playClick(650);
                    onSelectScenario(inv.scenario_target!);
                  }}
                  data-cursor-text="BENCHMARK"
                  className="px-3 py-1.5 rounded-lg bg-[#ffffff] border border-[rgb(0_0_0/10%)] hover:bg-[#101010] hover:text-white text-[#040404] transition-colors text-xs font-mono flex items-center gap-1.5 font-medium"
                >
                  <Play className="w-3 h-3 text-[#040404] group-hover:text-white" />
                  <span>Execute Benchmark</span>
                </button>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
