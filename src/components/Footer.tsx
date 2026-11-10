import { Shield, ArrowUpRight } from 'lucide-react';
import { sound } from '../utils/audio';

interface FooterProps {
  onSelectTab: (tab: 'studio' | 'gallery' | 'passport' | 'community' | 'invariants' | 'backend') => void;
  onOpenBackendModal: () => void;
}

export default function Footer({ onSelectTab, onOpenBackendModal }: FooterProps) {
  return (
    <footer className="border-t border-[rgb(0_0_0/10%)] bg-[#ffffff] py-10 sm:py-14 text-[#6b6b6b] text-xs font-body">
      <div className="max-w-5xl mx-auto px-4 sm:px-6 space-y-8">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-6 pb-8 border-b border-[rgb(0_0_0/10%)]">
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-[#040404]">
              <div className="h-6 w-6 rounded bg-[#F6F6F6] border border-[#D9D9D9] flex items-center justify-center text-[#040404]">
                <Shield className="w-3.5 h-3.5" />
              </div>
              <span className="font-serif font-bold text-base sm:text-lg tracking-tight">TRUSTRACE</span>
              <span className="text-[10px] font-mono text-[#6B6B6B] font-semibold">// PITCH SLIDE 10</span>
            </div>
            <p className="text-[#040404] font-serif text-sm max-w-md leading-relaxed">
              Trust, explained. See the signals. Inspect the evidence. Know what remains unknown.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3.5 sm:gap-6 text-xs font-mono">
            <button
              onClick={() => {
                sound.playClick(600);
                onSelectTab('studio');
              }}
              data-cursor-text="PLATFORM"
              className="text-[#6b6b6b] hover:text-[#040404] transition-colors"
            >
              Platform
            </button>
            <button
              onClick={() => {
                sound.playClick(600);
                onSelectTab('gallery');
              }}
              data-cursor-text="GALLERY"
              className="text-[#6b6b6b] hover:text-[#040404] transition-colors"
            >
              Gallery (06)
            </button>
            <button
              onClick={() => {
                sound.playClick(600);
                onSelectTab('passport');
              }}
              data-cursor-text="PASSPORT"
              className="text-[#6b6b6b] hover:text-[#040404] transition-colors"
            >
              Evidence Passport
            </button>
            <button
              onClick={() => {
                sound.playClick(600);
                onSelectTab('community');
              }}
              className="text-[#6b6b6b] hover:text-[#040404] transition-colors"
            >
              Threat Feeds
            </button>
            <button
              onClick={() => {
                sound.playClick(600);
                onSelectTab('invariants');
              }}
              className="text-[#6b6b6b] hover:text-[#040404] transition-colors"
            >
              8 Invariants
            </button>
            <button
              onClick={() => {
                sound.playClick(600);
                onOpenBackendModal();
              }}
              className="text-[#6b6b6b] hover:text-[#040404] transition-colors flex items-center gap-1"
            >
              <span>FastAPI Spec</span>
              <ArrowUpRight className="w-3 h-3 text-[#040404]" />
            </button>
          </div>
        </div>

        <div className="flex flex-col sm:flex-row items-center justify-between gap-4 font-mono text-[11px] text-[#6b6b6b]">
          <div>
            Continuous Offensive Exposure Management &bull; 8 Formal Invariants Preserved
          </div>
          <div className="flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-[#101010] inline-block" />
            <span>Zero Active Browser Risk &bull; Egress Guardrail</span>
          </div>
        </div>
      </div>
    </footer>
  );
}
