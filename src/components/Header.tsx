import { motion } from 'motion/react';
import { Volume2, VolumeX, Code, Terminal, Shield, ArrowUpRight } from 'lucide-react';
import { sound } from '../utils/audio';

interface HeaderProps {
  activeTab: 'studio' | 'gallery' | 'passport' | 'community' | 'invariants' | 'backend';
  setActiveTab: (tab: 'studio' | 'gallery' | 'passport' | 'community' | 'invariants' | 'backend') => void;
  soundEnabled: boolean;
  setSoundEnabled: (val: boolean) => void;
  onToggleJson: () => void;
  onOpenBackendModal: () => void;
  onShowToast: (msg: string) => void;
}

export default function Header({
  activeTab,
  setActiveTab,
  soundEnabled,
  setSoundEnabled,
  onToggleJson,
  onOpenBackendModal,
  onShowToast,
}: HeaderProps) {
  const toggleSound = () => {
    const newState = sound.toggle();
    setSoundEnabled(newState);
    onShowToast(`SFX audio: ${newState ? 'Enabled' : 'Muted'}`);
  };

  const navItems = [
    { id: 'studio', label: 'Platform & Triage' },
    { id: 'gallery', label: 'Gallery' },
    { id: 'passport', label: 'Evidence Passport' },
    { id: 'community', label: 'Threat Intel' },
    { id: 'invariants', label: '8 Invariants' },
  ] as const;

  return (
    <header className="sticky top-0 z-40 w-full border-b border-[rgb(0_0_0/10%)] bg-[#ffffff]/95 backdrop-blur-md">
      <div className="max-w-7xl mx-auto px-3 sm:px-6 h-14 sm:h-16 flex items-center justify-between gap-3 sm:gap-6">

        {/* Brand Zone */}
        <div className="flex items-center gap-2 sm:gap-3 shrink-0">
          <button
            onClick={() => {
              sound.playClick(500);
              setActiveTab('studio');
            }}
            data-cursor-text="HOME"
            className="flex items-center gap-2 text-left group focus:outline-none"
          >
            <div className="h-7 w-7 sm:h-8 sm:w-8 rounded-lg bg-[#101010] text-white flex items-center justify-center group-hover:scale-105 transition-transform shrink-0">
              <Shield className="w-3.5 h-3.5 sm:w-4 sm:h-4" />
            </div>
            <div className="flex items-baseline gap-2">
              <span className="font-serif font-bold text-lg sm:text-xl tracking-tight text-[#040404]">
                TRUSTRACE
              </span>
              <span className="text-[10px] sm:text-[11px] text-[#6B6B6B] font-mono tracking-widest uppercase hidden md:inline">
                &bull; HACKATHON 2026
              </span>
            </div>
          </button>
        </div>

        {/* Center Nav Links (Desktop & Tablet) */}
        <nav className="hidden lg:flex items-center gap-1 text-xs font-medium text-[#6b6b6b]">
          {navItems.map((item) => {
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => {
                  sound.playClick(650);
                  setActiveTab(item.id);
                }}
                data-cursor-text={item.id === 'gallery' ? 'GALLERY' : 'SELECT'}
                onMouseEnter={() => sound.playHover()}
                className={`relative px-3 py-1.5 rounded-lg transition-colors whitespace-nowrap ${
                  isActive ? 'text-[#040404] font-semibold' : 'text-[#6b6b6b] hover:text-[#040404]'
                }`}
              >
                {isActive && (
                  <motion.div
                    layoutId="header-active-pill"
                    className="absolute inset-0 bg-[#f6f6f6] border border-[rgb(0_0_0/8%)] rounded-lg"
                    transition={{ type: 'spring', stiffness: 450, damping: 35 }}
                  />
                )}
                <span className="relative z-10 flex items-center gap-1.5">
                  {isActive && <span className="w-1.5 h-1.5 rounded-full bg-[#101010] inline-block" />}
                  {item.label}
                </span>
              </button>
            );
          })}
        </nav>

        {/* Right Actions Zone */}
        <div className="flex items-center gap-1.5 sm:gap-2.5 shrink-0">
          {/* Sound Toggle */}
          <button
            onClick={toggleSound}
            data-cursor-text="AUDIO"
            title={soundEnabled ? 'Mute SFX' : 'Enable SFX'}
            className="p-1.5 sm:p-2 rounded-lg bg-[#f6f6f6] border border-[rgb(0_0_0/10%)] hover:border-[rgb(0_0_0/25%)] text-[#6b6b6b] hover:text-[#040404] transition-all text-xs"
          >
            {soundEnabled ? (
              <Volume2 className="w-3.5 h-3.5 text-[#040404]" />
            ) : (
              <VolumeX className="w-3.5 h-3.5 text-[#6b6b6b]" />
            )}
          </button>

          {/* JSON Inspector trigger */}
          <button
            onClick={() => {
              sound.playClick(700);
              onToggleJson();
            }}
            data-cursor-text="JSON"
            title="Inspect Canonical JSON Schema"
            className="p-1.5 sm:p-2 rounded-lg bg-[#f6f6f6] border border-[rgb(0_0_0/10%)] hover:border-[rgb(0_0_0/25%)] text-[#6b6b6b] hover:text-[#040404] transition-all text-xs hidden sm:flex items-center gap-1 font-mono"
          >
            <Code className="w-3.5 h-3.5" />
            <span className="text-[10px]">JSON</span>
          </button>

          {/* FastAPI Backend button */}
          <button
            onClick={() => {
              sound.playClick(600);
              onOpenBackendModal();
            }}
            data-cursor-text="PYTHON"
            className="px-2.5 sm:px-3 py-1.5 rounded-lg bg-[#f6f6f6] border border-[rgb(0_0_0/10%)] hover:border-[rgb(0_0_0/25%)] text-[#040404] hover:bg-[#d9d9d9] transition-all text-xs font-mono hidden sm:flex items-center gap-1.5"
          >
            <Terminal className="w-3.5 h-3.5 text-[#040404]" />
            <span>FastAPI</span>
          </button>

          {/* Primary Action CTA */}
          <button
            onClick={() => {
              sound.playClick(600);
              setActiveTab('studio');
            }}
            data-cursor-text="START"
            className="px-3 sm:px-4 py-1.5 sm:py-2 rounded-lg bg-[#101010] hover:bg-[#131313] text-white font-medium text-xs tracking-tight transition-all flex items-center gap-1.5 active:scale-95 whitespace-nowrap cursor-pointer shadow-sm"
          >
            <span className="hidden xs:inline">Triage Target</span>
            <span className="xs:hidden">Triage</span>
            <ArrowUpRight className="w-3 h-3 sm:w-3.5 sm:h-3.5" />
          </button>
        </div>

      </div>

      {/* Mobile & Tablet Nav Strip */}
      <div className="lg:hidden flex items-center px-3 py-2 border-t border-[rgb(0_0_0/10%)] bg-[#f6f6f6] overflow-x-auto gap-1.5 text-xs touch-pan-x scrollbar-none">
        {navItems.map((item) => (
          <button
            key={item.id}
            onClick={() => {
              sound.playClick(600);
              setActiveTab(item.id);
            }}
            className={`px-3 py-1.5 rounded-lg shrink-0 whitespace-nowrap font-mono text-[11px] transition-colors ${
              activeTab === item.id ? 'bg-[#101010] text-white font-bold shadow-xs' : 'text-[#6b6b6b] hover:text-[#040404] bg-[#ffffff] border border-[rgb(0_0_0/8%)]'
            }`}
          >
            {item.label}
          </button>
        ))}

        {/* Mobile quick actions */}
        <button
          onClick={() => {
            sound.playClick(600);
            onOpenBackendModal();
          }}
          className="sm:hidden px-2.5 py-1.5 rounded-lg shrink-0 whitespace-nowrap font-mono text-[11px] text-[#040404] bg-[#ffffff] border border-[rgb(0_0_0/10%)] flex items-center gap-1"
        >
          <Terminal className="w-3 h-3" />
          <span>FastAPI</span>
        </button>

        <button
          onClick={() => {
            sound.playClick(700);
            onToggleJson();
          }}
          className="sm:hidden px-2.5 py-1.5 rounded-lg shrink-0 whitespace-nowrap font-mono text-[11px] text-[#040404] bg-[#ffffff] border border-[rgb(0_0_0/10%)] flex items-center gap-1"
        >
          <Code className="w-3 h-3" />
          <span>JSON</span>
        </button>
      </div>
    </header>
  );
}
