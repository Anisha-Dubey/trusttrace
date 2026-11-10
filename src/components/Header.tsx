import { useState, useEffect } from 'react';
import { motion } from 'motion/react';
import { Volume2, VolumeX, Code, Terminal, Shield, ArrowUpRight } from 'lucide-react';
import { sound } from '../utils/audio';
import { triggerLiquidWarp } from './LiquidFilter';

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
  const [isPlayingAudio, setIsPlayingAudio] = useState(false);

  useEffect(() => {
    const unsubscribe = sound.subscribe((active) => {
      setIsPlayingAudio(active);
    });
    return unsubscribe;
  }, []);

  const toggleSound = () => {
    const newState = sound.toggle();
    setSoundEnabled(newState);
    triggerLiquidWarp(12);
    onShowToast(`SFX audio: ${newState ? 'Enabled' : 'Muted'}`);
  };

  const navItems = [
    { id: 'studio', label: 'Triage Studio' },
    { id: 'gallery', label: 'Case Gallery' },
    { id: 'passport', label: 'Evidence Passport' },
    { id: 'community', label: 'Threat Intel' },
    { id: 'invariants', label: '8 Invariants' },
  ] as const;

  return (
    <header className="sticky top-0 z-40 w-full border-b border-[#D9D9D9] bg-[#FFFFFF]/90 backdrop-blur-md transition-colors">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 h-15 sm:h-16 flex items-center justify-between gap-4">

        {/* Brand Zone */}
        <div className="flex items-center gap-2 sm:gap-3 shrink-0">
          <button
            onClick={() => {
              sound.playClick(500);
              triggerLiquidWarp(8);
              setActiveTab('studio');
            }}
            data-cursor-text="HOME"
            onMouseEnter={() => sound.playHover()}
            className="flex items-center gap-2.5 text-left group focus:outline-none cursor-pointer"
          >
            <div className="h-8 w-8 rounded-lg bg-[#040404] text-white flex items-center justify-center group-hover:scale-105 group-hover:rotate-1 transition-transform shrink-0 shadow-xs">
              <Shield className="w-4 h-4" />
            </div>
            <div className="flex items-baseline gap-2">
              <span className="font-serif font-bold text-lg sm:text-xl tracking-tight text-[#040404]">
                TRUSTRACE
              </span>
              <span className="text-[10px] text-[#6B6B6B] font-mono tracking-widest uppercase hidden md:inline">
                &bull; RISK TRIAGE
              </span>
            </div>
          </button>
        </div>

        {/* Center Nav Links (Desktop & Tablet) */}
        <nav className="hidden lg:flex items-center gap-1 text-xs font-medium text-[#6B6B6B]">
          {navItems.map((item) => {
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => {
                  sound.playClick(650);
                  triggerLiquidWarp(8);
                  setActiveTab(item.id);
                }}
                data-cursor-text={item.id === 'gallery' ? 'GALLERY' : 'SELECT'}
                onMouseEnter={() => sound.playHover()}
                className={`relative px-3.5 py-1.5 rounded-lg transition-colors whitespace-nowrap cursor-pointer ${
                  isActive ? 'text-[#040404] font-semibold' : 'text-[#6B6B6B] hover:text-[#040404]'
                }`}
              >
                {isActive && (
                  <motion.div
                    layoutId="header-active-pill"
                    className="absolute inset-0 bg-[#F6F6F6] border border-[#D9D9D9] rounded-lg"
                    transition={{ type: 'spring', stiffness: 450, damping: 35 }}
                  />
                )}
                <span className="relative z-10 flex items-center gap-1.5">
                  {isActive && <span className="w-1.5 h-1.5 rounded-full bg-[#040404] inline-block" />}
                  {item.label}
                </span>
              </button>
            );
          })}
        </nav>

        {/* Right Actions Zone */}
        <div className="flex items-center gap-2 shrink-0">
          {/* Osply-Style Sound Toggle with Equalizer Waveform */}
          <button
            onClick={toggleSound}
            data-cursor-text="AUDIO"
            title={soundEnabled ? 'Mute Sound Effects' : 'Enable Sound Effects'}
            onMouseEnter={() => sound.playHover()}
            className={`px-2.5 py-1.5 rounded-lg border text-xs font-mono transition-all flex items-center gap-2 cursor-pointer ${
              soundEnabled
                ? 'bg-[#F6F6F6] border-[#D9D9D9] text-[#040404] hover:border-[#040404]'
                : 'bg-transparent border-[#D9D9D9] text-[#6B6B6B] hover:text-[#040404]'
            }`}
          >
            {soundEnabled ? (
              <>
                {/* 3 Animated Equalizer Bars */}
                <span className="flex items-end gap-[2px] h-3 w-3 text-[#040404]" aria-hidden="true">
                  <motion.span
                    animate={{ height: isPlayingAudio ? ['40%', '100%', '30%'] : ['30%', '50%', '30%'] }}
                    transition={{ repeat: Infinity, duration: isPlayingAudio ? 0.35 : 1.2, ease: 'easeInOut' }}
                    className="w-[2.5px] bg-[#040404] rounded-full inline-block"
                  />
                  <motion.span
                    animate={{ height: isPlayingAudio ? ['80%', '30%', '90%'] : ['60%', '30%', '60%'] }}
                    transition={{ repeat: Infinity, duration: isPlayingAudio ? 0.45 : 1.5, ease: 'easeInOut' }}
                    className="w-[2.5px] bg-[#040404] rounded-full inline-block"
                  />
                  <motion.span
                    animate={{ height: isPlayingAudio ? ['30%', '90%', '50%'] : ['40%', '70%', '40%'] }}
                    transition={{ repeat: Infinity, duration: isPlayingAudio ? 0.4 : 1.3, ease: 'easeInOut' }}
                    className="w-[2.5px] bg-[#040404] rounded-full inline-block"
                  />
                </span>
                <span className="text-[11px] font-bold hidden sm:inline">SFX</span>
              </>
            ) : (
              <>
                <VolumeX className="w-3.5 h-3.5 text-[#6B6B6B]" />
                <span className="text-[11px] text-[#6B6B6B] hidden sm:inline">MUTED</span>
              </>
            )}
          </button>

          {/* JSON Inspector trigger */}
          <button
            onClick={() => {
              sound.playClick(700);
              triggerLiquidWarp(8);
              onToggleJson();
            }}
            data-cursor-text="JSON"
            title="Inspect Canonical JSON Schema"
            onMouseEnter={() => sound.playHover()}
            className="p-1.5 sm:px-2.5 sm:py-1.5 rounded-lg bg-[#F6F6F6] border border-[#D9D9D9] hover:border-[#040404] text-[#6B6B6B] hover:text-[#040404] transition-all text-xs hidden sm:flex items-center gap-1 font-mono cursor-pointer"
          >
            <Code className="w-3.5 h-3.5" />
            <span className="text-[10px]">JSON</span>
          </button>

          {/* FastAPI Backend button */}
          <button
            onClick={() => {
              sound.playClick(600);
              triggerLiquidWarp(8);
              onOpenBackendModal();
            }}
            data-cursor-text="PYTHON"
            onMouseEnter={() => sound.playHover()}
            className="px-2.5 sm:px-3 py-1.5 rounded-lg bg-[#F6F6F6] border border-[#D9D9D9] hover:border-[#040404] text-[#040404] hover:bg-white transition-all text-xs font-mono hidden sm:flex items-center gap-1.5 cursor-pointer"
          >
            <Terminal className="w-3.5 h-3.5 text-[#040404]" />
            <span>FastAPI</span>
          </button>

          {/* Primary Action CTA */}
          <button
            onClick={() => {
              sound.playClick(600);
              triggerLiquidWarp(12);
              setActiveTab('studio');
            }}
            data-cursor-text="START"
            onMouseEnter={() => sound.playHover()}
            className="px-3.5 sm:px-4 py-1.5 sm:py-2 rounded-lg bg-[#040404] hover:bg-[#101010] text-white font-medium text-xs tracking-tight transition-all flex items-center gap-1.5 active:scale-95 whitespace-nowrap cursor-pointer shadow-sm"
          >
            <span className="hidden xs:inline">Run Triage</span>
            <span className="xs:hidden">Triage</span>
            <ArrowUpRight className="w-3.5 h-3.5" />
          </button>
        </div>

      </div>

      {/* Mobile & Tablet Nav Strip */}
      <div className="lg:hidden flex items-center px-4 py-2 border-t border-[#D9D9D9] bg-[#F6F6F6] overflow-x-auto gap-1.5 text-xs touch-pan-x scrollbar-none">
        {navItems.map((item) => (
          <button
            key={item.id}
            onClick={() => {
              sound.playClick(600);
              triggerLiquidWarp(8);
              setActiveTab(item.id);
            }}
            className={`px-3 py-1.5 rounded-lg shrink-0 whitespace-nowrap font-mono text-[11px] transition-colors cursor-pointer ${
              activeTab === item.id
                ? 'bg-[#040404] text-white font-bold shadow-xs'
                : 'text-[#6B6B6B] hover:text-[#040404] bg-[#FFFFFF] border border-[#D9D9D9]'
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
          className="sm:hidden px-2.5 py-1.5 rounded-lg shrink-0 whitespace-nowrap font-mono text-[11px] text-[#040404] bg-[#FFFFFF] border border-[#D9D9D9] flex items-center gap-1"
        >
          <Terminal className="w-3 h-3" />
          <span>FastAPI</span>
        </button>

        <button
          onClick={() => {
            sound.playClick(700);
            onToggleJson();
          }}
          className="sm:hidden px-2.5 py-1.5 rounded-lg shrink-0 whitespace-nowrap font-mono text-[11px] text-[#040404] bg-[#FFFFFF] border border-[#D9D9D9] flex items-center gap-1"
        >
          <Code className="w-3 h-3" />
          <span>JSON</span>
        </button>
      </div>
    </header>
  );
}
