import { useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { ArrowDownRight, Globe, ShieldAlert, Sparkles, ChevronUp, ChevronDown } from 'lucide-react';
import { sound } from '../utils/audio';

interface HiYesCurtainProps {
  onQuickTriage: (url: string) => void;
  onScrollToTriage: () => void;
}

export default function HiYesCurtain({ onQuickTriage, onScrollToTriage }: HiYesCurtainProps) {
  const [isHovered, setIsHovered] = useState(false);
  const [isExpanded, setIsExpanded] = useState(false);

  const toggleExpand = () => {
    sound.playClick(600);
    setIsExpanded(!isExpanded);
  };

  return (
    <div className="w-full bg-[#ededf0] dark:bg-[#14161f] border-b border-zinc-200 dark:border-zinc-800 transition-colors relative overflow-hidden select-none">
      {/* Main "Hi, Yes?" Greeting Visual Bar matching Incroy screenshot */}
      <div
        onClick={toggleExpand}
        onMouseEnter={() => {
          setIsHovered(true);
          sound.playHover();
        }}
        onMouseLeave={() => setIsHovered(false)}
        className="w-full py-10 sm:py-16 md:py-20 flex flex-col items-center justify-center cursor-pointer group relative"
      >
        <motion.div
          animate={{
            scale: isHovered ? 1.02 : 1,
            y: isHovered ? -2 : 0,
          }}
          transition={{ type: 'spring', stiffness: 350, damping: 25 }}
          className="text-center"
        >
          {/* Giant White Display Typography */}
          <h1 className="font-display font-extrabold text-5xl sm:text-7xl md:text-8xl lg:text-9xl text-white dark:text-[#252836] tracking-tight drop-shadow-sm group-hover:text-white/95 dark:group-hover:text-zinc-200 transition-colors">
            Hi, Yes?
          </h1>

          <div className="flex items-center justify-center gap-2 mt-2 sm:mt-3 text-xs sm:text-sm font-sans font-medium text-zinc-500 dark:text-zinc-400 group-hover:text-[#5855e8] dark:group-hover:text-[#8d8aff] transition-colors">
            <span>
              {isExpanded ? 'Click to fold inquiry banner' : 'Need to verify a web domain? Click to interact'}
            </span>
            <motion.span
              animate={{ y: isHovered ? [0, 3, 0] : 0 }}
              transition={{ repeat: Infinity, duration: 1.2 }}
            >
              {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ArrowDownRight className="w-4 h-4" />}
            </motion.span>
          </div>
        </motion.div>
      </div>

      {/* Interactive Expandable Inquiry Deck */}
      <AnimatePresence>
        {isExpanded && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            transition={{ duration: 0.3, ease: [0.16, 1, 0.3, 1] }}
            className="border-t border-zinc-300/80 dark:border-zinc-800 bg-white/90 dark:bg-[#0f1118]/90 backdrop-blur-md px-6 py-8"
          >
            <div className="max-w-4xl mx-auto space-y-4 text-center">
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-indigo-50 dark:bg-indigo-950/50 text-[#5855e8] dark:text-[#9ea3ff] text-xs font-mono font-semibold">
                <Sparkles className="w-3.5 h-3.5" />
                <span>Zero Browser Risk &bull; 4 Verifiable Dimensions &bull; Audited Evidence</span>
              </div>

              <h2 className="text-xl sm:text-2xl font-display font-bold text-zinc-900 dark:text-white tracking-tight">
                Inspect any URL with mathematical coverage and verifiable proof.
              </h2>
              <p className="text-sm text-zinc-600 dark:text-zinc-400 max-w-xl mx-auto">
                No black-box scores. We unbundle transport TLS certificates from legitimate institutional delegation. Pick a test benchmark to launch:
              </p>

              {/* Quick Launch Buttons */}
              <div className="flex flex-wrap items-center justify-center gap-3 pt-2">
                <button
                  onClick={() => onQuickTriage('https://bank-secure-lоgin.com')}
                  className="px-4 py-2 handdrawn-pill bg-zinc-100 dark:bg-zinc-800 hover:bg-[#5855e8] hover:text-white text-zinc-800 dark:text-zinc-200 text-xs font-mono font-medium transition-all flex items-center gap-2 shadow-sm"
                >
                  <ShieldAlert className="w-3.5 h-3.5 text-amber-500" />
                  <span>Cyrillic Homoglyph (Phishing)</span>
                </button>

                <button
                  onClick={() => onQuickTriage('https://example.com')}
                  className="px-4 py-2 handdrawn-pill bg-zinc-100 dark:bg-zinc-800 hover:bg-emerald-600 hover:text-white text-zinc-800 dark:text-zinc-200 text-xs font-mono font-medium transition-all flex items-center gap-2 shadow-sm"
                >
                  <Globe className="w-3.5 h-3.5 text-emerald-500" />
                  <span>IANA Benchmark (Legitimate)</span>
                </button>

                <button
                  onClick={() => onQuickTriage('http://169.254.169.254/latest/meta-data')}
                  className="px-4 py-2 handdrawn-pill bg-zinc-100 dark:bg-zinc-800 hover:bg-rose-600 hover:text-white text-zinc-800 dark:text-zinc-200 text-xs font-mono font-medium transition-all flex items-center gap-2 shadow-sm"
                >
                  <Globe className="w-3.5 h-3.5 text-rose-500" />
                  <span>Metadata SSRF (Boundary Halt)</span>
                </button>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
