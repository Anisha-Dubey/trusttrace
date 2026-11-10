import { useEffect, useState } from 'react';
import { motion, useSpring } from 'motion/react';
import { ArrowUpRight } from 'lucide-react';

export default function CustomCursor() {
  const [visible, setVisible] = useState(false);
  const [isPointer, setIsPointer] = useState(false);
  const [cursorText, setCursorText] = useState<string | null>(null);
  const [isMouseDown, setIsMouseDown] = useState(false);

  // Baseline Agency spring settings: buttery smooth inertia with crisp snap
  const cursorX = useSpring(0, { damping: 26, stiffness: 320 });
  const cursorY = useSpring(0, { damping: 26, stiffness: 320 });
  const dotX = useSpring(0, { damping: 45, stiffness: 900 });
  const dotY = useSpring(0, { damping: 45, stiffness: 900 });

  useEffect(() => {
    if (typeof window === 'undefined') {
      return;
    }

    const isTouch = window.matchMedia('(pointer: coarse), (hover: none)').matches || 'ontouchstart' in window;
    if (isTouch) {
      return;
    }

    const handleTouchStart = () => {
      setVisible(false);
    };

    const moveCursor = (e: MouseEvent) => {
      cursorX.set(e.clientX);
      cursorY.set(e.clientY);
      dotX.set(e.clientX);
      dotY.set(e.clientY);
      if (!visible) setVisible(true);

      const target = e.target as HTMLElement | null;
      if (target) {
        // Check for interactive elements
        const isInteractive = Boolean(
          target.closest('button, a, input, select, textarea, [role="button"], .cursor-pointer')
        );
        setIsPointer(isInteractive);

        // Check for Baseline-style dynamic cursor badge text
        const cursorEl = target.closest('[data-cursor-text], [data-cursor]') as HTMLElement | null;
        if (cursorEl) {
          const text = cursorEl.getAttribute('data-cursor-text') ||
            (cursorEl.getAttribute('data-cursor') === 'view' ? 'VIEW' :
             cursorEl.getAttribute('data-cursor') === 'explore' ? 'EXPLORE' :
             cursorEl.getAttribute('data-cursor') === 'audit' ? 'AUDIT' : null);
          setCursorText(text);
        } else {
          setCursorText(null);
        }
      }
    };

    const handleMouseDown = () => setIsMouseDown(true);
    const handleMouseUp = () => setIsMouseDown(false);
    const handleMouseLeave = () => setVisible(false);
    const handleMouseEnter = () => setVisible(true);

    window.addEventListener('mousemove', moveCursor);
    window.addEventListener('mousedown', handleMouseDown);
    window.addEventListener('mouseup', handleMouseUp);
    window.addEventListener('touchstart', handleTouchStart, { passive: true });
    document.addEventListener('mouseleave', handleMouseLeave);
    document.addEventListener('mouseenter', handleMouseEnter);

    return () => {
      window.removeEventListener('mousemove', moveCursor);
      window.removeEventListener('mousedown', handleMouseDown);
      window.removeEventListener('mouseup', handleMouseUp);
      window.removeEventListener('touchstart', handleTouchStart);
      document.removeEventListener('mouseleave', handleMouseLeave);
      document.removeEventListener('mouseenter', handleMouseEnter);
    };
  }, [cursorX, cursorY, dotX, dotY, visible]);

  if (!visible) return null;

  return (
    <div className="pointer-events-none fixed inset-0 z-50 overflow-hidden hidden md:block">
      {/* Baseline Morphing Cursor Badge */}
      <motion.div
        style={{
          x: cursorX,
          y: cursorY,
          translateX: '-50%',
          translateY: '-50%',
        }}
        animate={{
          scale: isMouseDown ? 0.85 : cursorText ? 1 : isPointer ? 1.6 : 1,
          opacity: 1,
        }}
        transition={{ type: 'spring', damping: 22, stiffness: 360 }}
        className="fixed top-0 left-0 flex items-center justify-center pointer-events-none select-none"
      >
        {cursorText ? (
          <motion.div
            initial={{ scale: 0.6, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            exit={{ scale: 0.6, opacity: 0 }}
            transition={{ type: 'spring', damping: 20, stiffness: 350 }}
            className="px-3 py-1.5 rounded-full bg-[#101010] text-white text-[10px] font-mono font-bold tracking-widest flex items-center gap-1 shadow-lg border border-[rgb(255_255_255/15%)]"
          >
            <span>{cursorText}</span>
            <ArrowUpRight className="w-3 h-3 text-white" />
          </motion.div>
        ) : (
          <div
            className={`rounded-full transition-all duration-200 ${
              isPointer
                ? 'h-9 w-9 border border-[#101010] bg-[#101010]/5 backdrop-blur-[0.5px]'
                : 'h-8 w-8 border border-[rgb(0_0_0/20%)]'
            }`}
          />
        )}
      </motion.div>

      {/* Center sharp coordination dot (hidden when badge is active) */}
      {!cursorText && (
        <motion.div
          style={{
            x: dotX,
            y: dotY,
            translateX: '-50%',
            translateY: '-50%',
          }}
          animate={{
            scale: isMouseDown ? 1.5 : isPointer ? 0.5 : 1,
            backgroundColor: '#040404',
          }}
          transition={{ duration: 0.1 }}
          className="fixed top-0 left-0 h-1.5 w-1.5 rounded-full pointer-events-none"
        />
      )}
    </div>
  );
}
