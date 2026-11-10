import { useEffect, useState, useRef } from 'react';
import { motion, useSpring, useMotionValue } from 'motion/react';
import { ArrowUpRight } from 'lucide-react';

export default function CustomCursor() {
  const [visible, setVisible] = useState(false);
  const [isPointer, setIsPointer] = useState(false);
  const [isTextInput, setIsTextInput] = useState(false);
  const [cursorText, setCursorText] = useState<string | null>(null);
  const [isMouseDown, setIsMouseDown] = useState(false);

  // Osply Fluid spring physics:
  // - cursorX/cursorY: liquid outer aura with soft momentum
  // - dotX/dotY: instantaneous central tracking dot (near-zero latency precision)
  const cursorX = useSpring(0, { damping: 24, stiffness: 420 });
  const cursorY = useSpring(0, { damping: 24, stiffness: 420 });
  const dotX = useSpring(0, { damping: 55, stiffness: 1400 });
  const dotY = useSpring(0, { damping: 55, stiffness: 1400 });

  // Liquid velocity squish tracking
  const scaleX = useSpring(1, { damping: 18, stiffness: 320 });
  const scaleY = useSpring(1, { damping: 18, stiffness: 320 });
  const rotation = useMotionValue(0);

  const lastPos = useRef({ x: 0, y: 0, time: 0 });

  useEffect(() => {
    if (typeof window === 'undefined') return;

    const handleTouchStart = () => setVisible(false);

    const moveCursor = (e: MouseEvent) => {
      const now = performance.now();
      const dt = Math.max(1, now - lastPos.current.time);
      const dx = e.clientX - lastPos.current.x;
      const dy = e.clientY - lastPos.current.y;
      const speed = Math.min(Math.sqrt(dx * dx + dy * dy) / dt, 12);

      // Velocity-based liquid droplet squish and angle
      if (speed > 0.1) {
        const angle = (Math.atan2(dy, dx) * 180) / Math.PI;
        rotation.set(angle);
        scaleX.set(1 + speed * 0.04);
        scaleY.set(Math.max(0.65, 1 - speed * 0.03));
      } else {
        scaleX.set(1);
        scaleY.set(1);
      }

      lastPos.current = { x: e.clientX, y: e.clientY, time: now };

      cursorX.set(e.clientX);
      cursorY.set(e.clientY);
      dotX.set(e.clientX);
      dotY.set(e.clientY);

      if (!visible) setVisible(true);

      const target = e.target as HTMLElement | null;
      if (target) {
        const isText = Boolean(
          target.closest('input, textarea, [contenteditable="true"], [data-cursor="circle"]')
        );
        setIsTextInput(isText);

        const isInteractive = Boolean(
          target.closest('button, a, select, [role="button"], .cursor-pointer, [data-cursor-text]')
        );
        setIsPointer(isInteractive);

        const cursorEl = target.closest('[data-cursor-text], [data-cursor]') as HTMLElement | null;
        if (cursorEl && !isText) {
          const text =
            cursorEl.getAttribute('data-cursor-text') ||
            (cursorEl.getAttribute('data-cursor') === 'view'
              ? 'VIEW'
              : cursorEl.getAttribute('data-cursor') === 'explore'
              ? 'EXPLORE'
              : cursorEl.getAttribute('data-cursor') === 'audit'
              ? 'AUDIT'
              : null);
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
  }, [cursorX, cursorY, dotX, dotY, scaleX, scaleY, rotation, visible]);

  if (!visible) return null;

  return (
    <div
      aria-hidden="true"
      className="pointer-events-none fixed inset-0 z-[99999] overflow-hidden select-none"
    >
      {/* Osply Liquid Fluid Cursor Aura */}
      <motion.div
        style={{
          x: cursorX,
          y: cursorY,
          scaleX: cursorText ? 1 : isTextInput ? 1 : scaleX,
          scaleY: cursorText ? 1 : isTextInput ? 1 : scaleY,
          rotate: cursorText || isTextInput ? 0 : rotation,
          translateX: '-50%',
          translateY: '-50%',
        }}
        animate={{
          scale: isMouseDown ? 0.85 : cursorText ? 1 : isTextInput ? 1 : isPointer ? 1.5 : 1,
          opacity: 1,
        }}
        transition={{ type: 'spring', damping: 22, stiffness: 380 }}
        className="fixed top-0 left-0 flex items-center justify-center pointer-events-none select-none"
      >
        {cursorText ? (
          <motion.div
            initial={{ scale: 0.6, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            exit={{ scale: 0.6, opacity: 0 }}
            transition={{ type: 'spring', damping: 20, stiffness: 350 }}
            className="px-3 py-1.5 rounded-full bg-[#101010] text-white text-[10px] font-mono font-bold tracking-widest flex items-center gap-1 shadow-xl border border-white/20"
          >
            <span>{cursorText}</span>
            <ArrowUpRight className="w-3 h-3 text-white" />
          </motion.div>
        ) : isTextInput ? (
          <motion.div
            initial={{ scale: 0.6, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            exit={{ scale: 0.6, opacity: 0 }}
            transition={{ type: 'spring', damping: 20, stiffness: 350 }}
            className="relative flex items-center justify-center pointer-events-none"
          >
            {/* Big hand-drawn sketched circle matching user attachment */}
            <svg
              viewBox="0 0 64 64"
              className="w-[58px] h-[58px] overflow-visible"
              style={{
                filter: 'drop-shadow(0 1px 2px rgba(0,0,0,0.06))',
              }}
            >
              {/* Translucent lens fill so background text remains readable through the circle */}
              <path
                d="M 60.2,32.0 C 60.3,35.8 59.8,39.8 58.3,43.2 C 56.8,46.5 54.1,49.7 51.3,52.1 C 48.5,54.5 45.1,56.5 41.7,57.6 C 38.3,58.6 34.4,58.5 31.0,58.2 C 27.6,57.9 24.2,57.1 21.0,55.9 C 17.9,54.6 14.7,52.9 12.1,50.6 C 9.5,48.3 7.2,45.3 5.7,42.1 C 4.1,38.9 3.1,35.2 2.9,31.5 C 2.7,27.9 3.1,23.9 4.3,20.3 C 5.6,16.8 7.6,13.1 10.2,10.4 C 12.8,7.7 16.3,5.4 19.9,4.2 C 23.4,3.0 27.5,2.4 31.2,2.6 C 34.8,2.8 38.6,3.9 41.9,5.3 C 45.2,6.8 48.6,8.7 51.3,11.2 C 54.0,13.8 56.5,16.9 58.1,20.3 C 59.6,23.7 60.1,27.8 60.2,32.0 Z"
                fill="rgba(246, 246, 246, 0.45)"
                stroke="#040404"
                strokeWidth="2.2"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
              {/* Secondary delicate sketchy pen stroke */}
              <path
                d="M 59.7,31.4 C 59.8,35.3 59.1,39.3 57.5,42.7 C 55.9,46.1 53.3,49.3 50.5,51.7 C 47.7,54.1 44.3,56.1 40.9,57.2 C 37.5,58.2 33.7,58.1 30.3,57.8 C 26.9,57.5 23.5,56.7 20.4,55.4 C 17.3,54.1 14.2,52.4 11.6,50.1 C 9.0,47.8 6.7,44.8 5.2,41.6 C 3.6,38.4 2.6,34.7 2.4,31.0 C 2.2,27.4 2.6,23.4 3.9,19.9 C 5.1,16.3 7.1,12.7 9.7,10.0 C 12.3,7.3 15.8,5.1 19.4,3.8 C 22.9,2.6 27.0,2.1 30.7,2.2 C 34.3,2.4 38.1,3.5 41.4,4.9 C 44.7,6.4 48.1,8.3 50.8,10.8 C 53.5,13.3 56.0,16.4 57.6,19.8 C 59.1,23.1 59.8,27.3 59.7,31.4 Z"
                fill="none"
                stroke="#040404"
                strokeWidth="0.8"
                strokeDasharray="24 4 14 3"
                opacity="0.55"
              />
            </svg>
          </motion.div>
        ) : (
          <div
            className={`rounded-full transition-all duration-200 ${
              isPointer
                ? 'h-10 w-10 border-2 border-[#040404] bg-[#040404]/5 backdrop-blur-[0.5px]'
                : 'h-8 w-8 border border-[rgb(0_0_0/25%)] bg-transparent'
            }`}
            style={{
              filter: isPointer ? 'url(#liquid-glass-refract)' : 'none',
            }}
          />
        )}
      </motion.div>

      {/* Central Sharp Tracking Dot */}
      {!cursorText && (
        <motion.div
          style={{
            x: dotX,
            y: dotY,
            translateX: '-50%',
            translateY: '-50%',
          }}
          animate={{
            scale: isMouseDown ? 1.6 : isPointer ? 0.5 : 1,
            height: isTextInput ? 4.5 : isPointer ? 3 : 6,
            width: isTextInput ? 4.5 : isPointer ? 3 : 6,
            borderRadius: 9999,
            backgroundColor: '#040404',
          }}
          transition={{ duration: 0.06 }}
          className="fixed top-0 left-0 pointer-events-none shadow-xs"
        />
      )}
    </div>
  );
}
