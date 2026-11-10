import { useEffect, useState, useRef } from 'react';
import { motion, useSpring, useMotionValue } from 'motion/react';
import { ArrowUpRight } from 'lucide-react';
import { generateHanddrawnCircle, HanddrawnCirclePaths } from '../utils/handdrawn';

export default function CustomCursor() {
  const [visible, setVisible] = useState(false);
  const [isPointer, setIsPointer] = useState(false);
  const [isTextInput, setIsTextInput] = useState(false);
  const [cursorText, setCursorText] = useState<string | null>(null);
  const [isMouseDown, setIsMouseDown] = useState(false);
  // Procedural hand-drawn circle paths (randomized on page load/refresh & on input entry)
  const [circlePaths, setCirclePaths] = useState<HanddrawnCirclePaths>(() => generateHanddrawnCircle());
  const wasTextInputRef = useRef(false);

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
        // When pointer enters an input, generate a new randomized hand-drawn circle contour!
        if (isText && !wasTextInputRef.current) {
          setCirclePaths(generateHanddrawnCircle());
        }
        wasTextInputRef.current = isText;
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
                d={circlePaths.primaryPath}
                fill="rgba(246, 246, 246, 0.45)"
                stroke="#040404"
                strokeWidth="2.2"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
              {/* Secondary delicate sketchy pen stroke */}
              <path
                d={circlePaths.sketchPath}
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
