import React, { useRef, useState, useCallback } from 'react';
import { motion } from 'motion/react';
import { sound } from '../utils/audio';
import { triggerLiquidWarp } from './LiquidFilter';
import { useHanddrawnBorder, HanddrawnVariant } from '../utils/handdrawn';

interface LiquidButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  children: React.ReactNode;
  className?: string;
  variant?: 'primary' | 'secondary' | 'ghost';
  cursorBadge?: string;
  soundType?: 'click' | 'pill' | 'hover' | 'none';
  handdrawnVariant?: HanddrawnVariant;
  enableHoverAnimation?: boolean;
}

export default function LiquidButton({
  children,
  className = '',
  variant = 'primary',
  cursorBadge,
  soundType = 'click',
  handdrawnVariant = 'button',
  enableHoverAnimation = true,
  onClick,
  onMouseEnter,
  style: propStyle,
  ...rest
}: LiquidButtonProps) {
  const btnRef = useRef<HTMLButtonElement>(null);
  const [ripplePos, setRipplePos] = useState({ x: 0, y: 0, active: false });

  // Procedural random handdrawn border
  const { style: handdrawnStyle, morphBorder } = useHanddrawnBorder(handdrawnVariant);

  const handlePointerEnter = useCallback(
    (e: React.PointerEvent<HTMLButtonElement>) => {
      if (enableHoverAnimation) {
        if (soundType !== 'none') sound.playHover();
        triggerLiquidWarp(10);

        if (btnRef.current) {
          const rect = btnRef.current.getBoundingClientRect();
          setRipplePos({
            x: e.clientX - rect.left,
            y: e.clientY - rect.top,
            active: true,
          });
        }
      }
      onMouseEnter?.(e as never);
    },
    [onMouseEnter, enableHoverAnimation, soundType]
  );

  const handlePointerLeave = useCallback(() => {
    setRipplePos((prev) => ({ ...prev, active: false }));
  }, []);

  const handleClick = useCallback(
    (e: React.MouseEvent<HTMLButtonElement>) => {
      if (soundType === 'click') {
        sound.playClick();
      } else if (soundType === 'pill') {
        sound.playPill();
      }
      triggerLiquidWarp(16);
      morphBorder();
      onClick?.(e);
    },
    [onClick, soundType, morphBorder]
  );

  const baseStyles =
    variant === 'primary'
      ? 'bg-[#040404] text-white hover:bg-[#101010] shadow-sm'
      : variant === 'secondary'
      ? 'bg-[#F6F6F6] text-[#040404] border border-[#D9D9D9] hover:border-[#040404] hover:bg-white'
      : 'bg-transparent text-[#6B6B6B] hover:text-[#040404] hover:bg-[#F6F6F6]';

  return (
    <button
      ref={btnRef}
      onPointerEnter={handlePointerEnter}
      onPointerLeave={handlePointerLeave}
      onClick={handleClick}
      data-cursor-text={cursorBadge}
      style={{
        borderRadius: handdrawnStyle.borderRadius,
        borderWidth: handdrawnStyle.borderWidth,
        ...propStyle,
      }}
      className={`relative overflow-hidden transition-[border-radius,box-shadow,transform] duration-300 active:scale-95 cursor-pointer font-mono select-none ${baseStyles} ${className}`}
      {...rest}
    >
      {/* Hand-drawn liquid droplet ink ripple from pointer entry point */}
      {ripplePos.active && (
        <motion.span
          initial={{ scale: 0, opacity: 0.4 }}
          animate={{ scale: 3.8, opacity: 0 }}
          transition={{ duration: 0.65, ease: [0.16, 1, 0.3, 1] }}
          className="pointer-events-none absolute w-24 h-24 -translate-x-1/2 -translate-y-1/2 rounded-full bg-current opacity-25"
          style={{
            left: ripplePos.x,
            top: ripplePos.y,
          }}
        />
      )}

      {/* Button Content */}
      <span className="relative z-10 flex items-center justify-center gap-2">
        {children}
      </span>
    </button>
  );
}
