import React, { useRef, useState, useCallback } from 'react';
import { motion, useMotionValue, useSpring, useTransform } from 'motion/react';
import { sound } from '../utils/audio';
import { triggerLiquidWarp } from './LiquidFilter';

interface LiquidCardProps extends React.HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode;
  className?: string;
  enableTilt?: boolean;
  enableLiquidWarp?: boolean;
  cursorBadge?: string;
  soundType?: 'liquid' | 'hover' | 'pill' | 'none';
  variant?: 'card' | 'pill' | 'box';
  onClick?: (e: React.MouseEvent<HTMLDivElement>) => void;
}

export default function LiquidCard({
  children,
  className = '',
  enableTilt = true,
  enableLiquidWarp = true,
  cursorBadge,
  soundType = 'liquid',
  variant = 'card',
  onClick,
  ...rest
}: LiquidCardProps) {
  const cardRef = useRef<HTMLDivElement>(null);
  const [isHovered, setIsHovered] = useState(false);
  const [sheenPos, setSheenPos] = useState({ x: -100, y: -100 });

  // 3D Tilt Spring Physics
  const mouseX = useMotionValue(0);
  const mouseY = useMotionValue(0);

  const rotateX = useSpring(useTransform(mouseY, [-0.5, 0.5], [5, -5]), {
    damping: 24,
    stiffness: 300,
  });
  const rotateY = useSpring(useTransform(mouseX, [-0.5, 0.5], [-5, 5]), {
    damping: 24,
    stiffness: 300,
  });

  const handlePointerEnter = useCallback(
    (e: React.PointerEvent<HTMLDivElement>) => {
      setIsHovered(true);
      if (soundType === 'liquid') {
        sound.playLiquid();
      } else if (soundType === 'hover') {
        sound.playHover();
      } else if (soundType === 'pill') {
        sound.playPill();
      }

      if (enableLiquidWarp) {
        triggerLiquidWarp(10);
      }

      if (cardRef.current) {
        const rect = cardRef.current.getBoundingClientRect();
        setSheenPos({
          x: e.clientX - rect.left,
          y: e.clientY - rect.top,
        });
      }
    },
    [soundType, enableLiquidWarp]
  );

  const handlePointerMove = useCallback(
    (e: React.PointerEvent<HTMLDivElement>) => {
      if (!cardRef.current) return;
      const rect = cardRef.current.getBoundingClientRect();

      const relX = e.clientX - rect.left;
      const relY = e.clientY - rect.top;
      setSheenPos({ x: relX, y: relY });

      if (enableTilt) {
        const normX = (relX / rect.width) - 0.5;
        const normY = (relY / rect.height) - 0.5;
        mouseX.set(normX);
        mouseY.set(normY);
      }
    },
    [enableTilt, mouseX, mouseY]
  );

  const handlePointerLeave = useCallback(() => {
    setIsHovered(false);
    if (enableTilt) {
      mouseX.set(0);
      mouseY.set(0);
    }
  }, [enableTilt, mouseX, mouseY]);

  const handdrawnClass =
    variant === 'pill'
      ? 'handdrawn-pill'
      : variant === 'box'
      ? 'handdrawn-box'
      : 'handdrawn-card';

  return (
    <motion.div
      ref={cardRef}
      style={{
        perspective: 1000,
        rotateX: enableTilt ? rotateX : 0,
        rotateY: enableTilt ? rotateY : 0,
        transformStyle: 'preserve-3d',
      }}
      onPointerEnter={handlePointerEnter}
      onPointerMove={handlePointerMove}
      onPointerLeave={handlePointerLeave}
      onClick={onClick}
      data-cursor-text={cursorBadge}
      className={`relative overflow-hidden transition-all duration-300 ${handdrawnClass} ${
        isHovered ? 'shadow-xl shadow-black/5' : 'shadow-none'
      } ${className}`}
      {...(rest as any)}
    >
      {/* Hand-drawn matching liquid light sheen following pointer */}
      <div
        className="pointer-events-none absolute -inset-px transition-opacity duration-300 rounded-[inherit]"
        style={{
          opacity: isHovered ? 1 : 0,
          background: `radial-gradient(420px circle at ${sheenPos.x}px ${sheenPos.y}px, rgba(0, 0, 0, 0.05), transparent 70%)`,
        }}
      />

      {/* Hand-drawn organic border highlight on hover */}
      <div
        className="pointer-events-none absolute inset-0 rounded-[inherit] transition-opacity duration-300"
        style={{
          opacity: isHovered ? 1 : 0,
          boxShadow: isHovered ? 'inset 0 0 0 1.5px rgba(4,4,4,0.3)' : 'none',
        }}
      />

      {/* Card Content */}
      <div className={`relative z-10 w-full h-full ${enableLiquidWarp && isHovered ? 'liquid-warp-active' : ''}`}>
        {children}
      </div>
    </motion.div>
  );
}
