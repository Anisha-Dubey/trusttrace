import React, { useRef, useState, useCallback } from 'react';
import { motion, useSpring } from 'motion/react';
import { sound } from '../utils/audio';
import { useHanddrawnBorder, HanddrawnVariant } from '../utils/handdrawn';

interface LiquidCardProps extends React.HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode;
  className?: string;
  enableTilt?: boolean;
  enableLiquidWarp?: boolean;
  cursorBadge?: string;
  soundType?: 'liquid' | 'hover' | 'pill' | 'none';
  variant?: HanddrawnVariant;
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
  style: propStyle,
  ...rest
}: LiquidCardProps) {
  const cardRef = useRef<HTMLDivElement>(null);
  const [isHovered, setIsHovered] = useState(false);
  const [sheenPos, setSheenPos] = useState({ x: -100, y: -100 });

  // Procedural handdrawn random round border generator (unique for every box instance)
  const { style: handdrawnStyle, morphBorder } = useHanddrawnBorder(variant);

  // Smooth 2D micro-elevation (preserves 100% vector font sharpness on Windows)
  const translateY = useSpring(0, { damping: 22, stiffness: 350 });
  const scale = useSpring(1, { damping: 22, stiffness: 350 });

  const handlePointerEnter = useCallback(
    (e: React.PointerEvent<HTMLDivElement>) => {
      setIsHovered(true);

      // Re-morph hand-drawn round border on hover for subtle organic variation
      morphBorder();

      if (enableTilt) {
        translateY.set(-3);
        scale.set(1.012);
      }

      if (soundType === 'liquid') {
        sound.playLiquid();
      } else if (soundType === 'hover') {
        sound.playHover();
      } else if (soundType === 'pill') {
        sound.playPill();
      }

      if (cardRef.current) {
        const rect = cardRef.current.getBoundingClientRect();
        setSheenPos({
          x: e.clientX - rect.left,
          y: e.clientY - rect.top,
        });
      }
    },
    [soundType, enableTilt, morphBorder, translateY, scale]
  );

  const handlePointerMove = useCallback(
    (e: React.PointerEvent<HTMLDivElement>) => {
      if (!cardRef.current) return;
      const rect = cardRef.current.getBoundingClientRect();
      const relX = e.clientX - rect.left;
      const relY = e.clientY - rect.top;
      setSheenPos({ x: relX, y: relY });
    },
    []
  );

  const handlePointerLeave = useCallback(() => {
    setIsHovered(false);
    if (enableTilt) {
      translateY.set(0);
      scale.set(1);
    }
  }, [enableTilt, translateY, scale]);

  return (
    <motion.div
      ref={cardRef}
      style={{
        y: translateY,
        scale,
        borderRadius: handdrawnStyle.borderRadius,
        borderWidth: handdrawnStyle.borderWidth,
        WebkitFontSmoothing: 'antialiased',
        MozOsxFontSmoothing: 'grayscale',
        textRendering: 'optimizeLegibility',
        ...propStyle,
      }}
      onPointerEnter={handlePointerEnter}
      onPointerMove={handlePointerMove}
      onPointerLeave={handlePointerLeave}
      onClick={onClick}
      data-cursor-text={cursorBadge}
      className={`relative overflow-hidden transition-[box-shadow,border-radius] duration-200 select-none ${
        isHovered ? 'shadow-lg shadow-black/8' : 'shadow-none'
      } ${className}`}
      {...(rest as any)}
    >
      {/* Hand-drawn matching liquid light sheen following pointer */}
      <div
        className="pointer-events-none absolute -inset-px transition-opacity duration-300"
        style={{
          borderRadius: handdrawnStyle.borderRadius,
          opacity: isHovered ? 1 : 0,
          background: `radial-gradient(420px circle at ${sheenPos.x}px ${sheenPos.y}px, rgba(0, 0, 0, 0.04), transparent 70%)`,
        }}
      />

      {/* Hand-drawn organic border highlight on hover */}
      <div
        className="pointer-events-none absolute inset-0 transition-opacity duration-300"
        style={{
          borderRadius: handdrawnStyle.borderRadius,
          opacity: isHovered ? 1 : 0,
          boxShadow: 'inset 0 0 0 1.5px rgba(4,4,4,0.35)',
        }}
      />

      {/* Card Content - Rendered with 100% native text sharpness (zero filter blur) */}
      <div className="relative z-10 w-full h-full">
        {children}
      </div>
    </motion.div>
  );
}
