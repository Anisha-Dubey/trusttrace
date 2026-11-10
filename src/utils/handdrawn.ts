import { useState, useCallback, useEffect } from 'react';

export type HanddrawnVariant = 'card' | 'pill' | 'box' | 'button' | 'input' | 'round';

export interface HanddrawnStyle {
  borderRadius: string;
  borderWidth: string;
}

/**
 * Generates an organic hand-drawn box with a smooth CURVE at each of the 4 corners.
 * Uses 4 independent circular radii (Top-Left, Top-Right, Bottom-Right, Bottom-Left)
 * so every corner is an unmistakable, continuous, smooth curve (zero sharp tips/kinks),
 * while remaining hand-sketched with subtle organic irregularity.
 *
 * Every page refresh and every box instance generates completely unique random curve values.
 */
export function generateHanddrawnBorder(variant: HanddrawnVariant = 'card'): HanddrawnStyle {
  const r = (min: number, max: number) => Math.floor(min + Math.random() * (max - min + 1));
  const bw = (minW = 15, maxW = 18) => `${(r(minW, maxW) / 10).toFixed(1)}px`;

  if (variant === 'pill') {
    // Smooth capsule pill with subtle organic corner variation
    const r1 = r(999, 999);
    return {
      borderRadius: '9999px',
      borderWidth: bw(15, 18),
    };
  }

  if (variant === 'input' || variant === 'button') {
    // Input / Button: 4 smooth curved corners, randomly varied between 18px and 26px
    // Each corner is guaranteed to be a clean, smooth, beautiful curve
    const r1 = r(18, 25);
    const r2 = r(19, 26);
    const r3 = r(18, 25);
    const r4 = r(19, 26);
    const borderW = bw(15, 18);

    return {
      borderRadius: `${r1}px ${r2}px ${r3}px ${r4}px`,
      borderWidth: borderW,
    };
  }

  if (variant === 'box') {
    // Medium container / Scenario tile: 4 smooth curved corners (~22px to 32px)
    const r1 = r(22, 30);
    const r2 = r(24, 32);
    const r3 = r(22, 30);
    const r4 = r(24, 32);
    const borderW = bw(15, 18);

    return {
      borderRadius: `${r1}px ${r2}px ${r3}px ${r4}px`,
      borderWidth: borderW,
    };
  }

  if (variant === 'round') {
    // Ultra-curvy container: 4 large smooth curved corners (~36px to 48px)
    const r1 = r(36, 46);
    const r2 = r(38, 48);
    const r3 = r(36, 46);
    const r4 = r(38, 48);
    const borderW = bw(16, 20);

    return {
      borderRadius: `${r1}px ${r2}px ${r3}px ${r4}px`,
      borderWidth: borderW,
    };
  }

  // Default 'card': Bento boxes & evidence panels
  // 4 generous, smooth curved corners (~28px to 40px)
  const r1 = r(28, 38);
  const r2 = r(30, 40);
  const r3 = r(28, 38);
  const r4 = r(30, 40);
  const borderW = bw(15, 19);

  return {
    borderRadius: `${r1}px ${r2}px ${r3}px ${r4}px`,
    borderWidth: borderW,
  };
}

/**
 * React hook that yields a unique randomized hand-drawn curved border on mount
 * and supports re-randomizing (e.g. on pointer hover or page refresh).
 *
 * Every time the page is refreshed or component mounts, fresh random curves are generated.
 */
export function useHanddrawnBorder(variant: HanddrawnVariant = 'card') {
  const [style, setStyle] = useState<HanddrawnStyle>(() => generateHanddrawnBorder(variant));

  // Re-generate once on client mount to guarantee fresh random curves on every page refresh
  useEffect(() => {
    setStyle(generateHanddrawnBorder(variant));
  }, [variant]);

  const morphBorder = useCallback(() => {
    setStyle(generateHanddrawnBorder(variant));
  }, [variant]);

  return { style, morphBorder };
}
