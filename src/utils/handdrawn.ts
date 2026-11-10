import { useState, useCallback, useEffect } from 'react';

export type HanddrawnVariant = 'card' | 'pill' | 'box' | 'button' | 'input' | 'round';

export interface HanddrawnStyle {
  borderRadius: string;
  borderWidth: string;
}

/**
 * Generates an organic, hand-drawn ROUND CORNER specification.
 * Every invocation returns a completely unique combination of 8 corner radii
 * and 4 distinct border widths, ensuring every box has visibly round,
 * curvy corners while remaining uniquely sketched (no two boxes look alike).
 */
export function generateHanddrawnBorder(variant: HanddrawnVariant = 'card'): HanddrawnStyle {
  const r = (min: number, max: number) => Math.floor(min + Math.random() * (max - min + 1));
  const bw = () => `${(r(15, 23) / 10).toFixed(1)}px`;

  if (variant === 'pill') {
    // Fully rounded pill/capsule with organic subtle sketch variation
    const h1 = r(28, 38);
    const h2 = r(28, 38);
    const h3 = r(28, 38);
    const h4 = r(28, 38);

    const v1 = r(26, 36);
    const v2 = r(26, 36);
    const v3 = r(26, 36);
    const v4 = r(26, 36);

    return {
      borderRadius: `${h1}px ${h2}px ${h3}px ${h4}px / ${v1}px ${v2}px ${v3}px ${v4}px`,
      borderWidth: `${bw()} ${bw()} ${bw()} ${bw()}`,
    };
  }

  if (variant === 'button' || variant === 'input') {
    // Generously rounded button / input corners (round ~22px to 32px)
    const h1 = r(22, 30);
    const h2 = r(20, 28);
    const h3 = r(24, 32);
    const h4 = r(20, 28);

    const v1 = r(20, 28);
    const v2 = r(22, 30);
    const v3 = r(20, 28);
    const v4 = r(24, 32);

    return {
      borderRadius: `${h1}px ${h2}px ${h3}px ${h4}px / ${v1}px ${v2}px ${v3}px ${v4}px`,
      borderWidth: `${bw()} ${bw()} ${bw()} ${bw()}`,
    };
  }

  if (variant === 'box') {
    // Medium container / scenario tile with prominent round corners (round ~24px to 36px)
    const h1 = r(24, 36);
    const h2 = r(22, 34);
    const h3 = r(26, 38);
    const h4 = r(22, 34);

    const v1 = r(22, 34);
    const v2 = r(26, 38);
    const v3 = r(22, 34);
    const v4 = r(26, 38);

    return {
      borderRadius: `${h1}px ${h2}px ${h3}px ${h4}px / ${v1}px ${v2}px ${v3}px ${v4}px`,
      borderWidth: `${bw()} ${bw()} ${bw()} ${bw()}`,
    };
  }

  if (variant === 'round') {
    // Ultra-curvy round container (round ~38px to 54px)
    const h1 = r(40, 54);
    const h2 = r(36, 50);
    const h3 = r(42, 56);
    const h4 = r(38, 52);

    const v1 = r(38, 52);
    const v2 = r(42, 56);
    const v3 = r(36, 50);
    const v4 = r(40, 54);

    return {
      borderRadius: `${h1}px ${h2}px ${h3}px ${h4}px / ${v1}px ${v2}px ${v3}px ${v4}px`,
      borderWidth: `${bw()} ${bw()} ${bw()} ${bw()}`,
    };
  }

  // Default 'card': Bento boxes & evidence panels with generous, smooth round corners (~32px to 48px)
  // Both horizontal and vertical radii are calibrated to maintain prominent, unmistakable roundness
  // with delightful organic hand-drawn irregularity.
  const h1 = r(32, 46);
  const h2 = r(30, 44);
  const h3 = r(34, 48);
  const h4 = r(30, 44);

  const v1 = r(30, 44);
  const v2 = r(34, 48);
  const v3 = r(30, 44);
  const v4 = r(34, 48);

  return {
    borderRadius: `${h1}px ${h2}px ${h3}px ${h4}px / ${v1}px ${v2}px ${v3}px ${v4}px`,
    borderWidth: `${bw()} ${bw()} ${bw()} ${bw()}`,
  };
}

/**
 * React hook that yields a unique randomized hand-drawn round border on mount
 * and supports re-randomizing (e.g. on pointer hover or interaction).
 */
export function useHanddrawnBorder(variant: HanddrawnVariant = 'card') {
  const [style, setStyle] = useState<HanddrawnStyle>(() => generateHanddrawnBorder(variant));

  // Re-generate once on client mount to ensure fresh procedural shape
  useEffect(() => {
    setStyle(generateHanddrawnBorder(variant));
  }, [variant]);

  const morphBorder = useCallback(() => {
    setStyle(generateHanddrawnBorder(variant));
  }, [variant]);

  return { style, morphBorder };
}
