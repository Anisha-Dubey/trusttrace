import { useState, useCallback, useEffect } from 'react';

export type HanddrawnVariant = 'card' | 'pill' | 'box' | 'button' | 'input' | 'round';

export interface HanddrawnStyle {
  borderRadius: string;
  borderWidth: string;
}

/**
 * Authentic hand-drawn box generator with a smooth curve at each of the 4 corners.
 * Uses 8-point organic elliptical curvature (4 horizontal radii / 4 vertical radii)
 * so every corner is a continuous, beautiful curve without sharp kinks or drooping tails,
 * while preserving subtle organic asymmetry so every box looks hand-sketched.
 *
 * Each box instance and every page refresh generates completely unique random curves.
 */
export function generateHanddrawnBorder(variant: HanddrawnVariant = 'card'): HanddrawnStyle {
  const r = (min: number, max: number) => Math.floor(min + Math.random() * (max - min + 1));
  const uniformBw = `${(r(15, 18) / 10).toFixed(1)}px`;

  if (variant === 'pill') {
    return {
      borderRadius: '9999px',
      borderWidth: uniformBw,
    };
  }

  if (variant === 'button' || variant === 'input') {
    // Input / Button: 4 smoothly curved corners with organic variation.
    // Perfectly proportioned (18px - 26px) so there is zero corner drooping or miter overshoot.
    const h1 = r(18, 24);
    const h2 = r(20, 26);
    const h3 = r(18, 24);
    const h4 = r(20, 26);

    const v1 = r(20, 26);
    const v2 = r(18, 24);
    const v3 = r(20, 26);
    const v4 = r(18, 24);

    return {
      borderRadius: `${h1}px ${h2}px ${h3}px ${h4}px / ${v1}px ${v2}px ${v3}px ${v4}px`,
      borderWidth: uniformBw,
    };
  }

  if (variant === 'box') {
    // Benchmark scenario cards & medium containers:
    // 4 smooth handdrawn curved corners (22px to 34px), each corner organically varied.
    const h1 = r(22, 30);
    const h2 = r(24, 34);
    const h3 = r(20, 28);
    const h4 = r(24, 32);

    const v1 = r(24, 34);
    const v2 = r(20, 28);
    const v3 = r(26, 36);
    const v4 = r(22, 30);

    return {
      borderRadius: `${h1}px ${h2}px ${h3}px ${h4}px / ${v1}px ${v2}px ${v3}px ${v4}px`,
      borderWidth: uniformBw,
    };
  }

  if (variant === 'round') {
    // Ultra-curvy container:
    const h1 = r(34, 46);
    const h2 = r(36, 48);
    const h3 = r(32, 44);
    const h4 = r(36, 48);

    const v1 = r(36, 48);
    const v2 = r(32, 44);
    const v3 = r(38, 50);
    const v4 = r(34, 46);

    return {
      borderRadius: `${h1}px ${h2}px ${h3}px ${h4}px / ${v1}px ${v2}px ${v3}px ${v4}px`,
      borderWidth: uniformBw,
    };
  }

  // Default 'card': Large bento panels & evidence cards
  // 4 generous handdrawn curved corners (26px to 40px)
  const h1 = r(26, 36);
  const h2 = r(28, 38);
  const h3 = r(24, 34);
  const h4 = r(28, 38);

  const v1 = r(28, 38);
  const v2 = r(24, 34);
  const v3 = r(30, 42);
  const v4 = r(26, 36);

  return {
    borderRadius: `${h1}px ${h2}px ${h3}px ${h4}px / ${v1}px ${v2}px ${v3}px ${v4}px`,
    borderWidth: uniformBw,
  };
}

/**
 * React hook that yields a unique randomized hand-drawn sketch border on mount
 * and supports re-randomizing (e.g. on pointer hover or refresh).
 */
export function useHanddrawnBorder(variant: HanddrawnVariant = 'card') {
  const [style, setStyle] = useState<HanddrawnStyle>(() => generateHanddrawnBorder(variant));

  useEffect(() => {
    setStyle(generateHanddrawnBorder(variant));
  }, [variant]);

  const morphBorder = useCallback(() => {
    setStyle(generateHanddrawnBorder(variant));
  }, [variant]);

  return { style, morphBorder };
}
