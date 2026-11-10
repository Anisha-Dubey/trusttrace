import { useState, useCallback, useEffect } from 'react';

export type HanddrawnVariant = 'card' | 'pill' | 'box' | 'button' | 'input' | 'round';

export interface HanddrawnStyle {
  borderRadius: string;
  borderWidth: string;
}

/**
 * Authentic handdrawn sketch border specification (the previous handdrawn system).
 * Generates organic asymmetrical sketch curves with random variations on each mount and hover.
 */
export function generateHanddrawnBorder(variant: HanddrawnVariant = 'card'): HanddrawnStyle {
  const r = (min: number, max: number) => Math.floor(min + Math.random() * (max - min));
  const bw = () => `${(r(14, 24) / 10).toFixed(1)}px`;

  if (variant === 'pill') {
    // Asymmetrical pill with random organic pinch & bulge
    const h1 = r(225, 275);
    const h2 = r(18, 35);
    const h3 = r(210, 260);
    const h4 = r(18, 35);

    const v1 = r(18, 35);
    const v2 = r(210, 260);
    const v3 = r(18, 35);
    const v4 = r(225, 275);

    return {
      borderRadius: `${h1}px ${h2}px ${h3}px ${h4}px / ${v1}px ${v2}px ${v3}px ${v4}px`,
      borderWidth: `${bw()} ${bw()} ${bw()} ${bw()}`,
    };
  }

  if (variant === 'box') {
    // Medium container / scenario tile with irregular hand-drawn curvature
    const h1 = r(18, 36);
    const h2 = r(24, 42);
    const h3 = r(16, 32);
    const h4 = r(22, 38);

    const v1 = r(22, 38);
    const v2 = r(16, 32);
    const v3 = r(26, 44);
    const v4 = r(18, 34);

    return {
      borderRadius: `${h1}px ${h2}px ${h3}px ${h4}px / ${v1}px ${v2}px ${v3}px ${v4}px`,
      borderWidth: `${bw()} ${bw()} ${bw()} ${bw()}`,
    };
  }

  if (variant === 'button' || variant === 'input') {
    // Input / Button with responsive elongated sketch curvature
    const flip = Math.random() > 0.5;
    const h1 = flip ? r(230, 270) : r(16, 28);
    const h2 = flip ? r(16, 28) : r(230, 270);
    const h3 = flip ? r(220, 260) : r(18, 30);
    const h4 = flip ? r(18, 30) : r(220, 260);

    const v1 = flip ? r(16, 30) : r(220, 260);
    const v2 = flip ? r(220, 260) : r(16, 30);
    const v3 = flip ? r(16, 28) : r(225, 265);
    const v4 = flip ? r(225, 265) : r(16, 28);

    return {
      borderRadius: `${h1}px ${h2}px ${h3}px ${h4}px / ${v1}px ${v2}px ${v3}px ${v4}px`,
      borderWidth: `${bw()} ${bw()} ${bw()} ${bw()}`,
    };
  }

  // Default 'card': Large bento box with authentic hand-drawn organic sketch contour
  const pattern = r(0, 4);
  let h1: number, h2: number, h3: number, h4: number;
  let v1: number, v2: number, v3: number, v4: number;

  switch (pattern) {
    case 0:
      h1 = r(230, 270); h2 = r(14, 28); h3 = r(220, 260); h4 = r(16, 32);
      v1 = r(14, 30); v2 = r(215, 255); v3 = r(15, 30); v4 = r(225, 265);
      break;
    case 1:
      h1 = r(16, 32); h2 = r(225, 265); h3 = r(15, 30); h4 = r(220, 260);
      v1 = r(220, 260); v2 = r(14, 28); v3 = r(230, 270); v4 = r(16, 32);
      break;
    case 2:
      h1 = r(240, 280); h2 = r(20, 36); h3 = r(18, 34); h4 = r(210, 250);
      v1 = r(18, 34); v2 = r(220, 260); v3 = r(225, 265); v4 = r(16, 32);
      break;
    default:
      h1 = r(18, 34); h2 = r(210, 250); h3 = r(240, 280); h4 = r(20, 36);
      v1 = r(225, 265); v2 = r(16, 32); v3 = r(18, 34); v4 = r(220, 260);
      break;
  }

  return {
    borderRadius: `${h1}px ${h2}px ${h3}px ${h4}px / ${v1}px ${v2}px ${v3}px ${v4}px`,
    borderWidth: `${bw()} ${bw()} ${bw()} ${bw()}`,
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
