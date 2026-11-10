import { useState, useCallback, useEffect } from 'react';

export type HanddrawnVariant = 'card' | 'pill' | 'box' | 'button' | 'input' | 'round';

export interface HanddrawnStyle {
  borderRadius: string;
  borderWidth: string;
}

/**
 * Authentic hand-drawn box generator with a smooth curve at each of the 4 corners
 * and organic sketched edges (using alternating 220-275px and 14-26px elliptical radii).
 * Every box instance and every page refresh generates a completely unique random contour.
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

  if (variant === 'input') {
    // Input field: Fixed height ~54px. Bowed horizontal span with 20-26px vertical radii
    // to prevent miter overshoot while maintaining authentic hand-sketched character.
    const chirality = Math.random() > 0.5;
    const l1 = r(230, 265);
    const l2 = r(215, 250);
    const s1 = r(18, 26);
    const s2 = r(18, 26);
    const v1 = r(20, 26);
    const v2 = r(22, 28);
    const v3 = r(20, 26);
    const v4 = r(22, 28);

    const h = chirality ? [l1, s1, l2, s2] : [s1, l1, s2, l2];
    return {
      borderRadius: `${h[0]}px ${h[1]}px ${h[2]}px ${h[3]}px / ${v1}px ${v2}px ${v3}px ${v4}px`,
      borderWidth: uniformBw,
    };
  }

  // Authentic hand-drawn sketch box with 4 curved corners and subtle organic bowed lines.
  // Alternating large (215-275px) & small (14-26px) radii across 4 chiral configurations
  // guarantees every card, box, and container is completely unique and differently drawn!
  const mode = Math.floor(Math.random() * 4);
  const isCard = variant === 'card' || variant === 'round';
  const lMin = isCard ? 235 : 215;
  const lMax = isCard ? 275 : 255;
  const sMin = isCard ? 16 : 14;
  const sMax = isCard ? 26 : 22;

  const L = () => r(lMin, lMax);
  const S = () => r(sMin, sMax);

  let h: number[];
  let v: number[];

  switch (mode) {
    case 0:
      h = [L(), S(), L(), S()];
      v = [S(), L(), S(), L()];
      break;
    case 1:
      h = [S(), L(), S(), L()];
      v = [L(), S(), L(), S()];
      break;
    case 2:
      h = [L(), S(), S(), L()];
      v = [S(), L(), L(), S()];
      break;
    case 3:
    default:
      h = [S(), L(), L(), S()];
      v = [L(), S(), S(), L()];
      break;
  }

  return {
    borderRadius: `${h[0]}px ${h[1]}px ${h[2]}px ${h[3]}px / ${v[0]}px ${v[1]}px ${v[2]}px ${v[3]}px`,
    borderWidth: uniformBw,
  };
}

export interface HanddrawnCirclePaths {
  primaryPath: string;
  sketchPath: string;
}

/**
 * Procedural hand-drawn circle generator matching the user's sketch attachment.
 * Generates an organic, imperfect sketched circular loop with a secondary ink line.
 * Completely re-randomized on every page refresh and whenever the pointer enters an input.
 */
export function generateHanddrawnCircle(cx = 32, cy = 32, baseR = 26.5, numPts = 16): HanddrawnCirclePaths {
  const angles: number[] = [];
  const step = (2 * Math.PI) / numPts;
  for (let i = 0; i < numPts; i++) {
    angles.push(i * step);
  }

  const eccentricityAngle = Math.random() * 2 * Math.PI;
  const eccentricityAmount = 0.6 + Math.random() * 1.6;

  const radii1 = angles.map((a) => {
    const oval = eccentricityAmount * Math.cos(2 * (a - eccentricityAngle));
    const jitter = (Math.random() - 0.5) * 3.4;
    return baseR + oval + jitter;
  });

  const radii2 = angles.map((a) => {
    const oval = eccentricityAmount * 0.9 * Math.cos(2 * (a - eccentricityAngle));
    const jitter = (Math.random() - 0.5) * 2.8;
    return baseR * 0.99 + oval + jitter;
  });

  const toSvgPath = (radii: number[]) => {
    const pts = angles.map((a, i) => {
      const r = radii[i];
      const x = Number((cx + r * Math.cos(a)).toFixed(1));
      const y = Number((cy + r * Math.sin(a)).toFixed(1));
      return [x, y] as [number, number];
    });

    const n = pts.length;
    let d = `M ${pts[0][0]},${pts[0][1]} `;
    for (let i = 0; i < n; i++) {
      const p0 = pts[(i - 1 + n) % n];
      const p1 = pts[i];
      const p2 = pts[(i + 1) % n];
      const p3 = pts[(i + 2) % n];

      const cp1x = Number((p1[0] + (p2[0] - p0[0]) / 6.0).toFixed(1));
      const cp1y = Number((p1[1] + (p2[1] - p0[1]) / 6.0).toFixed(1));
      const cp2x = Number((p2[0] - (p3[0] - p1[0]) / 6.0).toFixed(1));
      const cp2y = Number((p2[1] - (p3[1] - p1[1]) / 6.0).toFixed(1));

      d += `C ${cp1x},${cp1y} ${cp2x},${cp2y} ${p2[0]},${p2[1]} `;
    }
    d += 'Z';
    return d;
  };

  return {
    primaryPath: toSvgPath(radii1),
    sketchPath: toSvgPath(radii2),
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
