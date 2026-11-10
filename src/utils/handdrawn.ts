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
    // Input / Button: 4 smoothly curved corners with noticeable organic variation.
    // Perfectly proportioned (16px - 28px) so there is zero corner drooping or miter overshoot.
    const h1 = r(16, 26);
    const h2 = r(18, 28);
    const h3 = r(16, 26);
    const h4 = r(18, 28);

    const v1 = r(18, 28);
    const v2 = r(16, 26);
    const v3 = r(18, 28);
    const v4 = r(16, 26);

    return {
      borderRadius: `${h1}px ${h2}px ${h3}px ${h4}px / ${v1}px ${v2}px ${v3}px ${v4}px`,
      borderWidth: uniformBw,
    };
  }

  if (variant === 'box') {
    // Benchmark scenario cards & medium containers:
    // 4 smooth handdrawn curved corners (18px to 38px), each corner organically varied on every refresh.
    const h1 = r(18, 36);
    const h2 = r(22, 38);
    const h3 = r(18, 34);
    const h4 = r(22, 38);

    const v1 = r(22, 38);
    const v2 = r(18, 34);
    const v3 = r(24, 40);
    const v4 = r(20, 36);

    return {
      borderRadius: `${h1}px ${h2}px ${h3}px ${h4}px / ${v1}px ${v2}px ${v3}px ${v4}px`,
      borderWidth: uniformBw,
    };
  }

  if (variant === 'round') {
    // Ultra-curvy container:
    const h1 = r(32, 48);
    const h2 = r(34, 50);
    const h3 = r(30, 46);
    const h4 = r(34, 50);

    const v1 = r(34, 50);
    const v2 = r(30, 46);
    const v3 = r(36, 52);
    const v4 = r(32, 48);

    return {
      borderRadius: `${h1}px ${h2}px ${h3}px ${h4}px / ${v1}px ${v2}px ${v3}px ${v4}px`,
      borderWidth: uniformBw,
    };
  }

  // Default 'card': Large bento panels & evidence cards
  // 4 generous handdrawn curved corners (20px to 44px) dynamically randomized on every refresh
  const h1 = r(22, 42);
  const h2 = r(26, 44);
  const h3 = r(20, 38);
  const h4 = r(24, 42);

  const v1 = r(24, 42);
  const v2 = r(20, 38);
  const v3 = r(26, 44);
  const v4 = r(22, 40);

  return {
    borderRadius: `${h1}px ${h2}px ${h3}px ${h4}px / ${v1}px ${v2}px ${v3}px ${v4}px`,
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
