import { useEffect } from 'react';

/**
 * Invisible SVG displacement filter for authentic Osply-style liquid distortion.
 * Animates turbulence frequency and displacement scale on hover triggers.
 */
export default function LiquidFilter() {
  useEffect(() => {
    let animId: number;
    let baseScale = 0;
    let targetScale = 0;
    let baseFreq = 0.02;
    let phase = 0;

    const dispMap = document.getElementById('liquid-disp-map') as SVGFEDisplacementMapElement | null;
    const turb = document.getElementById('liquid-turbulence') as SVGFETurbulenceElement | null;

    // Listen for custom trigger events or element hovers
    const handleTriggerWarp = (e: CustomEvent<{ scale?: number }>) => {
      targetScale = e.detail?.scale ?? 10;
    };

    window.addEventListener('trusttrace-liquid-warp' as never, handleTriggerWarp as EventListener);

    function loop() {
      // Lerp scale back to 0
      baseScale += (targetScale - baseScale) * 0.12;
      targetScale += (0 - targetScale) * 0.08;

      if (dispMap) {
        dispMap.scale.baseVal = Math.max(0, baseScale);
      }
      if (turb && baseScale > 0.1) {
        phase += 0.04;
        turb.baseFrequencyX.baseVal = baseFreq + Math.sin(phase) * 0.006;
        turb.baseFrequencyY.baseVal = baseFreq + Math.cos(phase) * 0.006;
      }

      animId = requestAnimationFrame(loop);
    }
    animId = requestAnimationFrame(loop);

    return () => {
      cancelAnimationFrame(animId);
      window.removeEventListener('trusttrace-liquid-warp' as never, handleTriggerWarp as EventListener);
    };
  }, []);

  return (
    <svg className="sr-only" aria-hidden="true">
      <defs>
        <filter id="liquid-warp" x="-15%" y="-15%" width="130%" height="130%" colorInterpolationFilters="sRGB">
          <feTurbulence
            id="liquid-turbulence"
            type="fractalNoise"
            baseFrequency="0.02 0.02"
            numOctaves="2"
            result="noise"
            seed="3"
          />
          <feDisplacementMap
            id="liquid-disp-map"
            in="SourceGraphic"
            in2="noise"
            scale="0"
            xChannelSelector="R"
            yChannelSelector="G"
          />
        </filter>

        {/* Secondary soft liquid ripple for card borders */}
        <filter id="liquid-glass-refract" x="-10%" y="-10%" width="120%" height="120%">
          <feTurbulence type="turbulence" baseFrequency="0.04 0.03" numOctaves="3" result="glassNoise" seed="7" />
          <feDisplacementMap in="SourceGraphic" in2="glassNoise" scale="3" xChannelSelector="G" yChannelSelector="B" />
        </filter>
      </defs>
    </svg>
  );
}

export function triggerLiquidWarp(scale = 12) {
  if (typeof window !== 'undefined') {
    window.dispatchEvent(new CustomEvent('trusttrace-liquid-warp', { detail: { scale } }));
  }
}
