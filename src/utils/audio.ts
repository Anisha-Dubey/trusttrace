// Ultra-refined Web Audio API sound engine with punchy, audible presence
// Higher gain levels calibrated for noticeable audio feedback across device speakers

type SoundListener = (active: boolean) => void;

class SoundEngine {
  private ctx: AudioContext | null = null;
  private enabled: boolean = true;
  private listeners: Set<SoundListener> = new Set();
  private activeSoundsCount = 0;
  private lastTickTime = 0;

  constructor() {
    if (typeof window !== 'undefined') {
      const stored = localStorage.getItem('trusttrace_sfx');
      this.enabled = stored !== 'false';

      // Auto-unlock AudioContext on first user interaction
      const unlock = () => {
        this.initCtx();
        window.removeEventListener('pointerdown', unlock);
        window.removeEventListener('keydown', unlock);
      };
      window.addEventListener('pointerdown', unlock, { passive: true, once: true });
      window.addEventListener('keydown', unlock, { passive: true, once: true });
    }
  }

  private initCtx() {
    if (!this.ctx && typeof window !== 'undefined') {
      const AudioCtx = window.AudioContext || (window as unknown as { webkitAudioContext: typeof AudioContext }).webkitAudioContext;
      if (AudioCtx) {
        this.ctx = new AudioCtx();
      }
    }
    if (this.ctx && this.ctx.state === 'suspended') {
      this.ctx.resume().catch(() => {});
    }
  }

  public subscribe(listener: SoundListener): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  private notify(active: boolean) {
    if (active) {
      this.activeSoundsCount++;
      if (this.activeSoundsCount === 1) {
        this.listeners.forEach((cb) => cb(true));
      }
    } else {
      this.activeSoundsCount = Math.max(0, this.activeSoundsCount - 1);
      if (this.activeSoundsCount === 0) {
        this.listeners.forEach((cb) => cb(false));
      }
    }
  }

  public isEnabled(): boolean {
    return this.enabled;
  }

  public toggle(): boolean {
    this.enabled = !this.enabled;
    if (typeof window !== 'undefined') {
      localStorage.setItem('trusttrace_sfx', this.enabled ? 'true' : 'false');
    }
    if (this.enabled) {
      this.playClick(650, 0.05);
    }
    return this.enabled;
  }

  // 1. Tactile click/pop on button / card hover (Noticeably loud & crisp)
  public playHover() {
    if (!this.enabled) return;
    try {
      this.initCtx();
      if (!this.ctx) return;

      const osc = this.ctx.createOscillator();
      const gain = this.ctx.createGain();
      const filter = this.ctx.createBiquadFilter();

      filter.type = 'lowpass';
      filter.frequency.setValueAtTime(2200, this.ctx.currentTime);

      osc.type = 'sine';
      osc.frequency.setValueAtTime(950, this.ctx.currentTime);
      osc.frequency.exponentialRampToValueAtTime(450, this.ctx.currentTime + 0.035);

      // Louder gain (0.09) with snappy curve
      gain.gain.setValueAtTime(0.09, this.ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.0001, this.ctx.currentTime + 0.035);

      osc.connect(filter);
      filter.connect(gain);
      gain.connect(this.ctx.destination);

      this.notify(true);
      osc.start();
      osc.stop(this.ctx.currentTime + 0.035);
      setTimeout(() => this.notify(false), 40);
    } catch {}
  }

  // 2. Liquid hover ripple droplet (Rich resonant water droplet tone)
  public playLiquid() {
    if (!this.enabled) return;
    try {
      this.initCtx();
      if (!this.ctx) return;

      const osc = this.ctx.createOscillator();
      const mod = this.ctx.createOscillator();
      const modGain = this.ctx.createGain();
      const gain = this.ctx.createGain();

      // FM synthesis for rich organic liquid droplet ripple
      mod.type = 'sine';
      mod.frequency.setValueAtTime(45, this.ctx.currentTime);
      modGain.gain.setValueAtTime(220, this.ctx.currentTime);
      modGain.gain.exponentialRampToValueAtTime(1, this.ctx.currentTime + 0.09);

      mod.connect(modGain);
      modGain.connect(osc.frequency);

      osc.type = 'sine';
      osc.frequency.setValueAtTime(820, this.ctx.currentTime);
      osc.frequency.exponentialRampToValueAtTime(360, this.ctx.currentTime + 0.09);

      // Louder gain (0.14)
      gain.gain.setValueAtTime(0.14, this.ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.0001, this.ctx.currentTime + 0.09);

      osc.connect(gain);
      gain.connect(this.ctx.destination);

      this.notify(true);
      mod.start();
      osc.start();
      mod.stop(this.ctx.currentTime + 0.09);
      osc.stop(this.ctx.currentTime + 0.09);
      setTimeout(() => this.notify(false), 100);
    } catch {}
  }

  // 3. Crisp tactile click (Punchy mechanical & glass attack)
  public playClick(freq = 780, duration = 0.045) {
    if (!this.enabled) return;
    try {
      this.initCtx();
      if (!this.ctx) return;

      const osc1 = this.ctx.createOscillator();
      const osc2 = this.ctx.createOscillator();
      const gain = this.ctx.createGain();

      // Dual-tone layered click for maximum presence
      osc1.type = 'sine';
      osc1.frequency.setValueAtTime(freq, this.ctx.currentTime);
      osc1.frequency.exponentialRampToValueAtTime(freq * 0.3, this.ctx.currentTime + duration);

      osc2.type = 'triangle';
      osc2.frequency.setValueAtTime(freq * 1.5, this.ctx.currentTime);
      osc2.frequency.exponentialRampToValueAtTime(freq * 0.4, this.ctx.currentTime + duration);

      // Louder gain (0.20)
      gain.gain.setValueAtTime(0.20, this.ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.0001, this.ctx.currentTime + duration);

      osc1.connect(gain);
      osc2.connect(gain);
      gain.connect(this.ctx.destination);

      this.notify(true);
      osc1.start();
      osc2.start();
      osc1.stop(this.ctx.currentTime + duration);
      osc2.stop(this.ctx.currentTime + duration);
      setTimeout(() => this.notify(false), duration * 1000 + 15);
    } catch {}
  }

  // 4. Scenario pill select pop (Noticeable organic bubble pop)
  public playPill(freq = 560) {
    if (!this.enabled) return;
    try {
      this.initCtx();
      if (!this.ctx) return;

      const osc = this.ctx.createOscillator();
      const gain = this.ctx.createGain();

      osc.type = 'triangle';
      osc.frequency.setValueAtTime(freq, this.ctx.currentTime);
      osc.frequency.exponentialRampToValueAtTime(freq * 1.5, this.ctx.currentTime + 0.05);

      // Louder gain (0.16)
      gain.gain.setValueAtTime(0.16, this.ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.0001, this.ctx.currentTime + 0.05);

      osc.connect(gain);
      gain.connect(this.ctx.destination);

      this.notify(true);
      osc.start();
      osc.stop(this.ctx.currentTime + 0.05);
      setTimeout(() => this.notify(false), 60);
    } catch {}
  }

  // 5. Telemetry scanner stage blip during active scan
  public playScanBlip(stepIndex: number) {
    if (!this.enabled) return;
    try {
      this.initCtx();
      if (!this.ctx) return;

      const osc = this.ctx.createOscillator();
      const gain = this.ctx.createGain();

      const baseFreq = 480 + stepIndex * 110;
      osc.type = 'sine';
      osc.frequency.setValueAtTime(baseFreq, this.ctx.currentTime);
      osc.frequency.exponentialRampToValueAtTime(baseFreq * 1.45, this.ctx.currentTime + 0.08);

      // Louder gain (0.18)
      gain.gain.setValueAtTime(0.18, this.ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.0001, this.ctx.currentTime + 0.08);

      osc.connect(gain);
      gain.connect(this.ctx.destination);

      this.notify(true);
      osc.start();
      osc.stop(this.ctx.currentTime + 0.08);
      setTimeout(() => this.notify(false), 90);
    } catch {}
  }

  // 6. Adjudication success harmonic chord (Triumphant rich triad)
  public playSuccess() {
    if (!this.enabled) return;
    try {
      this.initCtx();
      if (!this.ctx) return;

      // C5, E5, G5, C6 ascending harmonic triad
      const freqs = [523.25, 659.25, 783.99, 1046.50];
      this.notify(true);

      freqs.forEach((freq, idx) => {
        const osc = this.ctx!.createOscillator();
        const gain = this.ctx!.createGain();

        osc.type = 'sine';
        const start = this.ctx!.currentTime + idx * 0.04;
        const dur = 0.35;

        osc.frequency.setValueAtTime(freq, start);

        // Louder chord tones (0.14)
        gain.gain.setValueAtTime(0.14, start);
        gain.gain.exponentialRampToValueAtTime(0.0001, start + dur);

        osc.connect(gain);
        gain.connect(this.ctx!.destination);

        osc.start(start);
        osc.stop(start + dur);
      });

      setTimeout(() => this.notify(false), 420);
    } catch {}
  }

  // 7. Caution / Lookalike alert tone (Prominent warning drone)
  public playAlert() {
    if (!this.enabled) return;
    try {
      this.initCtx();
      if (!this.ctx) return;

      const osc = this.ctx.createOscillator();
      const gain = this.ctx.createGain();

      osc.type = 'sawtooth';
      osc.frequency.setValueAtTime(320, this.ctx.currentTime);
      osc.frequency.exponentialRampToValueAtTime(160, this.ctx.currentTime + 0.2);

      // Louder gain (0.16)
      gain.gain.setValueAtTime(0.16, this.ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.0001, this.ctx.currentTime + 0.2);

      osc.connect(gain);
      gain.connect(this.ctx.destination);

      this.notify(true);
      osc.start();
      osc.stop(this.ctx.currentTime + 0.2);
      setTimeout(() => this.notify(false), 210);
    } catch {}
  }

  // 8. Faint micro-tick when passing scroll checkpoints
  public playScrollTick() {
    if (!this.enabled) return;
    const now = Date.now();
    if (now - this.lastTickTime < 140) return;
    this.lastTickTime = now;

    try {
      this.initCtx();
      if (!this.ctx) return;

      const osc = this.ctx.createOscillator();
      const gain = this.ctx.createGain();

      osc.type = 'sine';
      osc.frequency.setValueAtTime(1300, this.ctx.currentTime);
      // Increased gain (0.04)
      gain.gain.setValueAtTime(0.04, this.ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.0001, this.ctx.currentTime + 0.02);

      osc.connect(gain);
      gain.connect(this.ctx.destination);

      osc.start();
      osc.stop(this.ctx.currentTime + 0.02);
    } catch {}
  }
}

export const sound = new SoundEngine();
