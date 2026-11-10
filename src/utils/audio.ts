// Ultra-refined Web Audio API sound engine for Osply-style tactile micro-interactions
// Zero external assets required — synthesized via pure Web Audio API oscillators and filters

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
      this.playClick();
    }
    return this.enabled;
  }

  // 1. Soft organic tactile tick on button / card hover (Osply style)
  public playHover() {
    if (!this.enabled) return;
    try {
      this.initCtx();
      if (!this.ctx) return;

      const osc = this.ctx.createOscillator();
      const gain = this.ctx.createGain();
      const filter = this.ctx.createBiquadFilter();

      filter.type = 'lowpass';
      filter.frequency.setValueAtTime(1600, this.ctx.currentTime);

      osc.type = 'sine';
      osc.frequency.setValueAtTime(850, this.ctx.currentTime);
      osc.frequency.exponentialRampToValueAtTime(420, this.ctx.currentTime + 0.025);

      gain.gain.setValueAtTime(0.02, this.ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.0001, this.ctx.currentTime + 0.025);

      osc.connect(filter);
      filter.connect(gain);
      gain.connect(this.ctx.destination);

      this.notify(true);
      osc.start();
      osc.stop(this.ctx.currentTime + 0.025);
      setTimeout(() => this.notify(false), 30);
    } catch {}
  }

  // 2. Liquid hover ripple droplet (Osply signature water/fluid morph)
  public playLiquid() {
    if (!this.enabled) return;
    try {
      this.initCtx();
      if (!this.ctx) return;

      const osc = this.ctx.createOscillator();
      const mod = this.ctx.createOscillator();
      const modGain = this.ctx.createGain();
      const gain = this.ctx.createGain();

      // FM synthesis for organic liquid droplet ripple
      mod.type = 'sine';
      mod.frequency.setValueAtTime(35, this.ctx.currentTime);
      modGain.gain.setValueAtTime(140, this.ctx.currentTime);
      modGain.gain.exponentialRampToValueAtTime(1, this.ctx.currentTime + 0.07);

      mod.connect(modGain);
      modGain.connect(osc.frequency);

      osc.type = 'sine';
      osc.frequency.setValueAtTime(740, this.ctx.currentTime);
      osc.frequency.exponentialRampToValueAtTime(320, this.ctx.currentTime + 0.07);

      gain.gain.setValueAtTime(0.035, this.ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.0001, this.ctx.currentTime + 0.07);

      osc.connect(gain);
      gain.connect(this.ctx.destination);

      this.notify(true);
      mod.start();
      osc.start();
      mod.stop(this.ctx.currentTime + 0.07);
      osc.stop(this.ctx.currentTime + 0.07);
      setTimeout(() => this.notify(false), 80);
    } catch {}
  }

  // 3. Crisp tactile click (glass / mechanical hybrid)
  public playClick(freq = 720, duration = 0.035) {
    if (!this.enabled) return;
    try {
      this.initCtx();
      if (!this.ctx) return;

      const osc = this.ctx.createOscillator();
      const gain = this.ctx.createGain();

      osc.type = 'sine';
      osc.frequency.setValueAtTime(freq, this.ctx.currentTime);
      osc.frequency.exponentialRampToValueAtTime(freq * 0.35, this.ctx.currentTime + duration);

      gain.gain.setValueAtTime(0.065, this.ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.0001, this.ctx.currentTime + duration);

      osc.connect(gain);
      gain.connect(this.ctx.destination);

      this.notify(true);
      osc.start();
      osc.stop(this.ctx.currentTime + duration);
      setTimeout(() => this.notify(false), duration * 1000 + 10);
    } catch {}
  }

  // 4. Scenario pill select pop
  public playPill(freq = 520) {
    if (!this.enabled) return;
    try {
      this.initCtx();
      if (!this.ctx) return;

      const osc = this.ctx.createOscillator();
      const gain = this.ctx.createGain();

      osc.type = 'triangle';
      osc.frequency.setValueAtTime(freq, this.ctx.currentTime);
      osc.frequency.exponentialRampToValueAtTime(freq * 1.4, this.ctx.currentTime + 0.04);

      gain.gain.setValueAtTime(0.04, this.ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.0001, this.ctx.currentTime + 0.04);

      osc.connect(gain);
      gain.connect(this.ctx.destination);

      this.notify(true);
      osc.start();
      osc.stop(this.ctx.currentTime + 0.04);
      setTimeout(() => this.notify(false), 50);
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

      const baseFreq = 420 + stepIndex * 90;
      osc.type = 'sine';
      osc.frequency.setValueAtTime(baseFreq, this.ctx.currentTime);
      osc.frequency.exponentialRampToValueAtTime(baseFreq * 1.35, this.ctx.currentTime + 0.07);

      gain.gain.setValueAtTime(0.045, this.ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.0001, this.ctx.currentTime + 0.07);

      osc.connect(gain);
      gain.connect(this.ctx.destination);

      this.notify(true);
      osc.start();
      osc.stop(this.ctx.currentTime + 0.07);
      setTimeout(() => this.notify(false), 80);
    } catch {}
  }

  // 6. Adjudication success harmonic chord
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
        const start = this.ctx!.currentTime + idx * 0.035;
        const dur = 0.28;

        osc.frequency.setValueAtTime(freq, start);

        gain.gain.setValueAtTime(0.035, start);
        gain.gain.exponentialRampToValueAtTime(0.0001, start + dur);

        osc.connect(gain);
        gain.connect(this.ctx!.destination);

        osc.start(start);
        osc.stop(start + dur);
      });

      setTimeout(() => this.notify(false), 380);
    } catch {}
  }

  // 7. Caution / Lookalike alert tone
  public playAlert() {
    if (!this.enabled) return;
    try {
      this.initCtx();
      if (!this.ctx) return;

      const osc = this.ctx.createOscillator();
      const gain = this.ctx.createGain();

      osc.type = 'sawtooth';
      osc.frequency.setValueAtTime(280, this.ctx.currentTime);
      osc.frequency.exponentialRampToValueAtTime(140, this.ctx.currentTime + 0.16);

      gain.gain.setValueAtTime(0.04, this.ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.0001, this.ctx.currentTime + 0.16);

      osc.connect(gain);
      gain.connect(this.ctx.destination);

      this.notify(true);
      osc.start();
      osc.stop(this.ctx.currentTime + 0.16);
      setTimeout(() => this.notify(false), 170);
    } catch {}
  }

  // 8. Faint micro-tick when passing slide checkpoints during scroll
  public playScrollTick() {
    if (!this.enabled) return;
    const now = Date.now();
    if (now - this.lastTickTime < 140) return; // Debounce rapid triggers
    this.lastTickTime = now;

    try {
      this.initCtx();
      if (!this.ctx) return;

      const osc = this.ctx.createOscillator();
      const gain = this.ctx.createGain();

      osc.type = 'sine';
      osc.frequency.setValueAtTime(1200, this.ctx.currentTime);
      gain.gain.setValueAtTime(0.008, this.ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.0001, this.ctx.currentTime + 0.015);

      osc.connect(gain);
      gain.connect(this.ctx.destination);

      osc.start();
      osc.stop(this.ctx.currentTime + 0.015);
    } catch {}
  }
}

export const sound = new SoundEngine();
