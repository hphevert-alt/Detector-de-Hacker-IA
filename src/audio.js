export class CyberAlertAudio {
  constructor() {
    this.ctx = null;
    this.enabled = true;
    this.loopTimer = null;
    this.pulseCount = 0;
    this.maxPulses = 14;
  }

  setEnabled(enabled) {
    this.enabled = Boolean(enabled);
    if (!this.enabled) {
      this.stopAlert();
    }
  }

  unlock() {
    if (typeof window === 'undefined') return;
    const AudioCtx = window.AudioContext || window.webkitAudioContext;
    if (!AudioCtx) return;

    if (!this.ctx) {
      try {
        this.ctx = new AudioCtx();
      } catch {
        this.ctx = null;
        return;
      }
    }

    if (this.ctx.state === 'suspended') {
      this.ctx.resume().catch(() => {});
    }
  }

  playSinglePulse() {
    if (!this.enabled) return;
    this.unlock();
    if (!this.ctx) return;

    const triggerOscillator = () => {
      if (!this.enabled || !this.ctx || this.ctx.state !== 'running') return;
      const now = this.ctx.currentTime;

      const osc = this.ctx.createOscillator();
      const filter = this.ctx.createBiquadFilter();
      const gain = this.ctx.createGain();

      osc.type = 'sawtooth';
      osc.frequency.setValueAtTime(920, now);
      osc.frequency.exponentialRampToValueAtTime(580, now + 0.16);
      osc.frequency.setValueAtTime(860, now + 0.22);
      osc.frequency.exponentialRampToValueAtTime(520, now + 0.38);

      filter.type = 'lowpass';
      filter.frequency.setValueAtTime(2200, now);

      gain.gain.setValueAtTime(0.0001, now);
      gain.gain.exponentialRampToValueAtTime(0.11, now + 0.025);
      gain.gain.exponentialRampToValueAtTime(0.0001, now + 0.19);
      gain.gain.setValueAtTime(0.0001, now + 0.21);
      gain.gain.exponentialRampToValueAtTime(0.1, now + 0.24);
      gain.gain.exponentialRampToValueAtTime(0.0001, now + 0.42);

      osc.connect(filter);
      filter.connect(gain);
      gain.connect(this.ctx.destination);

      osc.start(now);
      osc.stop(now + 0.45);
    };

    if (this.ctx.state === 'suspended') {
      this.ctx.resume().then(triggerOscillator).catch(() => {});
    } else {
      triggerOscillator();
    }
  }

  startAlert() {
    if (!this.enabled) return;
    this.stopAlert();
    this.pulseCount = 0;

    this.playSinglePulse();
    this.pulseCount += 1;

    this.loopTimer = window.setInterval(() => {
      if (!this.enabled || this.pulseCount >= this.maxPulses) {
        this.stopAlert();
        return;
      }
      this.playSinglePulse();
      this.pulseCount += 1;
    }, 1500);
  }

  stopAlert() {
    if (this.loopTimer !== null) {
      window.clearInterval(this.loopTimer);
      this.loopTimer = null;
    }
    this.pulseCount = 0;
  }
}
