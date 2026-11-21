const BG_LAST_TICK_KEY = 'aegis_ai_v1_bg_last_tick';

const BACKGROUND_DOMAINS = [
  { domain: 'api.escudo-local.dev', urlPath: '/bg/heartbeat', category: 'essential' },
  { domain: 'dns.cloudflare-dns.com', urlPath: '/dns-query', category: 'essential' },
  { domain: 'www.google-analytics.com', urlPath: '/g/collect?bg=1', category: 'tracker' },
  { domain: 'stats.g.doubleclick.net', urlPath: '/r/collect?bg=1', category: 'tracker' },
  { domain: 'gptbot.openai.test', urlPath: '/crawler/bg-probe', category: 'ai_crawler' },
];

export class AegisBackgroundMonitor {
  constructor() {
    this.isNativeRunning = false;
    this._reconciling = false;
    this._worker = null;
    this._workerUrl = null;
  }

  getNativePlugin() {
    if (typeof window === 'undefined') return null;
    const win = /** @type {any} */ (window);
    return win.Capacitor?.Plugins?.AegisBackground || null;
  }

  isNativeAndroid() {
    if (typeof window === 'undefined') return false;
    const win = /** @type {any} */ (window);
    return Boolean(win.Capacitor?.isNativePlatform?.() && this.getNativePlugin());
  }

  markHeartbeatTimestamp() {
    try {
      window.localStorage.setItem(BG_LAST_TICK_KEY, String(Date.now()));
    } catch {
      // ignore storage quota errors
    }
  }

  readLastTimestamp() {
    try {
      const raw = window.localStorage.getItem(BG_LAST_TICK_KEY);
      const parsed = raw ? Number(raw) : 0;
      return Number.isFinite(parsed) ? parsed : 0;
    } catch {
      return 0;
    }
  }

  _startWebWorkerHeartbeat() {
    if (this._worker || typeof Worker === 'undefined' || typeof Blob === 'undefined') return;
    try {
      const workerCode = 'setInterval(() => postMessage(Date.now()), 5000);';
      const blob = new Blob([workerCode], { type: 'application/javascript' });
      this._workerUrl = URL.createObjectURL(blob);
      this._worker = new Worker(this._workerUrl);
      this._worker.onmessage = () => {
        this.markHeartbeatTimestamp();
      };
    } catch {
      this._stopWebWorkerHeartbeat();
    }
  }

  _stopWebWorkerHeartbeat() {
    if (this._worker) {
      try {
        this._worker.terminate();
      } catch {
        // ignore
      }
      this._worker = null;
    }
    if (this._workerUrl) {
      try {
        URL.revokeObjectURL(this._workerUrl);
      } catch {
        // ignore
      }
      this._workerUrl = null;
    }
  }

  async syncState({ vpnActive, backgroundMode, dnsLabel = '1.1.1.2 (DoH)', rulesCount = 19 }) {
    const shouldRun = Boolean(vpnActive && backgroundMode);
    if (shouldRun) {
      this.markHeartbeatTimestamp();
      this._startWebWorkerHeartbeat();
    } else {
      this._stopWebWorkerHeartbeat();
      try {
        window.localStorage.removeItem(BG_LAST_TICK_KEY);
      } catch {
        // ignore
      }
    }

    const plugin = this.getNativePlugin();
    if (!plugin) {
      this.isNativeRunning = false;
      return { running: shouldRun, native: false };
    }

    try {
      if (shouldRun) {
        const res = await plugin.startMonitoring({ dnsLabel, rulesCount });
        this.isNativeRunning = Boolean(res?.running ?? true);
      } else {
        await plugin.stopMonitoring();
        this.isNativeRunning = false;
      }
      return { running: this.isNativeRunning, native: true };
    } catch {
      return { running: this.isNativeRunning, native: true };
    }
  }

  async minimizeToBackground({ dnsLabel = '1.1.1.2 (DoH)', rulesCount = 19 } = {}) {
    this.markHeartbeatTimestamp();
    this._startWebWorkerHeartbeat();
    const plugin = this.getNativePlugin();
    if (plugin?.minimizeToBackground) {
      try {
        const res = await plugin.minimizeToBackground({ dnsLabel, rulesCount });
        this.isNativeRunning = Boolean(res?.running ?? true);
        return { native: true, minimized: Boolean(res?.minimized) };
      } catch {
        return { native: true, minimized: false };
      }
    }
    return { native: false, minimized: false };
  }

  async getBatteryOptimizationStatus() {
    const plugin = this.getNativePlugin();
    if (!plugin?.isIgnoringBatteryOptimizations) {
      return { supported: false, ignoring: true };
    }
    try {
      const res = await plugin.isIgnoringBatteryOptimizations();
      return { supported: true, ignoring: Boolean(res?.ignoring) };
    } catch {
      return { supported: false, ignoring: true };
    }
  }

  async requestBatteryOptimizationExemption() {
    const plugin = this.getNativePlugin();
    if (!plugin?.requestBatteryOptimizationExemption) {
      return { launched: false };
    }
    try {
      const res = await plugin.requestBatteryOptimizationExemption();
      return { launched: Boolean(res?.launched) };
    } catch {
      return { launched: false };
    }
  }

  async reconcileOnResume({ storage, engine, onSyncResult }) {
    if (this._reconciling) return;
    this._reconciling = true;

    try {
      const settings = await storage.getSettings();
      const plugin = this.getNativePlugin();
      let nativeReport = null;

      if (plugin) {
        try {
          nativeReport = await plugin.consumePendingReport();
          this.isNativeRunning = Boolean(nativeReport?.running);
        } catch {
          nativeReport = null;
        }
      }

      if (nativeReport?.stoppedFromNotification && settings.vpnActive) {
        const updated = await storage.saveSettings({
          ...settings,
          vpnActive: false,
        });
        this._stopWebWorkerHeartbeat();
        await onSyncResult?.({
          stoppedFromNotification: true,
          updatedSettings: updated,
          cyclesProcessed: 0,
          networkEvents: 0,
        });
        return;
      }

      if (!settings.vpnActive || settings.backgroundMode === false) {
        return;
      }

      const now = Date.now();
      const lastTick = this.readLastTimestamp();
      const elapsedMs = lastTick > 0 ? Math.max(0, now - lastTick) : 0;
      const estimatedCycles = elapsedMs >= 15_000 ? Math.min(24, Math.floor(elapsedMs / 15_000)) : 0;
      const nativeCycles = nativeReport?.pendingCycles || 0;
      const cyclesToRecord = Math.min(24, Math.max(nativeCycles, estimatedCycles));
      const networkEvents = nativeReport?.networkEvents || 0;

      this.markHeartbeatTimestamp();

      if (cyclesToRecord > 0 || networkEvents > 0) {
        for (let i = 0; i < cyclesToRecord; i++) {
          let sample;
          if (i % 6 === 5) {
            sample = BACKGROUND_DOMAINS[4];
          } else if (i % 4 === 3) {
            sample = BACKGROUND_DOMAINS[2 + (i % 2)];
          } else {
            sample = BACKGROUND_DOMAINS[i % 2];
          }
          await engine.processRequest(sample.domain, sample.urlPath, sample.category, {
            isAmbient: true,
          });
        }

        if (networkEvents > 0) {
          await storage.put('logs', {
            id: `log_bg_net_${now}`,
            timestamp: now,
            domain: 'rede.android.local',
            urlPath: `/background/network-switch (${networkEvents}x)`,
            category: 'essential',
            action: 'allowed',
            severity: 'low',
            reason: `Modo Oculto validou ${networkEvents} troca(s) de interface de rede em 2º plano`,
            isAmbient: false,
          });
        }

        await onSyncResult?.({
          stoppedFromNotification: false,
          cyclesProcessed: cyclesToRecord,
          networkEvents,
          elapsedMinutes: Math.max(1, Math.round(elapsedMs / 60_000)),
        });
      }
    } finally {
      this._reconciling = false;
    }
  }
}
