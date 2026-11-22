const BG_LAST_TICK_KEY = 'aegis_ai_v1_bg_last_tick';
const DB_NAME = 'AegisAI_Vigilante_DB';
const DB_VERSION = 2;
const CYCLE_INTERVAL_MS = 2000;
const RISK_WINDOW_MS = 60_000;

export const DEFAULT_CYCLIC_METRICS = {
  key: 'bg_cyclic_counter',
  status: 'paused',
  cycleCount: 0,
  visibleCycles: 0,
  hiddenCycles: 0,
  suspensionGaps: 0,
  recoveredMissedCycles: 0,
  lastDriftMs: 0,
  avgDriftMs: 0,
  maxDriftMs: 0,
  hiddenDurationMs: 0,
  visibilityState: 'visible',
  lifecycleState: 'active',
  online: true,
  logsCount: 0,
  rulesCount: 0,
  activeAlertsCount: 0,
  workerActive: false,
  webLockHeld: false,
  swSyncCount: 0,
  startedAt: 0,
  lastCycleAt: 0,
  hiddenSinceAt: 0,
  updatedAt: 0,
};

function createCyclicWorkerSource() {
  return `
    const DB_NAME = ${JSON.stringify(DB_NAME)};
    const DB_VERSION = ${DB_VERSION};
    const CYCLE_INTERVAL_MS = ${CYCLE_INTERVAL_MS};
    const RISK_WINDOW_MS = ${RISK_WINDOW_MS};

    let running = false;
    let timerId = null;
    let db = null;
    let lastPerfNow = 0;
    let nextTargetPerf = 0;
    let writing = false;

    const state = {
      key: 'bg_cyclic_counter',
      status: 'paused',
      cycleCount: 0,
      visibleCycles: 0,
      hiddenCycles: 0,
      suspensionGaps: 0,
      recoveredMissedCycles: 0,
      lastDriftMs: 0,
      avgDriftMs: 0,
      maxDriftMs: 0,
      hiddenDurationMs: 0,
      visibilityState: 'visible',
      lifecycleState: 'active',
      online: typeof navigator !== 'undefined' ? navigator.onLine !== false : true,
      logsCount: 0,
      rulesCount: 0,
      activeAlertsCount: 0,
      workerActive: true,
      swSyncCount: 0,
      startedAt: 0,
      lastCycleAt: 0,
      hiddenSinceAt: 0,
      updatedAt: 0,
    };

    function openDb() {
      if (db) return Promise.resolve(db);
      if (typeof indexedDB === 'undefined') return Promise.resolve(null);
      return new Promise((resolve) => {
        try {
          const req = indexedDB.open(DB_NAME, DB_VERSION);
          req.onupgradeneeded = (event) => {
            const upg = event.target.result;
            if (!upg.objectStoreNames.contains('rules')) upg.createObjectStore('rules', { keyPath: 'id' });
            if (!upg.objectStoreNames.contains('logs')) upg.createObjectStore('logs', { keyPath: 'id' });
            if (!upg.objectStoreNames.contains('alerts')) upg.createObjectStore('alerts', { keyPath: 'id' });
            if (!upg.objectStoreNames.contains('settings')) upg.createObjectStore('settings', { keyPath: 'key' });
            if (!upg.objectStoreNames.contains('signatures')) upg.createObjectStore('signatures', { keyPath: 'id' });
          };
          req.onsuccess = () => {
            db = req.result;
            db.onclose = () => { db = null; };
            resolve(db);
          };
          req.onerror = () => resolve(null);
          req.onblocked = () => resolve(null);
        } catch {
          resolve(null);
        }
      });
    }

    function getBand(score) {
      const s = Math.min(100, Math.max(0, Math.round(score)));
      if (s <= 24) return { id: 'safe', label: 'SEGURO' };
      if (s <= 54) return { id: 'attention', label: 'ATENÇÃO' };
      if (s <= 79) return { id: 'elevated', label: 'AMEAÇA ELEVADA' };
      return { id: 'critical', label: 'INVASÃO CRÍTICA' };
    }

    function computeDecayedRisk(config, logs, alerts, now) {
      const vpnActive = config ? Boolean(config.vpnActive) : true;
      if (!vpnActive) {
        return { score: 0, bandId: 'safe', bandLabel: 'SEGURO', summary: 'Vigilância desativada · ponteiro zerado.' };
      }
      let rawScore = 0;
      const resolvedAlerts = alerts.filter((a) => a && a.resolved && now - a.timestamp < RISK_WINDOW_MS);
      const activeAlerts = alerts.filter((a) => a && !a.resolved && now - a.timestamp < RISK_WINDOW_MS);
      const isCovered = (log, list) => list.some((a) => a.domain === log.domain && Math.abs(a.timestamp - log.timestamp) <= 15000);

      for (const alert of activeAlerts) {
        const ageMs = Math.max(0, now - alert.timestamp);
        const decay = Math.max(0, 1 - ageMs / RISK_WINDOW_MS);
        if (decay <= 0) continue;
        let pts = 10;
        const desc = String(alert.description || '').toLowerCase();
        if (alert.type === 'dns_hijack' || alert.type === 'webrtc_leak') pts = 35;
        else if (alert.type === 'supply_chain') pts = /formul[aá]rio|input|exfil|skimmer/.test(desc) ? 35 : 20;
        else if (alert.type === 'bot_pattern' || alert.type === 'rapid_refresh') pts = 20;
        rawScore += pts * decay;
      }

      const seenBuckets = new Set();
      for (const log of logs) {
        if (!log || log.action !== 'blocked') continue;
        const ageMs = Math.max(0, now - log.timestamp);
        if (ageMs >= RISK_WINDOW_MS) continue;
        if (isCovered(log, resolvedAlerts)) continue;
        const matchedAlert = activeAlerts.some((a) =>
          (a.type === 'dns_hijack' || a.type === 'webrtc_leak' || a.type === 'supply_chain' || a.type === 'bot_pattern') &&
          a.domain === log.domain && Math.abs(a.timestamp - log.timestamp) <= 5000
        );
        if (matchedAlert) continue;
        const decay = Math.max(0, 1 - ageMs / RISK_WINDOW_MS);
        if (decay <= 0) continue;
        const bucket = log.domain + ':' + Math.floor(log.timestamp / 10000);
        if (seenBuckets.has(bucket)) continue;
        seenBuckets.add(bucket);
        const hay = (log.domain + ' ' + (log.urlPath || '') + ' ' + (log.reason || '')).toLowerCase();
        let pts = 10;
        if (log.category === 'media_leak' || /webrtc|stun|turn-stream|mediastream|captura oculta/.test(hay)) pts = 35;
        else if (/sequestro de dns|wifi-hijack|exfil|form-skimmer|ler campos de formul[aá]rio/.test(hay)) pts = 35;
        else if (log.category === 'ai_crawler' || log.category === 'ab_testing' || log.category === 'anomaly') pts = 20;
        rawScore += pts * decay;
      }

      const score = Math.min(100, Math.max(0, Math.round(rawScore)));
      const band = getBand(score);
      return {
        score,
        bandId: band.id,
        bandLabel: band.label,
        summary: score === 0 ? 'Nenhuma anomalia ativa no último 1 min · perímetro de rede estável.' : 'Monitoramento cíclico ativo (' + score + '/100).',
      };
    }

    async function hydrateFromDb() {
      const database = await openDb();
      if (!database) return;
      return new Promise((resolve) => {
        try {
          const tx = database.transaction(['settings'], 'readonly');
          const req = tx.objectStore('settings').get('bg_cyclic_counter');
          req.onsuccess = () => {
            const saved = req.result;
            if (saved) {
              state.cycleCount = Number(saved.cycleCount) || 0;
              state.visibleCycles = Number(saved.visibleCycles) || 0;
              state.hiddenCycles = Number(saved.hiddenCycles) || 0;
              state.suspensionGaps = Number(saved.suspensionGaps) || 0;
              state.recoveredMissedCycles = Number(saved.recoveredMissedCycles) || 0;
              state.maxDriftMs = Number(saved.maxDriftMs) || 0;
              state.avgDriftMs = Number(saved.avgDriftMs) || 0;
              state.hiddenDurationMs = Number(saved.hiddenDurationMs) || 0;
              state.swSyncCount = Number(saved.swSyncCount) || 0;
              state.startedAt = Number(saved.startedAt) || Date.now();
            }
            resolve();
          };
          req.onerror = () => resolve();
        } catch {
          resolve();
        }
      });
    }

    async function flushIndexedDbCycle(isCheckpointOnly = false) {
      if (writing) return;
      writing = true;
      try {
        const database = await openDb();
        const now = Date.now();
        if (!database) {
          state.updatedAt = now;
          self.postMessage({ type: 'CYCLE_TICK', metrics: { ...state } });
          return;
        }

        await new Promise((resolve) => {
          try {
            const stores = ['settings', 'logs', 'alerts', 'rules'].filter((s) =>
              database.objectStoreNames.contains(s)
            );
            if (!stores.includes('settings')) {
              resolve();
              return;
            }
            const tx = database.transaction(stores, 'readwrite');
            const settingsStore = tx.objectStore('settings');

            let configVal = null;
            let riskVal = null;
            let savedCounter = null;
            let allLogs = [];
            let allAlerts = [];
            let allRules = [];

            const cfgReq = settingsStore.get('config');
            cfgReq.onsuccess = () => { configVal = cfgReq.result || null; };

            const riskReq = settingsStore.get('risk_state');
            riskReq.onsuccess = () => { riskVal = riskReq.result || null; };

            const cntReq = settingsStore.get('bg_cyclic_counter');
            cntReq.onsuccess = () => { savedCounter = cntReq.result || null; };

            if (stores.includes('logs')) {
              const logsReq = tx.objectStore('logs').getAll();
              logsReq.onsuccess = () => {
                allLogs = logsReq.result || [];
                if (allLogs.length > 300) {
                  allLogs.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
                  const logsStore = tx.objectStore('logs');
                  for (let i = 300; i < allLogs.length; i++) {
                    if (allLogs[i] && allLogs[i].id) logsStore.delete(allLogs[i].id);
                  }
                  allLogs.length = 300;
                }
              };
            }
            if (stores.includes('alerts')) {
              const alReq = tx.objectStore('alerts').getAll();
              alReq.onsuccess = () => { allAlerts = alReq.result || []; };
            }
            if (stores.includes('rules')) {
              const ruReq = tx.objectStore('rules').getAll();
              ruReq.onsuccess = () => { allRules = ruReq.result || []; };
            }

            tx.oncomplete = () => {
              state.logsCount = allLogs.length;
              state.rulesCount = allRules.filter((r) => r && r.enabled).length;
              state.activeAlertsCount = allAlerts.filter((a) => a && !a.resolved).length;
              if (savedCounter && Number(savedCounter.swSyncCount) > state.swSyncCount) {
                state.swSyncCount = Number(savedCounter.swSyncCount);
              }
              state.updatedAt = now;

              // Persist updated cyclic counter & risk_state snapshot in quick commit tx
              try {
                const writeTx = database.transaction(['settings'], 'readwrite');
                const writeStore = writeTx.objectStore('settings');
                writeStore.put({ ...state, key: 'bg_cyclic_counter', updatedAt: now });

                if (!isCheckpointOnly) {
                  const computedRisk = computeDecayedRisk(configVal, allLogs, allAlerts, now);
                  const prevHist = Array.isArray(riskVal && riskVal.history) ? riskVal.history : [];
                  const lastHist = prevHist[prevHist.length - 1];
                  const shouldAppend = !lastHist || lastHist.score !== computedRisk.score || now - lastHist.timestamp >= 60000;
                  const nextHist = shouldAppend
                    ? prevHist.concat([{ score: computedRisk.score, band: computedRisk.bandId, timestamp: now }]).slice(-24)
                    : prevHist;
                  writeStore.put({
                    key: 'risk_state',
                    score: computedRisk.score,
                    bandId: computedRisk.bandId,
                    bandLabel: computedRisk.bandLabel,
                    summary: computedRisk.summary,
                    updatedAt: now,
                    history: nextHist,
                  });
                }
                writeTx.oncomplete = () => resolve();
                writeTx.onerror = () => resolve();
              } catch {
                resolve();
              }
            };
            tx.onerror = () => resolve();
          } catch {
            resolve();
          }
        });

        self.postMessage({ type: 'CYCLE_TICK', metrics: { ...state } });
      } finally {
        writing = false;
      }
    }

    function advanceMetrics(isForced = false) {
      const now = Date.now();
      const perf = typeof performance !== 'undefined' ? performance.now() : now;

      if (lastPerfNow > 0 && state.lastCycleAt > 0) {
        const wallDelta = Math.max(0, now - state.lastCycleAt);
        const perfDelta = Math.max(0, perf - lastPerfNow);
        const expected = isForced ? Math.min(wallDelta, CYCLE_INTERVAL_MS) : CYCLE_INTERVAL_MS;
        const measuredDelta = wallDelta > CYCLE_INTERVAL_MS * 2.5 ? wallDelta : perfDelta;
        const drift = Math.round(measuredDelta - expected);
        const absDrift = Math.abs(drift);

        state.lastDriftMs = drift;
        state.avgDriftMs = state.cycleCount === 0
          ? absDrift
          : Math.round(state.avgDriftMs * 0.75 + absDrift * 0.25);
        if (absDrift > state.maxDriftMs) {
          state.maxDriftMs = absDrift;
        }

        if (wallDelta > CYCLE_INTERVAL_MS * 2.5) {
          state.suspensionGaps += 1;
          const missed = Math.max(0, Math.floor(wallDelta / CYCLE_INTERVAL_MS) - 1);
          state.recoveredMissedCycles += missed;
        }

        if (state.visibilityState === 'hidden') {
          state.hiddenDurationMs += wallDelta;
        }
      }

      if (!state.startedAt) {
        state.startedAt = now;
      }

      state.cycleCount += 1;
      if (state.visibilityState === 'hidden') {
        state.hiddenCycles += 1;
        state.status = 'hidden_monitoring';
      } else {
        state.visibleCycles += 1;
        state.status = 'active';
      }
      state.lastCycleAt = now;
      lastPerfNow = perf;
    }

    function scheduleNextCycle() {
      if (!running) return;
      if (timerId !== null) {
        clearTimeout(timerId);
        timerId = null;
      }
      const nowPerf = typeof performance !== 'undefined' ? performance.now() : Date.now();
      if (nextTargetPerf <= nowPerf) {
        nextTargetPerf = nowPerf + CYCLE_INTERVAL_MS;
      }
      const delay = Math.max(250, Math.round(nextTargetPerf - nowPerf));
      timerId = setTimeout(async () => {
        if (!running) return;
        nextTargetPerf += CYCLE_INTERVAL_MS;
        advanceMetrics(false);
        await flushIndexedDbCycle(false);
        scheduleNextCycle();
      }, delay);
    }

    self.onmessage = async (event) => {
      const msg = event.data || {};
      if (msg.type === 'START') {
        await hydrateFromDb();
        running = true;
        state.workerActive = true;
        state.visibilityState = msg.visibilityState || state.visibilityState || 'visible';
        state.lifecycleState = msg.lifecycleState || state.lifecycleState || 'active';
        state.online = typeof msg.online === 'boolean' ? msg.online : state.online;
        if (!state.startedAt) state.startedAt = Date.now();
        // Reset monotonic baseline on start/resume from pause so paused time is not counted as drift
        lastPerfNow = typeof performance !== 'undefined' ? performance.now() : Date.now();
        state.lastCycleAt = Date.now();
        nextTargetPerf = lastPerfNow + CYCLE_INTERVAL_MS;
        advanceMetrics(true);
        await flushIndexedDbCycle(false);
        scheduleNextCycle();
      } else if (msg.type === 'SET_VISIBILITY') {
        const now = Date.now();
        const prevVis = state.visibilityState;
        const nextVis = msg.visibilityState === 'hidden' ? 'hidden' : 'visible';
        if (prevVis === 'hidden' && nextVis === 'visible' && state.hiddenSinceAt > 0 && state.lastCycleAt > 0) {
          // Remaining hidden fraction since last cycle is captured on next advanceMetrics
        }
        state.visibilityState = nextVis;
        state.lifecycleState = msg.lifecycleState || (nextVis === 'hidden' ? 'hidden' : 'active');
        if (nextVis === 'hidden' && prevVis !== 'hidden') {
          state.hiddenSinceAt = now;
        } else if (nextVis === 'visible') {
          state.hiddenSinceAt = 0;
        }
        if (running) {
          state.status = nextVis === 'hidden' ? 'hidden_monitoring' : 'active';
          await flushIndexedDbCycle(true);
        }
      } else if (msg.type === 'SET_ONLINE') {
        state.online = Boolean(msg.online);
        if (running) {
          await flushIndexedDbCycle(true);
        }
      } else if (msg.type === 'FORCE_CYCLE') {
        if (!running) return;
        advanceMetrics(true);
        nextTargetPerf = (typeof performance !== 'undefined' ? performance.now() : Date.now()) + CYCLE_INTERVAL_MS;
        await flushIndexedDbCycle(false);
        scheduleNextCycle();
      } else if (msg.type === 'STOP') {
        running = false;
        if (timerId !== null) {
          clearTimeout(timerId);
          timerId = null;
        }
        state.status = 'paused';
        state.workerActive = false;
        lastPerfNow = 0;
        await flushIndexedDbCycle(true);
      }
    };
  `;
}

export class AegisBackgroundMonitor {
  constructor() {
    this.isNativeRunning = false;
    this._reconciling = false;
    this._worker = null;
    this._workerUrl = null;
    this._fallbackTimer = null;
    this._lockRelease = null;
    this._lockActive = false;
    this._isMonitoring = false;
    this._onCycleTick = null;
    this.metrics = { ...DEFAULT_CYCLIC_METRICS };
  }

  setOnCycleTick(callback) {
    this._onCycleTick = typeof callback === 'function' ? callback : null;
  }

  getMetrics() {
    return {
      ...this.metrics,
      webLockHeld: this._lockActive,
    };
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

  _acquireWebLock() {
    if (this._lockActive || typeof navigator === 'undefined' || !navigator.locks?.request) {
      return;
    }
    this._lockActive = true;
    this.metrics.webLockHeld = true;
    navigator.locks
      .request('aegis_vigilance_keepalive', { mode: 'exclusive' }, () => {
        return new Promise((resolve) => {
          this._lockRelease = resolve;
        });
      })
      .catch(() => {
        this._lockActive = false;
        this.metrics.webLockHeld = false;
      });
  }

  _releaseWebLock() {
    if (this._lockRelease) {
      try {
        this._lockRelease();
      } catch {
        // ignore
      }
      this._lockRelease = null;
    }
    this._lockActive = false;
    this.metrics.webLockHeld = false;
  }

  _ensureWorker() {
    if (this._worker || typeof Worker === 'undefined' || typeof Blob === 'undefined') {
      return Boolean(this._worker);
    }
    try {
      const source = createCyclicWorkerSource();
      const blob = new Blob([source], { type: 'application/javascript' });
      this._workerUrl = URL.createObjectURL(blob);
      this._worker = new Worker(this._workerUrl);
      this._worker.onmessage = (event) => {
        const msg = event.data || {};
        if (msg.type === 'CYCLE_TICK' && msg.metrics) {
          this.metrics = {
            ...this.metrics,
            ...msg.metrics,
            webLockHeld: this._lockActive,
          };
          this.markHeartbeatTimestamp();
          this._onCycleTick?.(this.getMetrics());
        }
      };
      return true;
    } catch {
      this._terminateWorker();
      return false;
    }
  }

  _terminateWorker() {
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

  _startCyclicEngine({ visibilityState = 'visible', lifecycleState = 'active', online = true } = {}) {
    this._isMonitoring = true;
    this._acquireWebLock();

    if (this._ensureWorker()) {
      this._worker.postMessage({
        type: 'START',
        visibilityState,
        lifecycleState,
        online,
      });
      return;
    }

    // Fallback when Worker API is unavailable
    if (this._fallbackTimer !== null) return;
    let lastPerf = typeof performance !== 'undefined' ? performance.now() : Date.now();
    this.metrics.status = visibilityState === 'hidden' ? 'hidden_monitoring' : 'active';
    this.metrics.workerActive = true;
    this._fallbackTimer = window.setInterval(() => {
      if (!this._isMonitoring) return;
      const now = Date.now();
      const perf = typeof performance !== 'undefined' ? performance.now() : now;
      const delta = perf - lastPerf;
      lastPerf = perf;
      this.metrics.cycleCount += 1;
      if (this.metrics.visibilityState === 'hidden') {
        this.metrics.hiddenCycles += 1;
        this.metrics.hiddenDurationMs += Math.round(delta);
      } else {
        this.metrics.visibleCycles += 1;
      }
      this.metrics.lastDriftMs = Math.round(delta - CYCLE_INTERVAL_MS);
      this.metrics.lastCycleAt = now;
      this.markHeartbeatTimestamp();
      this._onCycleTick?.(this.getMetrics());
    }, CYCLE_INTERVAL_MS);
  }

  _stopCyclicEngine() {
    this._isMonitoring = false;
    this._releaseWebLock();
    if (this._worker) {
      this._worker.postMessage({ type: 'STOP' });
    }
    if (this._fallbackTimer !== null) {
      window.clearInterval(this._fallbackTimer);
      this._fallbackTimer = null;
    }
    this.metrics = {
      ...this.metrics,
      status: 'paused',
      workerActive: false,
      webLockHeld: false,
    };
    this._onCycleTick?.(this.getMetrics());
  }

  notifyVisibilityChange(visibilityState, lifecycleState = null) {
    const nextVis = visibilityState === 'hidden' ? 'hidden' : 'visible';
    const nextLifecycle = lifecycleState || (nextVis === 'hidden' ? 'hidden' : 'active');
    this.metrics.visibilityState = nextVis;
    this.metrics.lifecycleState = nextLifecycle;

    if (this._isMonitoring) {
      this.metrics.status = nextVis === 'hidden' ? 'hidden_monitoring' : 'active';
      this.markHeartbeatTimestamp();
      this._worker?.postMessage({
        type: 'SET_VISIBILITY',
        visibilityState: nextVis,
        lifecycleState: nextLifecycle,
        timestamp: Date.now(),
      });

      if (nextVis === 'hidden') {
        this._pingServiceWorker('visibility_hidden', nextVis);
      } else {
        this._worker?.postMessage({ type: 'FORCE_CYCLE' });
      }
    }

    this._onCycleTick?.(this.getMetrics());
  }

  notifyOnlineChange(online) {
    this.metrics.online = Boolean(online);
    this._worker?.postMessage({ type: 'SET_ONLINE', online: Boolean(online) });
    this._onCycleTick?.(this.getMetrics());
  }

  forceImmediateCycle() {
    if (!this._isMonitoring) return;
    this.markHeartbeatTimestamp();
    this._worker?.postMessage({ type: 'FORCE_CYCLE' });
  }

  _pingServiceWorker(source = 'visibility_heartbeat', visibilityState = 'hidden') {
    if (typeof navigator === 'undefined' || !('serviceWorker' in navigator)) return;
    try {
      navigator.serviceWorker.controller?.postMessage({
        type: 'AEGIS_SW_HEARTBEAT',
        source,
        visibilityState,
        timestamp: Date.now(),
      });
      navigator.serviceWorker.ready
        ?.then((reg) => {
          reg.sync?.register?.('aegis-idb-sync').catch(() => {});
          reg.periodicSync?.register?.('aegis-idb-keepalive', { minInterval: 60_000 }).catch(() => {});
        })
        .catch(() => {});
    } catch {
      // ignore SW unsupported errors
    }
  }

  async syncState({ vpnActive, backgroundMode, dnsLabel = '1.1.1.2 (DoH)', rulesCount = 19 }) {
    const shouldRun = Boolean(vpnActive && backgroundMode);
    const vis = typeof document !== 'undefined' ? document.visibilityState : 'visible';
    const online = typeof navigator !== 'undefined' ? navigator.onLine !== false : true;

    if (shouldRun) {
      this.markHeartbeatTimestamp();
      if (!this._isMonitoring) {
        this._startCyclicEngine({
          visibilityState: vis,
          lifecycleState: vis === 'hidden' ? 'hidden' : 'active',
          online,
        });
      } else {
        this.notifyOnlineChange(online);
      }
    } else {
      this._stopCyclicEngine();
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
    this.notifyVisibilityChange('hidden', 'minimized');
    if (!this._isMonitoring) {
      this._startCyclicEngine({
        visibilityState: 'hidden',
        lifecycleState: 'minimized',
        online: typeof navigator !== 'undefined' ? navigator.onLine !== false : true,
      });
    }
    this._pingServiceWorker('minimize_to_background', 'hidden');

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

  async reconcileOnResume({ storage, onSyncResult }) {
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
        this._stopCyclicEngine();
        await onSyncResult?.({
          stoppedFromNotification: true,
          updatedSettings: updated,
          cyclesProcessed: 0,
          networkEvents: 0,
        });
        return;
      }

      const isOnline = typeof navigator === 'undefined' ? true : navigator.onLine !== false;
      this.notifyOnlineChange(isOnline);

      const persistedCyclic = await storage.getBackgroundCyclicState();
      if (persistedCyclic) {
        this.metrics = {
          ...this.metrics,
          ...persistedCyclic,
          online: isOnline,
          webLockHeld: this._lockActive,
        };
      }

      if (!settings.vpnActive || settings.backgroundMode === false) {
        return;
      }

      this.forceImmediateCycle();

      const now = Date.now();
      const lastTick = this.readLastTimestamp();
      const elapsedMs = lastTick > 0 ? Math.max(0, now - lastTick) : 0;
      const networkEvents = nativeReport?.networkEvents || 0;

      this.markHeartbeatTimestamp();

      // Sem geração retroativa de logs fictícios: apenas eventos nativos reais com rede online e VPN/serviço nativo ativo
      if (isOnline && this.isNativeRunning && networkEvents > 0) {
        await storage.put('logs', {
          id: `log_bg_net_${now}`,
          timestamp: now,
          domain: 'rede.android.local',
          urlPath: `/background/network-switch (${networkEvents}x)`,
          category: 'essential',
          action: 'allowed',
          severity: 'low',
          reason: `Modo Oculto validou ${networkEvents} troca(s) real(is) de interface de rede em 2º plano`,
          isAmbient: false,
        });

        await onSyncResult?.({
          stoppedFromNotification: false,
          cyclesProcessed: this.metrics.cycleCount,
          networkEvents,
          elapsedMinutes: Math.max(1, Math.round(elapsedMs / 60_000)),
        });
      }
    } finally {
      this._reconciling = false;
    }
  }
}
