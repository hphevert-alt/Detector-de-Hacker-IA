import { AegisStorage } from './db.js';
import { AegisRadarEngine, RadarVisualizer } from './radar.js';
import { CyberAlertAudio } from './audio.js';
import { TelemetryChart } from './telemetry.js';
import { AegisBackgroundMonitor } from './background.js';
import { AegisApp } from './app.js';
import { initPwaSupport } from './pwa.js';

async function bootstrap() {
  const storage = new AegisStorage();
  await storage.init();

  const audio = new CyberAlertAudio();
  const backgroundMonitor = new AegisBackgroundMonitor();
  let appInstance = null;
  initPwaSupport(() => appInstance);

  const engine = new AegisRadarEngine(storage, async (logEntry, anomalyTriggered) => {
    if (!appInstance) return;
    if (logEntry) {
      appInstance.state.lastRadarLog = logEntry;
    }
    await appInstance.refreshAll();
    if (anomalyTriggered && logEntry) {
      appInstance.showToast(
        `Alerta crítico: ${logEntry.domain} interceptado pelo escudo.`,
        'danger'
      );
    }
  });

  await engine.detectRealRapidRefresh();

  const radarCanvas = document.getElementById('radar-canvas');
  const visualizer = new RadarVisualizer(radarCanvas, engine);

  const telemetryCanvas = document.getElementById('telemetry-canvas');
  const hoverReadout = document.getElementById('telemetry-hover-readout');
  const telemetry = new TelemetryChart(telemetryCanvas, {
    slotsCount: 30,
    bucketMs: 15_000,
    onHoverChange: (point) => {
      if (!hoverReadout) return;
      if (!point) {
        hoverReadout.textContent = 'Passe o cursor sobre o gráfico para inspecionar';
      } else {
        hoverReadout.textContent = `${point.time} · Normais: ${point.normal} · IA Bloqueadas: ${point.blocked}`;
      }
    },
  });

  appInstance = new AegisApp(storage, engine, visualizer, audio, telemetry, backgroundMonitor);
  await appInstance.mount();
}

document.addEventListener('DOMContentLoaded', () => {
  bootstrap().catch((err) => {
    console.error('Erro ao inicializar AEGIS AI:', err);
  });
});
