import {
  DNS_PRESETS,
  SENSOR_CHECKLIST_ITEMS,
  SIGNATURE_GROUPS,
  normalizeDomain,
} from './db.js';
import { computeNetworkRisk } from './risk.js';

const SCREEN_TITLES = {
  shield: 'Escudo Global',
  logs: 'Radar & Logs',
  rules: 'Regras & Defesa',
};

const CATEGORY_LABELS = {
  ai_crawler: 'Bot / IA',
  tracker: 'Rastreador',
  ab_testing: 'A/B Testing',
  third_party: 'Terceiros',
  media_leak: 'Sensores / WebRTC',
  anomaly: 'Anomalia / Rajada',
  essential: 'Essencial',
  manual: 'Manual',
};

const SEVERITY_LABELS = {
  critical: 'Crítica',
  high: 'Alta',
  medium: 'Média',
  low: 'Baixa',
};

const ALERT_TYPE_LABELS = {
  burst: 'Rajada Anômala',
  rapid_refresh: 'Refresh Suspeito',
  bot_pattern: 'Invasão de Bot IA',
  supply_chain: 'Ataque Supply Chain (A/B)',
  dns_hijack: 'Sequestro de DNS Wi-Fi',
  webrtc_leak: 'Vazamento WebRTC (Câmera/Mic)',
};

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function formatTime(ts) {
  const date = new Date(ts);
  return date.toLocaleTimeString('pt-BR', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

export class AegisApp {
  constructor(storage, engine, visualizer, audio, telemetry) {
    this.storage = storage;
    this.engine = engine;
    this.visualizer = visualizer;
    this.audio = audio;
    this.telemetry = telemetry;

    this.state = {
      activeScreen: 'shield',
      logFilterAction: 'all',
      logFilterCategory: 'all',
      logFilterSeverity: 'all',
      logSearch: '',
      ruleFilterType: 'all',
      ruleSearch: '',
      importMode: 'merge',
      settings: null,
      rules: [],
      signatures: [],
      logs: [],
      alerts: [],
      lastRadarLog: null,
      activeRedAlertId: null,
      risk: null,
      sensorChecklist: {},
    };
    this._riskDecayTimer = null;
  }

  async mount() {
    this._bindEvents();
    await this.refreshAll();
    this.visualizer.setActive(Boolean(this.state.settings.vpnActive));
    this.visualizer.start();
    this.telemetry?.setActive(Boolean(this.state.settings.vpnActive));
    this.engine.startBackgroundLoop(Boolean(this.state.settings.vpnActive));

    if (this._riskDecayTimer !== null) {
      window.clearInterval(this._riskDecayTimer);
    }
    this._riskDecayTimer = window.setInterval(() => {
      if (!this.state.settings) return;
      this.state.risk = computeNetworkRisk({
        settings: this.state.settings,
        logs: this.state.logs,
        alerts: this.state.alerts,
      });
      this._renderRiskScore();
    }, 10_000);
  }

  async refreshAll() {
    const [settings, rules, signatures, logs, alerts, checklistState] = await Promise.all([
      this.storage.getSettings(),
      this.storage.getAll('rules'),
      this.storage.getAll('signatures'),
      this.storage.getAll('logs'),
      this.storage.getAll('alerts'),
      this.storage.getSensorChecklist(),
    ]);

    logs.sort((a, b) => b.timestamp - a.timestamp);
    alerts.sort((a, b) => b.timestamp - a.timestamp);
    rules.sort((a, b) => (b.hits || 0) - (a.hits || 0) || a.domain.localeCompare(b.domain));

    this.state.settings = settings;
    this.state.rules = rules;
    this.state.signatures = signatures;
    this.state.logs = logs;
    this.state.alerts = alerts;
    this.state.sensorChecklist = checklistState?.checks || {};
    this.state.risk = computeNetworkRisk({ settings, logs, alerts });

    if (logs.length > 0 && !this.state.lastRadarLog) {
      this.state.lastRadarLog = logs[0];
    }

    if (this.audio) {
      this.audio.setEnabled(settings.alertSoundEnabled !== false);
    }

    this.storage.saveRiskSnapshot(this.state.risk).catch(() => {});

    this.render();
    this._syncRedAlertState();
  }

  setScreen(screenName) {
    if (!SCREEN_TITLES[screenName]) return;
    this.state.activeScreen = screenName;

    document.querySelectorAll('.screen').forEach((el) => {
      el.hidden = el.id !== `screen-${screenName}`;
      el.classList.toggle('is-active', el.id === `screen-${screenName}`);
    });

    document.querySelectorAll('[data-screen]').forEach((btn) => {
      const isMatch = btn.getAttribute('data-screen') === screenName;
      btn.classList.toggle('is-active', isMatch);
      if (btn.classList.contains('nav-item')) {
        if (isMatch) {
          btn.setAttribute('aria-current', 'page');
        } else {
          btn.removeAttribute('aria-current');
        }
      }
    });

    const titleEl = document.getElementById('topbar-screen-title');
    if (titleEl) {
      titleEl.textContent = SCREEN_TITLES[screenName];
    }

    this._closeMobileSidebar();
    this.render();
    if (screenName === 'shield') {
      this.telemetry?.draw();
    }
  }

  showToast(message, variant = 'info') {
    const region = document.getElementById('toast-region');
    if (!region) return;

    const toast = document.createElement('div');
    toast.className = `toast is-${variant}`;
    toast.textContent = message;
    region.appendChild(toast);

    window.setTimeout(() => {
      toast.remove();
    }, 3400);
  }

  async toggleVpn() {
    const current = this.state.settings || (await this.storage.getSettings());
    const nextActive = !current.vpnActive;
    const updated = await this.storage.saveSettings({
      ...current,
      vpnActive: nextActive,
    });
    this.state.settings = updated;
    this.visualizer.setActive(nextActive);
    this.telemetry?.setActive(nextActive);
    this.engine.startBackgroundLoop(nextActive);
    this.render();
    this.showToast(
      nextActive
        ? 'Vigilância VPN local ativada. Escudo contra IA e bots em operação.'
        : 'Vigilância VPN local pausada. Rede sem contenção ativa.',
      nextActive ? 'success' : 'warn'
    );
  }

  async allowDomain(domain) {
    const clean = normalizeDomain(domain);
    if (!clean) return;

    const rules = await this.storage.getAll('rules');
    const existing = rules.find((r) => normalizeDomain(r.domain) === clean);

    if (existing) {
      existing.type = 'allow';
      existing.enabled = true;
      await this.storage.put('rules', existing);
    } else {
      await this.storage.put('rules', {
        id: `rule_allow_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`,
        domain: clean,
        type: 'allow',
        category: 'essential',
        enabled: true,
        hits: 0,
        createdAt: Date.now(),
      });
    }

    const alerts = await this.storage.getAll('alerts');
    for (const alert of alerts) {
      if (!alert.resolved && normalizeDomain(alert.domain) === clean) {
        alert.resolved = true;
        await this.storage.put('alerts', alert);
      }
    }

    await this.refreshAll();
    this.showToast(`Domínio ${clean} liberado na Allowlist.`, 'success');
  }

  async blockDomain(domain, category = 'manual') {
    const clean = normalizeDomain(domain);
    if (!clean) return;

    const rules = await this.storage.getAll('rules');
    const existing = rules.find((r) => normalizeDomain(r.domain) === clean);

    if (existing) {
      existing.type = 'block';
      existing.enabled = true;
      await this.storage.put('rules', existing);
    } else {
      await this.storage.put('rules', {
        id: `rule_block_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`,
        domain: clean,
        type: 'block',
        category,
        enabled: true,
        hits: 0,
        createdAt: Date.now(),
      });
    }

    await this.refreshAll();
    this.showToast(`Domínio ${clean} bloqueado no escudo.`, 'danger');
  }

  render() {
    if (!this.state.settings) return;
    this._renderChrome();
    this._renderShieldScreen();
    this._renderLogsScreen();
    this._renderRulesScreen();
  }

  _syncRedAlertState() {
    const activeRedAlert = this.state.alerts.find(
      (a) =>
        !a.acknowledged &&
        !a.resolved &&
        (a.severity === 'critical' || a.severity === 'high')
    );

    const riskScore = this.state.risk?.score ?? 0;
    const isCriticalScore = riskScore >= 80;
    const latestAckAt = this.state.alerts.reduce(
      (max, a) => (a.acknowledgedAt ? Math.max(max, a.acknowledgedAt) : max),
      0
    );
    const latestThreatAt = this.state.logs.reduce(
      (max, l) => (l.action === 'blocked' && !l.isAmbient ? Math.max(max, l.timestamp) : max),
      0
    );
    const criticalScoreNeedsAlert =
      !activeRedAlert && isCriticalScore && latestThreatAt > latestAckAt;

    const banner = document.getElementById('red-alert-banner');
    if (!activeRedAlert && !criticalScoreNeedsAlert) {
      document.body.classList.remove('is-red-alert');
      if (banner) banner.hidden = true;
      if (this.state.activeRedAlertId !== null) {
        this.state.activeRedAlertId = null;
        this.audio?.stopAlert();
      }
      this._syncRiskPanelCriticalPulse();
      return;
    }

    document.body.classList.add('is-red-alert');
    const alertId = activeRedAlert ? activeRedAlert.id : `risk_critical_${latestThreatAt}`;
    if (banner) {
      banner.hidden = false;
      const originEl = document.getElementById('red-alert-origin');
      const typeEl = document.getElementById('red-alert-type');
      const timeEl = document.getElementById('red-alert-time');
      const descEl = document.getElementById('red-alert-desc');

      if (activeRedAlert) {
        if (originEl) originEl.textContent = activeRedAlert.domain;
        if (typeEl) {
          typeEl.textContent = ALERT_TYPE_LABELS[activeRedAlert.type] || 'Ameaça Crítica de IA';
        }
        if (timeEl) timeEl.textContent = formatTime(activeRedAlert.timestamp);
        if (descEl) descEl.textContent = activeRedAlert.description;
      } else {
        if (originEl) originEl.textContent = 'Perímetro Local';
        if (typeEl) typeEl.textContent = `INVASÃO CRÍTICA (Score ${riskScore}/100)`;
        if (timeEl) timeEl.textContent = formatTime(latestThreatAt || Date.now());
        if (descEl) descEl.textContent = this.state.risk?.summary || 'Score de risco atingiu faixa crítica.';
      }
    }

    if (this.state.activeRedAlertId !== alertId) {
      this.state.activeRedAlertId = alertId;
      if (this.state.settings?.alertSoundEnabled !== false) {
        this.audio?.startAlert();
      }
    }
    this._syncRiskPanelCriticalPulse();
  }

  _syncRiskPanelCriticalPulse() {
    const panel = document.getElementById('risk-score-panel');
    if (!panel) return;
    const isCritical = (this.state.risk?.score ?? 0) >= 80;
    panel.classList.toggle('is-critical', isCritical);
  }

  async acknowledgeRedAlert() {
    this.audio?.stopAlert();
    const now = Date.now();
    const alerts = await this.storage.getAll('alerts');
    let ackedCount = 0;

    for (const alert of alerts) {
      if (!alert.acknowledged) {
        alert.acknowledged = true;
        alert.acknowledgedAt = now;
        await this.storage.put('alerts', alert);
        ackedCount += 1;
      }
    }

    if (ackedCount > 0) {
      await this.storage.put('logs', {
        id: `log_ack_${now}`,
        timestamp: now,
        domain: 'aegis.sistema.local',
        urlPath: '/alerta-vermelho/ciencia-registrada',
        category: 'essential',
        severity: 'low',
        action: 'allowed',
        reason: `Ciência do Modo Alerta Vermelho registrada (${ackedCount} alerta(s) silenciado(s))`,
      });
    }

    this.state.activeRedAlertId = null;
    await this.refreshAll();
    this.showToast('Alerta Vermelho reconhecido, silenciado e registrado no IndexedDB.', 'success');
  }

  async toggleAlertSound() {
    this.audio?.unlock();
    const current = this.state.settings || (await this.storage.getSettings());
    const nextSound = current.alertSoundEnabled === false;
    const updated = await this.storage.saveSettings({
      ...current,
      alertSoundEnabled: nextSound,
    });
    this.state.settings = updated;
    this.audio?.setEnabled(nextSound);
    if (nextSound && this.state.activeRedAlertId) {
      this.audio?.startAlert();
    }
    this.render();
    this.showToast(
      nextSound ? 'Som de alerta cibernético ativado.' : 'Som de alerta colocado em mudo.',
      'info'
    );
  }

  _renderChrome() {
    const { settings, alerts } = this.state;
    const isActive = Boolean(settings.vpnActive);
    const soundEnabled = settings.alertSoundEnabled !== false;

    const topBtn = document.getElementById('topbar-vpn-btn');
    if (topBtn) {
      topBtn.textContent = isActive ? 'Pausar Vigilância' : 'Ativar Vigilância';
      topBtn.classList.toggle('is-shield-active', isActive);
    }

    const soundBtn = document.getElementById('topbar-sound-btn');
    const soundLabel = document.getElementById('topbar-sound-label');
    if (soundBtn && soundLabel) {
      soundBtn.setAttribute('aria-pressed', String(soundEnabled));
      soundLabel.textContent = soundEnabled
        ? 'Som de Alerta: Ativado'
        : 'Som de Alerta: Mudo';
      soundBtn.classList.toggle('is-muted', !soundEnabled);
    }

    const storageEl = document.getElementById('sidebar-storage-mode');
    if (storageEl) {
      storageEl.textContent =
        this.storage.backend === 'indexeddb' ? 'IndexedDB' : 'localStorage';
    }

    const dnsIpEl = document.getElementById('sidebar-dns-ip');
    if (dnsIpEl) {
      dnsIpEl.textContent = settings.dnsIp;
    }

    const pendingAlerts = alerts.filter((a) => !a.resolved).length;
    const navCount = document.getElementById('nav-alert-count');
    if (navCount) {
      navCount.textContent = String(pendingAlerts);
      navCount.hidden = pendingAlerts === 0;
    }
  }

  _renderRiskScore() {
    const risk =
      this.state.risk ||
      computeNetworkRisk({
        settings: this.state.settings,
        logs: this.state.logs,
        alerts: this.state.alerts,
      });
    this.state.risk = risk;

    const panel = document.getElementById('risk-score-panel');
    const scoreEl = document.getElementById('risk-score-value');
    const badge = document.getElementById('risk-band-badge');
    const bandLabel = document.getElementById('risk-band-label');
    const summaryEl = document.getElementById('risk-score-summary');
    const progressEl = document.getElementById('risk-gauge-progress');
    const dotEl = document.getElementById('risk-gauge-dot');

    const toneColors = {
      safe: '#22d3ee',
      attention: '#fbbf24',
      elevated: '#fb923c',
      critical: '#ef4444',
    };
    const toneClass = `is-${risk.band.tone}`;
    const strokeColor = toneColors[risk.band.tone] || '#22d3ee';

    if (panel) {
      panel.classList.remove('is-safe', 'is-attention', 'is-elevated', 'is-critical');
      panel.classList.add(toneClass);
    }

    if (scoreEl) {
      scoreEl.textContent = String(risk.score);
    }

    if (badge && bandLabel) {
      badge.classList.remove('is-safe', 'is-attention', 'is-elevated', 'is-critical');
      badge.classList.add(toneClass);
      bandLabel.textContent = risk.band.label;
    }

    if (summaryEl) {
      summaryEl.textContent = risk.summary;
    }

    const arcLen = Math.PI * 84; // 263.89
    const clampedRatio = Math.min(1, Math.max(0, risk.score / 100));
    if (progressEl) {
      progressEl.setAttribute('stroke', strokeColor);
      progressEl.setAttribute('stroke-dashoffset', (arcLen * (1 - clampedRatio)).toFixed(2));
    }

    if (dotEl) {
      const theta = clampedRatio * Math.PI;
      const cx = 110 - 84 * Math.cos(theta);
      const cy = 108 - 84 * Math.sin(theta);
      dotEl.setAttribute('cx', cx.toFixed(2));
      dotEl.setAttribute('cy', cy.toFixed(2));
      dotEl.setAttribute('fill', strokeColor);
    }

    document.querySelectorAll('[data-band-seg]').forEach((seg) => {
      seg.classList.toggle('is-current', seg.getAttribute('data-band-seg') === risk.band.id);
    });

    const dnsFactorEl = document.getElementById('risk-factor-dns');
    const aiFactorEl = document.getElementById('risk-factor-ai');
    const burstFactorEl = document.getElementById('risk-factor-burst');
    const vpnFactorEl = document.getElementById('risk-factor-vpn');

    if (dnsFactorEl) dnsFactorEl.textContent = `DNS / Exfil (+35): ${risk.counts.dnsOrExfil}`;
    if (aiFactorEl) aiFactorEl.textContent = `Supply / IA (+20): ${risk.counts.supplyOrAi}`;
    if (burstFactorEl) burstFactorEl.textContent = `Rajada / Polling (+10): ${risk.counts.bursts}`;
    if (vpnFactorEl) {
      vpnFactorEl.textContent = risk.counts.vpnPaused
        ? 'VPN (+25): Pausada'
        : 'VPN (+25 se pausada): Ativa';
    }
  }

  _renderShieldScreen() {
    this._renderRiskScore();
    const { settings, rules, logs, alerts, lastRadarLog } = this.state;
    const isActive = Boolean(settings.vpnActive);

    const indicator = document.getElementById('vpn-status-indicator');
    const statusText = document.getElementById('vpn-status-text');
    const heroToggleBtn = document.getElementById('hero-vpn-toggle-btn');
    const heroToggleLabel = document.getElementById('hero-vpn-toggle-label');
    const threatTextEl = document.getElementById('threat-level-text');

    if (indicator && statusText) {
      indicator.classList.toggle('is-active', isActive);
      indicator.classList.toggle('is-paused', !isActive);
      statusText.textContent = isActive ? 'Vigilância VPN Ativa' : 'Vigilância VPN Pausada';
    }

    if (heroToggleBtn && heroToggleLabel) {
      heroToggleBtn.classList.toggle('is-shield-active', isActive);
      heroToggleLabel.textContent = isActive
        ? 'Pausar Vigilância VPN Local'
        : 'Ativar Vigilância VPN Local';
    }

    const unresolvedAlerts = alerts.filter((a) => !a.resolved);
    const hasCriticalAlert = unresolvedAlerts.some((a) => a.severity === 'critical');
    const hasDnsHijackAlert = unresolvedAlerts.some((a) => a.type === 'dns_hijack');

    if (threatTextEl) {
      threatTextEl.classList.remove('is-elevated', 'is-critical');
      if (!isActive) {
        threatTextEl.textContent = 'Ameaça de Rede: Exposição Alta (Escudo Pausado)';
        threatTextEl.classList.add('is-critical');
      } else if (hasDnsHijackAlert) {
        threatTextEl.textContent = 'Ameaça de Rede: Crítica · Sequestro DNS Contido';
        threatTextEl.classList.add('is-critical');
      } else if (hasCriticalAlert) {
        threatTextEl.textContent = 'Ameaça de Rede: Elevada · Invasão Contida';
        threatTextEl.classList.add('is-elevated');
      } else {
        threatTextEl.textContent = 'Ameaça de Rede: Baixa / Contida';
      }
    }

    const heroDnsLabel = document.getElementById('hero-dns-label');
    if (heroDnsLabel) {
      heroDnsLabel.textContent = `${settings.dnsIp} (${settings.dnsProtocol})`;
    }

    const heroRulesCount = document.getElementById('hero-rules-count');
    if (heroRulesCount) {
      heroRulesCount.textContent = String(rules.filter((r) => r.enabled).length);
    }

    const radarCaption = document.getElementById('radar-last-event');
    if (radarCaption) {
      if (!isActive) {
        radarCaption.innerHTML =
          '<span class="mono">Radar em pausa · ative a vigilância para interceptar</span>';
      } else if (lastRadarLog) {
        const badge = lastRadarLog.action === 'blocked' ? 'BARRADO' : 'SEGURO';
        radarCaption.innerHTML = `<span class="mono">${escapeHtml(badge)} · ${escapeHtml(
          lastRadarLog.domain
        )}</span>`;
      } else {
        radarCaption.innerHTML =
          '<span class="mono">Aguardando próxima varredura...</span>';
      }
    }

    // Real-time KPIs
    const blockedLogs = logs.filter((l) => l.action === 'blocked');
    const aiBlockedCount = blockedLogs.filter((l) => l.category === 'ai_crawler').length;
    const otherBlockedCount = blockedLogs.length - aiBlockedCount;
    const allowedLogsCount = logs.filter((l) => l.action === 'allowed').length;

    const burstsBlockedCount = alerts.length;
    const pendingAlertsCount = unresolvedAlerts.length;

    // DNS Integrity percentage based on VPN status, secure protocol, and resolved threats
    let dnsIntegrity = isActive ? 100 : 42;
    if (isActive) {
      if (settings.dnsProtocol === 'DoH' || settings.dnsProtocol === 'DoT' || settings.dnsProtocol === 'DNSCrypt') {
        dnsIntegrity = Math.max(94, 100 - pendingAlertsCount * 2);
      } else {
        dnsIntegrity = Math.max(82, 92 - pendingAlertsCount * 2);
      }
      if (hasDnsHijackAlert) {
        dnsIntegrity = Math.max(58, dnsIntegrity - 36);
      }
    }

    document.getElementById('kpi-ai-blocked').textContent = String(blockedLogs.length);
    document.getElementById(
      'kpi-ai-breakdown'
    ).textContent = `${aiBlockedCount} bots/IA · ${otherBlockedCount} rastreadores e A/B`;

    document.getElementById('kpi-bursts-blocked').textContent = String(burstsBlockedCount);
    document.getElementById(
      'kpi-bursts-meta'
    ).textContent = `${pendingAlertsCount} alerta(s) heurístico(s) pendente(s)`;

    document.getElementById('kpi-dns-integrity').textContent = `${dnsIntegrity}%`;
    document.getElementById('kpi-dns-meta').textContent = !isActive
      ? 'Escudo pausado · resolução exposta'
      : hasDnsHijackAlert
      ? 'Alerta: tentativa de sequestro Wi-Fi detectada'
      : `${settings.dnsProtocol} cifrado · sem vazamentos`;

    document.getElementById('kpi-allowed-today').textContent = String(allowedLogsCount);
    document.getElementById('kpi-total-evaluated').textContent = `${logs.length} eventos inspecionados`;

    if (this.telemetry) {
      this.telemetry.setLogs(logs);
      const series = this.telemetry.computeSeries();
      const totalNormalEl = document.getElementById('telemetry-total-normal');
      const totalBlockedEl = document.getElementById('telemetry-total-blocked');
      if (totalNormalEl) totalNormalEl.textContent = String(series.totalNormal);
      if (totalBlockedEl) totalBlockedEl.textContent = String(series.totalBlocked);
    }

    // Network status panel
    const presetInfo = DNS_PRESETS[settings.dnsPreset] || DNS_PRESETS.custom;
    document.getElementById('net-tunnel-state').textContent = isActive
      ? 'Ativa · Escudo global operando'
      : 'Pausada · Sem inspeção ativa';
    document.getElementById('net-threat-level').textContent = !isActive
      ? 'Crítico · Vigilância desativada'
      : hasDnsHijackAlert
      ? 'Crítico · Sequestro DNS Wi-Fi contido'
      : hasCriticalAlert
      ? 'Elevado · Rajadas de IA contidas'
      : 'Baixo · Perímetro íntegro';
    document.getElementById('net-dns-provider').textContent = presetInfo.label;
    document.getElementById(
      'net-dns-endpoint'
    ).textContent = `${settings.dnsIp} · ${settings.dnsProtocol}`;
    document.getElementById(
      'net-burst-threshold'
    ).textContent = `${settings.burstThreshold} req / 10s`;
    document.getElementById('net-storage-backend').textContent =
      this.storage.backend === 'indexeddb'
        ? 'IndexedDB (AegisAI_Vigilante_DB)'
        : 'Fallback localStorage';

    const recentTbody = document.getElementById('recent-events-tbody');
    if (recentTbody) {
      const recent = logs.slice(0, 6);
      if (recent.length === 0) {
        recentTbody.innerHTML =
          '<tr><td colspan="4" class="meta-text">Nenhum evento registrado ainda.</td></tr>';
      } else {
        recentTbody.innerHTML = recent
          .map((item) => {
            const isBlocked = item.action === 'blocked';
            const sev = item.severity || 'low';
            return `
              <tr>
                <td class="mono tabular-nums">${escapeHtml(formatTime(item.timestamp))}</td>
                <td>
                  <div class="domain-cell">
                    <span class="domain-name">${escapeHtml(item.domain)}</span>
                  </div>
                </td>
                <td>
                  <span class="sev-text sev-${escapeHtml(sev)}">
                    ${escapeHtml(SEVERITY_LABELS[sev] || sev)}
                  </span>
                </td>
                <td class="text-right">
                  <span class="decision-label ${isBlocked ? 'is-blocked' : 'is-allowed'}">
                    ${isBlocked ? 'Barrado' : 'Permitido'}
                  </span>
                </td>
              </tr>
            `;
          })
          .join('');
      }
    }
  }

  _renderLogsScreen() {
    const alertsContainer = document.getElementById('alerts-list');
    if (alertsContainer) {
      if (this.state.alerts.length === 0) {
        alertsContainer.innerHTML = `
          <div class="empty-state">
            <p class="empty-title">Nenhum alerta heurístico registrado</p>
            <p class="empty-desc">
              Quando houver rajadas de requisições, bots de IA ou refresh suspeito, os alertas aparecerão aqui.
            </p>
          </div>
        `;
      } else {
        alertsContainer.innerHTML = this.state.alerts
          .slice(0, 20)
          .map((alert) => {
            const typeLabel = ALERT_TYPE_LABELS[alert.type] || 'Anomalia';
            const sev = alert.severity || 'medium';
            const sevClass = alert.resolved ? 'is-resolved' : `is-${sev}`;
            const sevText = alert.resolved
              ? 'Resolvido'
              : `Severidade ${SEVERITY_LABELS[sev] || 'Média'}`;

            return `
              <article class="alert-row ${alert.resolved ? 'is-resolved' : ''}">
                <div class="alert-info">
                  <div class="alert-headline">
                    <span class="alert-severity ${sevClass}">${escapeHtml(sevText)}</span>
                    <span class="meta-sep" aria-hidden="true">·</span>
                    <span>${escapeHtml(typeLabel)}</span>
                    <span class="meta-sep" aria-hidden="true">·</span>
                    <span class="mono">${escapeHtml(alert.domain)}</span>
                  </div>
                  <div class="alert-meta">
                    <span class="mono tabular-nums">${escapeHtml(formatTime(alert.timestamp))}</span>
                    <span aria-hidden="true"> · </span>
                    <span class="tabular-nums">${escapeHtml(alert.requestCount)} req / ${escapeHtml(
              alert.windowSeconds
            )}s</span>
                    <span aria-hidden="true"> · </span>
                    <span>${escapeHtml(alert.description)}</span>
                  </div>
                </div>
                <div class="alert-actions">
                  <button
                    type="button"
                    class="btn btn-danger btn-sm"
                    data-alert-action="block"
                    data-domain="${escapeHtml(alert.domain)}"
                    data-alert-id="${escapeHtml(alert.id)}"
                  >
                    Bloquear Domínio
                  </button>
                  <button
                    type="button"
                    class="btn btn-allow btn-sm"
                    data-alert-action="allow"
                    data-domain="${escapeHtml(alert.domain)}"
                    data-alert-id="${escapeHtml(alert.id)}"
                  >
                    Liberar Domínio
                  </button>
                  ${
                    alert.resolved
                      ? ''
                      : `<button
                          type="button"
                          class="btn btn-ghost btn-sm"
                          data-alert-action="resolve"
                          data-alert-id="${escapeHtml(alert.id)}"
                        >
                          Resolver
                        </button>`
                  }
                </div>
              </article>
            `;
          })
          .join('');
      }
    }

    const query = this.state.logSearch.trim().toLowerCase();
    const filtered = this.state.logs.filter((item) => {
      const itemSeverity = item.severity || 'low';
      if (this.state.logFilterSeverity !== 'all' && itemSeverity !== this.state.logFilterSeverity) {
        return false;
      }
      if (this.state.logFilterAction !== 'all' && item.action !== this.state.logFilterAction) {
        return false;
      }
      if (
        this.state.logFilterCategory !== 'all' &&
        item.category !== this.state.logFilterCategory
      ) {
        return false;
      }
      if (query) {
        const hay = `${item.domain} ${item.urlPath} ${item.reason}`.toLowerCase();
        if (!hay.includes(query)) return false;
      }
      return true;
    });

    const countLabel = document.getElementById('logs-count-label');
    if (countLabel) {
      countLabel.textContent = `${filtered.length} registro(s)`;
    }

    const tbody = document.getElementById('logs-tbody');
    const emptyState = document.getElementById('logs-empty-state');
    if (tbody && emptyState) {
      if (filtered.length === 0) {
        tbody.innerHTML = '';
        emptyState.hidden = false;
      } else {
        emptyState.hidden = true;
        tbody.innerHTML = filtered
          .slice(0, 100)
          .map((item) => {
            const isBlocked = item.action === 'blocked';
            const sev = item.severity || 'low';
            return `
              <tr>
                <td class="mono tabular-nums">${escapeHtml(formatTime(item.timestamp))}</td>
                <td>
                  <div class="domain-cell">
                    <span class="domain-name">${escapeHtml(item.domain)}</span>
                    <span class="domain-path">${escapeHtml(item.urlPath || '/')}</span>
                  </div>
                </td>
                <td>
                  <span class="sev-text sev-${escapeHtml(sev)}">
                    ${escapeHtml(SEVERITY_LABELS[sev] || sev)}
                  </span>
                </td>
                <td>${escapeHtml(CATEGORY_LABELS[item.category] || item.category)}</td>
                <td>
                  <span class="decision-label ${isBlocked ? 'is-blocked' : 'is-allowed'}">
                    ${isBlocked ? 'Barrado' : 'Permitido'}
                  </span>
                </td>
                <td class="meta-text">${escapeHtml(item.reason)}</td>
                <td class="text-right">
                  <div class="row-actions">
                    ${
                      isBlocked
                        ? `<button
                            type="button"
                            class="btn btn-allow btn-sm"
                            data-log-row-action="allow"
                            data-domain="${escapeHtml(item.domain)}"
                          >
                            Liberar Domínio
                          </button>`
                        : `<button
                            type="button"
                            class="btn btn-ghost btn-sm"
                            data-log-row-action="block"
                            data-domain="${escapeHtml(item.domain)}"
                            data-category="${escapeHtml(item.category)}"
                          >
                            Bloquear
                          </button>`
                    }
                  </div>
                </td>
              </tr>
            `;
          })
          .join('');
      }
    }
  }

  _renderSensorSentinel() {
    const { signatures, logs, sensorChecklist } = this.state;
    const sensorSigs = signatures.filter((s) => s.group === 'sensors_media');
    const activeSensorSigs = sensorSigs.filter((s) => s.enabled).length;

    const mediaBlocks = logs.filter(
      (l) => l.action === 'blocked' && l.category === 'media_leak'
    ).length;
    const blocksBadge = document.getElementById('sensor-blocks-badge');
    if (blocksBadge) {
      blocksBadge.textContent =
        mediaBlocks === 1
          ? '1 bloqueio WebRTC/mídia'
          : `${mediaBlocks} bloqueios WebRTC/mídia`;
    }

    const sigStatus = document.getElementById('sensor-sig-status');
    if (sigStatus) {
      sigStatus.textContent = `${activeSensorSigs}/${sensorSigs.length} ativas`;
      sigStatus.className = `decision-label ${
        activeSensorSigs === sensorSigs.length ? 'is-allowed' : 'is-blocked'
      }`;
    }

    const sensorSigList = document.getElementById('sensor-signatures-list');
    if (sensorSigList) {
      sensorSigList.innerHTML = sensorSigs
        .map(
          (sig) => `
          <div class="sig-row ${sig.enabled ? '' : 'is-disabled'}">
            <div class="sig-copy">
              <span class="sig-name">${escapeHtml(sig.name)}</span>
              <span class="sig-pattern mono">${escapeHtml(sig.pattern)}</span>
              <span class="sig-desc">${escapeHtml(sig.description)}</span>
            </div>
            <label class="switch-control" aria-label="Ativar ou desativar ${escapeHtml(sig.name)}">
              <input
                type="checkbox"
                data-sig-id="${escapeHtml(sig.id)}"
                ${sig.enabled ? 'checked' : ''}
              />
              <span class="switch-track"></span>
            </label>
          </div>
        `
        )
        .join('');
    }

    const checklistContainer = document.getElementById('sensor-checklist-list');
    const checkedCount = SENSOR_CHECKLIST_ITEMS.filter((item) =>
      Boolean(sensorChecklist[item.id])
    ).length;

    const progressEl = document.getElementById('sensor-checklist-progress');
    if (progressEl) {
      progressEl.textContent = `${checkedCount}/${SENSOR_CHECKLIST_ITEMS.length} verificados`;
    }

    const hintEl = document.getElementById('sensor-checklist-hint');
    if (hintEl) {
      hintEl.textContent =
        checkedCount === SENSOR_CHECKLIST_ITEMS.length
          ? 'Blindagem do aparelho concluída e salva no IndexedDB.'
          : 'Progresso salvo automaticamente no IndexedDB.';
    }

    if (checklistContainer) {
      checklistContainer.innerHTML = SENSOR_CHECKLIST_ITEMS.map((item) => {
        const checked = Boolean(sensorChecklist[item.id]);
        return `
          <label class="sensor-check-item ${checked ? 'is-checked' : ''}">
            <input
              type="checkbox"
              data-sensor-check-id="${escapeHtml(item.id)}"
              ${checked ? 'checked' : ''}
            />
            <div class="sensor-check-copy">
              <span class="sensor-check-title">${escapeHtml(item.title)}</span>
              <span class="sensor-check-detail">${escapeHtml(item.detail)}</span>
            </div>
          </label>
        `;
      }).join('');
    }
  }

  _renderRulesScreen() {
    this._renderSensorSentinel();
    const { settings, rules, signatures } = this.state;

    const sigGrid = document.getElementById('signatures-grid');
    const sigSummary = document.getElementById('signatures-summary-text');
    if (sigSummary) {
      const enabledCount = signatures.filter((s) => s.enabled).length;
      sigSummary.textContent = `${enabledCount}/${signatures.length} assinaturas ativas`;
    }

    if (sigGrid) {
      sigGrid.innerHTML = SIGNATURE_GROUPS.map((group) => {
        const groupItems = signatures.filter((s) => s.group === group.id);
        return `
          <div class="sig-group">
            <div class="sig-group-header">
              <h3 class="sig-group-title">${escapeHtml(group.title)}</h3>
              <p class="sig-group-sub">${escapeHtml(group.subtitle)}</p>
            </div>
            <div class="sig-list">
              ${groupItems
                .map(
                  (sig) => `
                  <div class="sig-row ${sig.enabled ? '' : 'is-disabled'}">
                    <div class="sig-copy">
                      <span class="sig-name">${escapeHtml(sig.name)}</span>
                      <span class="sig-pattern mono">${escapeHtml(sig.pattern)}</span>
                      <span class="sig-desc">${escapeHtml(sig.description)}</span>
                    </div>
                    <label class="switch-control" aria-label="Ativar ou desativar ${escapeHtml(sig.name)}">
                      <input
                        type="checkbox"
                        data-sig-id="${escapeHtml(sig.id)}"
                        ${sig.enabled ? 'checked' : ''}
                      />
                      <span class="switch-track"></span>
                    </label>
                  </div>
                `
                )
                .join('')}
            </div>
          </div>
        `;
      }).join('');
    }

    const presetSelect = document.getElementById('dns-preset-select');
    const protocolSelect = document.getElementById('dns-protocol-select');
    const ipInput = document.getElementById('dns-ip-input');
    const burstInput = document.getElementById('burst-threshold-input');
    const autoBlockCheckbox = document.getElementById('autoblock-bots-checkbox');

    if (presetSelect && document.activeElement !== presetSelect) {
      presetSelect.value = settings.dnsPreset;
    }
    if (protocolSelect && document.activeElement !== protocolSelect) {
      protocolSelect.value = settings.dnsProtocol;
    }
    if (ipInput && document.activeElement !== ipInput) {
      ipInput.value = settings.dnsIp;
    }
    if (burstInput && document.activeElement !== burstInput) {
      burstInput.value = String(settings.burstThreshold);
    }
    if (autoBlockCheckbox) {
      autoBlockCheckbox.checked = Boolean(settings.autoBlockBots);
    }

    const blockedCount = rules.filter((r) => r.type === 'block').length;
    const allowCount = rules.filter((r) => r.type === 'allow').length;
    const summaryEl = document.getElementById('rules-summary-text');
    if (summaryEl) {
      summaryEl.textContent = `${blockedCount} bloqueado(s) · ${allowCount} na allowlist`;
    }

    const query = this.state.ruleSearch.trim().toLowerCase();
    const filteredRules = rules.filter((r) => {
      if (this.state.ruleFilterType !== 'all' && r.type !== this.state.ruleFilterType) {
        return false;
      }
      if (query && !r.domain.toLowerCase().includes(query)) {
        return false;
      }
      return true;
    });

    const tbody = document.getElementById('rules-tbody');
    if (tbody) {
      if (filteredRules.length === 0) {
        tbody.innerHTML =
          '<tr><td colspan="6" class="meta-text">Nenhuma regra encontrada.</td></tr>';
      } else {
        tbody.innerHTML = filteredRules
          .map((rule) => {
            const isBlock = rule.type === 'block';
            return `
              <tr>
                <td class="mono">${escapeHtml(rule.domain)}</td>
                <td>${escapeHtml(CATEGORY_LABELS[rule.category] || rule.category)}</td>
                <td>
                  <span class="decision-label ${isBlock ? 'is-blocked' : 'is-allowed'}">
                    ${isBlock ? 'Bloqueio' : 'Allowlist'}
                  </span>
                </td>
                <td class="text-right mono tabular-nums">${escapeHtml(rule.hits || 0)}</td>
                <td>
                  <button
                    type="button"
                    class="btn btn-ghost btn-sm"
                    data-rule-action="toggle"
                    data-rule-id="${escapeHtml(rule.id)}"
                  >
                    ${rule.enabled ? 'Ativa' : 'Inativa'}
                  </button>
                </td>
                <td class="text-right">
                  <div class="row-actions">
                    <button
                      type="button"
                      class="btn btn-secondary btn-sm"
                      data-rule-action="flip-type"
                      data-rule-id="${escapeHtml(rule.id)}"
                    >
                      ${isBlock ? 'Mover p/ Allowlist' : 'Bloquear'}
                    </button>
                    <button
                      type="button"
                      class="btn btn-ghost btn-sm"
                      data-rule-action="delete"
                      data-rule-id="${escapeHtml(rule.id)}"
                    >
                      Remover
                    </button>
                  </div>
                </td>
              </tr>
            `;
          })
          .join('');
      }
    }
  }

  _openMobileSidebar() {
    const sidebar = document.getElementById('sidebar');
    const backdrop = document.getElementById('mobile-backdrop');
    if (sidebar) sidebar.classList.add('is-open');
    if (backdrop) backdrop.hidden = false;
  }

  _closeMobileSidebar() {
    const sidebar = document.getElementById('sidebar');
    const backdrop = document.getElementById('mobile-backdrop');
    if (sidebar) sidebar.classList.remove('is-open');
    if (backdrop) backdrop.hidden = true;
  }

  _bindEvents() {
    document.querySelectorAll('[data-screen]').forEach((btn) => {
      btn.addEventListener('click', () => {
        const screen = btn.getAttribute('data-screen');
        if (screen) this.setScreen(screen);
      });
    });

    document.querySelectorAll('[data-goto-screen]').forEach((btn) => {
      btn.addEventListener('click', () => {
        const screen = btn.getAttribute('data-goto-screen');
        if (screen) this.setScreen(screen);
      });
    });

    document.querySelectorAll('[data-nav]').forEach((link) => {
      link.addEventListener('click', (e) => {
        e.preventDefault();
        const screen = link.getAttribute('data-nav');
        if (screen) this.setScreen(screen);
      });
    });

    document.getElementById('open-sidebar-btn')?.addEventListener('click', () => {
      this._openMobileSidebar();
    });
    document.getElementById('close-sidebar-btn')?.addEventListener('click', () => {
      this._closeMobileSidebar();
    });
    document.getElementById('mobile-backdrop')?.addEventListener('click', () => {
      this._closeMobileSidebar();
    });

    const unlockAudio = () => {
      this.audio?.unlock();
    };
    window.addEventListener('pointerdown', unlockAudio, { once: true });
    window.addEventListener('keydown', unlockAudio, { once: true });

    document.getElementById('topbar-sound-btn')?.addEventListener('click', () => {
      this.toggleAlertSound();
    });

    document.getElementById('ack-red-alert-btn')?.addEventListener('click', () => {
      this.acknowledgeRedAlert();
    });

    document.getElementById('red-alert-inspect-btn')?.addEventListener('click', () => {
      this.setScreen('logs');
    });

    document.getElementById('topbar-vpn-btn')?.addEventListener('click', () => this.toggleVpn());
    document
      .getElementById('hero-vpn-toggle-btn')
      ?.addEventListener('click', () => this.toggleVpn());

    document.getElementById('hero-simulate-burst-btn')?.addEventListener('click', async () => {
      await this.engine.simulateMixedTraffic();
      await this.refreshAll();
      this.showToast('Varredura concluída: 6 requisições analisadas pelo escudo.', 'info');
    });

    document.getElementById('clear-telemetry-chart-btn')?.addEventListener('click', () => {
      this.telemetry?.clearChartHistory();
      const totalNormalEl = document.getElementById('telemetry-total-normal');
      const totalBlockedEl = document.getElementById('telemetry-total-blocked');
      if (totalNormalEl) totalNormalEl.textContent = '0';
      if (totalBlockedEl) totalBlockedEl.textContent = '0';
      this.showToast(
        'Histórico visual do gráfico limpo. Logs críticos no IndexedDB preservados.',
        'info'
      );
    });

    document.getElementById('logs-test-refresh-btn')?.addEventListener('click', async () => {
      await this.engine.simulateBurstAttack();
      await this.refreshAll();
      this.showToast('Invasão de IA simulada e contida pelo motor heurístico.', 'warn');
    });

    document.getElementById('logs-clear-btn')?.addEventListener('click', async () => {
      await this.storage.clearStore('logs');
      this.state.lastRadarLog = null;
      await this.refreshAll();
      this.showToast('Histórico de ameaças limpo.', 'info');
    });

    document.getElementById('resolve-all-alerts-btn')?.addEventListener('click', async () => {
      const alerts = await this.storage.getAll('alerts');
      for (const alert of alerts) {
        if (!alert.resolved) {
          alert.resolved = true;
          await this.storage.put('alerts', alert);
        }
      }
      await this.refreshAll();
      this.showToast('Alertas heurísticos marcados como resolvidos.', 'success');
    });

    document.getElementById('alerts-list')?.addEventListener('click', async (e) => {
      const btn = e.target.closest('button[data-alert-action]');
      if (!btn) return;
      const action = btn.getAttribute('data-alert-action');
      const domain = btn.getAttribute('data-domain');
      const alertId = btn.getAttribute('data-alert-id');

      if (action === 'allow' && domain) {
        await this.allowDomain(domain);
        return;
      }

      if (action === 'block' && domain) {
        await this.blockDomain(domain, 'anomaly');
      }

      if (alertId) {
        const alerts = await this.storage.getAll('alerts');
        const target = alerts.find((a) => a.id === alertId);
        if (target) {
          target.resolved = true;
          await this.storage.put('alerts', target);
          await this.refreshAll();
          if (action === 'resolve') {
            this.showToast('Alerta marcado como resolvido.', 'info');
          }
        }
      }
    });

    document.getElementById('logs-search-input')?.addEventListener('input', (e) => {
      this.state.logSearch = e.target.value;
      this._renderLogsScreen();
    });

    document.getElementById('logs-severity-select')?.addEventListener('change', (e) => {
      this.state.logFilterSeverity = e.target.value;
      this._renderLogsScreen();
    });

    document.getElementById('logs-category-select')?.addEventListener('change', (e) => {
      this.state.logFilterCategory = e.target.value;
      this._renderLogsScreen();
    });

    document.querySelectorAll('[data-log-action]').forEach((btn) => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('[data-log-action]').forEach((b) => b.classList.remove('is-active'));
        btn.classList.add('is-active');
        this.state.logFilterAction = btn.getAttribute('data-log-action') || 'all';
        this._renderLogsScreen();
      });
    });

    document.getElementById('logs-reset-filters-btn')?.addEventListener('click', () => {
      this.state.logSearch = '';
      this.state.logFilterSeverity = 'all';
      this.state.logFilterCategory = 'all';
      this.state.logFilterAction = 'all';
      const searchEl = document.getElementById('logs-search-input');
      const sevEl = document.getElementById('logs-severity-select');
      const catEl = document.getElementById('logs-category-select');
      if (searchEl) searchEl.value = '';
      if (sevEl) sevEl.value = 'all';
      if (catEl) catEl.value = 'all';
      document.querySelectorAll('[data-log-action]').forEach((b) => {
        b.classList.toggle('is-active', b.getAttribute('data-log-action') === 'all');
      });
      this._renderLogsScreen();
    });

    document.getElementById('logs-tbody')?.addEventListener('click', async (e) => {
      const btn = e.target.closest('button[data-log-row-action]');
      if (!btn) return;
      const action = btn.getAttribute('data-log-row-action');
      const domain = btn.getAttribute('data-domain');
      const category = btn.getAttribute('data-category') || 'manual';
      if (!domain) return;

      if (action === 'allow') {
        await this.allowDomain(domain);
      } else if (action === 'block') {
        await this.blockDomain(domain, category);
      }
    });

    document.getElementById('dns-preset-select')?.addEventListener('change', (e) => {
      const presetKey = e.target.value;
      const preset = DNS_PRESETS[presetKey];
      if (!preset) return;
      const ipInput = document.getElementById('dns-ip-input');
      const protoSelect = document.getElementById('dns-protocol-select');
      if (ipInput && presetKey !== 'custom') {
        ipInput.value = preset.ip;
      }
      if (protoSelect && presetKey !== 'custom') {
        protoSelect.value = preset.protocol;
      }
    });

    document.getElementById('network-config-form')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const preset = document.getElementById('dns-preset-select').value;
      const protocol = document.getElementById('dns-protocol-select').value;
      const ip = document.getElementById('dns-ip-input').value.trim();
      const burst = Number(document.getElementById('burst-threshold-input').value);
      const autoBlockBots = document.getElementById('autoblock-bots-checkbox').checked;

      if (!ip) {
        this.showToast('Informe um endpoint ou IP de DNS válido.', 'warn');
        return;
      }

      await this.storage.saveSettings({
        ...this.state.settings,
        dnsPreset: preset,
        dnsProtocol: protocol,
        dnsIp: ip,
        burstThreshold: Number.isFinite(burst) ? Math.min(50, Math.max(3, burst)) : 6,
        autoBlockBots,
      });

      await this.refreshAll();
      this.showToast('Configurações de DNS seguro e heurística salvas.', 'success');
    });

    const renderSimAlert = (title, detail, levelClass) => {
      const box = document.getElementById('sim-visual-alert');
      if (!box) return;
      box.hidden = false;
      box.className = `sim-visual-alert ${levelClass}`;
      box.innerHTML = `
        <div class="sim-alert-header">
          <strong>${escapeHtml(title)}</strong>
          <button type="button" class="btn btn-ghost btn-sm" data-goto-screen="logs">
            Ver no Radar &amp; Logs
          </button>
        </div>
        <div class="meta-text">${escapeHtml(detail)}</div>
      `;
      box.querySelector('[data-goto-screen="logs"]')?.addEventListener('click', () => {
        this.setScreen('logs');
      });
    };

    document.getElementById('sim-supply-chain-btn')?.addEventListener('click', async () => {
      const logEntry = await this.engine.simulateSupplyChainAttack();
      await this.refreshAll();
      renderSimAlert(
        'Alerta Crítico · Ataque Supply Chain Contido',
        `Script A/B comprometido (${logEntry.domain}${logEntry.urlPath}) foi barrado ao tentar ler formulários e gravado no IndexedDB.`,
        'is-danger'
      );
      this.showToast('Ataque Supply Chain (A/B) barrado e registrado no IndexedDB!', 'danger');
    });

    document.getElementById('sim-polling-burst-btn')?.addEventListener('click', async () => {
      const total = await this.engine.simulatePolling60sBurst();
      await this.refreshAll();
      renderSimAlert(
        'Alerta Heurístico · Rajada de Bot/IA (Polling 60s)',
        `${total} requisições repetitivas de ai-polling-60s.bot.test gravadas no IndexedDB. Detector de anomalia acionado.`,
        'is-warn'
      );
      this.showToast(`Rajada de ${total} req (Polling 60s) detectada e registrada!`, 'warn');
    });

    document.getElementById('sim-dns-hijack-btn')?.addEventListener('click', async () => {
      const logEntry = await this.engine.simulateWifiDnsHijack();
      await this.refreshAll();
      renderSimAlert(
        'Alerta de Integridade · Sequestro de DNS Wi-Fi Detectado',
        `Desvio malicioso para ${logEntry.domain} interceptado. Integridade DNS e status de ameaça atualizados no Escudo Global.`,
        'is-danger'
      );
      this.showToast('Tentativa de sequestro de DNS Wi-Fi detectada e gravada!', 'danger');
    });

    const triggerWebRtcLeakTest = async () => {
      const logEntry = await this.engine.simulateWebRtcMediaLeak();
      await this.refreshAll();
      renderSimAlert(
        'Alerta Crítico · Vazamento de Mídia WebRTC Contido',
        `Tentativa de captura oculta de microfone/câmera para ${logEntry.domain} (STUN/TURN + upload contínuo) bloqueada, gravada no IndexedDB e refletida no Score de Risco.`,
        'is-danger'
      );
      this.showToast(
        'Captura oculta de câmera/microfone (WebRTC Leak) bloqueada! Alerta Vermelho acionado.',
        'danger'
      );
    };

    document.getElementById('sim-webrtc-leak-btn')?.addEventListener('click', triggerWebRtcLeakTest);
    document.getElementById('sensor-quick-test-btn')?.addEventListener('click', triggerWebRtcLeakTest);

    document.getElementById('manual-probe-form')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const inputEl = document.getElementById('manual-probe-input');
      const boxEl = document.getElementById('probe-result-box');
      const rawValue = inputEl.value.trim();
      if (!rawValue) return;

      const result = await this.engine.processRequest(rawValue, null, null, {
        forceEvaluate: true,
      });
      await this.refreshAll();

      if (result && boxEl) {
        const { logEntry, anomalyTriggered } = result;
        const isBlocked = logEntry.action === 'blocked';
        const sev = logEntry.severity || 'low';
        boxEl.hidden = false;
        boxEl.innerHTML = `
          <div>
            <strong>Decisão:</strong>
            <span class="decision-label ${isBlocked ? 'is-blocked' : 'is-allowed'}">
              ${isBlocked ? 'Barrado' : 'Permitido'}
            </span>
            <span class="meta-sep">·</span>
            <span class="sev-text sev-${escapeHtml(sev)}">Severidade ${escapeHtml(
          SEVERITY_LABELS[sev] || sev
        )}</span>
            <span class="meta-sep">·</span>
            <span class="mono">${escapeHtml(logEntry.domain)}</span>
          </div>
          <div class="meta-text">
            Vetor: ${escapeHtml(CATEGORY_LABELS[logEntry.category] || logEntry.category)} ·
            Motivo: ${escapeHtml(logEntry.reason)}
            ${anomalyTriggered ? ' · Alerta heurístico disparado!' : ''}
          </div>
        `;
      }
    });

    const handleSignatureToggle = async (e) => {
      const checkbox = e.target.closest('input[type="checkbox"][data-sig-id]');
      if (!checkbox) return;
      const sigId = checkbox.getAttribute('data-sig-id');
      const sig = this.state.signatures.find((s) => s.id === sigId);
      if (!sig) return;

      sig.enabled = checkbox.checked;
      await this.storage.put('signatures', sig);
      await this.refreshAll();
      this.showToast(
        `Assinatura "${sig.name}" ${sig.enabled ? 'ativada' : 'desativada'}.`,
        sig.enabled ? 'success' : 'warn'
      );
    };

    document.getElementById('signatures-grid')?.addEventListener('change', handleSignatureToggle);
    document.getElementById('sensor-signatures-list')?.addEventListener('change', handleSignatureToggle);

    document.getElementById('sensor-checklist-list')?.addEventListener('change', async (e) => {
      const checkbox = e.target.closest('input[type="checkbox"][data-sensor-check-id]');
      if (!checkbox) return;
      const checkId = checkbox.getAttribute('data-sensor-check-id');
      if (!checkId) return;

      const nextChecks = {
        ...this.state.sensorChecklist,
        [checkId]: checkbox.checked,
      };
      this.state.sensorChecklist = nextChecks;
      await this.storage.saveSensorChecklist(nextChecks);
      this._renderSensorSentinel();
    });

    document.getElementById('sensor-checklist-reset-btn')?.addEventListener('click', async () => {
      this.state.sensorChecklist = {};
      await this.storage.saveSensorChecklist({});
      this._renderSensorSentinel();
      this.showToast('Checklist de blindagem de sensores reiniciado.', 'info');
    });

    document.getElementById('add-rule-form')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const domainEl = document.getElementById('new-rule-domain');
      const typeEl = document.getElementById('new-rule-type');
      const catEl = document.getElementById('new-rule-category');

      const clean = normalizeDomain(domainEl.value);
      if (!clean || !clean.includes('.')) {
        this.showToast('Digite um domínio válido (ex: scraper.ia-bot.net).', 'warn');
        return;
      }

      const type = typeEl.value === 'allow' ? 'allow' : 'block';
      const category = catEl.value;

      if (type === 'allow') {
        await this.allowDomain(clean);
      } else {
        await this.blockDomain(clean, category);
      }
      domainEl.value = '';
    });

    document.querySelectorAll('[data-rule-filter]').forEach((btn) => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('[data-rule-filter]').forEach((b) => b.classList.remove('is-active'));
        btn.classList.add('is-active');
        this.state.ruleFilterType = btn.getAttribute('data-rule-filter') || 'all';
        this._renderRulesScreen();
      });
    });

    document.getElementById('rules-search-input')?.addEventListener('input', (e) => {
      this.state.ruleSearch = e.target.value;
      this._renderRulesScreen();
    });

    document.getElementById('rules-tbody')?.addEventListener('click', async (e) => {
      const btn = e.target.closest('button[data-rule-action]');
      if (!btn) return;
      const action = btn.getAttribute('data-rule-action');
      const ruleId = btn.getAttribute('data-rule-id');
      const rule = this.state.rules.find((r) => r.id === ruleId);
      if (!rule) return;

      if (action === 'toggle') {
        rule.enabled = !rule.enabled;
        await this.storage.put('rules', rule);
        await this.refreshAll();
        this.showToast(
          `Regra ${rule.domain} ${rule.enabled ? 'ativada' : 'desativada'}.`,
          'info'
        );
      } else if (action === 'flip-type') {
        rule.type = rule.type === 'block' ? 'allow' : 'block';
        await this.storage.put('rules', rule);
        await this.refreshAll();
        this.showToast(
          `${rule.domain} movido para ${rule.type === 'allow' ? 'Allowlist' : 'Bloqueio'}.`,
          'success'
        );
      } else if (action === 'delete') {
        await this.storage.delete('rules', rule.id);
        await this.refreshAll();
        this.showToast(`Regra ${rule.domain} removida.`, 'info');
      }
    });

    document.getElementById('export-json-btn')?.addEventListener('click', async () => {
      const bundle = await this.storage.exportBundle();
      const jsonStr = JSON.stringify(bundle, null, 2);
      const blob = new Blob([jsonStr], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `aegis-ai-politicas-${new Date().toISOString().slice(0, 10)}.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      this.showToast('Arquivo JSON exportado com sucesso.', 'success');
    });

    document.getElementById('copy-json-btn')?.addEventListener('click', async () => {
      const bundle = await this.storage.exportBundle();
      const jsonStr = JSON.stringify(bundle, null, 2);
      const textarea = document.getElementById('import-json-textarea');
      if (textarea) textarea.value = jsonStr;
      try {
        await navigator.clipboard.writeText(jsonStr);
        this.showToast('Políticas JSON copiadas para a área de transferência.', 'success');
      } catch {
        this.showToast('JSON carregado na caixa de texto abaixo para cópia.', 'info');
      }
    });

    document.getElementById('reset-defaults-btn')?.addEventListener('click', async () => {
      await this.storage.resetDefaults();
      await this.refreshAll();
      this.visualizer.setActive(Boolean(this.state.settings.vpnActive));
      this.engine.startBackgroundLoop(Boolean(this.state.settings.vpnActive));
      this.showToast('Políticas padrão do AEGIS AI restauradas.', 'info');
    });

    document.querySelectorAll('[data-import-mode]').forEach((btn) => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('[data-import-mode]').forEach((b) => b.classList.remove('is-active'));
        btn.classList.add('is-active');
        this.state.importMode = btn.getAttribute('data-import-mode') || 'merge';
      });
    });

    document.getElementById('import-json-file')?.addEventListener('change', async (e) => {
      const file = e.target.files?.[0];
      if (!file) return;
      try {
        const text = await file.text();
        const textarea = document.getElementById('import-json-textarea');
        if (textarea) textarea.value = text;
        const count = await this.storage.importBundle(text, this.state.importMode);
        await this.refreshAll();
        this.showToast(`${count} regra(s) importada(s) do arquivo JSON.`, 'success');
      } catch (err) {
        this.showToast(err.message || 'Erro ao importar JSON.', 'danger');
      } finally {
        e.target.value = '';
      }
    });

    document.getElementById('import-json-apply-btn')?.addEventListener('click', async () => {
      const textarea = document.getElementById('import-json-textarea');
      const text = textarea?.value.trim();
      if (!text) {
        this.showToast('Cole o JSON na caixa de texto antes de importar.', 'warn');
        return;
      }
      try {
        const count = await this.storage.importBundle(text, this.state.importMode);
        await this.refreshAll();
        this.showToast(`${count} regra(s) importada(s) com sucesso.`, 'success');
      } catch (err) {
        this.showToast(err.message || 'Falha ao validar o JSON.', 'danger');
      }
    });
  }
}
