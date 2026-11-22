import { normalizeDomain, parseDomainAndPath } from './db.js';

function createTimeoutSignal(timeoutMs = 4000) {
  if (typeof AbortSignal !== 'undefined' && typeof AbortSignal.timeout === 'function') {
    return { signal: AbortSignal.timeout(timeoutMs), cleanup: () => {} };
  }
  if (typeof AbortController !== 'undefined') {
    const controller = new AbortController();
    const timerId = window.setTimeout(() => {
      controller.abort(new Error('TimeoutError'));
    }, timeoutMs);
    return {
      signal: controller.signal,
      cleanup: () => window.clearTimeout(timerId),
    };
  }
  return { signal: undefined, cleanup: () => {} };
}

export function domainMatches(targetDomain, ruleDomain) {
  const target = normalizeDomain(targetDomain);
  const rule = normalizeDomain(ruleDomain);
  if (!target || !rule) return false;
  return target === rule || target.endsWith('.' + rule);
}

export function findMatchingRuleInIndex(ruleMap, targetDomain) {
  let current = normalizeDomain(targetDomain);
  while (current) {
    const found = ruleMap.get(current);
    if (found) return found;
    const dot = current.indexOf('.');
    if (dot === -1) break;
    current = current.slice(dot + 1);
  }
  return null;
}

export function buildRuleLookupMaps(rules = []) {
  const allowMap = new Map();
  const blockMap = new Map();
  for (const r of rules) {
    if (!r || !r.enabled || !r.domain) continue;
    const clean = normalizeDomain(r.domain);
    if (!clean) continue;
    if (r.type === 'allow') {
      if (!allowMap.has(clean)) allowMap.set(clean, r);
    } else if (r.type === 'block') {
      if (!blockMap.has(clean)) blockMap.set(clean, r);
    }
  }
  return { allowMap, blockMap };
}

export function shannonEntropy(str) {
  const clean = String(str || '').toLowerCase();
  if (!clean.length) return 0;
  const counts = new Map();
  for (const ch of clean) {
    counts.set(ch, (counts.get(ch) || 0) + 1);
  }
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / clean.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export function inferCategory(domain, urlPath = '/') {
  const haystack = `${domain}${urlPath}`.toLowerCase();
  if (
    /stun|turn-stream|webrtc|mediastream|mediarecorder|mic-capture|cam-stream|bot-media|ai-capture/.test(
      haystack
    )
  ) {
    return 'media_leak';
  }
  if (
    /gptbot|bytespider|ccbot|claudebot|perplexity|crawler|scraper|llm|harvester|headless|playwright|puppeteer|ai\.test|bot\.test/.test(
      haystack
    )
  ) {
    return 'ai_crawler';
  }
  if (/optimizely|vwo|visualwebsiteoptimizer|abtasty|hotjar|abtest|experiment|variant/.test(haystack)) {
    return 'ab_testing';
  }
  if (/analytics|doubleclick|facebook|pixel|bing|ads|track|collect|beacon/.test(haystack)) {
    return 'tracker';
  }
  if (/segment|amplitude|fullstory|clarity|newrelic|sentry|telemetry|mixpanel/.test(haystack)) {
    return 'third_party';
  }
  return 'essential';
}

export function computeSeverity(category, action, isBurst = false) {
  if (isBurst || category === 'anomaly' || category === 'media_leak') return 'critical';
  if (category === 'ai_crawler') return action === 'blocked' ? 'high' : 'critical';
  if (category === 'ab_testing' || category === 'tracker' || category === 'third_party') {
    return 'medium';
  }
  return 'low';
}

export class AegisRadarEngine {
  constructor(storage, onUpdate) {
    this.storage = storage;
    this.onUpdate = onUpdate;
    this.timerId = null;
    this.isActive = true;
    this.isOnline = typeof navigator === 'undefined' ? true : navigator.onLine !== false;
    this.slidingWindows = new Map();
    this.recentBurstAlerts = new Map();
    this.radarBlips = [];
  }

  setOnline(online) {
    this.isOnline = Boolean(online);
  }

  startBackgroundLoop(isActive) {
    this.stopBackgroundLoop();
    this.isActive = Boolean(isActive);
    // Sem geração automática de tráfego simulado:
    // logs são gravados apenas por inspeção real sob demanda, refresh suspeito,
    // eventos reais de rede ou cenários disparados manualmente no Simulador.
  }

  stopBackgroundLoop() {
    if (this.timerId !== null) {
      window.clearTimeout(this.timerId);
      this.timerId = null;
    }
  }

  async evaluatePreRequestDecision(rawInput, customPath = null, forcedCategory = null, options = {}) {
    const parsed = parseDomainAndPath(rawInput);
    const domain = parsed.domain;
    const urlPath = customPath || parsed.urlPath;
    if (!domain) return null;

    const [settings, rules, signatures] = await Promise.all([
      this.storage.getSettings(),
      this.storage.getAll('rules'),
      this.storage.getAll('signatures'),
    ]);

    const sigActive = (sigId) => {
      const found = signatures.find((s) => s.id === sigId);
      return found ? Boolean(found.enabled) : true;
    };

    const inferredCat = inferCategory(domain, urlPath);
    const primaryLabel = domain.split('.')[0] || '';
    const isDgaCandidate =
      sigActive('sig_dga_entropy') &&
      primaryLabel.length >= 12 &&
      shannonEntropy(primaryLabel) >= 3.6;

    const { allowMap, blockMap } = buildRuleLookupMaps(rules);

    let action = 'allowed';
    let reason = `Resolvido via ${settings.dnsIp} (${settings.dnsProtocol})`;
    let matchedRule = null;
    let resolvedCategory = forcedCategory || inferredCat;

    if (!settings.vpnActive && !options.forceEvaluate) {
      action = 'allowed';
      reason = 'Vigilância VPN pausada · tráfego sem bloqueio';
    } else {
      const allowRule = findMatchingRuleInIndex(allowMap, domain);
      if (allowRule) {
        action = 'allowed';
        reason = `Permitido pela Allowlist: ${allowRule.domain}`;
        matchedRule = allowRule;
      } else {
        const blockRule = findMatchingRuleInIndex(blockMap, domain);
        if (blockRule) {
          action = 'blocked';
          reason = `Bloqueio real ativo · regra ${blockRule.domain}`;
          matchedRule = blockRule;
          if (!forcedCategory && blockRule.category && blockRule.category !== 'manual') {
            resolvedCategory = blockRule.category;
          }
        } else if (
          resolvedCategory === 'media_leak' &&
          (sigActive('sig_webrtc_stun') || sigActive('sig_hidden_media_upload'))
        ) {
          action = 'blocked';
          reason =
            'Sentinela de Sensores: canal STUN/TURN não autorizado ou upload oculto de mídia barrado';
        } else if (isDgaCandidate) {
          action = 'blocked';
          reason = `Heurística DGA: domínio de alta entropia (${shannonEntropy(primaryLabel).toFixed(2)})`;
        } else if (resolvedCategory === 'ai_crawler' && sigActive('sig_ai_crawlers')) {
          action = 'blocked';
          reason = 'Assinatura anti-IA: crawler/bot automatizado (GPTBot/Bytespider/CCBot)';
        } else if (
          resolvedCategory === 'ab_testing' &&
          (/hotjar|fullstory|clarity/.test(domain)
            ? sigActive('sig_session_replay')
            : sigActive('sig_ab_testing'))
        ) {
          action = 'blocked';
          reason = 'Assinatura Supply Chain: teste A/B ou session replay bloqueado';
        } else if (/headless|playwright|puppeteer/.test(`${domain}${urlPath}`) && sigActive('sig_headless_ua')) {
          action = 'blocked';
          reason = 'Assinatura Cabeçalho: User-Agent Headless/Automação barrado';
        } else if (resolvedCategory === 'ab_testing' || resolvedCategory === 'tracker') {
          reason = `Monitorado via ${settings.dnsIp} · sem bloqueio explícito`;
        }
      }
    }

    return {
      domain,
      urlPath,
      settings,
      rules,
      signatures,
      allowMap,
      blockMap,
      category: resolvedCategory,
      isDgaCandidate,
      action,
      reason,
      matchedRule,
      shouldBlockBeforeNetwork: action === 'blocked',
    };
  }

  async inspectDomainManually(rawInput) {
    const trimmed = String(rawInput || '').trim();
    const parsed = parseDomainAndPath(trimmed);
    if (!parsed.domain) return null;

    const scheme = /^http:\/\//i.test(trimmed) ? 'http://' : 'https://';
    const targetUrl = `${scheme}${parsed.domain}${parsed.urlPath || '/'}`;
    const online = typeof navigator === 'undefined' ? true : navigator.onLine !== false;
    this.isOnline = online;

    // Decisão em tempo real ANTES de qualquer requisição externa
    const preDecision = await this.evaluatePreRequestDecision(trimmed, null, null, {
      forceEvaluate: true,
    });

    let probe;
    if (preDecision?.shouldBlockBeforeNetwork) {
      probe = {
        status: 'blocked_locally',
        reachable: false,
        latencyMs: 0,
        targetUrl,
        blockedBeforeNetwork: true,
        detail: 'Requisição externa abortada antes da rede pelo escudo local',
      };
    } else if (!online) {
      probe = {
        status: 'offline',
        reachable: false,
        latencyMs: null,
        targetUrl,
        detail: 'Rede offline · tentativa externa ignorada sem conexão à internet',
      };
    } else {
      const startMs =
        typeof performance !== 'undefined' && typeof performance.now === 'function'
          ? performance.now()
          : Date.now();
      const { signal, cleanup } = createTimeoutSignal(4000);
      try {
        await fetch(targetUrl, {
          mode: 'no-cors',
          cache: 'no-store',
          signal,
        });
        const endMs =
          typeof performance !== 'undefined' && typeof performance.now === 'function'
            ? performance.now()
            : Date.now();
        const latencyMs = Math.max(1, Math.round(endMs - startMs));
        probe = {
          status: 'reachable',
          reachable: true,
          latencyMs,
          targetUrl,
          detail: `Conexão/resolução real alcançada em ${latencyMs} ms`,
        };
      } catch (err) {
        const endMs =
          typeof performance !== 'undefined' && typeof performance.now === 'function'
            ? performance.now()
            : Date.now();
        const latencyMs = Math.max(1, Math.round(endMs - startMs));
        const isTimeout =
          err?.name === 'TimeoutError' ||
          err?.name === 'AbortError' ||
          /timeout|abort/i.test(String(err?.message || ''));
        probe = {
          status: isTimeout ? 'timeout' : 'unreachable',
          reachable: false,
          latencyMs,
          targetUrl,
          detail: isTimeout
            ? `Timeout na conexão real após ${latencyMs} ms (limite 4000 ms)`
            : `Falha de DNS/conexão real em ${latencyMs} ms`,
        };
      } finally {
        cleanup();
      }
    }

    const result = await this.processRequest(trimmed, null, null, {
      forceEvaluate: true,
      probe,
      preDecision,
    });
    return result ? { ...result, probe } : null;
  }

  async detectRealRapidRefresh() {
    try {
      const key = 'aegis_refresh_history';
      const now = Date.now();
      const raw = window.sessionStorage.getItem(key);
      const history = raw ? JSON.parse(raw) : [];
      const recent = history.filter((ts) => now - ts <= 10_000);
      recent.push(now);
      window.sessionStorage.setItem(key, JSON.stringify(recent));

      if (recent.length >= 4) {
        await this.storage.put('alerts', {
          id: `alert_refresh_${now}`,
          timestamp: now,
          type: 'rapid_refresh',
          severity: 'high',
          domain: window.location.hostname || 'localhost',
          requestCount: recent.length,
          windowSeconds: 10,
          description: `Refresh suspeito detectado: ${recent.length} recarregamentos da sessão em menos de 10s.`,
          resolved: false,
          acknowledged: false,
        });
      }
    } catch {
      // sessionStorage unavailable
    }
  }

  async processRequest(rawInput, customPath = null, forcedCategory = null, options = {}) {
    const decision =
      options.preDecision ||
      (await this.evaluatePreRequestDecision(rawInput, customPath, forcedCategory, options));
    if (!decision) return null;

    const {
      domain,
      urlPath,
      settings,
      rules,
      signatures,
      category,
      isDgaCandidate,
      action,
      reason,
      matchedRule,
    } = decision;

    const now = Date.now();

    if (matchedRule) {
      matchedRule.hits = (matchedRule.hits || 0) + 1;
      await this.storage.put('rules', matchedRule);
    }

    let anomalyTriggered = false;
    if (settings.vpnActive || options.forceEvaluate) {
      anomalyTriggered = await this._evaluateBurstWindow(domain, settings, rules, signatures);
    }

    const severity = computeSeverity(category, action, anomalyTriggered || isDgaCandidate);

    const probe = options.probe || null;
    const combinedReason = probe ? `${reason} · ${probe.detail}` : reason;

    const logEntry = {
      id: `log_${now}_${Math.random().toString(36).slice(2, 7)}`,
      timestamp: now,
      domain,
      urlPath,
      category: isDgaCandidate ? 'anomaly' : category,
      severity,
      action,
      reason: combinedReason,
      isAmbient: Boolean(options.isAmbient),
      ...(probe
        ? {
            probeStatus: probe.status,
            latencyMs: probe.latencyMs,
            online: probe.status !== 'offline' && probe.status !== 'blocked_locally',
            blockedBeforeNetwork: Boolean(probe.blockedBeforeNetwork),
            targetUrl: probe.targetUrl,
          }
        : {}),
    };

    await this.storage.put('logs', logEntry);
    await this.storage.trimLogs(300);

    if (
      options.forceEvaluate &&
      !anomalyTriggered &&
      action === 'blocked' &&
      (severity === 'critical' || severity === 'high')
    ) {
      await this.storage.put('alerts', {
        id: `alert_probe_${now}_${Math.random().toString(36).slice(2, 6)}`,
        timestamp: now,
        type: 'bot_pattern',
        severity,
        domain,
        requestCount: 1,
        windowSeconds: 1,
        description: reason,
        resolved: false,
        acknowledged: false,
      });
      anomalyTriggered = true;
    }

    this._pushRadarBlip(domain, action, anomalyTriggered || isDgaCandidate);

    if (this.onUpdate) {
      await this.onUpdate(logEntry, anomalyTriggered);
    }

    return { logEntry, anomalyTriggered };
  }

  async _evaluateBurstWindow(domain, settings, rules, signatures = []) {
    const now = Date.now();
    const windowMs = 10_000;
    const timestamps = (this.slidingWindows.get(domain) || []).filter((ts) => now - ts <= windowMs);
    timestamps.push(now);
    this.slidingWindows.set(domain, timestamps);

    const sigBurst15 = signatures.find((s) => s.id === 'sig_burst_15_3s');
    const burst15Enabled = sigBurst15 ? Boolean(sigBurst15.enabled) : true;
    const recent3sCount = timestamps.filter((ts) => now - ts <= 3000).length;

    const threshold = Math.max(3, Number(settings.burstThreshold) || 6);
    const lastAlert = this.recentBurstAlerts.get(domain) || 0;
    const triggeredHighBurst = burst15Enabled && recent3sCount > 15;

    if ((timestamps.length >= threshold || triggeredHighBurst) && now - lastAlert > 8000) {
      this.recentBurstAlerts.set(domain, now);
      const spanSec = triggeredHighBurst
        ? 3
        : Math.max(1, Math.round((now - timestamps[0]) / 1000) || 1);
      const countLabel = triggeredHighBurst ? recent3sCount : timestamps.length;

      let autoBlockedMsg = '';
      if (settings.autoBlockBots) {
        const alreadyAllowed = rules.some(
          (r) => r.enabled && r.type === 'allow' && domainMatches(domain, r.domain)
        );
        const alreadyBlocked = rules.some(
          (r) => r.enabled && r.type === 'block' && domainMatches(domain, r.domain)
        );

        if (!alreadyAllowed && !alreadyBlocked) {
          await this.storage.put('rules', {
            id: `rule_auto_${now}_${Math.random().toString(36).slice(2, 5)}`,
            domain,
            type: 'block',
            category: 'anomaly',
            enabled: true,
            hits: 1,
            createdAt: now,
          });
          autoBlockedMsg = ' Domínio contido automaticamente na lista de bloqueio.';
        }
      }

      await this.storage.put('alerts', {
        id: `alert_burst_${now}_${Math.random().toString(36).slice(2, 6)}`,
        timestamp: now,
        type: 'burst',
        severity: 'critical',
        domain,
        requestCount: countLabel,
        windowSeconds: spanSec,
        description: `Rajada anômala de ${countLabel} requisições em ${spanSec}s detectada.${autoBlockedMsg}`,
        resolved: false,
        acknowledged: false,
      });

      return true;
    }

    return false;
  }

  async simulateMixedTraffic() {
    const scenarios = [
      { domain: 'gptbot.openai.test', urlPath: '/crawler/index-feed', category: 'ai_crawler' },
      { domain: 'claudebot.anthropic.test', urlPath: '/bot/scrape-html', category: 'ai_crawler' },
      { domain: 'cdn.optimizely.com', urlPath: '/js/2419820144.js', category: 'ab_testing' },
      { domain: 'www.google-analytics.com', urlPath: '/g/collect?v=2&tid=G-94K2', category: 'tracker' },
      { domain: 'cdn.jsdelivr.net', urlPath: '/npm/lucide@0.400.0/dist/umd/lucide.min.js', category: 'essential' },
      { domain: 'fonts.googleapis.com', urlPath: '/css2?family=IBM+Plex+Mono', category: 'essential' },
    ];
    for (const item of scenarios) {
      await this.processRequest(item.domain, item.urlPath, item.category, { forceEvaluate: true });
    }
  }

  async simulateBurstAttack(targetDomain = 'swarm-harvester.ai.test') {
    const settings = await this.storage.getSettings();
    const count = Math.max(8, Number(settings.burstThreshold || 6) + 2);
    for (let i = 0; i < count; i++) {
      await this.processRequest(
        targetDomain,
        `/v1/harvest?chunk=${i + 1}&rnd=${Math.random().toString(36).slice(2, 6)}`,
        'ai_crawler',
        { forceEvaluate: true }
      );
    }
  }

  async simulateBotAndRefreshAttack() {
    const now = Date.now();
    const botDomain = 'autonomous-agent.bot.test';

    for (let i = 0; i < 6; i++) {
      await this.processRequest(botDomain, `/api/scrape?step=${i + 1}`, 'anomaly', {
        forceEvaluate: true,
      });
    }

    await this.storage.put('alerts', {
      id: `alert_bot_${now}`,
      timestamp: now,
      type: 'bot_pattern',
      severity: 'critical',
      domain: botDomain,
      requestCount: 22,
      windowSeconds: 4,
      description: 'Enxame de bot IA / refresh em série detectado (intervalo automatizado < 200ms).',
      resolved: false,
      acknowledged: false,
    });

    if (this.onUpdate) {
      await this.onUpdate(null, true);
    }
  }

  async simulateSupplyChainAttack() {
    const now = Date.now();
    const compromisedDomain = 'cdn.optimizely.com';
    const maliciousPath = '/ab-variant/form-skimmer-hook.js?target=input[password]';

    const logEntry = {
      id: `log_sc_${now}_${Math.random().toString(36).slice(2, 6)}`,
      timestamp: now,
      domain: compromisedDomain,
      urlPath: maliciousPath,
      category: 'ab_testing',
      severity: 'critical',
      action: 'blocked',
      reason: 'Supply Chain bloqueado: script A/B externo tentou ler campos de formulário',
    };

    await this.storage.put('logs', logEntry);
    await this.storage.trimLogs(300);

    const rules = await this.storage.getAll('rules');
    const rule = rules.find((r) => r.domain === 'optimizely.com');
    if (rule) {
      rule.hits = (rule.hits || 0) + 1;
      await this.storage.put('rules', rule);
    }

    await this.storage.put('alerts', {
      id: `alert_sc_${now}_${Math.random().toString(36).slice(2, 5)}`,
      timestamp: now,
      type: 'supply_chain',
      severity: 'critical',
      domain: compromisedDomain,
      requestCount: 1,
      windowSeconds: 1,
      description:
        'Ataque Supply Chain contido: script A/B comprometido tentou interceptar inputs e dados de formulário.',
      resolved: false,
      acknowledged: false,
    });

    this._pushRadarBlip(compromisedDomain, 'blocked', true);

    if (this.onUpdate) {
      await this.onUpdate(logEntry, true);
    }

    return logEntry;
  }

  async simulatePolling60sBurst() {
    const targetDomain = 'ai-polling-60s.bot.test';
    const settings = await this.storage.getSettings();
    const totalRequests = Math.max(8, Number(settings.burstThreshold || 6) + 2);

    // Reset recent alert cooldown for immediate repeatable testing
    this.recentBurstAlerts.delete(targetDomain);

    for (let i = 0; i < totalRequests; i++) {
      await this.processRequest(
        targetDomain,
        `/v1/poll?window=60s&cycle=${i + 1}`,
        'ai_crawler',
        { forceEvaluate: true }
      );
    }

    return totalRequests;
  }

  async simulateWifiDnsHijack() {
    const now = Date.now();
    const rogueDomain = 'rogue-resolver.wifi-hijack.test';
    const settings = await this.storage.getSettings();

    const logEntry = {
      id: `log_dns_${now}_${Math.random().toString(36).slice(2, 6)}`,
      timestamp: now,
      domain: rogueDomain,
      urlPath: `/dns-query?spoof=${settings.dnsIp}->192.168.88.1`,
      category: 'anomaly',
      severity: 'critical',
      action: 'blocked',
      reason: `Sequestro de DNS Wi-Fi barrado · integridade mantida em ${settings.dnsIp} (${settings.dnsProtocol})`,
    };

    await this.storage.put('logs', logEntry);
    await this.storage.trimLogs(300);

    await this.storage.put('alerts', {
      id: `alert_dns_${now}_${Math.random().toString(36).slice(2, 5)}`,
      timestamp: now,
      type: 'dns_hijack',
      severity: 'critical',
      domain: rogueDomain,
      requestCount: 4,
      windowSeconds: 3,
      description: `Tentativa de sequestro de DNS na rede Wi-Fi local (desvio de ${settings.dnsIp} para gateway suspeito).`,
      resolved: false,
      acknowledged: false,
    });

    this._pushRadarBlip(rogueDomain, 'blocked', true);

    if (this.onUpdate) {
      await this.onUpdate(logEntry, true);
    }

    return logEntry;
  }

  async simulateWebRtcMediaLeak() {
    const now = Date.now();
    const leakDomain = 'turn-stream.ai-capture.test';
    const leakPath = '/webrtc/stun-ice?sensor=mic+cam&bg_upload=continuous-stream';

    const logEntry = {
      id: `log_webrtc_${now}_${Math.random().toString(36).slice(2, 6)}`,
      timestamp: now,
      domain: leakDomain,
      urlPath: leakPath,
      category: 'media_leak',
      severity: 'critical',
      action: 'blocked',
      reason:
        'Sentinela de Sensores: tentativa de captura oculta de microfone/câmera via servidor STUN/TURN não autorizado e upload contínuo bloqueada',
    };

    await this.storage.put('logs', logEntry);
    await this.storage.trimLogs(300);

    const rules = await this.storage.getAll('rules');
    const rule = rules.find((r) => r.domain === leakDomain);
    if (rule) {
      rule.hits = (rule.hits || 0) + 1;
      await this.storage.put('rules', rule);
    }

    await this.storage.put('alerts', {
      id: `alert_webrtc_${now}_${Math.random().toString(36).slice(2, 5)}`,
      timestamp: now,
      type: 'webrtc_leak',
      severity: 'critical',
      domain: leakDomain,
      requestCount: 3,
      windowSeconds: 2,
      description:
        'Vazamento WebRTC contido: script oculto tentou abrir canal STUN/TURN e transmitir áudio/vídeo em segundo plano.',
      resolved: false,
      acknowledged: false,
    });

    this._pushRadarBlip(leakDomain, 'blocked', true);

    if (this.onUpdate) {
      await this.onUpdate(logEntry, true);
    }

    return logEntry;
  }

  _pushRadarBlip(domain, action, isAnomaly) {
    const angle = Math.random() * Math.PI * 2;
    const radius = 0.25 + Math.random() * 0.65;
    this.radarBlips.unshift({
      domain,
      action,
      isAnomaly,
      angle,
      radius,
      createdAt: Date.now(),
    });
    if (this.radarBlips.length > 14) {
      this.radarBlips.length = 14;
    }
  }
}

export class RadarVisualizer {
  constructor(canvas, engine) {
    this.canvas = canvas;
    this.ctx = canvas.getContext('2d');
    this.engine = engine;
    this.sweepAngle = 0;
    this.isActive = true;
    this.isOnline = typeof navigator === 'undefined' ? true : navigator.onLine !== false;
    this.rafId = null;
    this.prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  }

  setActive(active) {
    this.isActive = Boolean(active);
    if (!this.rafId) {
      this.drawFrame();
    }
  }

  setOnline(online) {
    this.isOnline = Boolean(online);
    if (!this.rafId) {
      this.drawFrame();
    }
  }

  start() {
    const render = () => {
      this.drawFrame();
      if (this.isActive && this.isOnline && !this.prefersReducedMotion) {
        this.sweepAngle = (this.sweepAngle + 0.025) % (Math.PI * 2);
      }
      this.rafId = window.requestAnimationFrame(render);
    };
    this.rafId = window.requestAnimationFrame(render);
  }

  stop() {
    if (this.rafId) {
      window.cancelAnimationFrame(this.rafId);
      this.rafId = null;
    }
  }

  drawFrame() {
    const ctx = this.ctx;
    const w = this.canvas.width;
    const h = this.canvas.height;
    const cx = w / 2;
    const cy = h / 2;
    const maxR = Math.min(cx, cy) - 14;

    ctx.clearRect(0, 0, w, h);

    ctx.beginPath();
    ctx.arc(cx, cy, maxR, 0, Math.PI * 2);
    ctx.fillStyle = '#080d17';
    ctx.fill();
    ctx.lineWidth = 1.25;
    ctx.strokeStyle =
      this.isActive && !this.isOnline
        ? 'rgba(245, 158, 11, 0.36)'
        : 'rgba(148, 163, 184, 0.22)';
    ctx.stroke();

    [0.33, 0.66].forEach((ratio) => {
      ctx.beginPath();
      ctx.arc(cx, cy, maxR * ratio, 0, Math.PI * 2);
      ctx.strokeStyle = 'rgba(148, 163, 184, 0.12)';
      ctx.lineWidth = 1;
      ctx.stroke();
    });

    ctx.beginPath();
    ctx.moveTo(cx - maxR, cy);
    ctx.lineTo(cx + maxR, cy);
    ctx.moveTo(cx, cy - maxR);
    ctx.lineTo(cx, cy + maxR);
    ctx.strokeStyle = 'rgba(148, 163, 184, 0.1)';
    ctx.stroke();

    if (this.isActive && this.isOnline) {
      const sweepSpan = 0.55;
      const grad = ctx.createRadialGradient(cx, cy, 4, cx, cy, maxR);
      grad.addColorStop(0, 'rgba(14, 165, 233, 0.25)');
      grad.addColorStop(1, 'rgba(16, 185, 129, 0.03)');

      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.arc(cx, cy, maxR, this.sweepAngle - sweepSpan, this.sweepAngle);
      ctx.closePath();
      ctx.fillStyle = grad;
      ctx.fill();

      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.lineTo(
        cx + Math.cos(this.sweepAngle) * maxR,
        cy + Math.sin(this.sweepAngle) * maxR
      );
      ctx.strokeStyle = 'rgba(56, 189, 248, 0.78)';
      ctx.lineWidth = 1.5;
      ctx.stroke();
    }

    ctx.beginPath();
    ctx.arc(cx, cy, 4.5, 0, Math.PI * 2);
    ctx.fillStyle = !this.isActive ? '#d97706' : this.isOnline ? '#10b981' : '#f59e0b';
    ctx.fill();

    const now = Date.now();
    this.engine.radarBlips.forEach((blip) => {
      const age = now - blip.createdAt;
      if (age > 24_000) return;
      const alpha = Math.max(0.2, 1 - age / 24_000);
      const bx = cx + Math.cos(blip.angle) * (maxR * blip.radius);
      const by = cy + Math.sin(blip.angle) * (maxR * blip.radius);

      let color = `rgba(52, 211, 153, ${alpha})`;
      if (blip.isAnomaly) {
        color = `rgba(251, 191, 36, ${alpha})`;
      } else if (blip.action === 'blocked') {
        color = `rgba(248, 113, 113, ${alpha})`;
      }

      ctx.beginPath();
      ctx.arc(bx, by, blip.isAnomaly ? 5.5 : 4, 0, Math.PI * 2);
      ctx.fillStyle = color;
      ctx.fill();
    });

    if (this.isActive && !this.isOnline) {
      const boxW = Math.min(maxR * 1.65, 200);
      const boxH = 44;
      const boxX = cx - boxW / 2;
      const boxY = cy - boxH / 2;

      ctx.fillStyle = 'rgba(8, 13, 23, 0.88)';
      ctx.strokeStyle = 'rgba(245, 158, 11, 0.55)';
      ctx.lineWidth = 1;
      ctx.beginPath();
      if (typeof ctx.roundRect === 'function') {
        ctx.roundRect(boxX, boxY, boxW, boxH, 8);
      } else {
        ctx.rect(boxX, boxY, boxW, boxH);
      }
      ctx.fill();
      ctx.stroke();

      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.font = '700 11px "IBM Plex Mono", monospace';
      ctx.fillStyle = '#fbbf24';
      ctx.fillText('REDE OFFLINE', cx, cy - 8);
      ctx.font = '500 10.5px "Plus Jakarta Sans", sans-serif';
      ctx.fillStyle = '#cbd5e1';
      ctx.fillText('Varredura externa pausada', cx, cy + 9);
    }
  }
}
