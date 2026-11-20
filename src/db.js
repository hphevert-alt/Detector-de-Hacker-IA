const DB_NAME = 'AegisAI_Vigilante_DB';
const DB_VERSION = 2;
const LS_PREFIX = 'aegis_ai_v1_';

export const DNS_PRESETS = {
  'cloudflare-sec': {
    label: 'Cloudflare Security',
    ip: '1.1.1.2',
    protocol: 'DoH',
  },
  quad9: {
    label: 'Quad9 Threat Blocking',
    ip: '9.9.9.9',
    protocol: 'DoH',
  },
  adguard: {
    label: 'AdGuard DNS',
    ip: '94.140.14.14',
    protocol: 'DoH',
  },
  mullvad: {
    label: 'Mullvad DNS',
    ip: '194.242.2.2',
    protocol: 'DoT',
  },
  custom: {
    label: 'Personalizado',
    ip: '127.0.0.1',
    protocol: 'DNSCrypt',
  },
};

export const DEFAULT_SETTINGS = {
  key: 'config',
  vpnActive: true,
  dnsPreset: 'cloudflare-sec',
  dnsIp: '1.1.1.2',
  dnsProtocol: 'DoH',
  burstThreshold: 6,
  autoBlockBots: true,
  alertSoundEnabled: true,
};

export const SIGNATURE_GROUPS = [
  {
    id: 'supply_chain',
    title: '1. Scripts & Supply Chain',
    subtitle: 'Testes A/B, session replay/gravação de formulário e bots raspadores de IA',
  },
  {
    id: 'headers_exfiltration',
    title: '2. Cabeçalhos & Exfiltração',
    subtitle: 'Exfiltração de formulários, scripts sem SRI e agentes Headless/Automação',
  },
  {
    id: 'ai_heuristics',
    title: '3. Heurística Comportamental de IA',
    subtitle: 'Cadência fixa de polling 60s, rajadas intensas (15 req/3s) e domínios DGA',
  },
  {
    id: 'sensors_media',
    title: '4. Sentinela de Sensores (WebRTC & Mídia)',
    subtitle: 'Servidores STUN/TURN não autorizados e fluxo contínuo de upload oculto',
  },
];

export const SENSOR_CHECKLIST_ITEMS = [
  {
    id: 'chk_android_green_dot',
    title: 'Verificar indicador verde de câmera/microfone no Android',
    detail:
      'Confira o ponto verde na barra superior; se aparecer sem chamada ativa, toque nele para ver qual app está usando o sensor.',
  },
  {
    id: 'chk_revoke_bg_perms',
    title: 'Revogar permissões de sensores em segundo plano',
    detail:
      'Em Privacidade > Gerenciador de Permissões, restrinja Câmera e Microfone para "Permitir apenas durante o uso" ou "Não permitir".',
  },
  {
    id: 'chk_quick_tile_cutoff',
    title: 'Ativar o corte rápido global de Câmera e Microfone',
    detail:
      'Fixe os blocos "Acesso à câmera" e "Acesso ao microfone" no painel rápido do aparelho para desativação imediata em 1 toque.',
  },
  {
    id: 'chk_browser_webrtc',
    title: 'Bloquear solicitações automáticas de mídia e WebRTC no navegador',
    detail:
      'Mantenha permissões de mídia bloqueadas por padrão no navegador e deixe ativas as assinaturas STUN/TURN do AEGIS AI.',
  },
];

export function createDefaultSignatures() {
  return [
    {
      id: 'sig_ab_testing',
      group: 'supply_chain',
      name: 'Padrões de teste A/B e experimentação remota',
      pattern: 'optimizely · vwo · abtasty',
      description: 'Bloqueia scripts externos de testes A/B com capacidade de modificar o DOM em tempo real.',
      enabled: true,
    },
    {
      id: 'sig_session_replay',
      group: 'supply_chain',
      name: 'Session replay e gravação de formulários',
      pattern: 'hotjar · fullstory · clarity',
      description: 'Impede gravação de sessão, mapas de calor e captura de digitação em campos sensíveis.',
      enabled: true,
    },
    {
      id: 'sig_ai_crawlers',
      group: 'supply_chain',
      name: 'Bots raspadores de IA (GPTBot, Bytespider, CCBot)',
      pattern: 'GPTBot · Bytespider · CCBot · ClaudeBot',
      description: 'Contém crawlers e extratores automatizados usados para raspagem de conteúdo por IA.',
      enabled: true,
    },
    {
      id: 'sig_form_exfil',
      group: 'headers_exfiltration',
      name: 'Envio de dados de formulário para domínios externos',
      pattern: 'cross-origin POST · form-action',
      description: 'Detecta tentativas de leitura ou exfiltração de campos <form> para origens externas.',
      enabled: true,
    },
    {
      id: 'sig_no_sri',
      group: 'headers_exfiltration',
      name: 'Scripts externos sem hash de integridade SRI',
      pattern: 'script[src] sem integrity="sha*"',
      description: 'Sinaliza e barra scripts remotos carregados sem verificação criptográfica Subresource Integrity.',
      enabled: true,
    },
    {
      id: 'sig_headless_ua',
      group: 'headers_exfiltration',
      name: 'User-Agents Headless e frameworks de automação',
      pattern: 'HeadlessChrome · Playwright · Puppeteer',
      description: 'Identifica cabeçalhos de clientes automatizados simulando navegação humana.',
      enabled: true,
    },
    {
      id: 'sig_polling_60s',
      group: 'ai_heuristics',
      name: 'Cadência fixa de polling a cada 60s',
      pattern: 'intervalo periódico ~60s',
      description: 'Detecta loops automatizados de coleta ou heartbeat com cadência fixa a cada 60 segundos.',
      enabled: true,
    },
    {
      id: 'sig_burst_15_3s',
      group: 'ai_heuristics',
      name: 'Rajada acima de 15 requisições em 3s',
      pattern: '> 15 req / 3s por domínio',
      description: 'Aciona contenção imediata quando um domínio dispara enxames acima de 15 requisições em 3 segundos.',
      enabled: true,
    },
    {
      id: 'sig_dga_entropy',
      group: 'ai_heuristics',
      name: 'Domínios de alta entropia / DGA',
      pattern: 'Entropia Shannon >= 3.6',
      description: 'Identifica domínios pseudoaleatórios gerados por algoritmos (Domain Generation Algorithm).',
      enabled: true,
    },
    {
      id: 'sig_webrtc_stun',
      group: 'sensors_media',
      name: 'Servidores STUN/TURN não autorizados (WebRTC Leak)',
      pattern: 'stun: · turn: · RTCPeerConnection',
      description: 'Bloqueia abertura oculta de canais WebRTC/ICE para servidores STUN/TURN externos não confiáveis.',
      enabled: true,
    },
    {
      id: 'sig_hidden_media_upload',
      group: 'sensors_media',
      name: 'Fluxo contínuo de upload em segundo plano',
      pattern: 'MediaRecorder · stream upload > 64KB/s',
      description: 'Detecta transmissão contínua em segundo plano típica de captura silenciosa de áudio/vídeo por bots ou scripts de IA.',
      enabled: true,
    },
  ];
}

export function createDefaultRules() {
  const now = Date.now();
  return [
    {
      id: 'rule_ai_gptbot',
      domain: 'gptbot.openai.test',
      type: 'block',
      category: 'ai_crawler',
      enabled: true,
      hits: 18,
      createdAt: now - 3600_000 * 8,
    },
    {
      id: 'rule_ai_bytespider',
      domain: 'bytespider.bytedance.test',
      type: 'block',
      category: 'ai_crawler',
      enabled: true,
      hits: 14,
      createdAt: now - 3600_000 * 7,
    },
    {
      id: 'rule_ai_ccbot',
      domain: 'ccbot.commoncrawl.test',
      type: 'block',
      category: 'ai_crawler',
      enabled: true,
      hits: 11,
      createdAt: now - 3600_000 * 7,
    },
    {
      id: 'rule_ai_claude',
      domain: 'claudebot.anthropic.test',
      type: 'block',
      category: 'ai_crawler',
      enabled: true,
      hits: 12,
      createdAt: now - 3600_000 * 7,
    },
    {
      id: 'rule_ai_scraper',
      domain: 'headless-scraper.ai.test',
      type: 'block',
      category: 'ai_crawler',
      enabled: true,
      hits: 15,
      createdAt: now - 3600_000 * 5,
    },
    {
      id: 'rule_optimizely',
      domain: 'optimizely.com',
      type: 'block',
      category: 'ab_testing',
      enabled: true,
      hits: 14,
      createdAt: now - 3600_000 * 6,
    },
    {
      id: 'rule_vwo',
      domain: 'visualwebsiteoptimizer.com',
      type: 'block',
      category: 'ab_testing',
      enabled: true,
      hits: 8,
      createdAt: now - 3600_000 * 5,
    },
    {
      id: 'rule_abtasty',
      domain: 'abtasty.com',
      type: 'block',
      category: 'ab_testing',
      enabled: true,
      hits: 6,
      createdAt: now - 3600_000 * 5,
    },
    {
      id: 'rule_hotjar',
      domain: 'hotjar.com',
      type: 'block',
      category: 'ab_testing',
      enabled: true,
      hits: 11,
      createdAt: now - 3600_000 * 4,
    },
    {
      id: 'rule_fullstory',
      domain: 'fullstory.com',
      type: 'block',
      category: 'third_party',
      enabled: true,
      hits: 9,
      createdAt: now - 3600_000 * 4,
    },
    {
      id: 'rule_clarity',
      domain: 'clarity.ms',
      type: 'block',
      category: 'third_party',
      enabled: true,
      hits: 7,
      createdAt: now - 3600_000 * 4,
    },
    {
      id: 'rule_ga',
      domain: 'google-analytics.com',
      type: 'block',
      category: 'tracker',
      enabled: true,
      hits: 29,
      createdAt: now - 3600_000 * 8,
    },
    {
      id: 'rule_doubleclick',
      domain: 'doubleclick.net',
      type: 'block',
      category: 'tracker',
      enabled: true,
      hits: 22,
      createdAt: now - 3600_000 * 7,
    },
    {
      id: 'rule_fbpixel',
      domain: 'connect.facebook.net',
      type: 'block',
      category: 'tracker',
      enabled: true,
      hits: 17,
      createdAt: now - 3600_000 * 6,
    },
    {
      id: 'rule_segment',
      domain: 'cdn.segment.com',
      type: 'block',
      category: 'third_party',
      enabled: true,
      hits: 13,
      createdAt: now - 3600_000 * 5,
    },
    {
      id: 'rule_jsdelivr',
      domain: 'cdn.jsdelivr.net',
      type: 'allow',
      category: 'essential',
      enabled: true,
      hits: 19,
      createdAt: now - 3600_000 * 9,
    },
    {
      id: 'rule_fonts',
      domain: 'fonts.googleapis.com',
      type: 'allow',
      category: 'essential',
      enabled: true,
      hits: 12,
      createdAt: now - 3600_000 * 9,
    },
    {
      id: 'rule_stun_unauthorized',
      domain: 'stun-relay.bot-media.test',
      type: 'block',
      category: 'media_leak',
      enabled: true,
      hits: 6,
      createdAt: now - 3600_000 * 3,
    },
    {
      id: 'rule_turn_hidden_upload',
      domain: 'turn-stream.ai-capture.test',
      type: 'block',
      category: 'media_leak',
      enabled: true,
      hits: 4,
      createdAt: now - 3600_000 * 2,
    },
  ];
}

function createInitialLogs() {
  const now = Date.now();
  return [
    {
      id: 'log_init_1',
      timestamp: now - 420_000,
      domain: 'headless-scraper.ai.test',
      urlPath: '/v2/dom-harvest.js',
      category: 'ai_crawler',
      severity: 'high',
      action: 'blocked',
      reason: 'Bot de coleta de IA bloqueado: headless-scraper.ai.test',
      isAmbient: true,
    },
    {
      id: 'log_init_2',
      timestamp: now - 360_000,
      domain: 'gptbot.openai.test',
      urlPath: '/crawler/index-feed',
      category: 'ai_crawler',
      severity: 'high',
      action: 'blocked',
      reason: 'Regra anti-IA: gptbot.openai.test',
      isAmbient: true,
    },
    {
      id: 'log_init_3',
      timestamp: now - 300_000,
      domain: 'cdn.optimizely.com',
      urlPath: '/js/2419820144.js',
      category: 'ab_testing',
      severity: 'medium',
      action: 'blocked',
      reason: 'Script A/B bloqueado: optimizely.com',
      isAmbient: true,
    },
    {
      id: 'log_init_4',
      timestamp: now - 240_000,
      domain: 'cdn.jsdelivr.net',
      urlPath: '/npm/chart.js@4.4.0/dist/chart.umd.min.js',
      category: 'essential',
      severity: 'low',
      action: 'allowed',
      reason: 'Permitido pela Allowlist: cdn.jsdelivr.net',
      isAmbient: true,
    },
    {
      id: 'log_init_5',
      timestamp: now - 150_000,
      domain: 'www.google-analytics.com',
      urlPath: '/g/collect?v=2&tid=G-94K2',
      category: 'tracker',
      severity: 'medium',
      action: 'blocked',
      reason: 'Rastreador bloqueado: google-analytics.com',
      isAmbient: true,
    },
    {
      id: 'log_init_6',
      timestamp: now - 90_000,
      domain: 'fonts.googleapis.com',
      urlPath: '/css2?family=Plus+Jakarta+Sans',
      category: 'essential',
      severity: 'low',
      action: 'allowed',
      reason: 'Permitido pela Allowlist: fonts.googleapis.com',
      isAmbient: true,
    },
  ];
}

function createInitialAlerts() {
  const now = Date.now();
  return [
    {
      id: 'alert_init_1',
      timestamp: now - 180_000,
      type: 'burst',
      severity: 'critical',
      domain: 'swarm-harvester.ai.test',
      requestCount: 11,
      windowSeconds: 5,
      description: 'Rajada anômala de coleta automatizada de IA (11 req em 5s) contida pelo escudo.',
      resolved: true,
      acknowledged: true,
      acknowledgedAt: now - 160_000,
    },
  ];
}

export class AegisStorage {
  constructor() {
    this.db = null;
    this.backend = 'indexeddb';
  }

  async init() {
    if (typeof window === 'undefined' || !('indexedDB' in window)) {
      this.backend = 'localstorage';
      await this.seedIfEmpty();
      return this.backend;
    }

    try {
      this.db = await this._openIndexedDB();
      this.backend = 'indexeddb';
    } catch {
      this.db = null;
      this.backend = 'localstorage';
    }

    await this.seedIfEmpty();
    return this.backend;
  }

  _openIndexedDB() {
    return new Promise((resolve, reject) => {
      const request = window.indexedDB.open(DB_NAME, DB_VERSION);

      request.onupgradeneeded = (event) => {
        const db = event.target.result;
        if (!db.objectStoreNames.contains('rules')) {
          db.createObjectStore('rules', { keyPath: 'id' });
        }
        if (!db.objectStoreNames.contains('logs')) {
          db.createObjectStore('logs', { keyPath: 'id' });
        }
        if (!db.objectStoreNames.contains('alerts')) {
          db.createObjectStore('alerts', { keyPath: 'id' });
        }
        if (!db.objectStoreNames.contains('settings')) {
          db.createObjectStore('settings', { keyPath: 'key' });
        }
        if (!db.objectStoreNames.contains('signatures')) {
          db.createObjectStore('signatures', { keyPath: 'id' });
        }
      };

      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
      request.onblocked = () => reject(new Error('IndexedDB blocked'));
    });
  }

  _lsGet(storeName) {
    try {
      const raw = window.localStorage.getItem(LS_PREFIX + storeName);
      return raw ? JSON.parse(raw) : [];
    } catch {
      return [];
    }
  }

  _lsSet(storeName, items) {
    try {
      window.localStorage.setItem(LS_PREFIX + storeName, JSON.stringify(items));
    } catch {
      // Ignore quota errors
    }
  }

  async getAll(storeName) {
    if (this.backend === 'localstorage' || !this.db) {
      return this._lsGet(storeName);
    }
    return new Promise((resolve, reject) => {
      const tx = this.db.transaction(storeName, 'readonly');
      const store = tx.objectStore(storeName);
      const req = store.getAll();
      req.onsuccess = () => resolve(req.result || []);
      req.onerror = () => reject(req.error);
    });
  }

  async put(storeName, item) {
    if (this.backend === 'localstorage' || !this.db) {
      const keyName = storeName === 'settings' ? 'key' : 'id';
      const items = this._lsGet(storeName);
      const idx = items.findIndex((entry) => entry[keyName] === item[keyName]);
      if (idx >= 0) {
        items[idx] = item;
      } else {
        items.push(item);
      }
      this._lsSet(storeName, items);
      return item;
    }

    return new Promise((resolve, reject) => {
      const tx = this.db.transaction(storeName, 'readwrite');
      const store = tx.objectStore(storeName);
      const req = store.put(item);
      req.onsuccess = () => resolve(item);
      req.onerror = () => reject(req.error);
    });
  }

  async putMany(storeName, items) {
    if (this.backend === 'localstorage' || !this.db) {
      const keyName = storeName === 'settings' ? 'key' : 'id';
      const existing = this._lsGet(storeName);
      const map = new Map(existing.map((item) => [item[keyName], item]));
      for (const item of items) {
        map.set(item[keyName], item);
      }
      this._lsSet(storeName, Array.from(map.values()));
      return;
    }

    return new Promise((resolve, reject) => {
      const tx = this.db.transaction(storeName, 'readwrite');
      const store = tx.objectStore(storeName);
      for (const item of items) {
        store.put(item);
      }
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  }

  async delete(storeName, key) {
    if (this.backend === 'localstorage' || !this.db) {
      const keyName = storeName === 'settings' ? 'key' : 'id';
      const items = this._lsGet(storeName).filter((item) => item[keyName] !== key);
      this._lsSet(storeName, items);
      return;
    }

    return new Promise((resolve, reject) => {
      const tx = this.db.transaction(storeName, 'readwrite');
      const store = tx.objectStore(storeName);
      const req = store.delete(key);
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    });
  }

  async clearStore(storeName) {
    if (this.backend === 'localstorage' || !this.db) {
      this._lsSet(storeName, []);
      return;
    }

    return new Promise((resolve, reject) => {
      const tx = this.db.transaction(storeName, 'readwrite');
      const store = tx.objectStore(storeName);
      const req = store.clear();
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    });
  }

  async getSettings() {
    const all = await this.getAll('settings');
    const found = all.find((item) => item.key === 'config');
    return found ? { ...DEFAULT_SETTINGS, ...found } : { ...DEFAULT_SETTINGS };
  }

  async saveSettings(settings) {
    const merged = { ...DEFAULT_SETTINGS, ...settings, key: 'config' };
    await this.put('settings', merged);
    return merged;
  }

  async getRiskSnapshot() {
    const all = await this.getAll('settings');
    return all.find((item) => item.key === 'risk_state') || null;
  }

  async saveRiskSnapshot(risk) {
    const existing = await this.getRiskSnapshot();
    const prevHistory = Array.isArray(existing?.history) ? existing.history : [];
    const lastEntry = prevHistory[prevHistory.length - 1];
    const shouldAppend =
      !lastEntry ||
      lastEntry.score !== risk.score ||
      risk.updatedAt - lastEntry.timestamp >= 60_000;

    const nextHistory = shouldAppend
      ? [
          ...prevHistory,
          {
            score: risk.score,
            band: risk.band.id,
            timestamp: risk.updatedAt,
          },
        ].slice(-24)
      : prevHistory;

    const record = {
      key: 'risk_state',
      score: risk.score,
      bandId: risk.band.id,
      bandLabel: risk.band.label,
      summary: risk.summary,
      updatedAt: risk.updatedAt,
      history: nextHistory,
    };
    await this.put('settings', record);
    return record;
  }

  async getSensorChecklist() {
    const all = await this.getAll('settings');
    const found = all.find((item) => item.key === 'sensor_checklist');
    const checks = found && typeof found.checks === 'object' && found.checks ? found.checks : {};
    return {
      key: 'sensor_checklist',
      checks,
      updatedAt: found?.updatedAt || 0,
    };
  }

  async saveSensorChecklist(checks) {
    const record = {
      key: 'sensor_checklist',
      checks: { ...checks },
      updatedAt: Date.now(),
    };
    await this.put('settings', record);
    return record;
  }

  async seedIfEmpty() {
    const [existingRules, existingSettings, existingSignatures] = await Promise.all([
      this.getAll('rules'),
      this.getAll('settings'),
      this.getAll('signatures'),
    ]);

    if (existingSettings.length === 0) {
      await this.put('settings', { ...DEFAULT_SETTINGS });
    }

    const defaultSigs = createDefaultSignatures();
    if (existingSignatures.length === 0) {
      await this.putMany('signatures', defaultSigs);
    } else {
      const sigIds = new Set(existingSignatures.map((s) => s.id));
      const missingSigs = defaultSigs.filter((s) => !sigIds.has(s.id));
      if (missingSigs.length > 0) {
        await this.putMany('signatures', missingSigs);
      }
    }

    const defaultRules = createDefaultRules();
    if (existingRules.length === 0) {
      await this.putMany('rules', defaultRules);
      const existingLogs = await this.getAll('logs');
      if (existingLogs.length === 0) {
        await this.putMany('logs', createInitialLogs());
      }
      const existingAlerts = await this.getAll('alerts');
      if (existingAlerts.length === 0) {
        await this.putMany('alerts', createInitialAlerts());
      }
    } else {
      const ruleIds = new Set(existingRules.map((r) => r.id));
      const missingSensorRules = defaultRules.filter(
        (r) => r.category === 'media_leak' && !ruleIds.has(r.id)
      );
      if (missingSensorRules.length > 0) {
        await this.putMany('rules', missingSensorRules);
      }
    }
  }

  async trimLogs(maxLogs = 300) {
    const logs = await this.getAll('logs');
    if (logs.length <= maxLogs) return;
    logs.sort((a, b) => b.timestamp - a.timestamp);
    const toKeep = logs.slice(0, maxLogs);
    await this.clearStore('logs');
    await this.putMany('logs', toKeep);
  }

  async exportBundle() {
    const [rules, settings, signatures] = await Promise.all([
      this.getAll('rules'),
      this.getSettings(),
      this.getAll('signatures'),
    ]);
    return {
      app: 'AEGIS AI — Vigilante contra Invasões de IA',
      version: 2,
      exportedAt: new Date().toISOString(),
      settings: {
        dnsPreset: settings.dnsPreset,
        dnsIp: settings.dnsIp,
        dnsProtocol: settings.dnsProtocol,
        burstThreshold: settings.burstThreshold,
        autoBlockBots: settings.autoBlockBots,
        alertSoundEnabled: settings.alertSoundEnabled,
      },
      signatures: signatures.map((s) => ({
        id: s.id,
        enabled: s.enabled,
      })),
      rules: rules.map((r) => ({
        domain: r.domain,
        type: r.type,
        category: r.category,
        enabled: r.enabled,
      })),
    };
  }

  async importBundle(jsonText, mode = 'merge') {
    let parsed;
    try {
      parsed = JSON.parse(jsonText);
    } catch {
      throw new Error('JSON inválido. Verifique a sintaxe do arquivo ou texto.');
    }

    if (!parsed || !Array.isArray(parsed.rules)) {
      throw new Error('Estrutura inválida: o JSON precisa conter um array "rules".');
    }

    const validCategories = new Set([
      'ai_crawler',
      'tracker',
      'ab_testing',
      'third_party',
      'media_leak',
      'manual',
      'essential',
      'anomaly',
    ]);

    const normalizedRules = parsed.rules
      .filter((r) => r && typeof r.domain === 'string' && r.domain.trim().length > 0)
      .map((r, idx) => ({
        id: `rule_imp_${Date.now()}_${idx}_${Math.random().toString(36).slice(2, 6)}`,
        domain: normalizeDomain(r.domain),
        type: r.type === 'allow' ? 'allow' : 'block',
        category: validCategories.has(r.category) ? r.category : 'manual',
        enabled: r.enabled !== false,
        hits: typeof r.hits === 'number' ? r.hits : 0,
        createdAt: Date.now(),
      }));

    if (normalizedRules.length === 0) {
      throw new Error('Nenhuma regra válida encontrada no JSON.');
    }

    if (mode === 'replace') {
      await this.clearStore('rules');
      await this.putMany('rules', normalizedRules);
    } else {
      const current = await this.getAll('rules');
      const byDomain = new Map(current.map((r) => [r.domain.toLowerCase(), r]));
      for (const rule of normalizedRules) {
        const existing = byDomain.get(rule.domain.toLowerCase());
        if (existing) {
          byDomain.set(rule.domain.toLowerCase(), {
            ...existing,
            type: rule.type,
            category: rule.category,
            enabled: rule.enabled,
          });
        } else {
          byDomain.set(rule.domain.toLowerCase(), rule);
        }
      }
      await this.clearStore('rules');
      await this.putMany('rules', Array.from(byDomain.values()));
    }

    if (parsed.settings && typeof parsed.settings === 'object') {
      const currentSettings = await this.getSettings();
      await this.saveSettings({
        ...currentSettings,
        dnsPreset: parsed.settings.dnsPreset || currentSettings.dnsPreset,
        dnsIp: parsed.settings.dnsIp || currentSettings.dnsIp,
        dnsProtocol: parsed.settings.dnsProtocol || currentSettings.dnsProtocol,
        burstThreshold:
          Number(parsed.settings.burstThreshold) >= 3
            ? Number(parsed.settings.burstThreshold)
            : currentSettings.burstThreshold,
        autoBlockBots:
          typeof parsed.settings.autoBlockBots === 'boolean'
            ? parsed.settings.autoBlockBots
            : currentSettings.autoBlockBots,
        alertSoundEnabled:
          typeof parsed.settings.alertSoundEnabled === 'boolean'
            ? parsed.settings.alertSoundEnabled
            : currentSettings.alertSoundEnabled,
      });
    }

    if (Array.isArray(parsed.signatures)) {
      const currentSigs = await this.getAll('signatures');
      const sigMap = new Map(currentSigs.map((s) => [s.id, s]));
      for (const importedSig of parsed.signatures) {
        if (importedSig && sigMap.has(importedSig.id)) {
          sigMap.set(importedSig.id, {
            ...sigMap.get(importedSig.id),
            enabled: importedSig.enabled !== false,
          });
        }
      }
      await this.putMany('signatures', Array.from(sigMap.values()));
    }

    return normalizedRules.length;
  }

  async resetDefaults() {
    await this.clearStore('rules');
    await this.putMany('rules', createDefaultRules());
    await this.clearStore('signatures');
    await this.putMany('signatures', createDefaultSignatures());
    const currentSettings = await this.getSettings();
    await this.saveSettings({
      ...DEFAULT_SETTINGS,
      vpnActive: currentSettings.vpnActive,
    });
  }
}

export function normalizeDomain(input) {
  let cleaned = String(input || '').trim().toLowerCase();
  cleaned = cleaned.replace(/^https?:\/\//, '');
  cleaned = cleaned.split('/')[0];
  cleaned = cleaned.split('?')[0];
  cleaned = cleaned.split(':')[0];
  return cleaned;
}

export function parseDomainAndPath(input) {
  const raw = String(input || '').trim();
  const withoutProto = raw.replace(/^https?:\/\//i, '');
  const slashIdx = withoutProto.indexOf('/');
  if (slashIdx === -1) {
    return {
      domain: normalizeDomain(withoutProto),
      urlPath: '/',
    };
  }
  return {
    domain: normalizeDomain(withoutProto.slice(0, slashIdx)),
    urlPath: withoutProto.slice(slashIdx) || '/',
  };
}
