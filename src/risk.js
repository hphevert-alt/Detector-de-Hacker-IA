export const RISK_WINDOW_MS = 15 * 60 * 1000; // 15 minutos

export const RISK_BANDS = [
  { id: 'safe', min: 0, max: 24, label: 'SEGURO', tone: 'safe' },
  { id: 'attention', min: 25, max: 54, label: 'ATENÇÃO', tone: 'attention' },
  { id: 'elevated', min: 55, max: 79, label: 'AMEAÇA ELEVADA', tone: 'elevated' },
  { id: 'critical', min: 80, max: 100, label: 'INVASÃO CRÍTICA', tone: 'critical' },
];

export function getRiskBand(score) {
  const clamped = Math.min(100, Math.max(0, Math.round(score)));
  return (
    RISK_BANDS.find((band) => clamped >= band.min && clamped <= band.max) ||
    RISK_BANDS[RISK_BANDS.length - 1]
  );
}

function formatAgeMinutes(ageMs) {
  const mins = Math.max(1, Math.ceil(ageMs / 60_000));
  return mins === 1 ? '1 min' : `${mins} min`;
}

function pluralize(count, singular, plural) {
  return count === 1 ? `${count} ${singular}` : `${count} ${plural}`;
}

export function computeNetworkRisk({ settings, logs = [], alerts = [], now = Date.now() }) {
  const vpnActive = settings ? Boolean(settings.vpnActive) : true;

  let rawScore = 0;
  const factors = [];

  if (!vpnActive) {
    rawScore += 25;
    factors.push({
      kind: 'vpn_paused',
      points: 25,
      timestamp: now,
      label: 'Vigilância VPN pausada (+25 pts)',
    });
  }

  // Index resolved and active alerts to avoid double-counting identical incidents in logs
  const resolvedAlerts = alerts.filter(
    (a) => a && a.resolved && now - a.timestamp < RISK_WINDOW_MS
  );
  const activeAlerts = alerts.filter(
    (a) => a && !a.resolved && now - a.timestamp < RISK_WINDOW_MS
  );

  const isCoveredByAlert = (log, alertList) =>
    alertList.some(
      (a) =>
        a.domain === log.domain &&
        Math.abs(a.timestamp - log.timestamp) <= 15_000
    );

  // 1) Active unresolved alerts in the 15-minute window
  for (const alert of activeAlerts) {
    const ageMs = Math.max(0, now - alert.timestamp);
    const decay = Math.max(0, 1 - ageMs / RISK_WINDOW_MS);
    if (decay <= 0) continue;

    let basePoints = 10;
    let kind = 'burst';
    const desc = String(alert.description || '').toLowerCase();

    if (alert.type === 'dns_hijack') {
      basePoints = 35;
      kind = 'dns_hijack';
    } else if (alert.type === 'webrtc_leak') {
      basePoints = 35;
      kind = 'webrtc_leak';
    } else if (alert.type === 'supply_chain') {
      const isFormExfil = /formul[aá]rio|input|exfil|skimmer/.test(desc);
      basePoints = isFormExfil ? 35 : 20;
      kind = isFormExfil ? 'form_exfil' : 'supply_chain';
    } else if (alert.type === 'bot_pattern' || alert.type === 'rapid_refresh') {
      basePoints = 20;
      kind = 'ai_bot';
    } else if (alert.type === 'burst') {
      basePoints = 10;
      kind = 'burst';
    }

    const decayedPoints = basePoints * decay;
    rawScore += decayedPoints;
    factors.push({
      kind,
      points: decayedPoints,
      timestamp: alert.timestamp,
      domain: alert.domain,
    });
  }

  // 2) Recent blocked non-ambient logs (deduplicated per domain in 15s buckets)
  const seenBuckets = new Set();
  for (const log of logs) {
    if (!log || log.action !== 'blocked' || log.isAmbient) continue;
    const ageMs = Math.max(0, now - log.timestamp);
    if (ageMs >= RISK_WINDOW_MS) continue;

    // If user already resolved the corresponding alert, don't penalize its logs
    if (isCoveredByAlert(log, resolvedAlerts)) continue;

    // Avoid double-counting Supply Chain / DNS Hijack / WebRTC alerts that already carry +35
    const matchingHighAlert = activeAlerts.some(
      (a) =>
        (a.type === 'dns_hijack' ||
          a.type === 'webrtc_leak' ||
          a.type === 'supply_chain' ||
          a.type === 'bot_pattern') &&
        a.domain === log.domain &&
        Math.abs(a.timestamp - log.timestamp) <= 5_000
    );
    if (matchingHighAlert) continue;

    const bucketKey = `${log.domain}:${Math.floor(log.timestamp / 15_000)}`;
    if (seenBuckets.has(bucketKey)) continue;
    seenBuckets.add(bucketKey);

    const decay = Math.max(0, 1 - ageMs / RISK_WINDOW_MS);
    const haystack = `${log.domain} ${log.urlPath || ''} ${log.reason || ''}`.toLowerCase();

    let basePoints = 10;
    let kind = 'script_block';

    if (
      log.category === 'media_leak' ||
      /webrtc|stun|turn-stream|mediastream|captura oculta/.test(haystack)
    ) {
      basePoints = 35;
      kind = 'webrtc_leak';
    } else if (
      /sequestro de dns|wifi-hijack|exfil|form-skimmer|ler campos de formul[aá]rio/.test(haystack)
    ) {
      basePoints = 35;
      kind = /dns|wifi-hijack/.test(haystack) ? 'dns_hijack' : 'form_exfil';
    } else if (
      log.category === 'ai_crawler' ||
      log.category === 'ab_testing' ||
      log.category === 'anomaly'
    ) {
      basePoints = 20;
      kind = log.category === 'ab_testing' ? 'supply_chain' : 'ai_bot';
    }

    const decayedPoints = basePoints * decay;
    rawScore += decayedPoints;
    factors.push({
      kind,
      points: decayedPoints,
      timestamp: log.timestamp,
      domain: log.domain,
    });
  }

  const score = Math.min(100, Math.max(0, Math.round(rawScore)));
  const band = getRiskBand(score);
  const summary = buildRiskSummary({ score, vpnActive, factors, now });

  const counts = {
    dnsOrExfil: factors.filter(
      (f) => f.kind === 'dns_hijack' || f.kind === 'form_exfil' || f.kind === 'webrtc_leak'
    ).length,
    supplyOrAi: factors.filter(
      (f) => f.kind === 'supply_chain' || f.kind === 'ai_bot' || f.kind === 'script_block'
    ).length,
    bursts: factors.filter((f) => f.kind === 'burst').length,
    vpnPaused: !vpnActive,
  };

  return {
    score,
    band,
    summary,
    counts,
    factorsCount: factors.length,
    updatedAt: now,
  };
}

function buildRiskSummary({ score, vpnActive, factors, now }) {
  const threatFactors = factors.filter((f) => f.kind !== 'vpn_paused');

  if (threatFactors.length === 0) {
    if (!vpnActive) {
      return 'Vigilância VPN pausada (+25 pts) · ative o escudo para proteção integral.';
    }
    return 'Nenhuma anomalia ativa detectada · perímetro de rede estável.';
  }

  const counts = {
    dns_hijack: 0,
    form_exfil: 0,
    webrtc_leak: 0,
    supply_chain: 0,
    ai_bot: 0,
    burst: 0,
    script_block: 0,
  };

  let oldestAgeMs = 0;
  for (const f of threatFactors) {
    counts[f.kind] = (counts[f.kind] || 0) + 1;
    oldestAgeMs = Math.max(oldestAgeMs, now - f.timestamp);
  }

  const windowLabel = formatAgeMinutes(Math.min(RISK_WINDOW_MS, oldestAgeMs));
  const parts = [];

  if (counts.webrtc_leak > 0) {
    parts.push(
      pluralize(
        counts.webrtc_leak,
        'captura WebRTC de câmera/mic bloqueada',
        'capturas WebRTC de câmera/mic bloqueadas'
      )
    );
  }
  if (counts.dns_hijack > 0) {
    parts.push(
      pluralize(counts.dns_hijack, 'sequestro de DNS contido', 'sequestros de DNS contidos')
    );
  }
  if (counts.form_exfil > 0) {
    parts.push(
      pluralize(
        counts.form_exfil,
        'tentativa de exfiltração Supply Chain',
        'tentativas de exfiltração Supply Chain'
      )
    );
  }
  if (counts.burst > 0) {
    parts.push(pluralize(counts.burst, 'rajada de IA bloqueada', 'rajadas de IA bloqueadas'));
  }
  const aiAndSupply = counts.ai_bot + counts.supply_chain + counts.script_block;
  if (aiAndSupply > 0) {
    parts.push(
      pluralize(aiAndSupply, 'script/bot de IA barrado', 'scripts/bots de IA barrados')
    );
  }

  const primaryText = parts.slice(0, 2).join(' e ');
  const vpnSuffix = !vpnActive ? ' · Vigilância VPN pausada (+25 pts)' : '';

  if (score === 0) {
    return 'Eventos anteriores expiraram · perímetro de rede estável.';
  }

  return `${primaryText} nos últimos ${windowLabel}${vpnSuffix}.`;
}
