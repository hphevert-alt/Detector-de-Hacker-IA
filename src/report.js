import { computeNetworkRisk } from './risk.js';

const WEEK_MS = 7 * 24 * 60 * 60 * 1000;

const CATEGORY_LABELS = {
  ai_crawler: 'Bot / Scraper de IA',
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

function pad2(n) {
  return String(n).padStart(2, '0');
}

function formatDateTime(ts) {
  const d = new Date(ts);
  return `${pad2(d.getDate())}/${pad2(d.getMonth() + 1)}/${d.getFullYear()} ${pad2(
    d.getHours()
  )}:${pad2(d.getMinutes())}`;
}

function formatFileDate(ts) {
  const d = new Date(ts);
  return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())}`;
}

export function buildWeeklySummaryData({ settings, rules = [], logs = [], alerts = [] }) {
  const now = Date.now();
  const weekStart = now - WEEK_MS;

  const weeklyLogs = logs
    .filter((l) => Number(l.timestamp) >= weekStart)
    .sort((a, b) => b.timestamp - a.timestamp);
  const weeklyAlerts = alerts
    .filter((a) => Number(a.timestamp) >= weekStart)
    .sort((a, b) => b.timestamp - a.timestamp);

  const blockedLogs = weeklyLogs.filter((l) => l.action === 'blocked');
  const allowedLogs = weeklyLogs.filter((l) => l.action === 'allowed');
  const totalEvents = weeklyLogs.length;
  const blockRate = totalEvents > 0 ? Math.round((blockedLogs.length / totalEvents) * 100) : 0;

  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  const byCategory = {};
  const domainCounts = new Map();

  for (const log of blockedLogs) {
    const sev = log.severity || 'medium';
    bySeverity[sev] = (bySeverity[sev] || 0) + 1;

    const cat = log.category || 'manual';
    byCategory[cat] = (byCategory[cat] || 0) + 1;

    const dom = log.domain || 'desconhecido';
    domainCounts.set(dom, (domainCounts.get(dom) || 0) + 1);
  }

  const topBlockedDomains = Array.from(domainCounts.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([domain, count]) => ({ domain, count }));

  const risk = computeNetworkRisk({ settings, logs, alerts });

  return {
    generatedAt: now,
    periodStart: weekStart,
    periodEnd: now,
    fileDate: formatFileDate(now),
    settings,
    risk,
    activeRulesCount: rules.filter((r) => r.enabled).length,
    totalRulesCount: rules.length,
    totalEvents,
    blockedCount: blockedLogs.length,
    allowedCount: allowedLogs.length,
    blockRate,
    alertsTotal: weeklyAlerts.length,
    alertsResolved: weeklyAlerts.filter((a) => a.resolved).length,
    alertsPending: weeklyAlerts.filter((a) => !a.resolved).length,
    bySeverity,
    byCategory,
    topBlockedDomains,
    weeklyAlerts,
    blockedLogs,
  };
}

export function generateWeeklyTxt(summary) {
  const s = summary;
  const lines = [];
  const hr = '='.repeat(68);
  const subHr = '-'.repeat(68);

  lines.push(hr);
  lines.push('AEGIS AI - RESUMO SEMANAL DE AMEAÇAS E BLOQUEIOS (7 DIAS)');
  lines.push(hr);
  lines.push(`Gerado em:        ${formatDateTime(s.generatedAt)}`);
  lines.push(
    `Período analisado: ${formatDateTime(s.periodStart)} até ${formatDateTime(s.periodEnd)}`
  );
  lines.push(
    `Escudo / VPN:     ${s.settings?.vpnActive ? 'Ativa' : 'Pausada'} | Modo Oculto: ${
      s.settings?.backgroundMode !== false ? 'Ativo' : 'Desativado'
    }`
  );
  lines.push(
    `DNS Seguro:       ${s.settings?.dnsIp || '1.1.1.2'} (${s.settings?.dnsProtocol || 'DoH'})`
  );
  lines.push(
    `Score de Risco:   ${s.risk.score}/100 (${s.risk.band.label}) - ${s.risk.summary}`
  );
  lines.push(`Regras Ativas:    ${s.activeRulesCount} de ${s.totalRulesCount}`);
  lines.push('');

  lines.push('1. ESTATÍSTICAS DE BLOQUEIO DA SEMANA');
  lines.push(subHr);
  lines.push(`Total de eventos avaliados:     ${s.totalEvents}`);
  lines.push(`Ameaças e scripts barrados:     ${s.blockedCount} (${s.blockRate}%)`);
  lines.push(`Tráfego seguro permitido:       ${s.allowedCount}`);
  lines.push(
    `Alertas heurísticos (7 dias):   ${s.alertsTotal} (${s.alertsResolved} resolvidos / ${s.alertsPending} pendentes)`
  );
  lines.push('');

  lines.push('2. BLOQUEIOS POR SEVERIDADE');
  lines.push(subHr);
  for (const key of ['critical', 'high', 'medium', 'low']) {
    lines.push(`- ${SEVERITY_LABELS[key].padEnd(10, ' ')}: ${s.bySeverity[key] || 0}`);
  }
  lines.push('');

  lines.push('3. BLOQUEIOS POR VETOR / CATEGORIA');
  lines.push(subHr);
  const catEntries = Object.entries(s.byCategory).sort((a, b) => b[1] - a[1]);
  if (catEntries.length === 0) {
    lines.push('Nenhum bloqueio registrado nos últimos 7 dias.');
  } else {
    for (const [cat, count] of catEntries) {
      const label = CATEGORY_LABELS[cat] || cat;
      lines.push(`- ${label.padEnd(24, ' ')}: ${count}`);
    }
  }
  lines.push('');

  lines.push('4. TOP DOMÍNIOS BLOQUEADOS NA SEMANA');
  lines.push(subHr);
  if (s.topBlockedDomains.length === 0) {
    lines.push('Nenhum domínio bloqueado nos últimos 7 dias.');
  } else {
    s.topBlockedDomains.forEach((item, idx) => {
      lines.push(`${String(idx + 1).padStart(2, '0')}. ${item.domain} (${item.count}x)`);
    });
  }
  lines.push('');

  lines.push('5. ALERTAS HEURÍSTICOS DA SEMANA');
  lines.push(subHr);
  if (s.weeklyAlerts.length === 0) {
    lines.push('Nenhum alerta heurístico registrado nos últimos 7 dias.');
  } else {
    for (const alert of s.weeklyAlerts.slice(0, 40)) {
      const sev = SEVERITY_LABELS[alert.severity] || alert.severity;
      const status = alert.resolved ? 'Resolvido' : 'Pendente';
      lines.push(
        `[${formatDateTime(alert.timestamp)}] [${sev}] [${status}] ${alert.domain} - ${
          alert.description || alert.type
        }`
      );
    }
  }
  lines.push('');

  lines.push('6. HISTÓRICO RECENTE DE AMEAÇAS BARRADAS (ATÉ 120 REGISTROS)');
  lines.push(subHr);
  if (s.blockedLogs.length === 0) {
    lines.push('Nenhuma ameaça barrada nos últimos 7 dias.');
  } else {
    for (const log of s.blockedLogs.slice(0, 120)) {
      const sev = SEVERITY_LABELS[log.severity] || log.severity;
      const cat = CATEGORY_LABELS[log.category] || log.category;
      lines.push(
        `[${formatDateTime(log.timestamp)}] [${sev}] [${cat}] ${log.domain}${log.path || ''} :: ${
          log.reason || 'Bloqueado pelo escudo'
        }`
      );
    }
  }

  lines.push('');
  lines.push(hr);
  lines.push('AEGIS AI • Vigilante de Rede | Desenvolvido por Hevert Pereira');
  lines.push(hr);

  return lines.join('\r\n');
}

// Convert Unicode string to single-byte WinAnsi bytes + PDF string escaping
function encodeWinAnsi(text) {
  const normalized = String(text ?? '')
    .replace(/[•·]/g, '-')
    .replace(/[—–]/g, '-')
    .replace(/[“”]/g, '"')
    .replace(/[‘’]/g, "'")
    .replace(/≥/g, '>=')
    .replace(/≤/g, '<=');

  const bytes = [];
  for (let i = 0; i < normalized.length; i++) {
    const code = normalized.charCodeAt(i);
    if (code >= 0x20 && code <= 0x7e) {
      bytes.push(code);
    } else if (code >= 0xa0 && code <= 0xff) {
      bytes.push(code);
    } else {
      bytes.push(0x3f); // '?'
    }
  }
  return bytes;
}

function pdfLiteral(text) {
  const bytes = encodeWinAnsi(text);
  let out = '(';
  for (const b of bytes) {
    if (b === 0x28 || b === 0x29 || b === 0x5c) {
      out += '\\' + String.fromCharCode(b);
    } else if (b < 0x80) {
      out += String.fromCharCode(b);
    } else {
      out += '\\' + b.toString(8).padStart(3, '0');
    }
  }
  out += ')';
  return out;
}

function wrapText(text, maxChars) {
  const clean = String(text ?? '').replace(/\s+/g, ' ').trim();
  if (!clean) return [''];
  const words = clean.split(' ');
  const result = [];
  let current = '';
  for (const word of words) {
    if (!current) {
      if (word.length <= maxChars) {
        current = word;
      } else {
        for (let i = 0; i < word.length; i += maxChars) {
          result.push(word.slice(i, i + maxChars));
        }
      }
    } else if (current.length + 1 + word.length <= maxChars) {
      current += ' ' + word;
    } else {
      result.push(current);
      if (word.length <= maxChars) {
        current = word;
      } else {
        current = '';
        for (let i = 0; i < word.length; i += maxChars) {
          const chunk = word.slice(i, i + maxChars);
          if (chunk.length === maxChars) result.push(chunk);
          else current = chunk;
        }
      }
    }
  }
  if (current) result.push(current);
  return result;
}

export function generateWeeklyPdfBytes(summary) {
  const s = summary;
  const pageWidth = 595;
  const pageHeight = 842;
  const marginX = 44;
  const topY = 794;
  const bottomY = 56;

  /** @type {string[][]} */
  const pages = [[]];
  let y = topY;

  const addPage = () => {
    pages.push([]);
    y = topY;
  };

  const ensureSpace = (neededHeight) => {
    if (y - neededHeight < bottomY) {
      addPage();
    }
  };

  const drawTextLine = (text, { font = 'F1', size = 10, x = marginX, color = '0.12 0.16 0.23', lineGap = 14 } = {}) => {
    ensureSpace(lineGap);
    const cmds = pages[pages.length - 1];
    cmds.push(`BT /${font} ${size} Tf ${color} rg 1 0 0 1 ${x} ${y} Tm ${pdfLiteral(text)} Tj ET`);
    y -= lineGap;
  };

  const drawRule = () => {
    ensureSpace(12);
    const cmds = pages[pages.length - 1];
    cmds.push(`0.82 0.86 0.90 RG 0.7 w ${marginX} ${y + 4} m ${pageWidth - marginX} ${y + 4} l S`);
    y -= 10;
  };

  const drawSectionHeading = (title) => {
    y -= 4;
    ensureSpace(24);
    drawTextLine(title, { font: 'F2', size: 12, color: '0.03 0.35 0.55', lineGap: 16 });
    drawRule();
  };

  // Header Banner
  const firstPage = pages[0];
  firstPage.push(`0.05 0.09 0.14 rg ${marginX} ${y - 44} ${pageWidth - marginX * 2} 54 re f`);
  firstPage.push(
    `BT /F2 15 Tf 0.95 0.97 1.00 rg 1 0 0 1 ${marginX + 14} ${y - 12} Tm ${pdfLiteral(
      'AEGIS AI - Resumo Semanal de Ameaças (7 Dias)'
    )} Tj ET`
  );
  firstPage.push(
    `BT /F1 9.5 Tf 0.72 0.82 0.92 rg 1 0 0 1 ${marginX + 14} ${y - 30} Tm ${pdfLiteral(
      `Gerado em ${formatDateTime(s.generatedAt)} | Período: ${formatDateTime(
        s.periodStart
      )} a ${formatDateTime(s.periodEnd)}`
    )} Tj ET`
  );
  y -= 64;

  // Section 1: Summary & Risk
  drawSectionHeading('1. Visão Geral & Estatísticas da Semana');
  drawTextLine(
    `Escudo / VPN: ${s.settings?.vpnActive ? 'Ativa' : 'Pausada'}   |   Modo Oculto: ${
      s.settings?.backgroundMode !== false ? 'Ativo' : 'Desativado'
    }   |   DNS: ${s.settings?.dnsIp || '1.1.1.2'} (${s.settings?.dnsProtocol || 'DoH'})`,
    { size: 9.5 }
  );
  drawTextLine(
    `Score de Risco Atual: ${s.risk.score}/100 (${s.risk.band.label}) - ${s.risk.summary}`,
    { font: 'F2', size: 9.5 }
  );
  drawTextLine(
    `Eventos Avaliados (7d): ${s.totalEvents}   |   Ameaças Barradas: ${s.blockedCount} (${s.blockRate}%)   |   Permitidos: ${s.allowedCount}`,
    { size: 9.5 }
  );
  drawTextLine(
    `Alertas Heurísticos (7d): ${s.alertsTotal} (${s.alertsResolved} resolvidos / ${s.alertsPending} pendentes)   |   Regras Ativas: ${s.activeRulesCount}/${s.totalRulesCount}`,
    { size: 9.5 }
  );

  // Section 2: Severity & Vectors
  drawSectionHeading('2. Distribuição por Severidade e Vetor');
  drawTextLine(
    `Severidade -> Crítica: ${s.bySeverity.critical || 0}  |  Alta: ${
      s.bySeverity.high || 0
    }  |  Média: ${s.bySeverity.medium || 0}  |  Baixa: ${s.bySeverity.low || 0}`,
    { size: 9.5 }
  );
  const catEntries = Object.entries(s.byCategory).sort((a, b) => b[1] - a[1]);
  if (catEntries.length === 0) {
    drawTextLine('Vetores bloqueados: Nenhum bloqueio registrado nos últimos 7 dias.', { size: 9.5 });
  } else {
    const catSummary = catEntries
      .map(([cat, count]) => `${CATEGORY_LABELS[cat] || cat}: ${count}`)
      .join('  |  ');
    for (const line of wrapText(`Vetores -> ${catSummary}`, 92)) {
      drawTextLine(line, { size: 9.5, lineGap: 13 });
    }
  }

  // Section 3: Top Blocked Domains
  drawSectionHeading('3. Top Domínios Bloqueados na Semana');
  if (s.topBlockedDomains.length === 0) {
    drawTextLine('Nenhum domínio bloqueado registrado nos últimos 7 dias.', { size: 9.5 });
  } else {
    s.topBlockedDomains.forEach((item, idx) => {
      drawTextLine(`${String(idx + 1).padStart(2, '0')}. ${item.domain} (${item.count} bloqueios)`, {
        font: 'F3',
        size: 9,
        lineGap: 13,
      });
    });
  }

  // Section 4: Heuristics Alerts
  drawSectionHeading('4. Alertas Heurísticos Registrados (Últimos 7 Dias)');
  if (s.weeklyAlerts.length === 0) {
    drawTextLine('Nenhum alerta heurístico registrado nos últimos 7 dias.', { size: 9.5 });
  } else {
    for (const alert of s.weeklyAlerts.slice(0, 35)) {
      const sev = SEVERITY_LABELS[alert.severity] || alert.severity;
      const status = alert.resolved ? 'Resolvido' : 'Pendente';
      const raw = `[${formatDateTime(alert.timestamp)}] [${sev}/${status}] ${alert.domain} - ${
        alert.description || alert.type
      }`;
      for (const line of wrapText(raw, 94)) {
        drawTextLine(line, { size: 8.8, lineGap: 12 });
      }
    }
  }

  // Section 5: Threat Logs
  drawSectionHeading('5. Histórico de Ameaças Barradas (Até 90 Registros Recentes)');
  if (s.blockedLogs.length === 0) {
    drawTextLine('Nenhuma ameaça barrada registrada nos últimos 7 dias.', { size: 9.5 });
  } else {
    for (const log of s.blockedLogs.slice(0, 90)) {
      const sev = SEVERITY_LABELS[log.severity] || log.severity;
      const cat = CATEGORY_LABELS[log.category] || log.category;
      const raw = `[${formatDateTime(log.timestamp)}] [${sev}] [${cat}] ${log.domain}${
        log.path || ''
      } - ${log.reason || 'Bloqueado pelo escudo'}`;
      for (const line of wrapText(raw, 96)) {
        drawTextLine(line, { size: 8.5, lineGap: 11.5 });
      }
    }
  }

  // Add footer to every page
  pages.forEach((cmds, index) => {
    cmds.push(`0.82 0.86 0.90 RG 0.5 w ${marginX} 40 m ${pageWidth - marginX} 40 l S`);
    cmds.push(
      `BT /F1 8.5 Tf 0.40 0.46 0.54 rg 1 0 0 1 ${marginX} 26 Tm ${pdfLiteral(
        'AEGIS AI • Vigilante de Rede | Desenvolvido por Hevert Pereira'
      )} Tj ET`
    );
    cmds.push(
      `BT /F1 8.5 Tf 0.40 0.46 0.54 rg 1 0 0 1 ${pageWidth - marginX - 58} 26 Tm ${pdfLiteral(
        `Página ${index + 1}/${pages.length}`
      )} Tj ET`
    );
  });

  // Assemble PDF objects
  // 1: Catalog, 2: Pages, 3: F1 Helvetica, 4: F2 Helvetica-Bold, 5: F3 Courier, then Page+Content pairs
  const objects = [];
  const pageObjNums = [];
  const nextObjStart = 6;
  pages.forEach((_, idx) => {
    pageObjNums.push(nextObjStart + idx * 2);
  });

  objects.push(`1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n`);
  objects.push(
    `2 0 obj\n<< /Type /Pages /Kids [${pageObjNums
      .map((n) => `${n} 0 R`)
      .join(' ')}] /Count ${pageObjNums.length} >>\nendobj\n`
  );
  objects.push(
    `3 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>\nendobj\n`
  );
  objects.push(
    `4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>\nendobj\n`
  );
  objects.push(
    `5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>\nendobj\n`
  );

  pages.forEach((cmds, idx) => {
    const pageNum = nextObjStart + idx * 2;
    const contentNum = pageNum + 1;
    const streamStr = cmds.join('\n') + '\n';
    objects.push(
      `${pageNum} 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${pageWidth} ${pageHeight}] /Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >> /Contents ${contentNum} 0 R >>\nendobj\n`
    );
    objects.push(
      `${contentNum} 0 obj\n<< /Length ${streamStr.length} >>\nstream\n${streamStr}endstream\nendobj\n`
    );
  });

  const chunks = [];
  const offsets = [0];
  let bytePos = 0;

  const pushAscii = (str) => {
    const arr = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) {
      arr[i] = str.charCodeAt(i) & 0xff;
    }
    chunks.push(arr);
    bytePos += arr.length;
  };

  pushAscii('%PDF-1.4\n%\xE2\xE3\xCF\xD3\n');
  for (const obj of objects) {
    offsets.push(bytePos);
    pushAscii(obj);
  }

  const xrefStart = bytePos;
  pushAscii(`xref\n0 ${offsets.length}\n`);
  pushAscii('0000000000 65535 f \n');
  for (let i = 1; i < offsets.length; i++) {
    pushAscii(`${String(offsets[i]).padStart(10, '0')} 00000 n \n`);
  }
  pushAscii(
    `trailer\n<< /Size ${offsets.length} /Root 1 0 R >>\nstartxref\n${xrefStart}\n%%EOF\n`
  );

  const output = new Uint8Array(bytePos);
  let cursor = 0;
  for (const chunk of chunks) {
    output.set(chunk, cursor);
    cursor += chunk.length;
  }
  return output;
}

function uint8ToBase64(bytes) {
  let binary = '';
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const slice = bytes.subarray(i, i + chunkSize);
    binary += String.fromCharCode(...slice);
  }
  return btoa(binary);
}

export async function exportWeeklyReport({ format = 'pdf', settings, rules, logs, alerts }) {
  const summary = buildWeeklySummaryData({ settings, rules, logs, alerts });
  const ext = format === 'txt' ? 'txt' : 'pdf';
  const filename = `AEGIS-AI-Resumo-Semanal-${summary.fileDate}.${ext}`;
  const mimeType = ext === 'pdf' ? 'application/pdf' : 'text/plain;charset=utf-8';

  const bytes =
    ext === 'pdf'
      ? generateWeeklyPdfBytes(summary)
      : new TextEncoder().encode(generateWeeklyTxt(summary));

  // Native Android APK bridge (saves straight into phone's Downloads folder)
  const win = /** @type {any} */ (window);
  const plugin = win.Capacitor?.Plugins?.AegisBackground;
  if (win.Capacitor?.isNativePlatform?.() && plugin?.saveExportFile) {
    const res = await plugin.saveExportFile({
      filename,
      mimeType,
      base64Data: uint8ToBase64(bytes),
    });
    return {
      filename,
      format: ext,
      nativeSaved: true,
      location: res?.location || `Downloads/${filename}`,
      summary,
    };
  }

  // Standard Web / PWA download
  const blob = new Blob([bytes], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1500);

  return {
    filename,
    format: ext,
    nativeSaved: false,
    location: filename,
    summary,
  };
}
