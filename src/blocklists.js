import { normalizeDomain } from './db.js';

export const FREE_OPEN_BLOCKLISTS = [
  {
    id: 'hagezi_light',
    name: 'HaGeZi Multi Light (Trackers, Ads & Telemetria)',
    url: 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/light.txt',
    defaultCategory: 'tracker',
    description:
      'Lista pública leve e amplamente testada do projeto HaGeZi no GitHub para bloquear rastreadores e telemetria sem quebrar sites essenciais.',
  },
  {
    id: 'ai_crawler_huge',
    name: 'AI Blocklist / Crawlers & Scrapers (GitHub Hosts)',
    url: 'https://raw.githubusercontent.com/laylavish/uBlockOrigin-HUGE-AI-Blocklist/main/noai_hosts.txt',
    defaultCategory: 'ai_crawler',
    description:
      'Lista comunitária aberta focada em barrar domínios de raspagem, treinamento automatizado e crawlers de IA.',
  },
  {
    id: 'hagezi_tif_mini',
    name: 'HaGeZi Threat Intelligence Feeds (Mini)',
    url: 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/tif-mini.txt',
    defaultCategory: 'third_party',
    description:
      'Domínios maliciosos, phishing, C2 e infraestrutura de coleta de terceiros de alto risco (GitHub).',
  },
  {
    id: 'stevenblack_hosts',
    name: 'StevenBlack Unified Hosts (Adware & Rastreadores)',
    url: 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
    defaultCategory: 'tracker',
    description:
      'Consolidação clássica open-source em formato hosts para neutralização em nível de DNS.',
  },
];

const IGNORED_HOSTNAMES = new Set([
  'localhost',
  'localhost.localdomain',
  'local',
  'broadcasthost',
  'ip6-localhost',
  'ip6-loopback',
  'ip6-localnet',
  'ip6-mcastprefix',
  'ip6-allnodes',
  'ip6-allrouters',
  'ip6-allhosts',
  '0.0.0.0',
  '127.0.0.1',
  '255.255.255.255',
]);

const VALID_HOSTNAME_RE =
  /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;

const MAX_IMPORT_DOMAINS_DEFAULT = 25000;

export function categorizeImportedDomain(domain, fallbackCategory = 'manual') {
  const lower = String(domain || '').toLowerCase();
  if (!lower) return fallbackCategory || 'manual';

  if (
    /(^|\.)(gptbot|chatgpt|openai|anthropic|claude|bytespider|ccbot|commoncrawl|perplexity|cohere|diffbot|omgili|youbot|deepseek|mistral|x\.ai|grok|huggingface|crawler|scraper|llm|harvester|aibot|ai-bot|img2dataset)/.test(
      lower
    ) ||
    /(gptbot|bytespider|ccbot|claudebot|scraper|crawler|ai-collect|genai|llm-api)/.test(lower)
  ) {
    return 'ai_crawler';
  }

  if (
    /optimizely|vwo|visualwebsiteoptimizer|abtasty|hotjar|abtest|split\.io|launchdarkly|convert\.com|kameleoon|crazyegg|mouseflow|luckyorange/.test(
      lower
    )
  ) {
    return 'ab_testing';
  }

  if (
    /analytics|doubleclick|googlesyndication|googletagmanager|googleadservices|adservice|adsystem|facebook\.net|fbcdn|pixel|taboola|outbrain|criteo|pubmatic|rubicon|appnexus|quantserve|scorecardresearch|adnxs|tracking|tracker|beacon|metrics|ads\.|ad\.|adserver/.test(
      lower
    )
  ) {
    return 'tracker';
  }

  if (
    /segment|amplitude|fullstory|clarity|newrelic|sentry|telemetry|mixpanel|intercom|heap|datadog|bugsnag|rollbar|session-replay|collect\.|collector\./.test(
      lower
    )
  ) {
    return 'third_party';
  }

  return fallbackCategory || 'manual';
}

function normalizeCandidateToken(token) {
  let candidate = String(token || '')
    .trim()
    .replace(/^["'`]+|["'`,;]+$/g, '');
  if (!candidate) return '';

  // Support Adblock domain rules: ||example.com^ or ||example.com^$third-party
  if (candidate.startsWith('||')) {
    candidate = candidate.slice(2);
    const sepIdx = candidate.search(/[\^/$*]/);
    if (sepIdx !== -1) {
      candidate = candidate.slice(0, sepIdx);
    }
  } else {
    // Strip wildcards like *.example.com
    candidate = candidate.replace(/^\*\./, '');
    // Ignore rules with regex slashes or complex query modifiers
    if (candidate.startsWith('/') && candidate.endsWith('/')) {
      return '';
    }
    const dollarIdx = candidate.indexOf('$');
    if (dollarIdx !== -1) {
      candidate = candidate.slice(0, dollarIdx);
    }
    if (candidate.endsWith('^')) {
      candidate = candidate.slice(0, -1);
    }
  }

  const normalized = normalizeDomain(candidate).replace(/\.+$/, '');
  if (!normalized || normalized.length > 253) return '';
  if (IGNORED_HOSTNAMES.has(normalized)) return '';
  if (/^\d+(?:\.\d+){3}$/.test(normalized)) return '';
  if (!VALID_HOSTNAME_RE.test(normalized)) return '';
  return normalized;
}

function isHostsIpPrefix(token) {
  const clean = String(token || '').trim().toLowerCase();
  if (!clean) return false;
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(clean)) return true;
  if (clean === '::1' || clean === '::' || clean.includes(':')) {
    return !clean.startsWith('http://') && !clean.startsWith('https://');
  }
  return false;
}

function extractDomainsFromLine(rawLine) {
  let line = String(rawLine || '').trim();
  if (!line) return [];

  // Ignore comments & metadata headers
  if (
    line.startsWith('#') ||
    line.startsWith('!') ||
    line.startsWith(';') ||
    line.startsWith('//') ||
    line.startsWith('[') ||
    line.startsWith('@@')
  ) {
    return [];
  }

  // Ignore Adblock cosmetic filters (##, #@#, #?#) BEFORE stripping inline # comments
  if (line.includes('##') || line.includes('#@#') || line.includes('#?#')) {
    return [];
  }

  // Strip inline comments (# ...) safely without breaking URLs if # is only a fragment?
  // Wait: if line starts with http(s):// and has #fragment, normalizeDomain handles #fragment,
  // while hosts/domain lines use " # comment". Strip # comment when preceded by space or not part of URL,
  // and if URL has fragment, normalizeDomain strips # anyway.
  const hashCommentIdx = line.search(/\s+#/);
  if (hashCommentIdx !== -1) {
    line = line.slice(0, hashCommentIdx).trim();
  } else if (!/^https?:\/\//i.test(line)) {
    const hashIdx = line.indexOf('#');
    if (hashIdx !== -1) {
      line = line.slice(0, hashIdx).trim();
    }
  }

  const bangIdx = line.indexOf(' !');
  if (bangIdx !== -1) {
    line = line.slice(0, bangIdx).trim();
  }
  if (!line) return [];

  const parts = line.split(/\s+/);
  const extracted = [];

  if (parts.length >= 2 && isHostsIpPrefix(parts[0])) {
    for (let i = 1; i < parts.length; i++) {
      const dom = normalizeCandidateToken(parts[i]);
      if (dom) extracted.push(dom);
    }
    return extracted;
  }

  const single = normalizeCandidateToken(parts[0]);
  if (single) extracted.push(single);
  return extracted;
}

export function parseBlocklistText(
  rawText,
  {
    maxDomains = MAX_IMPORT_DOMAINS_DEFAULT,
    categoryMode = 'auto',
    fallbackCategory = 'manual',
  } = {}
) {
  const text = String(rawText || '').replace(/^\uFEFF/, '');
  const lines = text.split(/\r?\n/);

  const uniqueDomains = new Map();
  let totalLines = 0;
  let ignoredCommentsOrEmpty = 0;
  let invalidLines = 0;
  let truncatedCount = 0;

  for (let i = 0; i < lines.length; i++) {
    const rawLine = lines[i];
    const trimmed = rawLine.trim();
    totalLines += 1;

    if (
      !trimmed ||
      trimmed.startsWith('#') ||
      trimmed.startsWith('!') ||
      trimmed.startsWith(';') ||
      trimmed.startsWith('//') ||
      trimmed.startsWith('[')
    ) {
      ignoredCommentsOrEmpty += 1;
      continue;
    }

    const domains = extractDomainsFromLine(trimmed);
    if (domains.length === 0) {
      invalidLines += 1;
      continue;
    }

    for (const domain of domains) {
      if (uniqueDomains.has(domain)) {
        continue;
      }

      if (uniqueDomains.size >= maxDomains) {
        truncatedCount += 1;
        continue;
      }

      const category =
        categoryMode === 'auto'
          ? categorizeImportedDomain(domain, fallbackCategory)
          : categoryMode;

      uniqueDomains.set(domain, {
        domain,
        category,
      });
    }
  }

  const entries = Array.from(uniqueDomains.values());
  const categoryCounts = {};
  for (const entry of entries) {
    categoryCounts[entry.category] = (categoryCounts[entry.category] || 0) + 1;
  }

  return {
    entries,
    stats: {
      totalLines,
      ignoredCommentsOrEmpty,
      invalidLines,
      parsedCount: entries.length,
      truncatedCount,
      categoryCounts,
    },
  };
}

export function validatePublicListUrl(rawUrl) {
  const trimmed = String(rawUrl || '').trim();
  if (!trimmed) {
    throw new Error('Informe uma URL pública válida (https://...).');
  }
  let parsed;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new Error('URL inválida. Use um endereço completo iniciado por https://');
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw new Error('Protocolo não suportado. Apenas listas http:// ou https:// são permitidas.');
  }
  return parsed.toString();
}

export async function fetchPublicBlocklist(rawUrl, { timeoutMs = 18_000 } = {}) {
  const validUrl = validatePublicListUrl(rawUrl);

  if (typeof navigator !== 'undefined' && navigator.onLine === false) {
    throw new Error(
      'Dispositivo sem internet (offline). Conecte-se ou cole os domínios manualmente abaixo.'
    );
  }

  let controller = null;
  let timerId = null;
  if (typeof AbortController !== 'undefined') {
    controller = new AbortController();
    timerId = setTimeout(() => {
      controller.abort(new Error('TimeoutError'));
    }, timeoutMs);
  }

  try {
    const response = await fetch(validUrl, {
      method: 'GET',
      mode: 'cors',
      cache: 'no-store',
      signal: controller?.signal,
    });

    if (!response.ok) {
      throw new Error(`Falha ao baixar lista (HTTP ${response.status}).`);
    }

    const text = await response.text();
    if (!text || !text.trim()) {
      throw new Error('A lista baixada veio vazia.');
    }
    return {
      url: validUrl,
      text,
      bytes: text.length,
    };
  } catch (err) {
    if (err?.name === 'AbortError' || /timeout/i.test(String(err?.message || ''))) {
      throw new Error('Tempo limite excedido ao baixar a lista pública (18s).');
    }
    if (/Failed to fetch|NetworkError|Load failed/i.test(String(err?.message || ''))) {
      throw new Error(
        'Não foi possível acessar a URL (bloqueio de CORS do servidor ou falha de rede). Tente um link raw.githubusercontent.com ou cole o conteúdo no campo de texto.'
      );
    }
    throw err;
  } finally {
    if (timerId !== null) {
      clearTimeout(timerId);
    }
  }
}

export async function importBlocklistBatch({
  storage,
  entries = [],
  sourceTag = 'bulk_list',
  sourceLabel = '',
  respectAllowlist = true,
  chunkSize = 1000,
  onProgress = null,
}) {
  if (!storage) {
    throw new Error('Armazenamento IndexedDB indisponível.');
  }
  if (!Array.isArray(entries) || entries.length === 0) {
    return {
      batchId: null,
      added: 0,
      updated: 0,
      alreadyExisting: 0,
      skippedAllowlist: 0,
      persisted: 0,
      addedIds: [],
      totalRulesAfter: (await storage.getAll('rules')).length,
    };
  }

  const existingRules = await storage.getAll('rules');
  const existingByDomain = new Map();
  for (const rule of existingRules) {
    if (rule && rule.domain) {
      existingByDomain.set(String(rule.domain).toLowerCase(), rule);
    }
  }

  const now = Date.now();
  const batchId = `batch_${now}_${Math.random().toString(36).slice(2, 6)}`;
  const toPersist = [];
  const addedIds = [];
  const updatedBackups = [];
  let added = 0;
  let updated = 0;
  let alreadyExisting = 0;
  let skippedAllowlist = 0;

  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];
    const domain = String(entry?.domain || '').trim().toLowerCase();
    if (!domain) continue;

    const existing = existingByDomain.get(domain);
    if (existing) {
      if (respectAllowlist && existing.type === 'allow') {
        skippedAllowlist += 1;
        continue;
      }

      const needsReactivate = !existing.enabled;
      const needsTypeChange = existing.type !== 'block';
      const canEnrichCategory =
        existing.category === 'manual' && entry.category && entry.category !== 'manual';

      if (!needsReactivate && !needsTypeChange && !canEnrichCategory) {
        alreadyExisting += 1;
        continue;
      }

      updatedBackups.push({ ...existing });
      const updatedRule = {
        ...existing,
        type: 'block',
        category: canEnrichCategory ? entry.category : existing.category || entry.category || 'manual',
        enabled: true,
        source: existing.source || sourceTag,
      };
      existingByDomain.set(domain, updatedRule);
      toPersist.push(updatedRule);
      updated += 1;
    } else {
      const ruleId = `rule_bulk_${now}_${i}_${Math.random().toString(36).slice(2, 6)}`;
      const newRule = {
        id: ruleId,
        domain,
        type: 'block',
        category: entry.category || 'manual',
        enabled: true,
        hits: 0,
        source: sourceTag,
        batchId,
        createdAt: now,
      };
      existingByDomain.set(domain, newRule);
      toPersist.push(newRule);
      addedIds.push(ruleId);
      added += 1;
    }
  }

  const totalToPersist = toPersist.length;
  for (let offset = 0; offset < totalToPersist; offset += chunkSize) {
    const chunk = toPersist.slice(offset, offset + chunkSize);
    await storage.putMany('rules', chunk);
    if (typeof onProgress === 'function') {
      onProgress({
        processed: Math.min(offset + chunk.length, totalToPersist),
        total: totalToPersist,
      });
    }
    if (offset + chunkSize < totalToPersist) {
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
  }

  if ((addedIds.length > 0 || updatedBackups.length > 0) && typeof storage.saveLastBulkImportBatch === 'function') {
    await storage.saveLastBulkImportBatch({
      batchId,
      sourceLabel: sourceLabel || sourceTag,
      createdAt: now,
      addedIds,
      updatedBackups,
    });
  }

  return {
    batchId,
    added,
    updated,
    alreadyExisting,
    skippedAllowlist,
    persisted: totalToPersist,
    addedIds,
    totalRulesAfter: existingByDomain.size,
  };
}

export async function undoLastBulkImport({ storage, chunkSize = 1000, onProgress = null }) {
  if (!storage) {
    throw new Error('Armazenamento IndexedDB indisponível.');
  }
  const lastBatch =
    typeof storage.getLastBulkImportBatch === 'function'
      ? await storage.getLastBulkImportBatch()
      : null;

  const addedIds = Array.isArray(lastBatch?.addedIds) ? lastBatch.addedIds : [];
  const updatedBackups = Array.isArray(lastBatch?.updatedBackups)
    ? lastBatch.updatedBackups
    : [];

  if (!lastBatch || (addedIds.length === 0 && updatedBackups.length === 0)) {
    return {
      undone: false,
      removedCount: 0,
      restoredCount: 0,
      sourceLabel: '',
    };
  }

  const totalSteps = addedIds.length + updatedBackups.length;
  let processed = 0;

  for (let offset = 0; offset < addedIds.length; offset += chunkSize) {
    const chunk = addedIds.slice(offset, offset + chunkSize);
    if (typeof storage.deleteMany === 'function') {
      await storage.deleteMany('rules', chunk);
    } else {
      for (const id of chunk) {
        await storage.delete('rules', id);
      }
    }
    processed += chunk.length;
    if (typeof onProgress === 'function') {
      onProgress({ processed, total: totalSteps });
    }
    if (offset + chunkSize < addedIds.length) {
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
  }

  for (let offset = 0; offset < updatedBackups.length; offset += chunkSize) {
    const chunk = updatedBackups.slice(offset, offset + chunkSize);
    await storage.putMany('rules', chunk);
    processed += chunk.length;
    if (typeof onProgress === 'function') {
      onProgress({ processed, total: totalSteps });
    }
    if (offset + chunkSize < updatedBackups.length) {
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
  }

  if (typeof storage.clearLastBulkImportBatch === 'function') {
    await storage.clearLastBulkImportBatch();
  }

  return {
    undone: true,
    removedCount: addedIds.length,
    restoredCount: updatedBackups.length,
    sourceLabel: lastBatch.sourceLabel || 'último lote',
  };
}

export function buildAndroidVpnPolicyBundle({ settings = {}, rules = [], maxPreviewDomains = null } = {}) {
  const allowMap = new Map();
  const blockMap = new Map();
  const categoriesCount = {};

  for (const rule of rules) {
    if (!rule || !rule.enabled || !rule.domain) continue;
    const clean = normalizeDomain(rule.domain);
    if (!clean) continue;

    if (rule.type === 'allow') {
      allowMap.set(clean, {
        domain: clean,
        type: 'allow',
        category: rule.category || 'essential',
        enabled: true,
      });
      blockMap.delete(clean);
    } else if (rule.type === 'block' && !allowMap.has(clean)) {
      const cat = rule.category || 'manual';
      if (!blockMap.has(clean)) {
        blockMap.set(clean, {
          domain: clean,
          type: 'block',
          category: cat,
          enabled: true,
        });
        categoriesCount[cat] = (categoriesCount[cat] || 0) + 1;
      }
    }
  }

  const allowlistRules = Array.from(allowMap.values()).sort((a, b) =>
    a.domain.localeCompare(b.domain)
  );
  const allBlockedRules = Array.from(blockMap.values()).sort((a, b) =>
    a.domain.localeCompare(b.domain)
  );
  const visibleBlockedRules =
    typeof maxPreviewDomains === 'number' &&
    maxPreviewDomains > 0 &&
    allBlockedRules.length > maxPreviewDomains
      ? allBlockedRules.slice(0, maxPreviewDomains)
      : allBlockedRules;

  const rawDnsIp = String(settings.dnsIp || '1.1.1.2').trim();
  const dnsIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(rawDnsIp) ? rawDnsIp : '1.1.1.2';

  return {
    app: 'AEGIS AI — Vigilante contra Invasões de IA',
    packageName: 'com.hevertpereira.aegisai',
    schemaVersion: 2,
    generatedAt: new Date().toISOString(),
    settings: {
      vpnActive: Boolean(settings.vpnActive),
      dnsPreset: settings.dnsPreset || 'cloudflare-sec',
      dnsIp,
      dnsProtocol: settings.dnsProtocol || 'DoH',
      burstThreshold: Number(settings.burstThreshold) || 6,
      autoBlockBots: settings.autoBlockBots !== false,
    },
    stats: {
      totalAllowlist: allowlistRules.length,
      totalBlockedDomains: allBlockedRules.length,
      previewTruncated: visibleBlockedRules.length < allBlockedRules.length,
      categoriesCount,
    },
    rules: [...allowlistRules, ...visibleBlockedRules],
  };
}

export const ANDROID_KOTLIN_VPNSERVICE_CODE = `package com.hevertpereira.aegisai.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicBoolean

class AegisGuardVpnService : VpnService() {

    companion object {
        const val ACTION_START = "com.hevertpereira.aegisai.vpn.START"
        const val ACTION_STOP = "com.hevertpereira.aegisai.vpn.STOP"
        const val EXTRA_POLICY_PATH = "extra_policy_path"
        const val EXTRA_POLICY_JSON = "extra_policy_json"

        private const val TAG = "AegisGuardVpn"
        private const val VIRTUAL_DNS_IP = "10.66.0.2"
        private const val CHANNEL_ID = "aegis_vpn_channel"
        private const val NOTIFICATION_ID = 1042
    }

    private val running = AtomicBoolean(false)
    private var vpnInterface: ParcelFileDescriptor? = null
    private var workerThread: Thread? = null

    @Volatile
    private var currentPolicy: AegisPolicy = AegisPolicy(emptySet(), emptySet())

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopVpnTunnel()
                stopSelf()
                return START_NOT_STICKY
            }
            else -> {
                val inlineJson = intent?.getStringExtra(EXTRA_POLICY_JSON)
                val policyPath = intent?.getStringExtra(EXTRA_POLICY_PATH)
                if (!inlineJson.isNullOrBlank()) {
                    currentPolicy = AegisPolicyLoader.fromJsonString(inlineJson)
                } else if (!policyPath.isNullOrBlank()) {
                    currentPolicy = AegisPolicyLoader.fromFile(File(policyPath))
                } else {
                    val defaultFile = File(filesDir, "aegis-policy.json")
                    if (defaultFile.exists()) {
                        currentPolicy = AegisPolicyLoader.fromFile(defaultFile)
                    }
                }

                startForeground(NOTIFICATION_ID, buildNotification())
                if (!running.get()) {
                    startVpnTunnel()
                }
                return START_STICKY
            }
        }
    }

    private fun startVpnTunnel() {
        val builder = Builder()
            .setSession("AEGIS AI Vigilante DNS")
            .addAddress("10.66.0.1", 32)
            .addDnsServer(VIRTUAL_DNS_IP)
            .addRoute(VIRTUAL_DNS_IP, 32)
            .setMtu(1400)

        // Evita loop de VPN quando o proprio app baixar listas ou consultar APIs
        try {
            builder.addDisallowedApplication(packageName)
        } catch (e: Exception) {
            Log.w(TAG, "Nao foi possivel excluir pacote proprio da VPN: \${e.message}")
        }

        val tun = builder.establish() ?: run {
            Log.e(TAG, "Falha ao estabelecer interface TUN do VpnService")
            return
        }

        vpnInterface = tun
        running.set(true)

        workerThread = Thread({
            runPacketLoop(tun)
        }, "AegisDnsLoopThread").apply {
            isDaemon = true
            start()
        }
    }

    private fun stopVpnTunnel() {
        running.set(false)
        workerThread?.interrupt()
        workerThread = null
        try {
            vpnInterface?.close()
        } catch (_: Exception) {
        }
        vpnInterface = null
    }

    override fun onDestroy() {
        stopVpnTunnel()
        super.onDestroy()
    }

    override fun onRevoke() {
        stopVpnTunnel()
        super.onRevoke()
    }

    private fun runPacketLoop(tun: ParcelFileDescriptor) {
        val inputStream = FileInputStream(tun.fileDescriptor)
        val outputStream = FileOutputStream(tun.fileDescriptor)
        val packetBuffer = ByteArray(32767)

        try {
            while (running.get() && !Thread.currentThread().isInterrupted) {
                val length = inputStream.read(packetBuffer)
                if (length <= 0) continue

                val packet = packetBuffer.copyOf(length)
                val dnsInfo = parseIpv4UdpDns(packet) ?: continue

                val qName = AegisPolicyLoader.normalizeDomain(dnsInfo.qName)
                val policy = currentPolicy

                val isAllowed = AegisPolicyLoader.matchesDomain(qName, policy.allowedDomains)
                val isBlocked = !isAllowed && AegisPolicyLoader.matchesDomain(qName, policy.blockedDomains)

                if (isBlocked) {
                    Log.i(TAG, "BLOQUEADO DNS: \$qName")
                    val nxResponse = buildDnsNxDomainReply(
                        requestPacket = packet,
                        dnsHeaderOffset = dnsInfo.dnsPayloadOffset,
                        dnsPayloadLength = dnsInfo.dnsPayloadLength
                    )
                    if (nxResponse != null) {
                        outputStream.write(nxResponse)
                    }
                } else {
                    val upstreamReply = forwardDnsQuery(
                        dnsPayload = packet.copyOfRange(
                            dnsInfo.dnsPayloadOffset,
                            dnsInfo.dnsPayloadOffset + dnsInfo.dnsPayloadLength
                        ),
                        upstreamIp = policy.dnsIp
                    )
                    if (upstreamReply != null) {
                        val ipReply = wrapIpv4UdpReply(
                            originalRequest = packet,
                            udpHeaderOffset = dnsInfo.udpHeaderOffset,
                            newPayload = upstreamReply
                        )
                        if (ipReply != null) {
                            outputStream.write(ipReply)
                        }
                    }
                }
            }
        } catch (e: Exception) {
            if (running.get()) {
                Log.e(TAG, "Loop do VpnService encerrado com erro: \${e.message}")
            }
        }
    }

    private fun forwardDnsQuery(dnsPayload: ByteArray, upstreamIp: String): ByteArray? {
        var socket: DatagramSocket? = null
        return try {
            socket = DatagramSocket()
            // Obrigatorio para o socket sair pela rede real sem passar de volta pela VPN
            protect(socket)
            socket.soTimeout = 2500

            val address = InetAddress.getByName(upstreamIp)
            val req = DatagramPacket(dnsPayload, dnsPayload.size, address, 53)
            socket.send(req)

            val respBuffer = ByteArray(4096)
            val resp = DatagramPacket(respBuffer, respBuffer.size)
            socket.receive(resp)
            respBuffer.copyOf(resp.length)
        } catch (_: Exception) {
            null
        } finally {
            socket?.close()
        }
    }

    private data class ParsedDnsPacket(
        val qName: String,
        val udpHeaderOffset: Int,
        val dnsPayloadOffset: Int,
        val dnsPayloadLength: Int
    )

    private fun parseIpv4UdpDns(packet: ByteArray): ParsedDnsPacket? {
        if (packet.size < 28) return null
        val version = (packet[0].toInt() ushr 4) and 0x0F
        if (version != 4) return null

        val ihl = (packet[0].toInt() and 0x0F) * 4
        if (ihl < 20 || packet.size < ihl + 8) return null

        val protocol = packet[9].toInt() and 0xFF
        if (protocol != 17) return null // UDP apenas

        val dstPort = ((packet[ihl + 2].toInt() and 0xFF) shl 8) or (packet[ihl + 3].toInt() and 0xFF)
        if (dstPort != 53) return null

        val udpLength = ((packet[ihl + 4].toInt() and 0xFF) shl 8) or (packet[ihl + 5].toInt() and 0xFF)
        val dnsOffset = ihl + 8
        val dnsLength = udpLength - 8
        if (dnsLength < 12 || dnsOffset + dnsLength > packet.size) return null

        val qName = extractDnsQuestionName(packet, dnsOffset, dnsOffset + dnsLength) ?: return null
        return ParsedDnsPacket(
            qName = qName,
            udpHeaderOffset = ihl,
            dnsPayloadOffset = dnsOffset,
            dnsPayloadLength = dnsLength
        )
    }

    private fun extractDnsQuestionName(buf: ByteArray, start: Int, end: Int): String? {
        var pos = start + 12 // pula cabecalho DNS de 12 bytes
        val labels = mutableListOf<String>()
        var jumps = 0

        while (pos < end) {
            val len = buf[pos].toInt() and 0xFF
            if (len == 0) {
                return if (labels.isNotEmpty()) labels.joinToString(".") else null
            }
            if ((len and 0xC0) == 0xC0) {
                if (pos + 1 >= end || jumps++ > 5) return null
                val ptr = (((len and 0x3F) shl 8) or (buf[pos + 1].toInt() and 0xFF))
                pos = start + ptr
                continue
            }
            pos += 1
            if (pos + len > end) return null
            labels.add(String(buf, pos, len, Charsets.US_ASCII))
            pos += len
        }
        return null
    }

    private fun buildDnsNxDomainReply(
        requestPacket: ByteArray,
        dnsHeaderOffset: Int,
        dnsPayloadLength: Int
    ): ByteArray? {
        if (dnsPayloadLength < 12 || dnsHeaderOffset + dnsPayloadLength > requestPacket.size) return null
        val dnsReply = requestPacket.copyOfRange(dnsHeaderOffset, dnsHeaderOffset + dnsPayloadLength)
        // QR = 1 (resposta), Opcode = 0, AA = 1, RD = 1, RA = 1, RCODE = 3 (NXDOMAIN)
        dnsReply[2] = 0x85.toByte()
        dnsReply[3] = 0x83.toByte()
        return wrapIpv4UdpReply(
            originalRequest = requestPacket,
            udpHeaderOffset = requestPacket[0].toInt().and(0x0F) * 4,
            newPayload = dnsReply
        )
    }

    private fun wrapIpv4UdpReply(
        originalRequest: ByteArray,
        udpHeaderOffset: Int,
        newPayload: ByteArray
    ): ByteArray? {
        if (udpHeaderOffset < 20 || originalRequest.size < udpHeaderOffset + 8) return null
        val totalLen = udpHeaderOffset + 8 + newPayload.size
        val out = ByteArray(totalLen)

        System.arraycopy(originalRequest, 0, out, 0, udpHeaderOffset)
        // Troca IP origem e IP destino
        System.arraycopy(originalRequest, 16, out, 12, 4)
        System.arraycopy(originalRequest, 12, out, 16, 4)

        out[2] = ((totalLen ushr 8) and 0xFF).toByte()
        out[3] = (totalLen and 0xFF).toByte()
        out[8] = 64 // TTL

        // Cabecalho UDP: inverte portas origem/destino (53 <-> porta original)
        out[udpHeaderOffset] = originalRequest[udpHeaderOffset + 2]
        out[udpHeaderOffset + 1] = originalRequest[udpHeaderOffset + 3]
        out[udpHeaderOffset + 2] = originalRequest[udpHeaderOffset]
        out[udpHeaderOffset + 3] = originalRequest[udpHeaderOffset + 1]

        val udpLen = 8 + newPayload.size
        out[udpHeaderOffset + 4] = ((udpLen ushr 8) and 0xFF).toByte()
        out[udpHeaderOffset + 5] = (udpLen and 0xFF).toByte()
        // Checksum UDP = 0 (valido em IPv4)
        out[udpHeaderOffset + 6] = 0
        out[udpHeaderOffset + 7] = 0

        System.arraycopy(newPayload, 0, out, udpHeaderOffset + 8, newPayload.size)

        // Recalcula checksum IPv4
        out[10] = 0
        out[11] = 0
        val ipChecksum = computeIpv4Checksum(out, udpHeaderOffset)
        out[10] = ((ipChecksum ushr 8) and 0xFF).toByte()
        out[11] = (ipChecksum and 0xFF).toByte()

        return out
    }

    private fun computeIpv4Checksum(header: ByteArray, length: Int): Int {
        var sum = 0L
        var i = 0
        while (i < length - 1) {
            val word = ((header[i].toInt() and 0xFF) shl 8) or (header[i + 1].toInt() and 0xFF)
            sum += word
            i += 2
        }
        if (i < length) {
            sum += ((header[i].toInt() and 0xFF) shl 8)
        }
        while ((sum shr 16) != 0L) {
            sum = (sum and 0xFFFFL) + (sum shr 16)
        }
        return sum.inv().toInt() and 0xFFFF
    }

    private fun buildNotification(): Notification {
        val manager = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "AEGIS AI Vigilância DNS",
                NotificationManager.IMPORTANCE_LOW
            )
            manager.createNotificationChannel(channel)
        }

        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }

        return builder
            .setContentTitle("AEGIS AI — Escudo DNS Ativo")
            .setContentText("Filtrando domínios bloqueados em tempo real (\${currentPolicy.blockedDomains.size} regras)")
            .setSmallIcon(android.R.drawable.ic_lock_idle_lock)
            .setOngoing(true)
            .build()
    }
}
`;

export const ANDROID_KOTLIN_VPNBRIDGE_CODE = `package com.hevertpereira.aegisai.vpn

import android.content.Context
import android.webkit.JavascriptInterface
import org.json.JSONObject
import java.io.File

class AegisVpnBridge(
    private val context: Context,
    private val onRequestStartVpn: (policyFile: File) -> Unit,
    private val onRequestStopVpn: () -> Unit,
    private val isVpnRunningProvider: () -> Boolean
) {

    companion object {
        const val POLICY_FILENAME = "aegis-policy.json"
    }

    private fun getPolicyFile(): File {
        return File(context.filesDir, POLICY_FILENAME)
    }

    /**
     * Salva a lista JSON exportada pelo AEGIS AI no armazenamento privado do app
     * e dispara o fluxo de permissão/inicialização do VpnService.
     */
    @JavascriptInterface
    fun startVpnWithPolicy(policyJson: String): String {
        return try {
            // Valida estrutura mínima do JSON antes de gravar
            val parsed = JSONObject(policyJson)
            if (!parsed.has("rules")) {
                return """{"ok":false,"error":"JSON inválido: campo 'rules' ausente."}"""
            }

            val targetFile = getPolicyFile()
            targetFile.writeText(policyJson, Charsets.UTF_8)

            onRequestStartVpn(targetFile)
            """{"ok":true,"pendingPermission":true}"""
        } catch (e: Exception) {
            """{"ok":false,"error":"\${e.message?.replace("\\"", "'") ?: "Erro ao processar JSON"}"}"""
        }
    }

    /**
     * Atualiza apenas o arquivo de políticas enquanto a VPN já está ativa.
     */
    @JavascriptInterface
    fun updatePolicyJson(policyJson: String): String {
        return try {
            val parsed = JSONObject(policyJson)
            if (!parsed.has("rules")) {
                return """{"ok":false,"error":"JSON inválido: campo 'rules' ausente."}"""
            }

            val targetFile = getPolicyFile()
            targetFile.writeText(policyJson, Charsets.UTF_8)

            if (isVpnRunningProvider()) {
                onRequestStartVpn(targetFile)
            }
            """{"ok":true,"updated":true}"""
        } catch (e: Exception) {
            """{"ok":false,"error":"\${e.message?.replace("\\"", "'") ?: "Erro ao atualizar JSON"}"}"""
        }
    }

    /**
     * Encerra o túnel VPN local.
     */
    @JavascriptInterface
    fun stopVpn(): String {
        return try {
            onRequestStopVpn()
            """{"ok":true,"running":false}"""
        } catch (e: Exception) {
            """{"ok":false,"error":"\${e.message?.replace("\\"", "'") ?: "Erro ao parar VPN"}"}"""
        }
    }

    /**
     * Retorna o estado atual do serviço para a interface web sincronizar os botões.
     */
    @JavascriptInterface
    fun getVpnStatus(): String {
        val file = getPolicyFile()
        val running = isVpnRunningProvider()
        return """{"running":$running,"hasPolicyFile":\${file.exists()}}"""
    }
}
`;

export const ANDROID_KOTLIN_MAINACTIVITY_CODE = `package com.hevertpereira.aegisai

import android.Manifest
import android.annotation.SuppressLint
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.webkit.WebChromeClient
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import com.hevertpereira.aegisai.vpn.AegisGuardVpnService
import com.hevertpereira.aegisai.vpn.AegisVpnBridge
import java.io.File

class MainActivity : ComponentActivity() {

    private lateinit var webView: WebView
    private var pendingPolicyFile: File? = null
    private var vpnRunningFlag = false

    // Launcher moderno para capturar a resposta do usuário ao diálogo de VPN do Android
    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            val file = pendingPolicyFile ?: File(filesDir, AegisVpnBridge.POLICY_FILENAME)
            launchAegisVpnService(file)
            notifyWebVpnState(running = true, permissionDenied = false)
        } else {
            vpnRunningFlag = false
            notifyWebVpnState(running = false, permissionDenied = true)
        }
    }

    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { _ -> }

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        webView = WebView(this).apply {
            settings.javaScriptEnabled = true
            settings.domStorageEnabled = true
            settings.databaseEnabled = true
            settings.allowFileAccess = true
            settings.cacheMode = WebSettings.LOAD_DEFAULT
            webViewClient = WebViewClient()
            webChromeClient = WebChromeClient()
        }

        val bridge = AegisVpnBridge(
            context = applicationContext,
            onRequestStartVpn = { policyFile ->
                runOnUiThread {
                    prepareAndStartVpn(policyFile)
                }
            },
            onRequestStopVpn = {
                runOnUiThread {
                    stopAegisVpnService()
                }
            },
            isVpnRunningProvider = { vpnRunningFlag }
        )

        webView.addJavascriptInterface(bridge, "AegisNativeVpn")
        setContentView(webView)

        requestNotificationPermissionIfNeeded()
        webView.loadUrl("file:///android_asset/index.html")
    }

    private fun requestNotificationPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val granted = ContextCompat.checkSelfPermission(
                this,
                Manifest.permission.POST_NOTIFICATIONS
            ) == PackageManager.PERMISSION_GRANTED
            if (!granted) {
                notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }
    }

    private fun prepareAndStartVpn(policyFile: File) {
        pendingPolicyFile = policyFile
        val prepIntent = VpnService.prepare(this)
        if (prepIntent != null) {
            vpnPermissionLauncher.launch(prepIntent)
        } else {
            launchAegisVpnService(policyFile)
            notifyWebVpnState(running = true, permissionDenied = false)
        }
    }

    private fun launchAegisVpnService(policyFile: File) {
        val intent = Intent(this, AegisGuardVpnService::class.java).apply {
            action = AegisGuardVpnService.ACTION_START
            putExtra(AegisGuardVpnService.EXTRA_POLICY_PATH, policyFile.absolutePath)
        }
        ContextCompat.startForegroundService(this, intent)
        vpnRunningFlag = true
    }

    private fun stopAegisVpnService() {
        val intent = Intent(this, AegisGuardVpnService::class.java).apply {
            action = AegisGuardVpnService.ACTION_STOP
        }
        startService(intent)
        vpnRunningFlag = false
        notifyWebVpnState(running = false, permissionDenied = false)
    }

    private fun notifyWebVpnState(running: Boolean, permissionDenied: Boolean) {
        if (!::webView.isInitialized) return
        val script = """
            window.dispatchEvent(new CustomEvent('aegis:native-vpn-state', {
                detail: { running: $running, permissionDenied: $permissionDenied }
            }));
        """.trimIndent()
        webView.post {
            webView.evaluateJavascript(script, null)
        }
    }
}
`;

export const ANDROID_MANIFEST_XML_CODE = `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:tools="http://schemas.android.com/tools">

    <!-- Acesso à rede para WebView, consultas DNS upstream e recursos externos -->
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />

    <!-- Serviço em primeiro plano para manter a vigilância DNS ativa -->
    <uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
    <uses-permission android:name="android.permission.FOREGROUND_SERVICE_SPECIAL_USE" />

    <!-- Notificação do serviço em primeiro plano no Android 13+ (API 33+) -->
    <uses-permission android:name="android.permission.POST_NOTIFICATIONS" />

    <!-- Evita que o Android exija hardware de telefonia em tablets/dispositivos sem rádio celular -->
    <uses-feature
        android:name="android.hardware.telephony"
        android:required="false" />

    <application
        android:allowBackup="true"
        android:icon="@mipmap/ic_launcher"
        android:label="AEGIS AI"
        android:roundIcon="@mipmap/ic_launcher_round"
        android:supportsRtl="true"
        android:theme="@android:style/Theme.DeviceDefault.NoActionBar"
        android:usesCleartextTraffic="false"
        tools:targetApi="34">

        <activity
            android:name=".MainActivity"
            android:configChanges="orientation|screenSize|screenLayout|keyboardHidden"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>

        <service
            android:name=".vpn.AegisGuardVpnService"
            android:exported="false"
            android:foregroundServiceType="specialUse"
            android:permission="android.permission.BIND_VPN_SERVICE">
            <intent-filter>
                <action android:name="android.net.VpnService" />
            </intent-filter>
            <property
                android:name="android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE"
                android:value="Local DNS filtering and network threat monitoring" />
        </service>

    </application>

</manifest>
`;

export const ANDROID_GRADLE_KTS_CODE = `plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.hevertpereira.aegisai"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.hevertpereira.aegisai"
        minSdk = 24
        targetSdk = 34
        versionCode = 1
        versionName = "2.4.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
        debug {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.activity:activity-ktx:1.9.3")
}
`;




