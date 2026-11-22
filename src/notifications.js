const ALERT_TITLE_BY_TYPE = {
  burst: 'AEGIS AI · Alerta Crítico: Rajada Anômala',
  bot_pattern: 'AEGIS AI · Alerta Crítico: Invasão de Bot IA',
  supply_chain: 'AEGIS AI · Alerta Crítico: Ataque Supply Chain',
  dns_hijack: 'AEGIS AI · Alerta Crítico: Sequestro de DNS Wi-Fi',
  webrtc_leak: 'AEGIS AI · Alerta Crítico: Vazamento WebRTC',
  rapid_refresh: 'AEGIS AI · Alerta Crítico: Refresh Suspeito',
};

export function urlBase64ToUint8Array(base64String) {
  const clean = String(base64String || '').trim();
  if (!clean) return null;
  const padding = '='.repeat((4 - (clean.length % 4)) % 4);
  const base64 = (clean + padding).replace(/-/g, '+').replace(/_/g, '/');
  const rawData = window.atob(base64);
  const outputArray = new Uint8Array(rawData.length);
  for (let i = 0; i < rawData.length; ++i) {
    outputArray[i] = rawData.charCodeAt(i);
  }
  return outputArray;
}

export class AegisPushManager {
  constructor(storage) {
    this.storage = storage;
    this._notifiedIds = new Set();
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

  getCapabilities() {
    const notificationApi = typeof window !== 'undefined' && 'Notification' in window;
    const serviceWorkerApi = typeof navigator !== 'undefined' && 'serviceWorker' in navigator;
    const pushManagerApi =
      typeof window !== 'undefined' && 'PushManager' in window && serviceWorkerApi;
    const isNativeAndroid = this.isNativeAndroid();
    const permission = notificationApi
      ? Notification.permission
      : isNativeAndroid
      ? 'granted'
      : 'unsupported';

    return {
      notificationApi,
      serviceWorkerApi,
      pushManagerApi,
      isNativeAndroid,
      permission,
      supported: notificationApi || isNativeAndroid,
    };
  }

  async getStatus() {
    const caps = this.getCapabilities();
    const [settings, savedSub] = await Promise.all([
      this.storage.getSettings(),
      this.storage.getPushSubscription(),
    ]);

    let activeBrowserSub = null;
    if (caps.pushManagerApi) {
      try {
        const reg = await navigator.serviceWorker.ready;
        activeBrowserSub = await reg.pushManager.getSubscription();
      } catch {
        activeBrowserSub = null;
      }
    }

    const endpoint =
      activeBrowserSub?.endpoint || savedSub?.subscription?.endpoint || '';
    const enabled =
      Boolean(settings.pushNotificationsEnabled) &&
      (caps.permission === 'granted' || caps.isNativeAndroid);

    let mode = 'disabled';
    if (enabled) {
      if (caps.isNativeAndroid) {
        mode = 'android_native_channel';
      } else if (endpoint) {
        mode = 'web_push_vapid';
      } else {
        mode = 'sw_local_push';
      }
    }

    return {
      ...caps,
      enabled,
      mode,
      vapidPublicKey: settings.vapidPublicKey || '',
      subscriptionEndpoint: endpoint,
      hasRemoteSubscription: Boolean(endpoint),
    };
  }

  async enable({ vapidPublicKey = '' } = {}) {
    const caps = this.getCapabilities();
    const cleanVapid = String(vapidPublicKey || '').trim();

    if (!caps.supported) {
      throw new Error('Este navegador não suporta notificações Web Push.');
    }

    let permission = caps.permission;
    if (caps.notificationApi && permission !== 'granted') {
      permission = await Notification.requestPermission();
    }

    if (permission === 'denied') {
      const current = await this.storage.getSettings();
      await this.storage.saveSettings({
        ...current,
        pushNotificationsEnabled: false,
      });
      throw new Error(
        'Permissão de notificações bloqueada no navegador. Libere nas configurações do site.'
      );
    }

    if (permission !== 'granted' && !caps.isNativeAndroid) {
      throw new Error('Permissão de notificações não concedida.');
    }

    if (caps.isNativeAndroid) {
      const plugin = this.getNativePlugin();
      try {
        await plugin?.startMonitoring?.({
          dnsLabel: '1.1.1.2 (DoH)',
          rulesCount: 19,
        });
      } catch {
        // Ignore if already granted/running
      }
    }

    let subscriptionJson = null;
    if (caps.pushManagerApi && cleanVapid) {
      try {
        const reg = await navigator.serviceWorker.ready;
        const existing = await reg.pushManager.getSubscription();
        if (existing) {
          subscriptionJson = existing.toJSON();
        } else {
          const applicationServerKey = urlBase64ToUint8Array(cleanVapid);
          if (applicationServerKey) {
            const sub = await reg.pushManager.subscribe({
              userVisibleOnly: true,
              applicationServerKey,
            });
            subscriptionJson = sub.toJSON();
          }
        }
      } catch (err) {
        throw new Error(
          `Chave VAPID inválida ou falha ao registrar PushManager: ${err?.message || 'erro'}`
        );
      }
    }

    const currentSettings = await this.storage.getSettings();
    await this.storage.saveSettings({
      ...currentSettings,
      pushNotificationsEnabled: true,
      vapidPublicKey: cleanVapid,
    });

    await this.storage.savePushSubscription({
      mode: subscriptionJson
        ? 'web_push_vapid'
        : caps.isNativeAndroid
        ? 'android_native_channel'
        : 'sw_local_push',
      vapidPublicKey: cleanVapid,
      subscription: subscriptionJson,
      subscribedAt: Date.now(),
    });

    return this.getStatus();
  }

  async disable() {
    const caps = this.getCapabilities();
    if (caps.pushManagerApi) {
      try {
        const reg = await navigator.serviceWorker.ready;
        const sub = await reg.pushManager.getSubscription();
        if (sub) {
          await sub.unsubscribe();
        }
      } catch {
        // Ignore unsubscribe error
      }
    }

    const currentSettings = await this.storage.getSettings();
    await this.storage.saveSettings({
      ...currentSettings,
      pushNotificationsEnabled: false,
    });
    await this.storage.savePushSubscription(null);
    return this.getStatus();
  }

  async notifyCriticalThreat({
    alertId = `push_${Date.now()}`,
    title = '',
    body = '',
    domain = '',
    type = 'bot_pattern',
    severity = 'critical',
    forceTest = false,
  }) {
    // Filtro estrito: Web Push dispara apenas para ameaças de nível Crítico
    if (!forceTest && String(severity || '').toLowerCase() !== 'critical') {
      return { sent: false, reason: 'severity_not_critical' };
    }

    if (!forceTest && this._notifiedIds.has(alertId)) {
      return { sent: false, reason: 'already_notified' };
    }

    const status = await this.getStatus();
    if (!forceTest && !status.enabled) {
      return { sent: false, reason: 'push_disabled' };
    }
    if (status.permission !== 'granted' && !status.isNativeAndroid) {
      return { sent: false, reason: 'permission_not_granted' };
    }

    if (!forceTest) {
      this._notifiedIds.add(alertId);
      if (this._notifiedIds.size > 150) {
        const first = this._notifiedIds.values().next().value;
        this._notifiedIds.delete(first);
      }
    }

    const notifTitle =
      title || ALERT_TITLE_BY_TYPE[type] || 'AEGIS AI · Ameaça Crítica Detectada';
    const notifBody =
      body ||
      `Origem: ${domain || 'Rede local'} · Ação imediata de contenção executada pelo motor heurístico.`;

    const payload = {
      alertId,
      title: notifTitle,
      body: notifBody,
      domain,
      type,
      severity: 'critical',
      tag: `aegis-critical-${alertId}`,
      timestamp: Date.now(),
      forceTest,
    };

    let delivered = false;

    // 1) Native Android High-Priority Channel (works even when app WebView is closed/killed)
    if (status.isNativeAndroid) {
      const plugin = this.getNativePlugin();
      if (plugin?.notifyCriticalThreat) {
        try {
          await plugin.notifyCriticalThreat({
            alertId: payload.alertId,
            title: payload.title,
            body: payload.body,
            domain: payload.domain || '',
            severity: 'critical',
          });
          delivered = true;
        } catch {
          // Fallback to Web Notification below
        }
      }
    }

    // 2) Service Worker persistent OS Notification (works in background / minimized browser)
    if (status.serviceWorkerApi && status.permission === 'granted') {
      try {
        const reg = await navigator.serviceWorker.ready;
        if (reg?.showNotification) {
          await reg.showNotification(payload.title, {
            body: payload.body,
            icon: './pwa-192x192.png',
            badge: './pwa-192x192.png',
            tag: payload.tag,
            renotify: true,
            requireInteraction: true,
            vibrate: [240, 120, 240, 120, 360],
            data: {
              url: './',
              screen: 'logs',
              alertId: payload.alertId,
              domain: payload.domain,
              severity: 'critical',
            },
            actions: [
              { action: 'inspect', title: 'Inspecionar Ameaça' },
              { action: 'acknowledge', title: 'Confirmar Ciência' },
            ],
          });
          delivered = true;
        }
      } catch {
        // Fallback to controller postMessage / Window Notification
      }
    }

    // 3) Window Notification fallback if SW unavailable
    if (!delivered && status.notificationApi && status.permission === 'granted') {
      try {
        const n = new Notification(payload.title, {
          body: payload.body,
          icon: './pwa-192x192.png',
          tag: payload.tag,
          requireInteraction: true,
        });
        n.onclick = () => {
          try {
            window.focus();
          } catch {
            // ignore
          }
          n.close();
        };
        delivered = true;
      } catch {
        delivered = false;
      }
    }

    return { sent: delivered, mode: status.mode, alertId };
  }

  async notifyCriticalFromAlerts(alerts = [], settings = null) {
    const activeSettings = settings || (await this.storage.getSettings());
    if (!activeSettings?.vpnActive || !activeSettings?.pushNotificationsEnabled) {
      return 0;
    }

    let sentCount = 0;
    for (const alert of alerts) {
      if (
        !alert ||
        String(alert.severity || '').toLowerCase() !== 'critical' ||
        alert.resolved ||
        alert.acknowledged ||
        alert.pushNotifiedAt
      ) {
        continue;
      }

      const res = await this.notifyCriticalThreat({
        alertId: alert.id,
        domain: alert.domain,
        type: alert.type,
        severity: alert.severity,
        body: `${alert.domain}: ${alert.description}`,
      });

      if (res.sent) {
        alert.pushNotifiedAt = Date.now();
        await this.storage.put('alerts', alert);
        sentCount += 1;
      }
    }
    return sentCount;
  }
}
