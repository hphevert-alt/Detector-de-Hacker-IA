const CACHE_VERSION = '2.4.0-dev';
const CACHE_NAME = `aegis-ai-cache-${CACHE_VERSION}`;

const CORE_ASSETS = [
  './',
  './index.html',
  './manifest.json',
  './icon.svg',
  './pwa-192x192.png',
  './pwa-512x512.png',
  './pwa-maskable-512x512.png',
  './apple-touch-icon.png',
];

const BUILD_ASSETS = [];

self.addEventListener('install', (event) => {
  const assetsToCache = Array.from(new Set([...CORE_ASSETS, ...BUILD_ASSETS]));
  event.waitUntil(
    caches
      .open(CACHE_NAME)
      .then((cache) =>
        Promise.allSettled(
          assetsToCache.map((url) =>
            cache.add(new Request(url, { cache: 'reload' }))
          )
        )
      )
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) =>
        Promise.all(
          keys
            .filter((key) => key !== CACHE_NAME)
            .map((oldKey) => caches.delete(oldKey))
        )
      )
      .then(() => self.clients.claim())
  );
});

const DB_NAME = 'AegisAI_Vigilante_DB';
const DB_VERSION = 2;

function showCriticalPushNotification(payload = {}) {
  const severity = String(payload.severity || 'critical').toLowerCase();
  if (severity !== 'critical' && !payload.forceTest) {
    return Promise.resolve(false);
  }
  const title =
    payload.title ||
    (payload.domain
      ? `AEGIS AI · Ameaça Crítica: ${payload.domain}`
      : 'AEGIS AI · Ameaça Crítica Detectada');
  const body =
    payload.body ||
    payload.description ||
    'O motor heurístico detectou uma ameaça de nível Crítico em sua rede.';
  const alertId = payload.alertId || `sw_push_${Date.now()}`;

  return self.registration
    .showNotification(title, {
      body,
      icon: './pwa-192x192.png',
      badge: './pwa-192x192.png',
      tag: payload.tag || `aegis-critical-${alertId}`,
      renotify: true,
      requireInteraction: true,
      vibrate: [240, 120, 240, 120, 360],
      data: {
        url: payload.url || './',
        screen: 'logs',
        alertId,
        domain: payload.domain || '',
        severity: 'critical',
      },
      actions: [
        { action: 'inspect', title: 'Inspecionar Ameaça' },
        { action: 'acknowledge', title: 'Confirmar Ciência' },
      ],
    })
    .then(() => true)
    .catch(() => false);
}

function acknowledgeAlertInIndexedDb(alertId) {
  if (!alertId || typeof indexedDB === 'undefined') {
    return Promise.resolve(false);
  }
  return new Promise((resolve) => {
    try {
      const req = indexedDB.open(DB_NAME, DB_VERSION);
      req.onerror = () => resolve(false);
      req.onsuccess = () => {
        const db = req.result;
        try {
          if (!db.objectStoreNames.contains('alerts')) {
            db.close();
            resolve(false);
            return;
          }
          const tx = db.transaction(['alerts'], 'readwrite');
          const store = tx.objectStore('alerts');
          const getReq = store.get(alertId);
          getReq.onsuccess = () => {
            const existing = getReq.result;
            if (existing) {
              existing.acknowledged = true;
              existing.acknowledgedAt = Date.now();
              store.put(existing);
            }
          };
          tx.oncomplete = () => {
            db.close();
            resolve(true);
          };
          tx.onerror = () => {
            db.close();
            resolve(false);
          };
        } catch {
          db.close();
          resolve(false);
        }
      };
    } catch {
      resolve(false);
    }
  });
}

function touchAegisIndexedDb(payload = {}) {
  if (typeof indexedDB === 'undefined') {
    return Promise.resolve(false);
  }
  const pendingNotifications = [];

  return new Promise((resolve) => {
    try {
      const req = indexedDB.open(DB_NAME, DB_VERSION);
      req.onerror = () => resolve(false);
      req.onsuccess = () => {
        const db = req.result;
        try {
          if (!db.objectStoreNames.contains('settings')) {
            db.close();
            resolve(false);
            return;
          }
          const storeNames = ['settings'];
          if (db.objectStoreNames.contains('logs')) storeNames.push('logs');
          if (db.objectStoreNames.contains('alerts')) storeNames.push('alerts');

          const tx = db.transaction(storeNames, 'readwrite');
          const settingsStore = tx.objectStore('settings');
          const getReq = settingsStore.get('bg_cyclic_counter');
          const cfgReq = settingsStore.get('config');
          let configVal = null;

          cfgReq.onsuccess = () => {
            configVal = cfgReq.result || null;
          };

          getReq.onsuccess = () => {
            const existing = getReq.result || { key: 'bg_cyclic_counter', cycleCount: 0 };
            const now = Date.now();
            settingsStore.put({
              ...existing,
              key: 'bg_cyclic_counter',
              swSyncCount: (existing.swSyncCount || 0) + 1,
              swLastTouchAt: now,
              swSource: payload.source || 'sw_message',
              visibilityState: payload.visibilityState || existing.visibilityState || 'hidden',
              ...(payload.lastPushAt ? { lastPushAt: payload.lastPushAt } : {}),
              updatedAt: now,
            });
          };

          if (storeNames.includes('logs')) {
            const logsStore = tx.objectStore('logs');
            const logsReq = logsStore.getAll();
            logsReq.onsuccess = () => {
              const allLogs = logsReq.result || [];
              if (allLogs.length > 300) {
                allLogs.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
                for (let i = 300; i < allLogs.length; i++) {
                  if (allLogs[i]?.id) {
                    logsStore.delete(allLogs[i].id);
                  }
                }
              }
            };
          }

          if (storeNames.includes('alerts')) {
            const alertsStore = tx.objectStore('alerts');
            const alertsReq = alertsStore.getAll();
            alertsReq.onsuccess = () => {
              const canNotify =
                configVal?.vpnActive !== false && Boolean(configVal?.pushNotificationsEnabled);
              if (!canNotify) return;
              const now = Date.now();
              const allAlerts = alertsReq.result || [];
              for (const alert of allAlerts) {
                if (
                  alert &&
                  String(alert.severity || '').toLowerCase() === 'critical' &&
                  !alert.resolved &&
                  !alert.acknowledged &&
                  !alert.pushNotifiedAt
                ) {
                  alert.pushNotifiedAt = now;
                  alertsStore.put(alert);
                  pendingNotifications.push({
                    alertId: alert.id,
                    domain: alert.domain,
                    severity: 'critical',
                    body: `${alert.domain}: ${alert.description}`,
                  });
                }
              }
            };
          }

          tx.oncomplete = () => {
            db.close();
            if (pendingNotifications.length > 0) {
              Promise.allSettled(
                pendingNotifications.map((item) => showCriticalPushNotification(item))
              ).then(() => resolve(true));
            } else {
              resolve(true);
            }
          };
          tx.onerror = () => {
            db.close();
            resolve(false);
          };
        } catch {
          db.close();
          resolve(false);
        }
      };
    } catch {
      resolve(false);
    }
  });
}

self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
    return;
  }
  if (event.data && event.data.type === 'AEGIS_SW_HEARTBEAT') {
    event.waitUntil(
      touchAegisIndexedDb({
        source: event.data.source || 'visibility_heartbeat',
        visibilityState: event.data.visibilityState || 'hidden',
      })
    );
    return;
  }
  if (event.data && event.data.type === 'AEGIS_CRITICAL_ALERT_NOTIFY') {
    event.waitUntil(showCriticalPushNotification(event.data.payload || {}));
  }
});

self.addEventListener('push', (event) => {
  let payload = {};
  if (event.data) {
    try {
      payload = event.data.json();
    } catch {
      payload = {
        severity: 'critical',
        title: 'AEGIS AI · Ameaça Crítica Detectada',
        body: event.data.text(),
      };
    }
  } else {
    payload = {
      severity: 'critical',
      title: 'AEGIS AI · Alerta Crítico de Rede',
      body: 'Uma ameaça crítica foi interceptada em segundo plano pelo motor heurístico.',
    };
  }

  // Filtro estrito para notificações Web Push: apenas severidade Crítica
  const sev = String(payload.severity || 'critical').toLowerCase();
  if (sev !== 'critical' && !payload.forceTest) {
    return;
  }

  event.waitUntil(
    Promise.all([
      showCriticalPushNotification(payload),
      touchAegisIndexedDb({
        source: 'web_push_event',
        visibilityState: 'hidden',
        lastPushAt: Date.now(),
      }),
    ])
  );
});

self.addEventListener('notificationclick', (event) => {
  const data = event.notification?.data || {};
  event.notification.close();

  if (event.action === 'acknowledge') {
    event.waitUntil(acknowledgeAlertInIndexedDb(data.alertId));
    return;
  }

  const targetUrl = `./?screen=${encodeURIComponent(data.screen || 'logs')}${
    data.alertId ? `&alert=${encodeURIComponent(data.alertId)}` : ''
  }`;

  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clientList) => {
      for (const client of clientList) {
        if ('focus' in client) {
          client.postMessage({
            type: 'AEGIS_OPEN_THREAT',
            screen: data.screen || 'logs',
            alertId: data.alertId || null,
            domain: data.domain || null,
          });
          return client.focus();
        }
      }
      if (self.clients.openWindow) {
        return self.clients.openWindow(targetUrl);
      }
      return undefined;
    })
  );
});

self.addEventListener('pushsubscriptionchange', (event) => {
  event.waitUntil(
    (async () => {
      try {
        const oldOptions = event.oldSubscription?.options;
        if (oldOptions?.applicationServerKey && self.registration?.pushManager) {
          const newSub = await self.registration.pushManager.subscribe({
            userVisibleOnly: true,
            applicationServerKey: oldOptions.applicationServerKey,
          });
          const jsonSub = newSub.toJSON();
          const req = indexedDB.open(DB_NAME, DB_VERSION);
          req.onsuccess = () => {
            const db = req.result;
            try {
              const tx = db.transaction(['settings'], 'readwrite');
              const store = tx.objectStore('settings');
              store.put({
                key: 'push_subscription',
                mode: 'web_push_vapid',
                subscription: jsonSub,
                updatedAt: Date.now(),
              });
              tx.oncomplete = () => db.close();
            } catch {
              db.close();
            }
          };
        }
      } catch {
        // Ignore re-subscription errors when applicationServerKey is unavailable
      }
    })()
  );
});

self.addEventListener('sync', (event) => {
  if (event.tag === 'aegis-idb-sync') {
    event.waitUntil(
      touchAegisIndexedDb({ source: 'background_sync', visibilityState: 'hidden' })
    );
  }
});

self.addEventListener('periodicsync', (event) => {
  if (event.tag === 'aegis-idb-keepalive') {
    event.waitUntil(
      touchAegisIndexedDb({ source: 'periodic_sync', visibilityState: 'hidden' })
    );
  }
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;

  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;

  // Never intercept service worker script or APK installer binary downloads
  if (
    url.pathname.endsWith('/sw.js') ||
    url.pathname === 'sw.js' ||
    url.pathname.endsWith('.apk')
  ) {
    return;
  }

  // Navigation requests (HTML shell): Network-First with offline fallback
  if (req.mode === 'navigate') {
    event.respondWith(
      fetch(req)
        .then((res) => {
          if (res && res.ok) {
            const copy = res.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put('./index.html', copy));
          }
          return res;
        })
        .catch(() =>
          caches.match('./index.html').then((cached) => cached || caches.match('./'))
        )
    );
    return;
  }

  // Hashed build assets under ./assets/ can be Cache-First with network update
  if (url.pathname.includes('/assets/')) {
    event.respondWith(
      caches.match(req).then((cached) => {
        if (cached) return cached;
        return fetch(req).then((res) => {
          if (res && res.ok) {
            const copy = res.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(req, copy));
          }
          return res;
        });
      })
    );
    return;
  }

  // Manifest, icons, and non-hashed files: Network-First for instant GitHub Pages updates
  event.respondWith(
    fetch(req)
      .then((res) => {
        if (res && res.ok) {
          const copy = res.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(req, copy));
        }
        return res;
      })
      .catch(() => caches.match(req))
  );
});
