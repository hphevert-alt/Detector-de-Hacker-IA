export function getBuildVersion() {
  return typeof __AEGIS_BUILD_VERSION__ !== 'undefined'
    ? __AEGIS_BUILD_VERSION__
    : 'v2.4.0-dev';
}

export function isRunningStandalone() {
  if (typeof window === 'undefined') return false;
  const nav = /** @type {Navigator & { standalone?: boolean }} */ (window.navigator);
  const win = /** @type {Window & { Capacitor?: { isNativePlatform?: () => boolean } }} */ (window);
  return (
    Boolean(win.Capacitor?.isNativePlatform?.()) ||
    window.matchMedia('(display-mode: standalone)').matches ||
    nav.standalone === true ||
    document.referrer.startsWith('android-app://')
  );
}

export function initPwaSupport(getAppInstance) {
  const versionEl = document.getElementById('app-build-version');
  if (versionEl) {
    versionEl.textContent = `Build ${getBuildVersion()}`;
  }

  // 1) Service Worker com caminhos relativos compatíveis com GitHub Pages
  if ('serviceWorker' in navigator) {
    const hadController = Boolean(navigator.serviceWorker.controller);
    let refreshing = false;

    navigator.serviceWorker.addEventListener('controllerchange', () => {
      if (!hadController || refreshing) return;
      refreshing = true;
      window.location.reload();
    });

    navigator.serviceWorker
      .register('./sw.js', { scope: './', updateViaCache: 'none' })
      .then((registration) => {
        registration.addEventListener('updatefound', () => {
          const newWorker = registration.installing;
          if (!newWorker) return;
          newWorker.addEventListener('statechange', () => {
            if (newWorker.state === 'installed' && navigator.serviceWorker.controller) {
              const app = getAppInstance?.();
              app?.showToast(
                'Nova versão do AEGIS AI baixada. Atualizando cache automaticamente...',
                'info'
              );
              newWorker.postMessage({ type: 'SKIP_WAITING' });
            }
          });
        });

        document.addEventListener('visibilitychange', () => {
          if (document.visibilityState === 'visible') {
            registration.update().catch(() => {});
          }
        });

        window.setInterval(() => {
          registration.update().catch(() => {});
        }, 30 * 60 * 1000);
      })
      .catch(() => {
        // Ignora erro de registro caso o ambiente bloqueie Service Workers
      });
  }

  // 2) Card guiado de instalação no smartphone Android
  const cardEl = document.getElementById('pwa-install-card');
  const installBtn = document.getElementById('pwa-install-btn');
  const guideEl = document.getElementById('pwa-manual-guide');
  const dismissBtn = document.getElementById('pwa-install-dismiss-btn');

  if (!cardEl) return;

  /** @type {any} */
  let deferredPrompt = null;
  let dismissed = false;
  let justInstalled = false;

  const syncInstallCard = () => {
    const installed = isRunningStandalone() || justInstalled;
    if (installed || dismissed) {
      cardEl.hidden = true;
      return;
    }

    cardEl.hidden = false;
    if (guideEl) {
      guideEl.hidden = Boolean(deferredPrompt);
    }
  };

  syncInstallCard();

  window.addEventListener('beforeinstallprompt', (event) => {
    event.preventDefault();
    deferredPrompt = event;
    syncInstallCard();
  });

  window.addEventListener('appinstalled', () => {
    deferredPrompt = null;
    justInstalled = true;
    syncInstallCard();
    getAppInstance?.()?.showToast(
      'AEGIS AI instalado com sucesso na tela inicial!',
      'success'
    );
  });

  const standaloneMedia = window.matchMedia('(display-mode: standalone)');
  standaloneMedia.addEventListener?.('change', syncInstallCard);

  installBtn?.addEventListener('click', async () => {
    if (deferredPrompt) {
      deferredPrompt.prompt();
      const choice = await deferredPrompt.userChoice;
      if (choice?.outcome === 'accepted') {
        justInstalled = true;
      }
      deferredPrompt = null;
      syncInstallCard();
      return;
    }

    if (guideEl) {
      guideEl.hidden = false;
      guideEl.classList.remove('is-highlighted');
      void guideEl.offsetWidth;
      guideEl.classList.add('is-highlighted');
      window.setTimeout(() => guideEl.classList.remove('is-highlighted'), 2200);
    }

    getAppInstance?.()?.showToast(
      'Siga os 2 passos no menu ⋮ do Chrome para instalar o aplicativo.',
      'info'
    );
  });

  dismissBtn?.addEventListener('click', () => {
    dismissed = true;
    syncInstallCard();
  });
}
