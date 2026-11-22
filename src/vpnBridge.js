function safeParseJson(raw) {
  if (raw && typeof raw === 'object') return raw;
  if (typeof raw !== 'string' || !raw.trim()) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function hasBridgeMethods(candidate) {
  return Boolean(
    candidate &&
      typeof candidate.startVpnWithPolicy === 'function' &&
      typeof candidate.stopVpn === 'function' &&
      typeof candidate.getVpnStatus === 'function'
  );
}

export function getNativeVpnBridge() {
  if (typeof window === 'undefined') return null;
  const win = /** @type {any} */ (window);
  if (hasBridgeMethods(win.AegisNativeVpn)) {
    return win.AegisNativeVpn;
  }
  if (hasBridgeMethods(win.AegisVpnBridge)) {
    return win.AegisVpnBridge;
  }
  return null;
}

export function getNativeVpnBridgeName() {
  if (typeof window === 'undefined') return 'AegisNativeVpn';
  const win = /** @type {any} */ (window);
  if (hasBridgeMethods(win.AegisNativeVpn)) return 'AegisNativeVpn';
  if (hasBridgeMethods(win.AegisVpnBridge)) return 'AegisVpnBridge';
  return 'AegisNativeVpn';
}

export function getAndroidVpnBridgeStatus() {
  const bridge = getNativeVpnBridge();
  const bridgeName = getNativeVpnBridgeName();
  if (!bridge) {
    return {
      available: false,
      bridgeName: null,
      running: false,
      hasPolicyFile: false,
    };
  }
  try {
    const parsed = safeParseJson(bridge.getVpnStatus());
    return {
      available: true,
      bridgeName,
      running: Boolean(parsed?.running),
      hasPolicyFile: Boolean(parsed?.hasPolicyFile),
    };
  } catch (err) {
    return {
      available: true,
      bridgeName,
      running: false,
      hasPolicyFile: false,
      error: err?.message || `Falha ao consultar ${bridgeName}.getVpnStatus()`,
    };
  }
}

export function startNativeVpnWithPolicy(policyJson) {
  const bridge = getNativeVpnBridge();
  const bridgeName = getNativeVpnBridgeName();
  if (!bridge) {
    return { available: false, ok: false, error: 'Bridge Android não detectada neste navegador.' };
  }
  try {
    const parsed = safeParseJson(bridge.startVpnWithPolicy(policyJson));
    return {
      available: true,
      bridgeName,
      ok: Boolean(parsed?.ok),
      pendingPermission: Boolean(parsed?.pendingPermission),
      error: parsed?.error || null,
    };
  } catch (err) {
    return {
      available: true,
      bridgeName,
      ok: false,
      error: err?.message || `Erro ao chamar ${bridgeName}.startVpnWithPolicy()`,
    };
  }
}

export function updateNativeVpnPolicy(policyJson) {
  const bridge = getNativeVpnBridge();
  const bridgeName = getNativeVpnBridgeName();
  if (!bridge || typeof bridge.updatePolicyJson !== 'function') {
    return { available: false, ok: false };
  }
  try {
    const parsed = safeParseJson(bridge.updatePolicyJson(policyJson));
    return {
      available: true,
      bridgeName,
      ok: Boolean(parsed?.ok),
      updated: Boolean(parsed?.updated),
      error: parsed?.error || null,
    };
  } catch (err) {
    return {
      available: true,
      bridgeName,
      ok: false,
      error: err?.message || `Erro ao chamar ${bridgeName}.updatePolicyJson()`,
    };
  }
}

export function stopNativeVpn() {
  const bridge = getNativeVpnBridge();
  const bridgeName = getNativeVpnBridgeName();
  if (!bridge) {
    return { available: false, ok: false };
  }
  try {
    const parsed = safeParseJson(bridge.stopVpn());
    return {
      available: true,
      bridgeName,
      ok: Boolean(parsed?.ok),
      running: Boolean(parsed?.running),
      error: parsed?.error || null,
    };
  } catch (err) {
    return {
      available: true,
      bridgeName,
      ok: false,
      error: err?.message || `Erro ao chamar ${bridgeName}.stopVpn()`,
    };
  }
}
