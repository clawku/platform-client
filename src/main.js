class ClientConnection {
  ws = null;
  cfg;
  heartbeatTimer = null;
  native = false;
  nativeUnlisten = [];
  reconnectTimer = null;
  reconnectAttempts = 0;
  shouldReconnect = true;

  constructor(cfg) {
    this.cfg = cfg;
  }

  connect() {
    this.shouldReconnect = true;
    this.reconnectAttempts = 0;
    if (this.cfg.native && this.cfg.native.start) {
      this.native = true;
      this.connectNative();
      return;
    }
    const url = `${this.cfg.wsUrl}?token=${encodeURIComponent(this.cfg.deviceToken)}`;
    this.ws = new WebSocket(url);

    this.ws.onopen = () => {
      const hello = {
        deviceId: this.cfg.deviceId,
        platform: this.cfg.platform,
        version: this.cfg.version,
      };
      this.send('device.hello', hello);
      this.startHeartbeat();
    };

    this.ws.onmessage = (evt) => {
      try {
        const msg = JSON.parse(String(evt.data));
        this.onMessage(msg);
      } catch {
        // ignore malformed
      }
    };

    this.ws.onclose = () => {
      this.stopHeartbeat();
      this.scheduleReconnect();
    };
  }

  async connectNative() {
    // Clean up any existing listeners before creating new ones
    for (const unlisten of this.nativeUnlisten) {
      try { unlisten(); } catch {}
    }
    this.nativeUnlisten = [];

    const tauriApi = window.__TAURI__;
    const invoke = tauriApi?.core?.invoke || tauriApi?.invoke;
    const eventApi = tauriApi?.event;
    if (!invoke || !eventApi) {
      logLine(`Native WS not available (tauri=${!!tauriApi} core=${!!invoke} event=${!!eventApi})`);
      return;
    }
    try {
      await invoke('start_mtls_ws', {
        wsUrl: this.cfg.wsUrl,
        deviceToken: this.cfg.deviceToken,
        serverCertPem: this.cfg.native.serverCertPem,
        serverCaPem: this.cfg.native.serverCaPem,
      });
      const unlistenMessage = await eventApi.listen('device_ws_message', (event) => {
        logLine(`[WS] Received: ${String(event.payload || '').slice(0, 100)}...`);
        try {
          const msg = JSON.parse(String(event.payload || ''));
          this.onMessage(msg);
        } catch (e) {
          logLine(`[WS] Parse error: ${e}`);
        }
      });
      logLine('[WS] Event listeners attached');
      const unlistenError = await eventApi.listen('device_ws_error', (event) => {
        logLine(`Device WS error: ${event.payload}`);
        this.stopHeartbeat();
        this.scheduleReconnect();
      });
      const unlistenClosed = await eventApi.listen('device_ws_closed', () => {
        this.stopHeartbeat();
        this.scheduleReconnect();
      });
      this.nativeUnlisten = [unlistenMessage, unlistenError, unlistenClosed];
      this.startHeartbeat();
    } catch (err) {
      logLine(`Native WS failed: ${err instanceof Error ? err.message : String(err)}`);
      this.scheduleReconnect();
    }
  }

  send(type, payload) {
    const message = JSON.stringify({ type, payload });
    if (this.native) {
      const invoke = window.__TAURI__?.core?.invoke || window.__TAURI__?.invoke;
      if (invoke) {
        invoke('send_device_ws', { message })
          .then(() => logLine(`[WS] Sent: ${type}`))
          .catch((err) => logLine(`[WS] Send failed: ${type} - ${err}`));
      }
      return;
    }
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return;
    this.ws.send(message);
  }

  // Hook for app-level handling
  onJobEnqueue(_job) {}
  onJobUpload(_job) {}

  startHeartbeat() {
    if (this.heartbeatTimer) return;
    this.heartbeatTimer = setInterval(() => {
      void this.sendHeartbeat();
    }, 30_000);
  }

  stopHeartbeat() {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
    for (const unlisten of this.nativeUnlisten) {
      try { unlisten(); } catch {}
    }
    this.nativeUnlisten = [];
    if (this.native) {
      const invoke = window.__TAURI__?.core?.invoke || window.__TAURI__?.invoke;
      if (invoke) {
        void invoke('stop_mtls_ws', {});
      }
    }
  }

  scheduleReconnect() {
    if (!this.shouldReconnect) return;
    if (this.reconnectTimer) return;
    const delay = Math.min(30_000, 1_000 * Math.pow(2, this.reconnectAttempts));
    this.reconnectAttempts += 1;
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      if (this.native) {
        this.connectNative();
      } else {
        this.connect();
      }
    }, delay);
  }

  stop() {
    this.shouldReconnect = false;
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    this.stopHeartbeat();
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.close();
    }
  }

  async sendHeartbeat() {
    try {
      await fetch(`${this.cfg.apiBaseUrl}/devices/heartbeat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          deviceId: this.cfg.deviceId,
          deviceToken: this.cfg.deviceToken,
        }),
      });
    } catch {
      // Heartbeat failures are non-fatal; device will try again.
    }
  }

  onMessage(msg) {
    if (!msg?.type) return;
    if (msg.type === 'job.enqueue') {
      this.onJobEnqueue(msg.payload);
    } else if (msg.type === 'job.upload') {
      this.onJobUpload(msg.payload);
    }
  }
}

const els = {
  // Auth elements
  authCard: document.getElementById('authCard'),
  loginEmail: document.getElementById('loginEmail'),
  loginPassword: document.getElementById('loginPassword'),
  loginButton: document.getElementById('loginButton'),
  loginStatus: document.getElementById('loginStatus'),
  openRegister: document.getElementById('openRegister'),
  authLogOutput: document.getElementById('authLogOutput'),

  // Header & Navigation
  mainHeader: document.getElementById('mainHeader'),
  clientStatus: document.getElementById('clientStatus'),

  // Main app container
  appMain: document.getElementById('appMain'),

  // Dashboard page
  pageDashboard: document.getElementById('pageDashboard'),
  deviceIdDisplay: document.getElementById('deviceIdDisplay'),
  deviceNameDisplay: document.getElementById('deviceNameDisplay'),
  // Pairing views
  pairedView: document.getElementById('pairedView'),
  unpairView: document.getElementById('unpairView'),
  showRepairBtn: document.getElementById('showRepairBtn'),
  connectClient: document.getElementById('connectClient'),
  // Unpaired elements
  deviceName: document.getElementById('deviceName'),
  pairingBox: document.getElementById('pairingBox'),
  pairingCode: document.getElementById('pairingCode'),
  pairingCodeInput: document.getElementById('pairingCodeInput'),
  pairingStatus: document.getElementById('pairingStatus'),
  startPairing: document.getElementById('startPairing'),
  finishPairing: document.getElementById('finishPairing'),
  // Jobs
  jobs: document.getElementById('jobs'),
  jobsEmpty: document.getElementById('jobsEmpty'),
  jobCount: document.getElementById('jobCount'),
  logOutput: document.getElementById('logOutput'),
  clearLogs: document.getElementById('clearLogs'),

  // Settings page
  pageSettings: document.getElementById('pageSettings'),
  profileAvatar: document.getElementById('profileAvatar'),
  profileName: document.getElementById('profileName'),
  profileEmail: document.getElementById('profileEmail'),
  logoutButton: document.getElementById('logoutButton'),
  settingsDeviceId: document.getElementById('settingsDeviceId'),
  settingsConnectionStatus: document.getElementById('settingsConnectionStatus'),
  toggleAutoApprove: document.getElementById('toggleAutoApprove'),
  toggleNotifications: document.getElementById('toggleNotifications'),
  toggleDebug: document.getElementById('toggleDebug'),
  logsCard: document.getElementById('logsCard'),
  enableAutostart: document.getElementById('enableAutostart'),
  disableAutostart: document.getElementById('disableAutostart'),
  clearPairing: document.getElementById('clearPairing'),
  exportPolicy: document.getElementById('exportPolicy'),

  // Update elements
  currentVersion: document.getElementById('currentVersion'),
  updateStatus: document.getElementById('updateStatus'),
  checkUpdates: document.getElementById('checkUpdates'),
  installUpdate: document.getElementById('installUpdate'),
  updateMessage: document.getElementById('updateMessage'),
  updateProgress: document.getElementById('updateProgress'),
  updateProgressBar: document.getElementById('updateProgressBar'),
  updateProgressText: document.getElementById('updateProgressText'),

  // About elements
  aboutVersion: document.getElementById('aboutVersion'),
  viewLicense: document.getElementById('viewLicense'),
  viewSourceCode: document.getElementById('viewSourceCode'),
  licenseModal: document.getElementById('licenseModal'),
  closeLicenseModal: document.getElementById('closeLicenseModal'),
  licenseText: document.getElementById('licenseText'),
};

const storage = {
  get: (key, fallback = '') => localStorage.getItem(key) || fallback,
  set: (key, value) => localStorage.setItem(key, value),
};

const autoApproveStored = localStorage.getItem('clawku.autoApprove');
if (autoApproveStored === null) {
  localStorage.setItem('clawku.autoApprove', 'true');
}

// Production vs Development API configuration
const PROD_API_BASE = 'https://api.b.clawku.id';
const PROD_WS_BASE = 'wss://api.b.clawku.id';
const DEV_API_BASES = ['http://localhost:3000', 'http://127.0.0.1:3000'];

// Set by detectBuildMode() in init() - defaults to release (production) for safety
let IS_DEBUG_BUILD = false;
const WEB_BASE_URL = 'http://localhost';

// Returns API candidates based on build mode - dev tries localhost first, release goes straight to prod
function getApiCandidates() {
  return IS_DEBUG_BUILD ? [...DEV_API_BASES, PROD_API_BASE] : [PROD_API_BASE];
}

const state = {
  deviceToken: '',
  deviceId: storage.get('clawku.deviceId', ''),
  deviceName: storage.get('clawku.deviceName', ''),
  devicePolicyJson: storage.get('clawku.devicePolicyJson', ''),
  devicePolicySig: storage.get('clawku.devicePolicySig', ''),
  pendingJobs: [],
  pairingCode: '',
  client: null,
  user: null,
  apiBaseUrl: PROD_API_BASE, // Will be set by resolveApiBaseUrl() based on detected build mode
  wsUrl: `${PROD_WS_BASE}/devices/ws`, // Will be set by resolveApiBaseUrl()
  apiReady: false,
  // Settings
  autoApprove: storage.get('clawku.autoApprove', 'false') === 'true',
  showNotifications: storage.get('clawku.showNotifications', 'true') === 'true',
  debugMode: storage.get('clawku.debugMode', 'false') === 'true',
  currentPage: 'dashboard',
};

const nonceCache = new Map();
const NONCE_TTL_MS = 10 * 60 * 1000;
const POLICY_TTL_MS = 30 * 24 * 60 * 60 * 1000;

function loadNonceStore() {
  try {
    const raw = localStorage.getItem('clawku.jobNonces');
    if (!raw) return;
    const items = JSON.parse(raw);
    if (Array.isArray(items)) {
      const now = Date.now();
      items.forEach((entry) => {
        if (entry?.nonce && entry?.expiresAt && entry.expiresAt > now) {
          nonceCache.set(entry.nonce, entry.expiresAt);
        }
      });
    }
  } catch {
    // ignore
  }
}

function persistNonceStore() {
  try {
    const now = Date.now();
    const items = [];
    for (const [nonce, expiresAt] of nonceCache.entries()) {
      if (expiresAt > now) items.push({ nonce, expiresAt });
    }
    localStorage.setItem('clawku.jobNonces', JSON.stringify(items.slice(0, 500)));
  } catch {
    // ignore
  }
}

function matchPattern(pattern, command) {
  if (pattern === '*') return true;
  if (pattern.endsWith('*')) {
    return command.startsWith(pattern.slice(0, -1));
  }
  return command === pattern;
}

function isCommandAllowed(command, allowList, denyList) {
  const deny = Array.isArray(denyList) && denyList.some((p) => matchPattern(p, command));
  if (deny) return false;
  if (!Array.isArray(allowList) || allowList.length === 0) return false;
  return allowList.some((p) => matchPattern(p, command));
}

async function verifyPolicy(payloadJson, signature) {
  const invoke = window.__TAURI__?.core?.invoke || window.__TAURI__?.invoke;
  if (!invoke) return false;
  const signing = await invoke('ensure_device_signing_key', {});
  const publicKeyPem = signing?.public_key_b64;
  if (!publicKeyPem) return false;
  const ok = await invoke('verify_payload_signature', {
    payloadJson,
    signatureB64: signature,
    publicKeyPem,
  });
  return Boolean(ok?.valid);
}

async function ensureDevicePolicy(autoApproveFlag = true) {
  const invoke = window.__TAURI__?.core?.invoke || window.__TAURI__?.invoke;
  if (!invoke || !state.user) return;
  const allowList = ['*'];
  const denyList = [];
  const issuedAt = Date.now();
  const payload = {
    v: 1,
    deviceId: state.deviceId,
    userId: state.user.id,
    allowList,
    denyList,
    autoApprove: Boolean(autoApproveFlag),
    issuedAt,
    expiresAt: issuedAt + POLICY_TTL_MS,
    nonce: crypto?.randomUUID ? crypto.randomUUID() : `nonce_${Date.now()}`,
  };
  const payloadJson = JSON.stringify(payload);
  const signature = await invoke('sign_result_payload', { payloadJson });
  storage.set('clawku.devicePolicyJson', payloadJson);
  storage.set('clawku.devicePolicySig', signature);
  state.devicePolicyJson = payloadJson;
  state.devicePolicySig = signature;
  try {
    await apiRequest('/devices/policy', 'POST', {
      deviceId: state.deviceId,
      payloadJson,
      signature,
    });
  } catch (err) {
    logLine(`Failed to sync policy: ${err instanceof Error ? err.message : String(err)}`);
  }
}

async function clearDevicePolicy() {
  storage.set('clawku.devicePolicyJson', '');
  storage.set('clawku.devicePolicySig', '');
  state.devicePolicyJson = '';
  state.devicePolicySig = '';
  try {
    await apiRequest(`/devices/policy/${state.deviceId}`, 'DELETE');
  } catch {
    // ignore
  }
}

function parseJobEnvelope(envelope) {
  if (!envelope) return null;
  if (envelope.payload) return envelope.payload;
  if (envelope.payloadJson) {
    try {
      return JSON.parse(envelope.payloadJson);
    } catch {
      return null;
    }
  }
  return envelope;
}

function validateJobPayload(payload) {
  if (!payload?.jobId || !payload?.deviceId || !payload?.command) return null;
  if (payload.deviceId !== state.deviceId) return null;
  const now = Date.now();
  if (payload.expiresAt && payload.expiresAt < now) return null;
  if (payload.issuedAt && payload.issuedAt > now + 30_000) return null;
  return payload;
}

async function verifyPolicyForCommand(command) {
  if (!state.devicePolicyJson || !state.devicePolicySig) {
    return { ok: false, reason: 'Policy missing' };
  }
  const policyOk = await verifyPolicy(state.devicePolicyJson, state.devicePolicySig);
  if (!policyOk) {
    return { ok: false, reason: 'Policy signature invalid' };
  }
  const policy = JSON.parse(state.devicePolicyJson);
  if (policy.deviceId && policy.deviceId !== state.deviceId) {
    return { ok: false, reason: 'Policy device mismatch' };
  }
  if (policy.expiresAt && policy.expiresAt < Date.now()) {
    return { ok: false, reason: 'Policy expired' };
  }
  const allowed = isCommandAllowed(command, policy.allowList, policy.denyList);
  if (!allowed) {
    return { ok: false, reason: 'Policy blocked command' };
  }
  return { ok: true, policy };
}

function ensureDeviceId() {
  if (!state.deviceId) {
    state.deviceId = crypto?.randomUUID ? crypto.randomUUID() : `device_${Date.now()}`;
    storage.set('clawku.deviceId', state.deviceId);
  }
  updateDeviceDisplays();
}

function updateDeviceDisplays() {
  // Dashboard device info
  if (els.deviceIdDisplay) {
    els.deviceIdDisplay.textContent = state.deviceId ? state.deviceId.slice(0, 8) + '...' : '-';
  }
  if (els.deviceNameDisplay) {
    els.deviceNameDisplay.textContent = state.deviceName || '-';
  }
  if (els.deviceName) {
    els.deviceName.value = state.deviceName;
  }
  // Settings device info
  if (els.settingsDeviceId) {
    els.settingsDeviceId.textContent = state.deviceId || '-';
  }
}

function navigateTo(pageName) {
  state.currentPage = pageName;
  // Update nav tabs
  document.querySelectorAll('.nav-tab').forEach((tab) => {
    tab.classList.toggle('active', tab.dataset.page === pageName);
  });
  // Update pages
  if (els.pageDashboard) {
    els.pageDashboard.classList.toggle('active', pageName === 'dashboard');
  }
  if (els.pageSettings) {
    els.pageSettings.classList.toggle('active', pageName === 'settings');
  }
}

function updateProfileDisplay() {
  if (!state.user) return;
  const name = state.user.displayName || state.user.email?.split('@')[0] || 'User';
  const email = state.user.email || '';
  const initial = name.charAt(0).toUpperCase();

  if (els.profileAvatar) els.profileAvatar.textContent = initial;
  if (els.profileName) els.profileName.textContent = name;
  if (els.profileEmail) els.profileEmail.textContent = email;
}

function updateToggles() {
  if (els.toggleAutoApprove) {
    els.toggleAutoApprove.classList.toggle('active', state.autoApprove);
  }
  if (els.toggleNotifications) {
    els.toggleNotifications.classList.toggle('active', state.showNotifications);
  }
  if (els.toggleDebug) {
    els.toggleDebug.classList.toggle('active', state.debugMode);
  }
  // Show/hide logs card based on debug mode
  if (els.logsCard) {
    els.logsCard.style.display = state.debugMode ? 'block' : 'none';
  }
}

function updateConnectionStatus(status) {
  if (els.settingsConnectionStatus) {
    els.settingsConnectionStatus.textContent = status;
  }
}

function updatePairingView(isPaired) {
  if (els.pairedView) {
    els.pairedView.style.display = isPaired ? 'block' : 'none';
  }
  if (els.unpairView) {
    els.unpairView.style.display = isPaired ? 'none' : 'block';
  }
}

function showRepairFlow() {
  // Switch to unpaired view to allow re-pairing
  if (els.pairedView) els.pairedView.style.display = 'none';
  if (els.unpairView) els.unpairView.style.display = 'block';
  // Reset pairing state
  state.pairingCode = '';
  if (els.pairingBox) els.pairingBox.style.display = 'none';
  if (els.pairingCode) els.pairingCode.textContent = '------';
  if (els.pairingCodeInput) els.pairingCodeInput.value = '';
  if (els.pairingStatus) els.pairingStatus.textContent = '';
  logLine('Re-pairing mode enabled.');
}

function setStatus(text) {
  if (els.clientStatus) {
    els.clientStatus.textContent = text;
    // Update status pill styling based on connection state
    els.clientStatus.classList.remove('connected', 'error');
    if (text.toLowerCase().includes('connected')) {
      els.clientStatus.classList.add('connected');
    } else if (text.toLowerCase().includes('error') || text.toLowerCase().includes('failed')) {
      els.clientStatus.classList.add('error');
    }
  }
  updateConnectionStatus(text);
}

function logLine(text) {
  const timestamp = new Date().toLocaleTimeString();
  if (els.logOutput) {
    els.logOutput.value += `[${timestamp}] ${text}\n`;
    els.logOutput.scrollTop = els.logOutput.scrollHeight;
  }
  if (els.authLogOutput) {
    els.authLogOutput.value += `[${timestamp}] ${text}\n`;
    els.authLogOutput.scrollTop = els.authLogOutput.scrollHeight;
  }
}

function renderJobs() {
  if (!els.jobs || !els.jobsEmpty) return;
  els.jobs.innerHTML = '';

  // Update job count display
  const count = state.pendingJobs.length;
  if (els.jobCount) {
    els.jobCount.textContent = count === 0 ? '0 pending' : `${count} pending`;
  }

  if (count === 0) {
    els.jobsEmpty.style.display = 'block';
    return;
  }
  els.jobsEmpty.style.display = 'none';

  for (const job of state.pendingJobs) {
    const wrapper = document.createElement('div');
    wrapper.className = 'job-item';
    wrapper.innerHTML = `
      <div class="job-command">${escapeHtml(job.command)}</div>
      <div class="job-meta">
        <span class="job-info">from ${escapeHtml(job.requestedBy || 'agent')} &bull; ${new Date(job.receivedAt).toLocaleTimeString()}</span>
        <div class="job-actions">
          <button class="approve success sm">Approve</button>
          <button class="deny danger sm">Deny</button>
        </div>
      </div>
    `;
    wrapper.querySelector('.approve')?.addEventListener('click', () => handleApprove(job));
    wrapper.querySelector('.deny')?.addEventListener('click', () => handleDeny(job));
    els.jobs.appendChild(wrapper);
  }
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function normalizePairingCode(value) {
  return String(value || '')
    .replace(/[^a-zA-Z0-9]/g, '')
    .toUpperCase()
    .slice(0, 6);
}

function setLoginStatus(text) {
  if (els.loginStatus) {
    els.loginStatus.textContent = text;
  }
}

function normalizeBaseUrl(url) {
  return url.replace(/\/+$/, '');
}

function deriveWsUrl(apiBaseUrl) {
  const base = normalizeBaseUrl(apiBaseUrl);
  if (base.startsWith('https://')) return `${base.replace('https://', 'wss://')}/devices/ws`;
  if (base.startsWith('http://')) return `${base.replace('http://', 'ws://')}/devices/ws`;
  return `${base}/devices/ws`;
}

async function probeApiBase(apiBaseUrl) {
  const url = `${normalizeBaseUrl(apiBaseUrl)}/health`;
  logLine(`Probing: ${url}`);

  // Use Tauri invoke if available (bypasses browser CORS restrictions)
  const invoke = window.__TAURI__?.core?.invoke || window.__TAURI__?.invoke;
  if (invoke) {
    try {
      const ok = await invoke('http_probe', { url });
      logLine(`Probe result (native): ${url} -> ${ok ? 'OK' : 'FAIL'}`);
      return ok;
    } catch (err) {
      logLine(`Probe error (native): ${url} -> ${err}`);
      return false;
    }
  }

  // Fallback to fetch for non-Tauri environments
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);
  try {
    const res = await fetch(url, {
      method: 'GET',
      signal: controller.signal,
    });
    logLine(`Probe result: ${url} -> ${res.status}`);
    return res.ok;
  } catch (err) {
    logLine(`Probe error: ${url} -> ${err.message || err}`);
    return false;
  } finally {
    clearTimeout(timeout);
  }
}

async function resolveApiBaseUrl() {
  const candidates = getApiCandidates();
  for (const candidate of candidates) {
    const ok = await probeApiBase(candidate);
    if (ok) {
      const base = normalizeBaseUrl(candidate);
      state.apiBaseUrl = base;
      state.wsUrl = deriveWsUrl(base);
      state.apiReady = true;
      logLine(`API base: ${state.apiBaseUrl}`);
      logLine(`WS url: ${state.wsUrl}`);
      return true;
    }
    logLine(`Probe failed: ${normalizeBaseUrl(candidate)}/health`);
  }
  logLine(`API base: unreachable (${candidates.join(', ')})`);
  setLoginStatus('Cannot reach API. Check your connection.');
  state.apiReady = false;
  return false;
}

function setUser(user) {
  state.user = user;
  if (user) {
    document.body.classList.remove('auth-mode');
    if (els.mainHeader) els.mainHeader.style.display = 'block';
    if (els.authCard) els.authCard.style.display = 'none';
    if (els.appMain) els.appMain.style.display = 'block';
    updateProfileDisplay();
    if (!state.devicePolicyJson) {
      ensureDevicePolicy(state.autoApprove);
    }
  } else {
    document.body.classList.add('auth-mode');
    if (els.mainHeader) els.mainHeader.style.display = 'none';
    if (els.authCard) els.authCard.style.display = 'block';
    if (els.appMain) els.appMain.style.display = 'none';
  }
}

async function apiRequest(path, method = 'GET', body) {
  const url = `${state.apiBaseUrl}${path}`;
  logLine(`Request ${method} ${url}`);

  // Use Tauri invoke if available (bypasses browser CORS restrictions)
  const invoke = window.__TAURI__?.core?.invoke || window.__TAURI__?.invoke;
  if (invoke) {
    try {
      let responseText;
      if (method === 'GET') {
        responseText = await invoke('http_get', { url });
      } else {
        responseText = await invoke('http_post', { url, body: body ? JSON.stringify(body) : '{}' });
      }
      logLine(`Response OK (native) ${method} ${url}`);
      return JSON.parse(responseText);
    } catch (err) {
      logLine(`Native request error: ${err}`);
      throw new Error(String(err));
    }
  }

  // Fallback to fetch for non-Tauri environments
  let res;
  try {
    res = await fetch(url, {
      method,
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: body ? JSON.stringify(body) : undefined,
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    logLine(`Network error: ${msg}`);
    throw err;
  }
  if (!res.ok) {
    const text = await res.text();
    logLine(`HTTP ${res.status}: ${text || 'no body'}`);
    throw new Error(text || `HTTP ${res.status}`);
  }
  const json = await res.json();
  logLine(`Response OK ${method} ${url}`);
  return json;
}

async function startPairing() {
  try {
    if (!state.user) {
      throw new Error('Please login first.');
    }
    if (!state.deviceName) {
      throw new Error('Enter a device name before pairing.');
    }
    const invoke = window.__TAURI__?.core?.invoke || window.__TAURI__?.invoke;
    let deviceSigningPublicKey;
    let deviceTlsFingerprint;
    if (invoke) {
      try {
        const signing = await invoke('ensure_device_signing_key', {});
        deviceSigningPublicKey = signing?.public_key_b64 || undefined;
        const tls = await invoke('ensure_device_tls_cert', { deviceId: state.deviceId });
        deviceTlsFingerprint = tls?.fingerprint_sha256 || undefined;
      } catch {
        // non-fatal
      }
    }
    const platform = navigator.platform || 'unknown';
    const version = '0.1.0';
    const payload = {
      deviceId: state.deviceId,
      deviceName: state.deviceName || undefined,
      platform,
      version,
      deviceSigningPublicKey,
      deviceTlsFingerprint,
    };
    const res = await apiRequest('/devices/pair/start', 'POST', payload);
    const code = normalizePairingCode(res?.code);
    if (!code) {
      throw new Error('Pairing code missing from server response');
    }
    state.pairingCode = code;
    logLine(`Pairing started. Code: ${code}`);
    if (els.pairingBox) els.pairingBox.style.display = 'block';
    if (els.pairingCode) els.pairingCode.textContent = code;
    if (els.pairingCodeInput) els.pairingCodeInput.value = code;
    if (els.pairingStatus) els.pairingStatus.textContent = 'Waiting for approval...';
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Failed to start pairing';
    if (els.pairingStatus) els.pairingStatus.textContent = msg;
    logLine(msg);
  }
}

async function finishPairing() {
  try {
    if (els.deviceName) {
      const name = els.deviceName.value.trim();
      state.deviceName = name;
      storage.set('clawku.deviceName', name);
    }
    const manualCode = normalizePairingCode(els.pairingCodeInput?.value || '');
    if (manualCode) {
      state.pairingCode = manualCode;
      if (els.pairingBox) els.pairingBox.style.display = 'block';
      if (els.pairingCode) els.pairingCode.textContent = manualCode;
    }
    if (!state.pairingCode) {
      if (els.pairingStatus) els.pairingStatus.textContent = 'Start pairing first.';
      return;
    }
    if (els.pairingStatus) els.pairingStatus.textContent = 'Checking...';
    const res = await apiRequest('/devices/pair/finish', 'POST', {
      deviceId: state.deviceId,
      code: state.pairingCode,
      deviceName: state.deviceName || undefined,
    });
    if (res.status === 'PENDING') {
      if (els.pairingStatus) els.pairingStatus.textContent = 'Still pending. Approve in the web app.';
      logLine('Pairing still pending.');
      return;
    }
    if (res.status === 'CONFIRMED') {
      state.deviceToken = res.deviceToken;
      if (res.deviceGateway?.wsUrl) {
        state.wsUrl = res.deviceGateway.wsUrl;
        storage.set('clawku.wsUrl', state.wsUrl);
        logLine(`WS url: ${state.wsUrl}`);
      }
      if (res.deviceGateway?.serverCertPem) {
        storage.set('clawku.deviceGatewayCertPem', res.deviceGateway.serverCertPem);
        logLine(`Gateway cert loaded (${res.deviceGateway.serverCertPem.length} bytes)`);
      }
      if (res.deviceGateway?.serverCaPem) {
        storage.set('clawku.deviceGatewayCaPem', res.deviceGateway.serverCaPem);
        logLine(`Gateway CA loaded (${res.deviceGateway.serverCaPem.length} bytes)`);
      } else if (res.deviceGateway?.wsUrl?.startsWith('wss://')) {
        logLine('Gateway CA missing in pairing response');
      }
      const invoke = window.__TAURI__?.core?.invoke || window.__TAURI__?.invoke;
      if (invoke) {
        await invoke('store_device_token', { token: state.deviceToken });
      }
      if (els.pairingStatus) els.pairingStatus.textContent = 'Paired! Connecting...';
      logLine('Pairing confirmed.');
      updatePairingView(true);
      if (!state.devicePolicyJson) {
        ensureDevicePolicy(state.autoApprove);
      }
      connectClient();
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Failed to finish pairing';
    if (els.pairingStatus) els.pairingStatus.textContent = msg;
    logLine(msg);
  }
}

function connectClient() {
  // Stop old client before creating new one
  if (state.client) {
    state.client.stop();
    state.client = null;
  }
  if (!state.deviceToken) {
    setStatus('Missing device token');
    return;
  }
  const wsUrl = storage.get('clawku.wsUrl', state.wsUrl);
  const serverCertPem = storage.get('clawku.deviceGatewayCertPem', '');
  const serverCaPem = storage.get('clawku.deviceGatewayCaPem', '');
  if (wsUrl.startsWith('wss://') && !serverCaPem) {
    logLine('Gateway CA not found in local storage');
  }
  const apiBaseUrl = state.apiBaseUrl;
  const client = new ClientConnection({
    wsUrl,
    apiBaseUrl,
    deviceToken: state.deviceToken,
    deviceId: state.deviceId,
    platform: navigator.platform || 'unknown',
    version: '0.1.0',
    native: wsUrl.startsWith('wss://') && !!serverCertPem ? { start: true, serverCertPem, serverCaPem } : null,
  });
  client.onJobEnqueue = async (envelope) => {
    try {
      const payload = validateJobPayload(parseJobEnvelope(envelope));
      if (!payload?.nonce) {
        logLine('Skipping job: invalid payload');
        return;
      }
      const now = Date.now();
      for (const [nonce, expiresAt] of nonceCache.entries()) {
        if (expiresAt < now) nonceCache.delete(nonce);
      }
      if (nonceCache.has(payload.nonce)) {
        logLine('Skipping job: nonce replay');
        return;
      }
      nonceCache.set(payload.nonce, payload.expiresAt || now + NONCE_TTL_MS);
      persistNonceStore();

      const job = { ...payload, receivedAt: Date.now() };

      // Auto-approve if enabled
      if (state.autoApprove) {
        const policyCheck = await verifyPolicyForCommand(job.command);
        if (policyCheck.ok) {
          logLine(`Auto-approving job: ${job.command}`);
          await handleApprove(job);
          return;
        }
        logLine(`Auto-approve blocked: ${policyCheck.reason}`);
      }

      // Show notification if enabled
      if (state.showNotifications && 'Notification' in window) {
        if (Notification.permission === 'granted') {
          new Notification('Clawku - Command Received', {
            body: verified.command.slice(0, 100),
            tag: verified.jobId,
          });
        } else if (Notification.permission !== 'denied') {
          Notification.requestPermission();
        }
      }

      state.pendingJobs = [...state.pendingJobs, job];
      logLine(`Job queued: ${job.command}`);
      renderJobs();
    } catch (err) {
      logLine(`Job verification failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  // Handle file upload requests - auto-approved for efficiency
  client.onJobUpload = async (envelope) => {
    const start = Date.now();
    try {
      const verified = validateJobPayload(parseJobEnvelope(envelope));
      if (!verified?.nonce) {
        logLine('Skipping upload: invalid payload');
        return;
      }

      // Check nonce replay
      const now = Date.now();
      for (const [nonce, expiresAt] of nonceCache.entries()) {
        if (expiresAt < now) nonceCache.delete(nonce);
      }
      if (nonceCache.has(verified.nonce)) {
        logLine('Skipping upload: nonce replay');
        return;
      }
      nonceCache.set(verified.nonce, verified.expiresAt || now + NONCE_TTL_MS);
      persistNonceStore();

      const policyCheck = await verifyPolicyForCommand(verified.command);
      if (!policyCheck.ok) {
        logLine(`Upload blocked: ${policyCheck.reason}`);
        throw new Error(policyCheck.reason);
      }

      // The command field contains the file path for uploads
      const filePath = verified.command;
      logLine(`Uploading file: ${filePath}`);

      // Get Tauri invoke function
      const invoke = window.__TAURI__?.core?.invoke || window.__TAURI__?.invoke;
      if (!invoke) throw new Error('Tauri runtime not available');

      // Read the file as base64
      const fileResult = await invoke('read_file_base64', { filePath });

      // Send file data back to server
      const payload = {
        jobId: verified.jobId,
        status: 'COMPLETED',
        durationMs: Date.now() - start,
        summary: `Uploaded ${fileResult.size_bytes} bytes`,
        fileData: fileResult.data_b64,
        mimeType: fileResult.mime_type,
        sizeBytes: fileResult.size_bytes,
        fileName: filePath.split('/').pop() || 'file',
        issuedAt: Date.now(),
        nonce: crypto?.randomUUID ? crypto.randomUUID() : `nonce_${Date.now()}`,
      };
      const payloadJson = JSON.stringify(payload);
      const signature = await invoke('sign_result_payload', { payloadJson });
      state.client?.send('file.upload', { payloadJson, signature });
      logLine(`File uploaded: ${filePath} (${fileResult.size_bytes} bytes)`);
    } catch (err) {
      const errMsg = err instanceof Error ? err.message : String(err);
      logLine(`Upload failed: ${errMsg}`);

      // Send error result
      const invoke = window.__TAURI__?.core?.invoke || window.__TAURI__?.invoke;
      try {
        const parsed = parseJobEnvelope(envelope) || {};
        const payload = {
          jobId: parsed.jobId || 'unknown',
          status: 'FAILED',
          durationMs: Date.now() - start,
          summary: 'Upload failed',
          errorText: errMsg,
          issuedAt: Date.now(),
          nonce: crypto?.randomUUID ? crypto.randomUUID() : `nonce_${Date.now()}`,
        };
        if (invoke) {
          const payloadJson = JSON.stringify(payload);
          const signature = await invoke('sign_result_payload', { payloadJson });
          state.client?.send('file.upload', { payloadJson, signature });
        }
      } catch {
        // Ignore secondary errors
      }
    }
  };
  client.connect();
  state.client = client;
  setStatus('Connected');
  logLine('Connected to gateway.');
}

async function handleApprove(job) {
  const start = Date.now();
  try {
    const policyCheck = await verifyPolicyForCommand(job.command);
    if (!policyCheck.ok) {
      logLine(`Approval blocked: ${policyCheck.reason}`);
      const invoke = window.__TAURI__?.core?.invoke || window.__TAURI__?.invoke;
      const payload = {
        jobId: job.jobId,
        status: 'DENIED',
        summary: `Policy blocked: ${policyCheck.reason}`,
        issuedAt: Date.now(),
        nonce: crypto?.randomUUID ? crypto.randomUUID() : `nonce_${Date.now()}`,
      };
      if (invoke) {
        try {
          const payloadJson = JSON.stringify(payload);
          const signature = await invoke('sign_result_payload', { payloadJson });
          state.client?.send('job.result', { payloadJson, signature });
        } catch {
          state.client?.send('job.result', payload);
        }
      } else {
        state.client?.send('job.result', payload);
      }
      return;
    }
    const invoke = window.__TAURI__?.core?.invoke || window.__TAURI__?.invoke;
    if (!invoke) throw new Error('Tauri runtime not available');
    const result = await invoke('run_command', { command: job.command, cwd: job.cwd || null });
    const payload = {
      jobId: job.jobId,
      status: 'COMPLETED',
      exitCode: result?.exitCode ?? 0,
      durationMs: Date.now() - start,
      summary: result?.summary || 'Completed',
      output: result?.output || '',
      errorText: result?.error || '',
      issuedAt: Date.now(),
      nonce: crypto?.randomUUID ? crypto.randomUUID() : `nonce_${Date.now()}`,
    };
    const payloadJson = JSON.stringify(payload);
    const signature = await invoke('sign_result_payload', { payloadJson });
    state.client?.send('job.result', { payloadJson, signature });
    logLine(`Job completed: ${job.command}`);
  } catch (err) {
    try {
      const invoke = window.__TAURI__?.core?.invoke || window.__TAURI__?.invoke;
      const payload = {
        jobId: job.jobId,
        status: 'FAILED',
        exitCode: 1,
        durationMs: Date.now() - start,
        summary: 'Execution failed',
        errorText: err instanceof Error ? err.message : String(err),
        issuedAt: Date.now(),
        nonce: crypto?.randomUUID ? crypto.randomUUID() : `nonce_${Date.now()}`,
      };
      if (invoke) {
        const payloadJson = JSON.stringify(payload);
        const signature = await invoke('sign_result_payload', { payloadJson });
        state.client?.send('job.result', { payloadJson, signature });
      } else {
        state.client?.send('job.result', payload);
      }
    } catch {
      state.client?.send('job.result', {
        jobId: job.jobId,
        status: 'FAILED',
        exitCode: 1,
        durationMs: Date.now() - start,
        summary: 'Execution failed',
        errorText: err instanceof Error ? err.message : String(err),
      });
    }
    logLine(`Job failed: ${job.command}`);
  } finally {
    state.pendingJobs = state.pendingJobs.filter((p) => p.jobId !== job.jobId);
    renderJobs();
  }
}

function handleDeny(job) {
  (async () => {
    const invoke = window.__TAURI__?.core?.invoke || window.__TAURI__?.invoke;
    const payload = {
      jobId: job.jobId,
      status: 'DENIED',
      summary: 'User denied request',
      issuedAt: Date.now(),
      nonce: crypto?.randomUUID ? crypto.randomUUID() : `nonce_${Date.now()}`,
    };
    if (invoke) {
      try {
        const payloadJson = JSON.stringify(payload);
        const signature = await invoke('sign_result_payload', { payloadJson });
        state.client?.send('job.result', { payloadJson, signature });
        return;
      } catch {
        // fallthrough
      }
    }
    state.client?.send('job.result', payload);
  })();
  logLine(`Job denied: ${job.command}`);
  state.pendingJobs = state.pendingJobs.filter((p) => p.jobId !== job.jobId);
  renderJobs();
}

function init() {
  // Start in auth mode (prevents scrolling until logged in)
  document.body.classList.add('auth-mode');

  ensureDeviceId();
  logLine(`Device ID: ${state.deviceId}`);
  loadNonceStore();

  // Initialize toggles state
  updateToggles();

  // Navigation tabs
  document.querySelectorAll('.nav-tab').forEach((tab) => {
    tab.addEventListener('click', () => {
      const page = tab.dataset.page;
      if (page) navigateTo(page);
    });
  });

  // Toggle switches
  if (els.toggleAutoApprove) {
    els.toggleAutoApprove.addEventListener('click', () => {
      state.autoApprove = !state.autoApprove;
      storage.set('clawku.autoApprove', String(state.autoApprove));
      updateToggles();
      logLine(`Auto-approve: ${state.autoApprove ? 'enabled' : 'disabled'}`);
      ensureDevicePolicy(state.autoApprove);
    });
  }
  if (els.toggleNotifications) {
    els.toggleNotifications.addEventListener('click', () => {
      state.showNotifications = !state.showNotifications;
      storage.set('clawku.showNotifications', String(state.showNotifications));
      updateToggles();
      logLine(`Notifications: ${state.showNotifications ? 'enabled' : 'disabled'}`);
    });
  }
  if (els.toggleDebug) {
    els.toggleDebug.addEventListener('click', () => {
      state.debugMode = !state.debugMode;
      storage.set('clawku.debugMode', String(state.debugMode));
      updateToggles();
      logLine(`Debug mode: ${state.debugMode ? 'enabled' : 'disabled'}`);
    });
  }

  if (els.exportPolicy) {
    els.exportPolicy.addEventListener('click', async () => {
      try {
        if (!state.devicePolicyJson || !state.devicePolicySig) {
          await ensureDevicePolicy(state.autoApprove);
        }
        const policy = state.devicePolicyJson ? JSON.parse(state.devicePolicyJson) : {};
        const exportPayload = {
          policy,
          signature: state.devicePolicySig || '',
          deviceId: state.deviceId,
          exportedAt: new Date().toISOString(),
        };
        const blob = new Blob([JSON.stringify(exportPayload, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `clawku-policy-${state.deviceId}.json`;
        a.click();
        URL.revokeObjectURL(url);
        logLine('Policy exported.');
      } catch (err) {
        logLine(`Policy export failed: ${err instanceof Error ? err.message : String(err)}`);
      }
    });
  }

  if (els.pairingCodeInput) {
    els.pairingCodeInput.addEventListener('input', (evt) => {
      const target = evt.target;
      if (target && typeof target.value === 'string') {
        const code = normalizePairingCode(target.value);
        target.value = code;
        state.pairingCode = code;
        if (code) {
          if (els.pairingBox) els.pairingBox.style.display = 'block';
          if (els.pairingCode) els.pairingCode.textContent = code;
        }
      }
    });
  }
  if (els.deviceName) {
    els.deviceName.addEventListener('input', (evt) => {
      const target = evt.target;
      if (target && typeof target.value === 'string') {
        state.deviceName = target.value.trim();
        storage.set('clawku.deviceName', state.deviceName);
        updateDeviceDisplays();
      }
    });
  }
  if (els.loginButton) {
    els.loginButton.addEventListener('click', async () => {
      console.log('[LOGIN] Button clicked');
      logLine('Login button clicked');
      console.log('[LOGIN] state.apiReady:', state.apiReady);
      if (!state.apiReady) {
        setLoginStatus('API not reachable. Start the API on localhost:3000.');
        return;
      }
      const email = els.loginEmail?.value?.trim() || '';
      const password = els.loginPassword?.value || '';
      console.log('[LOGIN] Email:', email, 'Password length:', password.length);
      if (!email || !password) {
        setLoginStatus('Enter email and password.');
        return;
      }
      logLine(`Login attempt: ${email}`);
      setLoginStatus('Signing in...');
      try {
        const res = await apiRequest('/auth/login', 'POST', { email, password });
        setUser(res.user);
        setLoginStatus('Signed in.');
      } catch (err) {
        const raw = err instanceof Error ? err.message : 'Login failed';
        let msg = raw;
        // Handle "HTTP 401: {...json...}" format from native invoke
        const jsonMatch = raw.match(/HTTP \d+:\s*(\{.+\})/);
        const jsonStr = jsonMatch ? jsonMatch[1] : (raw.trim().startsWith('{') ? raw : null);
        if (jsonStr) {
          try {
            const parsed = JSON.parse(jsonStr);
            msg = parsed?.message || parsed?.error || 'Login failed';
          } catch {
            msg = 'Login failed';
          }
        }
        setLoginStatus(msg);
      }
    });
  }
  if (els.openRegister) {
    els.openRegister.addEventListener('click', () => {
      window.open(WEB_BASE_URL, '_blank');
    });
  }
  if (els.logoutButton) {
    els.logoutButton.addEventListener('click', async () => {
      try {
        await apiRequest('/auth/logout', 'POST', {});
      } catch {
        // ignore
      }
      if (state.client) {
        state.client.stop();
        state.client = null;
      }
      setUser(null);
      setStatus('Disconnected');
      logLine('Logged out.');
    });
  }
  if (els.startPairing) els.startPairing.addEventListener('click', startPairing);
  if (els.finishPairing) els.finishPairing.addEventListener('click', finishPairing);
  if (els.connectClient) els.connectClient.addEventListener('click', connectClient);
  if (els.showRepairBtn) els.showRepairBtn.addEventListener('click', showRepairFlow);
  if (els.clearPairing) {
    els.clearPairing.addEventListener('click', async () => {
      const invoke = window.__TAURI__?.core?.invoke || window.__TAURI__?.invoke;
      if (invoke) {
        await invoke('clear_device_token', {});
      }
      localStorage.removeItem('clawku.wsUrl');
      localStorage.removeItem('clawku.deviceGatewayCertPem');
      localStorage.removeItem('clawku.deviceGatewayCaPem');
      localStorage.removeItem('clawku.userSigningPublicKey');
      localStorage.removeItem('clawku.userSigningKeyId');
      localStorage.removeItem('clawku.devicePolicyJson');
      localStorage.removeItem('clawku.devicePolicySig');
      localStorage.removeItem('clawku.jobNonces');
      state.wsUrl = deriveWsUrl(state.apiBaseUrl);
      if (state.client) {
        state.client.stop();
        state.client = null;
      }
      state.deviceToken = '';
      setStatus('Disconnected');
      updatePairingView(false);
      logLine('Pairing cleared.');
    });
  }
  if (els.enableAutostart) {
    els.enableAutostart.addEventListener('click', async () => {
      const invoke = window.__TAURI__?.core?.invoke || window.__TAURI__?.invoke;
      if (!invoke) return;
      const appPath = await invoke('get_executable_path', {});
      await invoke('enable_autostart', { appPath });
      logLine('Autostart enabled.');
    });
  }
  if (els.disableAutostart) {
    els.disableAutostart.addEventListener('click', async () => {
      const invoke = window.__TAURI__?.core?.invoke || window.__TAURI__?.invoke;
      if (!invoke) return;
      await invoke('disable_autostart', {});
      logLine('Autostart disabled.');
    });
  }
  if (els.clearLogs) {
    els.clearLogs.addEventListener('click', () => {
      if (els.logOutput) els.logOutput.value = '';
    });
  }
  renderJobs();

  (async () => {
    // Detect build mode from Rust (cfg!(debug_assertions))
    const invoke = window.__TAURI__?.core?.invoke || window.__TAURI__?.invoke;
    if (invoke) {
      try {
        IS_DEBUG_BUILD = await invoke('is_debug_build', {});
      } catch (err) {
        logLine(`Build mode detection failed: ${err}`);
        IS_DEBUG_BUILD = false; // Default to production for safety
      }
    }
    logLine(`Build mode: ${IS_DEBUG_BUILD ? 'DEBUG' : 'RELEASE'}`);
    const ready = await resolveApiBaseUrl();
    if (!ready) {
      setUser(null);
      return;
    }
    try {
      const me = await apiRequest('/me', 'GET');
      setUser(me.user);
    } catch {
      setUser(null);
    }
    // Reuse invoke from above for device token loading
    if (invoke) {
      try {
        const token = await invoke('load_device_token', {});
        if (typeof token === 'string' && token) {
          state.deviceToken = token;
        }
      } catch {
        // ignore
      }
    }
    if (state.deviceToken) {
      updatePairingView(true);
      connectClient();
    } else {
      updatePairingView(false);
      setStatus('Disconnected');
    }
  })();
}

async function setupTrayListeners() {
  const tauriApi = window.__TAURI__;
  const eventApi = tauriApi?.event;
  if (!eventApi) return;

  await eventApi.listen('tray_action', (event) => {
    const action = event.payload;
    logLine(`Tray action: ${action}`);

    switch (action) {
      case 'connect':
        connectClient();
        break;
      case 'repair':
        showRepairFlow();
        break;
      case 'clear':
        // Trigger clear pairing
        els.clearPairing?.click();
        break;
      case 'auto_approve':
        // Toggle auto-approve
        state.autoApprove = !state.autoApprove;
        storage.set('clawku.autoApprove', String(state.autoApprove));
        updateToggles();
        logLine(`Auto-approve: ${state.autoApprove ? 'enabled' : 'disabled'}`);
        break;
      case 'logout':
        // Trigger logout
        els.logoutButton?.click();
        break;
    }
  });
}

// ==================== OTA Updates ====================

let pendingUpdate = null;

async function checkForUpdates() {
  const tauriApi = window.__TAURI__;
  if (!tauriApi) {
    logLine('Updates not available (not running in Tauri)');
    return;
  }

  try {
    els.checkUpdates.disabled = true;
    els.checkUpdates.textContent = 'Checking...';
    els.updateStatus.textContent = 'Checking for updates...';

    // Import the updater plugin
    const { check } = await import('@tauri-apps/plugin-updater');
    const update = await check();

    if (update) {
      pendingUpdate = update;
      els.updateStatus.textContent = `Update available: v${update.version}`;
      els.updateMessage.textContent = update.body || 'A new version is available.';
      els.installUpdate.style.display = 'inline-flex';
      logLine(`Update available: v${update.version}`);
    } else {
      els.updateStatus.textContent = 'Up to date';
      els.updateMessage.textContent = `Last checked: ${new Date().toLocaleString()}`;
      els.installUpdate.style.display = 'none';
      logLine('No updates available');
    }
  } catch (err) {
    const errMsg = err instanceof Error ? err.message : String(err);
    els.updateStatus.textContent = 'Check failed';
    els.updateMessage.textContent = `Error: ${errMsg}`;
    logLine(`Update check failed: ${errMsg}`);
  } finally {
    els.checkUpdates.disabled = false;
    els.checkUpdates.textContent = 'Check for Updates';
  }
}

async function installUpdate() {
  if (!pendingUpdate) {
    logLine('No pending update to install');
    return;
  }

  try {
    els.installUpdate.disabled = true;
    els.installUpdate.textContent = 'Downloading...';
    els.updateProgress.style.display = 'block';
    els.updateProgressBar.style.width = '0%';
    els.updateProgressText.textContent = 'Starting download...';

    let downloaded = 0;
    let contentLength = 0;

    await pendingUpdate.downloadAndInstall((event) => {
      switch (event.event) {
        case 'Started':
          contentLength = event.data.contentLength || 0;
          els.updateProgressText.textContent = `Downloading: 0 / ${formatBytes(contentLength)}`;
          logLine(`Download started: ${formatBytes(contentLength)}`);
          break;
        case 'Progress':
          downloaded += event.data.chunkLength;
          const percent = contentLength > 0 ? Math.round((downloaded / contentLength) * 100) : 0;
          els.updateProgressBar.style.width = `${percent}%`;
          els.updateProgressText.textContent = `Downloading: ${formatBytes(downloaded)} / ${formatBytes(contentLength)} (${percent}%)`;
          break;
        case 'Finished':
          els.updateProgressBar.style.width = '100%';
          els.updateProgressText.textContent = 'Download complete. Installing...';
          logLine('Download complete, installing update...');
          break;
      }
    });

    // The app will restart automatically after installation
    els.updateProgressText.textContent = 'Update installed. Restarting...';
    logLine('Update installed, restarting app...');

  } catch (err) {
    const errMsg = err instanceof Error ? err.message : String(err);
    els.updateStatus.textContent = 'Install failed';
    els.updateProgressText.textContent = `Error: ${errMsg}`;
    logLine(`Update install failed: ${errMsg}`);
    els.installUpdate.disabled = false;
    els.installUpdate.textContent = 'Install Update';
  }
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function setupUpdateListeners() {
  els.checkUpdates?.addEventListener('click', checkForUpdates);
  els.installUpdate?.addEventListener('click', installUpdate);

  // Set current version from Tauri
  const tauriApi = window.__TAURI__;
  if (tauriApi?.app?.getVersion) {
    tauriApi.app.getVersion().then(version => {
      if (els.currentVersion) els.currentVersion.textContent = version;
    });
  }
}

// ==================== About & License ====================

const APACHE_LICENSE_TEXT = `                                 Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

   1. Definitions.

      "License" shall mean the terms and conditions for use, reproduction,
      and distribution as defined by Sections 1 through 9 of this document.

      "Licensor" shall mean the copyright owner or entity authorized by
      the copyright owner that is granting the License.

      "Legal Entity" shall mean the union of the acting entity and all
      other entities that control, are controlled by, or are under common
      control with that entity. For the purposes of this definition,
      "control" means (i) the power, direct or indirect, to cause the
      direction or management of such entity, whether by contract or
      otherwise, or (ii) ownership of fifty percent (50%) or more of the
      outstanding shares, or (iii) beneficial ownership of such entity.

      "You" (or "Your") shall mean an individual or Legal Entity
      exercising permissions granted by this License.

      "Source" form shall mean the preferred form for making modifications,
      including but not limited to software source code, documentation
      source, and configuration files.

      "Object" form shall mean any form resulting from mechanical
      transformation or translation of a Source form, including but
      not limited to compiled object code, generated documentation,
      and conversions to other media types.

      "Work" shall mean the work of authorship, whether in Source or
      Object form, made available under the License, as indicated by a
      copyright notice that is included in or attached to the work
      (an example is provided in the Appendix below).

      "Derivative Works" shall mean any work, whether in Source or Object
      form, that is based on (or derived from) the Work and for which the
      editorial revisions, annotations, elaborations, or other modifications
      represent, as a whole, an original work of authorship. For the purposes
      of this License, Derivative Works shall not include works that remain
      separable from, or merely link (or bind by name) to the interfaces of,
      the Work and Derivative Works thereof.

      "Contribution" shall mean any work of authorship, including
      the original version of the Work and any modifications or additions
      to that Work or Derivative Works thereof, that is intentionally
      submitted to the Licensor for inclusion in the Work by the copyright owner
      or by an individual or Legal Entity authorized to submit on behalf of
      the copyright owner. For the purposes of this definition, "submitted"
      means any form of electronic, verbal, or written communication sent
      to the Licensor or its representatives, including but not limited to
      communication on electronic mailing lists, source code control systems,
      and issue tracking systems that are managed by, or on behalf of, the
      Licensor for the purpose of discussing and improving the Work, but
      excluding communication that is conspicuously marked or otherwise
      designated in writing by the copyright owner as "Not a Contribution."

      "Contributor" shall mean Licensor and any individual or Legal Entity
      on behalf of whom a Contribution has been received by Licensor and
      subsequently incorporated within the Work.

   2. Grant of Copyright License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      copyright license to reproduce, prepare Derivative Works of,
      publicly display, publicly perform, sublicense, and distribute the
      Work and such Derivative Works in Source or Object form.

   3. Grant of Patent License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      (except as stated in this section) patent license to make, have made,
      use, offer to sell, sell, import, and otherwise transfer the Work,
      where such license applies only to those patent claims licensable
      by such Contributor that are necessarily infringed by their
      Contribution(s) alone or by combination of their Contribution(s)
      with the Work to which such Contribution(s) was submitted. If You
      institute patent litigation against any entity (including a
      cross-claim or counterclaim in a lawsuit) alleging that the Work
      or a Contribution incorporated within the Work constitutes direct
      or contributory patent infringement, then any patent licenses
      granted to You under this License for that Work shall terminate
      as of the date such litigation is filed.

   4. Redistribution. You may reproduce and distribute copies of the
      Work or Derivative Works thereof in any medium, with or without
      modifications, and in Source or Object form, provided that You
      meet the following conditions:

      (a) You must give any other recipients of the Work or
          Derivative Works a copy of this License; and

      (b) You must cause any modified files to carry prominent notices
          stating that You changed the files; and

      (c) You must retain, in the Source form of any Derivative Works
          that You distribute, all copyright, patent, trademark, and
          attribution notices from the Source form of the Work,
          excluding those notices that do not pertain to any part of
          the Derivative Works; and

      (d) If the Work includes a "NOTICE" text file as part of its
          distribution, then any Derivative Works that You distribute must
          include a readable copy of the attribution notices contained
          within such NOTICE file, excluding those notices that do not
          pertain to any part of the Derivative Works, in at least one
          of the following places: within a NOTICE text file distributed
          as part of the Derivative Works; within the Source form or
          documentation, if provided along with the Derivative Works; or,
          within a display generated by the Derivative Works, if and
          wherever such third-party notices normally appear. The contents
          of the NOTICE file are for informational purposes only and
          do not modify the License. You may add Your own attribution
          notices within Derivative Works that You distribute, alongside
          or as an addendum to the NOTICE text from the Work, provided
          that such additional attribution notices cannot be construed
          as modifying the License.

      You may add Your own copyright statement to Your modifications and
      may provide additional or different license terms and conditions
      for use, reproduction, or distribution of Your modifications, or
      for any such Derivative Works as a whole, provided Your use,
      reproduction, and distribution of the Work otherwise complies with
      the conditions stated in this License.

   5. Submission of Contributions. Unless You explicitly state otherwise,
      any Contribution intentionally submitted for inclusion in the Work
      by You to the Licensor shall be under the terms and conditions of
      this License, without any additional terms or conditions.
      Notwithstanding the above, nothing herein shall supersede or modify
      the terms of any separate license agreement you may have executed
      with Licensor regarding such Contributions.

   6. Trademarks. This License does not grant permission to use the trade
      names, trademarks, service marks, or product names of the Licensor,
      except as required for reasonable and customary use in describing the
      origin of the Work and reproducing the content of the NOTICE file.

   7. Disclaimer of Warranty. Unless required by applicable law or
      agreed to in writing, Licensor provides the Work (and each
      Contributor provides its Contributions) on an "AS IS" BASIS,
      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
      implied, including, without limitation, any warranties or conditions
      of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A
      PARTICULAR PURPOSE. You are solely responsible for determining the
      appropriateness of using or redistributing the Work and assume any
      risks associated with Your exercise of permissions under this License.

   8. Limitation of Liability. In no event and under no legal theory,
      whether in tort (including negligence), contract, or otherwise,
      unless required by applicable law (such as deliberate and grossly
      negligent acts) or agreed to in writing, shall any Contributor be
      liable to You for damages, including any direct, indirect, special,
      incidental, or consequential damages of any character arising as a
      result of this License or out of the use or inability to use the
      Work (including but not limited to damages for loss of goodwill,
      work stoppage, computer failure or malfunction, or any and all
      other commercial damages or losses), even if such Contributor
      has been advised of the possibility of such damages.

   9. Accepting Warranty or Additional Liability. While redistributing
      the Work or Derivative Works thereof, You may choose to offer,
      and charge a fee for, acceptance of support, warranty, indemnity,
      or other liability obligations and/or rights consistent with this
      License. However, in accepting such obligations, You may act only
      on Your own behalf and on Your sole responsibility, not on behalf
      of any other Contributor, and only if You agree to indemnify,
      defend, and hold each Contributor harmless for any liability
      incurred by, or claims asserted against, such Contributor by reason
      of your accepting any such warranty or additional liability.

   END OF TERMS AND CONDITIONS

   Copyright 2024 Clawku

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.`;

const SOURCE_CODE_URL = 'https://github.com/clawku/platform-client';

function showLicenseModal() {
  if (els.licenseText) els.licenseText.textContent = APACHE_LICENSE_TEXT;
  if (els.licenseModal) els.licenseModal.style.display = 'flex';
}

function hideLicenseModal() {
  if (els.licenseModal) els.licenseModal.style.display = 'none';
}

function setupAboutListeners() {
  // View license button
  els.viewLicense?.addEventListener('click', showLicenseModal);

  // Close modal button
  els.closeLicenseModal?.addEventListener('click', hideLicenseModal);

  // Close modal on backdrop click
  els.licenseModal?.querySelector('.modal-backdrop')?.addEventListener('click', hideLicenseModal);

  // Close modal on escape key
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && els.licenseModal?.style.display === 'flex') {
      hideLicenseModal();
    }
  });

  // View source code button
  els.viewSourceCode?.addEventListener('click', () => {
    window.open(SOURCE_CODE_URL, '_blank');
  });

  // Set about version from Tauri
  const tauriApi = window.__TAURI__;
  if (tauriApi?.app?.getVersion) {
    tauriApi.app.getVersion().then(version => {
      if (els.aboutVersion) els.aboutVersion.textContent = version;
    });
  }
}

window.addEventListener('DOMContentLoaded', () => {
  init();
  setupTrayListeners();
  setupUpdateListeners();
  setupAboutListeners();
});
