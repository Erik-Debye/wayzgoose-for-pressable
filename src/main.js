'use strict';

const { app, BrowserWindow, ipcMain, safeStorage, shell } = require('electron');
const path = require('node:path');
const fs = require('node:fs/promises');
const {
  PressableClient,
  normalizeBackup,
  normalizePreload,
  normalizeEdgeCache,
  isFinalState,
  isFailedState,
  sleep,
} = require('./pressable');
const security = require('./security');

const MAX_PER_TYPE = 3; // Pressable's per-site limit for each on-demand backup type
const CONFIG_DEFAULTS = {
  siteIds: [],
  task: {
    kind: 'backup', // backup | cache | preload
    backupTypes: ['fs', 'db'],
    clearEdge: true,
    clearObject: false,
    preloadEnabled: true,
    preloadTurnOnEdgeCache: false,
  },
  delayBetweenSitesMs: 1500,
  // Vulnerability checks
  securityScope: 'all', // all | list
  webhookUrl: '',
  alertAutomatically: true,
  dailyCheck: false,
  nvdApiKey: '',
};

let mainWindow = null;
let client = null;
let currentRun = null;
let currentScan = null;

// ---------- Paths & storage ----------

const userDataDir = () => app.getPath('userData');
const configPath = () => path.join(userDataDir(), 'config.json');
const credsPath = () => path.join(userDataDir(), 'credentials.bin');
const runLogPath = () => path.join(userDataDir(), 'runs.log');
const seenFindingsPath = () => path.join(userDataDir(), 'seen-findings.json');
const cveCachePath = () => path.join(userDataDir(), 'cve-cache.json');
const lastFindingsPath = () => path.join(userDataDir(), 'last-findings.json');

async function readJson(file, fallback) {
  try {
    return JSON.parse(await fs.readFile(file, 'utf8'));
  } catch (err) {
    if (err.code === 'ENOENT') return fallback;
    throw err;
  }
}

async function writeJson(file, value) {
  await fs.mkdir(path.dirname(file), { recursive: true });
  await fs.writeFile(file, JSON.stringify(value, null, 2), 'utf8');
}

async function loadConfig() {
  const stored = await readJson(configPath(), {});
  const task = { ...CONFIG_DEFAULTS.task, ...(stored.task || {}) };
  // Older configs kept backup types at the top level.
  if (Array.isArray(stored.backupTypes) && !stored.task) task.backupTypes = stored.backupTypes;
  return { ...CONFIG_DEFAULTS, ...stored, task };
}

async function saveConfig(patch) {
  const current = await loadConfig();
  const next = { ...current, ...patch };
  if (patch && patch.task) next.task = { ...current.task, ...patch.task };
  await writeJson(configPath(), next);
  return next;
}

// Credentials are encrypted with the OS keystore (Keychain on macOS, DPAPI on
// Windows) via Electron's safeStorage. Only the main process can read them.
async function loadCredentials() {
  try {
    const buf = await fs.readFile(credsPath());
    const text = safeStorage.isEncryptionAvailable()
      ? safeStorage.decryptString(buf)
      : buf.toString('utf8');
    return JSON.parse(text);
  } catch (err) {
    if (err.code === 'ENOENT') return null;
    throw err;
  }
}

async function saveCredentials({ clientId, clientSecret }) {
  const text = JSON.stringify({ clientId, clientSecret });
  const buf = safeStorage.isEncryptionAvailable()
    ? safeStorage.encryptString(text)
    : Buffer.from(text, 'utf8');
  await fs.mkdir(userDataDir(), { recursive: true });
  await fs.writeFile(credsPath(), buf, { mode: 0o600 });
}

async function clearCredentials() {
  try {
    await fs.unlink(credsPath());
  } catch (err) {
    if (err.code !== 'ENOENT') throw err;
  }
}

async function appendRunLog(entry) {
  try {
    await fs.appendFile(
      runLogPath(),
      JSON.stringify({ at: new Date().toISOString(), ...entry }) + '\n',
      'utf8',
    );
  } catch {
    // Logging never blocks a backup.
  }
}

async function getClient() {
  if (client) return client;
  const creds = await loadCredentials();
  if (!creds) throw new Error('Add your Pressable API client ID and secret in Settings first.');
  client = new PressableClient(creds);
  return client;
}

// ---------- Window ----------

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1180,
    height: 760,
    minWidth: 920,
    minHeight: 600,
    title: 'Wayzgoose for Pressable',
    backgroundColor: '#f4f6f8',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });
  mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));

  // Open any external link in the system browser, never inside the app.
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https:\/\//.test(url)) shell.openExternal(url);
    return { action: 'deny' };
  });
  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

const send = (channel, payload) => {
  if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send(channel, payload);
};

// ---------- Site helpers ----------

function compactSite(site) {
  return {
    id: site.id,
    name: site.name,
    displayName: site.displayName || site.name,
    url: site.url,
    state: site.state,
    staging: Boolean(site.staging),
    sandbox: Boolean(site.sandbox),
    tags: Array.isArray(site.tags) ? site.tags.map((t) => (t && t.name) || String(t)) : [],
  };
}

// ---------- Task run engine ----------
//
// A run applies one task to a set of sites. Each task expands into one or
// more items per site:
//   backup  → { kind: 'backup', type: 'fs' | 'db' }
//   cache   → { kind: 'purge-edge' } and/or { kind: 'flush-object' }
//   preload → { kind: 'preload', enabled, turnOnEdgeCache }

function expandTask(task) {
  switch (task.kind) {
    case 'backup':
      return (task.backupTypes || []).filter((t) => t === 'fs' || t === 'db').map((type) => ({ kind: 'backup', type }));
    case 'cache': {
      const items = [];
      if (task.clearEdge) items.push({ kind: 'purge-edge' });
      if (task.clearObject) items.push({ kind: 'flush-object' });
      return items;
    }
    case 'preload':
      return [{ kind: 'preload', enabled: Boolean(task.preloadEnabled), turnOnEdgeCache: Boolean(task.preloadTurnOnEdgeCache) }];
    default:
      return [];
  }
}

async function makeRoomIfFull(api, siteId, type) {
  const backups = (await api.listOndemandBackups(siteId))
    .map(normalizeBackup)
    .filter((b) => b && b.type === type);
  if (backups.length < MAX_PER_TYPE) return null;

  const oldest = [...backups].sort(
    (a, b) => new Date(a.created || 0) - new Date(b.created || 0),
  )[0];
  if (!oldest || oldest.id === null) {
    throw new Error(`This site already has ${MAX_PER_TYPE} ${type === 'fs' ? 'filesystem' : 'database'} backups and the oldest could not be identified.`);
  }
  await api.deleteOndemandBackup(siteId, oldest.id);
  return oldest.id;
}

async function runItem(api, site, item) {
  switch (item.kind) {
    case 'backup': {
      // Pressable keeps at most 3 per type; always make room for the new one.
      const replacedId = await makeRoomIfFull(api, site.id, item.type);
      const requestedAt = new Date().toISOString();
      const created = normalizeBackup(await api.createOndemandBackup(site.id, item.type));
      return {
        backupId: created ? created.id : null,
        state: created && created.state ? created.state : null,
        replacedId,
        requestedAt,
        response: created ? created.raw : null,
      };
    }
    case 'purge-edge':
      await api.purgeEdgeCache(site.id);
      return {};
    case 'flush-object':
      await api.flushObjectCache(site.id);
      return {};
    case 'preload': {
      let edgeCacheTurnedOn = false;
      if (item.enabled && item.turnOnEdgeCache) {
        const edge = normalizeEdgeCache(await api.getEdgeCache(site.id));
        if (edge && !edge.active) {
          await api.setEdgeCache(site.id, true);
          edgeCacheTurnedOn = true;
        }
      }
      const preload = normalizePreload(await api.setCachePreload(site.id, item.enabled));
      return { preload, edgeCacheTurnedOn };
    }
    default:
      throw new Error(`Unknown task ${item.kind}`);
  }
}

async function executeRun({ sites, items, config }) {
  const api = await getClient();
  const run = { id: Date.now(), cancelled: false };
  currentRun = run;
  const total = sites.length * items.length;
  const emit = (payload) => send('run:event', { runId: run.id, ...payload });

  emit({ kind: 'started', total, siteCount: sites.length, items });
  await appendRunLog({ event: 'run:started', runId: run.id, siteIds: sites.map((s) => s.id), items });

  let index = 0;
  for (const site of sites) {
    if (run.cancelled) break;
    for (const item of items) {
      if (run.cancelled) break;
      index += 1;
      emit({ kind: 'item:started', siteId: site.id, item, index, total });
      try {
        const result = await runItem(api, site, item);
        const { response, ...forRenderer } = result;
        emit({ kind: 'item:done', siteId: site.id, item, index, total, result: forRenderer });
        await appendRunLog({ event: 'item:done', runId: run.id, siteId: site.id, item, result });
      } catch (err) {
        emit({
          kind: 'item:failed',
          siteId: site.id,
          item,
          index,
          total,
          error: err.message,
          status: err.status || null,
          code: err.code || null,
        });
        await appendRunLog({ event: 'item:failed', runId: run.id, siteId: site.id, item, error: err.message, status: err.status || null, code: err.code || null, errors: err.errors || [] });
      }
    }
    if (!run.cancelled && config.delayBetweenSitesMs > 0 && site !== sites[sites.length - 1]) {
      await sleep(config.delayBetweenSitesMs);
    }
  }

  emit({ kind: 'finished', cancelled: run.cancelled, total });
  await appendRunLog({ event: 'run:finished', runId: run.id, cancelled: run.cancelled });
  if (currentRun === run) currentRun = null;
  return run.id;
}

// ---------- Vulnerability checks ----------
//
// Pulls Pressable's plugin/theme security alerts (WPScan data) for each
// site, groups them into one finding per vulnerability with every affected
// site, enriches each CVE with its official record, and optionally posts the
// new ones to a Slack/Discord webhook. "New" means not yet sent to the
// webhook; sending marks findings as reported.

async function scanTargets(api, config, scope, siteId) {
  const all = (await api.listAllSites()).map(compactSite);
  if (scope === 'single') {
    const t = all.filter((s) => String(s.id) === String(siteId));
    if (t.length === 0) throw new Error('That site was not found on your account.');
    return t;
  }
  if (scope === 'list') {
    const wanted = new Set((config.siteIds || []).map(String));
    const t = all.filter((s) => wanted.has(String(s.id)));
    if (t.length === 0) throw new Error('Your list is empty. Tick the sites you want on the left.');
    return t;
  }
  if (all.length === 0) throw new Error('No sites found on your account.');
  return all;
}

async function executeSecurityScan({ targets, scope, notify, trigger }) {
  const api = await getClient();
  const config = await loadConfig();
  const scan = { id: Date.now(), cancelled: false };
  currentScan = scan;
  const emit = (payload) => send('scan:event', { scanId: scan.id, ...payload });

  emit({ kind: 'started', total: targets.length, scope, trigger });
  await appendRunLog({ event: 'scan:started', scanId: scan.id, scope, trigger, siteIds: targets.map((s) => s.id) });

  const perSite = [];
  const errors = [];
  let index = 0;
  for (const site of targets) {
    if (scan.cancelled) break;
    index += 1;
    emit({ kind: 'site', index, total: targets.length, siteId: site.id, siteName: site.displayName });
    try {
      const [plugins, themes] = await Promise.all([
        api.listSecurityAlerts(site.id, 'plugins'),
        api.listSecurityAlerts(site.id, 'themes'),
      ]);
      const vulns = [
        ...security.extractVulnerabilities(plugins, 'plugin'),
        ...security.extractVulnerabilities(themes, 'theme'),
      ];
      perSite.push({ site, vulns });
      if (vulns.length > 0) {
        await appendRunLog({ event: 'scan:site', scanId: scan.id, siteId: site.id, count: vulns.length, raw: { plugins, themes } });
      }
    } catch (err) {
      errors.push({ siteId: site.id, siteName: site.displayName, error: err.message });
      await appendRunLog({ event: 'scan:site-failed', scanId: scan.id, siteId: site.id, error: err.message });
    }
    if (!scan.cancelled && index < targets.length) await sleep(Math.min(config.delayBetweenSitesMs || 0, 600));
  }

  let findings = security.groupFindings(perSite);
  const cache = await readJson(cveCachePath(), {});
  if (findings.length > 0) {
    if (!scan.cancelled) emit({ kind: 'enriching', total: findings.length });
    await security.enrichFindings(findings, {
      cache,
      nvdApiKey: config.nvdApiKey || null,
      // A cancelled scan still shapes what it has, but makes no lookups.
      fetchImpl: scan.cancelled ? async () => ({ ok: false, status: 404 }) : undefined,
      delayMs: scan.cancelled ? 0 : 300,
      onProgress: (done, total, f) => { if (!scan.cancelled) emit({ kind: 'enrich', done, total, cve: f.cves[0] || null }); },
    });
    if (!scan.cancelled) await writeJson(cveCachePath(), cache);
  }

  const seen = await readJson(seenFindingsPath(), {});
  security.markNew(findings, seen);
  findings = security.sortFindings(findings);

  const result = {
    scanId: scan.id,
    at: new Date().toISOString(),
    scope,
    trigger,
    siteCount: targets.length,
    checked: perSite.length,
    cancelled: scan.cancelled,
    errors,
    findings,
    newCount: findings.filter((f) => f.isNew).length,
    notified: null,
  };

  if (notify && config.webhookUrl && !scan.cancelled && result.newCount > 0) {
    try {
      const sentCount = await notifyWebhook(config, findings, { onlyNew: true });
      result.notified = { ok: true, findings: result.newCount, messages: sentCount };
      await writeJson(seenFindingsPath(), security.rememberFindings(findings, seen));
      security.markNew(findings, security.rememberFindings(findings, seen)); // nothing is "new" once sent
      result.findings = findings;
      result.newCount = 0;
      result.notified.reported = true;
    } catch (err) {
      result.notified = { ok: false, error: err.message };
    }
  }

  await writeJson(lastFindingsPath(), result);
  await appendRunLog({ event: 'scan:finished', scanId: scan.id, findings: findings.length, newCount: result.newCount, notified: result.notified, errors: errors.length, cancelled: scan.cancelled });
  emit({ kind: 'finished', result });
  if (currentScan === scan) currentScan = null;
  return result;
}

// Sends findings (all, or just the ones not yet reported) to the webhook.
async function notifyWebhook(config, findings, { onlyNew }) {
  const kind = security.webhookKind(config.webhookUrl);
  if (!kind) throw new Error('Add a Slack or Discord webhook URL in Settings first.');
  let toSend = findings;
  if (onlyNew) {
    toSend = findings
      .filter((f) => f.isNew)
      .map((f) => ({ ...f, sites: f.sites.filter((s) => s.isNew) }));
  }
  if (toSend.length === 0) return 0;
  const label = client && client.identity ? client.identity.name || client.identity.email : null;
  const payloads = security.buildWebhookPayloads(kind, toSend, { onlyNew, accountLabel: label });
  return security.sendWebhook(config.webhookUrl, payloads);
}

async function loadLastFindings() {
  const result = await readJson(lastFindingsPath(), null);
  if (!result) return null;
  const seen = await readJson(seenFindingsPath(), {});
  security.markNew(result.findings || [], seen);
  result.newCount = (result.findings || []).filter((f) => f.isNew).length;
  return result;
}

// Once a day while the app is open, if enabled.
async function maybeScheduledScan() {
  try {
    const config = await loadConfig();
    if (!config.dailyCheck || currentScan) return;
    const last = await readJson(lastFindingsPath(), null);
    const lastAt = last && last.at ? new Date(last.at).getTime() : 0;
    if (Date.now() - lastAt < 24 * 3600 * 1000) return;
    const api = await getClient();
    const targets = await scanTargets(api, config, config.securityScope === 'list' ? 'list' : 'all');
    await executeSecurityScan({ targets, scope: config.securityScope === 'list' ? 'list' : 'all', notify: config.alertAutomatically, trigger: 'scheduled' });
  } catch (err) {
    await appendRunLog({ event: 'scan:scheduled-skipped', error: err.message });
  }
}

// ---------- IPC ----------

function registerIpc() {
  ipcMain.handle('credentials:status', async () => {
    const creds = await loadCredentials();
    return {
      configured: Boolean(creds),
      clientIdHint: creds ? `${creds.clientId.slice(0, 6)}…${creds.clientId.slice(-4)}` : null,
      encrypted: safeStorage.isEncryptionAvailable(),
      identity: client ? client.identity : null,
    };
  });

  ipcMain.handle('credentials:save', async (_event, { clientId, clientSecret }) => {
    const id = String(clientId || '').trim();
    const secret = String(clientSecret || '').trim();
    if (!id || !secret) throw new Error('Both the client ID and the client secret are required.');

    // Prove the pair works before storing it.
    const candidate = new PressableClient({ clientId: id, clientSecret: secret });
    await candidate.getToken(true);
    const account = await candidate.getAccount();

    await saveCredentials({ clientId: id, clientSecret: secret });
    client = candidate;
    return {
      identity: candidate.identity,
      account: account
        ? { name: account.name, email: account.email, organization: account.organization, sitesCount: account.sitesCount }
        : null,
    };
  });

  ipcMain.handle('credentials:clear', async () => {
    await clearCredentials();
    client = null;
    return true;
  });

  ipcMain.handle('config:get', () => loadConfig());
  ipcMain.handle('config:set', (_event, patch) => saveConfig(patch || {}));

  ipcMain.handle('sites:list', async () => {
    const api = await getClient();
    const sites = await api.listAllSites();
    return sites.map(compactSite).sort((a, b) => a.displayName.localeCompare(b.displayName));
  });

  ipcMain.handle('backups:list', async (_event, siteId) => {
    const api = await getClient();
    const list = await api.listOndemandBackups(siteId);
    return list.map(normalizeBackup).filter(Boolean).map(({ raw, ...rest }) => rest);
  });

  // Poll the state of backups created during a run. Items that came back
  // from the create call without an id are matched against the site's backup
  // list instead: the newest backup of that type made since we asked for it.
  ipcMain.handle('backups:status', async (_event, items) => {
    const api = await getClient();
    const out = [];
    const listCache = new Map();
    const listFor = async (siteId) => {
      if (!listCache.has(siteId)) {
        listCache.set(siteId, (await api.listOndemandBackups(siteId)).map(normalizeBackup).filter(Boolean));
      }
      return listCache.get(siteId);
    };

    for (const item of items || []) {
      const { siteId, type, backupId, requestedAt } = item;
      try {
        let backup = null;
        if (backupId !== null && backupId !== undefined) {
          backup = normalizeBackup(await api.getOndemandBackup(siteId, backupId));
        } else {
          const since = new Date(requestedAt || 0).getTime() - 120_000;
          const candidates = (await listFor(siteId))
            .filter((b) => b.type === type)
            .filter((b) => !b.created || new Date(b.created).getTime() >= since)
            .sort((a, b) => {
              const byDate = new Date(b.created || 0) - new Date(a.created || 0);
              return byDate !== 0 ? byDate : Number(b.id) - Number(a.id);
            });
          backup = candidates[0] || null;
        }
        const state = backup ? backup.state : null;
        out.push({
          siteId,
          type,
          backupId: backup ? backup.id : backupId ?? null,
          state,
          final: isFinalState(state),
          failed: isFailedState(state),
          found: Boolean(backup),
        });
      } catch (err) {
        out.push({ siteId, type, backupId: backupId ?? null, state: null, error: err.message, final: false, failed: false, found: false });
      }
    }
    return out;
  });

  ipcMain.handle('run:start', async (_event, { mode, siteId, task }) => {
    if (currentRun) throw new Error('A run is already in progress.');
    const api = await getClient();
    const config = await loadConfig();
    const effectiveTask = { ...config.task, ...(task || {}) };
    const items = expandTask(effectiveTask);
    if (items.length === 0) throw new Error('Choose at least one option for this task.');

    const all = (await api.listAllSites()).map(compactSite);
    let targets;
    if (mode === 'single') {
      targets = all.filter((s) => String(s.id) === String(siteId));
      if (targets.length === 0) throw new Error('That site was not found on your account.');
    } else {
      const wanted = new Set((config.siteIds || []).map(String));
      targets = all.filter((s) => wanted.has(String(s.id)));
      if (targets.length === 0) throw new Error('Your list is empty. Tick the sites you want on the left.');
    }

    // Don't block the IPC reply; progress streams back over run:event.
    executeRun({ sites: targets, items, config }).catch((err) => {
      send('run:event', { kind: 'error', error: err.message });
      currentRun = null;
    });
    return { siteCount: targets.length, items };
  });

  // Current edge cache + cache preload state for one site (the single-site panel).
  ipcMain.handle('site:cacheStatus', async (_event, siteId) => {
    const api = await getClient();
    const [edge, preload] = await Promise.allSettled([
      api.getEdgeCache(siteId),
      api.getCachePreload(siteId),
    ]);
    return {
      edge: edge.status === 'fulfilled' ? normalizeEdgeCache(edge.value) : null,
      edgeError: edge.status === 'rejected' ? edge.reason.message : null,
      preload: preload.status === 'fulfilled' ? normalizePreload(preload.value) : null,
      preloadError: preload.status === 'rejected' ? preload.reason.message : null,
    };
  });

  ipcMain.handle('run:cancel', () => {
    if (currentRun) currentRun.cancelled = true;
    return Boolean(currentRun);
  });

  // ----- Vulnerability checks -----

  ipcMain.handle('security:scan', async (_event, { scope, siteId, notify }) => {
    if (currentScan) throw new Error('A vulnerability check is already running.');
    const api = await getClient();
    const config = await loadConfig();
    const targets = await scanTargets(api, config, scope, siteId);
    executeSecurityScan({
      targets,
      scope,
      notify: notify !== undefined ? Boolean(notify) : config.alertAutomatically,
      trigger: 'manual',
    }).catch((err) => {
      send('scan:event', { kind: 'error', error: err.message });
      currentScan = null;
    });
    return { siteCount: targets.length };
  });

  ipcMain.handle('security:cancel', () => {
    if (currentScan) currentScan.cancelled = true;
    return Boolean(currentScan);
  });

  ipcMain.handle('security:lastResult', () => loadLastFindings());

  ipcMain.handle('security:notify', async (_event, { onlyNew }) => {
    const config = await loadConfig();
    const result = await loadLastFindings();
    if (!result || !result.findings || result.findings.length === 0) throw new Error('Run a vulnerability check first.');
    const sent = await notifyWebhook(config, result.findings, { onlyNew: Boolean(onlyNew) });
    if (sent === 0) return { sent: 0, findings: 0 };
    const seen = await readJson(seenFindingsPath(), {});
    const reported = onlyNew ? result.findings.filter((f) => f.isNew) : result.findings;
    await writeJson(seenFindingsPath(), security.rememberFindings(reported, seen));
    return { sent, findings: reported.length };
  });

  ipcMain.handle('security:testWebhook', async (_event, { url }) => {
    const kind = security.webhookKind(url);
    if (!kind) throw new Error('Enter a webhook URL first.');
    await security.sendWebhook(url, security.testPayload(kind));
    return { kind };
  });

  ipcMain.handle('shell:openExternal', (_event, url) => {
    if (typeof url === 'string' && /^https:\/\//.test(url)) {
      return shell.openExternal(url);
    }
    return false;
  });

  ipcMain.handle('shell:openDataFolder', () => shell.openPath(userDataDir()));
}

// ---------- Auto-update ----------
//
// Installed builds check the GitHub Releases of the repository named in
// package.json, download a newer version in the background, and apply it on
// the next launch (electron-updater notifies the person when a download is
// ready). Needs a public repository, and on macOS a signed build; otherwise
// it fails quietly and logs the reason.

function setupAutoUpdate() {
  if (!app.isPackaged) return;
  try {
    const { autoUpdater } = require('electron-updater');
    autoUpdater.logger = null;
    autoUpdater.on('error', (err) => appendRunLog({ event: 'update:error', error: err.message }));
    autoUpdater.on('update-downloaded', (info) => appendRunLog({ event: 'update:downloaded', version: info.version }));
    autoUpdater.checkForUpdatesAndNotify().catch(() => {});
    setInterval(() => autoUpdater.checkForUpdatesAndNotify().catch(() => {}), 6 * 3600 * 1000).unref();
  } catch (err) {
    appendRunLog({ event: 'update:unavailable', error: err.message });
  }
}

// ---------- App lifecycle ----------

app.whenReady().then(() => {
  registerIpc();
  createWindow();
  setupAutoUpdate();
  // unref: the window keeps Electron alive; these timers never should.
  setTimeout(maybeScheduledScan, 20_000).unref();
  setInterval(maybeScheduledScan, 30 * 60_000).unref();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
