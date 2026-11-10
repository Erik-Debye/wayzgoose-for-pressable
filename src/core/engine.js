'use strict';

// Everything Wayzgoose does, independent of how it is hosted. The Electron
// app (src/main.js) and the self-hosted server (src/server/server.js) both
// create one engine and expose its handlers: the Electron app over IPC, the
// server over HTTP, with progress events streamed back on either.
//
// createEngine({ dataDir, credentials, emit })
//   dataDir      folder for config.json, runs.log, admins.json, ...
//   credentials  { load(), save({clientId, clientSecret}), clear(), encrypted() }
//   emit(channel, payload)  'run:event' | 'scan:event' | 'audit:event' | 'sentinel:event'

const path = require('node:path');
const fs = require('node:fs/promises');
const fsSync = require('node:fs');
const {
  PressableClient,
  normalizeBackup,
  normalizePreload,
  normalizeEdgeCache,
  isFinalState,
  isFailedState,
  sleep,
} = require('../pressable');
const security = require('../security');
const users = require('../users');
const uptime = require('../uptime');
const configCheck = require('../config-check');
const phplogs = require('../phplogs');
const pkg = require('../../package.json');

const SESSION_CHECK_PHP = fsSync.readFileSync(path.join(__dirname, '..', '..', 'scripts', 'session-check.php'), 'utf8');
const CONFIG_REPORT_PHP = fsSync.readFileSync(path.join(__dirname, '..', '..', 'scripts', 'config-report.php'), 'utf8');

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
  // Privileged-user audit + on-site sentinel
  userWebhookUrl: '',
  watchedRoles: 'administrator',
  userAlertAutomatically: true,
};


function createEngine({ dataDir, credentials, emit }) {
  let client = null;
  let currentRun = null;
  let currentScan = null;
  let currentAudit = null;
  let currentUptime = null;
  let currentConfig = null;
  let sitesCache = { at: 0, sites: [] };
  const send = emit;
  const handlers = {};

  // ---------- Paths & storage ----------

  const userDataDir = () => dataDir;
  const configPath = () => path.join(userDataDir(), 'config.json');
  const runLogPath = () => path.join(userDataDir(), 'runs.log');
  const seenFindingsPath = () => path.join(userDataDir(), 'seen-findings.json');
  const cveCachePath = () => path.join(userDataDir(), 'cve-cache.json');
  const lastFindingsPath = () => path.join(userDataDir(), 'last-findings.json');
  const adminsSnapshotPath = () => path.join(userDataDir(), 'admins.json');
  const lastAuditPath = () => path.join(userDataDir(), 'last-audit.json');
  const scheduleStatePath = () => path.join(userDataDir(), 'schedule.json');
  const uptimeStatePath = () => path.join(userDataDir(), 'uptime.json');
  const lastConfigPath = () => path.join(userDataDir(), 'last-config.json');
  const phpErrorsPath = () => path.join(userDataDir(), 'php-errors.json');

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


  const loadCredentials = () => credentials.load();
  const saveCredentials = (c) => credentials.save(c);
  const clearCredentials = () => credentials.clear();

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
      const scope = config.securityScope === 'list' ? 'list' : 'all';
      const targets = await scanTargets(api, config, scope);
      await executeSecurityScan({ targets, scope, notify: config.alertAutomatically, trigger: 'scheduled' });
      if (!currentAudit) {
        await executeUserAudit({ targets, scope, notify: config.userAlertAutomatically, trigger: 'scheduled' });
      }
    } catch (err) {
      await appendRunLog({ event: 'scan:scheduled-skipped', error: err.message });
    }
  }

  // ---------- Privileged-user audit ----------
  //
  // Lists each site's WordPress users through the API, keeps the ones holding
  // a watched role, diffs against admins.json and reports additions, role
  // changes and removals. The first run on a site records a baseline silently.

  async function executeUserAudit({ targets, scope, notify, trigger }) {
    const api = await getClient();
    const config = await loadConfig();
    const watched = users.parseWatchedRoles(config.watchedRoles);
    const audit = { id: Date.now(), cancelled: false };
    currentAudit = audit;
    const emit = (payload) => send('audit:event', { auditId: audit.id, ...payload });

    emit({ kind: 'started', total: targets.length, scope, trigger });
    await appendRunLog({ event: 'audit:started', auditId: audit.id, scope, trigger, siteIds: targets.map((s) => s.id), watched });

    const snapshot = await readJson(adminsSnapshotPath(), {});
    const sites = [];
    const events = [];
    const errors = [];
    let index = 0;
    for (const site of targets) {
      if (audit.cancelled) break;
      index += 1;
      emit({ kind: 'site', index, total: targets.length, siteId: site.id, siteName: site.displayName });
      try {
        const raw = await api.listWordpressUsers(site.id);
        const all = raw.map(users.normalizeUser).filter(Boolean);
        const privileged = all.filter((u) => users.isPrivileged(u, watched));
        const before = snapshot[String(site.id)] || null;
        const diff = users.diffPrivileged(before, privileged);
        snapshot[String(site.id)] = diff.snapshot;
        const siteEvents = [
          ...diff.added.map((user) => ({ kind: 'added', user })),
          ...diff.changed.map((c) => ({ kind: 'changed', user: c.user, from: c.from, to: c.to })),
          ...diff.removed.map((user) => ({ kind: 'removed', user })),
        ].map((ev) => ({ ...ev, siteId: site.id, siteName: site.displayName, siteUrl: site.url }));
        if (siteEvents.length > 0) {
          emit({ kind: 'forensics', siteId: site.id, siteName: site.displayName });
          const forensics = await gatherForensics(api, site.id, {
            since: before && before.checkedAt ? new Date(new Date(before.checkedAt).getTime() - 5 * 60_000).toISOString() : null,
            until: new Date().toISOString(),
          });
          for (const ev of siteEvents) ev.forensics = forensics;
          await appendRunLog({ event: 'audit:forensics', auditId: audit.id, siteId: site.id, requests: forensics.requests.length, activity: forensics.activity.length, error: forensics.error });

          // Ask the site itself which role-capable users were logged in. It
          // answers in the channel, a little after this alert (job queue).
          const sessionCheck = { requested: false, error: null };
          if (notify && config.userWebhookUrl) {
            try {
              const command = users.buildSessionCheckCommand(SESSION_CHECK_PHP, {
                webhook: config.userWebhookUrl,
                since: Math.floor(new Date(forensics.window.since || Date.now() - 24 * 3600_000).getTime() / 1000),
                until: Math.floor(new Date(forensics.window.until).getTime() / 1000),
                ips: [...new Set(forensics.requests.map((r) => r.ip).filter(Boolean))].slice(0, 20),
                site: site.url || site.displayName,
                event: siteEvents.map((e) => `${e.kind}: ${e.user.login || 'unknown'}`).join(', '),
              });
              await api.runWpCli(site.id, [command]);
              sessionCheck.requested = true;
            } catch (err) {
              sessionCheck.error = err.message;
            }
            await appendRunLog({ event: 'audit:session-check', auditId: audit.id, siteId: site.id, ...sessionCheck });
          }
          for (const ev of siteEvents) ev.sessionCheck = sessionCheck;
        }
        events.push(...siteEvents);
        sites.push({
          siteId: site.id,
          siteName: site.displayName,
          url: site.url,
          totalUsers: all.length,
          privileged: privileged.map((u) => ({ ...u, isNew: diff.added.includes(u), changed: diff.changed.some((c) => c.user === u) })),
          removed: diff.removed,
          baseline: diff.baseline,
        });
        if (all.length > 0 && all.every((u) => u.roles.length === 0)) {
          errors.push({ siteId: site.id, siteName: site.displayName, error: 'The API returned users without roles; see runs.log for the raw shape.' });
          await appendRunLog({ event: 'audit:no-roles', auditId: audit.id, siteId: site.id, sample: raw.slice(0, 2) });
        }
      } catch (err) {
        errors.push({ siteId: site.id, siteName: site.displayName, error: err.message });
        await appendRunLog({ event: 'audit:site-failed', auditId: audit.id, siteId: site.id, error: err.message });
      }
      if (!audit.cancelled && index < targets.length) await sleep(Math.min(config.delayBetweenSitesMs || 0, 600));
    }

    if (!audit.cancelled) await writeJson(adminsSnapshotPath(), snapshot);

    const result = {
      auditId: audit.id,
      at: new Date().toISOString(),
      scope,
      trigger,
      watched,
      siteCount: targets.length,
      checked: sites.length,
      cancelled: audit.cancelled,
      sites,
      events,
      errors,
      notified: null,
    };

    if (notify && config.userWebhookUrl && !audit.cancelled && events.length > 0) {
      try {
        const kind = security.webhookKind(config.userWebhookUrl);
        const label = client && client.identity ? client.identity.name || client.identity.email : null;
        const sent = await security.sendWebhook(config.userWebhookUrl, users.buildAuditPayloads(kind, events, { accountLabel: label }));
        result.notified = { ok: true, events: events.length, messages: sent };
      } catch (err) {
        result.notified = { ok: false, error: err.message };
      }
    }

    await writeJson(lastAuditPath(), result);
    await appendRunLog({ event: 'audit:finished', auditId: audit.id, events: events.length, errors: errors.length, notified: result.notified, cancelled: audit.cancelled });
    emit({ kind: 'finished', result });
    if (currentAudit === audit) currentAudit = null;
    return result;
  }

  // Pull the site's write requests to user-management endpoints and its
  // Pressable activity for the window since the last audit. Best effort: the
  // web server log keeps 7 days or 10,000 entries, whichever runs out first.
  async function gatherForensics(api, siteId, window) {
    const forensics = { window, requests: [], activity: [], requestsChecked: false, error: null };
    const since = window.since ? new Date(window.since).getTime() : 0;
    try {
      const raw = [];
      for (const requestType of ['POST', 'PUT', 'PATCH', 'DELETE']) {
        let scrollId = null;
        for (let page = 0; page < 10; page += 1) {
          const { logs, scrollId: next } = await api.listWebserverLogs(siteId, { requestType, scrollId });
          raw.push(...logs);
          const oldest = logs.map(users.normalizeLogEntry).filter((e) => e && e.time).map((e) => e.time.getTime());
          if (logs.length < 200 || !next || (oldest.length && Math.min(...oldest) < since)) break;
          scrollId = next;
        }
      }
      forensics.requests = users.relevantRequests(raw, window);
      forensics.requestsChecked = true;
    } catch (err) {
      forensics.error = `web server log: ${err.message}`;
    }
    try {
      const activity = await api.listSiteActivity(siteId, { page: 1, perPage: 100 });
      forensics.activity = users.relevantActivity(activity, window);
    } catch (err) {
      forensics.error = forensics.error ? `${forensics.error}; activity log: ${err.message}` : `activity log: ${err.message}`;
    }
    // Keep the stored result small.
    forensics.requests = forensics.requests.slice(0, 25).map((r) => ({ ...r, time: r.time ? r.time.toISOString() : null }));
    forensics.activity = forensics.activity.slice(0, 25).map((a) => ({ ...a, time: a.time ? a.time.toISOString() : null }));
    return forensics;
  }

  // ---------- Sentinel (on-site mu-plugin) ----------
  //
  // Registers mu-plugin/wayzgoose-sentinel.php from this project's repository
  // as an account-wide must-use plugin (existing and future sites), then writes
  // the webhook and watched roles into each target site through WP-CLI and
  // fires the plugin's test hook so every site confirms itself in the channel.

  async function ensureSentinelRegistered(api) {
    const source = users.sentinelSourceUrl(pkg.repository && pkg.repository.url);
    if (!source) throw new Error('package.json has no GitHub repository URL to load the sentinel from.');
    const existing = (await api.listMuPlugins()).find((m) => String(m.path || m.url || '').includes('wayzgoose-sentinel.php'));
    if (existing) {
      await api.updateMuPlugin(existing.id, { path: source, existingSites: true, futureSites: true });
      return { id: existing.id, source, action: 'updated' };
    }
    const created = await api.createMuPlugin({ path: source, existingSites: true, futureSites: true });
    return { id: created && created.id, source, action: 'created' };
  }

  async function installSentinel({ targets }) {
    const api = await getClient();
    const config = await loadConfig();
    if (!config.userWebhookUrl) throw new Error('Add a webhook for user privilege alerts in Settings first.');
    const watched = users.parseWatchedRoles(config.watchedRoles);
    const commands = users.sentinelConfigCommands(config.userWebhookUrl, watched);
    const emit = (payload) => send('sentinel:event', payload);

    emit({ kind: 'started', total: targets.length });
    let registration;
    try {
      registration = await ensureSentinelRegistered(api);
      emit({ kind: 'registered', ...registration });
      await appendRunLog({ event: 'sentinel:registered', ...registration });
    } catch (err) {
      emit({ kind: 'finished', result: { ok: false, error: `Could not register the mu-plugin: ${err.message}`, sites: [] } });
      await appendRunLog({ event: 'sentinel:register-failed', error: err.message });
      return;
    }

    const sites = [];
    let index = 0;
    for (const site of targets) {
      index += 1;
      emit({ kind: 'site', index, total: targets.length, siteId: site.id, siteName: site.displayName });
      const entry = { siteId: site.id, siteName: site.displayName, configured: null, tested: false, error: null };
      try {
        try {
          await api.runWpCli(site.id, commands.constants);
          entry.configured = 'wp-config constant';
        } catch (err) {
          await api.runWpCli(site.id, commands.options);
          entry.configured = `option (wp-config not writable: ${err.message})`;
        }
        try {
          await api.runWpCli(site.id, commands.test);
          entry.tested = true;
        } catch (err) {
          entry.error = `Configured, but the test message failed: ${err.message}`;
        }
      } catch (err) {
        entry.error = err.message;
      }
      sites.push(entry);
      await appendRunLog({ event: 'sentinel:site', ...entry });
      if (index < targets.length) await sleep(Math.min(config.delayBetweenSitesMs || 0, 600));
    }
    const result = { ok: true, registration, sites };
    emit({ kind: 'finished', result });
    return result;
  }


  // Site list cached briefly so frequent uptime checks don't hit the API each time.
  async function getSitesCached(maxAgeMs = 30 * 60_000) {
    if (Date.now() - sitesCache.at < maxAgeMs && sitesCache.sites.length) return sitesCache.sites;
    const api = await getClient();
    sitesCache = { at: Date.now(), sites: (await api.listAllSites()).map(compactSite) };
    return sitesCache.sites;
  }

  // ---------- Uptime ----------
  //
  // Fetches each site's homepage. A site that fails is probed once more after
  // a short pause inside the same check; it is reported down once it has
  // failed uptimeFailuresToAlert checks in a row, and reported back up once.

  async function uptimeTargets(config, scope, siteId) {
    const all = await getSitesCached(scope === 'single' ? 0 : undefined);
    if (scope === 'single') {
      const t = all.filter((s) => String(s.id) === String(siteId));
      if (t.length === 0) throw new Error('That site was not found on your account.');
      return t;
    }
    let targets = all;
    if (scope === 'list') {
      const wanted = new Set((config.siteIds || []).map(String));
      targets = all.filter((s) => wanted.has(String(s.id)));
      if (targets.length === 0) throw new Error('Your list is empty. Tick the sites you want on the left.');
    }
    if (!config.uptimeIncludeStaging) targets = targets.filter((s) => !s.staging && !s.sandbox);
    targets = targets.filter((s) => !s.state || s.state === 'live');
    if (targets.length === 0) throw new Error('No live sites to check.');
    return targets;
  }

  async function executeUptimeCheck({ targets, scope, notify, trigger }) {
    const config = await loadConfig();
    const check = { id: Date.now(), cancelled: false };
    currentUptime = check;
    const emit = (payload) => send('uptime:event', { checkId: check.id, ...payload });
    const stored = await readJson(uptimeStatePath(), { sites: {} });
    const failuresToAlert = Math.max(1, Number(config.uptimeFailuresToAlert) || 2);

    emit({ kind: 'started', total: targets.length, scope, trigger });
    const sites = [];
    const events = [];
    let done = 0;

    const phpState = await readJson(phpErrorsPath(), { sites: {} });
    const phpEvery = Math.max(0, Number(config.phpLogEveryMinutes) || 0);
    const api = phpEvery > 0 ? await getClient().catch(() => null) : null;

    const checkOne = async (site) => {
      const url = uptime.siteUrl(site);
      if (!url) return;
      let result = await uptime.probe(url);
      if (!uptime.isUp(result) && !check.cancelled) {
        await sleep(5_000);
        result = await uptime.probe(url);
      }
      const prev = stored.sites[String(site.id)] || null;
      const { state, event } = uptime.nextState(prev, result, { failuresToAlert });
      const siteEvents = [];
      if (event) siteEvents.push({ ...event, detail: uptime.describeResult(result) });

      // TLS: once an hour, or right away when the probe failed on TLS.
      const host = (() => { try { return new URL(url).hostname; } catch { return null; } })();
      const tlsDue = host && (!state.tls || !state.tls.checkedAt || Date.now() - new Date(state.tls.checkedAt).getTime() > uptime.TLS_RECHECK_MS || (!uptime.isUp(result) && /TLS|certificate/i.test(result.error || '')));
      if (tlsDue) {
        const info = await uptime.checkTls(host);
        const { tls, event: tlsEvent } = uptime.nextTlsState(state.tls || null, info);
        state.tls = tls;
        if (tlsEvent) siteEvents.push(tlsEvent);
      }

      // PHP fatals: every phpLogEveryMinutes, from the API.
      let php = phpState.sites[String(site.id)] || null;
      const phpDue = api && phpEvery > 0 && (!php || !php.lastCheckedAt || Date.now() - new Date(php.lastCheckedAt).getTime() >= phpEvery * 60_000 - 5_000);
      if (phpDue) {
        try {
          const raw = [];
          for (const severity of ['Fatal error', 'Parse error']) {
            const { logs } = await api.listPhpLogs(site.id, { severity });
            raw.push(...logs);
          }
          const { state: next, events: phpEvents } = phplogs.triage(php, raw);
          php = next;
          phpState.sites[String(site.id)] = next;
          siteEvents.push(...phpEvents);
        } catch (err) {
          php = { ...(php || { signatures: {} }), lastError: err.message, lastErrorAt: new Date().toISOString() };
          phpState.sites[String(site.id)] = php;
          await appendRunLog({ event: 'uptime:php-log-failed', checkId: check.id, siteId: site.id, error: err.message });
        }
      }

      stored.sites[String(site.id)] = state;
      const entry = {
        siteId: site.id, siteName: site.displayName, url,
        status: state.status, since: state.since, failures: state.failures, lastChecked: state.lastChecked, lastResult: state.lastResult,
        detail: uptime.describeResult(result),
        tls: state.tls ? { validTo: state.tls.validTo, daysLeft: state.tls.daysLeft, issuer: state.tls.issuer, authorized: state.tls.authorized, authorizationError: state.tls.authorizationError, lastError: state.tls.lastError || null } : null,
        php: php ? { ...phplogs.summarize(php), lastError: php.lastError || null } : null,
      };
      sites.push(entry);
      for (const ev of siteEvents) {
        events.push({ ...ev, siteId: site.id, siteName: site.displayName, url });
        await appendRunLog({ event: `uptime:${ev.kind}`, checkId: check.id, siteId: site.id, url, detail: ev.detail || ev.sample || ev.validTo || null });
      }
      done += 1;
      emit({ kind: 'site', index: done, total: targets.length, siteId: site.id, siteName: site.displayName, status: state.status, detail: entry.detail });
    };

    // Five probes at a time.
    const queue = [...targets];
    const workers = Array.from({ length: Math.min(5, queue.length) }, async () => {
      while (queue.length && !check.cancelled) await checkOne(queue.shift());
    });
    await Promise.all(workers);

    sites.sort((a, b) => (a.status === b.status ? a.siteName.localeCompare(b.siteName) : a.status === 'down' ? -1 : b.status === 'down' ? 1 : 0));
    stored.lastRun = new Date().toISOString();
    await writeJson(uptimeStatePath(), stored);
    if (phpEvery > 0) await writeJson(phpErrorsPath(), phpState);

    const result = {
      checkId: check.id,
      at: stored.lastRun,
      scope,
      trigger,
      checked: sites.length,
      up: sites.filter((s) => s.status === 'up').length,
      down: sites.filter((s) => s.status === 'down').length,
      degraded: sites.filter((s) => s.status !== 'down' && s.failures > 0).length,
      sites,
      events,
      notified: null,
    };
    if (notify && config.uptimeWebhookUrl && events.length) {
      try {
        const kind = security.webhookKind(config.uptimeWebhookUrl);
        const label = client && client.identity ? client.identity.name || client.identity.email : null;
        const sent = await security.sendWebhook(config.uptimeWebhookUrl, uptime.buildUptimePayloads(kind, events, { accountLabel: label }));
        result.notified = { ok: true, events: events.length, messages: sent };
      } catch (err) {
        result.notified = { ok: false, error: err.message };
      }
    }
    await appendRunLog({ event: 'uptime:finished', checkId: check.id, trigger, checked: result.checked, down: result.down, events: events.length, notified: result.notified });
    emit({ kind: 'finished', result });
    if (currentUptime === check) currentUptime = null;
    return result;
  }

  async function loadUptime() {
    const stored = await readJson(uptimeStatePath(), null);
    if (!stored) return null;
    const phpState = await readJson(phpErrorsPath(), { sites: {} });
    const sites = Object.entries(stored.sites || {}).map(([siteId, st]) => {
      const php = phpState.sites[siteId];
      return {
        siteId,
        ...st,
        tls: st.tls ? { validTo: st.tls.validTo, daysLeft: st.tls.daysLeft, issuer: st.tls.issuer, authorized: st.tls.authorized, authorizationError: st.tls.authorizationError, lastError: st.tls.lastError || null } : null,
        php: php ? { ...phplogs.summarize(php), lastError: php.lastError || null } : null,
      };
    });
    return { at: stored.lastRun || null, sites };
  }

  // ---------- Config check ----------
  //
  // Compares what Pressable records for a site with what the site says
  // about itself from the outside (home/siteurl via the REST index,
  // redirects, canonical, noindex, robots.txt). With deep on, also sends a
  // WP-CLI job that posts the wp-config.php constants to the alerts webhook.

  async function configTargets(config, scope, siteId) {
    const all = await getSitesCached(scope === 'single' ? 0 : undefined);
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
    return all.filter((s) => !s.state || s.state === 'live');
  }

  async function executeConfigCheck({ targets, scope, deep, trigger }) {
    const api = await getClient();
    const config = await loadConfig();
    const check = { id: Date.now(), cancelled: false };
    currentConfig = check;
    const emit = (payload) => send('config:event', { checkId: check.id, ...payload });
    emit({ kind: 'started', total: targets.length, scope, deep: Boolean(deep), trigger });

    const sites = [];
    let done = 0;
    const checkOne = async (site) => {
      let full = site;
      try {
        const detail = await api.getSite(site.id);
        if (detail) full = { ...site, ...compactSite(detail), phpVersion: detail.phpVersion ?? detail.php_version ?? null, datacenterCode: detail.datacenterCode ?? detail.datacenter_code ?? null, raw: detail };
      } catch {
        // list data is enough
      }
      const { facts, findings } = await configCheck.inspectSite(full);
      const entry = { siteId: site.id, siteName: site.displayName, url: site.url, staging: Boolean(site.staging), sandbox: Boolean(site.sandbox), facts, findings, worst: configCheck.worst(findings), deep: null };
      if (deep && config.webhookUrl) {
        try {
          const command = users.buildEvalCommand(CONFIG_REPORT_PHP, {
            webhook: config.webhookUrl,
            pressableUrl: site.url || '',
            staging: Boolean(site.staging || site.sandbox),
            site: site.url || site.displayName,
          });
          await api.runWpCli(site.id, [command]);
          entry.deep = { requested: true };
        } catch (err) {
          entry.deep = { requested: false, error: err.message };
        }
      } else if (deep) {
        entry.deep = { requested: false, error: 'no alerts webhook configured' };
      }
      sites.push(entry);
      if (findings.some((f) => f.severity === 'high' || f.severity === 'medium')) {
        await appendRunLog({ event: 'config:findings', checkId: check.id, siteId: site.id, findings, facts });
      }
      done += 1;
      emit({ kind: 'site', index: done, total: targets.length, siteId: site.id, siteName: site.displayName, worst: entry.worst });
    };
    const queue = [...targets];
    const workers = Array.from({ length: Math.min(4, queue.length) }, async () => {
      while (queue.length && !check.cancelled) await checkOne(queue.shift());
    });
    await Promise.all(workers);

    const rank = { high: 0, medium: 1, low: 2, info: 3, ok: 4 };
    sites.sort((a, b) => rank[a.worst] - rank[b.worst] || a.siteName.localeCompare(b.siteName));
    const result = {
      checkId: check.id,
      at: new Date().toISOString(),
      scope,
      deep: Boolean(deep),
      trigger,
      checked: sites.length,
      withIssues: sites.filter((s) => s.worst === 'high' || s.worst === 'medium').length,
      sites,
    };
    await writeJson(lastConfigPath(), result);
    await appendRunLog({ event: 'config:finished', checkId: check.id, checked: result.checked, withIssues: result.withIssues, deep: result.deep });
    emit({ kind: 'finished', result });
    if (currentConfig === check) currentConfig = null;
    return result;
  }

  // ---------- Schedule ----------
  //
  // Runs whatever is due: the daily vulnerability check (plus a user audit
  // with it), a user audit every N hours, and a nightly backup of the list.
  // Safe to call often; each job checks its own last-run time.

  async function maybeScheduled() {
    await maybeScheduledScan();
    try {
      const config = await loadConfig();
      const state = await readJson(scheduleStatePath(), {});
      const now = new Date();

      if (config.auditEveryHours > 0 && !currentAudit) {
        const last = await readJson(lastAuditPath(), null);
        const lastAt = last && last.at ? new Date(last.at).getTime() : 0;
        if (now.getTime() - lastAt >= config.auditEveryHours * 3600_000) {
          const api = await getClient();
          const scope = config.securityScope === 'list' ? 'list' : 'all';
          const targets = await scanTargets(api, config, scope);
          await executeUserAudit({ targets, scope, notify: config.userAlertAutomatically, trigger: 'scheduled' });
        }
      }

      if (config.uptimeEveryMinutes > 0 && !currentUptime) {
        const last = await readJson(uptimeStatePath(), null);
        const lastAt = last && last.lastRun ? new Date(last.lastRun).getTime() : 0;
        if (now.getTime() - lastAt >= config.uptimeEveryMinutes * 60_000 - 5_000) {
          const scope = config.uptimeScope === 'list' ? 'list' : 'live';
          const targets = await uptimeTargets(config, scope);
          await executeUptimeCheck({ targets, scope, notify: true, trigger: 'scheduled' });
        }
      }

      if (/^\d{2}:\d{2}$/.test(config.backupListAt || '') && !currentRun) {
        const [hh, mm] = config.backupListAt.split(':').map(Number);
        const today = now.toISOString().slice(0, 10);
        const due = now.getHours() > hh || (now.getHours() === hh && now.getMinutes() >= mm);
        if (due && state.lastBackupDay !== today && (config.siteIds || []).length > 0) {
          state.lastBackupDay = today;
          await writeJson(scheduleStatePath(), state);
          const api = await getClient();
          const targets = await scanTargets(api, config, 'list');
          const items = expandTask({ ...config.task, kind: 'backup' });
          if (items.length) await executeRun({ sites: targets, items, config });
        }
      }
    } catch (err) {
      await appendRunLog({ event: 'schedule:skipped', error: err.message });
    }
  }

  function startScheduler({ firstDelayMs = 20_000, everyMs = 60_000 } = {}) {
    const first = setTimeout(maybeScheduled, firstDelayMs);
    const timer = setInterval(maybeScheduled, everyMs);
    if (first.unref) first.unref();
    if (timer.unref) timer.unref();
    return () => {
      clearTimeout(first);
      clearInterval(timer);
    };
  }

  // ---------- Handlers (one per IPC channel / HTTP route) ----------

  handlers['credentials:status'] = async () => {
    const creds = await loadCredentials();
    return {
      configured: Boolean(creds),
      clientIdHint: creds ? `${creds.clientId.slice(0, 6)}…${creds.clientId.slice(-4)}` : null,
      encrypted: credentials.encrypted(),
      identity: client ? client.identity : null,
    };
  };

  handlers['credentials:save'] = async ({ clientId, clientSecret }) => {
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
  };

  handlers['credentials:clear'] = async () => {
    await clearCredentials();
    client = null;
    return true;
  };

  handlers['config:get'] = () => loadConfig();
  handlers['config:set'] = (patch) => saveConfig(patch || {});

  handlers['sites:list'] = async () => {
    const api = await getClient();
    const sites = await api.listAllSites();
    return sites.map(compactSite).sort((a, b) => a.displayName.localeCompare(b.displayName));
  };

  handlers['backups:list'] = async (siteId) => {
    const api = await getClient();
    const list = await api.listOndemandBackups(siteId);
    return list.map(normalizeBackup).filter(Boolean).map(({ raw, ...rest }) => rest);
  };

  // Poll the state of backups created during a run. Items that came back
  // from the create call without an id are matched against the site's backup
  // list instead: the newest backup of that type made since we asked for it.
  handlers['backups:status'] = async (items) => {
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
  };

  handlers['run:start'] = async ({ mode, siteId, task }) => {
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
  };

  // Current edge cache + cache preload state for one site (the single-site panel).
  handlers['site:cacheStatus'] = async (siteId) => {
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
  };

  handlers['run:cancel'] = () => {
    if (currentRun) currentRun.cancelled = true;
    return Boolean(currentRun);
  };

  // ----- Vulnerability checks -----

  handlers['security:scan'] = async ({ scope, siteId, notify }) => {
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
  };

  handlers['security:cancel'] = () => {
    if (currentScan) currentScan.cancelled = true;
    return Boolean(currentScan);
  };

  handlers['security:lastResult'] = () => loadLastFindings();

  handlers['security:notify'] = async ({ onlyNew }) => {
    const config = await loadConfig();
    const result = await loadLastFindings();
    if (!result || !result.findings || result.findings.length === 0) throw new Error('Run a vulnerability check first.');
    const sent = await notifyWebhook(config, result.findings, { onlyNew: Boolean(onlyNew) });
    if (sent === 0) return { sent: 0, findings: 0 };
    const seen = await readJson(seenFindingsPath(), {});
    const reported = onlyNew ? result.findings.filter((f) => f.isNew) : result.findings;
    await writeJson(seenFindingsPath(), security.rememberFindings(reported, seen));
    return { sent, findings: reported.length };
  };

  handlers['security:testWebhook'] = async ({ url }) => {
    const kind = security.webhookKind(url);
    if (!kind) throw new Error('Enter a webhook URL first.');
    await security.sendWebhook(url, security.testPayload(kind));
    return { kind };
  };

  // ----- Privileged-user audit & sentinel -----

  handlers['users:audit'] = async ({ scope, siteId, notify }) => {
    if (currentAudit) throw new Error('A user audit is already running.');
    const api = await getClient();
    const config = await loadConfig();
    const targets = await scanTargets(api, config, scope, siteId);
    executeUserAudit({
      targets,
      scope,
      notify: notify !== undefined ? Boolean(notify) : config.userAlertAutomatically,
      trigger: 'manual',
    }).catch((err) => {
      send('audit:event', { kind: 'error', error: err.message });
      currentAudit = null;
    });
    return { siteCount: targets.length };
  };

  handlers['users:cancel'] = () => {
    if (currentAudit) currentAudit.cancelled = true;
    return Boolean(currentAudit);
  };

  handlers['users:lastResult'] = () => readJson(lastAuditPath(), null);

  handlers['sentinel:install'] = async ({ scope, siteId }) => {
    const api = await getClient();
    const config = await loadConfig();
    const targets = await scanTargets(api, config, scope, siteId);
    installSentinel({ targets }).catch((err) => send('sentinel:event', { kind: 'finished', result: { ok: false, error: err.message, sites: [] } }));
    return { siteCount: targets.length };
  };

  handlers['sentinel:status'] = async () => {
    const api = await getClient();
    const source = users.sentinelSourceUrl(pkg.repository && pkg.repository.url);
    const list = await api.listMuPlugins();
    const existing = list.find((m) => String(m.path || m.url || '').includes('wayzgoose-sentinel.php'));
    return { source, registered: Boolean(existing), muPlugin: existing || null };
  };


  // ----- Uptime -----

  handlers['uptime:check'] = async ({ scope, siteId, notify } = {}) => {
    if (currentUptime) throw new Error('An uptime check is already running.');
    const config = await loadConfig();
    const effectiveScope = scope || (config.uptimeScope === 'list' ? 'list' : 'live');
    const targets = await uptimeTargets(config, effectiveScope, siteId);
    executeUptimeCheck({ targets, scope: effectiveScope, notify: notify !== false, trigger: 'manual' }).catch((err) => {
      send('uptime:event', { kind: 'error', error: err.message });
      currentUptime = null;
    });
    return { siteCount: targets.length };
  };

  handlers['uptime:lastResult'] = () => loadUptime();

  // ----- Config check -----

  handlers['config:check'] = async ({ scope, siteId, deep } = {}) => {
    if (currentConfig) throw new Error('A config check is already running.');
    const config = await loadConfig();
    const effectiveScope = scope || 'all';
    const targets = await configTargets(config, effectiveScope, siteId);
    executeConfigCheck({ targets, scope: effectiveScope, deep: Boolean(deep), trigger: 'manual' }).catch((err) => {
      send('config:event', { kind: 'error', error: err.message });
      currentConfig = null;
    });
    return { siteCount: targets.length };
  };

  handlers['config:lastResult'] = () => readJson(lastConfigPath(), null);

  return { handlers, startScheduler, maybeScheduled, loadConfig, saveConfig, getClient, dataDir, appendRunLog };
}

module.exports = { createEngine, CONFIG_DEFAULTS };
