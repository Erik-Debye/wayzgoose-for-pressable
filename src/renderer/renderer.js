'use strict';

const api = window.pressable;
const $ = (id) => document.getElementById(id);

// After a run, check on new backups every 15 s for two minutes, then every
// 30 s, and give up after an hour.
const POLL_FAST_MS = 15_000;
const POLL_SLOW_MS = 30_000;
const POLL_FAST_ROUNDS = 8;
const POLL_MAX_MS = 60 * 60_000;

const state = {
  sites: [],
  config: { siteIds: [], task: { kind: 'backup', backupTypes: ['fs', 'db'] } },
  running: false,
  rows: new Map(), // row key -> <tr>
  pending: new Map(), // row key -> { siteId, type, backupId, requestedAt, replacedId }
  pollTimer: null,
  pollRounds: 0,
  pollStartedAt: 0,
  tally: { requested: 0, completed: 0, failed: 0 },
  summaryPrefix: '',
  statusRequest: 0,
  scanning: false,
  lastScan: null,
  auditing: false,
  installing: false,
  lastAudit: null,
};

// ---------- Helpers ----------

const siteById = (id) => state.sites.find((s) => String(s.id) === String(id));
const siteLabel = (id) => {
  const site = siteById(id);
  return site ? site.displayName : `Site ${id}`;
};
const selectedIds = () => new Set((state.config.siteIds || []).map(String));
const timeNow = () => new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
const task = () => state.config.task;

function pill(text, kind) {
  const span = document.createElement('span');
  span.className = `pill ${kind || ''}`.trim();
  span.textContent = text;
  return span;
}

function matches(site, needle) {
  if (!needle) return true;
  const hay = `${site.displayName} ${site.name} ${site.url} ${site.tags.join(' ')}`.toLowerCase();
  return hay.includes(needle);
}

function setConn(text, kind) {
  const el = $('conn');
  el.textContent = text;
  el.className = `conn ${kind || ''}`.trim();
}

function plural(n, one, many) {
  return `${n} ${n === 1 ? one : many || `${one}s`}`;
}

// Read the task options off the form into a task object.
function readTaskForm() {
  const kind = document.querySelector('.seg[aria-checked="true"]').dataset.task;
  const backupTypes = [];
  if ($('type-fs').checked) backupTypes.push('fs');
  if ($('type-db').checked) backupTypes.push('db');
  return {
    kind,
    backupTypes,
    clearEdge: $('cache-edge').checked,
    clearObject: $('cache-object').checked,
    preloadEnabled: $('preload-on').checked,
    preloadTurnOnEdgeCache: $('preload-edge').checked,
  };
}

// Security options live at the top level of config (shared with scheduling).
function readSecurityForm() {
  return {
    securityScope: $('security-list').checked ? 'list' : 'all',
    alertAutomatically: $('security-notify').checked,
  };
}

function writeSecurityForm(cfg) {
  $('security-all').checked = cfg.securityScope !== 'list';
  $('security-list').checked = cfg.securityScope === 'list';
  $('security-notify').checked = Boolean(cfg.alertAutomatically);
  const hasWebhook = Boolean(cfg.webhookUrl);
  $('security-notify').disabled = !hasWebhook;
  $('security-notify-hint').textContent = hasWebhook ? '' : '(add a webhook in Settings)';

  // The user audit shares the scope choice with the vulnerability check.
  $('users-all').checked = cfg.securityScope !== 'list';
  $('users-list').checked = cfg.securityScope === 'list';
  $('users-notify').checked = Boolean(cfg.userAlertAutomatically);
  const hasUserWebhook = Boolean(cfg.userWebhookUrl);
  $('users-notify').disabled = !hasUserWebhook;
  $('users-notify-hint').textContent = hasUserWebhook ? '' : '(add a webhook in Settings)';
  $('users-roles-label').textContent = (cfg.watchedRoles || 'administrator').split(/[,\s]+/).filter(Boolean).join(', ');
  $('btn-sentinel').disabled = !hasUserWebhook || state.installing;
}

function readUsersForm() {
  return {
    securityScope: $('users-list').checked ? 'list' : 'all',
    userAlertAutomatically: $('users-notify').checked,
  };
}

function writeTaskForm(t) {
  for (const seg of document.querySelectorAll('.seg')) {
    seg.setAttribute('aria-checked', seg.dataset.task === t.kind ? 'true' : 'false');
  }
  $('type-fs').checked = t.backupTypes.includes('fs');
  $('type-db').checked = t.backupTypes.includes('db');
  $('cache-edge').checked = Boolean(t.clearEdge);
  $('cache-object').checked = Boolean(t.clearObject);
  $('preload-on').checked = Boolean(t.preloadEnabled);
  $('preload-off').checked = !t.preloadEnabled;
  $('preload-edge').checked = Boolean(t.preloadTurnOnEdgeCache);
  $('opts-backup').hidden = t.kind !== 'backup';
  $('opts-cache').hidden = t.kind !== 'cache';
  $('opts-preload').hidden = t.kind !== 'preload';
  $('opts-security').hidden = t.kind !== 'security';
  $('opts-users').hidden = t.kind !== 'users';
}

// Is the task runnable as configured?
function taskReady(t) {
  if (t.kind === 'backup') return t.backupTypes.length > 0;
  if (t.kind === 'cache') return t.clearEdge || t.clearObject;
  return true;
}

// Copy for the two action cards.
function taskCopy(t, siteCount) {
  const sites = plural(siteCount, 'site');
  switch (t.kind) {
    case 'backup': {
      const what = t.backupTypes.length === 2
        ? 'a filesystem and a database backup'
        : t.backupTypes[0] === 'fs' ? 'a filesystem backup' : 'a database backup';
      return {
        listTitle: 'Back up your list',
        listSummary: `Creates ${what} for each of the ${sites} on your list.`,
        listButton: `Back up ${sites}`,
        singleButton: 'Back up this site',
        runLabel: what,
      };
    }
    case 'cache': {
      const layers = [t.clearEdge ? 'edge cache' : null, t.clearObject ? 'object cache' : null].filter(Boolean).join(' and ');
      return {
        listTitle: 'Clear cache on your list',
        listSummary: `Clears the ${layers} on each of the ${sites} on your list.`,
        listButton: `Clear cache on ${sites}`,
        singleButton: 'Clear cache on this site',
        runLabel: `clear ${layers}`,
      };
    }
    case 'preload': {
      const verb = t.preloadEnabled ? 'on' : 'off';
      return {
        listTitle: `Turn cache preload ${verb} for your list`,
        listSummary: `Turns cache preload ${verb} for each of the ${sites} on your list.`,
        listButton: `Turn preload ${verb} for ${sites}`,
        singleButton: `Turn preload ${verb} for this site`,
        runLabel: `cache preload ${verb}`,
      };
    }
    case 'security': {
      const scopeList = state.config.securityScope === 'list';
      const count = scopeList ? siteCount : state.sites.length;
      const where = scopeList ? 'on your list' : 'on your account';
      return {
        listTitle: 'Check for vulnerabilities',
        listSummary: `Checks the plugins and themes on ${plural(count, 'site')} ${where} and groups each vulnerability with every site it affects.`,
        listButton: `Check ${plural(count, 'site')}`,
        singleButton: 'Check this site',
        runLabel: 'vulnerability check',
        scopeCount: count,
      };
    }
    case 'users': {
      const scopeList = state.config.securityScope === 'list';
      const count = scopeList ? siteCount : state.sites.length;
      const where = scopeList ? 'on your list' : 'on your account';
      return {
        listTitle: 'Audit privileged users',
        listSummary: `Lists the privileged accounts on ${plural(count, 'site')} ${where} and reports what changed since the last audit.`,
        listButton: `Audit ${plural(count, 'site')}`,
        singleButton: 'Audit this site',
        runLabel: 'user audit',
        scopeCount: count,
      };
    }
    default:
      return { listTitle: '', listSummary: '', listButton: 'Run', singleButton: 'Run', runLabel: '' };
  }
}

// Label for one expanded item in the activity table.
function itemLabel(item) {
  switch (item.kind) {
    case 'backup': return item.type === 'fs' ? 'Filesystem backup' : 'Database backup';
    case 'purge-edge': return 'Clear edge cache';
    case 'flush-object': return 'Flush object cache';
    case 'preload': return item.enabled ? 'Preload on' : 'Preload off';
    case 'security': return 'Vulnerability check';
    case 'audit': return 'User audit';
    case 'sentinel': return 'Install sentinel';
    default: return item.kind;
  }
}

// Rows are keyed per run so a second run on the same site gets fresh rows.
const itemKey = (ev) => `${ev.runId}:${ev.siteId}:${ev.item.kind}:${ev.item.type || ''}`;

// ---------- Sites sidebar ----------

function renderSites() {
  const list = $('site-list');
  const needle = $('site-search').value.trim().toLowerCase();
  const selected = selectedIds();
  list.replaceChildren();

  const shown = state.sites.filter((s) => matches(s, needle));
  for (const site of shown) {
    const li = document.createElement('li');
    const label = document.createElement('label');
    label.className = 'site-row';

    const box = document.createElement('input');
    box.type = 'checkbox';
    box.checked = selected.has(String(site.id));
    box.addEventListener('change', () => toggleSite(site.id, box.checked));

    const text = document.createElement('span');
    const name = document.createElement('span');
    name.className = 'site-name';
    name.textContent = site.displayName;
    const url = document.createElement('span');
    url.className = 'site-url';
    url.textContent = site.url || site.name;
    text.append(name, url);

    label.append(box, text);
    if (site.staging || site.sandbox || (site.state && site.state !== 'live')) {
      const badge = document.createElement('span');
      badge.className = 'badge';
      badge.textContent = site.staging ? 'staging' : site.sandbox ? 'sandbox' : site.state;
      label.append(badge);
    }
    li.append(label);
    list.append(li);
  }

  const empty = $('sites-empty');
  if (state.sites.length === 0) {
    empty.textContent = 'No sites loaded yet.';
    empty.hidden = false;
  } else if (shown.length === 0) {
    empty.textContent = 'No sites match that filter.';
    empty.hidden = false;
  } else {
    empty.hidden = true;
  }

  renderSinglePicker();
  renderCounts();
}

function renderCounts() {
  const t = task();
  const selected = selectedIds();
  const onList = state.sites.filter((s) => selected.has(String(s.id))).length;
  $('list-count').textContent = `${onList} on your list`;

  const copy = taskCopy(t, onList);
  $('list-title').textContent = copy.listTitle;
  const wide = t.kind === 'security' || t.kind === 'users';
  const primaryCount = wide ? copy.scopeCount : onList;
  if (primaryCount === 0) {
    $('list-summary').textContent = wide && state.config.securityScope !== 'list'
      ? 'No sites loaded yet.'
      : 'Tick sites on the left to build your list.';
  } else if (!taskReady(t)) {
    $('list-summary').textContent = 'Choose at least one option above.';
  } else {
    $('list-summary').textContent = copy.listSummary;
  }
  $('run-list').textContent = copy.listButton;
  $('run-single').textContent = copy.singleButton;
  const busy = state.running || state.scanning || state.auditing || state.installing;
  $('run-list').disabled = busy || primaryCount === 0 || !taskReady(t);
  $('run-single').disabled = busy || !$('single-site').value || !taskReady(t);
}

function renderSinglePicker() {
  const select = $('single-site');
  const needle = $('single-filter').value.trim().toLowerCase();
  const previous = select.value;
  select.replaceChildren();
  for (const site of state.sites.filter((s) => matches(s, needle))) {
    const opt = document.createElement('option');
    opt.value = String(site.id);
    opt.textContent = site.url ? `${site.displayName}  (${site.url})` : site.displayName;
    select.append(opt);
  }
  if ([...select.options].some((o) => o.value === previous)) select.value = previous;
  if (select.value !== previous) loadSiteStatus();
}

async function toggleSite(id, on) {
  const ids = new Set((state.config.siteIds || []).map(String));
  if (on) ids.add(String(id));
  else ids.delete(String(id));
  state.config = await api.config.set({ siteIds: [...ids] });
  renderCounts();
}

async function loadSites() {
  $('btn-refresh').disabled = true;
  try {
    state.sites = await api.sites.list();
    renderSites();
    setConn(`Connected · ${plural(state.sites.length, 'site')}`, 'ok');
    loadSiteStatus();
    refreshSentinelStatus();
  } catch (err) {
    setConn(err.message, 'bad');
    state.sites = [];
    renderSites();
  } finally {
    $('btn-refresh').disabled = false;
  }
}

// ---------- Single-site cache status ----------

function statusRow(dl, term, text, cls) {
  const dt = document.createElement('dt');
  dt.textContent = term;
  const dd = document.createElement('dd');
  dd.textContent = text;
  if (cls) dd.className = cls;
  dl.append(dt, dd);
}

async function loadSiteStatus() {
  const dl = $('site-status');
  const siteId = $('single-site').value;
  if (!siteId) {
    dl.replaceChildren();
    return;
  }
  const requestId = ++state.statusRequest;
  dl.replaceChildren();
  statusRow(dl, 'Edge cache', 'Checking…', 'muted');
  statusRow(dl, 'Cache preload', 'Checking…', 'muted');

  let status;
  try {
    status = await api.sites.cacheStatus(siteId);
  } catch (err) {
    if (requestId !== state.statusRequest) return;
    dl.replaceChildren();
    statusRow(dl, 'Status', err.message, 'muted');
    return;
  }
  if (requestId !== state.statusRequest) return; // a newer selection superseded this one

  dl.replaceChildren();
  if (status.edge) {
    let text = status.edge.active ? 'On' : 'Off';
    if (status.edge.defensiveActive) {
      const until = status.edge.defensiveUntil
        ? ` until ${new Date(Number(status.edge.defensiveUntil) * 1000).toLocaleString([], { hour: '2-digit', minute: '2-digit', month: 'short', day: 'numeric' })}`
        : '';
      text += ` · defensive mode${until}`;
    }
    statusRow(dl, 'Edge cache', text);
  } else {
    statusRow(dl, 'Edge cache', status.edgeError || 'Unknown', 'muted');
  }

  if (status.preload) {
    statusRow(dl, 'Cache preload', preloadText(status.preload));
    for (const warning of status.preload.warnings) {
      const note = document.createElement('div');
      note.className = 'status-note';
      note.textContent = warning;
      dl.append(note);
    }
  } else {
    statusRow(dl, 'Cache preload', status.preloadError || 'Unknown', 'muted');
  }
}

function preloadText(p) {
  if (!p.enabled) return 'Off';
  const parts = ['On'];
  if (p.state) parts.push(p.state.replace(/[_-]+/g, ' '));
  const found = p.urlsFound !== null && p.urlsFound !== undefined ? `${p.urlsFound} pages found` : null;
  const warmed = p.urlsPreloaded !== null && p.urlsPreloaded !== undefined ? `${p.urlsPreloaded} warmed` : null;
  if (found || warmed) parts.push([found, warmed].filter(Boolean).join(', '));
  return parts.join(' · ');
}

// ---------- Activity log ----------

function logTableBody(title) {
  $('log-empty').hidden = true;
  $('log-table').hidden = false;
  const tbody = document.createElement('tbody');
  const tr = document.createElement('tr');
  tr.className = 'run-row';
  const td = document.createElement('td');
  td.colSpan = 4;
  td.textContent = title;
  tr.append(td);
  tbody.append(tr);
  const table = $('log-table');
  table.insertBefore(tbody, table.tBodies[0] || null);
  return tbody;
}

function addRow(tbody, key, siteId, item) {
  const tr = document.createElement('tr');
  const site = document.createElement('td');
  site.textContent = siteLabel(siteId);
  const kind = document.createElement('td');
  kind.textContent = itemLabel(item);
  const status = document.createElement('td');
  status.append(pill('Queued'));
  const details = document.createElement('td');
  details.className = 'details';
  tr.append(site, kind, status, details);
  tbody.append(tr);
  state.rows.set(key, tr);
  return tr;
}

function ensureRow(ev) {
  const key = itemKey(ev);
  if (currentBody && !state.rows.has(key)) addRow(currentBody, key, ev.siteId, ev.item);
  return key;
}

function setRow(key, { status, kind, details }) {
  const tr = state.rows.get(key);
  if (!tr) return;
  if (status) tr.cells[2].replaceChildren(pill(status, kind));
  if (details !== undefined) tr.cells[3].textContent = details;
}

function rowDetails(key) {
  const tr = state.rows.get(key);
  return tr ? tr.cells[3].textContent : '';
}

function humanState(raw) {
  if (!raw) return 'Requested';
  return raw.charAt(0).toUpperCase() + raw.slice(1).replace(/[_-]+/g, ' ');
}

// ---------- Run lifecycle ----------

let currentBody = null;

function setRunning(on) {
  state.running = on;
  $('btn-cancel').hidden = !on && !state.scanning;
  if (on) $('progress').hidden = false;
  renderCounts();
}

function setProgress(done, total, text) {
  $('progress-fill').style.width = total ? `${Math.round((done / total) * 100)}%` : '0%';
  $('progress-text').textContent = text;
}

async function startRun(mode) {
  if (state.running || state.scanning) return;
  const t = readTaskForm();
  if (!taskReady(t)) return;
  const siteId = mode === 'single' ? $('single-site').value : null;
  if (t.kind === 'security') {
    startScan(mode === 'single' ? 'single' : (state.config.securityScope === 'list' ? 'list' : 'all'), siteId);
    return;
  }
  if (t.kind === 'users') {
    startAudit(mode === 'single' ? 'single' : (state.config.securityScope === 'list' ? 'list' : 'all'), siteId);
    return;
  }

  try {
    state.tally = { requested: 0, completed: 0, failed: 0 };
    state.summaryPrefix = '';
    setRunning(true);
    setProgress(0, 1, 'Starting…');
    const { siteCount } = await api.run.start({ mode, siteId, task: t });
    const copy = taskCopy(t, siteCount);
    const label = mode === 'single'
      ? `${timeNow()} · ${siteLabel(siteId)} · ${copy.runLabel}`
      : `${timeNow()} · ${plural(siteCount, 'site')} from your list · ${copy.runLabel}`;
    currentBody = logTableBody(label);
  } catch (err) {
    setRunning(false);
    $('progress').hidden = true;
    currentBody = logTableBody(`${timeNow()} · Could not start`);
    appendNoteRow(currentBody, err.message);
  }
}

function appendNoteRow(tbody, text) {
  const tr = document.createElement('tr');
  const td = document.createElement('td');
  td.colSpan = 4;
  td.className = 'details';
  td.textContent = text;
  tr.append(td);
  tbody.append(tr);
}

// Turn a finished item into a pill + details line.
function describeResult(ev) {
  const { item, result } = ev;
  switch (item.kind) {
    case 'backup': {
      const final = /(complete|success|ready|available|finish|done)/i.test(result.state || '');
      const details = [
        result.backupId !== null && result.backupId !== undefined ? `Backup #${result.backupId}` : 'Requested',
        result.replacedId ? `replaced #${result.replacedId}` : null,
      ].filter(Boolean).join(' · ');
      return { status: humanState(result.state), kind: final ? 'done' : 'requested', details, final };
    }
    case 'purge-edge':
      return { status: 'Cleared', kind: 'done', details: '', final: true };
    case 'flush-object':
      return { status: 'Flushed', kind: 'done', details: '', final: true };
    case 'preload': {
      const p = result.preload;
      const bits = [];
      if (p) {
        if (p.enabled && p.state) bits.push(`crawl ${p.state.replace(/[_-]+/g, ' ')}`);
        bits.push(...p.warnings);
      }
      if (result.edgeCacheTurnedOn) bits.unshift('edge cache turned on');
      const on = p ? p.enabled : item.enabled;
      return { status: on ? 'On' : 'Off', kind: 'done', details: bits.join(' · '), final: true };
    }
    default:
      return { status: 'Done', kind: 'done', details: '', final: true };
  }
}

function handleRunEvent(ev) {
  switch (ev.kind) {
    case 'started': {
      setProgress(0, ev.total, `0 of ${ev.total} done`);
      break;
    }
    case 'item:started': {
      const key = ensureRow(ev);
      setRow(key, { status: 'Working', kind: 'working', details: '' });
      setProgress(ev.index - 1, ev.total, `${ev.index - 1} of ${ev.total} done · now ${siteLabel(ev.siteId)}`);
      break;
    }
    case 'item:done': {
      const key = ensureRow(ev);
      const d = describeResult(ev);
      setRow(key, d);
      state.tally.requested += 1;
      if (d.final) state.tally.completed += 1;
      if (ev.item.kind === 'backup' && !d.final) {
        state.pending.set(key, {
          siteId: ev.siteId,
          type: ev.item.type,
          backupId: ev.result.backupId ?? null,
          requestedAt: ev.result.requestedAt,
          replacedId: ev.result.replacedId ?? null,
        });
      }
      setProgress(ev.index, ev.total, `${ev.index} of ${ev.total} done`);
      break;
    }
    case 'item:failed': {
      const key = ensureRow(ev);
      setRow(key, { status: 'Failed', kind: 'failed', details: ev.status ? `${ev.error} (HTTP ${ev.status})` : ev.error });
      state.tally.failed += 1;
      setProgress(ev.index, ev.total, `${ev.index} of ${ev.total} done`);
      break;
    }
    case 'finished': {
      setRunning(false);
      state.summaryPrefix = ev.cancelled ? 'Cancelled' : 'Finished';
      $('progress-fill').style.width = '100%';
      renderSummary();
      if (ev.cancelled) {
        for (const [key, tr] of state.rows) {
          const text = tr.cells[2].textContent;
          if (text === 'Queued' || text === 'Working') setRow(key, { status: 'Cancelled', kind: '' });
        }
      }
      startPolling();
      loadSiteStatus(); // the selected site may have just changed
      break;
    }
    case 'error': {
      setRunning(false);
      if (currentBody) appendNoteRow(currentBody, ev.error);
      break;
    }
    default:
      break;
  }
}

function renderSummary(extra) {
  if (state.running || !state.summaryPrefix) return;
  const { requested, completed, failed } = state.tally;
  const parts = [`${requested} of ${requested + failed} done`];
  if (completed && completed !== requested) parts.push(`${completed} completed`);
  if (failed) parts.push(`${failed} failed`);
  if (extra) parts.push(extra);
  else if (state.pending.size) parts.push('watching backups for completion');
  $('progress-text').textContent = `${state.summaryPrefix} · ${parts.join(' · ')}`;
}

// ---------- Backup completion polling ----------

function schedulePoll() {
  const delay = state.pollRounds < POLL_FAST_ROUNDS ? POLL_FAST_MS : POLL_SLOW_MS;
  state.pollTimer = setTimeout(pollOnce, delay);
}

function startPolling() {
  if (state.pollTimer || state.pending.size === 0) return;
  state.pollRounds = 0;
  state.pollStartedAt = Date.now();
  schedulePoll();
}

function stopPolling(reason) {
  if (state.pollTimer) clearTimeout(state.pollTimer);
  state.pollTimer = null;
  renderSummary(reason);
}

function baseDetails(item) {
  return [
    item.backupId !== null && item.backupId !== undefined ? `Backup #${item.backupId}` : 'Requested',
    item.replacedId ? `replaced #${item.replacedId}` : null,
  ].filter(Boolean).join(' · ');
}

async function pollOnce() {
  state.pollTimer = null;
  if (state.pending.size === 0) {
    stopPolling('');
    return;
  }
  if (Date.now() - state.pollStartedAt > POLL_MAX_MS) {
    for (const [key] of state.pending) {
      setRow(key, { details: `${rowDetails(key)} · still running after an hour; check MyPressable` });
    }
    state.pending.clear();
    stopPolling('stopped watching after an hour');
    return;
  }
  state.pollRounds += 1;

  const entries = [...state.pending.entries()];
  try {
    const results = await api.backups.status(
      entries.map(([, v]) => ({ siteId: v.siteId, type: v.type, backupId: v.backupId, requestedAt: v.requestedAt })),
    );
    results.forEach((res, i) => {
      const [key, item] = entries[i];
      if (res.error) {
        setRow(key, { details: `${baseDetails(item)} · status check failed: ${res.error}` });
        return;
      }
      if (res.found && res.backupId !== null && item.backupId === null) {
        item.backupId = res.backupId; // learned the id from the site's backup list
      }
      if (res.state) {
        const stamp = res.final ? ` · ${res.failed ? 'failed' : 'finished'} ${timeNow()}` : '';
        setRow(key, {
          status: humanState(res.state),
          kind: res.failed ? 'failed' : res.final ? 'done' : 'requested',
          details: baseDetails(item) + stamp,
        });
      } else {
        setRow(key, { details: baseDetails(item) });
      }
      if (res.final) {
        state.pending.delete(key);
        if (res.failed) state.tally.failed += 1;
        else state.tally.completed += 1;
      }
    });
  } catch {
    // Network blip; try again next round.
  }
  if (state.pending.size > 0) {
    renderSummary();
    schedulePoll();
  } else {
    stopPolling('');
  }
}

function clearLog() {
  const table = $('log-table');
  for (const body of [...table.tBodies]) body.remove();
  table.hidden = true;
  $('log-empty').hidden = false;
  state.rows.clear();
  state.pending.clear();
  $('progress').hidden = true;
  stopPolling('');
}

// ---------- Vulnerability checks ----------

let scanBody = null;
let scanRowKey = null;

async function startScan(scope, siteId) {
  const notify = $('security-notify').checked && !$('security-notify').disabled;
  try {
    state.scanning = true;
    state.summaryPrefix = '';
    $('btn-cancel').hidden = false;
    $('progress').hidden = false;
    setProgress(0, 1, 'Starting…');
    renderCounts();
    const { siteCount } = await api.security.scan({ scope, siteId, notify });
    const where = scope === 'single' ? siteLabel(siteId) : scope === 'list' ? `${plural(siteCount, 'site')} from your list` : `all ${plural(siteCount, 'site')}`;
    scanBody = logTableBody(`${timeNow()} · ${where} · vulnerability check`);
    scanRowKey = `scan:${Date.now()}`;
    const tr = addRow(scanBody, scanRowKey, null, { kind: 'security' });
    tr.cells[0].textContent = scope === 'single' ? siteLabel(siteId) : scope === 'list' ? 'Your list' : 'All sites';
    setRow(scanRowKey, { status: 'Working', kind: 'working', details: '' });
  } catch (err) {
    state.scanning = false;
    $('btn-cancel').hidden = true;
    $('progress').hidden = true;
    renderCounts();
    const body = logTableBody(`${timeNow()} · Could not start`);
    appendNoteRow(body, err.message);
  }
}

function handleScanEvent(ev) {
  switch (ev.kind) {
    case 'started':
      if (ev.trigger === 'scheduled' && !state.scanning) {
        state.scanning = true;
        $('progress').hidden = false;
        renderCounts();
        scanBody = logTableBody(`${timeNow()} · scheduled daily vulnerability check`);
        scanRowKey = `scan:${ev.scanId}`;
        const tr = addRow(scanBody, scanRowKey, null, { kind: 'security' });
        tr.cells[0].textContent = ev.scope === 'list' ? 'Your list' : 'All sites';
        setRow(scanRowKey, { status: 'Working', kind: 'working', details: '' });
      }
      setProgress(0, ev.total, `Checking 0 of ${ev.total} sites`);
      break;
    case 'site':
      setProgress(ev.index - 1, ev.total, `Checking ${ev.index} of ${ev.total} sites · ${ev.siteName}`);
      break;
    case 'enriching':
      setProgress(1, 1, `Looking up ${plural(ev.total, 'vulnerability', 'vulnerabilities')}…`);
      break;
    case 'enrich':
      setProgress(ev.done, ev.total, `Looking up ${ev.done} of ${ev.total}${ev.cve ? ` · ${ev.cve}` : ''}`);
      break;
    case 'finished': {
      state.scanning = false;
      $('btn-cancel').hidden = !state.running;
      const r = ev.result;
      state.lastScan = r;
      const n = r.findings.length;
      const summary = [`${r.checked} of ${r.siteCount} sites checked`];
      if (r.errors.length) summary.push(`${r.errors.length} could not be read`);
      if (r.notified && r.notified.ok) summary.push(`alert sent (${plural(r.notified.findings, 'finding')})`);
      else if (r.notified && !r.notified.ok) summary.push(`alert failed: ${r.notified.error}`);
      else if (r.newCount) summary.push(`${r.newCount} not yet reported`);
      if (r.cancelled) summary.unshift('cancelled');
      setRow(scanRowKey, {
        status: n === 0 ? 'Clean' : `${n} found`,
        kind: n === 0 ? 'done' : (r.findings.some((f) => f.severity === 'critical' || f.severity === 'high') ? 'failed' : 'requested'),
        details: summary.join(' · '),
      });
      $('progress-fill').style.width = '100%';
      $('progress-text').textContent = `${r.cancelled ? 'Cancelled' : 'Finished'} · ${n === 0 ? 'no known vulnerabilities' : plural(n, 'vulnerability', 'vulnerabilities')} · ${summary.join(' · ')}`;
      renderFindings(r);
      renderCounts();
      break;
    }
    case 'error':
      state.scanning = false;
      $('btn-cancel').hidden = !state.running;
      if (scanRowKey) setRow(scanRowKey, { status: 'Failed', kind: 'failed', details: ev.error });
      renderCounts();
      break;
    default:
      break;
  }
}

const SEVERITY_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', none: 'Info', unknown: 'Severity unknown' };

function renderFindings(result) {
  const panel = $('findings');
  const list = $('findings-list');
  if (!result || !result.findings) {
    panel.hidden = true;
    return;
  }
  const findings = result.findings;
  const sites = new Set();
  for (const f of findings) for (const s of f.sites) sites.add(String(s.siteId));
  const when = new Date(result.at).toLocaleString([], { hour: '2-digit', minute: '2-digit', month: 'short', day: 'numeric' });
  $('findings-title').textContent = findings.length === 0
    ? 'No known vulnerabilities'
    : `${plural(findings.length, 'vulnerability', 'vulnerabilities')} across ${plural(sites.size, 'site')}`;
  const scopeText = result.scope === 'single' ? 'one site' : result.scope === 'list' ? 'your list' : 'all sites';
  $('findings-meta').textContent = `Checked ${scopeText} · ${when}${result.newCount ? ` · ${result.newCount} not yet sent to your channel` : ''}`;

  const hasWebhook = Boolean(state.config.webhookUrl);
  $('btn-send-new').hidden = !hasWebhook || findings.length === 0;
  $('btn-send-all').hidden = !hasWebhook || findings.length === 0;
  $('btn-send-new').disabled = !result.newCount;
  const note = $('findings-note');
  if (!hasWebhook && findings.length) {
    note.textContent = 'Add a Slack or Discord webhook in Settings to have new findings posted to your team.';
    note.hidden = false;
  } else if (result.errors && result.errors.length) {
    note.textContent = `Could not read alerts for: ${result.errors.map((e) => `${e.siteName} (${e.error})`).join('; ')}`;
    note.hidden = false;
  } else {
    note.hidden = true;
  }

  list.replaceChildren();
  for (const f of findings) list.append(findingCard(f));
  panel.hidden = false;
}

function findingCard(f) {
  const card = document.createElement('article');
  card.className = 'finding';

  const head = document.createElement('div');
  head.className = 'finding-head';
  const sev = pill(`${SEVERITY_LABEL[f.severity] || 'Unknown'}${f.score !== null && f.score !== undefined ? ` ${f.score}` : ''}`, `sev-${f.severity || 'unknown'}`);
  const title = document.createElement('h4');
  title.textContent = f.title;
  head.append(sev, title);
  if (f.isNew) {
    const b = document.createElement('span');
    b.className = 'badge new';
    b.textContent = 'not yet reported';
    head.append(b);
  }
  card.append(head);

  const versions = [...new Set(f.sites.map((s) => s.version).filter(Boolean))];
  const meta = document.createElement('p');
  meta.className = 'finding-meta';
  meta.textContent = [
    `${f.component.kind === 'theme' ? 'Theme' : 'Plugin'}: ${f.component.name}${versions.length ? ` ${versions.join(', ')}` : ''}`,
    f.fixedIn ? `fixed in ${f.fixedIn}` : 'no fix released yet',
    f.cves.length ? f.cves.join(', ') : null,
    f.vulnType || null,
  ].filter(Boolean).join(' · ');
  card.append(meta);

  if (f.access) {
    const access = document.createElement('p');
    access.className = 'finding-access';
    access.textContent = f.access;
    card.append(access);
  }

  const desc = (f.enrichment && f.enrichment.description) || f.description;
  if (desc || f.references.length) {
    const details = document.createElement('details');
    const summary = document.createElement('summary');
    summary.textContent = 'Details and references';
    details.append(summary);
    if (desc) {
      const p = document.createElement('p');
      p.textContent = desc;
      details.append(p);
    }
    if (f.enrichment && f.enrichment.cwes && f.enrichment.cwes.length) {
      const p = document.createElement('p');
      p.textContent = `Weakness: ${f.enrichment.cwes.join(', ')}`;
      details.append(p);
    }
    const links = [...new Set([
      ...f.cves.map((c) => `https://www.cve.org/CVERecord?id=${c}`),
      ...f.references,
    ])].slice(0, 8);
    if (links.length) {
      const ul = document.createElement('ul');
      for (const url of links) {
        const li = document.createElement('li');
        const a = document.createElement('a');
        a.href = url;
        a.textContent = url;
        a.addEventListener('click', (e) => {
          e.preventDefault();
          api.openExternal(url);
        });
        li.append(a);
        ul.append(li);
      }
      details.append(ul);
    }
    card.append(details);
  }

  const sitesEl = document.createElement('div');
  sitesEl.className = 'finding-sites';
  for (const s of f.sites) {
    const chip = document.createElement('span');
    chip.className = `chip${s.isNew ? ' new' : ''}`;
    chip.textContent = `${s.siteName}${s.version ? ` ${s.version}` : ''}`;
    chip.title = s.url || '';
    sitesEl.append(chip);
  }
  card.append(sitesEl);
  return card;
}

async function sendFindings(onlyNew) {
  const btn = onlyNew ? $('btn-send-new') : $('btn-send-all');
  const original = btn.textContent;
  btn.disabled = true;
  btn.textContent = 'Sending…';
  try {
    const res = await api.security.notify({ onlyNew });
    btn.textContent = res.findings ? `Sent ${plural(res.findings, 'finding')}` : 'Nothing new to send';
    const last = await api.security.lastResult();
    if (last) {
      state.lastScan = last;
      setTimeout(() => renderFindings(last), 1200);
    }
  } catch (err) {
    btn.textContent = original;
    btn.disabled = false;
    const note = $('findings-note');
    note.textContent = `Could not send: ${err.message}`;
    note.hidden = false;
  }
}

// ---------- Privileged-user audit ----------

let auditRowKey = null;
let sentinelRowKey = null;

function scopeLabel(scope, siteId, siteCount) {
  return scope === 'single' ? siteLabel(siteId) : scope === 'list' ? `${plural(siteCount, 'site')} from your list` : `all ${plural(siteCount, 'site')}`;
}

async function startAudit(scope, siteId) {
  const notify = $('users-notify').checked && !$('users-notify').disabled;
  try {
    state.auditing = true;
    state.summaryPrefix = '';
    $('btn-cancel').hidden = false;
    $('progress').hidden = false;
    setProgress(0, 1, 'Starting…');
    renderCounts();
    const { siteCount } = await api.users.audit({ scope, siteId, notify });
    const body = logTableBody(`${timeNow()} · ${scopeLabel(scope, siteId, siteCount)} · user audit`);
    auditRowKey = `audit:${Date.now()}`;
    const tr = addRow(body, auditRowKey, null, { kind: 'audit' });
    tr.cells[0].textContent = scope === 'single' ? siteLabel(siteId) : scope === 'list' ? 'Your list' : 'All sites';
    setRow(auditRowKey, { status: 'Working', kind: 'working', details: '' });
  } catch (err) {
    state.auditing = false;
    $('btn-cancel').hidden = true;
    $('progress').hidden = true;
    renderCounts();
    appendNoteRow(logTableBody(`${timeNow()} · Could not start`), err.message);
  }
}

function handleAuditEvent(ev) {
  switch (ev.kind) {
    case 'started':
      if (ev.trigger === 'scheduled' && !state.auditing) {
        state.auditing = true;
        $('progress').hidden = false;
        renderCounts();
        const body = logTableBody(`${timeNow()} · scheduled daily user audit`);
        auditRowKey = `audit:${ev.auditId}`;
        const tr = addRow(body, auditRowKey, null, { kind: 'audit' });
        tr.cells[0].textContent = ev.scope === 'list' ? 'Your list' : 'All sites';
        setRow(auditRowKey, { status: 'Working', kind: 'working', details: '' });
      }
      setProgress(0, ev.total, `Auditing 0 of ${ev.total} sites`);
      break;
    case 'site':
      setProgress(ev.index - 1, ev.total, `Auditing ${ev.index} of ${ev.total} sites · ${ev.siteName}`);
      break;
    case 'forensics':
      $('progress-text').textContent = `Change found on ${ev.siteName} · reading its web server and activity logs…`;
      break;
    case 'finished': {
      state.auditing = false;
      $('btn-cancel').hidden = !(state.running || state.scanning);
      const r = ev.result;
      state.lastAudit = r;
      const privileged = r.sites.reduce((n, s) => n + s.privileged.length, 0);
      const baselines = r.sites.filter((s) => s.baseline).length;
      const parts = [`${plural(privileged, 'privileged account')} on ${plural(r.checked, 'site')}`];
      if (r.events.length) parts.push(`${plural(r.events.length, 'change')} since last audit`);
      if (baselines) parts.push(`${plural(baselines, 'baseline')} recorded`);
      if (r.errors.length) parts.push(`${r.errors.length} could not be read`);
      if (r.notified && r.notified.ok) parts.push('alert sent');
      else if (r.notified && !r.notified.ok) parts.push(`alert failed: ${r.notified.error}`);
      if (r.cancelled) parts.unshift('cancelled');
      setRow(auditRowKey, {
        status: r.events.length ? `${r.events.length} changed` : 'No changes',
        kind: r.events.some((e) => e.kind === 'added' || e.kind === 'changed') ? 'failed' : r.events.length ? 'requested' : 'done',
        details: parts.join(' · '),
      });
      $('progress-fill').style.width = '100%';
      $('progress-text').textContent = `${r.cancelled ? 'Cancelled' : 'Finished'} · ${parts.join(' · ')}`;
      renderAdmins(r);
      renderCounts();
      break;
    }
    case 'error':
      state.auditing = false;
      $('btn-cancel').hidden = !(state.running || state.scanning);
      if (auditRowKey) setRow(auditRowKey, { status: 'Failed', kind: 'failed', details: ev.error });
      renderCounts();
      break;
    default:
      break;
  }
}

function renderAdmins(result) {
  const panel = $('admins');
  const list = $('admins-list');
  if (!result || !result.sites) {
    panel.hidden = true;
    return;
  }
  const privileged = result.sites.reduce((n, s) => n + s.privileged.length, 0);
  const when = new Date(result.at).toLocaleString([], { hour: '2-digit', minute: '2-digit', month: 'short', day: 'numeric' });
  $('admins-title').textContent = `${plural(privileged, 'privileged account')} across ${plural(result.checked, 'site')}`;
  const scopeText = result.scope === 'single' ? 'one site' : result.scope === 'list' ? 'your list' : 'all sites';
  $('admins-meta').textContent = `Watching ${result.watched.join(', ')} · audited ${scopeText} · ${when}${result.events.length ? ` · ${plural(result.events.length, 'change')} highlighted` : ''}`;

  const note = $('admins-note');
  if (result.errors && result.errors.length) {
    note.textContent = `Could not read users for: ${result.errors.map((e) => `${e.siteName} (${e.error})`).join('; ')}`;
    note.hidden = false;
  } else {
    note.hidden = true;
  }

  list.replaceChildren();
  const sorted = [...result.sites].sort((a, b) => {
    const ea = a.privileged.some((u) => u.isNew || u.changed) || a.removed.length;
    const eb = b.privileged.some((u) => u.isNew || u.changed) || b.removed.length;
    return (eb ? 1 : 0) - (ea ? 1 : 0) || a.siteName.localeCompare(b.siteName);
  });
  for (const site of sorted) {
    const group = document.createElement('div');
    group.className = 'site-group';
    const head = document.createElement('div');
    head.className = 'site-group-head';
    const h4 = document.createElement('h4');
    h4.textContent = site.siteName;
    const meta = document.createElement('span');
    meta.textContent = `${plural(site.privileged.length, 'privileged account')} of ${plural(site.totalUsers, 'user')}${site.baseline ? ' · baseline recorded' : ''}`;
    head.append(h4, meta);
    group.append(head);

    const chips = document.createElement('div');
    chips.className = 'finding-sites';
    for (const u of site.privileged) {
      const chip = document.createElement('span');
      chip.className = `chip${u.isNew ? ' new' : ''}${u.changed ? ' changed' : ''}`;
      chip.textContent = `${u.login || 'unknown'}${u.roles.length ? ` · ${u.roles.join(', ')}` : ''}${u.isNew ? ' · new' : ''}${u.changed ? ' · roles changed' : ''}`;
      chip.title = [u.email, u.registered ? `registered ${u.registered}` : null].filter(Boolean).join(' · ');
      chips.append(chip);
    }
    for (const u of site.removed) {
      const chip = document.createElement('span');
      chip.className = 'chip removed';
      chip.textContent = `${u.login || 'unknown'} · removed`;
      chips.append(chip);
    }
    if (site.privileged.length === 0 && site.removed.length === 0) {
      const none = document.createElement('span');
      none.className = 'finding-meta';
      none.textContent = 'No accounts with a watched role.';
      chips.append(none);
    }
    group.append(chips);

    const siteEvents = (result.events || []).filter((e) => String(e.siteId) === String(site.siteId) && e.forensics);
    if (siteEvents.length) {
      const f = siteEvents[0].forensics;
      const sc = siteEvents[0].sessionCheck;
      const details = document.createElement('details');
      const summary = document.createElement('summary');
      summary.textContent = f.requests.length
        ? `${plural(f.requests.length, 'request')} to user-management endpoints in the window · ${plural(f.activity.length, 'Pressable action')}`
        : `No matching requests in the web server log · ${plural(f.activity.length, 'Pressable action')}`;
      details.append(summary);
      const ul = document.createElement('ul');
      const lines = forensicsLinesForUi(f);
      if (sc && sc.requested) lines.push('Session check sent to the site: it posts to your channel which role-capable users were logged in during the window.');
      else if (sc && sc.error) lines.push(`Session check could not be started: ${sc.error}`);
      for (const line of lines) {
        const li = document.createElement('li');
        li.textContent = line;
        ul.append(li);
      }
      details.append(ul);
      group.append(details);
    }
    list.append(group);
  }
  panel.hidden = false;
}

// Same content the alert carries, minus the window header line.
function forensicsLinesForUi(f) {
  const fmt = (t) => (t ? new Date(t).toLocaleString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', month: 'short', day: 'numeric' }) : 'time unknown');
  const lines = [];
  for (const r of f.requests) {
    lines.push(`${fmt(r.time)} · ${r.method} ${r.path}${r.status ? ` → ${r.status}` : ''} · from ${r.ip || '?'}${r.userAgent ? ` · ${r.userAgent.slice(0, 90)}` : ''} (${r.what})`);
  }
  for (const a of f.activity) {
    lines.push(`${fmt(a.time)} · Pressable: ${a.description || a.name || 'action'}${a.email ? ` by ${a.email}` : ''}${a.ip ? ` from ${a.ip}` : ''}`);
  }
  if (!f.requests.length && f.requestsChecked) lines.push('Nothing in the web server log points at wp-admin or the REST API; the change may have come from WP-CLI, a database edit, or fell outside log retention (7 days / 10,000 entries).');
  if (f.error) lines.push(`Log lookup incomplete: ${f.error}`);
  return lines;
}

// ---------- Sentinel ----------

async function refreshSentinelStatus() {
  const el = $('sentinel-status');
  if (!state.sites.length) {
    el.textContent = 'Sentinel: not connected';
    return;
  }
  try {
    const status = await api.sentinel.status();
    el.textContent = status.registered
      ? 'Sentinel: registered as an account-wide mu-plugin'
      : 'Sentinel: not installed yet';
    el.title = status.source || '';
  } catch (err) {
    el.textContent = `Sentinel: ${err.message}`;
  }
}

async function startSentinelInstall() {
  const scope = state.config.securityScope === 'list' ? 'list' : 'all';
  try {
    state.installing = true;
    $('btn-sentinel').disabled = true;
    $('progress').hidden = false;
    setProgress(0, 1, 'Registering the sentinel mu-plugin…');
    renderCounts();
    const { siteCount } = await api.sentinel.install({ scope });
    const body = logTableBody(`${timeNow()} · ${scopeLabel(scope, null, siteCount)} · install sentinel`);
    sentinelRowKey = `sentinel:${Date.now()}`;
    const tr = addRow(body, sentinelRowKey, null, { kind: 'sentinel' });
    tr.cells[0].textContent = scope === 'list' ? 'Your list' : 'All sites';
    setRow(sentinelRowKey, { status: 'Working', kind: 'working', details: '' });
  } catch (err) {
    state.installing = false;
    $('progress').hidden = true;
    renderCounts();
    appendNoteRow(logTableBody(`${timeNow()} · Could not start`), err.message);
  }
}

function handleSentinelEvent(ev) {
  switch (ev.kind) {
    case 'registered':
      setProgress(0, 1, `Mu-plugin ${ev.action} · configuring sites…`);
      break;
    case 'site':
      setProgress(ev.index - 1, ev.total, `Configuring ${ev.index} of ${ev.total} sites · ${ev.siteName}`);
      break;
    case 'finished': {
      state.installing = false;
      const r = ev.result;
      if (!r.ok) {
        setRow(sentinelRowKey, { status: 'Failed', kind: 'failed', details: r.error });
        $('progress-text').textContent = `Failed · ${r.error}`;
      } else {
        const ok = r.sites.filter((s) => !s.error).length;
        const failed = r.sites.filter((s) => s.error);
        const viaOption = r.sites.filter((s) => s.configured && s.configured.startsWith('option')).length;
        const parts = [`mu-plugin ${r.registration.action}`, `${ok} of ${r.sites.length} sites configured and tested`];
        if (viaOption) parts.push(`${viaOption} stored as an option (wp-config not writable)`);
        if (failed.length) parts.push(`failed: ${failed.map((s) => `${s.siteName} (${s.error})`).join('; ')}`);
        setRow(sentinelRowKey, { status: failed.length ? `${failed.length} failed` : 'Installed', kind: failed.length ? 'requested' : 'done', details: parts.join(' · ') });
        $('progress-fill').style.width = '100%';
        $('progress-text').textContent = `Finished · ${parts.join(' · ')}`;
      }
      refreshSentinelStatus();
      renderCounts();
      break;
    }
    default:
      break;
  }
}

// ---------- Settings ----------

async function refreshCredentialStatus() {
  const status = await api.credentials.status();
  if (status.configured) {
    $('client-id').placeholder = status.clientIdHint ? `Saved: ${status.clientIdHint}` : '';
    $('client-secret').placeholder = 'Saved';
    $('btn-forget').hidden = false;
  } else {
    $('client-id').placeholder = '';
    $('client-secret').placeholder = '';
    $('btn-forget').hidden = true;
  }
  return status;
}

function openSettings(message, kind) {
  const el = $('settings-status');
  el.textContent = message || '';
  el.className = `status ${kind || ''}`.trim();
  $('webhook-url').value = state.config.webhookUrl || '';
  $('daily-check').checked = Boolean(state.config.dailyCheck);
  $('nvd-key').value = state.config.nvdApiKey || '';
  $('alerts-status').textContent = '';
  $('alerts-status').className = 'status';
  $('user-webhook-url').value = state.config.userWebhookUrl || '';
  $('watched-roles').value = state.config.watchedRoles || 'administrator';
  $('users-status').textContent = '';
  $('users-status').className = 'status';
  $('audit-every').value = String(state.config.auditEveryHours || 0);
  $('backup-at').value = state.config.backupListAt || '';
  $('schedule-status').textContent = '';
  $('schedule-status').className = 'status';
  if (!$('settings').open) $('settings').showModal();
}

async function saveSchedule() {
  const statusEl = $('schedule-status');
  const backupAt = $('backup-at').value.trim();
  if (backupAt && !/^\d{2}:\d{2}$/.test(backupAt)) {
    statusEl.className = 'status bad';
    statusEl.textContent = 'Use a time like 02:30.';
    return;
  }
  state.config = await api.config.set({ auditEveryHours: Number($('audit-every').value) || 0, backupListAt: backupAt });
  statusEl.className = 'status ok';
  statusEl.textContent = 'Saved.';
}

async function saveUserAlertSettings() {
  const statusEl = $('users-status');
  const url = $('user-webhook-url').value.trim();
  if (url && !/^https:\/\//.test(url)) {
    statusEl.className = 'status bad';
    statusEl.textContent = 'The webhook URL needs to start with https://';
    return;
  }
  const roles = $('watched-roles').value.trim() || 'administrator';
  state.config = await api.config.set({ userWebhookUrl: url, watchedRoles: roles });
  writeSecurityForm(state.config);
  statusEl.className = 'status ok';
  statusEl.textContent = url
    ? 'Saved. Run "Install sentinel" on the Users tab to push the webhook to your sites.'
    : 'Saved.';
}

async function testUserWebhook() {
  const statusEl = $('users-status');
  const url = $('user-webhook-url').value.trim();
  statusEl.className = 'status';
  statusEl.textContent = 'Sending…';
  try {
    const { kind } = await api.security.testWebhook(url);
    statusEl.className = 'status ok';
    statusEl.textContent = `Test message delivered to ${kind === 'slack' ? 'Slack' : kind === 'discord' ? 'Discord' : 'your webhook'}.`;
  } catch (err) {
    statusEl.className = 'status bad';
    statusEl.textContent = err.message;
  }
}

async function saveAlertSettings() {
  const statusEl = $('alerts-status');
  const url = $('webhook-url').value.trim();
  if (url && !/^https:\/\//.test(url)) {
    statusEl.className = 'status bad';
    statusEl.textContent = 'The webhook URL needs to start with https://';
    return;
  }
  state.config = await api.config.set({
    webhookUrl: url,
    dailyCheck: $('daily-check').checked,
    nvdApiKey: $('nvd-key').value.trim(),
  });
  writeSecurityForm(state.config);
  if (state.lastScan) renderFindings(state.lastScan);
  statusEl.className = 'status ok';
  statusEl.textContent = url ? 'Saved. New findings will be posted to your channel after each check.' : 'Saved.';
}

async function testWebhook() {
  const statusEl = $('alerts-status');
  const url = $('webhook-url').value.trim();
  statusEl.className = 'status';
  statusEl.textContent = 'Sending…';
  try {
    const { kind } = await api.security.testWebhook(url);
    statusEl.className = 'status ok';
    statusEl.textContent = `Test message delivered to ${kind === 'slack' ? 'Slack' : kind === 'discord' ? 'Discord' : 'your webhook'}.`;
  } catch (err) {
    statusEl.className = 'status bad';
    statusEl.textContent = err.message;
  }
}

async function saveCredentials() {
  const btn = $('btn-save-creds');
  const statusEl = $('settings-status');
  btn.disabled = true;
  statusEl.className = 'status';
  statusEl.textContent = 'Signing in…';
  try {
    const result = await api.credentials.save({
      clientId: $('client-id').value,
      clientSecret: $('client-secret').value,
    });
    const who = result.account?.name || result.identity?.name || 'your account';
    statusEl.className = 'status ok';
    statusEl.textContent = `Connected as ${who}. Loading sites…`;
    $('client-id').value = '';
    $('client-secret').value = '';
    await refreshCredentialStatus();
    await loadSites();
    statusEl.textContent = `Connected as ${who}.`;
    setTimeout(() => $('settings').close(), 600);
  } catch (err) {
    statusEl.className = 'status bad';
    statusEl.textContent = err.message;
  } finally {
    btn.disabled = false;
  }
}

async function forgetCredentials() {
  if (!window.confirm('Remove the saved client ID and secret from this computer?')) return;
  await api.credentials.clear();
  state.sites = [];
  renderSites();
  $('site-status').replaceChildren();
  setConn('Not connected');
  await refreshCredentialStatus();
  openSettings('Credentials removed.', '');
}

// ---------- Wiring ----------

async function onTaskFormChange() {
  const t = readTaskForm();
  state.config = await api.config.set({ task: t });
  writeTaskForm(state.config.task);
  renderCounts();
}

function wire() {
  $('site-search').addEventListener('input', renderSites);
  $('single-filter').addEventListener('input', () => {
    renderSinglePicker();
    renderCounts();
  });
  $('single-site').addEventListener('change', () => {
    renderCounts();
    loadSiteStatus();
  });

  $('btn-add-shown').addEventListener('click', async () => {
    const needle = $('site-search').value.trim().toLowerCase();
    const ids = selectedIds();
    for (const site of state.sites.filter((s) => matches(s, needle))) ids.add(String(site.id));
    state.config = await api.config.set({ siteIds: [...ids] });
    renderSites();
  });
  $('btn-clear-list').addEventListener('click', async () => {
    state.config = await api.config.set({ siteIds: [] });
    renderSites();
  });
  $('btn-refresh').addEventListener('click', loadSites);

  for (const seg of document.querySelectorAll('.seg')) {
    seg.addEventListener('click', () => {
      for (const other of document.querySelectorAll('.seg')) other.setAttribute('aria-checked', 'false');
      seg.setAttribute('aria-checked', 'true');
      onTaskFormChange();
    });
  }
  for (const id of ['type-fs', 'type-db', 'cache-edge', 'cache-object', 'preload-on', 'preload-off', 'preload-edge']) {
    $(id).addEventListener('change', onTaskFormChange);
  }
  for (const id of ['security-all', 'security-list', 'security-notify']) {
    $(id).addEventListener('change', async () => {
      state.config = await api.config.set(readSecurityForm());
      writeSecurityForm(state.config);
      renderCounts();
    });
  }
  $('btn-send-new').addEventListener('click', () => sendFindings(true));
  $('btn-send-all').addEventListener('click', () => sendFindings(false));
  $('btn-hide-findings').addEventListener('click', () => { $('findings').hidden = true; });
  $('btn-save-alerts').addEventListener('click', saveAlertSettings);
  $('btn-test-webhook').addEventListener('click', testWebhook);
  api.security.onEvent(handleScanEvent);

  for (const id of ['users-all', 'users-list', 'users-notify']) {
    $(id).addEventListener('change', async () => {
      state.config = await api.config.set(readUsersForm());
      writeSecurityForm(state.config);
      renderCounts();
    });
  }
  $('btn-sentinel').addEventListener('click', startSentinelInstall);
  $('btn-hide-admins').addEventListener('click', () => { $('admins').hidden = true; });
  $('btn-save-users').addEventListener('click', saveUserAlertSettings);
  $('btn-save-schedule').addEventListener('click', saveSchedule);
  $('btn-test-user-webhook').addEventListener('click', testUserWebhook);
  api.users.onEvent(handleAuditEvent);
  api.sentinel.onEvent(handleSentinelEvent);

  $('run-list').addEventListener('click', () => startRun('list'));
  $('run-single').addEventListener('click', () => startRun('single'));
  $('btn-cancel').addEventListener('click', async () => {
    $('btn-cancel').disabled = true;
    if (state.scanning) await api.security.cancel();
    if (state.auditing) await api.users.cancel();
    if (state.running) await api.run.cancel();
    $('progress-text').textContent = 'Cancelling after the current step…';
    $('btn-cancel').disabled = false;
  });
  $('btn-clear-log').addEventListener('click', clearLog);

  $('btn-settings').addEventListener('click', () => openSettings(''));
  $('btn-close-settings').addEventListener('click', () => $('settings').close());
  $('btn-save-creds').addEventListener('click', saveCredentials);
  $('btn-forget').addEventListener('click', forgetCredentials);
  $('btn-data-folder').addEventListener('click', () => api.openDataFolder());
  $('link-apps').addEventListener('click', (e) => {
    e.preventDefault();
    api.openExternal('https://my.pressable.com/api/applications');
  });
  $('settings-form').addEventListener('submit', (e) => e.preventDefault());
  $('client-secret').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      saveCredentials();
    }
  });

  api.run.onEvent(handleRunEvent);
}

async function init() {
  wire();
  state.config = await api.config.get();
  writeTaskForm(state.config.task);
  writeSecurityForm(state.config);
  renderSites();

  const creds = await refreshCredentialStatus();
  if (!creds.configured) {
    openSettings('Connect your Pressable account to get started.', '');
    return;
  }
  setConn('Connecting…');
  await loadSites();
  try {
    const last = await api.security.lastResult();
    if (last && last.findings && last.findings.length) {
      state.lastScan = last;
      renderFindings(last);
    }
  } catch {
    // No earlier check; nothing to show.
  }
  try {
    const lastAudit = await api.users.lastResult();
    if (lastAudit && lastAudit.sites && lastAudit.sites.length) {
      state.lastAudit = lastAudit;
      renderAdmins(lastAudit);
    }
  } catch {
    // No earlier audit.
  }
  refreshSentinelStatus();
}

init().catch((err) => setConn(err.message, 'bad'));
