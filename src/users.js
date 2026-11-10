'use strict';

// Privileged-user audit: who holds administrator (or other watched) roles on
// each site, what changed since last time, and how to tell a channel.
//
// Two layers work together. This module is the app-side audit: it polls the
// Pressable API and diffs. The mu-plugin in mu-plugin/wayzgoose-sentinel.php
// is the on-site layer that fires the instant a role changes and knows who
// did it. The audit catches anything the hooks can't see (direct database
// edits, changes made while the sentinel wasn't installed).

const DEFAULT_ROLES = ['administrator'];

function normalizeRoles(raw) {
  if (Array.isArray(raw)) return raw.map((r) => String(r).toLowerCase()).filter(Boolean);
  if (raw && typeof raw === 'object') return Object.keys(raw).filter((k) => raw[k]).map((k) => k.toLowerCase());
  if (typeof raw === 'string') return raw.split(/[,\s]+/).map((r) => r.toLowerCase()).filter(Boolean);
  return [];
}

// Field names on a user object aren't fully documented; read the usual variants.
function normalizeUser(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const roles = normalizeRoles(raw.roles ?? raw.role ?? raw.capabilities ?? raw.wp_capabilities ?? []);
  const login = raw.user_login ?? raw.login ?? raw.username ?? raw.slug ?? null;
  return {
    id: raw.id ?? raw.ID ?? null,
    login: login !== null ? String(login) : null,
    email: raw.user_email ?? raw.email ?? null,
    displayName: raw.display_name ?? raw.displayName ?? raw.name ?? null,
    registered: raw.user_registered ?? raw.registered ?? raw.registered_date ?? null,
    roles,
  };
}

function parseWatchedRoles(text) {
  const roles = String(text || '').split(/[,\s]+/).map((r) => r.trim().toLowerCase()).filter(Boolean);
  return roles.length ? [...new Set(roles)] : [...DEFAULT_ROLES];
}

function isPrivileged(user, watched) {
  return user.roles.some((r) => watched.includes(r));
}

const userKey = (u) => (u.id !== null && u.id !== undefined ? `id:${u.id}` : `login:${u.login}`);

// Compare this site's privileged users with the stored snapshot.
// snapshot: { [userKey]: { login, email, roles, registered, firstSeen } } or null on first run.
function diffPrivileged(siteSnapshot, privilegedUsers, now = new Date().toISOString()) {
  const previous = siteSnapshot && siteSnapshot.users ? siteSnapshot.users : null;
  const nextUsers = {};
  const added = [];
  const removed = [];
  const changed = [];

  for (const u of privilegedUsers) {
    const key = userKey(u);
    const before = previous ? previous[key] : null;
    nextUsers[key] = {
      login: u.login,
      email: u.email,
      displayName: u.displayName,
      roles: u.roles,
      registered: u.registered,
      firstSeen: before ? before.firstSeen : now,
    };
    if (previous && !before) added.push(u);
    else if (before && before.roles && before.roles.join(',') !== u.roles.join(',')) changed.push({ user: u, from: before.roles, to: u.roles });
  }
  if (previous) {
    for (const [key, before] of Object.entries(previous)) {
      if (!(key in nextUsers)) removed.push({ ...before, key });
    }
  }
  return {
    baseline: !previous,
    added,
    removed,
    changed,
    snapshot: { users: nextUsers, checkedAt: now },
  };
}

// ----- WP-CLI commands that configure the sentinel on a site -----
// `wp config set` writes a constant into wp-config.php; if the host refuses
// to touch wp-config, the option fallback is used and the mu-plugin reads
// either. Quotes: webhook URLs and role lists never contain single quotes.

function sentinelConfigCommands(webhookUrl, watchedRoles) {
  const roles = (watchedRoles && watchedRoles.length ? watchedRoles : DEFAULT_ROLES).join(',');
  if (/'/.test(webhookUrl) || /'/.test(roles)) throw new Error('Webhook URL and roles must not contain single quotes.');
  return {
    constants: [
      `config set WAYZGOOSE_SENTINEL_WEBHOOK '${webhookUrl}' --type=constant --quiet`,
      `config set WAYZGOOSE_SENTINEL_ROLES '${roles}' --type=constant --quiet`,
    ],
    options: [
      `option update wayzgoose_sentinel_webhook '${webhookUrl}' --autoload=yes --quiet`,
      `option update wayzgoose_sentinel_roles '${roles}' --autoload=yes --quiet`,
    ],
    test: [`eval 'do_action("wayzgoose_sentinel_test");'`],
    remove: [
      'config delete WAYZGOOSE_SENTINEL_WEBHOOK --quiet',
      'config delete WAYZGOOSE_SENTINEL_ROLES --quiet',
      'option delete wayzgoose_sentinel_webhook --quiet',
      'option delete wayzgoose_sentinel_roles --quiet',
    ],
  };
}

// Raw-file URL for the sentinel in the project's own repository, derived from
// package.json's repository field so forks publish their own copy.
function sentinelSourceUrl(repositoryUrl, ref = 'main') {
  const m = String(repositoryUrl || '').match(/github\.com[/:]([^/]+)\/([^/.]+)(?:\.git)?/i);
  if (!m) return null;
  return `https://raw.githubusercontent.com/${m[1]}/${m[2]}/${ref}/mu-plugin/wayzgoose-sentinel.php`;
}

// ----- Forensics from Pressable's logs -----
//
// The web server log can't name the WordPress user (no cookies or request
// bodies are logged), but it does show which requests could have made the
// change, when, from which IP and client. The site activity log adds any
// Pressable-level action (WP-CLI, phpMyAdmin, restores) with the Pressable
// account that did it. Together they usually answer "how and from where".

const USER_MGMT_PATHS = [
  [/\/wp-admin\/user-new\.php/i, 'Add New User screen'],
  [/\/wp-admin\/user-edit\.php/i, 'Edit User screen'],
  [/\/wp-admin\/users\.php/i, 'Users list (bulk role change or delete)'],
  [/\/wp-admin\/profile\.php/i, 'Profile screen'],
  [/\/wp-json\/wp\/v2\/users/i, 'REST API users endpoint'],
  [/\/xmlrpc\.php/i, 'XML-RPC'],
  [/\/wp-admin\/admin-ajax\.php/i, 'admin-ajax'],
  [/\/wp-admin\/network\/(users|user-new|site-users)\.php/i, 'Network admin users'],
];

const WRITE_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE'];

function parseLogTime(raw) {
  if (raw === null || raw === undefined) return null;
  if (typeof raw === 'number') return new Date(raw < 1e12 ? raw * 1000 : raw);
  const d = new Date(raw);
  return Number.isNaN(d.getTime()) ? null : d;
}

function normalizeLogEntry(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const method = String(raw.request_type ?? raw.method ?? raw.request_method ?? '').toUpperCase();
  let path = raw.path ?? raw.url ?? raw.request_uri ?? raw.uri ?? raw.request ?? '';
  path = String(path);
  const m = path.match(/^[A-Z]+\s+(\S+)/);
  if (m) path = m[1];
  return {
    time: parseLogTime(raw.timestamp ?? raw['@timestamp'] ?? raw.time ?? raw.date ?? raw.created ?? raw.datetime ?? null),
    method,
    path,
    status: raw.status ?? raw.status_code ?? raw.response_code ?? null,
    ip: raw.user_ip ?? raw.ip ?? raw.remote_addr ?? raw.client_ip ?? null,
    userAgent: raw.user_agent ?? raw.userAgent ?? raw.http_user_agent ?? raw.agent ?? null,
    referer: raw.referer ?? raw.referrer ?? raw.http_referer ?? null,
  };
}

// Write requests to user-management endpoints inside the window.
function relevantRequests(entries, { since, until }) {
  const from = since ? new Date(since).getTime() : 0;
  const to = until ? new Date(until).getTime() : Infinity;
  const out = [];
  for (const raw of entries) {
    const e = normalizeLogEntry(raw);
    if (!e || !WRITE_METHODS.includes(e.method)) continue;
    const hit = USER_MGMT_PATHS.find(([re]) => re.test(e.path));
    if (!hit) continue;
    if (e.time && (e.time.getTime() < from || e.time.getTime() > to)) continue;
    out.push({ ...e, what: hit[1] });
  }
  return out.sort((a, b) => (a.time ? a.time.getTime() : 0) - (b.time ? b.time.getTime() : 0));
}

function normalizeActivity(raw) {
  if (!raw || typeof raw !== 'object') return null;
  return {
    time: parseLogTime(raw.created ?? raw.createdAt ?? raw.timestamp ?? raw.date ?? null),
    name: raw.name ?? raw.action ?? null,
    description: raw.description ?? raw.message ?? null,
    message: raw.message ?? null,
    email: raw.email ?? raw.user ?? raw.userEmail ?? null,
    ip: raw.ipAddress ?? raw.ip_address ?? raw.ip ?? null,
    source: raw.source ?? null,
  };
}

function relevantActivity(entries, { since, until }) {
  const from = since ? new Date(since).getTime() : 0;
  const to = until ? new Date(until).getTime() : Infinity;
  return entries.map(normalizeActivity).filter(Boolean)
    .filter((a) => !a.time || (a.time.getTime() >= from && a.time.getTime() <= to))
    .sort((a, b) => (a.time ? a.time.getTime() : 0) - (b.time ? b.time.getTime() : 0));
}

function shortAgent(ua) {
  if (!ua) return null;
  const s = String(ua);
  const browser = (s.match(/(Edg|OPR|Chrome|Firefox|Safari)\/[\d.]+/) || [])[0] || (s.match(/^[^\s/]+\/[\d.]+/) || [])[0] || s.slice(0, 40);
  const os = (s.match(/\((Windows NT [\d.]+|Macintosh|iPhone|iPad|Android[^;)]*|Linux[^;)]*)/) || [])[1] || null;
  return [browser, os].filter(Boolean).join(' · ');
}

const fmtTime = (d) => {
  if (!d) return 'time unknown';
  const date = d instanceof Date ? d : new Date(d);
  return Number.isNaN(date.getTime()) ? 'time unknown' : date.toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
};

function forensicsLines(forensics) {
  if (!forensics) return [];
  const lines = [];
  const win = forensics.window;
  lines.push(`Window: ${win && win.since ? fmtTime(new Date(win.since)) : 'start'} → ${win && win.until ? fmtTime(new Date(win.until)) : 'now'}`);
  if (forensics.requests.length) {
    lines.push(`Requests that could have made the change (${forensics.requests.length}):`);
    for (const r of forensics.requests.slice(0, 8)) {
      lines.push(`• ${fmtTime(r.time)} ${r.method} ${r.path.slice(0, 80)}${r.status ? ` → ${r.status}` : ''} · from ${r.ip || '?'}${r.userAgent ? ` · ${shortAgent(r.userAgent)}` : ''} (${r.what})`);
    }
    if (forensics.requests.length > 8) lines.push(`• …and ${forensics.requests.length - 8} more`);
  } else if (forensics.requestsChecked) {
    lines.push('No write requests to user-management endpoints in the window: change likely came from WP-CLI, a database edit, or outside the log retention.');
  }
  if (forensics.activity.length) {
    lines.push(`Pressable activity in the window:`);
    for (const a of forensics.activity.slice(0, 6)) {
      lines.push(`• ${fmtTime(a.time)} ${a.description || a.name || 'action'}${a.email ? ` · by ${a.email}` : ''}${a.ip ? ` · ${a.ip}` : ''}${a.source ? ` · ${a.source}` : ''}`);
    }
  }
  if (forensics.error) lines.push(`Log lookup incomplete: ${forensics.error}`);
  return lines;
}

// ----- Session check (WP-CLI job on the site) -----
//
// scripts/session-check.php is sent to the site as `wp eval '<one line>'`.
// It must contain no single quotes; comment lines are stripped here. The
// arguments ride along as base64 JSON prepended as $args.

function buildEvalCommand(phpSource, cfg) {
  const lines = String(phpSource)
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('//') && !l.startsWith('<?php'));
  const body = lines.join(' ');
  if (body.includes("'")) throw new Error('Scripts sent through wp eval must not contain single quotes.');
  const args = Buffer.from(JSON.stringify(cfg), 'utf8').toString('base64');
  return `eval '$args = array("${args}"); ${body}' --skip-plugins --skip-themes`;
}

// ----- Webhook messages for audit results -----

function eventLines(ev, { markdown }) {
  const b = markdown === 'discord' ? (t) => `**${t}**` : (t) => `*${t}*`;
  const lines = [];
  const u = ev.user;
  lines.push(`${b('User')}: ${u.login || 'unknown'}${u.id !== null && u.id !== undefined ? ` (ID ${u.id})` : ''}${u.email ? ` · ${u.email}` : ''}`);
  if (ev.kind === 'changed') lines.push(`${b('Roles')}: ${ev.from.join(', ')} → ${ev.to.join(', ')}`);
  else lines.push(`${b('Roles')}: ${u.roles.join(', ')}`);
  if (u.registered) lines.push(`${b('Registered')}: ${u.registered}`);
  lines.push(`${b('Site')}: ${ev.siteName}${ev.siteUrl ? ` (${ev.siteUrl})` : ''}`);
  if (ev.forensics) {
    lines.push('');
    lines.push(...forensicsLines(ev.forensics));
  }
  if (ev.sessionCheck && ev.sessionCheck.requested) {
    lines.push('A session check was sent to the site; it posts here which users able to change roles were logged in during the window.');
  } else if (ev.sessionCheck && ev.sessionCheck.error) {
    lines.push(`Session check could not be started: ${ev.sessionCheck.error}`);
  }
  lines.push('_Found by audit. Logs show how and from where; the session check and, if installed, the sentinel narrow down who._');
  return lines;
}

const KIND_TITLE = {
  added: 'New privileged user',
  changed: 'Privileged user’s roles changed',
  removed: 'Privileged user removed',
};
const KIND_EMOJI = { added: '🟥', changed: '🟧', removed: '🟨' };
const KIND_COLOR = { added: 0xb0392f, changed: 0xd9772c, removed: 0xc9a227 };

// events: [{ kind: 'added'|'changed'|'removed', user, from?, to?, siteId, siteName, siteUrl }]
function buildAuditPayloads(webhookKind, events, { accountLabel = null } = {}) {
  if (events.length === 0) return [];
  const sites = new Set(events.map((e) => String(e.siteId)));
  const title = `${events.length} privileged-user ${events.length === 1 ? 'change' : 'changes'} across ${sites.size} ${sites.size === 1 ? 'site' : 'sites'} on Pressable`;
  const sub = `${accountLabel ? `${accountLabel} · ` : ''}${new Date().toLocaleString()}`;
  const payloads = [];

  if (webhookKind === 'discord') {
    if (events.length > 1) payloads.push({ content: `**${title}**\n${sub}` });
    for (const ev of events) {
      payloads.push({ embeds: [{
        title: `${KIND_EMOJI[ev.kind]} ${KIND_TITLE[ev.kind]} on ${ev.siteName}`.slice(0, 256),
        description: eventLines(ev, { markdown: 'discord' }).join('\n').slice(0, 4000),
        color: KIND_COLOR[ev.kind],
        footer: { text: `Wayzgoose for Pressable${accountLabel ? ` · ${accountLabel}` : ''} · audit` },
        timestamp: new Date().toISOString(),
      }] });
    }
    return payloads;
  }

  if (webhookKind === 'slack') {
    if (events.length > 1) {
      payloads.push({ text: title, blocks: [
        { type: 'header', text: { type: 'plain_text', text: title.slice(0, 150) } },
        { type: 'context', elements: [{ type: 'mrkdwn', text: sub }] },
      ] });
    }
    for (const ev of events) {
      payloads.push({
        text: `${KIND_TITLE[ev.kind]} on ${ev.siteName}: ${ev.user.login || 'unknown'}`,
        blocks: [
          { type: 'header', text: { type: 'plain_text', text: `${KIND_EMOJI[ev.kind]} ${KIND_TITLE[ev.kind]} on ${ev.siteName}`.slice(0, 150) } },
          { type: 'section', text: { type: 'mrkdwn', text: eventLines(ev, { markdown: 'slack' }).join('\n').slice(0, 2900) } },
          { type: 'context', elements: [{ type: 'mrkdwn', text: `Wayzgoose for Pressable${accountLabel ? ` · ${accountLabel}` : ''} · audit · ${new Date().toLocaleString()}` }] },
        ],
      });
    }
    return payloads;
  }

  return events.map((ev, i) => ({
    text: `${KIND_TITLE[ev.kind]} on ${ev.siteName}: ${ev.user.login || 'unknown'}`,
    generatedAt: new Date().toISOString(),
    batch: { index: i + 1, total: events.length, summary: title },
    event: ev,
  }));
}

module.exports = {
  DEFAULT_ROLES,
  USER_MGMT_PATHS,
  normalizeLogEntry,
  relevantRequests,
  normalizeActivity,
  relevantActivity,
  forensicsLines,
  buildEvalCommand,
  buildSessionCheckCommand: buildEvalCommand,
  normalizeUser,
  normalizeRoles,
  parseWatchedRoles,
  isPrivileged,
  userKey,
  diffPrivileged,
  sentinelConfigCommands,
  sentinelSourceUrl,
  buildAuditPayloads,
};
