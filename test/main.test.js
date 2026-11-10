'use strict';

// Exercises the main process end to end with a fake Electron and mocked
// Pressable, cve.org and Slack endpoints. No display or Electron binary needed.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { jsonResponse, makeFakeElectron, installFakeElectron, sleep } = require('./helpers');

const userData = fs.mkdtempSync(path.join(os.tmpdir(), 'wayzgoose-test-'));
fs.writeFileSync(path.join(userData, 'credentials.bin'), JSON.stringify({ clientId: 'id', clientSecret: 'sec' }));
fs.writeFileSync(path.join(userData, 'config.json'), JSON.stringify({
  siteIds: ['1'], webhookUrl: 'https://hooks.slack.com/services/T/B/X', alertAutomatically: true, delayBetweenSitesMs: 0,
  userWebhookUrl: 'https://discord.com/api/webhooks/9/zzz', watchedRoles: 'administrator', userAlertAutomatically: true,
}));

const posted = [];
const discordPosted = [];
const wpcli = [];
const muPlugins = [];
let auditRound = 0;
const realFetch = globalThis.fetch;
globalThis.fetch = async (url, opts = {}) => {
  const u = String(url);
  if (u.endsWith('/auth/token')) return jsonResponse(200, { access_token: 't', expires_in: 3600, name: 'Jane Doe', email: 'j@x.com' });
  if (u.includes('/v1/sites?')) {
    return jsonResponse(200, { data: [
      { id: 1, name: 'acme', displayName: 'Acme Dental', url: 'acmedental.com', state: 'live' },
      { id: 2, name: 'blue', displayName: 'Blue River', url: 'blueriver.com', state: 'live' },
      { id: 3, name: 'sandbox', displayName: 'Sandbox', url: 's.com', state: 'live' },
    ] });
  }
  if (u.includes('/security-alerts/plugins')) {
    if (u.includes('/sites/3/')) return jsonResponse(400, { message: 'Bad Request', errors: ['Site is not live'] });
    return jsonResponse(200, { data: [{ slug: 'redirection', name: 'Redirection', version: '3.6.2', vulnerabilities: [
      { id: 'v1', title: 'Redirection < 3.6.3 - XSS', fixed_in: '3.6.3', references: { url: ['https://wpscan.com/vulnerability/9014'], cve: ['2018-6710'] } },
    ] }] });
  }
  if (u.includes('/security-alerts/themes')) return jsonResponse(200, { data: [] });
  if (u.includes('/wordpress/users')) {
    const siteId = Number(u.match(/sites\/(\d+)\//)[1]);
    if (siteId === 3) return jsonResponse(400, { message: 'Bad Request', errors: ['Site is not live'] });
    const list = [{ id: 1, user_login: 'erik', user_email: 'erik@example.com', roles: ['administrator'] }, { id: 2, user_login: 'ed', roles: ['editor'] }];
    if (siteId === 2 && auditRound > 1) list.push({ id: 7, user_login: 'intruder', user_email: 'x@evil.test', roles: ['administrator'], user_registered: '2026-11-09 22:00:00' });
    return jsonResponse(200, { data: { users: list } });
  }
  if (u.includes('/logs/webserver')) {
    const type = new URL(u).searchParams.get('request_type');
    const logs = type === 'POST' ? [
      { timestamp: new Date(Date.now() - 60_000).toISOString(), request_type: 'POST', path: '/wp-admin/user-new.php', status: 302, user_ip: '203.0.113.5', user_agent: 'Mozilla/5.0 (Windows NT 10.0) Chrome/130.0.0.0' },
      { timestamp: new Date(Date.now() - 50_000).toISOString(), request_type: 'POST', path: '/wp-admin/admin-ajax.php', status: 200, user_ip: '203.0.113.5' },
    ] : [];
    return jsonResponse(200, { data: { logs, scroll_id: null } });
  }
  if (u.endsWith('/logs/activity')) return jsonResponse(200, { data: { logs: [{ created: new Date(Date.now() - 30_000).toISOString(), description: 'Executed WP-CLI command', email: 'erik@example.com', ipAddress: '203.0.113.5', source: 'ui' }] } });
  if (u.endsWith('/wordpress/wpcli')) { wpcli.push([u.match(/sites\/(\d+)\//)[1], JSON.parse(opts.body).commands]); return jsonResponse(200, { data: null }); }
  if (u.endsWith('/v1/mu-plugins') && opts.method === 'POST') { muPlugins.push(JSON.parse(opts.body)); return jsonResponse(201, { data: { id: 42, ...JSON.parse(opts.body) } }); }
  if (u.endsWith('/v1/mu-plugins')) return jsonResponse(200, { data: muPlugins.map((m, i) => ({ id: 42 + i, ...m })) });
  if (u.includes('/v1/mu-plugins/') && opts.method === 'PUT') return jsonResponse(200, { data: { id: 42 } });
  if (u.startsWith('https://discord.com/api/webhooks/')) { discordPosted.push(JSON.parse(opts.body)); return jsonResponse(204, ''); }
  if (u.includes('/ondemand-backups') && opts.method === 'POST') return jsonResponse(201, { data: { id: 500, backup_type: JSON.parse(opts.body).backup_type, state: 'pending' } });
  if (u.includes('/ondemand-backups')) return jsonResponse(200, { data: [] });
  if (u.includes('cveawg.mitre.org')) {
    return jsonResponse(200, { cveMetadata: { cveId: 'CVE-2018-6710', assignerShortName: 'mitre' }, containers: { cna: {
      descriptions: [{ lang: 'en', value: 'XSS in Redirection before 3.6.3.' }],
      metrics: [{ cvssV3_1: { baseScore: 6.1, baseSeverity: 'MEDIUM', vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N' } }],
    } } });
  }
  if (u.startsWith('https://hooks.slack.com/')) { posted.push(JSON.parse(opts.body)); return jsonResponse(200, 'ok'); }
  return jsonResponse(404, { message: `unexpected ${u}` });
};

const electron = makeFakeElectron(userData);
const restore = installFakeElectron(electron);
require('../src/main');
electron.app._ready();
const h = electron._handlers;

const waitFor = async (predicate, ms = 5000) => {
  const start = Date.now();
  while (Date.now() - start < ms) {
    if (predicate()) return;
    await sleep(25);
  }
  throw new Error('timed out waiting');
};

test.after(() => {
  restore();
  globalThis.fetch = realFetch;
  fs.rmSync(userData, { recursive: true, force: true });
});

test('backup run replaces nothing when a site has room and streams events', async () => {
  await sleep(50);
  const start = await h.get('run:start')({}, { mode: 'single', siteId: 1, task: { kind: 'backup', backupTypes: ['fs'] } });
  assert.equal(start.siteCount, 1);
  await waitFor(() => electron._sent.some(([c, p]) => c === 'run:event' && p.kind === 'finished'));
  const done = electron._sent.find(([c, p]) => c === 'run:event' && p.kind === 'item:done')[1];
  assert.equal(done.result.backupId, 500);
  assert.equal(done.result.replacedId, null);
});

test('vulnerability check groups sites, enriches the CVE and alerts once', async () => {
  const start = await h.get('security:scan')({}, { scope: 'all', notify: true });
  assert.equal(start.siteCount, 3);
  await waitFor(() => electron._sent.some(([c, p]) => c === 'scan:event' && p.kind === 'finished'));
  const result = electron._sent.find(([c, p]) => c === 'scan:event' && p.kind === 'finished')[1].result;

  assert.equal(result.findings.length, 1);
  const [finding] = result.findings;
  assert.equal(finding.key, 'CVE-2018-6710');
  assert.equal(finding.severity, 'medium');
  assert.deepEqual(finding.sites.map((s) => s.siteName), ['Acme Dental', 'Blue River']);
  assert.deepEqual(result.errors.map((e) => e.siteName), ['Sandbox']);
  assert.equal(result.notified.ok, true);
  assert.equal(result.newCount, 0, 'everything is reported after the automatic alert');
  assert.equal(posted.length, 1, 'one finding, so one message and no summary');
  assert.match(posted[0].blocks[0].text.text, /MEDIUM 6\.1/);

  const again = await h.get('security:notify')({}, { onlyNew: true });
  assert.deepEqual(again, { sent: 0, findings: 0 });
  const all = await h.get('security:notify')({}, { onlyNew: false });
  assert.equal(all.findings, 1);
  assert.equal(posted.length, 2);

  const seen = JSON.parse(fs.readFileSync(path.join(userData, 'seen-findings.json'), 'utf8'));
  assert.deepEqual(Object.keys(seen).sort(), ['CVE-2018-6710|1', 'CVE-2018-6710|2']);
  assert.ok(fs.existsSync(path.join(userData, 'cve-cache.json')));
});

test('user audit records a baseline, then alerts on a new administrator', async () => {
  auditRound = 1;
  electron._sent.length = 0;
  await h.get('users:audit')({}, { scope: 'all', notify: true });
  await waitFor(() => electron._sent.some(([c, p]) => c === 'audit:event' && p.kind === 'finished'));
  const first = electron._sent.find(([c, p]) => c === 'audit:event' && p.kind === 'finished')[1].result;
  assert.equal(first.checked, 2);
  assert.ok(first.sites.every((s) => s.baseline));
  assert.equal(first.events.length, 0);
  assert.deepEqual(first.errors.map((e) => e.siteName), ['Sandbox']);
  assert.equal(discordPosted.length, 0, 'baseline is silent');

  auditRound = 2;
  electron._sent.length = 0;
  await h.get('users:audit')({}, { scope: 'all', notify: true });
  await waitFor(() => electron._sent.some(([c, p]) => c === 'audit:event' && p.kind === 'finished'));
  const second = electron._sent.find(([c, p]) => c === 'audit:event' && p.kind === 'finished')[1].result;
  assert.equal(second.events.length, 1);
  assert.equal(second.events[0].kind, 'added');
  assert.equal(second.events[0].user.login, 'intruder');
  assert.equal(second.events[0].siteName, 'Blue River');
  assert.equal(second.notified.ok, true);
  assert.equal(discordPosted.length, 1, 'single change, single embed, no summary');
  assert.match(discordPosted[0].embeds[0].title, /New privileged user on Blue River/);
  const f = second.events[0].forensics;
  assert.equal(f.requestsChecked, true);
  assert.deepEqual(f.requests.map((r) => r.path), ['/wp-admin/user-new.php', '/wp-admin/admin-ajax.php']);
  assert.equal(f.activity.length, 1);
  assert.match(discordPosted[0].embeds[0].description, /POST \/wp-admin\/user-new\.php → 302 · from 203\.0\.113\.5/);
  assert.match(discordPosted[0].embeds[0].description, /Executed WP-CLI command · by erik@example\.com/);
  assert.equal(second.events[0].sessionCheck.requested, true);
  const evalCall = wpcli.find(([id, cmds]) => id === '2' && cmds[0].startsWith('eval '));
  assert.ok(evalCall, 'session check sent to the changed site through WP-CLI');
  assert.match(evalCall[1][0], /WP_Session_Tokens/);
  assert.match(discordPosted[0].embeds[0].description, /session check was sent to the site/);
  const blue = second.sites.find((s) => s.siteName === 'Blue River');
  assert.ok(blue.privileged.find((u) => u.login === 'intruder').isNew);
});

test('sentinel install registers the mu-plugin once and configures each site', async () => {
  electron._sent.length = 0;
  await h.get('sentinel:install')({}, { scope: 'all' });
  await waitFor(() => electron._sent.some(([c, p]) => c === 'sentinel:event' && p.kind === 'finished'));
  const r = electron._sent.find(([c, p]) => c === 'sentinel:event' && p.kind === 'finished')[1].result;
  assert.equal(r.ok, true);
  assert.equal(r.registration.action, 'created');
  assert.match(r.registration.source, /raw\.githubusercontent\.com\/Erik-Debye\/wayzgoose-for-pressable\/main\/mu-plugin\/wayzgoose-sentinel\.php$/);
  assert.equal(muPlugins.length, 1);
  assert.deepEqual([muPlugins[0].existing_sites, muPlugins[0].future_sites], [true, true]);
  assert.equal(r.sites.length, 3);
  assert.ok(r.sites.every((s) => s.configured === 'wp-config constant' && s.tested && !s.error));
  // per site: constants, then the test hook (the earlier audit test also ran an eval on site 2)
  const site1 = wpcli.filter(([id]) => id === '1');
  assert.equal(site1.length, 2);
  assert.match(site1[0][1][0], /config set WAYZGOOSE_SENTINEL_WEBHOOK 'https:\/\/discord\.com\/api\/webhooks\/9\/zzz'/);
  assert.match(site1[1][1][0], /wayzgoose_sentinel_test/);

  const status = await h.get('sentinel:status')();
  assert.equal(status.registered, true);

  // second install updates instead of creating a duplicate
  electron._sent.length = 0;
  await h.get('sentinel:install')({}, { scope: 'single', siteId: 1 });
  await waitFor(() => electron._sent.some(([c, p]) => c === 'sentinel:event' && p.kind === 'finished'));
  const again = electron._sent.find(([c, p]) => c === 'sentinel:event' && p.kind === 'finished')[1].result;
  assert.equal(again.registration.action, 'updated');
  assert.equal(muPlugins.length, 1);
});
