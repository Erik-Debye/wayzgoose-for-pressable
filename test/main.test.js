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
}));

const posted = [];
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
