'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const users = require('../src/users');

const apiUsers = [
  { id: 1, user_login: 'erik', user_email: 'erik@example.com', roles: ['administrator'], user_registered: '2024-01-01 10:00:00' },
  { id: 2, user_login: 'editor', user_email: 'ed@example.com', roles: ['editor'] },
  { id: 3, user_login: 'subscriber', roles: ['subscriber'] },
];

test('normalizes users and picks out watched roles', () => {
  const all = apiUsers.map(users.normalizeUser);
  const watched = users.parseWatchedRoles('administrator');
  assert.deepEqual(all.filter((u) => users.isPrivileged(u, watched)).map((u) => u.login), ['erik']);
  assert.deepEqual(users.parseWatchedRoles('Administrator, editor'), ['administrator', 'editor']);
  assert.deepEqual(users.parseWatchedRoles(''), ['administrator']);
  // capabilities-object shape
  assert.deepEqual(users.normalizeUser({ ID: 9, login: 'x', capabilities: { administrator: true, subscriber: false } }).roles, ['administrator']);
});

test('first audit is a silent baseline; later audits report added, changed and removed', () => {
  const watched = ['administrator'];
  const first = users.diffPrivileged(null, apiUsers.map(users.normalizeUser).filter((u) => users.isPrivileged(u, watched)));
  assert.equal(first.baseline, true);
  assert.deepEqual(first.added, []);
  assert.deepEqual(Object.keys(first.snapshot.users), ['id:1']);

  const later = [
    { id: 1, user_login: 'erik', roles: ['administrator'] },
    { id: 4, user_login: 'intruder', user_email: 'x@evil.test', roles: ['administrator'], user_registered: '2026-11-09 22:00:00' },
  ].map(users.normalizeUser);
  const second = users.diffPrivileged(first.snapshot, later);
  assert.equal(second.baseline, false);
  assert.deepEqual(second.added.map((u) => u.login), ['intruder']);
  assert.equal(second.snapshot.users['id:1'].firstSeen, first.snapshot.users['id:1'].firstSeen, 'firstSeen is preserved');

  const third = users.diffPrivileged(second.snapshot, [users.normalizeUser({ id: 4, user_login: 'intruder', roles: ['administrator', 'editor'] })]);
  assert.deepEqual(third.removed.map((u) => u.login), ['erik']);
  assert.equal(third.changed.length, 1);
  assert.deepEqual(third.changed[0].to, ['administrator', 'editor']);
});

test('builds WP-CLI commands and the sentinel source URL', () => {
  const cmds = users.sentinelConfigCommands('https://discord.com/api/webhooks/1/abc', ['administrator', 'editor']);
  assert.match(cmds.constants[0], /^config set WAYZGOOSE_SENTINEL_WEBHOOK 'https:\/\/discord\.com\/api\/webhooks\/1\/abc' --type=constant/);
  assert.match(cmds.constants[1], /'administrator,editor'/);
  assert.match(cmds.options[0], /^option update wayzgoose_sentinel_webhook/);
  assert.match(cmds.test[0], /wayzgoose_sentinel_test/);
  assert.throws(() => users.sentinelConfigCommands("https://x/'", []), /single quotes/);
  assert.equal(
    users.sentinelSourceUrl('https://github.com/Erik-Debye/wayzgoose-for-pressable.git'),
    'https://raw.githubusercontent.com/Erik-Debye/wayzgoose-for-pressable/main/mu-plugin/wayzgoose-sentinel.php',
  );
  assert.equal(users.sentinelSourceUrl('git@github.com:Erik-Debye/wayzgoose-for-pressable.git'), users.sentinelSourceUrl('https://github.com/Erik-Debye/wayzgoose-for-pressable'));
  assert.equal(users.sentinelSourceUrl(''), null);
});

test('audit alerts are one message per change', () => {
  const events = [
    { kind: 'added', user: users.normalizeUser({ id: 4, user_login: 'intruder', user_email: 'x@evil.test', roles: ['administrator'] }), siteId: 1, siteName: 'Acme', siteUrl: 'acme.com' },
    { kind: 'removed', user: users.normalizeUser({ id: 1, user_login: 'erik', roles: ['administrator'] }), siteId: 3, siteName: 'Blue', siteUrl: 'blue.com' },
  ];
  const discord = users.buildAuditPayloads('discord', events, { accountLabel: 'Erik' });
  assert.equal(discord.length, 3);
  assert.match(discord[0].content, /2 privileged-user changes across 2 sites/);
  assert.match(discord[1].embeds[0].title, /New privileged user on Acme/);
  assert.match(discord[1].embeds[0].description, /intruder \(ID 4\) · x@evil\.test/);
  const slack = users.buildAuditPayloads('slack', events.slice(0, 1));
  assert.equal(slack.length, 1);
  assert.equal(slack[0].blocks[0].type, 'header');
  assert.equal(users.buildAuditPayloads('generic', []).length, 0);
});

test('picks write requests to user-management endpoints from the web server log', () => {
  const entries = [
    { timestamp: '2026-11-09T21:41:07Z', request_type: 'POST', path: '/wp-admin/user-new.php', status: 302, user_ip: '203.0.113.5', user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64) Chrome/130.0.0.0 Safari/537.36' },
    { timestamp: '2026-11-09T21:41:08Z', request_type: 'GET', path: '/wp-admin/users.php', status: 200, user_ip: '203.0.113.5' },
    { timestamp: '2026-11-09T21:45:00Z', request_type: 'POST', path: '/wp-json/wp/v2/users/7', status: 200, user_ip: '198.51.100.9', user_agent: 'python-requests/2.32' },
    { timestamp: '2026-11-09T21:46:00Z', request_type: 'POST', path: '/wp-admin/admin-ajax.php', status: 200, user_ip: '203.0.113.5' },
    { timestamp: '2026-11-08T10:00:00Z', request_type: 'POST', path: '/wp-admin/user-edit.php', status: 302, user_ip: '10.0.0.1' },
    { request: 'POST /wp-login.php HTTP/1.1', status: 302, user_ip: '203.0.113.5' },
  ];
  const hits = users.relevantRequests(entries, { since: '2026-11-09T21:00:00Z', until: '2026-11-09T22:00:00Z' });
  assert.deepEqual(hits.map((h) => h.path), ['/wp-admin/user-new.php', '/wp-json/wp/v2/users/7', '/wp-admin/admin-ajax.php']);
  assert.equal(hits[0].what, 'Add New User screen');
  assert.equal(hits[1].what, 'REST API users endpoint');
  // "request line" shape and numeric timestamps are understood too
  const e = users.normalizeLogEntry({ request: 'PUT /wp-json/wp/v2/users/3?x=1 HTTP/1.1', request_type: 'PUT', timestamp: 1794260000 });
  assert.equal(e.path, '/wp-json/wp/v2/users/3?x=1');
  assert.equal(e.time.getUTCFullYear(), 2026);

  const lines = users.forensicsLines({
    window: { since: '2026-11-09T21:00:00Z', until: '2026-11-09T22:00:00Z' },
    requests: hits.map((h) => ({ ...h, time: h.time.toISOString() })),
    requestsChecked: true,
    activity: users.relevantActivity([{ created: '2026-11-09T21:40:00Z', description: 'WP-CLI command executed', email: 'erik@example.com', ipAddress: '203.0.113.5', source: 'ui' }], {}),
    error: null,
  });
  assert.match(lines.join('\n'), /21:41:07 UTC POST \/wp-admin\/user-new\.php → 302 · from 203\.0\.113\.5 · Chrome\/130\.0\.0\.0 · Windows NT 10\.0 \(Add New User screen\)/);
  assert.match(lines.join('\n'), /WP-CLI command executed · by erik@example\.com/);
});

test('session-check script is single-quote free and builds a one-line wp eval command', () => {
  const fs = require('node:fs');
  const php = fs.readFileSync(require('node:path').join(__dirname, '..', 'scripts', 'session-check.php'), 'utf8');
  assert.ok(!php.includes("'"), 'no single quotes in the PHP');
  const cmd = users.buildSessionCheckCommand(php, { webhook: 'https://discord.com/api/webhooks/1/a', since: 1, until: 2, ips: ['203.0.113.5'], site: 'acme.com', event: 'added: intruder' });
  assert.ok(cmd.startsWith("eval '$args = array(\""), cmd.slice(0, 40));
  assert.ok(cmd.endsWith("' --skip-plugins --skip-themes"));
  assert.ok(!cmd.includes('\n'), 'single line');
  assert.ok(!cmd.includes('Wayzgoose session check. Run on a site'), 'comment lines stripped');
  const b64 = cmd.match(/array\("([A-Za-z0-9+/=]+)"\)/)[1];
  assert.deepEqual(JSON.parse(Buffer.from(b64, 'base64').toString('utf8')).ips, ['203.0.113.5']);
  assert.match(cmd, /WP_Session_Tokens::get_instance/);
  assert.match(cmd, /get_user_application_passwords/);
  assert.throws(() => users.buildSessionCheckCommand("echo 'x';", {}), /single quotes/);
});
