'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const php = require('../src/phplogs');
const uptime = require('../src/uptime');

test('normalizes raw PHP log lines and structured entries', () => {
  const e = php.normalizePhpEntry('[10-Nov-2026 12:00:00 UTC] PHP Fatal error:  Uncaught Error: Call to undefined function foo() in /srv/htdocs/wp-content/plugins/acme-forms/includes/x.php:12');
  assert.equal(e.severity, 'Fatal error');
  assert.equal(e.time.toISOString(), '2026-11-10T12:00:00.000Z');
  assert.equal(e.file, '/srv/htdocs/wp-content/plugins/acme-forms/includes/x.php');
  assert.equal(e.line, 12);
  assert.ok(php.isFatal(e));
  assert.equal(php.componentOf(e.file), 'plugin acme-forms');

  const w = php.normalizePhpEntry({ timestamp: '2026-11-10T12:01:00Z', severity: 'Warning', message: 'Undefined variable $x in /srv/htdocs/wp-content/themes/astra/functions.php on line 40' });
  assert.ok(!php.isFatal(w));
  assert.equal(w.file, '/srv/htdocs/wp-content/themes/astra/functions.php');
  assert.equal(w.line, 40);

  const mem = php.normalizePhpEntry('PHP Fatal error:  Allowed memory size of 536870912 bytes exhausted (tried to allocate 20480 bytes) in /srv/htdocs/wp-includes/class-wp-query.php on line 847');
  assert.ok(php.isFatal(mem));
  assert.equal(php.componentOf(mem.file), 'WordPress core');
});

test('same error with different numbers shares a signature', () => {
  const a = php.normalizePhpEntry('PHP Fatal error:  Allowed memory size of 536870912 bytes exhausted (tried to allocate 20480 bytes) in /x/y.php on line 847');
  const b = php.normalizePhpEntry('PHP Fatal error:  Allowed memory size of 536870912 bytes exhausted (tried to allocate 65536 bytes) in /x/y.php on line 847');
  const c = php.normalizePhpEntry('PHP Fatal error:  Uncaught TypeError: boom in /x/z.php:3');
  assert.equal(php.signatureOf(a), php.signatureOf(b));
  assert.notEqual(php.signatureOf(a), php.signatureOf(c));
});

test('triage groups fatals, alerts once per signature with a cooldown, ignores old entries', () => {
  const t0 = '2026-11-10T12:00:00.000Z';
  const lines = [
    '[10-Nov-2026 11:58:00 UTC] PHP Fatal error:  Uncaught Error: boom in /srv/htdocs/wp-content/plugins/acme/a.php:1',
    '[10-Nov-2026 11:59:00 UTC] PHP Fatal error:  Uncaught Error: boom in /srv/htdocs/wp-content/plugins/acme/a.php:1',
    '[10-Nov-2026 11:59:30 UTC] PHP Warning:  something minor in /x.php on line 2',
    '[09-Nov-2026 11:00:00 UTC] PHP Fatal error:  Uncaught Error: ancient in /x/old.php:1',
  ];
  const first = php.triage({ lastCheckedAt: '2026-11-10T11:45:00.000Z', signatures: {} }, lines, { now: t0 });
  assert.equal(first.events.length, 1, 'ancient entry is before lastCheckedAt, warning ignored');
  assert.equal(first.events[0].count, 2);
  assert.equal(first.events[0].component, 'plugin acme');
  assert.match(first.events[0].sample, /^Uncaught Error: boom/);

  // 15 minutes later it is still happening: counted, not re-alerted
  const second = php.triage(first.state, ['[10-Nov-2026 12:10:00 UTC] PHP Fatal error:  Uncaught Error: boom in /srv/htdocs/wp-content/plugins/acme/a.php:1'], { now: '2026-11-10T12:15:00.000Z' });
  assert.equal(second.events.length, 0);
  assert.equal(Object.values(second.state.signatures)[0].count, 3);

  // after the cooldown it alerts again, with the running count
  const third = php.triage(second.state, ['[10-Nov-2026 18:20:00 UTC] PHP Fatal error:  Uncaught Error: boom in /srv/htdocs/wp-content/plugins/acme/a.php:1'], { now: '2026-11-10T18:30:00.000Z' });
  assert.equal(third.events.length, 1);
  assert.equal(third.events[0].count, 4);

  const s = php.summarize(third.state, new Date('2026-11-10T19:00:00Z').getTime());
  assert.equal(s.count24h, 4);
  assert.equal(s.distinct24h, 1);
});

test('TLS state: warns at each threshold once, notes expiry once, and recovers on renewal', () => {
  const day = 86_400_000;
  const now = new Date('2026-11-10T00:00:00Z').getTime();
  const cert = (daysLeft) => uptime.certInfo({ valid_to: new Date(now + daysLeft * day).toUTCString(), valid_from: new Date(now - 60 * day).toUTCString(), issuer: { O: "Let's Encrypt" }, subject: { CN: 'acme.com' } }, true, null, now);

  let r = uptime.nextTlsState(null, cert(40));
  assert.equal(r.event, null);
  assert.equal(r.tls.daysLeft, 40);
  r = uptime.nextTlsState(r.tls, cert(14));
  assert.equal(r.event.kind, 'tls-expiring');
  assert.equal(r.event.threshold, 14);
  r = uptime.nextTlsState(r.tls, cert(13));
  assert.equal(r.event, null, 'no repeat inside the same threshold');
  r = uptime.nextTlsState(r.tls, cert(6));
  assert.equal(r.event.threshold, 7);
  r = uptime.nextTlsState(r.tls, cert(0));
  assert.equal(r.event.threshold, 1, 'skipping straight past 3 to 1 still fires once');
  r = uptime.nextTlsState(r.tls, cert(-1));
  assert.equal(r.event.kind, 'tls-expired');
  r = uptime.nextTlsState(r.tls, cert(-2));
  assert.equal(r.event, null);
  r = uptime.nextTlsState(r.tls, cert(89));
  assert.equal(r.event.kind, 'tls-renewed');
  assert.deepEqual(r.tls.alerted, []);

  const failed = uptime.nextTlsState(r.tls, { ok: false, error: 'TLS handshake timed out after 10 s' });
  assert.equal(failed.event, null);
  assert.equal(failed.tls.validTo, r.tls.validTo, 'a failed read keeps the last known certificate');
  assert.match(failed.tls.lastError, /timed out/);

  const payloads = uptime.buildUptimePayloads('discord', [
    { kind: 'tls-expiring', siteName: 'Acme', url: 'https://acme.com/', daysLeft: 6, validTo: '2026-11-16T00:00:00Z', issuer: "Let's Encrypt" },
    { kind: 'php-fatal', siteName: 'Acme', url: 'https://acme.com/', sample: 'Uncaught Error: boom', file: '/srv/htdocs/wp-content/plugins/acme/a.php', line: 1, component: 'plugin acme', count: 3, firstSeen: '2026-11-10T11:58:00Z', lastSeen: '2026-11-10T12:10:00Z' },
  ]);
  assert.match(payloads[0].embeds[0].title, /expires in 6 days/);
  assert.match(payloads[0].embeds[0].description, /Let's Encrypt/);
  assert.match(payloads[1].embeds[0].title, /logging PHP fatal errors/);
  assert.match(payloads[1].embeds[0].description, /plugin acme/);
});

test('checkTls reads a certificate from a fake socket', async () => {
  const EventEmitter = require('node:events');
  const fakeConnect = () => {
    const s = new EventEmitter();
    s.authorized = true;
    s.authorizationError = null;
    s.getPeerCertificate = () => ({ valid_to: new Date(Date.now() + 30 * 86_400_000).toUTCString(), valid_from: new Date().toUTCString(), issuer: { O: 'Test CA' }, subject: { CN: 'acme.com' } });
    s.end = () => {};
    s.destroy = () => {};
    setImmediate(() => s.emit('secureConnect'));
    return s;
  };
  const info = await uptime.checkTls('acme.com', { connect: fakeConnect });
  assert.equal(info.ok, true);
  assert.equal(info.daysLeft, 29);
  assert.equal(info.issuer, 'Test CA');

  const bad = await uptime.checkTls('acme.com', { connect: () => { const s = new EventEmitter(); s.destroy = () => {}; setImmediate(() => s.emit('error', Object.assign(new Error('x'), { code: 'ECONNREFUSED' }))); return s; } });
  assert.equal(bad.ok, false);
  assert.equal(bad.error, 'connection refused');
});
