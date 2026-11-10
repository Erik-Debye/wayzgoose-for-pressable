'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const uptime = require('../src/uptime');

test('probe classifies responses and errors', async () => {
  const ok = await uptime.probe('https://example.test/', { fetchImpl: async () => ({ status: 200, url: 'https://example.test/', body: { cancel: async () => {} } }) });
  assert.equal(uptime.isUp(ok), true);
  assert.match(uptime.describeResult(ok), /HTTP 200 in \d+ ms/);

  const maintenance = await uptime.probe('https://example.test/', { fetchImpl: async () => ({ status: 503, url: 'https://example.test/' }) });
  assert.equal(uptime.isUp(maintenance), false);

  const forbidden = await uptime.probe('https://example.test/', { fetchImpl: async () => ({ status: 403, url: 'https://example.test/' }) });
  assert.equal(uptime.isUp(forbidden), true, 'password-protected sites still count as up');

  const dns = await uptime.probe('https://nope.test/', { fetchImpl: async () => { const e = new Error('fetch failed'); e.cause = { code: 'ENOTFOUND' }; throw e; } });
  assert.equal(uptime.isUp(dns), false);
  assert.equal(dns.error, 'DNS lookup failed');

  const slow = await uptime.probe('https://slow.test/', { timeoutMs: 30, fetchImpl: (_u, { signal }) => new Promise((_r, rej) => signal.addEventListener('abort', () => { const e = new Error('aborted'); e.name = 'AbortError'; rej(e); })) });
  assert.equal(slow.ok, false);
  assert.match(slow.error, /no response within/);
});

test('state machine reports down once after N failures and up once on recovery', () => {
  const up = { ok: true, status: 200, latencyMs: 100, error: null };
  const down = { ok: false, status: null, latencyMs: 15000, error: 'no response within 15 s' };
  const t = (i) => new Date(Date.UTC(2026, 10, 10, 12, i)).toISOString();

  let s = uptime.nextState(null, up, { failuresToAlert: 2, now: t(0) });
  assert.equal(s.state.status, 'up');
  assert.equal(s.event, null);

  s = uptime.nextState(s.state, down, { failuresToAlert: 2, now: t(5) });
  assert.equal(s.state.status, 'up', 'one failure is not yet down');
  assert.equal(s.state.failures, 1);
  assert.equal(s.event, null);

  s = uptime.nextState(s.state, down, { failuresToAlert: 2, now: t(10) });
  assert.equal(s.state.status, 'down');
  assert.equal(s.event.kind, 'down');
  assert.equal(s.event.since, t(5), 'down since the first failure');

  s = uptime.nextState(s.state, down, { failuresToAlert: 2, now: t(15) });
  assert.equal(s.event, null, 'no repeat alert while still down');
  assert.equal(s.state.failures, 3);

  s = uptime.nextState(s.state, up, { failuresToAlert: 2, now: t(40) });
  assert.equal(s.state.status, 'up');
  assert.equal(s.event.kind, 'up');
  assert.equal(s.event.downFor, '35 min');
  assert.equal(s.state.failures, 0);

  // a blip that recovers before the threshold never alerts
  s = uptime.nextState(s.state, down, { failuresToAlert: 2, now: t(45) });
  s = uptime.nextState(s.state, up, { failuresToAlert: 2, now: t(50) });
  assert.equal(s.event, null);
  assert.equal(s.state.status, 'up');
});

test('duration text and webhook payloads', () => {
  assert.equal(uptime.durationText('2026-11-10T00:00:00Z', '2026-11-10T00:00:20Z'), 'under a minute');
  assert.equal(uptime.durationText('2026-11-10T00:00:00Z', '2026-11-10T03:05:00Z'), '3 h 5 min');
  assert.equal(uptime.durationText('2026-11-08T00:00:00Z', '2026-11-10T02:00:00Z'), '2 d 2 h');
  const events = [
    { kind: 'down', siteName: 'Acme', url: 'https://acme.com/', detail: 'HTTP 503 in 120 ms', since: '2026-11-10T12:05:00Z', failures: 2 },
    { kind: 'up', siteName: 'Acme', url: 'https://acme.com/', detail: 'HTTP 200 in 300 ms', downSince: '2026-11-10T12:05:00Z', downFor: '35 min' },
  ];
  const discord = uptime.buildUptimePayloads('discord', events, { accountLabel: 'Erik' });
  assert.equal(discord.length, 2);
  assert.match(discord[0].embeds[0].title, /🔴 Acme is down/);
  assert.match(discord[0].embeds[0].description, /HTTP 503/);
  assert.match(discord[1].embeds[0].title, /🟢 Acme is back up/);
  assert.match(discord[1].embeds[0].description, /Was down for.*35 min/);
  assert.equal(uptime.buildUptimePayloads('slack', events)[0].blocks[0].type, 'header');
  assert.equal(uptime.siteUrl({ url: 'acme.com' }), 'https://acme.com/');
  assert.equal(uptime.siteUrl({ url: 'https://acme.com/shop' }), 'https://acme.com/shop');
});
