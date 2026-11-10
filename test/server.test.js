'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createServer, encryptedCredentials, loadOrCreateKey } = require('../src/server/server');

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'wayzgoose-server-'));
const env = {
  WAYZGOOSE_DATA_DIR: dataDir,
  WAYZGOOSE_PASSWORD: 'correct-horse-battery',
  WAYZGOOSE_INSECURE_COOKIE: '1',
  WAYZGOOSE_WEBHOOK_URL: 'https://hooks.slack.com/services/T/B/seed',
  PORT: '0',
  HOST: '127.0.0.1',
};

let app;
let base;
test.before(async () => {
  app = createServer(env);
  const addr = await app.listen(0, '127.0.0.1');
  base = `http://127.0.0.1:${addr.port}`;
});
test.after(async () => {
  await app.close();
  fs.rmSync(dataDir, { recursive: true, force: true });
});

test('refuses a short password', () => {
  assert.throws(() => createServer({ ...env, WAYZGOOSE_PASSWORD: 'short' }), /at least 12/);
});

test('shows the sign-in page to strangers and rejects API calls', async () => {
  const page = await fetch(`${base}/`);
  assert.equal(page.status, 200);
  assert.match(await page.text(), /Sign in/);
  assert.match(page.headers.get('content-security-policy'), /default-src 'self'/);
  const api = await fetch(`${base}/api/config:get`, { method: 'POST', headers: { 'X-Wayzgoose': '1' } });
  assert.equal(api.status, 401);
});

test('wrong password fails and is rate limited after five tries', async () => {
  for (let i = 0; i < 5; i += 1) {
    const r = await fetch(`${base}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password: 'nope-nope-nope' }) });
    assert.equal(r.status, 401);
  }
  const r = await fetch(`${base}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password: 'correct-horse-battery' }) });
  assert.equal(r.status, 429, 'even the right password is refused during the lockout');
});

test('signs in on a fresh server, serves the dashboard and the API, seeds config, and requires the CSRF header', async () => {
  // separate server so the rate limit from the previous test doesn't apply
  const dir2 = fs.mkdtempSync(path.join(os.tmpdir(), 'wayzgoose-server2-'));
  const app2 = createServer({ ...env, WAYZGOOSE_DATA_DIR: dir2 });
  const addr = await app2.listen(0, '127.0.0.1');
  const b = `http://127.0.0.1:${addr.port}`;
  try {
    const login = await fetch(`${b}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password: 'correct-horse-battery' }), redirect: 'manual' });
    assert.equal(login.status, 200);
    const cookie = login.headers.get('set-cookie');
    assert.match(cookie, /wz_session=.*HttpOnly.*SameSite=Strict/);
    const jar = cookie.split(';')[0];

    const page = await fetch(`${b}/`, { headers: { Cookie: jar } });
    const html = await page.text();
    assert.match(html, /<script src="\/bridge\.js"><\/script>/);
    assert.ok(!/Content-Security-Policy/.test(html), 'meta CSP removed in favour of the header');

    const noHeader = await fetch(`${b}/api/config:get`, { method: 'POST', headers: { Cookie: jar } });
    assert.equal(noHeader.status, 403);

    const cfg = await fetch(`${b}/api/config:get`, { method: 'POST', headers: { Cookie: jar, 'X-Wayzgoose': '1' } });
    assert.equal(cfg.status, 200);
    const body = await cfg.json();
    assert.equal(body.ok, true);
    assert.equal(body.result.webhookUrl, 'https://hooks.slack.com/services/T/B/seed', 'seeded from the environment');

    const set = await fetch(`${b}/api/config:set`, { method: 'POST', headers: { Cookie: jar, 'X-Wayzgoose': '1', 'Content-Type': 'application/json' }, body: JSON.stringify({ payload: { watchedRoles: 'administrator,editor' } }) });
    assert.equal((await set.json()).result.watchedRoles, 'administrator,editor');

    const unknown = await fetch(`${b}/api/nope`, { method: 'POST', headers: { Cookie: jar, 'X-Wayzgoose': '1' } });
    assert.equal(unknown.status, 404);

    const status = await fetch(`${b}/api/credentials:status`, { method: 'POST', headers: { Cookie: jar, 'X-Wayzgoose': '1' } });
    assert.deepEqual((await status.json()).result.configured, false);

    const logout = await fetch(`${b}/auth/logout`, { method: 'POST', headers: { Cookie: jar }, redirect: 'manual' });
    assert.equal(logout.status, 303);
    const after = await fetch(`${b}/api/config:get`, { method: 'POST', headers: { Cookie: jar, 'X-Wayzgoose': '1' } });
    assert.equal(after.status, 401);
  } finally {
    await app2.close();
    fs.rmSync(dir2, { recursive: true, force: true });
  }
});

test('bearer token works for automation without a session', async () => {
  const dir3 = fs.mkdtempSync(path.join(os.tmpdir(), 'wayzgoose-server3-'));
  const app3 = createServer({ ...env, WAYZGOOSE_DATA_DIR: dir3, WAYZGOOSE_API_TOKEN: 'tok-tok-tok-tok' });
  const addr = await app3.listen(0, '127.0.0.1');
  try {
    const r = await fetch(`http://127.0.0.1:${addr.port}/api/config:get`, { method: 'POST', headers: { Authorization: 'Bearer tok-tok-tok-tok' } });
    assert.equal(r.status, 200);
    const bad = await fetch(`http://127.0.0.1:${addr.port}/api/config:get`, { method: 'POST', headers: { Authorization: 'Bearer wrong' } });
    assert.equal(bad.status, 401);
  } finally {
    await app3.close();
    fs.rmSync(dir3, { recursive: true, force: true });
  }
});

test('credentials are encrypted at rest and env credentials take precedence', async () => {
  const dir4 = fs.mkdtempSync(path.join(os.tmpdir(), 'wayzgoose-creds-'));
  const key = loadOrCreateKey(dir4, null);
  assert.ok(fs.existsSync(path.join(dir4, 'secret.key')), 'key generated on first run');
  const store = encryptedCredentials({ dataDir: dir4, key });
  await store.save({ clientId: 'abc', clientSecret: 'shh' });
  const raw = fs.readFileSync(path.join(dir4, 'credentials.enc'));
  assert.ok(!raw.includes('shh'), 'secret not in plaintext');
  assert.deepEqual(await store.load(), { clientId: 'abc', clientSecret: 'shh' });
  const wrongKey = encryptedCredentials({ dataDir: dir4, key: Buffer.alloc(32, 1) });
  await assert.rejects(() => wrongKey.load(), /could not be decrypted/);
  const fromEnv = encryptedCredentials({ dataDir: dir4, key, envId: 'env-id', envSecret: 'env-secret' });
  assert.deepEqual(await fromEnv.load(), { clientId: 'env-id', clientSecret: 'env-secret' });
  await assert.rejects(() => fromEnv.save({ clientId: 'x', clientSecret: 'y' }), /server environment/);
  fs.rmSync(dir4, { recursive: true, force: true });
});
