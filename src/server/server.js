'use strict';

// Self-hosted Wayzgoose: the same engine as the desktop app, behind a small
// HTTP server. The dashboard is the desktop renderer served as a web page;
// src/server/bridge.js stands in for Electron's preload and talks to the
// routes below. Progress streams back over server-sent events.
//
// Environment (see .env.example):
//   WAYZGOOSE_PASSWORD         required: dashboard password
//   WAYZGOOSE_SECRET_KEY       64 hex chars; encrypts the Pressable secret at
//                              rest. Generated into <data>/secret.key if unset.
//   WAYZGOOSE_DATA_DIR         default /data
//   PORT, HOST                 default 8080, 0.0.0.0
//   PRESSABLE_CLIENT_ID/SECRET optional; if set they win over the dashboard
//   WAYZGOOSE_WEBHOOK_URL, WAYZGOOSE_USER_WEBHOOK_URL  optional first-run seeds
//   WAYZGOOSE_API_TOKEN        optional bearer token for scripts/automation
//   WAYZGOOSE_INSECURE_COOKIE  set to 1 only when serving plain http on a
//                              private network (Tailscale); cookies then lack
//                              the Secure flag
//   WAYZGOOSE_TRUST_PROXY      set to 1 behind Caddy/nginx so rate limiting
//                              sees the real client IP

const http = require('node:http');
const path = require('node:path');
const fs = require('node:fs/promises');
const fsSync = require('node:fs');
const crypto = require('node:crypto');
const { createEngine } = require('../core/engine');

const RENDERER_DIR = path.join(__dirname, '..', 'renderer');
const STATIC = {
  '/styles.css': { file: path.join(RENDERER_DIR, 'styles.css'), type: 'text/css; charset=utf-8' },
  '/renderer.js': { file: path.join(RENDERER_DIR, 'renderer.js'), type: 'text/javascript; charset=utf-8' },
  '/bridge.js': { file: path.join(__dirname, 'bridge.js'), type: 'text/javascript; charset=utf-8' },
};
const SESSION_TTL_MS = 12 * 3600_000;
const LOGIN_WINDOW_MS = 15 * 60_000;
const LOGIN_MAX_ATTEMPTS = 5;

// ---------- Credentials at rest: AES-256-GCM with the server key ----------

function encryptedCredentials({ dataDir, key, envId, envSecret }) {
  const file = path.join(dataDir, 'credentials.enc');
  return {
    encrypted: () => true,
    async load() {
      if (envId && envSecret) return { clientId: envId, clientSecret: envSecret };
      try {
        const buf = await fs.readFile(file);
        const iv = buf.subarray(0, 12);
        const tag = buf.subarray(12, 28);
        const data = buf.subarray(28);
        const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
        decipher.setAuthTag(tag);
        const text = Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8');
        return JSON.parse(text);
      } catch (err) {
        if (err.code === 'ENOENT') return null;
        throw new Error(`Stored credentials could not be decrypted (wrong WAYZGOOSE_SECRET_KEY?): ${err.message}`);
      }
    },
    async save({ clientId, clientSecret }) {
      if (envId && envSecret) throw new Error('Credentials come from the server environment (PRESSABLE_CLIENT_ID / PRESSABLE_CLIENT_SECRET) and cannot be changed here.');
      const iv = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
      const data = Buffer.concat([cipher.update(JSON.stringify({ clientId, clientSecret }), 'utf8'), cipher.final()]);
      await fs.mkdir(dataDir, { recursive: true });
      await fs.writeFile(file, Buffer.concat([iv, cipher.getAuthTag(), data]), { mode: 0o600 });
    },
    async clear() {
      if (envId && envSecret) throw new Error('Credentials come from the server environment and cannot be removed here.');
      try {
        await fs.unlink(file);
      } catch (err) {
        if (err.code !== 'ENOENT') throw err;
      }
    },
  };
}

function loadOrCreateKey(dataDir, hex) {
  if (hex) {
    if (!/^[0-9a-f]{64}$/i.test(hex)) throw new Error('WAYZGOOSE_SECRET_KEY must be 64 hex characters (openssl rand -hex 32).');
    return Buffer.from(hex, 'hex');
  }
  const file = path.join(dataDir, 'secret.key');
  try {
    const existing = fsSync.readFileSync(file, 'utf8').trim();
    if (/^[0-9a-f]{64}$/i.test(existing)) return Buffer.from(existing, 'hex');
  } catch {
    // generate below
  }
  const generated = crypto.randomBytes(32).toString('hex');
  fsSync.mkdirSync(dataDir, { recursive: true });
  fsSync.writeFileSync(file, generated + '\n', { mode: 0o600 });
  return Buffer.from(generated, 'hex');
}

// ---------- Small helpers ----------

function timingSafeEqualStr(a, b) {
  const ab = Buffer.from(String(a), 'utf8');
  const bb = Buffer.from(String(b), 'utf8');
  if (ab.length !== bb.length) {
    // Compare against self to keep timing flat, then fail.
    crypto.timingSafeEqual(ab, ab);
    return false;
  }
  return crypto.timingSafeEqual(ab, bb);
}

function parseCookies(header) {
  const out = {};
  for (const part of String(header || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

function readBody(req, limit = 1_000_000) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) {
        reject(new Error('Request body too large'));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function securityHeaders(res, { html = false } = {}) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cache-Control', 'no-store');
  if (html) {
    res.setHeader('Content-Security-Policy', "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
  }
}

function sendJson(res, status, body) {
  securityHeaders(res);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(body));
}

const LOGIN_PAGE = (error) => `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Wayzgoose for Pressable</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="/styles.css"></head>
<body>
<header class="topbar"><div class="brand">Wayzgoose <span class="brand-sub">for Pressable</span></div></header>
<main class="app login-main">
  <form method="post" action="/auth/login" class="action login-form">
    <h3>Sign in</h3>
    <label class="field"><span>Password</span><input class="input" type="password" name="password" autocomplete="current-password" autofocus required></label>
    ${error ? `<p class="status bad">${error}</p>` : ''}
    <button class="btn btn-accent" type="submit">Sign in</button>
  </form>
</main>
</body></html>`;

// ---------- Server ----------

function createServer(env = process.env) {
  const dataDir = env.WAYZGOOSE_DATA_DIR || '/data';
  const password = env.WAYZGOOSE_PASSWORD;
  if (!password || password.length < 12) {
    throw new Error('Set WAYZGOOSE_PASSWORD to at least 12 characters.');
  }
  const key = loadOrCreateKey(dataDir, env.WAYZGOOSE_SECRET_KEY);
  const apiToken = env.WAYZGOOSE_API_TOKEN || null;
  const secureCookie = env.WAYZGOOSE_INSECURE_COOKIE !== '1';
  const trustProxy = env.WAYZGOOSE_TRUST_PROXY === '1';

  const sseClients = new Set();
  const engine = createEngine({
    dataDir,
    credentials: encryptedCredentials({ dataDir, key, envId: env.PRESSABLE_CLIENT_ID, envSecret: env.PRESSABLE_CLIENT_SECRET }),
    emit: (channel, payload) => {
      const frame = `event: ${channel}\ndata: ${JSON.stringify(payload)}\n\n`;
      for (const res of sseClients) res.write(frame);
    },
  });

  // First-run seeds from the environment, never overwriting dashboard edits.
  const seed = async () => {
    const cfg = await engine.loadConfig();
    const patch = {};
    if (env.WAYZGOOSE_WEBHOOK_URL && !cfg.webhookUrl) patch.webhookUrl = env.WAYZGOOSE_WEBHOOK_URL;
    if (env.WAYZGOOSE_USER_WEBHOOK_URL && !cfg.userWebhookUrl) patch.userWebhookUrl = env.WAYZGOOSE_USER_WEBHOOK_URL;
    if (Object.keys(patch).length) await engine.saveConfig(patch);
  };

  const sessions = new Map(); // token -> expiresAt
  const loginAttempts = new Map(); // ip -> { count, resetAt }

  const clientIp = (req) => {
    if (trustProxy) {
      const fwd = req.headers['x-forwarded-for'];
      if (fwd) return String(fwd).split(',')[0].trim();
    }
    return req.socket.remoteAddress || 'unknown';
  };

  const isAuthed = (req) => {
    const auth = req.headers.authorization;
    if (apiToken && auth && auth.startsWith('Bearer ') && timingSafeEqualStr(auth.slice(7), apiToken)) return true;
    const token = parseCookies(req.headers.cookie).wz_session;
    if (!token) return false;
    const expires = sessions.get(token);
    if (!expires) return false;
    if (expires < Date.now()) {
      sessions.delete(token);
      return false;
    }
    return true;
  };

  const setSession = (res) => {
    const token = crypto.randomBytes(32).toString('base64url');
    sessions.set(token, Date.now() + SESSION_TTL_MS);
    res.setHeader('Set-Cookie', `wz_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_TTL_MS / 1000}${secureCookie ? '; Secure' : ''}`);
  };

  const clearSession = (req, res) => {
    const token = parseCookies(req.headers.cookie).wz_session;
    if (token) sessions.delete(token);
    res.setHeader('Set-Cookie', `wz_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${secureCookie ? '; Secure' : ''}`);
  };

  const rateLimited = (ip) => {
    const now = Date.now();
    const entry = loginAttempts.get(ip);
    if (!entry || entry.resetAt < now) return false;
    return entry.count >= LOGIN_MAX_ATTEMPTS;
  };
  const noteFailure = (ip) => {
    const now = Date.now();
    const entry = loginAttempts.get(ip);
    if (!entry || entry.resetAt < now) loginAttempts.set(ip, { count: 1, resetAt: now + LOGIN_WINDOW_MS });
    else entry.count += 1;
  };

  const indexHtml = async () => {
    const html = await fs.readFile(path.join(RENDERER_DIR, 'index.html'), 'utf8');
    return html
      .replace(/<meta http-equiv="Content-Security-Policy"[^>]*>\s*/i, '') // the HTTP header governs here
      .replace('<script src="renderer.js"></script>', '<script src="/bridge.js"></script>\n  <script src="/renderer.js"></script>')
      .replace('href="styles.css"', 'href="/styles.css"');
  };

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://localhost');
    const ip = clientIp(req);
    try {
      if (url.pathname === '/healthz') {
        securityHeaders(res);
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('ok');
        return;
      }

      if (url.pathname === '/styles.css') {
        securityHeaders(res);
        res.writeHead(200, { 'Content-Type': STATIC['/styles.css'].type });
        res.end(await fs.readFile(STATIC['/styles.css'].file));
        return;
      }

      if (url.pathname === '/auth/login' && req.method === 'POST') {
        if (rateLimited(ip)) {
          securityHeaders(res, { html: true });
          res.writeHead(429, { 'Content-Type': 'text/html; charset=utf-8' });
          res.end(LOGIN_PAGE('Too many attempts. Try again in 15 minutes.'));
          return;
        }
        const body = await readBody(req, 10_000);
        const ct = String(req.headers['content-type'] || '');
        const supplied = ct.includes('application/json')
          ? (JSON.parse(body || '{}').password || '')
          : (new URLSearchParams(body).get('password') || '');
        if (timingSafeEqualStr(supplied, password)) {
          setSession(res);
          if (ct.includes('application/json')) {
            sendJson(res, 200, { ok: true });
          } else {
            securityHeaders(res);
            res.writeHead(303, { Location: '/' });
            res.end();
          }
        } else {
          noteFailure(ip);
          await engine.appendRunLog({ event: 'auth:failed', ip });
          securityHeaders(res, { html: true });
          res.writeHead(401, { 'Content-Type': 'text/html; charset=utf-8' });
          res.end(LOGIN_PAGE('Wrong password.'));
        }
        return;
      }

      if (url.pathname === '/auth/logout' && req.method === 'POST') {
        clearSession(req, res);
        securityHeaders(res);
        res.writeHead(303, { Location: '/' });
        res.end();
        return;
      }

      if (!isAuthed(req)) {
        if (url.pathname.startsWith('/api/')) {
          sendJson(res, 401, { ok: false, error: 'Not signed in.' });
        } else {
          securityHeaders(res, { html: true });
          res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
          res.end(LOGIN_PAGE(''));
        }
        return;
      }

      // ----- signed in from here -----

      if (url.pathname === '/' || url.pathname === '/index.html') {
        securityHeaders(res, { html: true });
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(await indexHtml());
        return;
      }

      if (STATIC[url.pathname]) {
        securityHeaders(res);
        res.writeHead(200, { 'Content-Type': STATIC[url.pathname].type });
        res.end(await fs.readFile(STATIC[url.pathname].file));
        return;
      }

      if (url.pathname === '/api/events' && req.method === 'GET') {
        securityHeaders(res);
        res.writeHead(200, { 'Content-Type': 'text/event-stream', Connection: 'keep-alive', 'X-Accel-Buffering': 'no' });
        res.write('retry: 3000\n\n');
        sseClients.add(res);
        const ping = setInterval(() => res.write(': ping\n\n'), 25_000);
        req.on('close', () => {
          clearInterval(ping);
          sseClients.delete(res);
        });
        return;
      }

      if (url.pathname.startsWith('/api/') && req.method === 'POST') {
        // Same-site cookies plus a custom header: a cross-site form can't
        // reach these routes.
        if (req.headers['x-wayzgoose'] !== '1' && !(req.headers.authorization || '').startsWith('Bearer ')) {
          sendJson(res, 403, { ok: false, error: 'Missing X-Wayzgoose header.' });
          return;
        }
        const channel = decodeURIComponent(url.pathname.slice(5));
        const fn = engine.handlers[channel];
        if (!fn) {
          sendJson(res, 404, { ok: false, error: `Unknown action ${channel}` });
          return;
        }
        const body = await readBody(req);
        const payload = body ? JSON.parse(body).payload : undefined;
        try {
          const result = await fn(payload);
          sendJson(res, 200, { ok: true, result: result === undefined ? null : result });
        } catch (err) {
          sendJson(res, 400, { ok: false, error: err.message });
        }
        return;
      }

      sendJson(res, 404, { ok: false, error: 'Not found' });
    } catch (err) {
      sendJson(res, 500, { ok: false, error: err.message });
    }
  });

  // Expire sessions and rate-limit entries now and then.
  const sweep = setInterval(() => {
    const now = Date.now();
    for (const [t, exp] of sessions) if (exp < now) sessions.delete(t);
    for (const [k, v] of loginAttempts) if (v.resetAt < now) loginAttempts.delete(k);
  }, 60_000);
  sweep.unref();

  return {
    server,
    engine,
    seed,
    async listen(port = Number(env.PORT) || 8080, host = env.HOST || '0.0.0.0') {
      await fs.mkdir(dataDir, { recursive: true });
      await seed();
      await new Promise((resolve) => server.listen(port, host, resolve));
      return server.address();
    },
    close() {
      clearInterval(sweep);
      for (const res of sseClients) res.end();
      return new Promise((resolve) => server.close(resolve));
    },
  };
}

module.exports = { createServer, encryptedCredentials, loadOrCreateKey };

if (require.main === module) {
  const app = createServer(process.env);
  app.listen().then((addr) => {
    const stop = app.engine.startScheduler({ firstDelayMs: 30_000, everyMs: 5 * 60_000 });
    console.log(`Wayzgoose for Pressable listening on ${addr.address}:${addr.port}, data in ${app.engine.dataDir}`);
    const shutdown = () => {
      stop();
      app.close().then(() => process.exit(0));
    };
    process.on('SIGTERM', shutdown);
    process.on('SIGINT', shutdown);
  }).catch((err) => {
    console.error(err.message);
    process.exit(1);
  });
}
