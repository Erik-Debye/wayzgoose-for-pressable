'use strict';

// Uptime: fetch each site's homepage, decide up or down, remember the state
// between checks so a site is reported once when it goes down and once when
// it comes back, and only after it has failed a configurable number of
// checks in a row (one slow response shouldn't page anyone).

const tls = require('node:tls');

const DEFAULT_TIMEOUT_MS = 15_000;
const TLS_THRESHOLDS_DAYS = [14, 7, 3, 1];
const TLS_RECHECK_MS = 60 * 60_000;
const USER_AGENT = 'Wayzgoose-for-Pressable uptime check (+https://github.com/Erik-Debye/wayzgoose-for-pressable)';

function siteUrl(site) {
  const raw = String(site.url || site.name || '').trim();
  if (!raw) return null;
  return /^https?:\/\//i.test(raw) ? raw : `https://${raw}/`;
}

// One probe. Never throws; the outcome is in the returned object.
async function probe(url, { fetchImpl = globalThis.fetch, timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  const started = Date.now();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetchImpl(url, {
      method: 'GET',
      redirect: 'follow',
      headers: { 'User-Agent': USER_AGENT, Accept: 'text/html,*/*' },
      signal: controller.signal,
    });
    const latencyMs = Date.now() - started;
    if (res.body && typeof res.body.cancel === 'function') res.body.cancel().catch(() => {});
    return { url, ok: true, status: res.status, latencyMs, finalUrl: res.url || url, error: null };
  } catch (err) {
    const latencyMs = Date.now() - started;
    const timedOut = err && (err.name === 'AbortError' || /aborted/i.test(err.message || ''));
    return {
      url,
      ok: false,
      status: null,
      latencyMs,
      finalUrl: url,
      error: timedOut ? `no response within ${Math.round(timeoutMs / 1000)} s` : describeError(err),
    };
  } finally {
    clearTimeout(timer);
  }
}

function describeError(err) {
  const cause = err && err.cause ? err.cause : err;
  const code = cause && cause.code ? String(cause.code) : '';
  const map = {
    ENOTFOUND: 'DNS lookup failed',
    EAI_AGAIN: 'DNS lookup failed',
    ECONNREFUSED: 'connection refused',
    ECONNRESET: 'connection reset',
    ETIMEDOUT: 'connection timed out',
    CERT_HAS_EXPIRED: 'TLS certificate expired',
    ERR_TLS_CERT_ALTNAME_INVALID: 'TLS certificate does not match the domain',
    DEPTH_ZERO_SELF_SIGNED_CERT: 'self-signed TLS certificate',
    UNABLE_TO_VERIFY_LEAF_SIGNATURE: 'TLS certificate could not be verified',
  };
  if (code && map[code]) return map[code];
  const msg = (cause && cause.message) || (err && err.message) || 'request failed';
  return code ? `${msg} (${code})` : msg;
}

// Up means the server answered with anything below 500. A 401/403/404 on
// the homepage still proves the site is serving; 5xx (including Pressable's
// maintenance-mode 503), timeouts and connection errors do not.
function isUp(result) {
  return result.ok && typeof result.status === 'number' && result.status < 500;
}

function describeResult(result) {
  if (!result.ok) return result.error || 'request failed';
  return `HTTP ${result.status} in ${result.latencyMs} ms`;
}

// Fold a probe into the site's stored state. Returns the next state and any
// event ('down' | 'up') the caller should report.
//
// state: { status: 'up'|'down'|'unknown', since, lastChecked, lastResult,
//          failures, alertedDown }
function nextState(prev, result, { failuresToAlert = 2, now = new Date().toISOString() } = {}) {
  const state = prev ? { ...prev } : { status: 'unknown', since: now, failures: 0, alertedDown: false };
  const up = isUp(result);
  state.lastChecked = now;
  state.lastResult = { status: result.status, latencyMs: result.latencyMs, error: result.error, finalUrl: result.finalUrl };
  let event = null;

  if (up) {
    if (state.status === 'down') {
      event = { kind: 'up', downSince: state.since, downFor: durationText(state.since, now), alerted: Boolean(state.alertedDown) };
    }
    if (state.status !== 'up') state.since = now;
    state.status = 'up';
    state.failures = 0;
    state.alertedDown = false;
  } else {
    state.failures = (state.failures || 0) + 1;
    if (state.status !== 'down') {
      if (state.failures >= failuresToAlert) {
        state.status = 'down';
        state.since = state.firstFailureAt || now;
      }
    }
    if (state.failures === 1) state.firstFailureAt = now;
    if (state.status === 'down' && !state.alertedDown) {
      event = { kind: 'down', since: state.since, failures: state.failures };
      state.alertedDown = true;
    }
  }
  if (up) delete state.firstFailureAt;
  return { state, event };
}

function durationText(fromIso, toIso) {
  const ms = Math.max(0, new Date(toIso) - new Date(fromIso));
  const m = Math.round(ms / 60_000);
  if (m < 1) return 'under a minute';
  if (m < 60) return `${m} min`;
  const h = Math.floor(m / 60);
  const rem = m % 60;
  if (h < 24) return rem ? `${h} h ${rem} min` : `${h} h`;
  const d = Math.floor(h / 24);
  return `${d} d ${h % 24} h`;
}

// ----- TLS certificate -----

// A separate handshake, because fetch() doesn't expose the peer certificate.
// rejectUnauthorized is off so an expired or mismatched certificate can still
// be read; its validity is reported in `authorized` / `authorizationError`.
function checkTls(host, { port = 443, timeoutMs = 10_000, connect = tls.connect } = {}) {
  return new Promise((resolve) => {
    let settled = false;
    const done = (value) => {
      if (settled) return;
      settled = true;
      resolve(value);
    };
    let socket;
    try {
      socket = connect({ host, port, servername: host, rejectUnauthorized: false, timeout: timeoutMs });
    } catch (err) {
      done({ ok: false, error: err.message });
      return;
    }
    socket.once('secureConnect', () => {
      const cert = socket.getPeerCertificate();
      const info = certInfo(cert, socket.authorized, socket.authorizationError);
      socket.end();
      done(info);
    });
    socket.once('timeout', () => {
      socket.destroy();
      done({ ok: false, error: `TLS handshake timed out after ${Math.round(timeoutMs / 1000)} s` });
    });
    socket.once('error', (err) => done({ ok: false, error: describeError(err) }));
  });
}

function certInfo(cert, authorized, authorizationError, now = Date.now()) {
  if (!cert || !cert.valid_to) return { ok: false, error: 'no certificate presented' };
  const validTo = new Date(cert.valid_to);
  const validFrom = cert.valid_from ? new Date(cert.valid_from) : null;
  const issuer = cert.issuer ? (cert.issuer.O || cert.issuer.CN || null) : null;
  return {
    ok: true,
    validFrom: validFrom && !Number.isNaN(validFrom.getTime()) ? validFrom.toISOString() : null,
    validTo: Number.isNaN(validTo.getTime()) ? null : validTo.toISOString(),
    daysLeft: Number.isNaN(validTo.getTime()) ? null : Math.floor((validTo.getTime() - now) / 86_400_000),
    issuer,
    subject: cert.subject ? cert.subject.CN || null : null,
    authorized: Boolean(authorized),
    authorizationError: authorizationError ? String(authorizationError.code || authorizationError) : null,
    checkedAt: new Date(now).toISOString(),
  };
}

// Fold a certificate reading into the stored tls state and decide whether to
// say something: once per threshold (14, 7, 3, 1 days), once when expired,
// once when a renewal pushes the expiry out again.
function nextTlsState(prev, info, { thresholds = TLS_THRESHOLDS_DAYS } = {}) {
  if (!info || !info.ok) {
    return { tls: { ...(prev || {}), lastError: info ? info.error : 'unknown', checkedAt: info && info.checkedAt ? info.checkedAt : new Date().toISOString() }, event: null };
  }
  const tls = {
    validTo: info.validTo,
    validFrom: info.validFrom,
    daysLeft: info.daysLeft,
    issuer: info.issuer,
    subject: info.subject,
    authorized: info.authorized,
    authorizationError: info.authorizationError,
    checkedAt: info.checkedAt,
    alerted: Array.isArray(prev && prev.alerted) ? [...prev.alerted] : [],
    expiredAlerted: Boolean(prev && prev.expiredAlerted),
    lastError: null,
  };
  let event = null;

  const renewed = prev && prev.validTo && info.validTo && new Date(info.validTo) > new Date(prev.validTo);
  if (renewed) {
    const hadWarned = (prev.alerted && prev.alerted.length) || prev.expiredAlerted;
    tls.alerted = [];
    tls.expiredAlerted = false;
    if (hadWarned) event = { kind: 'tls-renewed', validTo: info.validTo, issuer: info.issuer, daysLeft: info.daysLeft };
  }
  if (!event && info.daysLeft !== null) {
    if (info.daysLeft < 0) {
      if (!tls.expiredAlerted) {
        tls.expiredAlerted = true;
        event = { kind: 'tls-expired', validTo: info.validTo, issuer: info.issuer, daysLeft: info.daysLeft };
      }
    } else {
      const due = thresholds.filter((t) => info.daysLeft <= t && !tls.alerted.includes(t));
      if (due.length) {
        tls.alerted.push(...due);
        event = { kind: 'tls-expiring', validTo: info.validTo, issuer: info.issuer, daysLeft: info.daysLeft, threshold: Math.min(...due) };
      }
    }
  }
  return { tls, event };
}

// ----- Webhook messages -----

const COLORS = { down: 0xb0392f, up: 0x2e7d4f, 'tls-expiring': 0xd9772c, 'tls-expired': 0xb0392f, 'tls-renewed': 0x2e7d4f, 'php-fatal': 0xd9772c };

const dateOnly = (iso) => (iso ? new Date(iso).toISOString().slice(0, 10) : '?');

function eventTitle(ev) {
  switch (ev.kind) {
    case 'down': return `🔴 ${ev.siteName} is down`;
    case 'up': return `🟢 ${ev.siteName} is back up`;
    case 'tls-expiring': return `🟠 TLS certificate for ${ev.siteName} expires in ${ev.daysLeft} ${ev.daysLeft === 1 ? 'day' : 'days'}`;
    case 'tls-expired': return `🔴 TLS certificate for ${ev.siteName} has expired`;
    case 'tls-renewed': return `🟢 TLS certificate for ${ev.siteName} was renewed`;
    case 'php-fatal': return `🟠 ${ev.siteName} is logging PHP fatal errors`;
    default: return `${ev.siteName}: ${ev.kind}`;
  }
}

function eventLines(ev, markdown) {
  const b = markdown === 'discord' ? (t) => `**${t}**` : (t) => `*${t}*`;
  const lines = [];
  lines.push(`${b('URL')}: ${ev.url}`);
  switch (ev.kind) {
    case 'down':
      lines.push(`${b('Problem')}: ${ev.detail}`);
      lines.push(`${b('Since')}: ${new Date(ev.since).toUTCString()} (${ev.failures} ${ev.failures === 1 ? 'failed check' : 'failed checks in a row'})`);
      break;
    case 'up':
      lines.push(`${b('Now')}: ${ev.detail}`);
      lines.push(`${b('Was down for')}: ${ev.downFor} (since ${new Date(ev.downSince).toUTCString()})`);
      break;
    case 'tls-expiring':
    case 'tls-expired':
    case 'tls-renewed':
      lines.push(`${b('Valid until')}: ${dateOnly(ev.validTo)}${ev.issuer ? ` · issued by ${ev.issuer}` : ''}`);
      if (ev.kind === 'tls-expiring') lines.push('Pressable renews certificates automatically; a renewal this late usually means the domain’s DNS or CAA record is blocking it. Check the domain in MyPressable.');
      if (ev.kind === 'tls-expired') lines.push('Browsers are now showing a security warning for this site.');
      break;
    case 'php-fatal':
      lines.push(`${b('Error')}: ${ev.sample}`);
      if (ev.file) lines.push(`${b('In')}: ${ev.file}${ev.line ? `:${ev.line}` : ''}${ev.component ? ` (${ev.component})` : ''}`);
      lines.push(`${b('Seen')}: ${ev.count} ${ev.count === 1 ? 'time' : 'times'} since ${new Date(ev.firstSeen).toUTCString()}${ev.lastSeen && ev.lastSeen !== ev.firstSeen ? `, last ${new Date(ev.lastSeen).toUTCString()}` : ''}`);
      lines.push('One alert per distinct error every 6 hours while it keeps happening.');
      break;
    default:
      break;
  }
  return lines;
}

function buildUptimePayloads(webhookKind, events, { accountLabel = null } = {}) {
  if (events.length === 0) return [];
  const sub = `${accountLabel ? `${accountLabel} · ` : ''}${new Date().toLocaleString()}`;
  if (webhookKind === 'discord') {
    return events.map((ev) => ({ embeds: [{
      title: eventTitle(ev).slice(0, 256),
      description: eventLines(ev, 'discord').join('\n').slice(0, 4000),
      color: COLORS[ev.kind] || 0x8a94a0,
      footer: { text: `Wayzgoose for Pressable · uptime${accountLabel ? ` · ${accountLabel}` : ''}` },
      timestamp: new Date().toISOString(),
    }] }));
  }
  if (webhookKind === 'slack') {
    return events.map((ev) => ({
      text: `${eventTitle(ev)} · ${ev.detail}`,
      blocks: [
        { type: 'header', text: { type: 'plain_text', text: eventTitle(ev).slice(0, 150) } },
        { type: 'section', text: { type: 'mrkdwn', text: eventLines(ev, 'slack').join('\n').slice(0, 2900) } },
        { type: 'context', elements: [{ type: 'mrkdwn', text: `Wayzgoose for Pressable · uptime · ${sub}` }] },
      ],
    }));
  }
  return events.map((ev) => ({ text: eventTitle(ev), generatedAt: new Date().toISOString(), event: ev }));
}

module.exports = {
  DEFAULT_TIMEOUT_MS,
  TLS_THRESHOLDS_DAYS,
  TLS_RECHECK_MS,
  checkTls,
  certInfo,
  nextTlsState,
  siteUrl,
  probe,
  isUp,
  describeResult,
  nextState,
  durationText,
  buildUptimePayloads,
};
