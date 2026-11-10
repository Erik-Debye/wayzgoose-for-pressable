'use strict';

// PHP error log triage. Pressable keeps 7 days of PHP logs per site and lets
// the API filter by severity. Fatal errors are the ones that take pages
// down, so those are grouped by signature (same error, same file) and
// reported once per signature, with a cooldown while they keep recurring.

const crypto = require('node:crypto');

const FATAL_RE = /\b(fatal error|parse error|uncaught)\b/i;
const COOLDOWN_MS = 6 * 3600_000;

function parseTime(raw) {
  if (raw === null || raw === undefined) return null;
  if (typeof raw === 'number') return new Date(raw < 1e12 ? raw * 1000 : raw);
  const d = new Date(raw);
  if (!Number.isNaN(d.getTime())) return d;
  // "[10-Nov-2026 12:00:00 UTC]" as PHP writes it
  const m = String(raw).match(/(\d{2})-([A-Za-z]{3})-(\d{4}) (\d{2}):(\d{2}):(\d{2})/);
  if (m) {
    const d2 = new Date(`${m[1]} ${m[2]} ${m[3]} ${m[4]}:${m[5]}:${m[6]} UTC`);
    if (!Number.isNaN(d2.getTime())) return d2;
  }
  return null;
}

// Accepts structured entries ({timestamp, severity, message, file, line}) or
// raw log lines, and returns one shape.
function normalizePhpEntry(raw) {
  if (!raw) return null;
  let text;
  let time = null;
  let severity = null;
  let file = null;
  let line = null;
  if (typeof raw === 'string') {
    text = raw;
  } else if (typeof raw === 'object') {
    text = String(raw.message ?? raw.log ?? raw.line ?? raw.text ?? raw.entry ?? '');
    time = parseTime(raw.timestamp ?? raw['@timestamp'] ?? raw.time ?? raw.date ?? raw.created ?? null);
    severity = raw.severity ?? raw.level ?? raw.type ?? null;
    file = raw.file ?? raw.path ?? null;
    line = raw.line_number ?? raw.lineno ?? null;
  } else {
    return null;
  }
  text = text.trim();
  if (!time) {
    const t = text.match(/^\[([^\]]+)\]\s*/);
    if (t) {
      time = parseTime(t[1]);
      text = text.slice(t[0].length);
    }
  }
  if (!severity) {
    const sv = text.match(/^PHP (Fatal error|Parse error|Warning|Notice|Deprecated|User [A-Za-z]+)/i);
    severity = sv ? sv[1] : null;
  }
  text = text.replace(/^PHP (Fatal error|Parse error|Warning|Notice|Deprecated|User [A-Za-z]+):\s*/i, '');
  if (!file) {
    const m = text.match(/ in (\/[^\s:]+?\.php)(?::(\d+)| on line (\d+))/);
    if (m) {
      file = m[1];
      line = Number(m[2] || m[3]) || null;
    }
  }
  return { time, severity: severity ? String(severity) : null, message: text.slice(0, 500), file, line: line !== null ? Number(line) : null };
}

function isFatal(entry) {
  if (!entry) return false;
  return FATAL_RE.test(entry.severity || '') || /^(Uncaught|Allowed memory size|Maximum execution time)/i.test(entry.message);
}

// wp-content/plugins/<slug>/… → "plugin <slug>"; themes likewise; else core/mu-plugin/unknown
function componentOf(file) {
  if (!file) return null;
  const p = file.match(/wp-content\/plugins\/([^/]+)/);
  if (p) return `plugin ${p[1]}`;
  const t = file.match(/wp-content\/themes\/([^/]+)/);
  if (t) return `theme ${t[1]}`;
  const mu = file.match(/wp-content\/mu-plugins\/([^/]+)/);
  if (mu) return `mu-plugin ${mu[1].replace(/\.php$/, '')}`;
  if (/\/wp-(admin|includes)\//.test(file)) return 'WordPress core';
  return null;
}

// Same error with different numbers (memory sizes, ids, line numbers) is the
// same signature.
function signatureOf(entry) {
  const base = `${entry.file || ''}|${entry.message}`
    .replace(/\d+/g, '#')
    .replace(/\s+/g, ' ')
    .slice(0, 300);
  return crypto.createHash('sha1').update(base).digest('hex').slice(0, 12);
}

// state: { lastCheckedAt, signatures: { [sig]: { firstSeen, lastSeen, count, alertedAt, sample, file, line, component } } }
function triage(prevState, rawEntries, { now = new Date().toISOString(), cooldownMs = COOLDOWN_MS } = {}) {
  const state = {
    lastCheckedAt: now,
    signatures: { ...((prevState && prevState.signatures) || {}) },
  };
  const since = prevState && prevState.lastCheckedAt ? new Date(prevState.lastCheckedAt).getTime() : 0;
  const nowMs = new Date(now).getTime();
  const events = [];
  const touched = new Set();

  for (const raw of rawEntries) {
    const e = normalizePhpEntry(raw);
    if (!e || !isFatal(e)) continue;
    const t = e.time ? e.time.getTime() : nowMs;
    if (t < since) continue; // already seen in an earlier check
    const sig = signatureOf(e);
    const iso = new Date(t).toISOString();
    const rec = state.signatures[sig] || { firstSeen: iso, lastSeen: iso, count: 0, alertedAt: null, sample: e.message, file: e.file, line: e.line, component: componentOf(e.file) };
    rec.count += 1;
    if (t < new Date(rec.firstSeen).getTime()) rec.firstSeen = iso;
    if (t > new Date(rec.lastSeen).getTime()) rec.lastSeen = iso;
    state.signatures[sig] = rec;
    touched.add(sig);
  }

  for (const sig of touched) {
    const rec = state.signatures[sig];
    const lastAlert = rec.alertedAt ? new Date(rec.alertedAt).getTime() : 0;
    if (nowMs - lastAlert >= cooldownMs) {
      rec.alertedAt = now;
      events.push({ kind: 'php-fatal', signature: sig, sample: rec.sample, file: rec.file, line: rec.line, component: rec.component, count: rec.count, firstSeen: rec.firstSeen, lastSeen: rec.lastSeen });
    }
  }

  // Forget signatures not seen for 7 days (Pressable's own retention).
  for (const [sig, rec] of Object.entries(state.signatures)) {
    if (nowMs - new Date(rec.lastSeen).getTime() > 7 * 86_400_000) delete state.signatures[sig];
  }
  return { state, events };
}

// Summary for the panel: fatals in the last 24 h and the most recent one.
function summarize(state, now = Date.now()) {
  const sigs = Object.values((state && state.signatures) || {});
  const recent = sigs.filter((r) => now - new Date(r.lastSeen).getTime() <= 86_400_000);
  const count = recent.reduce((n, r) => n + r.count, 0);
  const latest = recent.sort((a, b) => new Date(b.lastSeen) - new Date(a.lastSeen))[0] || null;
  return { count24h: count, distinct24h: recent.length, latest };
}

module.exports = { normalizePhpEntry, isFatal, componentOf, signatureOf, triage, summarize, COOLDOWN_MS };
