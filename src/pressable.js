'use strict';

// Thin client for the Pressable control-panel API.
// Docs: https://my.pressable.com/documentation/api/v1
//
// Runs in the Electron main process only. The renderer never sees the
// client secret or the access token.

const BASE = 'https://my.pressable.com';

class PressableError extends Error {
  constructor(message, { status, code, errors } = {}) {
    super(message);
    this.name = 'PressableError';
    this.status = status;
    this.code = code;
    this.errors = errors || [];
  }
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function safeJson(res) {
  const text = await res.text();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return { message: text.slice(0, 300) };
  }
}

class PressableClient {
  constructor({ clientId, clientSecret, fetchImpl = globalThis.fetch }) {
    if (!clientId || !clientSecret) throw new Error('Client ID and client secret are required');
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.fetch = fetchImpl;
    this.token = null; // { accessToken, expiresAt }
    this.identity = null; // { name, email, scopes }
    this.tokenPromise = null;
  }

  // Access tokens live for one hour. Refresh a minute early, and make sure
  // concurrent callers share one token request.
  async getToken(force = false) {
    if (!force && this.token && this.token.expiresAt > Date.now() + 60_000) {
      return this.token.accessToken;
    }
    if (!this.tokenPromise) {
      this.tokenPromise = this.fetchToken().finally(() => {
        this.tokenPromise = null;
      });
    }
    return this.tokenPromise;
  }

  async fetchToken() {
    const body = new URLSearchParams({
      grant_type: 'client_credentials',
      client_id: this.clientId,
      client_secret: this.clientSecret,
    });
    const res = await this.fetch(`${BASE}/auth/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
      },
      body,
    });
    const data = await safeJson(res);
    if (!res.ok || !data || !data.access_token) {
      const detail = (data && (data.error_description || data.error || data.message)) || '';
      throw new PressableError(
        detail ? `Sign-in failed: ${detail}` : `Sign-in failed (HTTP ${res.status})`,
        { status: res.status },
      );
    }
    const ttl = Number(data.expires_in) || 3600;
    this.token = { accessToken: data.access_token, expiresAt: Date.now() + ttl * 1000 };
    this.identity = { name: data.name, email: data.email, scopes: data.scopes || [] };
    return this.token.accessToken;
  }

  async request(method, path, { body, query, retries = 3, retriedAuth = false } = {}) {
    const url = new URL(`${BASE}/v1${path}`);
    if (query) {
      for (const [key, value] of Object.entries(query)) {
        if (value !== undefined && value !== null) url.searchParams.set(key, String(value));
      }
    }
    const token = await this.getToken();
    const headers = { Authorization: `Bearer ${token}`, Accept: 'application/json' };
    let payload;
    if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
      payload = JSON.stringify(body);
    }

    const res = await this.fetch(url, { method, headers, body: payload });

    if (res.status === 401 && !retriedAuth) {
      await this.getToken(true);
      return this.request(method, path, { body, query, retries, retriedAuth: true });
    }
    if (res.status === 429 && retries > 0) {
      const retryAfter = Number(res.headers.get('retry-after'));
      const waitMs = Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter * 1000 : 5000;
      await sleep(waitMs);
      return this.request(method, path, { body, query, retries: retries - 1, retriedAuth });
    }

    const data = await safeJson(res);
    if (!res.ok) {
      const errors = data && Array.isArray(data.errors) ? data.errors.filter(Boolean) : [];
      const message = errors[0] || (data && data.message) || `${method} ${path} failed (HTTP ${res.status})`;
      throw new PressableError(message, { status: res.status, code: data && data.code, errors });
    }
    return data;
  }

  // ----- Account -----

  async getAccount() {
    const res = await this.request('GET', '/account');
    return res && res.data;
  }

  // ----- Sites -----

  // Walks every page of GET /sites. If the API returns everything in one
  // response (no "page" block), this stops after the first call.
  async listAllSites() {
    const sites = [];
    let page = 1;
    for (;;) {
      const res = await this.request('GET', '/sites', { query: { per_page: 50, page } });
      const batch = res && Array.isArray(res.data) ? res.data : [];
      sites.push(...batch);
      const next = res && res.page ? res.page.nextPage : null;
      if (!next || batch.length === 0 || next === page) break;
      page = next;
    }
    return sites;
  }

  // ----- On-demand backups -----
  // Each site can hold at most 3 filesystem and 3 database on-demand backups.

  async listOndemandBackups(siteId) {
    const res = await this.request('GET', `/sites/${siteId}/ondemand-backups`);
    const data = res && res.data;
    if (Array.isArray(data)) return data;
    if (data && Array.isArray(data.backups)) return data.backups;
    return [];
  }

  async getOndemandBackup(siteId, backupId) {
    const res = await this.request('GET', `/sites/${siteId}/ondemand-backups/${backupId}`);
    return res && res.data;
  }

  // backupType is 'fs' (filesystem) or 'db' (database).
  async createOndemandBackup(siteId, backupType) {
    const res = await this.request('POST', `/sites/${siteId}/ondemand-backups`, {
      body: { backup_type: backupType },
    });
    return res && res.data;
  }

  async deleteOndemandBackup(siteId, backupId) {
    const res = await this.request('DELETE', `/sites/${siteId}/ondemand-backups/${backupId}`);
    return res && res.data;
  }

  // ----- Security alerts (WPScan-backed) -----
  // kind is 'plugins' or 'themes'. Shape is not fully documented, so callers
  // normalize defensively (see security.js).

  async listSecurityAlerts(siteId, kind) {
    const res = await this.request('GET', `/sites/${siteId}/security-alerts/${kind}`);
    return res && res.data;
  }

  // ----- Edge cache -----
  // GET returns { active, defensive_mode: { active, active_until } }.

  async getEdgeCache(siteId) {
    const res = await this.request('GET', `/sites/${siteId}/edge-cache`);
    return res && res.data;
  }

  // Sending `enabled` makes the call idempotent; omitting it would toggle.
  async setEdgeCache(siteId, enabled) {
    const res = await this.request('PUT', `/sites/${siteId}/edge-cache`, { body: { enabled: Boolean(enabled) } });
    return res && res.data;
  }

  async purgeEdgeCache(siteId) {
    const res = await this.request('DELETE', `/sites/${siteId}/edge-cache`);
    return res && res.data;
  }

  // ----- Object cache (Memcached) -----
  // Endpoint path taken from community clients; the official docs list the
  // action under Sites → "Flush Object Cache" without showing the path.

  async flushObjectCache(siteId) {
    const res = await this.request('POST', `/sites/${siteId}/flush-object-cache`);
    return res && res.data;
  }

  // ----- Cache preload (beta) -----
  // GET/PUT return { enabled, state, urls_found, urls_preloaded, searching, warnings }.
  // Turning it on requires a live site with edge cache on (422 otherwise).

  async getCachePreload(siteId) {
    const res = await this.request('GET', `/sites/${siteId}/cache-preload`);
    return res && res.data;
  }

  async setCachePreload(siteId, enabled) {
    const res = await this.request('PUT', `/sites/${siteId}/cache-preload`, { body: { enabled: Boolean(enabled) } });
    return res && res.data;
  }
}

function normalizePreload(raw) {
  if (!raw || typeof raw !== 'object') return null;
  return {
    enabled: Boolean(raw.enabled),
    state: raw.state ?? null,
    urlsFound: raw.urls_found ?? raw.urlsFound ?? null,
    urlsPreloaded: raw.urls_preloaded ?? raw.urlsPreloaded ?? null,
    searching: raw.searching ?? null,
    warnings: Array.isArray(raw.warnings) ? raw.warnings.map((w) => (w && w.message) || String(w)) : [],
  };
}

function normalizeEdgeCache(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const defensive = raw.defensive_mode || raw.defensiveMode || {};
  return {
    active: Boolean(raw.active),
    defensiveActive: Boolean(defensive.active),
    defensiveUntil: defensive.active_until ?? defensive.activeUntil ?? null, // unix seconds
  };
}

// The exact field names on a backup object vary a little between endpoints,
// so read them defensively.
function normalizeBackup(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const typeRaw = String(raw.backupType ?? raw.backup_type ?? raw.type ?? '').toLowerCase();
  let type = 'unknown';
  if (/^(fs|file)/.test(typeRaw)) type = 'fs';
  else if (/^(db|data)/.test(typeRaw)) type = 'db';
  else if (typeRaw) type = typeRaw;

  const state = raw.state ?? raw.status ?? null;
  const created = raw.created ?? raw.createdAt ?? raw.created_at ?? raw.timestamp ?? null;
  return {
    id: raw.id ?? null,
    type,
    state: state === null || state === undefined ? null : String(state),
    created,
    size: raw.size ?? raw.sizeInBytes ?? raw.size_in_bytes ?? null,
    raw,
  };
}

function isFinalState(state) {
  if (!state) return false;
  const s = state.toLowerCase();
  return /(complete|success|ready|available|finish|done|fail|error|cancel)/.test(s);
}

function isFailedState(state) {
  if (!state) return false;
  return /(fail|error|cancel)/.test(state.toLowerCase());
}

module.exports = {
  PressableClient,
  PressableError,
  normalizeBackup,
  normalizePreload,
  normalizeEdgeCache,
  isFinalState,
  isFailedState,
  sleep,
};
