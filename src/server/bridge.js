'use strict';

// Served by src/server/server.js in place of Electron's preload. Exposes the
// same window.pressable surface the renderer expects; every call becomes a
// POST to /api/<channel>, and progress events arrive over /api/events.

(() => {
  const listeners = new Map(); // channel -> Set(callback)

  async function invoke(channel, payload) {
    const res = await fetch(`/api/${encodeURIComponent(channel)}`, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-Wayzgoose': '1' },
      body: JSON.stringify({ payload }),
    });
    if (res.status === 401) {
      window.location.reload(); // session expired: back to the sign-in page
      throw new Error('Signed out.');
    }
    const body = await res.json().catch(() => ({ ok: false, error: `HTTP ${res.status}` }));
    if (!body.ok) throw new Error(body.error || `HTTP ${res.status}`);
    return body.result;
  }

  function on(channel, callback) {
    if (!listeners.has(channel)) listeners.set(channel, new Set());
    listeners.get(channel).add(callback);
    return () => listeners.get(channel).delete(callback);
  }

  function connectEvents() {
    const source = new EventSource('/api/events', { withCredentials: true });
    for (const channel of ['run:event', 'scan:event', 'audit:event', 'sentinel:event', 'uptime:event', 'config:event']) {
      source.addEventListener(channel, (ev) => {
        let payload;
        try {
          payload = JSON.parse(ev.data);
        } catch {
          return;
        }
        for (const cb of listeners.get(channel) || []) cb(payload);
      });
    }
    source.onerror = () => {
      // EventSource reconnects on its own; nothing to do.
    };
    return source;
  }
  connectEvents();

  window.pressable = {
    credentials: {
      status: () => invoke('credentials:status'),
      save: (creds) => invoke('credentials:save', creds),
      clear: () => invoke('credentials:clear'),
    },
    config: {
      get: () => invoke('config:get'),
      set: (patch) => invoke('config:set', patch),
    },
    sites: {
      list: () => invoke('sites:list'),
      cacheStatus: (siteId) => invoke('site:cacheStatus', siteId),
    },
    backups: {
      list: (siteId) => invoke('backups:list', siteId),
      status: (items) => invoke('backups:status', items),
    },
    run: {
      start: (options) => invoke('run:start', options),
      cancel: () => invoke('run:cancel'),
      onEvent: (cb) => on('run:event', cb),
    },
    security: {
      scan: (options) => invoke('security:scan', options),
      cancel: () => invoke('security:cancel'),
      lastResult: () => invoke('security:lastResult'),
      notify: (options) => invoke('security:notify', options),
      testWebhook: (url) => invoke('security:testWebhook', { url }),
      onEvent: (cb) => on('scan:event', cb),
    },
    users: {
      audit: (options) => invoke('users:audit', options),
      cancel: () => invoke('users:cancel'),
      lastResult: () => invoke('users:lastResult'),
      onEvent: (cb) => on('audit:event', cb),
    },
    sentinel: {
      install: (options) => invoke('sentinel:install', options),
      status: () => invoke('sentinel:status'),
      onEvent: (cb) => on('sentinel:event', cb),
    },
    uptime: {
      check: (options) => invoke('uptime:check', options),
      lastResult: () => invoke('uptime:lastResult'),
      onEvent: (cb) => on('uptime:event', cb),
    },
    config_check: {
      check: (options) => invoke('config:check', options),
      lastResult: () => invoke('config:lastResult'),
      onEvent: (cb) => on('config:event', cb),
    },
    openExternal: (url) => {
      if (/^https:\/\//.test(String(url))) window.open(url, '_blank', 'noopener,noreferrer');
      return Promise.resolve(true);
    },
    openDataFolder: () => Promise.resolve(false),
  };

  // Web-only touches: no local data folder to open, and a way to sign out.
  document.addEventListener('DOMContentLoaded', () => {
    const folderBtn = document.getElementById('btn-data-folder');
    if (folderBtn) folderBtn.hidden = true;
    const topbar = document.querySelector('.topbar');
    if (topbar) {
      const form = document.createElement('form');
      form.method = 'post';
      form.action = '/auth/logout';
      form.style.margin = '0';
      const btn = document.createElement('button');
      btn.type = 'submit';
      btn.className = 'btn btn-quiet';
      btn.textContent = 'Log out';
      form.append(btn);
      topbar.append(form);
    }
  });
})();
