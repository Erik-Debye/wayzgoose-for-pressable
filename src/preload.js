'use strict';

const { contextBridge, ipcRenderer } = require('electron');

// The renderer only ever sees this surface. No Node, no secrets.
contextBridge.exposeInMainWorld('pressable', {
  credentials: {
    status: () => ipcRenderer.invoke('credentials:status'),
    save: (creds) => ipcRenderer.invoke('credentials:save', creds),
    clear: () => ipcRenderer.invoke('credentials:clear'),
  },
  config: {
    get: () => ipcRenderer.invoke('config:get'),
    set: (patch) => ipcRenderer.invoke('config:set', patch),
  },
  sites: {
    list: () => ipcRenderer.invoke('sites:list'),
    cacheStatus: (siteId) => ipcRenderer.invoke('site:cacheStatus', siteId),
  },
  backups: {
    list: (siteId) => ipcRenderer.invoke('backups:list', siteId),
    status: (items) => ipcRenderer.invoke('backups:status', items),
  },
  run: {
    start: (options) => ipcRenderer.invoke('run:start', options),
    cancel: () => ipcRenderer.invoke('run:cancel'),
    onEvent: (callback) => {
      const handler = (_event, payload) => callback(payload);
      ipcRenderer.on('run:event', handler);
      return () => ipcRenderer.removeListener('run:event', handler);
    },
  },
  security: {
    scan: (options) => ipcRenderer.invoke('security:scan', options),
    cancel: () => ipcRenderer.invoke('security:cancel'),
    lastResult: () => ipcRenderer.invoke('security:lastResult'),
    notify: (options) => ipcRenderer.invoke('security:notify', options),
    testWebhook: (url) => ipcRenderer.invoke('security:testWebhook', { url }),
    onEvent: (callback) => {
      const handler = (_event, payload) => callback(payload);
      ipcRenderer.on('scan:event', handler);
      return () => ipcRenderer.removeListener('scan:event', handler);
    },
  },
  users: {
    audit: (options) => ipcRenderer.invoke('users:audit', options),
    cancel: () => ipcRenderer.invoke('users:cancel'),
    lastResult: () => ipcRenderer.invoke('users:lastResult'),
    onEvent: (callback) => {
      const handler = (_event, payload) => callback(payload);
      ipcRenderer.on('audit:event', handler);
      return () => ipcRenderer.removeListener('audit:event', handler);
    },
  },
  sentinel: {
    install: (options) => ipcRenderer.invoke('sentinel:install', options),
    status: () => ipcRenderer.invoke('sentinel:status'),
    onEvent: (callback) => {
      const handler = (_event, payload) => callback(payload);
      ipcRenderer.on('sentinel:event', handler);
      return () => ipcRenderer.removeListener('sentinel:event', handler);
    },
  },
  openExternal: (url) => ipcRenderer.invoke('shell:openExternal', url),
  openDataFolder: () => ipcRenderer.invoke('shell:openDataFolder'),
});
