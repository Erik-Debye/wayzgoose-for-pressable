'use strict';

// Shared test helpers: a tiny fake fetch response and a fake Electron module
// so main.js can be exercised without a display or an installed Electron.

const Module = require('node:module');

function jsonResponse(status, body, headers = {}) {
  const lower = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]));
  return {
    ok: status < 400,
    status,
    headers: { get: (k) => lower[k.toLowerCase()] ?? null },
    text: async () => (typeof body === 'string' ? body : JSON.stringify(body)),
    json: async () => body,
  };
}

function makeFakeElectron(userDataDir) {
  const handlers = new Map();
  const sent = [];
  let resolveReady;
  const ready = new Promise((r) => { resolveReady = r; });
  const electron = {
    app: {
      getPath: () => userDataDir,
      whenReady: () => ready,
      on: () => {},
      quit: () => {},
      isPackaged: false,
      _ready: () => resolveReady(),
    },
    BrowserWindow: class {
      constructor() {
        this.webContents = { send: (channel, payload) => sent.push([channel, payload]), setWindowOpenHandler() {} };
      }
      loadFile() {}
      on() {}
      isDestroyed() { return false; }
      static getAllWindows() { return [1]; }
    },
    ipcMain: { handle: (name, fn) => handlers.set(name, fn) },
    safeStorage: { isEncryptionAvailable: () => false },
    shell: { openExternal: async () => {}, openPath: async () => '' },
    _handlers: handlers,
    _sent: sent,
  };
  return electron;
}

// Route require('electron') to the fake for the duration of a test file.
function installFakeElectron(fake) {
  const original = Module._load;
  Module._load = function patched(request, parent, isMain) {
    if (request === 'electron') return fake;
    return original.call(this, request, parent, isMain);
  };
  return () => { Module._load = original; };
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

module.exports = { jsonResponse, makeFakeElectron, installFakeElectron, sleep };
