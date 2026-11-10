'use strict';

// Electron host: a window, the OS keychain for the Pressable secret, IPC
// wiring to the shared engine, and auto-update. Everything else lives in
// src/core/engine.js so the self-hosted server can run the same code.

const { app, BrowserWindow, ipcMain, safeStorage, shell } = require('electron');
const path = require('node:path');
const fs = require('node:fs/promises');
const { createEngine } = require('./core/engine');

let mainWindow = null;
let engine = null;

// Credentials are encrypted with the OS keystore (Keychain on macOS, DPAPI on
// Windows) via Electron's safeStorage. Only the main process can read them.
function keychainCredentials(dataDir) {
  const file = path.join(dataDir, 'credentials.bin');
  return {
    encrypted: () => safeStorage.isEncryptionAvailable(),
    async load() {
      try {
        const buf = await fs.readFile(file);
        const text = safeStorage.isEncryptionAvailable() ? safeStorage.decryptString(buf) : buf.toString('utf8');
        return JSON.parse(text);
      } catch (err) {
        if (err.code === 'ENOENT') return null;
        throw err;
      }
    },
    async save({ clientId, clientSecret }) {
      const text = JSON.stringify({ clientId, clientSecret });
      const buf = safeStorage.isEncryptionAvailable() ? safeStorage.encryptString(text) : Buffer.from(text, 'utf8');
      await fs.mkdir(dataDir, { recursive: true });
      await fs.writeFile(file, buf, { mode: 0o600 });
    },
    async clear() {
      try {
        await fs.unlink(file);
      } catch (err) {
        if (err.code !== 'ENOENT') throw err;
      }
    },
  };
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1180,
    height: 760,
    minWidth: 920,
    minHeight: 600,
    title: 'Wayzgoose for Pressable',
    backgroundColor: '#f4f6f8',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });
  mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));

  // Open any external link in the system browser, never inside the app.
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https:\/\//.test(url)) shell.openExternal(url);
    return { action: 'deny' };
  });
  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

function registerIpc() {
  for (const [channel, fn] of Object.entries(engine.handlers)) {
    ipcMain.handle(channel, (_event, payload) => fn(payload));
  }
  ipcMain.handle('shell:openExternal', (_event, url) => {
    if (typeof url === 'string' && /^https:\/\//.test(url)) return shell.openExternal(url);
    return false;
  });
  ipcMain.handle('shell:openDataFolder', () => shell.openPath(engine.dataDir));
}

// ---------- Auto-update ----------
//
// Installed builds check the GitHub Releases of the repository named in
// package.json, download a newer version in the background, and apply it on
// the next launch (electron-updater notifies the person when a download is
// ready). Needs a public repository, and on macOS a signed build; otherwise
// it fails quietly and logs the reason.

function setupAutoUpdate() {
  if (!app.isPackaged) return;
  try {
    const { autoUpdater } = require('electron-updater');
    autoUpdater.logger = null;
    autoUpdater.on('error', (err) => engine.appendRunLog({ event: 'update:error', error: err.message }));
    autoUpdater.on('update-downloaded', (info) => engine.appendRunLog({ event: 'update:downloaded', version: info.version }));
    autoUpdater.checkForUpdatesAndNotify().catch(() => {});
    setInterval(() => autoUpdater.checkForUpdatesAndNotify().catch(() => {}), 6 * 3600 * 1000).unref();
  } catch (err) {
    engine.appendRunLog({ event: 'update:unavailable', error: err.message });
  }
}

// ---------- App lifecycle ----------

app.whenReady().then(() => {
  const dataDir = app.getPath('userData');
  engine = createEngine({
    dataDir,
    credentials: keychainCredentials(dataDir),
    emit: (channel, payload) => {
      if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send(channel, payload);
    },
  });
  registerIpc();
  createWindow();
  setupAutoUpdate();
  engine.startScheduler(); // timers are unref'd; the window keeps the app alive
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
