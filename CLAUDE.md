# Wayzgoose for Pressable

Electron desktop app (macOS, Windows) for routine work on Pressable-hosted WordPress sites via the Pressable REST API: on-demand backups, edge/object cache clearing, cache-preload toggling, and vulnerability checks with Slack/Discord alerts. Tasks run on a saved list of sites or on one site.

## Commands

```bash
npm install        # downloads Electron (~100 MB); needed for npm start and dist
npm test           # unit + integration tests, no Electron binary needed
npm start          # run from source
npm run dist:mac   # local installer builds (CI normally does this)
```

Releases: push a tag `v<version>` (`git tag v0.2.0 && git push origin v0.2.0`). `.github/workflows/release.yml` stamps package.json with the tag's version, builds the installers on GitHub's Mac and Windows runners and attaches them to a release for that tag. Signing env vars are only exported when the matching secrets exist (an empty `CSC_LINK` breaks electron-builder). Installed copies auto-update from Releases via electron-updater.

## Layout

```
src/main.js             Electron main process: window, config + encrypted credentials, IPC, the task run
                        engine (backup / cache / preload), the vulnerability scan engine, daily scheduling,
                        webhook notify, auto-update
src/pressable.js        API client: OAuth client-credentials token (1 h, refreshed early), 401 retry,
                        429 Retry-After, site pagination, all endpoint wrappers, normalizeBackup()
src/security.js         Pure functions: extractVulnerabilities() (walks Pressable's alert JSON),
                        groupFindings(), CVE enrichment (cve.org, NVD fallback), CVSS → plain English,
                        new-finding tracking, Slack/Discord/generic webhook payloads, sendWebhook()
src/preload.js          contextBridge surface (`window.pressable.*`); the only thing the renderer can call
src/renderer/           Vanilla HTML/CSS/JS. renderer.js: site list, task switcher, run/scan lifecycle,
                        findings panel, backup-completion polling, settings dialog
test/                   node:test suites. helpers.js fakes Electron so main.js runs headless.
```

## Security model

- Renderer runs sandboxed with `contextIsolation`, no Node. All network calls happen in main.
- Client ID/secret are encrypted with `safeStorage` (Keychain / DPAPI) in `credentials.bin` under `app.getPath('userData')`. Never send them to the renderer; `credentials:status` returns only a masked hint.
- `shell:openExternal` accepts https URLs only.
- No secrets are in the repo. Placeholders remain in `package.json` (`repository.url`, `author`) and `LICENSE`.

## What the API docs confirm vs what is assumed

Confirmed from https://my.pressable.com/documentation/api/v1:

- `POST /auth/token` (form-encoded client_credentials), `GET /v1/account`, `GET /v1/sites`
- `GET|POST /v1/sites/{id}/ondemand-backups` with `{ "backup_type": "fs" | "db" }`; max 3 per type per site; `GET|DELETE …/ondemand-backups/{backupId}`
- `GET|PUT|DELETE /v1/sites/{id}/edge-cache` (`{ enabled }`; DELETE purges)
- `GET|PUT /v1/sites/{id}/cache-preload` (`{ enabled }`; needs edge cache on + live site; 422 otherwise)
- `GET /v1/sites/{id}/security-alerts/plugins` and `/themes` (WPScan data; objects have title, description, fixed_in, references)
- Responses are `{ message, data, errors?, code?, page? }`.

Assumed (fix here if a real run disagrees):

- `POST /v1/sites/{id}/flush-object-cache` — path from community clients; the docs list the action but not the path.
- Field names on a backup object (`state`/`status`, `created`/`createdAt`): see `normalizeBackup()` in `src/pressable.js` and `isFinalState()`.
- The wrapper around security-alert vulnerability objects: see `extractVulnerabilities()` / `componentFrom()` in `src/security.js`. Raw responses for sites with findings are written to `runs.log` in userData.
- `GET /v1/sites` pagination params (`per_page`, `page`) mirror the collaborators endpoint; the client stops after one page if no `page` block comes back.

## Behavioural rules worth keeping

- Backups: always delete the oldest on-demand backup of the same type when a site already holds 3, then create. Record `replacedId`.
- Backup completion is polled from the renderer after a run (15 s × 8, then 30 s, up to 1 h) via `backups:status`, which can match backups that came back without an id by site list + requestedAt.
- Runs are sequential per site with `delayBetweenSitesMs` between sites; one run or scan at a time.
- Vulnerability "new" = not yet sent to the webhook, tracked per `findingKey|siteId` in `seen-findings.json`. Only successful sends mark things seen.
- Webhook: one message per vulnerability, sites grouped by installed version, summary message first when >1, 1.2 s spacing.
- Activity rows are keyed per run (`runId:siteId:kind:type`) so repeated runs never overwrite rows.
- UI follows the OS light/dark theme via CSS variables; `[hidden] { display: none !important }` exists because several containers set `display: flex/grid`.

## Testing

`npm test` covers the API client, the security module and a headless pass through main.js (fake Electron in `test/helpers.js`, `globalThis.fetch` mocked). Timers in main.js are `unref()`ed so the test process exits. For UI checks, load `src/renderer/index.html` in a headless browser with `window.pressable` stubbed before scripts run (Playwright `add_init_script`); the real preload is not needed.

Nothing has been run against the live Pressable API yet. First real run: check `runs.log` for the raw shapes listed under "Assumed".

## Style

- Plain Node/Electron, no bundler, no framework. Keep files runnable with `node --check`.
- Pin dependency versions exactly; prefer releases older than two weeks.
- Error messages shown to the person should be the API's own text when available (`PressableError.message`).
- Keep copy in the UI short and in sentence case; the app addresses the person as "you".
