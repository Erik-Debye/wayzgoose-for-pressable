# Wayzgoose for Pressable

Electron desktop app (macOS, Windows) for routine work on Pressable-hosted WordPress sites via the Pressable REST API: on-demand backups, edge/object cache clearing, cache-preload toggling, and vulnerability checks with Slack/Discord alerts. Tasks run on a saved list of sites or on one site.

## Commands

```bash
npm install        # downloads Electron (~100 MB); needed for npm start and dist
npm test           # unit + integration tests, no Electron binary needed
npm start          # run the desktop app from source
npm run serve      # run the self-hosted server (needs WAYZGOOSE_PASSWORD, WAYZGOOSE_DATA_DIR)
npm run dist:mac   # local installer builds (CI normally does this)
docker compose up -d   # self-hosted with Caddy (see README "Self-hosting")
```

Releases: push a tag `v<version>` (`git tag v0.2.0 && git push origin v0.2.0`). `.github/workflows/release.yml` stamps package.json with the tag's version, builds the installers on GitHub's Mac and Windows runners and attaches them to a release for that tag. Signing env vars are only exported when the matching secrets exist (an empty `CSC_LINK` breaks electron-builder). Installed copies auto-update from Releases via electron-updater.

## Layout

```
src/core/engine.js      createEngine({ dataDir, credentials, emit }) → { handlers, startScheduler, ... }.
                        All behaviour lives here: config, task runs (backup / cache / preload), vulnerability
                        scan, user audit + forensics + session check, sentinel install, scheduler.
                        handlers[channel](payload) mirrors the IPC channel names; both hosts delegate to it.
src/main.js             Electron host only: window, safeStorage credentials, ipcMain → engine.handlers,
                        shell:* handlers, auto-update
src/server/server.js    Self-hosted host: createServer(env) → http server. Password login (rate limited),
                        session cookies, POST /api/<channel> → engine.handlers (needs X-Wayzgoose header or
                        bearer token), GET /api/events (SSE), static renderer + bridge, AES-256-GCM credentials
src/server/bridge.js    window.pressable for the browser (fetch + EventSource), replaces preload.js
src/pressable.js        API client: OAuth client-credentials token (1 h, refreshed early), 401 retry,
                        429 Retry-After, site pagination, all endpoint wrappers, normalizeBackup()
src/security.js         Pure functions: extractVulnerabilities() (walks Pressable's alert JSON),
                        groupFindings(), CVE enrichment (cve.org, NVD fallback), CVSS → plain English,
                        new-finding tracking, Slack/Discord/generic webhook payloads, sendWebhook()
src/users.js            Pure functions: normalizeUser(), diffPrivileged() (baseline + added/changed/removed),
                        log forensics (normalizeLogEntry, relevantRequests, relevantActivity, forensicsLines),
                        sentinelConfigCommands() (WP-CLI), sentinelSourceUrl(), buildAuditPayloads()
scripts/session-check.php  PHP sent via `wp eval` (one line, single quotes forbidden, // comments stripped) after an audit change:
                        lists role-capable users' core session tokens + application-password last_used/last_ip in the window,
                        matches against web-log IPs, posts candidates to the user webhook. Built by buildSessionCheckCommand().
mu-plugin/wayzgoose-sentinel.php  Must-use plugin pushed to every site via POST /mu-plugins; hooks set_user_role,
                        add/remove_user_role, user_register, delete_user, (grant|revoke)_super_admin and posts to the
                        webhook with actor, IP, UA, request. Reads WAYZGOOSE_SENTINEL_WEBHOOK/ROLES constants or options.
src/uptime.js           Pure: siteUrl(), probe() (never throws), isUp() (<500), nextState() state machine with
                        failuresToAlert + alertedDown, checkTls() (own tls.connect, rejectUnauthorized:false),
                        certInfo(), nextTlsState() (thresholds 14/7/3/1 once each, expired once, renewed once),
                        durationText(), buildUptimePayloads() for down/up/tls-*/php-fatal
src/phplogs.js          Pure: normalizePhpEntry() (raw lines or objects), isFatal(), componentOf(path),
                        signatureOf() (digits → #), triage(prev, entries) with 6 h cooldown, summarize()
src/config-check.js     Pure: inspectSite(site, {fetchImpl}) → { facts, findings }; evaluate(facts) encodes the rules
                        (staging host on production, redirects/home/siteurl vs Pressable host, noindex, robots.txt,
                        http://, unreachable). bareHost() strips www. Deep check = scripts/config-report.php via wp eval.
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
- `GET /v1/sites/{id}/wordpress/users` (paginated; docs show page/per_page in a body, sent as query here), `POST /v1/sites/{id}/wordpress/wpcli` `{ commands: [...] }`
- `GET|POST /v1/mu-plugins`, `PUT /v1/mu-plugins/{id}` with `{ path, existing_sites, future_sites }` (path = raw file URL)
- `GET /v1/sites/{id}/logs/webserver` (docs index) / `/logs/server` (docs example; client falls back on 404) with `request_type`, `status`, `user_ip`, `scroll_id`; 200 per page, 7 days / 10k entries
- `POST /v1/sites/{id}/logs/activity` `{ page, per_page }` (30 days; entries carry description, email, ipAddress, source)
- Responses are `{ message, data, errors?, code?, page? }`.

Assumed (fix here if a real run disagrees):

- `POST /v1/sites/{id}/flush-object-cache` — path from community clients; the docs list the action but not the path.
- Field names on a backup object (`state`/`status`, `created`/`createdAt`): see `normalizeBackup()` in `src/pressable.js` and `isFinalState()`.
- The wrapper around security-alert vulnerability objects: see `extractVulnerabilities()` / `componentFrom()` in `src/security.js`. Raw responses for sites with findings are written to `runs.log` in userData.
- Field names on a WordPress user from `/wordpress/users` (roles may be `roles`, `role` or a capabilities object): `normalizeUser()` in `src/users.js`. If every user comes back role-less the audit flags it and logs a sample.
- Field names on web server log entries (timestamp/path/status/user_ip/user_agent variants are handled in `normalizeLogEntry()`); on the first real audit that finds a change, compare `runs.log` `audit:forensics` counts with the UI.
- WP-CLI through the API is a job queue with no returned output, which is why the session check posts its own result to the webhook instead of returning it.
- Whether `wp config set` is allowed on Pressable; the sentinel installer falls back to `wp option update` and the plugin reads either.
- Which OAuth scope `/mu-plugins` needs.
- `GET /v1/sites/{id}/logs/php` path and entry shape (severity filter values from Pressable's MCP docs: "Fatal error", "Parse error", "Warning", "Deprecated", "User"); client falls back to `/logs/php-errors` on 404. If a real run shows no fatals that MyPressable shows, check `runs.log` for `uptime:php-log-failed` and the raw shape.
- `GET /v1/sites/{id}` detail fields (phpVersion, datacenterCode assumed; raw kept on the config result)
- `GET /v1/sites` pagination params (`per_page`, `page`) mirror the collaborators endpoint; the client stops after one page if no `page` block comes back.

## Behavioural rules worth keeping

- Backups: always delete the oldest on-demand backup of the same type when a site already holds 3, then create. Record `replacedId`.
- Backup completion is polled from the renderer after a run (15 s × 8, then 30 s, up to 1 h) via `backups:status`, which can match backups that came back without an id by site list + requestedAt.
- Runs are sequential per site with `delayBetweenSitesMs` between sites; one run or scan at a time.
- Vulnerability "new" = not yet sent to the webhook, tracked per `findingKey|siteId` in `seen-findings.json`. Only successful sends mark things seen.
- Webhook: one message per vulnerability, sites grouped by installed version, summary message first when >1, 1.2 s spacing.
- User audit: first audit of a site is a silent baseline. When a site shows a change, `gatherForensics()` pulls POST/PUT/PATCH/DELETE web server log pages (≤10 per method, stops once older than the window) plus the activity log, and attaches `forensics` to every event for that site; alerts and the panel render it. Alerts are one message per change. Sentinel install = register mu-plugin (create or update by path match) → per site: `config set` constants, else `option update` → fire `wayzgoose_sentinel_test`.
- Uptime extras: TLS is re-read hourly per site (`TLS_RECHECK_MS`) or at once when a probe fails on a TLS error; PHP logs are pulled every `phpLogEveryMinutes` per site (state in `php-errors.json`); both ride on the uptime check and post to `uptimeWebhookUrl`. Tests stub `uptime.checkTls` to keep handshakes off the network.
- Uptime: `executeUptimeCheck` probes 5 at a time, retries a failure once after 5 s, folds into `uptime.json` via `nextState`, posts down/up events to `uptimeWebhookUrl`. Scheduled checks emit `finished` with `trigger: 'scheduled'`; the renderer only adds an activity row when `events` is non-empty. Site list is cached 30 min (`getSitesCached`) so frequent checks don't hit the API.
- Scheduler (`engine.maybeScheduled`, ticks every 60 s, unref'd): uptime every `uptimeEveryMinutes`; daily vuln check (+audit) when `dailyCheck`; user audit every `auditEveryHours`; backup of the list once per day at `backupListAt` (local time, `schedule.json` remembers the day).
- Config check: `executeConfigCheck` (4 at a time) merges `GET /sites/{id}` detail, runs `inspectSite`, sorts worst-first, stores `last-config.json`; with `deep` it sends `config-report.php` via WP-CLI to post to `webhookUrl`. The renderer bridge key is `config_check` (not `config`, which is the settings store).
- Element ids in index.html must be unique; `$()` is getElementById and a duplicate silently returns the first match (this bit once: a radio and a panel both named `uptime-list`).
- Server: `/api/*` POST requires session + `X-Wayzgoose: 1` (CSRF) or `Authorization: Bearer WAYZGOOSE_API_TOKEN`. The renderer's meta CSP is stripped and replaced by the HTTP header. Inline `style=""` is blocked by that CSP; use classes.
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
