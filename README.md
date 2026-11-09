# Wayzgoose for Pressable

*Backups, cache control and vulnerability alerts for your Pressable sites.*

A small Electron desktop app (macOS and Windows 11) for routine operations on your Pressable sites through the Pressable REST API. Pick a task, then run it on your saved list of sites or on a single site:

- **Back up** – create filesystem and/or database on-demand backups.
- **Clear cache** – purge the edge cache and/or flush the object cache.
- **Cache preload** – turn Pressable's crawl-and-warm feature on or off.
- **Security** – check every plugin and theme for known vulnerabilities, grouped by vulnerability with every affected site, enriched with the CVE's severity and the access an attacker needs, and posted to a Slack or Discord webhook.

The site list is built by ticking sites in the sidebar and is saved between launches. This is an independent tool built on Pressable's public API; it isn't made or endorsed by Pressable or Automattic.

**About the name.** A wayzgoose was the annual feast a master printer gave the people who kept the press running. Nobody is quite sure where the word comes from, which is part of its charm. The single-site card shows that site's current edge cache and cache preload status. Progress and results stream into an activity table, and backups keep being checked until Pressable reports them finished (see *How completion is tracked*).

## Before you start

1. In MyPressable go to **User Settings → API Applications → Create New API Application**
   (https://my.pressable.com/api/applications).
2. Give the application **Sites: Read** and **Sites: Edit**. Those are the scopes the on-demand backup endpoints require.
3. Copy the client ID and client secret. You'll paste them into the app on first launch; they are stored encrypted with your OS keystore (Keychain on macOS, DPAPI on Windows) and never leave the main process.

You need Node.js 20 or newer to run or build the app.

## Getting installers without building anything

The repository includes a GitHub Actions workflow (`.github/workflows/release.yml`) that builds the macOS `.dmg` (Apple Silicon and Intel) and the Windows installer on GitHub's own machines and attaches them to a GitHub Release. You never run a build locally.

1. Create a public GitHub repository and upload this folder to it (GitHub Desktop or the web uploader both work). Public repositories get unlimited Actions minutes, and the app's auto-updater reads the Releases page anonymously.
2. In `package.json`, set `repository.url` to your repository's URL. Optionally change `build.appId`.
3. Make a release. Either:
   - on GitHub: **Releases → Draft a new release**, create a tag like `v0.1.0` that matches the `version` in `package.json`, publish; or
   - locally, if you have Node: `npm version patch && git push --follow-tags`.
4. Watch the **Actions** tab. After roughly five to ten minutes the release carries `Wayzgoose-for-Pressable-0.1.0-arm64.dmg`, `Wayzgoose-for-Pressable-0.1.0-x64.dmg` and `Wayzgoose-for-Pressable-0.1.0-Setup.exe`. Download and install like any other app.

For each later version, bump `version` in `package.json` and repeat step 3. Installed copies check the repository for new releases every six hours and apply them on the next launch (macOS requires a signed build for this; unsigned Mac builds just keep working on the version you installed).

### First launch of an unsigned build

Without code-signing certificates the installers work, but each OS warns once:

- **macOS** says Apple could not verify the app. Open **System Settings → Privacy & Security**, scroll to the message about Wayzgoose for Pressable and click **Open Anyway**. If it says the app is damaged, run `xattr -cr "/Applications/Wayzgoose for Pressable.app"` in Terminal once.
- **Windows** SmartScreen shows "Windows protected your PC". Click **More info → Run anyway**.

To remove the warnings, add signing secrets in the repository's **Settings → Secrets and variables → Actions**: for macOS, `CSC_LINK` (base64 of a Developer ID Application `.p12`), `CSC_KEY_PASSWORD`, `APPLE_ID`, `APPLE_APP_SPECIFIC_PASSWORD` and `APPLE_TEAM_ID` (Apple Developer Program, US$99/year); for Windows, `WIN_CSC_LINK` and `WIN_CSC_KEY_PASSWORD` from a code-signing certificate. The workflow picks them up automatically and notarizes the Mac build.

## Run, test or build locally (optional)

```bash
npm install        # downloads Electron; needed for npm start and dist
npm test           # unit and integration tests; runs without Electron installed
npm start          # run from source
npm run dist:mac   # or dist:win — installers land in release/
```

Build each platform on that platform: macOS builds need a Mac. `CLAUDE.md` describes the architecture and what is verified against the Pressable docs versus assumed, for anyone (or any coding agent) picking the project up.

## How it talks to Pressable

| What | Endpoint |
| --- | --- |
| Sign in (client credentials) | `POST https://my.pressable.com/auth/token` |
| Account check after saving credentials | `GET /v1/account` |
| Load your sites | `GET /v1/sites` (paginated) |
| List a site's on-demand backups | `GET /v1/sites/{id}/ondemand-backups` |
| Create a backup | `POST /v1/sites/{id}/ondemand-backups` with `{"backup_type": "fs"}` or `"db"` |
| Check one backup | `GET /v1/sites/{id}/ondemand-backups/{backupId}` |
| Delete the oldest backup when a site is full | `DELETE /v1/sites/{id}/ondemand-backups/{backupId}` |
| Edge cache status | `GET /v1/sites/{id}/edge-cache` |
| Turn edge cache on (only with the preload fallback option) | `PUT /v1/sites/{id}/edge-cache` with `{"enabled": true}` |
| Purge edge cache | `DELETE /v1/sites/{id}/edge-cache` |
| Flush object cache | `POST /v1/sites/{id}/flush-object-cache` (see note below) |
| Cache preload status | `GET /v1/sites/{id}/cache-preload` |
| Plugin / theme vulnerability alerts | `GET /v1/sites/{id}/security-alerts/plugins` and `/themes` |
| Turn cache preload on/off | `PUT /v1/sites/{id}/cache-preload` with `{"enabled": true|false}` |

Access tokens last an hour; the client refreshes a minute early and retries once on a 401. On a 429 it waits for `Retry-After` and retries. Sites are processed one after another with a short pause between them.

## The 3-backup limit

Pressable keeps at most **3 filesystem and 3 database on-demand backups per site**, and auto-deletes them after 7–30 days. Before every backup the app lists the site's existing on-demand backups of that type; if there are already 3, it deletes the oldest (by created date) and then creates the new one. The activity row shows which backup was replaced. Nothing is deleted when the site has room.

## Cache tasks

**Clear cache** has two layers you can tick independently. *Edge cache* is Pressable's page cache at the edge; purging it is safe and instant. *Object cache* is the Memcached layer behind WordPress; flushing it can slow a busy site briefly while it refills, so it's off by default. The object-cache endpoint path (`POST /sites/{id}/flush-object-cache`) comes from community API clients rather than the official docs, which list the action but not its path. If it ever returns a 404, the activity row will say so; check the docs under Sites → Flush Object Cache for the current path.

**Cache preload** (Pressable calls it a beta) crawls a site and warms its pages after each cache clear. Turning it on requires a live site with edge cache on; the API answers 422 otherwise and the row shows that message. Tick *Turn on edge cache first if a site has it off* to have the app enable edge cache before turning preload on. Turning edge cache off also turns preload off on Pressable's side. Pressable's own warnings (for example, sites with 5 or fewer PHP workers) are shown in the row and in the single-site status panel.

## Vulnerability checks

Pressable's Security Alerts are powered by WPScan's vulnerability database (Automattic owns both WPScan and Jetpack Protect, so it's the same data Jetpack Protect shows inside wp-admin). The API exposes it per site: `GET /sites/{id}/security-alerts/plugins` and `/themes` return each vulnerable plugin or theme with its vulnerabilities (title, description, fixed-in version, references). The check:

1. Pulls both lists for every site in scope (all sites on the account, or just your list) and groups the results so each vulnerability appears once with every site and installed version it affects.
2. Looks each CVE up at cve.org (no key needed; the CNA that assigned the CVE, usually Wordfence, Patchstack or WPScan, supplies a CVSS vector) and falls back to NVD when the record carries no score. Results are cached for a week in `cve-cache.json`.
3. Turns the CVSS vector into one line you can act on, such as "Exploitable over the network; requires a logged-in user (subscriber-level or similar); no user interaction." That answers the "what access does the attacker need" question. Finer preconditions, such as whether comments must be enabled, aren't structured anywhere; they're in the CVE description, which the finding shows under *Details*.
4. Posts new findings to your webhook, if one is configured. Each vulnerability is its own message (a Discord embed or a Slack block message) so your team can react to or thread on each one; when there are several, a one-line summary goes first. Inside each message the affected sites are grouped by installed version, so it's obvious which sites share a fix. Slack and Discord URLs are detected automatically; any other https URL receives one JSON call per vulnerability (handy for Zapier or n8n). A site counts as *new* for a vulnerability until it has been sent, so repeat checks only alert on changes, and a vulnerability that spreads to another site alerts again with just that site. *Send all* re-posts everything. Messages are spaced 1.2 s apart to stay under both services' webhook rate limits.

Enable *Check for vulnerabilities once a day while the app is open* in Settings for an unattended daily check. Pressable refreshes WPScan data daily and plugin lists several times a week, so checking more often adds nothing.

Rate limits: cve.org has no published limit and the app spaces lookups 300 ms apart; NVD allows 5 requests per 30 seconds without a key and 50 with one, so add a key in Settings if you have many CVEs without cve.org scores.

Note: the exact JSON wrapper around Pressable's alert objects isn't shown in the docs, so `extractVulnerabilities()` in `src/security.js` walks the response and treats anything WPScan-shaped (`fixed_in`, `vuln_type`, `references`…) as a vulnerability. The raw response for any site with findings is written to `runs.log`.

## How completion is tracked

Creating a backup is asynchronous on Pressable's side: the API accepts the request and the backup finishes later. Pressable offers a webhook for this, but a desktop app has nowhere to receive one, so the app polls instead:

- When the run finishes, every backup that isn't already in a final state is checked every 15 seconds for the first two minutes, then every 30 seconds, for up to an hour.
- Backups the API returned an id for are checked with `GET /v1/sites/{id}/ondemand-backups/{backupId}`. If the create call returned no id, the app looks at the site's backup list for the newest backup of that type created since the request and tracks that one.
- A status is treated as final when it contains *complete*, *success*, *ready*, *available*, *finished*, *done*, *failed*, *error* or *cancelled*. The row's pill updates and the details column gets a "finished 10:42 AM" (or "failed …") stamp. The summary line above the activity table keeps a running count of requested / completed / failed.
- Polling only happens while the app is open. If you quit mid-way, the backups still complete on Pressable's side; the app just won't show it.

Cache clears and preload changes are synchronous from the API's point of view, so their rows finish immediately. For preload, the status panel on the single-site card shows the live crawl state (pending / running / finished, pages found and warmed) whenever that site is selected.

## Where things live

Settings and credentials are in the app's user-data folder (Settings → *Open data folder*):

- `config.json` – your saved site list and the last task you ran with its options
- `credentials.bin` – encrypted client ID and secret
- `runs.log` – one JSON line per operation, including raw API responses, handy if anything looks off
- `last-findings.json`, `seen-findings.json`, `cve-cache.json` – the last vulnerability check, what has been reported to your webhook, and cached CVE records

## Project layout

```
src/
  main.js              Electron main process: window, storage, IPC, task run engine
  pressable.js         API client (auth, retries, sites, backups, edge cache, cache preload, security alerts)
  security.js          Vulnerability findings: normalize alerts, CVE enrichment, CVSS wording, webhook messages
  preload.js           The only bridge the UI can use (contextBridge)
  renderer/
    index.html
    styles.css         Follows the OS light/dark theme
    renderer.js        Site list, task switcher, list/single-site modes, findings panel, activity table, polling
test/                  node:test suites (client, security module, headless main-process run)
CLAUDE.md              Project notes for coding agents
```

## A note on response fields

The Pressable docs show the request side of the on-demand backup endpoints clearly, but the exact field names on a backup object (state, created date) aren't spelled out. `normalizeBackup()` in `src/pressable.js` reads the common variants (`state`/`status`, `created`/`createdAt`/`created_at`, `backup_type`/`type`). If the status column shows "Requested" and never updates after a real run, open `runs.log`, look at a `backup:created` entry's `response`, and adjust the field names there.

## License

MIT. See `LICENSE`.
