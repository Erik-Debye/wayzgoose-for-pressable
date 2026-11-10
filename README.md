# Wayzgoose for Pressable

*Backups, cache control and vulnerability alerts for your Pressable sites.*
*Backups, Cache-Steuerung und Sicherheitswarnungen für deine Pressable-Seiten.*

A small Electron desktop app (macOS and Windows 11) for routine operations on your Pressable sites through the Pressable REST API. Pick a task, then run it on your saved list of sites or on a single site:

- **Back up** – create filesystem and/or database on-demand backups.
- **Clear cache** – purge the edge cache and/or flush the object cache.
- **Cache preload** – turn Pressable's crawl-and-warm feature on or off.
- **Security** – check every plugin and theme for known vulnerabilities, grouped by vulnerability with every affected site, enriched with the CVE's severity and the access an attacker needs, and posted to a Slack or Discord webhook.
- **Users** – audit which accounts hold administrator (or any watched) roles on every site and alert on new, promoted or removed ones; plus a one-click sentinel mu-plugin that reports role changes the instant they happen, with who did it.
- **Uptime** – load every live site's homepage every 1, 5, 10 or 15 minutes and post to a third webhook when a site stops answering, and again when it's back, with how long it was out.
- **Config** – compare what Pressable records for each site with what the site says about itself, to catch a staging push that carried its configuration onto production; optionally have each site report its wp-config.php constants to your channel.

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
3. Push a version tag. The tag is the version; the build stamps `package.json` with it, so the app, the installer filenames and the release always agree:
   ```bash
   git tag v0.1.0 && git push origin v0.1.0
   ```
   (Creating the tag through GitHub's **Releases → Draft a new release** page works too.)
4. Watch the **Actions** tab. After roughly five to ten minutes the release carries `Wayzgoose-for-Pressable-0.1.0-arm64.dmg`, `Wayzgoose-for-Pressable-0.1.0-x64.dmg` and `Wayzgoose-for-Pressable-0.1.0-Setup.exe`. Download and install like any other app.

For each later version, push the next tag (`v0.2.0`). Bumping `version` in `package.json` as well is tidy but not required. Installed copies check the repository for new releases every six hours and apply them on the next launch (macOS requires a signed build for this; unsigned Mac builds just keep working on the version you installed).

### First launch of an unsigned build

Without code-signing certificates the installers work, but each OS warns once:

- **macOS** says Apple could not verify the app. Open **System Settings → Privacy & Security**, scroll to the message about Wayzgoose for Pressable and click **Open Anyway**. If it says the app is damaged, run `xattr -cr "/Applications/Wayzgoose for Pressable.app"` in Terminal once.
- **Windows** SmartScreen shows "Windows protected your PC". Click **More info → Run anyway**.

To remove the warnings, add signing secrets in the repository's **Settings → Secrets and variables → Actions**: for macOS, `CSC_LINK` (base64 of a Developer ID Application `.p12`), `CSC_KEY_PASSWORD`, `APPLE_ID`, `APPLE_APP_SPECIFIC_PASSWORD` and `APPLE_TEAM_ID` (Apple Developer Program, US$99/year); for Windows, `WIN_CSC_LINK` and `WIN_CSC_KEY_PASSWORD` from a code-signing certificate. The workflow picks them up automatically and notarizes the Mac build.

## Self-hosting (runs around the clock)

The desktop app only checks while it's open. The same code also runs as a small server with the dashboard served as a web page, so the daily vulnerability check, the user audit and a nightly backup of your list happen on their own. It ships as a Docker image with Caddy in front for automatic HTTPS.

**You need:** a Linux VPS (1 vCPU / 512 MB is plenty), Docker, and a domain or subdomain whose DNS A record points at the server.

```bash
# 1. Docker, if the server doesn't have it (Ubuntu/Debian)
curl -fsSL https://get.docker.com | sh

# 2. The code
git clone https://github.com/Erik-Debye/wayzgoose-for-pressable.git
cd wayzgoose-for-pressable

# 3. Settings: three values are required
cp .env.example .env
openssl rand -hex 32        # paste the output as WAYZGOOSE_SECRET_KEY
nano .env                   # WAYZGOOSE_DOMAIN, WAYZGOOSE_PASSWORD, WAYZGOOSE_SECRET_KEY

# 4. Up
docker compose up -d
```

Open `https://your-domain`, sign in with the password, and enter your Pressable client ID and secret in Settings (or put them in `.env` as `PRESSABLE_CLIENT_ID` / `PRESSABLE_CLIENT_SECRET`). Everything else works exactly as in the desktop app; the **Schedule** section in Settings sets the audit interval and the nightly backup time.

Updating: `git pull && docker compose up -d --build`. Logs: `docker compose logs -f wayzgoose`. Data (config, results, encrypted credentials, `runs.log`) lives in the `wayzgoose-data` volume.

### How it's locked down

- Only Caddy is reachable from the internet, on 80 and 443; the app container has no published ports.
- Caddy fetches and renews a Let's Encrypt certificate itself and sets HSTS.
- Password sign-in with a 12-character minimum, constant-time comparison, five attempts per 15 minutes per IP, sessions in HttpOnly SameSite=Strict cookies that expire after 12 hours.
- Every API call needs both the session cookie and a custom header, so a cross-site page can't trigger actions.
- A strict Content Security Policy (same-origin scripts and styles only), no framing, no referrers.
- The Pressable secret is encrypted at rest with AES-256-GCM using `WAYZGOOSE_SECRET_KEY`; the key is the one thing to back up.
- The app container runs as an unprivileged user on a read-only filesystem with all capabilities dropped.

Optional: `WAYZGOOSE_API_TOKEN` lets scripts call `/api/<action>` with a bearer token (for example `curl -X POST https://your-domain/api/security:scan -H "Authorization: Bearer …" -d '{"payload":{"scope":"all"}}'`).

**Private network instead of a public domain?** If the server is on Tailscale or behind a VPN, drop the `caddy` service, publish port 8080 on the Tailscale address only, and set `WAYZGOOSE_INSECURE_COOKIE=1` (the cookie loses its Secure flag because there's no TLS). Don't do that on a public interface.

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
| WordPress users on a site | `GET /v1/sites/{id}/wordpress/users` (paginated) |
| Run WP-CLI on a site | `POST /v1/sites/{id}/wordpress/wpcli` with `{ "commands": [...] }` |
| Web server log (7 days, 200 per page) | `GET /v1/sites/{id}/logs/webserver` with `request_type`, `status`, `user_ip`, `scroll_id` |
| Site activity log (30 days) | `POST /v1/sites/{id}/logs/activity` with `{ page, per_page }` |
| PHP error log (7 days) | `GET /v1/sites/{id}/logs/php` with `severity` ("Fatal error", "Parse error", …) and `scroll_id` |
| Session check on a site | `POST /v1/sites/{id}/wordpress/wpcli` with `eval '…'` built from `scripts/session-check.php` |
| Account-wide mu-plugins | `GET/POST /v1/mu-plugins`, `PUT /v1/mu-plugins/{id}` with `{ path, existing_sites, future_sites }` |
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

## Privileged-user alerts

Two layers, sharing one webhook (Settings → *User privilege alerts*), kept separate from the vulnerability channel so role changes stand out. The first layer needs nothing on your sites; the second is optional.

**Audit, through the Pressable API only.** The Users tab lists each site's WordPress users, keeps the ones holding a watched role (default `administrator`; editable in Settings) and compares them with the previous audit stored in `admins.json`. New accounts, role changes and removals are shown in the panel and posted to the channel, one message per change. The first audit of a site records a baseline silently. The audit runs with the daily check if that's enabled.

When a change is found, the audit also pulls two of Pressable's logs for the window since the previous audit and attaches what it finds to the alert:

- the **web server log**, filtered to write requests (POST/PUT/PATCH/DELETE) against user-management endpoints (`user-new.php`, `user-edit.php`, `users.php`, `profile.php`, `/wp-json/wp/v2/users`, `xmlrpc.php`, `admin-ajax.php`), each with its time, status, IP and browser;
- the **site activity log**, which names the Pressable account behind any WP-CLI run, phpMyAdmin session or restore in that window.

That answers *how* and *from where*. For *which WordPress user*, the audit then sends a **session check** to the site: a one-off WP-CLI job (`scripts/session-check.php`, run through `wp eval`) that needs no plugin. WordPress core already records, for every logged-in session, the IP, user agent and login time, and for every application password its last-used time and IP. The script takes every user able to change roles (`promote_users`, `create_users`, `edit_users`, `delete_users`), finds their sessions and application-password uses overlapping the window, marks the ones whose IP matches a request from the web server log, and posts the candidates to the same channel, directly from the site. Because Pressable runs WP-CLI through a job queue, that message arrives a little after the audit alert. Where two admins share an IP you get both names and the user agents to tell them apart; a change with no candidate session at all points at WP-CLI, cron or a database edit.

Limits: the web server log keeps 7 days or 10,000 entries, whichever runs out first, so on a busy site the request evidence can scroll away within hours of a daily audit (audit more often if that matters); sessions expire after 48 hours, or 14 days with "Remember Me", so the session check is most useful when the audit runs at least daily; and a change made straight in the database leaves neither a request nor a session. When the logs show nothing, the alert says so rather than guessing.

One thing to know: Pressable stores WP-CLI commands in plain text in the site's activity log, so the webhook URL passes through there (the same is true of the sentinel's `wp config set`). A Discord webhook URL only allows posting to that channel; if it ever leaks, delete it in Discord and paste a new one into Settings.

**Sentinel, on the sites (optional).** For the WordPress username and an alert at the moment it happens, `mu-plugin/wayzgoose-sentinel.php` is a small must-use plugin. *Install sentinel* on the Users tab registers it through Pressable's account-wide mu-plugin API, pointing at the copy in this repository (`raw.githubusercontent.com/<owner>/<repo>/main/mu-plugin/wayzgoose-sentinel.php`), with *existing sites* and *future sites* both on. It then writes the webhook URL and watched roles into each site's `wp-config.php` as constants through WP-CLI (falling back to options if wp-config isn't writable) and fires the plugin's test hook so each site confirms itself in the channel. From then on, the moment a user is created with, promoted to, demoted from, or deleted while holding a watched role, the site posts the account, its registration date, a link to its edit screen, and the actor: the logged-in user, how (wp-admin, REST API, WP-CLI, cron, XML-RPC), their IP and user agent. A change with no logged-in user is flagged for investigation. Super-admin grants on multisite are covered too.

Because mu-plugins can't be disabled from wp-admin, an attacker who gains an administrator account can't switch the sentinel off without file access. Push the repository before installing (Pressable fetches the file from GitHub), and re-run *Install sentinel* after changing the webhook or roles, or after adding sites by hand. Registering mu-plugins may need an extra scope on your API application; the activity row shows the API's message if so.

## Uptime monitoring

The Uptime tab loads each site's homepage over HTTPS from the machine the app runs on (five at a time, 15-second timeout). A site is **up** when it answers with any status below 500; 401/403/404 still prove it's serving. It's **down** on a timeout, a DNS or TLS failure, a refused connection, or a 5xx, which includes Pressable's maintenance-mode 503. A failed probe is retried once after five seconds inside the same check, and a site is only reported down after it has failed the configured number of checks in a row (default two), so a single slow response never pages anyone.

Alerts go to the uptime webhook in Settings: one message when a site goes down (what failed, since when, how many checks) and one when it recovers (how long it was out). Nothing repeats while a site stays down. The panel shows every monitored site with its status, last response and how long it's been in that state; sites that are failing but not yet past the threshold are marked so you can see trouble coming.

"Check every" on the Uptime tab turns on automatic checks. In the desktop app they run while the app is open; on a self-hosted server they run around the clock. By default staging and sandbox sites are skipped and only live sites are checked; "Only my list" narrows it further. Each scheduled check that changes nothing stays out of the activity table; changes get a row.

**TLS certificates.** Once an hour per site (and immediately when a probe fails on a certificate error) the check opens its own TLS handshake and reads the certificate: expiry, issuer, and whether it's valid for the hostname. Warnings go to the uptime channel at 14, 7, 3 and 1 days before expiry, once each; one message when a certificate has expired; and one when a renewal pushes the expiry out again. Pressable renews certificates on its own, so a warning this late usually means the domain's DNS or a CAA record is blocking the renewal. The panel shows days left per site, in amber under 14.

**PHP fatal errors.** With *Look for PHP fatal errors every 15 minutes* (or 30, 60, never) the check pulls each site's PHP error log from Pressable, filtered to fatal and parse errors, and groups what it finds by signature: the same error in the same file counts as one, even when memory sizes or line numbers differ. A new signature is reported to the uptime channel with the message, the file and line, the plugin or theme it belongs to, and how many times it has fired; while it keeps recurring it's repeated at most every six hours. Warnings, notices and deprecations are ignored on purpose. Pressable keeps PHP logs for seven days, and so does the app's memory of signatures. The panel shows fatals in the last 24 hours under the affected site.

Measured from where the app runs, so a check from your laptop on hotel Wi-Fi can flag a site your visitors reach fine; the server version is the one to trust for that.

## Configuration check

After pushing staging to production, the files or database can carry staging settings across while the Pressable dashboard still shows the production record. The Config tab compares the two.

**What it reads from the outside, with no credentials:** the homepage (where it redirects to, its canonical link, the robots meta tag and X-Robots-Tag header, the generator tag, the REST link), the REST index at `/wp-json/` (which publicly exposes WordPress's `home` and `siteurl`), and `robots.txt`. From Pressable it takes the site's address, whether it's staging or sandbox, and its PHP version.

**What it flags on a production site:** any staging address (`*.mystagingwebsite.com`) in home, siteurl, the final redirect or the canonical link; a homepage that ends up somewhere other than Pressable's address; home or siteurl disagreeing with Pressable; `noindex`, which on production usually means "Discourage search engines" came over from staging; a robots.txt that disallows everything; http:// in home or siteurl; and a 5xx or unreachable homepage. On a staging site the search-engine blocks are reported as normal, and a staging site whose home points at the production domain gets its own warning. www. and bare hosts are treated as the same site.

**Deep check.** The constants in `wp-config.php` (WP_HOME, WP_SITEURL, WP_ENVIRONMENT_TYPE, WP_DEBUG, DISALLOW_FILE_MODS, JETPACK_STAGING_MODE, the masked DB_NAME and DB_HOST, table prefix, and more) can't be read from outside and the API can't return WP-CLI output, so with *Deep check* on, each site runs `scripts/config-report.php` through WP-CLI and posts its own report to the vulnerability-alerts channel, flagging anything that disagrees with Pressable (a home option pointing at staging, environment type `staging` on production, WP_DEBUG on, search engines discouraged). Reports arrive a little after the check because Pressable queues WP-CLI jobs.

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
- `admins.json`, `last-audit.json` – privileged users per site from the last audit, and its full result
- `uptime.json` – per-site uptime state (status, since when, consecutive failures, last response, certificate)
- `php-errors.json` – PHP fatal signatures per site with counts and when they were last reported
- `last-config.json` – the last configuration check

## Project layout

```
src/
  core/engine.js       Everything the app does, independent of host: config, task runs, vulnerability checks,
                       user audit, sentinel, scheduler. One handler per action, used by both hosts below
  main.js              Electron host: window, OS-keychain credentials, IPC → engine, auto-update
  pressable.js         API client (auth, retries, sites, backups, edge cache, cache preload, security alerts)
  security.js          Vulnerability findings: normalize alerts, CVE enrichment, CVSS wording, webhook messages
  users.js             Privileged-user audit: normalize users, diff snapshots, sentinel WP-CLI commands, alerts
  uptime.js            Uptime: probe, up/down classification, per-site state machine, TLS certificate reading and expiry thresholds, alerts
  phplogs.js           PHP log triage: normalize entries, keep fatals, group by signature, attribute to plugin/theme, cooldown
  config-check.js      Config: inspect a site's public surface and compare with Pressable's record
scripts/
  session-check.php    Sent to a site via wp eval after a change: which role-capable users were logged in, and from where
  config-report.php    Sent to a site via wp eval by the deep config check: wp-config constants and key options
mu-plugin/
  wayzgoose-sentinel.php  Must-use plugin installed on every site; posts role-change alerts with the actor
  preload.js           The only bridge the UI can use (contextBridge)
  server/server.js     Self-hosted host: sign-in, sessions, HTTP routes → engine, SSE events, static dashboard
  server/bridge.js     Browser stand-in for preload: window.pressable over fetch + EventSource
  renderer/
    index.html
    styles.css         Follows the OS light/dark theme
    renderer.js        Site list, task switcher, list/single-site modes, findings panel, activity table, polling
test/                  node:test suites (client, security, users, headless main-process run, server)
Dockerfile, docker-compose.yml, Caddyfile, .env.example   Self-hosting
CLAUDE.md              Project notes for coding agents
```

## A note on response fields

The Pressable docs show the request side of the on-demand backup endpoints clearly, but the exact field names on a backup object (state, created date) aren't spelled out. `normalizeBackup()` in `src/pressable.js` reads the common variants (`state`/`status`, `created`/`createdAt`/`created_at`, `backup_type`/`type`). If the status column shows "Requested" and never updates after a real run, open `runs.log`, look at a `backup:created` entry's `response`, and adjust the field names there.

## License

MIT. See `LICENSE`.
