'use strict';

// Configuration check. Pressable knows a site's address, PHP version and
// whether it's staging; the site itself knows where it thinks it lives
// (home/siteurl), whether it's hiding from search engines, and what version
// of WordPress it runs. After a staging-to-production push those two views
// can disagree. This module reads the site's public surface (no credentials
// needed) and compares.

const STAGING_HOST = /\.mystagingwebsite\.com$/i;
const TIMEOUT_MS = 15_000;

function hostOf(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
}

// www.acme.com and acme.com are the same site for our purposes.
function bareHost(url) {
  const h = hostOf(url);
  return h ? h.replace(/^www\./, '') : null;
}

function siteBase(site) {
  const raw = String(site.url || site.name || '').trim();
  return /^https?:\/\//i.test(raw) ? raw.replace(/\/+$/, '') : `https://${raw.replace(/\/+$/, '')}`;
}

async function fetchText(url, { fetchImpl, accept }) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetchImpl(url, {
      method: 'GET',
      redirect: 'follow',
      headers: { 'User-Agent': 'Wayzgoose-for-Pressable config check', Accept: accept || 'text/html,*/*' },
      signal: controller.signal,
    });
    const text = await res.text();
    const headers = {};
    if (res.headers && typeof res.headers.forEach === 'function') res.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
    else if (res.headers && typeof res.headers.get === 'function') for (const k of ['x-robots-tag', 'content-type', 'link']) { const v = res.headers.get(k); if (v) headers[k] = v; }
    return { ok: true, status: res.status, finalUrl: res.url || url, text: text.slice(0, 400_000), headers };
  } catch (err) {
    const timedOut = err && (err.name === 'AbortError');
    return { ok: false, status: null, finalUrl: url, text: '', headers: {}, error: timedOut ? `no response within ${TIMEOUT_MS / 1000} s` : (err && err.message) || 'request failed' };
  } finally {
    clearTimeout(timer);
  }
}

// ----- HTML scraping (regex is enough for these four tags) -----

function attr(tag, name) {
  const m = tag.match(new RegExp(`${name}\\s*=\\s*["']([^"']*)["']`, 'i'));
  return m ? m[1] : null;
}

function parseHtml(html) {
  const out = { canonical: null, robotsMeta: null, generator: null, apiLink: null, title: null };
  for (const tag of html.match(/<link\b[^>]*>/gi) || []) {
    const rel = (attr(tag, 'rel') || '').toLowerCase();
    if (rel === 'canonical') out.canonical = attr(tag, 'href');
    if (rel === 'https://api.w.org/') out.apiLink = attr(tag, 'href');
  }
  for (const tag of html.match(/<meta\b[^>]*>/gi) || []) {
    const name = (attr(tag, 'name') || '').toLowerCase();
    if (name === 'robots') out.robotsMeta = attr(tag, 'content');
    if (name === 'generator' && !out.generator) out.generator = attr(tag, 'content');
  }
  const t = html.match(/<title[^>]*>([^<]*)<\/title>/i);
  if (t) out.title = t[1].trim().slice(0, 120);
  return out;
}

function parseRobotsTxt(text) {
  // true when some "User-agent: *" group disallows everything
  const lines = text.split(/\r?\n/).map((l) => l.split('#')[0].trim()).filter(Boolean);
  let star = false;
  let disallowAll = false;
  for (const line of lines) {
    const [k, ...rest] = line.split(':');
    const v = rest.join(':').trim();
    const key = k.trim().toLowerCase();
    if (key === 'user-agent') star = v === '*';
    else if (star && key === 'disallow' && v === '/') disallowAll = true;
  }
  return disallowAll;
}

// ----- Inspection -----

async function inspectSite(site, { fetchImpl = globalThis.fetch } = {}) {
  const base = siteBase(site);
  const facts = {
    pressableUrl: site.url || null,
    pressableHost: bareHost(base),
    staging: Boolean(site.staging),
    sandbox: Boolean(site.sandbox),
    phpVersion: site.phpVersion || site.php_version || null,
    datacenter: site.datacenterCode || site.datacenter || null,
    homepage: null,
    rest: null,
    robotsTxt: null,
  };

  const home = await fetchText(`${base}/`, { fetchImpl });
  const parsed = home.ok ? parseHtml(home.text) : {};
  facts.homepage = {
    ok: home.ok,
    status: home.status,
    finalUrl: home.finalUrl,
    finalHost: bareHost(home.finalUrl),
    error: home.error || null,
    canonical: parsed.canonical || null,
    robotsMeta: parsed.robotsMeta || null,
    xRobotsTag: home.headers['x-robots-tag'] || null,
    generator: parsed.generator || null,
    apiLink: parsed.apiLink || null,
    title: parsed.title || null,
  };

  const restUrl = facts.homepage.apiLink || `${base}/wp-json/`;
  const rest = await fetchText(restUrl, { fetchImpl, accept: 'application/json' });
  if (rest.ok && rest.status < 400) {
    try {
      const j = JSON.parse(rest.text);
      facts.rest = { ok: true, status: rest.status, home: j.home || null, siteurl: j.url || null, name: j.name || null, timezone: j.timezone_string || null };
    } catch {
      facts.rest = { ok: false, status: rest.status, error: 'not JSON' };
    }
  } else {
    facts.rest = { ok: false, status: rest.status, error: rest.error || `HTTP ${rest.status}` };
  }

  const robots = await fetchText(`${base}/robots.txt`, { fetchImpl, accept: 'text/plain,*/*' });
  facts.robotsTxt = robots.ok && robots.status === 200 ? { ok: true, disallowAll: parseRobotsTxt(robots.text) } : { ok: false, status: robots.status };

  return { facts, findings: evaluate(facts) };
}

// Findings: { severity: 'high'|'medium'|'low'|'info', code, message }
function evaluate(f) {
  const out = [];
  const production = !f.staging && !f.sandbox;
  const push = (severity, code, message) => out.push({ severity, code, message });
  const hp = f.homepage;

  if (!hp.ok) {
    push('high', 'unreachable', `Homepage could not be loaded: ${hp.error}.`);
    return out;
  }
  if (hp.status >= 500) push('high', 'server-error', `Homepage answers HTTP ${hp.status}.`);

  const hosts = {
    final: hp.finalHost,
    home: f.rest && f.rest.ok ? bareHost(f.rest.home) : null,
    siteurl: f.rest && f.rest.ok ? bareHost(f.rest.siteurl) : null,
    canonical: bareHost(hp.canonical),
    api: bareHost(hp.apiLink),
  };
  const isStagingHost = (h) => h && STAGING_HOST.test(h);

  if (production) {
    const stagingHits = Object.entries(hosts).filter(([, h]) => isStagingHost(h)).map(([k]) => k);
    if (stagingHits.length) {
      push('high', 'staging-address-on-production', `This production site points at a staging address in: ${stagingHits.join(', ')}. That's the signature of a staging push that carried its configuration along.`);
    }
  } else if (hosts.home && f.pressableHost && hosts.home !== f.pressableHost && !isStagingHost(hosts.home)) {
    push('medium', 'production-address-on-staging', `This staging site reports its home as ${hosts.home}, not its own address. Visitors to staging may be sent to production.`);
  }

  if (hosts.final && f.pressableHost && hosts.final !== f.pressableHost) {
    push(production ? 'high' : 'low', 'redirects-elsewhere', `The homepage ends up at ${hosts.final} instead of ${f.pressableHost}.`);
  }
  if (hosts.home && f.pressableHost && hosts.home !== f.pressableHost) {
    push(production ? 'high' : 'low', 'home-mismatch', `WordPress reports its home address as ${hosts.home}; Pressable has ${f.pressableHost}.`);
  }
  if (hosts.siteurl && hosts.home && hosts.siteurl !== hosts.home) {
    push('medium', 'siteurl-differs', `siteurl (${hosts.siteurl}) differs from home (${hosts.home}).`);
  }
  if (f.rest && f.rest.ok) {
    if (/^http:\/\//i.test(f.rest.home || '') || /^http:\/\//i.test(f.rest.siteurl || '')) {
      push('medium', 'insecure-url', 'home or siteurl is set to http://, not https://.');
    }
  } else if (f.rest) {
    push('info', 'rest-unavailable', `The REST index (/wp-json/) didn't answer (${f.rest.error}); home and siteurl couldn't be read from the site.`);
  }
  if (hosts.canonical && f.pressableHost && hosts.canonical !== f.pressableHost && !hosts.home) {
    push('low', 'canonical-elsewhere', `The canonical link points at ${hosts.canonical}.`);
  }

  const noindex = /noindex/i.test(hp.robotsMeta || '') || /noindex/i.test(hp.xRobotsTag || '');
  if (noindex) {
    push(production ? 'high' : 'info', 'noindex', production
      ? 'Search engines are told not to index this site (noindex). On a production site that usually means "Discourage search engines" was pushed from staging.'
      : 'Search engines are blocked (noindex), which is normal for staging.');
  }
  if (f.robotsTxt && f.robotsTxt.ok && f.robotsTxt.disallowAll) {
    push(production ? 'medium' : 'info', 'robots-disallow-all', 'robots.txt disallows everything for all crawlers.');
  }

  if (!hp.generator && hp.status < 400 && !hp.apiLink) {
    push('info', 'no-wordpress-markers', 'The homepage shows no WordPress generator tag or REST link; the site may hide them, or something else is answering at this address.');
  }
  return out;
}

const RANK = { high: 0, medium: 1, low: 2, info: 3 };
function worst(findings) {
  let w = null;
  for (const f of findings) if (w === null || RANK[f.severity] < RANK[w]) w = f.severity;
  return w || 'ok';
}

module.exports = { inspectSite, evaluate, parseHtml, parseRobotsTxt, bareHost, siteBase, worst, STAGING_HOST };
