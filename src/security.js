'use strict';

// Vulnerability findings: normalize Pressable's security alerts (WPScan data),
// enrich each CVE with its official record, and build chat alerts.
//
// Pure functions live here so they can be unit-tested without Electron.

const CVE_RE = /\bCVE-\d{4}-\d{4,}\b/gi;

// ---------- Normalizing Pressable alerts ----------

// Pressable's docs show WPScan-shaped vulnerability objects (title,
// description, fixed_in, references…) but not the exact wrapper around them.
// Walk whatever comes back, treat any object that looks like a vulnerability
// as one, and pick up plugin/theme name and version from its ancestors.
function extractVulnerabilities(data, kind) {
  const found = [];
  const seen = new Set();

  const looksLikeVuln = (o) =>
    o && typeof o === 'object' && !Array.isArray(o) &&
    ('fixed_in' in o || 'fixedIn' in o || 'vuln_type' in o || 'vulnType' in o ||
      ('title' in o && ('references' in o || 'published_date' in o || 'cvss' in o)));

  const walk = (node, ancestors) => {
    if (Array.isArray(node)) {
      for (const child of node) walk(child, ancestors);
      return;
    }
    if (!node || typeof node !== 'object') return;

    if (looksLikeVuln(node)) {
      const component = componentFrom([...ancestors, node], kind);
      const vuln = normalizeVulnerability(node, component);
      const dedupe = `${component.slug}|${vuln.id || vuln.title}`;
      if (!seen.has(dedupe)) {
        seen.add(dedupe);
        found.push(vuln);
      }
      return;
    }
    for (const value of Object.values(node)) {
      if (value && typeof value === 'object') walk(value, [...ancestors, node]);
    }
  };

  walk(data, []);
  return found;
}

function componentFrom(chain, kind) {
  // The vulnerability object itself may carry plugin fields (flat records),
  // otherwise the nearest ancestor with a slug/name/version wins.
  for (let i = chain.length - 1; i >= 0; i -= 1) {
    const a = chain[i];
    const isVulnNode = i === chain.length - 1;
    const slug = a.slug ?? a.plugin_slug ?? a.pluginSlug ?? a.theme_slug ?? a.themeSlug ?? a.plugin ?? a.theme ?? a.stylesheet ?? a.textdomain ?? null;
    const explicitName = a.plugin_name ?? a.pluginName ?? a.theme_name ?? a.themeName ?? null;
    // On the vulnerability node, "name"/"title" are the vulnerability's own.
    const name = explicitName ?? (isVulnNode ? null : (a.name ?? a.title ?? a.displayName ?? null));
    const version = a.installed_version ?? a.installedVersion ?? a.current_version ?? a.currentVersion ?? (isVulnNode ? null : a.version) ?? null;
    if ((slug && !isVulnNode) || (isVulnNode && slug && typeof slug === 'string' && (explicitName || version)) || (name && version)) {
      return {
        kind,
        slug: String(slug || slugify(name)),
        name: String(name || slug),
        version: version === null || version === undefined ? null : String(version),
        latestVersion: a.latest_version ?? a.latestVersion ?? a.new_version ?? null,
      };
    }
  }
  return { kind, slug: 'unknown', name: 'Unknown', version: null, latestVersion: null };
}

function slugify(text) {
  return String(text || 'unknown').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'unknown';
}

function normalizeVulnerability(raw, component) {
  const refs = raw.references || {};
  const urls = []
    .concat(Array.isArray(refs.url) ? refs.url : [])
    .concat(Array.isArray(raw.references) ? raw.references : [])
    .concat(Array.isArray(refs) ? [] : Object.values(refs).flat().filter((v) => typeof v === 'string' && /^https?:/i.test(v)))
    .filter((u) => typeof u === 'string');
  const cveSources = []
    .concat(Array.isArray(refs.cve) ? refs.cve : [])
    .concat(raw.cve ? [raw.cve] : [])
    .concat(Array.isArray(raw.cves) ? raw.cves : []);
  const cves = new Set(cveSources.map((c) => normalizeCve(c)).filter(Boolean));
  for (const match of JSON.stringify(raw).match(CVE_RE) || []) cves.add(match.toUpperCase());

  const cvss = raw.cvss || raw.CVSS || null;
  const score = cvss && (cvss.score ?? cvss.base_score ?? cvss.baseScore);
  return {
    id: raw.id ?? raw.uuid ?? raw.wpvulndb_id ?? null,
    title: String(raw.title || raw.name || raw.description || 'Vulnerability').trim(),
    description: raw.description && raw.description !== raw.title ? String(raw.description) : null,
    vulnType: raw.vuln_type ?? raw.vulnType ?? raw.type ?? null,
    fixedIn: raw.fixed_in ?? raw.fixedIn ?? null,
    introducedIn: raw.introduced_in ?? raw.introducedIn ?? null,
    publishedDate: raw.published_date ?? raw.publishedDate ?? raw.created_at ?? null,
    cves: [...cves].sort(),
    references: [...new Set(urls)].slice(0, 8),
    score: score !== undefined && score !== null ? Number(score) : null,
    vector: cvss && (cvss.vector ?? cvss.vectorString) ? String(cvss.vector ?? cvss.vectorString) : null,
    severity: cvss && cvss.severity ? String(cvss.severity).toLowerCase() : null,
    component,
  };
}

function normalizeCve(value) {
  if (!value) return null;
  const text = String(value).toUpperCase();
  const match = text.match(/CVE-\d{4}-\d{4,}/);
  if (match) return match[0];
  if (/^\d{4}-\d{4,}$/.test(text)) return `CVE-${text}`;
  return null;
}

// ---------- Grouping across sites ----------

// Group per-site vulnerabilities into findings: one entry per vulnerability,
// listing every site it affects.
function groupFindings(perSite) {
  const byKey = new Map();
  for (const { site, vulns } of perSite) {
    for (const v of vulns) {
      const key = v.cves[0] || (v.id ? `wpscan:${v.id}` : `${v.component.kind}:${v.component.slug}:${slugify(v.title)}`);
      let finding = byKey.get(key);
      if (!finding) {
        finding = {
          key,
          title: v.title,
          description: v.description,
          vulnType: v.vulnType,
          fixedIn: v.fixedIn,
          introducedIn: v.introducedIn,
          publishedDate: v.publishedDate,
          cves: [...v.cves],
          references: [...v.references],
          score: v.score,
          vector: v.vector,
          severity: v.severity,
          component: { kind: v.component.kind, slug: v.component.slug, name: v.component.name },
          sites: [],
          enrichment: null,
        };
        byKey.set(key, finding);
      }
      for (const c of v.cves) if (!finding.cves.includes(c)) finding.cves.push(c);
      for (const r of v.references) if (!finding.references.includes(r)) finding.references.push(r);
      if (!finding.description && v.description) finding.description = v.description;
      if (!finding.fixedIn && v.fixedIn) finding.fixedIn = v.fixedIn;
      if (!finding.sites.some((s) => String(s.siteId) === String(site.id))) {
        finding.sites.push({
          siteId: site.id,
          siteName: site.displayName || site.name,
          url: site.url,
          version: v.component.version,
          fixAvailable: Boolean(v.fixedIn),
        });
      }
    }
  }
  const findings = [...byKey.values()];
  for (const f of findings) {
    f.sites.sort((a, b) => a.siteName.localeCompare(b.siteName));
    f.references = f.references.slice(0, 8);
  }
  return findings;
}

// ---------- CVSS ----------

const AV = { N: 'over the network', A: 'from an adjacent network', L: 'with local access', P: 'with physical access' };
const PR = {
  N: 'no login (unauthenticated)',
  L: 'a logged-in user (subscriber-level or similar)',
  H: 'an administrator-level account',
};
const UI = { N: 'no user interaction', R: 'needs a user to do something (such as open a link)', P: 'needs a user to do something', A: 'needs an active user' };
const AU2 = { N: 'no login (unauthenticated)', S: 'a logged-in account', M: 'more than one account' };

function parseCvssVector(vector) {
  if (!vector || typeof vector !== 'string') return null;
  const parts = Object.fromEntries(
    vector.split('/').map((p) => p.split(':')).filter((kv) => kv.length === 2),
  );
  const version = parts.CVSS || (parts.Au ? '2.0' : null);
  const out = { vector, version };
  if (parts.AV && AV[parts.AV]) out.attackVector = AV[parts.AV];
  if (parts.PR && PR[parts.PR]) out.privilegesRequired = PR[parts.PR];
  else if (parts.Au && AU2[parts.Au]) out.privilegesRequired = AU2[parts.Au];
  if (parts.UI && UI[parts.UI]) out.userInteraction = UI[parts.UI];
  if (parts.AC) out.attackComplexity = parts.AC === 'L' ? 'low' : 'high';
  return out;
}

// One line a person can act on: "Exploitable over the network by any
// logged-in user; needs a user to open a link."
function accessSummary(cvss) {
  if (!cvss) return null;
  const bits = [];
  if (cvss.attackVector) bits.push(`exploitable ${cvss.attackVector}`);
  if (cvss.privilegesRequired) bits.push(`requires ${cvss.privilegesRequired}`);
  if (cvss.userInteraction) bits.push(cvss.userInteraction);
  if (bits.length === 0) return null;
  const text = bits.join('; ');
  return text.charAt(0).toUpperCase() + text.slice(1) + '.';
}

function severityFromScore(score) {
  if (score === null || score === undefined || Number.isNaN(Number(score))) return null;
  const s = Number(score);
  if (s >= 9) return 'critical';
  if (s >= 7) return 'high';
  if (s >= 4) return 'medium';
  if (s > 0) return 'low';
  return 'none';
}

// ---------- CVE enrichment ----------

// cve.org's public record API needs no key. The CNA for most WordPress
// plugin CVEs (Wordfence, Patchstack, WPScan) supplies CVSS, so the vector
// is usually there even when NVD hasn't analysed the CVE yet.
async function fetchCveRecord(cveId, fetchImpl = globalThis.fetch) {
  const res = await fetchImpl(`https://cveawg.mitre.org/api/cve/${encodeURIComponent(cveId)}`, {
    headers: { Accept: 'application/json' },
  });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`cve.org returned HTTP ${res.status}`);
  const json = await res.json();
  return parseCveRecord(json);
}

function parseCveRecord(json) {
  const cna = json && json.containers && json.containers.cna;
  if (!cna) return null;
  const adp = (json.containers.adp || []);
  const metricSets = [].concat(cna.metrics || [], ...adp.map((a) => a.metrics || []));
  let vector = null;
  let score = null;
  let severity = null;
  for (const m of metricSets) {
    const c = m.cvssV4_0 || m.cvssV3_1 || m.cvssV3_0 || m.cvssV2_0;
    if (c && c.vectorString) {
      vector = c.vectorString;
      score = c.baseScore ?? null;
      severity = c.baseSeverity ? String(c.baseSeverity).toLowerCase() : null;
      break;
    }
  }
  const description = (cna.descriptions || []).find((d) => d.lang === 'en' || d.lang === 'en-US');
  const cwes = [];
  for (const pt of cna.problemTypes || []) {
    for (const d of pt.descriptions || []) if (d.cweId) cwes.push(d.cweId);
  }
  return {
    source: 'cve.org',
    cveId: json.cveMetadata && json.cveMetadata.cveId,
    state: json.cveMetadata && json.cveMetadata.state,
    assigner: json.cveMetadata && json.cveMetadata.assignerShortName,
    published: json.cveMetadata && json.cveMetadata.datePublished,
    title: cna.title || null,
    description: description ? description.value : null,
    vector,
    score,
    severity,
    cwes,
    references: (cna.references || []).map((r) => r.url).filter(Boolean).slice(0, 8),
  };
}

// NVD as a fallback when the CVE record carries no CVSS. Unauthenticated
// callers get 5 requests per 30 seconds, so this is used sparingly.
async function fetchNvd(cveId, apiKey, fetchImpl = globalThis.fetch) {
  const headers = { Accept: 'application/json' };
  if (apiKey) headers.apiKey = apiKey;
  const res = await fetchImpl(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cveId)}`, { headers });
  if (!res.ok) throw new Error(`NVD returned HTTP ${res.status}`);
  const json = await res.json();
  const cve = json && json.vulnerabilities && json.vulnerabilities[0] && json.vulnerabilities[0].cve;
  if (!cve) return null;
  const metrics = cve.metrics || {};
  const m = (metrics.cvssMetricV40 || metrics.cvssMetricV31 || metrics.cvssMetricV30 || metrics.cvssMetricV2 || [])[0];
  const description = (cve.descriptions || []).find((d) => d.lang === 'en');
  return {
    source: 'nvd',
    cveId: cve.id,
    description: description ? description.value : null,
    vector: m && m.cvssData ? m.cvssData.vectorString : null,
    score: m && m.cvssData ? m.cvssData.baseScore : null,
    severity: m ? String(m.cvssData.baseSeverity || m.baseSeverity || '').toLowerCase() || null : null,
    cwes: [],
    references: (cve.references || []).map((r) => r.url).slice(0, 8),
  };
}

// Fill in CVSS / description for each finding. `cache` is a plain object the
// caller persists; entries older than `ttlMs` are refreshed.
async function enrichFindings(findings, { cache = {}, ttlMs = 7 * 24 * 3600 * 1000, nvdApiKey = null, fetchImpl, onProgress = () => {}, delayMs = 300 } = {}) {
  const doFetch = fetchImpl || globalThis.fetch;
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const now = Date.now();
  let i = 0;
  for (const finding of findings) {
    i += 1;
    onProgress(i, findings.length, finding);
    const cveId = finding.cves[0];
    if (!cveId) {
      applyEnrichment(finding, null);
      continue;
    }
    let entry = cache[cveId];
    if (!entry || now - entry.fetchedAt > ttlMs) {
      let record = null;
      let error = null;
      try {
        record = await fetchCveRecord(cveId, doFetch);
      } catch (err) {
        error = err.message;
      }
      if (!record || !record.vector) {
        try {
          const nvd = await fetchNvd(cveId, nvdApiKey, doFetch);
          if (nvd && (nvd.vector || !record)) {
            record = record ? { ...record, vector: nvd.vector, score: nvd.score ?? record.score, severity: nvd.severity || record.severity, source: 'cve.org + nvd' } : nvd;
          }
        } catch (err) {
          error = error || err.message;
        }
      }
      entry = { fetchedAt: now, record, error };
      cache[cveId] = entry;
      await sleep(delayMs);
    }
    applyEnrichment(finding, entry.record, entry.error);
  }
  return cache;
}

function applyEnrichment(finding, record, error) {
  const vector = (record && record.vector) || finding.vector || null;
  const cvss = parseCvssVector(vector);
  const score = finding.score ?? (record ? record.score : null);
  const severity = finding.severity || (record && record.severity) || severityFromScore(score) || 'unknown';
  finding.score = score;
  finding.vector = vector;
  finding.severity = severity;
  finding.cvss = cvss;
  finding.access = accessSummary(cvss);
  finding.enrichment = record
    ? { source: record.source, description: record.description, cwes: record.cwes || [], assigner: record.assigner || null, published: record.published || null }
    : (error ? { source: null, error } : null);
  if (!finding.description && record && record.description) finding.description = record.description;
  for (const r of (record && record.references) || []) {
    if (finding.references.length < 8 && !finding.references.includes(r)) finding.references.push(r);
  }
}

// ---------- Ordering & "new" detection ----------

const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3, none: 4, unknown: 5 };

function sortFindings(findings) {
  return [...findings].sort((a, b) => {
    const r = (SEVERITY_RANK[a.severity] ?? 5) - (SEVERITY_RANK[b.severity] ?? 5);
    if (r !== 0) return r;
    return b.sites.length - a.sites.length;
  });
}

// seen: { "<findingKey>|<siteId>": isoDate }. Marks each site on each finding
// as new or previously reported, and returns the keys to persist.
function markNew(findings, seen) {
  const seenMap = seen || {};
  for (const f of findings) {
    let anyNew = false;
    for (const s of f.sites) {
      s.isNew = !(`${f.key}|${s.siteId}` in seenMap);
      if (s.isNew) anyNew = true;
    }
    f.isNew = anyNew;
  }
  return findings;
}

function rememberFindings(findings, seen, when = new Date().toISOString()) {
  const next = { ...(seen || {}) };
  for (const f of findings) for (const s of f.sites) next[`${f.key}|${s.siteId}`] = next[`${f.key}|${s.siteId}`] || when;
  return next;
}

// ---------- Webhook messages ----------

function webhookKind(url) {
  if (!url) return null;
  if (/^https:\/\/(discord\.com|discordapp\.com)\/api\/webhooks\//i.test(url)) return 'discord';
  if (/^https:\/\/hooks\.slack\.com\//i.test(url)) return 'slack';
  return 'generic';
}

const SEVERITY_EMOJI = { critical: '🟥', high: '🟧', medium: '🟨', low: '🟩', none: '⬜', unknown: '⬜' };
const SEVERITY_COLOR = { critical: 0xb0392f, high: 0xd9772c, medium: 0xc9a227, low: 0x2e7d4f, none: 0x8a94a0, unknown: 0x8a94a0 };

function truncate(text, max) {
  const t = String(text).replace(/[ \t]+/g, ' ').replace(/\n{3,}/g, '\n\n').trim();
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}

function headline(findings, { onlyNew }) {
  const sites = new Set();
  for (const f of findings) for (const s of f.sites) sites.add(String(s.siteId));
  return `${findings.length} ${onlyNew ? 'new ' : ''}${findings.length === 1 ? 'vulnerability' : 'vulnerabilities'} across ${sites.size} ${sites.size === 1 ? 'site' : 'sites'} on Pressable`;
}

function severityLabel(f) {
  return `${SEVERITY_EMOJI[f.severity] || '⬜'} ${f.severity && f.severity !== 'unknown' ? f.severity.toUpperCase() : 'SEVERITY UNKNOWN'}${f.score !== null && f.score !== undefined ? ` ${f.score}` : ''}`;
}

function componentLabel(f) {
  return f.component.kind === 'theme' ? 'Theme' : 'Plugin';
}

function fixLabel(f) {
  return f.fixedIn ? `Update to ${f.fixedIn}` : 'No fix released yet';
}

function primaryLink(f) {
  return f.cves[0] ? `https://www.cve.org/CVERecord?id=${f.cves[0]}` : f.references[0] || null;
}

function descriptionOf(f) {
  return (f.enrichment && f.enrichment.description) || f.description || null;
}

// Sites for one message: only the not-yet-reported ones when onlyNew, and
// grouped by installed version so it's obvious which sites share a fix.
function siteGroups(f, { onlyNew }) {
  const sites = onlyNew ? f.sites.filter((s) => s.isNew !== false) : f.sites;
  const groups = new Map();
  for (const s of sites) {
    const version = s.version || 'version unknown';
    if (!groups.has(version)) groups.set(version, []);
    groups.get(version).push(s);
  }
  // Highest-risk first is not knowable; sort by group size, then version.
  return [...groups.entries()]
    .map(([version, list]) => ({ version, sites: list }))
    .sort((a, b) => b.sites.length - a.sites.length || String(a.version).localeCompare(String(b.version)));
}

function siteBullet(s, { onlyNew, bold }) {
  const flag = !onlyNew && s.isNew ? (bold ? ' · **new**' : ' · _new_') : '';
  return `• ${s.siteName}${s.url && s.url !== s.siteName ? ` (${s.url})` : ''}${flag}`;
}

// Split a list of lines into chunks that each fit a character cap.
function chunkLines(lines, cap) {
  const chunks = [];
  let current = '';
  for (const line of lines) {
    if (current && current.length + line.length + 1 > cap) {
      chunks.push(current);
      current = '';
    }
    current = current ? `${current}\n${line}` : line;
  }
  if (current) chunks.push(current);
  return chunks;
}

// ----- Discord: one embed per vulnerability, sites grouped by version -----

function discordEmbed(f, { onlyNew, accountLabel }) {
  const fields = [
    { name: componentLabel(f), value: truncate(f.component.name, 1024), inline: true },
    { name: 'Fix', value: fixLabel(f), inline: true },
  ];
  if (f.cves.length) fields.push({ name: f.cves.length === 1 ? 'CVE' : 'CVEs', value: truncate(f.cves.join(', '), 1024), inline: true });
  if (f.vulnType) fields.push({ name: 'Type', value: truncate(f.vulnType, 1024), inline: true });
  if (f.enrichment && f.enrichment.cwes && f.enrichment.cwes.length) {
    fields.push({ name: 'Weakness', value: truncate(f.enrichment.cwes.join(', '), 1024), inline: true });
  }

  const groups = siteGroups(f, { onlyNew });
  const totalSites = groups.reduce((n, g) => n + g.sites.length, 0);
  for (const g of groups) {
    const lines = g.sites.map((s) => siteBullet(s, { onlyNew, bold: true }));
    const chunks = chunkLines(lines, 1000);
    chunks.forEach((value, i) => {
      if (fields.length >= 24) return; // leave room for references
      const name = `${g.sites.length === totalSites && groups.length === 1 ? 'Sites' : 'Sites'} on ${g.version} (${g.sites.length})${i > 0 ? ' (cont.)' : ''}`;
      fields.push({ name, value, inline: false });
    });
  }

  const refs = f.references.filter((r) => r !== primaryLink(f)).slice(0, 3);
  if (refs.length && fields.length < 25) fields.push({ name: 'References', value: truncate(refs.join('\n'), 1024), inline: false });

  const descriptionParts = [];
  if (f.access) descriptionParts.push(`**${f.access}**`);
  const desc = descriptionOf(f);
  if (desc) descriptionParts.push(truncate(desc, 700));

  const embed = {
    title: truncate(`${severityLabel(f)} · ${f.title}`, 256),
    description: descriptionParts.join('\n\n') || undefined,
    color: SEVERITY_COLOR[f.severity] || SEVERITY_COLOR.unknown,
    fields,
    footer: { text: truncate(`Wayzgoose for Pressable${accountLabel ? ` · ${accountLabel}` : ''} · ${totalSites} ${totalSites === 1 ? 'site' : 'sites'} affected`, 2048) },
    timestamp: new Date().toISOString(),
  };
  const url = primaryLink(f);
  if (url) embed.url = url;
  return embed;
}

// ----- Slack: one message per vulnerability, sites grouped by version -----

function slackBlocks(f, { onlyNew, accountLabel }) {
  const blocks = [
    { type: 'header', text: { type: 'plain_text', text: truncate(`${severityLabel(f)} · ${f.title}`, 150) } },
  ];
  const metaBits = [
    `*${componentLabel(f)}:* ${f.component.name}`,
    `*Fix:* ${fixLabel(f)}`,
  ];
  if (f.cves.length) metaBits.push(`*${f.cves.length === 1 ? 'CVE' : 'CVEs'}:* ${f.cves.map((c) => `<https://www.cve.org/CVERecord?id=${c}|${c}>`).join(', ')}`);
  if (f.vulnType) metaBits.push(`*Type:* ${f.vulnType}`);
  blocks.push({ type: 'section', text: { type: 'mrkdwn', text: truncate(metaBits.join(' · '), 2900) } });

  const descParts = [];
  if (f.access) descParts.push(`*${f.access}*`);
  const desc = descriptionOf(f);
  if (desc) descParts.push(truncate(desc, 700));
  if (descParts.length) blocks.push({ type: 'section', text: { type: 'mrkdwn', text: truncate(descParts.join('\n\n'), 2900) } });

  const groups = siteGroups(f, { onlyNew });
  for (const g of groups) {
    const lines = g.sites.map((s) => siteBullet(s, { onlyNew, bold: false }));
    const chunks = chunkLines(lines, 2800);
    chunks.forEach((value, i) => {
      if (blocks.length >= 46) return;
      blocks.push({ type: 'section', text: { type: 'mrkdwn', text: `*Sites on ${g.version} (${g.sites.length})${i > 0 ? ' (cont.)' : ''}*\n${value}` } });
    });
  }

  const refs = f.references.filter((r) => r !== primaryLink(f)).slice(0, 3);
  const footer = [`Wayzgoose for Pressable${accountLabel ? ` · ${accountLabel}` : ''}`, new Date().toLocaleString()];
  if (refs.length) footer.push(refs.map((r) => `<${r}|reference>`).join(' · '));
  blocks.push({ type: 'context', elements: [{ type: 'mrkdwn', text: truncate(footer.join(' · '), 2000) }] });
  return blocks;
}

// Build the request bodies for the webhook: one message per vulnerability,
// preceded by a one-line summary when there is more than one. Sites inside
// each message are grouped by installed version.
function buildWebhookPayloads(kind, findings, { onlyNew = false, accountLabel = null } = {}) {
  const sorted = sortFindings(findings);
  if (sorted.length === 0) return [];
  const title = headline(sorted, { onlyNew });
  const sub = accountLabel ? `${accountLabel} · ${new Date().toLocaleString()}` : new Date().toLocaleString();
  const payloads = [];

  if (kind === 'discord') {
    if (sorted.length > 1) payloads.push({ content: `**${title}**\n${sub}` });
    for (const f of sorted) payloads.push({ embeds: [discordEmbed(f, { onlyNew, accountLabel })] });
    return payloads;
  }

  if (kind === 'slack') {
    if (sorted.length > 1) {
      payloads.push({
        text: title,
        blocks: [
          { type: 'header', text: { type: 'plain_text', text: truncate(title, 150) } },
          { type: 'context', elements: [{ type: 'mrkdwn', text: sub }] },
        ],
      });
    }
    for (const f of sorted) {
      payloads.push({ text: truncate(`${severityLabel(f)} · ${f.title} · ${fixLabel(f)}`, 300), blocks: slackBlocks(f, { onlyNew, accountLabel }) });
    }
    return payloads;
  }

  // Generic JSON (Zapier, n8n, your own endpoint): one call per vulnerability.
  sorted.forEach((f, i) => {
    payloads.push({
      text: `${title}: ${f.title}`,
      generatedAt: new Date().toISOString(),
      onlyNew,
      batch: { index: i + 1, total: sorted.length, summary: title },
      finding: {
        key: f.key,
        title: f.title,
        severity: f.severity,
        score: f.score,
        vector: f.vector,
        access: f.access,
        cves: f.cves,
        component: f.component,
        fixedIn: f.fixedIn,
        vulnType: f.vulnType,
        description: descriptionOf(f),
        references: f.references,
        siteGroups: siteGroups(f, { onlyNew }).map((g) => ({ version: g.version, sites: g.sites })),
      },
    });
  });
  return payloads;
}

async function sendWebhook(url, payloads, fetchImpl = globalThis.fetch) {
  let sent = 0;
  for (const body of payloads) {
    const res = await fetchImpl(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      throw new Error(`Webhook returned HTTP ${res.status}${text ? `: ${truncate(text, 200)}` : ''}`);
    }
    sent += 1;
    // Discord allows 5 requests per 2 s per webhook, Slack about 1 per s.
    if (payloads.length > 1) await new Promise((r) => setTimeout(r, 1200));
  }
  return sent;
}

function testPayload(kind) {
  const text = 'Wayzgoose for Pressable can reach this channel. Vulnerability alerts will arrive here.';
  if (kind === 'discord') return [{ content: text }];
  if (kind === 'slack') return [{ text }];
  return [{ text, test: true }];
}

module.exports = {
  extractVulnerabilities,
  normalizeVulnerability,
  groupFindings,
  parseCvssVector,
  accessSummary,
  severityFromScore,
  parseCveRecord,
  fetchCveRecord,
  fetchNvd,
  enrichFindings,
  sortFindings,
  markNew,
  rememberFindings,
  webhookKind,
  buildWebhookPayloads,
  sendWebhook,
  testPayload,
};
