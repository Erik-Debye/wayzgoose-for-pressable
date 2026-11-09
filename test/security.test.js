'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const sec = require('../src/security');
const { jsonResponse } = require('./helpers');

const pluginsResponse = [
  {
    slug: 'redirection', name: 'Redirection', version: '3.6.2',
    vulnerabilities: [{
      id: 'abc-123', title: 'Redirection < 3.6.3 - XSS', vuln_type: 'XSS', fixed_in: '3.6.3',
      references: { url: ['https://wpscan.com/vulnerability/9014'], cve: ['2018-6710'], wpvulndb: ['9014'] },
    }],
  },
  {
    slug: 'wordfence', name: 'Wordfence Security', version: '7.1.12',
    vulnerabilities: [{ id: 'def-456', title: 'Wordfence < 7.1.14 - Banned IP Bypass', fixed_in: '7.1.14', references: { url: [] } }],
  },
];

test('extracts WPScan-shaped vulnerabilities with their plugin', () => {
  const vulns = sec.extractVulnerabilities(pluginsResponse, 'plugin');
  assert.equal(vulns.length, 2);
  assert.equal(vulns[0].component.name, 'Redirection');
  assert.equal(vulns[0].component.version, '3.6.2');
  assert.deepEqual(vulns[0].cves, ['CVE-2018-6710']);
  assert.equal(vulns[1].fixedIn, '7.1.14');
});

test('handles flat records that carry plugin fields on the vulnerability itself', () => {
  const flat = { data: [{ pluginName: 'Redirection', installedVersion: '3.6.2', slug: 'redirection', title: 'Redirection < 3.6.3 - XSS', fixedIn: '3.6.3', references: ['CVE-2018-6710'] }] };
  const [v] = sec.extractVulnerabilities(flat, 'plugin');
  assert.equal(v.component.name, 'Redirection');
  assert.equal(v.component.version, '3.6.2');
  assert.deepEqual(v.cves, ['CVE-2018-6710']);
});

test('groups the same vulnerability across sites', () => {
  const vulns = sec.extractVulnerabilities(pluginsResponse, 'plugin');
  const findings = sec.groupFindings([
    { site: { id: 1, displayName: 'Acme', url: 'acme.com' }, vulns },
    { site: { id: 3, displayName: 'Blue', url: 'blue.com' }, vulns: vulns.slice(0, 1) },
  ]);
  assert.equal(findings.length, 2);
  const xss = findings.find((f) => f.key === 'CVE-2018-6710');
  assert.deepEqual(xss.sites.map((s) => s.siteName), ['Acme', 'Blue']);
});

test('turns CVSS vectors into plain language', () => {
  assert.equal(
    sec.accessSummary(sec.parseCvssVector('CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N')),
    'Exploitable over the network; requires a logged-in user (subscriber-level or similar); no user interaction.',
  );
  assert.equal(sec.parseCvssVector('AV:N/AC:L/Au:S/C:P/I:P/A:P').privilegesRequired, 'a logged-in account');
  assert.match(sec.accessSummary(sec.parseCvssVector('CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N')), /administrator-level/);
});

test('enriches from cve.org and falls back gracefully', async () => {
  const vulns = sec.extractVulnerabilities(pluginsResponse, 'plugin');
  const findings = sec.groupFindings([{ site: { id: 1, displayName: 'Acme' }, vulns }]);
  const fetchImpl = async (url) => {
    if (String(url).includes('cveawg') && String(url).includes('CVE-2018-6710')) {
      return jsonResponse(200, {
        cveMetadata: { cveId: 'CVE-2018-6710', assignerShortName: 'mitre' },
        containers: { cna: {
          descriptions: [{ lang: 'en', value: 'XSS in Redirection before 3.6.3.' }],
          metrics: [{ cvssV3_1: { baseScore: 6.1, baseSeverity: 'MEDIUM', vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N' } }],
        } },
      });
    }
    return jsonResponse(404, {});
  };
  const cache = {};
  await sec.enrichFindings(findings, { cache, fetchImpl, delayMs: 0 });
  const xss = findings.find((f) => f.key === 'CVE-2018-6710');
  assert.equal(xss.severity, 'medium');
  assert.equal(xss.score, 6.1);
  assert.match(xss.access, /no login/);
  assert.equal(xss.enrichment.source, 'cve.org');
  assert.deepEqual(Object.keys(cache), ['CVE-2018-6710']);
  const other = findings.find((f) => f.key !== 'CVE-2018-6710');
  assert.equal(other.severity, 'unknown');
});

test('tracks new findings per site', () => {
  const vulns = sec.extractVulnerabilities(pluginsResponse, 'plugin');
  const findings = sec.groupFindings([
    { site: { id: 1, displayName: 'Acme' }, vulns: vulns.slice(0, 1) },
    { site: { id: 3, displayName: 'Blue' }, vulns: vulns.slice(0, 1) },
  ]);
  sec.markNew(findings, { 'CVE-2018-6710|1': '2026-11-01T00:00:00Z' });
  assert.equal(findings[0].isNew, true);
  assert.deepEqual(findings[0].sites.map((s) => s.isNew), [false, true]);
  const seen = sec.rememberFindings(findings, {});
  assert.deepEqual(Object.keys(seen).sort(), ['CVE-2018-6710|1', 'CVE-2018-6710|3']);
});

test('builds one message per vulnerability with sites grouped by version', () => {
  const finding = {
    key: 'CVE-2026-1101', title: 'Redirection < 3.6.3 - XSS', severity: 'high', score: 7.1,
    access: 'Exploitable over the network; requires no login (unauthenticated); no user interaction.',
    cves: ['CVE-2026-1101'], vulnType: 'XSS', fixedIn: '3.6.3',
    component: { kind: 'plugin', slug: 'redirection', name: 'Redirection' },
    description: null, enrichment: { description: 'Reflected XSS.', cwes: ['CWE-79'] }, references: ['https://wpscan.com/vulnerability/9014'],
    sites: [
      { siteId: 1, siteName: 'Acme', url: 'acme.com', version: '3.6.2', isNew: true },
      { siteId: 3, siteName: 'Blue', url: 'blue.com', version: '3.6.2', isNew: true },
      { siteId: 4, siteName: 'Harbor', url: 'harbor.com', version: '3.5.0', isNew: false },
    ],
    isNew: true,
  };
  const second = { ...finding, key: 'wpscan:x', cves: [], severity: 'unknown', score: null, access: null, title: 'Other' };

  const discord = sec.buildWebhookPayloads('discord', [finding, second], { onlyNew: false, accountLabel: 'Jane' });
  assert.equal(discord.length, 3, 'summary + one per finding');
  assert.match(discord[0].content, /2 vulnerabilities across 3 sites/);
  const embed = discord[1].embeds[0];
  assert.equal(embed.url, 'https://www.cve.org/CVERecord?id=CVE-2026-1101');
  const groups = embed.fields.filter((f) => f.name.startsWith('Sites on'));
  assert.deepEqual(groups.map((g) => g.name), ['Sites on 3.6.2 (2)', 'Sites on 3.5.0 (1)']);

  const onlyNew = sec.buildWebhookPayloads('discord', [finding], { onlyNew: true });
  assert.equal(onlyNew.length, 1, 'no summary for a single finding');
  assert.deepEqual(onlyNew[0].embeds[0].fields.filter((f) => f.name.startsWith('Sites on')).map((g) => g.name), ['Sites on 3.6.2 (2)']);

  const slack = sec.buildWebhookPayloads('slack', [finding], { onlyNew: false });
  assert.equal(slack[0].blocks[0].type, 'header');
  assert.match(slack[0].blocks[0].text.text, /HIGH 7\.1/);

  assert.equal(sec.webhookKind('https://discord.com/api/webhooks/1/a'), 'discord');
  assert.equal(sec.webhookKind('https://hooks.slack.com/services/T/B/X'), 'slack');
  assert.equal(sec.webhookKind('https://hooks.zapier.com/x'), 'generic');
});
