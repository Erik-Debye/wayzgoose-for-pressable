'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const cc = require('../src/config-check');

function page({ canonical, robots, generator = 'WordPress 6.7', api } = {}) {
  return `<!DOCTYPE html><html><head><title>Acme Dental</title>
${canonical ? `<link rel="canonical" href="${canonical}" />` : ''}
${robots ? `<meta name='robots' content='${robots}' />` : ''}
<meta name="generator" content="${generator}" />
${api ? `<link rel='https://api.w.org/' href='${api}' />` : ''}
</head><body>hi</body></html>`;
}

function fakeFetch(map) {
  return async (url) => {
    const entry = map[String(url)] || map['*'];
    if (!entry) throw new Error('unexpected ' + url);
    if (entry.throw) throw entry.throw;
    const headers = new Map(Object.entries(entry.headers || {}));
    return { status: entry.status ?? 200, url: entry.finalUrl || String(url), text: async () => entry.body || '', headers: { forEach: (fn) => headers.forEach((v, k) => fn(v, k)), get: (k) => headers.get(k) ?? null } };
  };
}

test('a healthy production site produces no findings', async () => {
  const fetchImpl = fakeFetch({
    'https://acmedental.com/': { body: page({ canonical: 'https://www.acmedental.com/', api: 'https://www.acmedental.com/wp-json/' }), finalUrl: 'https://www.acmedental.com/' },
    'https://www.acmedental.com/wp-json/': { body: JSON.stringify({ name: 'Acme', url: 'https://www.acmedental.com', home: 'https://www.acmedental.com' }) },
    'https://acmedental.com/robots.txt': { body: 'User-agent: *\nDisallow: /wp-admin/\n' },
  });
  const { facts, findings } = await cc.inspectSite({ url: 'acmedental.com', staging: false }, { fetchImpl });
  assert.deepEqual(findings, []);
  assert.equal(cc.worst(findings), 'ok');
  assert.equal(facts.homepage.generator, 'WordPress 6.7');
  assert.equal(facts.rest.home, 'https://www.acmedental.com');
});

test('a production site carrying staging configuration is flagged loudly', async () => {
  const fetchImpl = fakeFetch({
    'https://acmedental.com/': { body: page({ canonical: 'https://acme-dental.mystagingwebsite.com/', robots: 'noindex, nofollow', api: 'https://acme-dental.mystagingwebsite.com/wp-json/' }), finalUrl: 'https://acme-dental.mystagingwebsite.com/' },
    'https://acme-dental.mystagingwebsite.com/wp-json/': { body: JSON.stringify({ url: 'https://acme-dental.mystagingwebsite.com', home: 'https://acme-dental.mystagingwebsite.com' }) },
    'https://acmedental.com/robots.txt': { body: 'User-agent: *\nDisallow: /\n' },
  });
  const { findings } = await cc.inspectSite({ url: 'acmedental.com', staging: false }, { fetchImpl });
  const codes = findings.map((f) => f.code);
  assert.ok(codes.includes('staging-address-on-production'));
  assert.ok(codes.includes('redirects-elsewhere'));
  assert.ok(codes.includes('home-mismatch'));
  assert.ok(codes.includes('noindex'));
  assert.ok(codes.includes('robots-disallow-all'));
  assert.equal(cc.worst(findings), 'high');
  assert.match(findings.find((f) => f.code === 'noindex').message, /pushed from staging/);
});

test('noindex on staging is informational; staging pointing at production is a check', async () => {
  const fetchImpl = fakeFetch({
    'https://acme-dental.mystagingwebsite.com/': { body: page({ robots: 'noindex' }) },
    'https://acme-dental.mystagingwebsite.com/wp-json/': { body: JSON.stringify({ url: 'https://acmedental.com', home: 'https://acmedental.com' }) },
    'https://acme-dental.mystagingwebsite.com/robots.txt': { status: 404 },
  });
  const { findings } = await cc.inspectSite({ url: 'acme-dental.mystagingwebsite.com', staging: true }, { fetchImpl });
  assert.equal(findings.find((f) => f.code === 'noindex').severity, 'info');
  assert.equal(findings.find((f) => f.code === 'production-address-on-staging').severity, 'medium');
  assert.equal(cc.worst(findings), 'medium');
});

test('unreachable sites and missing REST index are reported, http home is flagged', async () => {
  const down = await cc.inspectSite({ url: 'gone.example' }, { fetchImpl: fakeFetch({ '*': { throw: Object.assign(new Error('fetch failed'), { cause: { code: 'ENOTFOUND' } }) } }) });
  assert.equal(down.findings[0].code, 'unreachable');

  const fetchImpl = fakeFetch({
    'https://acmedental.com/': { body: page({ api: 'https://acmedental.com/wp-json/' }) },
    'https://acmedental.com/wp-json/': { status: 403, body: 'forbidden' },
    'https://acmedental.com/robots.txt': { status: 404 },
  });
  const r = await cc.inspectSite({ url: 'acmedental.com' }, { fetchImpl });
  assert.equal(r.findings.find((f) => f.code === 'rest-unavailable').severity, 'info');

  const insecure = fakeFetch({
    'https://acmedental.com/': { body: page({ api: 'https://acmedental.com/wp-json/' }) },
    'https://acmedental.com/wp-json/': { body: JSON.stringify({ url: 'http://acmedental.com', home: 'http://acmedental.com' }) },
    'https://acmedental.com/robots.txt': { status: 404 },
  });
  const i = await cc.inspectSite({ url: 'acmedental.com' }, { fetchImpl: insecure });
  assert.ok(i.findings.some((f) => f.code === 'insecure-url'));
});

test('helpers', () => {
  assert.equal(cc.bareHost('https://www.Acme.com/x'), 'acme.com');
  assert.equal(cc.siteBase({ url: 'acme.com/' }), 'https://acme.com');
  assert.equal(cc.parseRobotsTxt('User-agent: Googlebot\nDisallow: /\nUser-agent: *\nDisallow: /wp-admin/'), false);
  assert.equal(cc.parseRobotsTxt('# all\nUser-agent: *\nDisallow: /'), true);
  const fs = require('node:fs');
  const php = fs.readFileSync(require('node:path').join(__dirname, '..', 'scripts', 'config-report.php'), 'utf8');
  assert.ok(!php.includes("'"), 'config-report.php has no single quotes');
  const users = require('../src/users');
  const cmd = users.buildEvalCommand(php, { webhook: 'https://discord.com/api/webhooks/1/a', pressableUrl: 'acme.com', staging: false, site: 'acme.com' });
  assert.match(cmd, /^eval '\$args = array\("[A-Za-z0-9+/=]+"\); \$cfg = json_decode/);
  assert.match(cmd, /DISALLOW_FILE_MODS/);
});
