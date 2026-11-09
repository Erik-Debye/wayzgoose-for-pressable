'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { PressableClient, normalizeBackup, isFinalState } = require('../src/pressable');
const { jsonResponse } = require('./helpers');

function fakeApi() {
  const state = { tokenCalls: 0, rateLimited: true, calls: [] };
  const fetchImpl = async (url, opts = {}) => {
    const u = String(url);
    state.calls.push(`${opts.method || 'GET'} ${u}`);
    if (u.endsWith('/auth/token')) {
      state.tokenCalls += 1;
      const params = new URLSearchParams(opts.body);
      assert.equal(params.get('grant_type'), 'client_credentials');
      return jsonResponse(200, { access_token: `tok${state.tokenCalls}`, expires_in: 3599, name: 'Jane', email: 'j@x.com', scopes: ['authorized'] });
    }
    if (opts.headers.Authorization !== `Bearer tok${state.tokenCalls}`) return jsonResponse(401, { message: 'unauthorized' });
    if (u.includes('/v1/sites?')) {
      const page = Number(new URL(u).searchParams.get('page'));
      if (state.rateLimited && page === 1) {
        state.rateLimited = false;
        return jsonResponse(429, { message: 'slow down' }, { 'Retry-After': '0' });
      }
      return jsonResponse(200, {
        data: page === 1 ? [{ id: 1 }, { id: 2 }] : [{ id: 3 }],
        page: { currentPage: page, nextPage: page === 1 ? 2 : null },
      });
    }
    if (u.endsWith('/v1/sites/1/ondemand-backups') && opts.method === 'POST') {
      assert.deepEqual(JSON.parse(opts.body), { backup_type: 'fs' });
      return jsonResponse(201, { data: { id: 77, backup_type: 'fs', state: 'pending' } });
    }
    if (u.endsWith('/v1/sites/1/ondemand-backups')) {
      return jsonResponse(400, { message: 'Bad Request', errors: ['You have reached the maximum number of backups'] });
    }
    return jsonResponse(404, { message: 'nope' });
  };
  return { state, fetchImpl };
}

test('paginates sites and retries once on 429', async () => {
  const { state, fetchImpl } = fakeApi();
  const client = new PressableClient({ clientId: 'id', clientSecret: 'sec', fetchImpl });
  const sites = await client.listAllSites();
  assert.deepEqual(sites.map((s) => s.id), [1, 2, 3]);
  assert.equal(state.tokenCalls, 1);
});

test('creates a backup with the documented body and normalizes the result', async () => {
  const { fetchImpl } = fakeApi();
  const client = new PressableClient({ clientId: 'id', clientSecret: 'sec', fetchImpl });
  const backup = normalizeBackup(await client.createOndemandBackup(1, 'fs'));
  assert.equal(backup.id, 77);
  assert.equal(backup.type, 'fs');
  assert.equal(isFinalState(backup.state), false);
});

test('surfaces the API error text', async () => {
  const { fetchImpl } = fakeApi();
  const client = new PressableClient({ clientId: 'id', clientSecret: 'sec', fetchImpl });
  await assert.rejects(() => client.listOndemandBackups(1), (err) => {
    assert.equal(err.name, 'PressableError');
    assert.equal(err.status, 400);
    assert.match(err.message, /maximum number of backups/);
    return true;
  });
});

test('refreshes the token when it is about to expire', async () => {
  const { state, fetchImpl } = fakeApi();
  const client = new PressableClient({ clientId: 'id', clientSecret: 'sec', fetchImpl });
  await client.listAllSites();
  client.token.expiresAt = Date.now() + 10_000; // inside the 60 s refresh margin
  await client.listAllSites();
  assert.equal(state.tokenCalls, 2);
});
