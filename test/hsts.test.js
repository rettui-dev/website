// Strict-Transport-Security: sent on answers to requests that came over https (a trusted proxy that
// says so in X-Forwarded-Proto; a TLS connection is checked in login.test.js, viaHttps), never on
// plain http, and never because someone else's X-Forwarded-Proto claims https.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Monitor } from '../lib/monitor.js';
import { loadConfig } from '../lib/config.js';
import { HSTS, createApp } from '../lib/app.js';
import { createLogin } from '../lib/login.js';

const publicDir = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'public');

// An app whose trusted proxies are `trusted` (the test connects from 127.0.0.1), with no users.
async function setup(trusted, { login = true } = {}) {
  // Users made on the website are what allow the login settings without users in the file.
  const config = loadConfig(`login:\n  trusted_proxies: ${JSON.stringify(trusted)}\nnodes:\n  - address: a.test:1\n`, { storeUsers: true });
  const monitor = new Monitor({ targets: config.targets, dataDir: await fs.mkdtemp(path.join(os.tmpdir(), 'hsts-')), probeFn: async () => ({ up: true, ms: 1 }) });
  const server = createApp({ monitor, publicDir, login: login ? createLogin({ users: [], settings: config.login }) : null });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return { port: server.address().port, close: () => (server.closeAllConnections(), new Promise((r) => server.close(r))) };
}

function request(port, { method = 'GET', path: p, headers = {} }) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path: p, method, headers }, (res) => {
      res.resume();
      res.on('end', () => resolve({ status: res.statusCode, hsts: res.headers['strict-transport-security'] }));
    });
    req.on('error', reject);
    req.end();
  });
}

// Pages, files, the APIs, a 404, a 405 and the health check: every kind of answer.
const PATHS = [['GET', '/'], ['GET', '/status'], ['GET', '/site.css'], ['GET', '/api/status'], ['GET', '/healthz'], ['GET', '/nope.html'], ['DELETE', '/'], ['POST', '/login']];

test('HSTS is sent on every answer to a request a trusted proxy says came over https', async () => {
  const s = await setup(['127.0.0.1']);
  try {
    for (const [method, p] of PATHS) {
      const r = await request(s.port, { method, path: p, headers: { 'X-Forwarded-Proto': 'https', 'X-Forwarded-For': '203.0.113.7' } });
      assert.equal(r.hsts, HSTS, `${method} ${p} (${r.status})`);
    }
    assert.equal(HSTS, 'max-age=31536000; includeSubDomains');
  } finally {
    await s.close();
  }
});

test('HSTS is never sent over plain http, whatever an untrusted peer claims', async () => {
  const trusted = await setup(['127.0.0.1']);
  const untrusted = await setup(['10.0.0.1']);
  const none = await setup([], { login: false });
  try {
    for (const [method, p] of PATHS) {
      // From the trusted proxy, but over http, or saying nothing.
      assert.equal((await request(trusted.port, { method, path: p, headers: { 'X-Forwarded-Proto': 'http' } })).hsts, undefined, `${method} ${p} http`);
      assert.equal((await request(trusted.port, { method, path: p })).hsts, undefined, `${method} ${p} no header`);
      // Someone who is not a trusted proxy cannot ask for it.
      assert.equal((await request(untrusted.port, { method, path: p, headers: { 'X-Forwarded-Proto': 'https' } })).hsts, undefined, `${method} ${p} untrusted`);
      assert.equal((await request(none.port, { method, path: p, headers: { 'X-Forwarded-Proto': 'https' } })).hsts, undefined, `${method} ${p} no login`);
    }
  } finally {
    await Promise.all([trusted.close(), untrusted.close(), none.close()]);
  }
});
