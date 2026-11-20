import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Monitor } from '../lib/monitor.js';
import { loadConfig } from '../lib/config.js';
import { createApp, LOGIN_FAILED } from '../lib/app.js';
import { COOKIE, createLogin, hashGate } from '../lib/login.js';
import { hashPassword } from '../lib/password.js';
import { fakeHasher } from './helpers/fake-hasher.js';

const publicDir = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'public');
const MIN = 60_000;
const NOW = 1_800_000_000_000;
const PASSWORD = 'correct horse battery';

const statsData = () => ({
  rettuiVersion: '9.8.7', generatedAt: 1, uptimeSeconds: 100,
  interfaces: { total: 1, online: 1, clients: 4, rxBytes: 1, txBytes: 1 },
  peersHeard: { total: 3, lxmf: 2, nomad: 1, propagation: 0 }, announcesLastMinute: 0,
  disk: { dataBytes: 123_456, fsTotalBytes: 1000, fsFreeBytes: 80 },
  propagation: {
    enabled: true, storedMessages: 4242, storedBytes: 4343, storageLimitBytes: null, peersConnected: null, peersTotal: 4444, peersAlive: 4545, peersStatic: null,
    peersAuto: null, peerLimit: null, staticPeers: null, autopeerDepth: null, messagesReceived: null, messagesServed: null, messagesSentToPeers: 4646,
    messagesReceivedFromPeers: 4747, messagesOfferedToPeers: null, unhandledMessages: 4848, autopeer: null,
  },
});

// Numbers that only a logged-in visitor may see, as they appear in JSON.
const SECRET = ['4242', '4343', '4444', '4545', '4646', '4747', '4848', '9.8.7', '"disk":{', 'peerSummary', 'usedPercent', 'level'];

async function setup({ top = '', nodeA = '', users = true, gate, warn } = {}) {
  const hash = await hashPassword(PASSWORD, undefined, fakeHasher);
  const config = loadConfig(`${users ? `users:\n  - name: Alice\n    password_hash: '${hash}'\n` : ''}${top}
nodes:
  - address: p.test:1
    stats_url: https://p.test/s
    proxy_for: [a.test:1, b.test:1]
  - address: a.test:1
    stats_url: https://a.test/s
${nodeA}
  - address: b.test:1
    stats_url: https://b.test/s
`);
  let clock = NOW - 30 * MIN;
  const monitor = new Monitor({
    targets: config.targets, nodes: config.nodes, statsUrls: config.statsUrls, dataDir: await fs.mkdtemp(path.join(os.tmpdir(), 'website-')),
    publicDetails: config.defaults.publicDetails, publicDiskFigures: config.defaults.publicDiskFigures, requireLogin: config.defaults.requireLogin,
    tokens: new Map([['a.test:1', 't'.repeat(20)]]),
    probeFn: async () => ({ up: true, ms: 1 }),
    statsFn: async () => ({ ok: true, data: statsData(), propagationPeers: { listed: 3, alive: 2, static: 0, unhandled: 0, truncated: false } }),
    now: () => clock,
    sampleIntervalMs: 1000,
  });
  for (let i = 0; i < 4; i++) {
    await monitor.checkAll();
    clock += 5 * MIN;
  }
  clock -= 5 * MIN;
  const login = createLogin({ users: config.users, settings: config.login, hasher: fakeHasher, ...(gate ? { gate } : {}) });
  const server = createApp({ monitor, publicDir, login, ...(warn ? { warn } : {}) });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  return { monitor, login, port, base: `http://127.0.0.1:${port}`, close: () => (server.closeAllConnections(), new Promise((r) => server.close(r))) };
}

// A raw request, so that Origin, Sec-Fetch-Site and Cookie are exactly what the test says.
function request(port, { method = 'GET', path: p, headers = {}, body }) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path: p, method, headers }, (res) => {
      let text = '';
      res.on('data', (c) => (text += c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text, json: () => JSON.parse(text) }));
    });
    req.on('error', reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}

const FORM = { 'Content-Type': 'application/x-www-form-urlencoded', 'Sec-Fetch-Site': 'same-origin', 'X-Rettui-Request': '1' };
const form = (o) => new URLSearchParams(o).toString();
const post = (s, p, body, headers = FORM) => request(s.port, { method: 'POST', path: p, headers, body });
const get = (s, p, cookie) => request(s.port, { path: p, headers: cookie ? { Cookie: cookie } : {} });

async function logIn(s, name = 'alice', password = PASSWORD, extra = {}) {
  const r = await post(s, '/login', form({ name, password }), { ...FORM, ...extra });
  const set = r.headers['set-cookie']?.[0] ?? '';
  return { r, set, cookie: set.split(';')[0] };
}

test('without users the API is exactly as before: no login, no viewer, no locks', async () => {
  const s = await setup({ users: false });
  try {
    const r = await get(s, '/api/status');
    assert.equal(r.headers['cache-control'], 'no-store');
    assert.equal(r.headers.vary, undefined);
    const body = r.json();
    assert.equal('viewer' in body, false);
    assert.equal('locked' in body.hosts[1], false);
    assert.equal(body.hosts[1].stats.data.propagation.storedMessages, 4242);
    assert.equal(body.hosts[1].stats.data.rettuiVersion, '9.8.7');
    const d = await get(s, '/api/stats?host=a.test:1&range=6h');
    assert.equal(d.status, 200);
    assert.equal('locked' in d.json(), false);
    assert.equal(d.json().version.current, '9.8.7');
    const p = await post(s, '/login', form({ name: 'alice', password: PASSWORD }));
    assert.equal(p.status, 405);
    // The sign in button of every page asks this: with no users it stays hidden.
    const session = await get(s, '/api/session');
    assert.equal(session.status, 200);
    assert.deepEqual(session.json(), { enabled: false, name: null });
    assert.equal(session.headers['cache-control'], 'no-store');
  } finally {
    await s.close();
  }
});

test('/api/session says whether there are users and who is signed in, and is never cached or shared', async () => {
  const s = await setup();
  try {
    const anon = await get(s, '/api/session');
    assert.equal(anon.status, 200);
    assert.deepEqual(anon.json(), { enabled: true, name: null });
    assert.equal(anon.headers['cache-control'], 'private, no-store');
    assert.equal(anon.headers.vary, 'Cookie');
    const { cookie } = await logIn(s);
    assert.deepEqual((await get(s, '/api/session', cookie)).json(), { enabled: true, name: 'Alice' });
    // A made-up or ended session is the same as none.
    assert.deepEqual((await get(s, `/api/session`, `${COOKIE}=${'a'.repeat(43)}`)).json(), { enabled: true, name: null });
    await post(s, '/logout', '', { ...FORM, Cookie: cookie });
    assert.deepEqual((await get(s, '/api/session', cookie)).json(), { enabled: true, name: null });
    assert.equal((await request(s.port, { method: 'POST', path: '/api/session', headers: FORM, body: '' })).status, 405);
  } finally {
    await s.close();
  }
});

test('by default a visitor without a login sees no locked number anywhere', async () => {
  const s = await setup();
  try {
    const r = await get(s, '/api/status');
    assert.equal(r.status, 200);
    assert.equal(r.headers['cache-control'], 'private, no-store');
    assert.equal(r.headers.vary, 'Cookie');
    for (const x of SECRET) assert.equal(r.text.includes(x), false, x);
    const body = r.json();
    assert.deepEqual(body.viewer, { name: null });
    assert.deepEqual(body.hosts.map((h) => h.locked), [['details', 'storage', 'peers', 'disk', 'versions'], ['details', 'storage', 'peers', 'disk', 'versions'], ['details', 'storage', 'peers', 'disk', 'versions']]);
    // What stays public: up or down, uptime, clients and peers heard, for nodes and the group.
    const a = body.hosts[1];
    assert.equal(a.status, 'up');
    assert.equal(a.uptimePercent, 100);
    assert.equal(a.stats.data.interfaces.clients, 4);
    assert.equal(a.stats.data.peersHeard.total, 3);
    assert.equal(a.hasDetail, true);
    const g = body.hosts[0].group;
    assert.equal(g.data.interfaces.clients, 8);
    assert.equal(g.data.disk, null);
    assert.equal(g.data.propagation, null);
    // The details answer 401, for one node and for the combined view.
    for (const p of ['/api/stats?host=a.test:1&range=6h', '/api/stats?host=p.test:1&range=7d&view=combined', '/api/stats?host=p.test:1&range=6h']) {
      const d = await get(s, p);
      assert.equal(d.status, 401, p);
      assert.deepEqual(d.json(), { error: 'log in to see the details' });
      assert.equal(d.headers['cache-control'], 'private, no-store');
      for (const x of SECRET) assert.equal(d.text.includes(x), false, x);
    }
    // Unknown hosts and bad ranges are still 404 and 400, login or not.
    assert.equal((await get(s, '/api/stats?host=nope.test:1&range=6h')).status, 404);
    assert.equal((await get(s, '/api/stats?host=a.test:1&range=1y')).status, 400);
  } finally {
    await s.close();
  }
});

test('logged in, everything is there, and the answers are not shared', async () => {
  const s = await setup();
  try {
    const { r, set, cookie } = await logIn(s);
    assert.equal(r.status, 200);
    assert.deepEqual(r.json(), { ok: true, name: 'Alice' });
    assert.match(set, new RegExp(`^${COOKIE}=[A-Za-z0-9_-]{43}; Path=/; Max-Age=43200; HttpOnly; Secure; SameSite=Strict$`));
    assert.equal(r.headers['cache-control'], 'no-store');
    const st = await get(s, '/api/status', cookie);
    assert.equal(st.headers.vary, 'Cookie');
    const body = st.json();
    assert.deepEqual(body.viewer, { name: 'Alice' });
    assert.deepEqual(body.hosts.map((h) => h.locked), [[], [], []]);
    assert.equal(body.hosts[1].stats.data.propagation.storedMessages, 4242);
    assert.equal(body.hosts[1].stats.data.rettuiVersion, '9.8.7');
    assert.equal(body.hosts[1].stats.data.disk.level, 'full');
    assert.equal(body.hosts[1].stats.peerSummary.listed, 3);
    assert.equal(body.hosts[0].group.data.propagation.storedMessages, 2 * 4242);
    assert.equal(body.hosts[0].group.data.disk.worst.level, 'full');
    const d = await get(s, '/api/stats?host=a.test:1&range=6h', cookie);
    assert.equal(d.status, 200);
    assert.equal(d.json().version.current, '9.8.7');
    assert.equal(d.json().version.history.length, 1);
    assert.ok(d.json().series.propagation);
    assert.equal('locked' in d.json(), false);
    const c = await get(s, '/api/stats?host=p.test:1&range=6h&view=combined', cookie);
    assert.equal(c.status, 200);
    assert.deepEqual(c.json().members.map((m) => m.version), ['9.8.7', '9.8.7']);
    // The cache keeps the two kinds of answer apart.
    assert.equal((await get(s, '/api/stats?host=a.test:1&range=6h')).status, 401);
    assert.equal((await get(s, '/api/stats?host=a.test:1&range=6h', cookie)).status, 200);
    // A made-up or ended session is no login.
    assert.equal((await get(s, '/api/stats?host=a.test:1&range=6h', `${COOKIE}=${'A'.repeat(43)}`)).status, 401);
  } finally {
    await s.close();
  }
});

test('details public but storage, disk and versions locked: the details leave them out, in the combined view too', async () => {
  const s = await setup({ top: 'require_login: [storage, disk, versions]' });
  try {
    for (const p of ['/api/status', '/api/stats?host=a.test:1&range=6h', '/api/stats?host=p.test:1&range=6h&view=combined']) {
      const r = await get(s, p);
      assert.equal(r.status, 200, p);
      for (const x of ['4242', '4343', '4646', '4747', '4848', '9.8.7', 'usedPercent', 'fsFreeBytes']) assert.equal(r.text.includes(x), false, `${p} ${x}`);
      // Peered nodes are not locked here.
      if (p !== '/api/status') assert.ok(r.text.includes('peersAlive'), p);
    }
    const d = (await get(s, '/api/stats?host=a.test:1&range=6h')).json();
    assert.deepEqual(d.locked, ['storage', 'disk', 'versions']);
    assert.deepEqual(d.version.history, []);
    assert.equal(d.version.current, null);
    assert.equal(d.series.disk, null);
    assert.deepEqual(Object.keys(d.series.propagation).sort(), ['peersAlive', 'peersTotal']);
    assert.equal(d.stats.peerSummary.listed, 3);
  } finally {
    await s.close();
  }
});

test('one locked node: its numbers leave the group line and the combined view of a public proxy', async () => {
  const s = await setup({ top: 'require_login: []', nodeA: '    require_login: [details, storage, peers, disk]' });
  try {
    const body = (await get(s, '/api/status')).json();
    assert.deepEqual(body.hosts.map((h) => h.locked), [[], ['details', 'storage', 'peers', 'disk'], []]);
    // b still shows its own numbers in its row; the group sum would give a's away, so it goes.
    assert.equal(body.hosts[2].stats.data.propagation.storedMessages, 4242);
    assert.equal(body.hosts[1].stats.data.propagation, undefined);
    assert.equal(body.hosts[0].group.data.propagation, null);
    assert.equal(body.hosts[0].group.data.disk, null);
    const c = await get(s, '/api/stats?host=p.test:1&range=6h&view=combined');
    assert.equal(c.status, 200);
    const combined = c.json();
    assert.deepEqual(combined.members.map((m) => m.host), ['b.test:1']);
    assert.equal(c.text.includes('a.test'), false);
    assert.equal(combined.series.members, 1);
    assert.equal((await get(s, '/api/stats?host=a.test:1&range=6h')).status, 401);
    assert.equal((await get(s, '/api/stats?host=b.test:1&range=6h')).status, 200);
  } finally {
    await s.close();
  }
});

test('public_details false still wins over a login: 404 for everyone', async () => {
  const s = await setup({ nodeA: '    public_details: false' });
  try {
    const { cookie } = await logIn(s);
    const r = await get(s, '/api/stats?host=a.test:1&range=6h', cookie);
    assert.equal(r.status, 404);
    assert.equal((await get(s, '/api/stats?host=a.test:1&range=6h')).status, 404);
  } finally {
    await s.close();
  }
});

test('a wrong password and an unknown name get the same answer', async () => {
  const s = await setup();
  try {
    const wrong = await post(s, '/login', form({ name: 'alice', password: 'nope' }));
    const unknown = await post(s, '/login', form({ name: 'mallory', password: 'nope' }));
    for (const r of [wrong, unknown]) {
      assert.equal(r.status, 401);
      assert.deepEqual(r.json(), { error: LOGIN_FAILED });
      assert.equal(r.headers['set-cookie'], undefined);
    }
    assert.deepEqual(Object.keys(wrong.headers).sort(), Object.keys(unknown.headers).sort());
    assert.equal(wrong.text, unknown.text);
  } finally {
    await s.close();
  }
});

test('login requests from other sites, with other content types or too large are refused', async () => {
  const s = await setup();
  try {
    const body = form({ name: 'alice', password: PASSWORD });
    const cases = [
      [{ 'Content-Type': 'application/x-www-form-urlencoded', 'Sec-Fetch-Site': 'cross-site' }, 403],
      [{ 'Content-Type': 'application/x-www-form-urlencoded', 'Sec-Fetch-Site': 'same-site' }, 403],
      [{ 'Content-Type': 'application/x-www-form-urlencoded', Origin: 'https://evil.test' }, 403],
      [{ 'Content-Type': 'application/x-www-form-urlencoded' }, 403],
      // The page sends X-Rettui-Request, which a form on another site cannot.
      [{ 'Content-Type': 'application/x-www-form-urlencoded', 'Sec-Fetch-Site': 'same-origin' }, 403],
      [{ 'Content-Type': 'application/x-www-form-urlencoded', 'Sec-Fetch-Site': 'same-origin', 'X-Rettui-Request': '0' }, 403],
      [{ 'Content-Type': 'text/plain', 'Sec-Fetch-Site': 'same-origin', 'X-Rettui-Request': '1' }, 415],
      [{ 'Content-Type': 'application/json', 'Sec-Fetch-Site': 'same-origin', 'X-Rettui-Request': '1' }, 415],
      [{ 'Sec-Fetch-Site': 'same-origin', 'X-Rettui-Request': '1' }, 415],
    ];
    for (const [headers, status] of cases) {
      const r = await post(s, '/login', body, headers);
      assert.equal(r.status, status, JSON.stringify(headers));
      assert.equal(r.headers['set-cookie'], undefined);
    }
    // An older browser without Sec-Fetch-Site: the Origin must name this host.
    const host = `127.0.0.1:${s.port}`;
    const old = await post(s, '/login', body, { 'Content-Type': 'application/x-www-form-urlencoded', 'X-Rettui-Request': '1', Origin: `http://${host}`, Host: host });
    assert.equal(old.status, 200);
    const big = await post(s, '/login', form({ name: 'alice', password: 'x'.repeat(5000) }));
    assert.equal(big.status, 413);
    const missing = await post(s, '/login', form({ name: 'alice' }));
    assert.equal(missing.status, 400);
    assert.equal((await post(s, '/login', '')).status, 400);
    // Logout takes the same checks.
    assert.equal((await post(s, '/logout', '', { 'Content-Type': 'application/x-www-form-urlencoded', 'Sec-Fetch-Site': 'cross-site' })).status, 403);
    assert.equal((await post(s, '/logout', '', { 'Sec-Fetch-Site': 'same-origin', 'X-Rettui-Request': '1' })).status, 415);
    // Without the header, logout and the code step are refused too, and the session stays.
    const { cookie } = await logIn(s);
    const noHeader = { 'Content-Type': 'application/x-www-form-urlencoded', 'Sec-Fetch-Site': 'same-origin', Cookie: cookie };
    assert.equal((await post(s, '/logout', '', noHeader)).status, 403);
    assert.equal((await post(s, '/login/code', form({ pending: 'x', code: '123456' }), noHeader)).status, 403);
    assert.equal((await get(s, '/api/session', cookie)).json().name, 'Alice');
    // Only POST.
    assert.equal((await request(s.port, { method: 'PUT', path: '/login', headers: FORM, body })).status, 405);
    assert.equal((await get(s, '/login')).status, 404);
  } finally {
    await s.close();
  }
});

test('logout ends the session, and a new login gets a new id', async () => {
  const s = await setup();
  try {
    const first = await logIn(s);
    assert.equal((await get(s, '/api/stats?host=a.test:1&range=6h', first.cookie)).status, 200);
    // Logging in again with the old cookie: the old id is dropped, a new one is given.
    const second = await logIn(s, 'alice', PASSWORD, { Cookie: first.cookie });
    assert.notEqual(second.cookie, first.cookie);
    assert.equal((await get(s, '/api/stats?host=a.test:1&range=6h', first.cookie)).status, 401);
    assert.equal((await get(s, '/api/stats?host=a.test:1&range=6h', second.cookie)).status, 200);
    const out = await post(s, '/logout', '', { ...FORM, Cookie: second.cookie });
    assert.equal(out.status, 200);
    assert.match(out.headers['set-cookie'][0], new RegExp(`^${COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict$`));
    assert.equal((await get(s, '/api/stats?host=a.test:1&range=6h', second.cookie)).status, 401);
    assert.deepEqual((await get(s, '/api/status', second.cookie)).json().viewer, { name: null });
    assert.equal(s.login.sessions.size, 0);
  } finally {
    await s.close();
  }
});

test('repeated failures are slowed down with 429 and Retry-After, without a hint about the name', async () => {
  const s = await setup();
  try {
    for (let i = 0; i < 6; i++) assert.equal((await post(s, '/login', form({ name: 'alice', password: 'nope' }))).status, 401);
    const r = await post(s, '/login', form({ name: 'alice', password: PASSWORD }));
    assert.equal(r.status, 429);
    assert.match(r.json().error, /^Too many failed attempts\. Try again in \d+ seconds?\.$/);
    assert.ok(Number(r.headers['retry-after']) >= 1);
    assert.equal(r.headers['set-cookie'], undefined);
  } finally {
    await s.close();
  }
});

test('with all hash slots taken a login is turned away with 503', async () => {
  const gate = hashGate(1, 0);
  let release;
  const held = gate(() => new Promise((r) => (release = r)));
  const s = await setup({ gate });
  try {
    const r = await post(s, '/login', form({ name: 'alice', password: PASSWORD }));
    assert.equal(r.status, 503);
    assert.equal(r.headers['retry-after'], '2');
  } finally {
    release();
    await held;
    await s.close();
  }
});

test('a failing hasher is a 500 with no details', async () => {
  const s = await setup();
  const original = s.login.attempt;
  try {
    const errors = [];
    const log = console.error;
    console.error = (m) => errors.push(m);
    try {
      // The hasher is reached through attempt; break it for one request.
      s.login.attempt = async () => {
        throw new Error('out of memory');
      };
      const r = await post(s, '/login', form({ name: 'alice', password: PASSWORD }));
      assert.equal(r.status, 500);
      assert.equal(r.text, 'Server error\n');
    } finally {
      console.error = log;
    }
    assert.equal(errors.some((e) => e.includes(PASSWORD)), false);
  } finally {
    s.login.attempt = original;
    await s.close();
  }
});

test('X-Forwarded-For from a local proxy that is not trusted is warned about once', async () => {
  const warnings = [];
  const s = await setup({ warn: (m) => warnings.push(m) });
  try {
    await get(s, '/api/status');
    assert.deepEqual(warnings, [], 'quiet without X-Forwarded-For');
    for (let i = 0; i < 3; i++) await request(s.port, { path: '/api/status', headers: { 'X-Forwarded-For': '203.0.113.7' } });
    assert.equal(warnings.length, 1);
    assert.match(warnings[0], /^WARNING: .*127\.0\.0\.1 is not a trusted proxy.*login\.trusted_proxies.*LOGIN_TRUSTED_PROXIES/);
    assert.equal(warnings[0].includes('203.0.113.7'), false);
  } finally {
    await s.close();
  }
});

test('X-Forwarded-For from a trusted proxy that is not an address is warned about once; with a port it is read', async () => {
  const warnings = [];
  const s = await setup({ top: 'login:\n  trusted_proxies: ["127.0.0.0/8"]\n', warn: (m) => warnings.push(m) });
  try {
    await request(s.port, { path: '/api/status', headers: { 'X-Forwarded-For': '203.0.113.7:5678, [2001:db8::1]:443' } });
    assert.deepEqual(warnings, [], 'a port is read, not warned about');
    for (let i = 0; i < 3; i++) await request(s.port, { path: '/api/status', headers: { 'X-Forwarded-For': 'client.example' } });
    assert.equal(warnings.length, 1);
    assert.match(warnings[0], /^WARNING: login: the trusted proxy 127\.0\.0\.1 sent an X-Forwarded-For entry that is not an IP address/);
    assert.equal(warnings[0].includes('client.example'), false, 'the header is not repeated');
  } finally {
    await s.close();
  }
});

test('X-Forwarded-For from a trusted proxy, or without users, is not warned about', async () => {
  const warnings = [];
  const warn = (m) => warnings.push(m);
  for (const opts of [{ top: 'login:\n  trusted_proxies: ["127.0.0.1"]\n' }, { users: false }]) {
    const s = await setup({ ...opts, warn });
    try {
      await request(s.port, { path: '/api/status', headers: { 'X-Forwarded-For': '203.0.113.7' } });
    } finally {
      await s.close();
    }
  }
  assert.deepEqual(warnings, []);
});
