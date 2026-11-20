import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Monitor } from '../lib/monitor.js';
import { loadConfig } from '../lib/config.js';
import { createApp } from '../lib/app.js';
import { createLogin } from '../lib/login.js';
import { hashPassword } from '../lib/password.js';
import { fetchStats } from '../lib/stats.js';
import { stripStats } from '../lib/access.js';
import { comparePeerRows, MAX_PEER_ROWS, MAX_PROPAGATION_PEERS, sanitizePropagationPeerRows } from '../lib/propagation.js';
import { fakeHasher } from './helpers/fake-hasher.js';

const publicDir = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'public');
const MIN = 60_000;
const NOW = 1_800_000_000_000;
const TOKEN = 't'.repeat(20);
const addr = (n) => n.toString(16).padStart(32, '0');

// Made-up rows, as a rettui node sends them.
const row = (n, o = {}) => ({
  address: addr(n), name: `Relay ${n}`, alive: true, static: false, depth: 2, state: 'idle', last_heard_seconds_ago: 30, last_sync_seconds_ago: 600,
  messages_offered: 12, unhandled: 3, sync_failures: 0, last_attempt_seconds_ago: 600, next_attempt_in_seconds: null, peering_cost: 18, ...o,
});
const auth = (rows, extra = {}) => ({ authorised: true, propagation_peers: rows, ...extra });

test('rows are cleaned: bad addresses and repeats are dropped, wrong types become null', () => {
  const rows = sanitizePropagationPeerRows(auth([
    row(1, { name: '‮evil​ name\u0007' }),
    row(2, { alive: 'yes', static: 1, depth: 'x', state: 'Bad State!', unhandled: -9, messages_offered: 1e300, last_sync_seconds_ago: '5', sync_failures: NaN }),
    row(2, { name: 'again' }),
    row(3, { address: addr(3).toUpperCase().replace(/[0-9]/g, 'A') }),
    { address: 'zz' }, { address: addr(4) + '0' }, { name: 'none' }, null, 'x', 5, [], { address: 7 },
    row(5, { name: 42 }),
  ]));
  assert.equal(rows.length, 3);
  const byAddress = Object.fromEntries(rows.map((r) => [r.address, r]));
  assert.equal(byAddress[addr(1)].name, 'evil name');
  const two = byAddress[addr(2)];
  assert.equal(two.name, 'Relay 2');
  assert.deepEqual([two.alive, two.static, two.depth, two.state, two.unhandled, two.lastSyncSecondsAgo, two.syncFailures], [null, null, null, null, 0, null, null]);
  assert.equal(two.messagesOffered, 1e12);
  assert.equal(byAddress[addr(5)].name, null);
});

test('only the known fields are kept, and the strings are cut', () => {
  const [r] = sanitizePropagationPeerRows(auth([{ ...row(1, { name: 'x'.repeat(500), state: 'y'.repeat(60) }), extra: 'secret', html: '<b>' }]));
  assert.deepEqual(Object.keys(r).sort(), [
    'address', 'alive', 'depth', 'hasSync', 'lastAttemptSecondsAgo', 'lastHeardSecondsAgo', 'lastSyncSecondsAgo', 'messagesOffered', 'name',
    'nextAttemptInSeconds', 'peeringCost', 'state', 'static', 'syncFailures', 'unhandled',
  ]);
  assert.equal(r.name.length, 64);
  assert.equal(r.state, null);
  assert.equal(JSON.stringify(r).includes('secret'), false);
});

test('there is no list without the token answer or without a list', () => {
  for (const none of [null, 5, {}, { propagation_peers: [row(1)] }, { authorised: false, propagation_peers: [row(1)] }, { authorised: true }, { authorised: true, propagation_peers: {} }]) {
    assert.equal(sanitizePropagationPeerRows(none), null);
  }
  assert.deepEqual(sanitizePropagationPeerRows(auth([])), []);
});

test('at most 64 rows are kept, after 256 are looked at, and the best sorted ones stay', () => {
  const many = Array.from({ length: 400 }, (_, i) => row(i + 1, { static: i === 299 }));
  const rows = sanitizePropagationPeerRows(auth(many));
  assert.equal(rows.length, MAX_PEER_ROWS);
  assert.equal(MAX_PEER_ROWS, 64);
  // Row 300 is past the 256 looked at, so it never counts.
  assert.equal(rows.some((r) => r.address === addr(300)), false);
  const late = sanitizePropagationPeerRows(auth(Array.from({ length: 200 }, (_, i) => row(i + 1, { static: i === 150 }))));
  assert.equal(late[0].address, addr(151));
  assert.equal(MAX_PROPAGATION_PEERS, 256);
});

test('the order: static first, then the most recent sync, never synced last, then name, then address', () => {
  const rows = sanitizePropagationPeerRows(auth([
    row(1, { name: 'delta', last_sync_seconds_ago: 50 }),
    row(2, { name: 'Alpha', last_sync_seconds_ago: 50 }),
    row(3, { name: 'gamma', last_sync_seconds_ago: null }),
    row(4, { name: 'zulu', static: true, last_sync_seconds_ago: 9000 }),
    row(5, { name: 'beta', last_sync_seconds_ago: 10 }),
    row(6, { name: null, last_sync_seconds_ago: 50 }),
    row(7, { name: 'same', last_sync_seconds_ago: 50 }),
    row(8, { name: 'same', last_sync_seconds_ago: 50 }),
    row(9, { name: 'omega', static: true, last_sync_seconds_ago: null }),
  ]));
  assert.deepEqual(rows.map((r) => r.address), [4, 9, 5, 2, 1, 7, 8, 6, 3].map(addr));
  // The same whatever the arrival order.
  const shuffled = sanitizePropagationPeerRows(auth([...rows].reverse().map((r) => row(Number.parseInt(r.address, 16), { name: r.name, static: r.static, last_sync_seconds_ago: r.lastSyncSecondsAgo }))));
  assert.deepEqual(shuffled.map((r) => r.address), rows.map((r) => r.address));
  assert.equal(comparePeerRows(rows[0], rows[0]), 0);
});

test('an older node without the sync fields is marked, and nothing else breaks', () => {
  const old = row(1);
  for (const k of ['last_sync_seconds_ago', 'sync_failures', 'last_attempt_seconds_ago', 'next_attempt_in_seconds']) delete old[k];
  const [r] = sanitizePropagationPeerRows(auth([old]));
  assert.equal(r.hasSync, false);
  assert.equal(r.lastSyncSecondsAgo, null);
  assert.equal(r.syncFailures, null);
  assert.equal(sanitizePropagationPeerRows(auth([row(2, { last_sync_seconds_ago: null })]))[0].hasSync, true);
});

test('stripStats takes the rows out with the peers section only', () => {
  const stats = { ok: true, data: { uptimeSeconds: 1 }, peerSummary: { listed: 1 }, peerRows: [{ address: addr(1) }] };
  assert.equal('peerRows' in stripStats(stats, new Set(['peers'])), false);
  assert.equal('peerSummary' in stripStats(stats, new Set(['peers'])), false);
  for (const section of ['details', 'storage', 'disk', 'versions']) assert.equal('peerRows' in stripStats(stats, new Set([section])), true, section);
  assert.equal(stripStats(stats, new Set()), stats);
});

const body = (rows) => ({
  version: 1, rettui_version: '2.1.0', generated_at: 1, uptime_seconds: 1,
  interfaces: { total: 1, online: 1, clients: 1, rx_bytes: 1, tx_bytes: 1 },
  peers_heard: { total: 3, lxmf: 2, nomad: 1, propagation: 0 }, announces_last_minute: 0,
  propagation: { enabled: true, stored_messages: 7 },
  ...auth(rows),
});
const fakeFetch = (rows) => async () => new Response(JSON.stringify(body(rows)));

test('fetchStats keeps rows only for a request with a token, outside the stats data', async () => {
  const withToken = await fetchStats('https://a.test/s', { fetchFn: fakeFetch([row(1)]), token: TOKEN });
  assert.equal(withToken.peerRows.length, 1);
  assert.equal('peerRows' in withToken.data, false);
  assert.equal(JSON.stringify(withToken.data).includes(addr(1)), false);
  const without = await fetchStats('https://a.test/s', { fetchFn: fakeFetch([row(1)]) });
  assert.equal('peerRows' in without, false);
});

const MARK = 'Zebra Relay';

async function setup({ top = '', users = true, nodeA = '' } = {}) {
  const hash = await hashPassword('correct horse battery', undefined, fakeHasher);
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
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'website-rows-'));
  const rows = [row(1, { name: MARK, static: true }), row(2, { last_sync_seconds_ago: null, sync_failures: 3 })];
  const monitor = new Monitor({
    targets: config.targets, nodes: config.nodes, statsUrls: config.statsUrls, dataDir: dir,
    publicDetails: config.defaults.publicDetails, publicDiskFigures: config.defaults.publicDiskFigures, requireLogin: config.defaults.requireLogin,
    tokens: new Map([['a.test:1', TOKEN]]),
    probeFn: async () => ({ up: true, ms: 1 }),
    statsFn: (url, opts) => fetchStats(url, { fetchFn: fakeFetch(rows), ...opts }),
    now: () => clock,
    sampleIntervalMs: 1000,
  });
  for (let i = 0; i < 4; i++) {
    await monitor.checkAll();
    clock += 5 * MIN;
  }
  clock -= 5 * MIN;
  await monitor.flush();
  const login = users ? createLogin({ users: config.users, settings: config.login, hasher: fakeHasher }) : null;
  const server = createApp({ monitor, publicDir, login, publicTtlMs: 0 });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  return { monitor, dir, port, close: () => (server.closeAllConnections(), new Promise((r) => server.close(r))) };
}

function get(port, p, cookie) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path: p, headers: cookie ? { Cookie: cookie } : {} }, (res) => {
      let text = '';
      res.on('data', (c) => (text += c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text, json: () => JSON.parse(text) }));
    });
    req.on('error', reject);
    req.end();
  });
}

async function logIn(s) {
  const r = await new Promise((resolve, reject) => {
    const data = new URLSearchParams({ name: 'alice', password: 'correct horse battery' }).toString();
    const req = http.request({ host: '127.0.0.1', port: s.port, path: '/login', method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Sec-Fetch-Site': 'same-origin' } }, (res) => {
      res.resume();
      res.on('end', () => resolve(res));
    });
    req.on('error', reject);
    req.end(data);
  });
  return r.headers['set-cookie'][0].split(';')[0];
}

test('without users the node detail has the rows; nothing else does', async () => {
  const s = await setup({ users: false });
  try {
    const d = (await get(s.port, '/api/stats?host=a.test:1&range=6h')).json();
    assert.equal(d.stats.peerRows.length, 2);
    assert.equal(d.stats.peerRows[0].name, MARK);
    assert.equal(d.stats.peerRows[0].address, addr(1));
    assert.equal(d.stats.peerSummary.listed, 2);
    // b has no token: no summary, no rows.
    const b = (await get(s.port, '/api/stats?host=b.test:1&range=6h')).json();
    assert.equal('peerRows' in b.stats, false);
    for (const p of ['/api/status', '/api/public/stats', '/api/stats?host=p.test:1&range=6h&view=combined', '/api/incidents']) {
      const r = await get(s.port, p);
      assert.equal(r.status, 200, p);
      for (const x of [MARK, addr(1), addr(2), 'peerRows', 'syncFailures']) assert.equal(r.text.includes(x), false, `${p} ${x}`);
    }
  } finally {
    await s.close();
  }
});

test('with peers behind a login, a visitor gets no rows and a logged in user does', async () => {
  const s = await setup({ top: 'require_login: [peers]' });
  try {
    const anon = await get(s.port, '/api/stats?host=a.test:1&range=6h');
    assert.equal(anon.status, 200);
    for (const x of [MARK, addr(1), 'peerRows', 'peerSummary']) assert.equal(anon.text.includes(x), false, x);
    assert.deepEqual(anon.json().locked, ['peers']);
    const cookie = await logIn(s);
    const user = await get(s.port, '/api/stats?host=a.test:1&range=6h', cookie);
    assert.equal(user.json().stats.peerRows.length, 2);
    assert.equal('locked' in user.json(), false);
    // The answers are cached apart.
    assert.equal((await get(s.port, '/api/stats?host=a.test:1&range=6h')).text.includes(MARK), false);
    // The combined view and the list never carry rows, even for a user.
    for (const p of ['/api/status', '/api/public/stats', '/api/stats?host=p.test:1&range=6h&view=combined']) {
      const r = await get(s.port, p, cookie);
      assert.equal(r.text.includes(MARK), false, p);
      assert.equal(r.text.includes('peerRows'), false, p);
    }
  } finally {
    await s.close();
  }
});

test('details behind a login keep the rows too; public_details false hides the view', async () => {
  const s = await setup({ top: 'require_login: [details]' });
  try {
    const anon = await get(s.port, '/api/stats?host=a.test:1&range=6h');
    assert.equal(anon.status, 401);
    assert.equal(anon.text.includes(MARK), false);
    assert.equal((await get(s.port, '/api/stats?host=a.test:1&range=6h', await logIn(s))).json().stats.peerRows.length, 2);
  } finally {
    await s.close();
  }
  const hidden = await setup({ users: false, nodeA: '    public_details: false' });
  try {
    const r = await get(hidden.port, '/api/stats?host=a.test:1&range=6h');
    assert.equal(r.status, 404);
    assert.equal(r.text.includes(MARK), false);
  } finally {
    await hidden.close();
  }
});

test('the saved stats history holds no row and the memory copy is dropped without the token fetch', async () => {
  const s = await setup({ users: false });
  try {
    for (const f of await fs.readdir(s.dir)) {
      const text = await fs.readFile(path.join(s.dir, f), 'utf8');
      for (const x of [MARK, addr(1), addr(2), 'peerRows', 'syncFailures', 'Relay']) assert.equal(text.includes(x), false, `${f} ${x}`);
    }
    assert.ok((await fs.readdir(s.dir)).includes('stats-history.json'));
    // A fetch that fails the token (no list) drops the rows: they would be stale.
    s.monitor.statsFn = async () => ({ ok: true, data: s.monitor.stats.get('a.test:1').data });
    await s.monitor.fetchStatsAll();
    assert.equal(s.monitor.peerRowLists.has('a.test:1'), false);
    assert.equal('peerRows' in (await get(s.port, '/api/stats?host=a.test:1&range=6h')).json().stats, false);
  } finally {
    await s.close();
  }
});
