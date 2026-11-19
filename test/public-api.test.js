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
import { etagMatches, memoJson, publicIncidents, publicStats } from '../lib/public-api.js';
import { fakeHasher } from './helpers/fake-hasher.js';

const publicDir = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'public');
const MIN = 60_000;
const NOW = 1_800_000_000_000;
const TOKEN = 't'.repeat(20);

const statsData = () => ({
  rettuiVersion: '9.8.7', generatedAt: 1, uptimeSeconds: 100,
  interfaces: { total: 2, online: 1, clients: 4, rxBytes: 11, txBytes: 12 },
  peersHeard: { total: 3, lxmf: 2, nomad: 1, propagation: 0 }, announcesLastMinute: 7,
  disk: { dataBytes: 123_456, fsTotalBytes: 1000, fsFreeBytes: 80 },
  propagation: {
    enabled: true, storedMessages: 4242, storedBytes: 4343, storageLimitBytes: null, peersConnected: null, peersTotal: 4444, peersAlive: 4545, peersStatic: null,
    peersAuto: null, peerLimit: null, staticPeers: null, autopeerDepth: null, messagesReceived: null, messagesServed: null, messagesSentToPeers: 4646,
    messagesReceivedFromPeers: 4747, messagesOfferedToPeers: null, unhandledMessages: 4848, autopeer: null,
  },
});

// Things only a logged-in visitor (or nobody) may see, as they appear in JSON.
const SECRET = ['4242', '4343', '4444', '4545', '4646', '4747', '4848', '9.8.7', 'peerSummary', 'fsFreeBytes', 'fsTotalBytes', 'dataBytes', TOKEN, os.tmpdir(), 'stats_url', 'https://'];

async function setup({ top = '', users = false, nodes, createOptions = {}, statsFn } = {}) {
  const hash = users ? await hashPassword('correct horse battery', undefined, fakeHasher) : null;
  const config = loadConfig(`${users ? `users:\n  - name: Alice\n    password_hash: '${hash}'\n` : ''}${top}
nodes:
${nodes ?? `  - address: p.test:1
    name: Proxy
    stats_url: https://p.test/s
    proxy_for: [a.test:1, b.test:1]
  - address: a.test:1
    stats_url: https://a.test/s
  - address: b.test:1
    stats_url: https://b.test/s
  - address: c.test:1
`}`);
  let clock = NOW - 30 * MIN;
  const monitor = new Monitor({
    targets: config.targets, nodes: config.nodes, statsUrls: config.statsUrls, dataDir: await fs.mkdtemp(path.join(os.tmpdir(), 'website-pub-')),
    publicDetails: config.defaults.publicDetails, publicDiskFigures: config.defaults.publicDiskFigures, requireLogin: config.defaults.requireLogin,
    tokens: new Map([['a.test:1', TOKEN]]),
    probeFn: async (host) => ({ up: host !== 'c.test', ms: 5 }),
    statsFn: statsFn ?? (async () => ({ ok: true, data: statsData(), propagationPeers: { listed: 3, alive: 2, static: 0, unhandled: 0, truncated: false } })),
    now: () => clock,
    sampleIntervalMs: 1000,
  });
  for (let i = 0; i < 4; i++) {
    await monitor.checkAll();
    clock += 5 * MIN;
  }
  clock -= 5 * MIN;
  const login = users ? createLogin({ users: config.users, settings: config.login, hasher: fakeHasher }) : null;
  const server = createApp({ monitor, publicDir, login, publicTtlMs: 0, ...createOptions });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  return { monitor, port, close: () => (server.closeAllConnections(), new Promise((r) => server.close(r))) };
}

function request(port, { method = 'GET', path: p, headers = {} }) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path: p, method, headers }, (res) => {
      let text = '';
      res.on('data', (c) => (text += c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text, json: () => JSON.parse(text) }));
    });
    req.on('error', reject);
    req.end();
  });
}

test('stats: fields, versions and headers', async () => {
  const s = await setup();
  try {
    const r = await request(s.port, { path: '/api/public/stats' });
    assert.equal(r.status, 200);
    assert.equal(r.headers['content-type'], 'application/json; charset=utf-8');
    assert.equal(r.headers['access-control-allow-origin'], '*');
    assert.equal(r.headers['cache-control'], 'public, max-age=30');
    assert.match(r.headers.etag, /^"[0-9a-f]{24}"$/);
    assert.equal(r.headers['set-cookie'], undefined);
    assert.equal(r.headers['x-content-type-options'], 'nosniff');
    assert.match(r.headers['content-security-policy'], /default-src 'none'/);
    const body = r.json();
    assert.deepEqual(Object.keys(body), ['version', 'generated', 'nodes', 'network']);
    assert.equal(body.version, 1);
    assert.equal(body.generated, new Date(NOW - 15 * MIN).toISOString());
    assert.equal(body.nodes.length, 4);
    const [p, a, , c] = body.nodes;
    assert.deepEqual(Object.keys(a), ['name', 'address', 'role', 'status', 'up', 'connectMs', 'lastChecked', 'uptime30', 'uptime90', 'clients', 'interfaces', 'peersHeard', 'announcesLastMinute', 'propagation', 'disk', 'announceQueue', 'proxyFor', 'proxiedBy', 'group']);
    assert.equal(a.name, 'a.test');
    assert.equal(a.address, 'a.test:1');
    assert.equal(a.up, true);
    assert.equal(a.connectMs, 5);
    assert.equal(a.clients, 4);
    assert.deepEqual(a.interfaces, { total: 2, online: 1 });
    assert.deepEqual(a.peersHeard, { total: 3, lxmf: 2, nomad: 1, propagation: 0 });
    assert.equal(a.announcesLastMinute, 7);
    assert.equal(a.propagation.storedMessages, 4242);
    assert.equal(a.propagation.enabled, undefined);
    assert.deepEqual(Object.keys(a.disk), ['level', 'usedPercent']);
    assert.equal(a.proxiedBy, 'p.test:1');
    assert.equal(a.group, null);
    // No announce queue reported: null.
    assert.equal(a.announceQueue, null);
    // A node with no stats URL: up and connect time only.
    assert.equal(c.address, 'c.test:1');
    assert.equal(c.up, false);
    assert.equal(c.connectMs, null);
    assert.equal(c.clients, null);
    assert.equal(c.peersHeard, null);
    // The proxy has the combined view.
    assert.equal(p.name, 'Proxy');
    assert.equal(p.role, 'proxy');
    assert.deepEqual(p.proxyFor, ['a.test:1', 'b.test:1']);
    assert.equal(p.group.nodes, 2);
    assert.equal(p.group.reporting, 2);
    assert.equal(p.group.clients, 8);
    assert.equal(p.group.announcesLastMinute, 14);
    assert.deepEqual(p.group.peersHeard.total, { min: 3, max: 6 });
    assert.equal(p.group.peersHeard.exact, false);
    assert.equal(p.group.propagation.storedMessages, 8484);
    // Network totals count the group once, and the node outside it.
    assert.equal(body.network.nodes, 4);
    assert.equal(body.network.down, 1);
    assert.equal(body.network.overall, 'degraded');
    assert.equal(body.network.clients, 8);
    assert.equal(body.network.peersHeardSum.total, 6);
    assert.deepEqual(body.network.interfaces, { total: 4, online: 2 });
  } finally {
    await s.close();
  }
});

test('stats: nothing locked leaks with users, require_login and public_details false', async () => {
  const s = await setup({ users: true, top: 'public_details: false\n' });
  try {
    const anon = await request(s.port, { path: '/api/public/stats' });
    assert.equal(anon.status, 200);
    for (const secret of SECRET) assert.equal(anon.text.includes(secret), false, `leaked ${secret}`);
    const body = anon.json();
    for (const n of body.nodes) {
      assert.equal(n.propagation, null);
      assert.equal(n.disk, null);
      if (n.group) assert.equal(n.group.disk, null);
      if (n.group) assert.equal(n.group.propagation, null);
    }
    // Public numbers stay.
    assert.equal(body.nodes[1].clients, 4);
    // The answer does not depend on the cookie, and sets none.
    const withCookie = await request(s.port, { path: '/api/public/stats', headers: { cookie: 'rettui_session=abc; other=1' } });
    assert.equal(withCookie.json().nodes.length, body.nodes.length);
    assert.equal(withCookie.headers['set-cookie'], undefined);
    assert.equal(withCookie.headers.vary, undefined);
    assert.equal(withCookie.text.replace(/"generated":"[^"]*"/, ''), anon.text.replace(/"generated":"[^"]*"/, ''));
    // The incidents are public too, and carry only their own fields.
    const inc = await request(s.port, { path: '/api/public/incidents' });
    assert.equal(inc.status, 200);
    for (const secret of SECRET) assert.equal(inc.text.includes(secret), false, `leaked ${secret}`);
  } finally {
    await s.close();
  }
});

test('stats: a logged-in session cookie never unlocks the public endpoint', async () => {
  const s = await setup({ users: true });
  try {
    const name = 'rettui_session';
    const anon = await request(s.port, { path: '/api/public/stats' });
    const other = await request(s.port, { path: '/api/public/stats', headers: { cookie: `${name}=${'a'.repeat(43)}` } });
    assert.equal(other.headers.etag, anon.headers.etag);
    assert.equal(anon.text.includes('4242'), false);
  } finally {
    await s.close();
  }
});

test('stats: public sections follow public_disk_figures and require_login', async () => {
  const open = await setup({ top: 'public_disk_figures: false\n' });
  const figures = await setup({ top: 'public_disk_figures: true\n' });
  const partly = await setup({ users: true, top: 'require_login: [peers, disk, versions, details]\n' });
  try {
    const a = (await request(open.port, { path: '/api/public/stats' })).json().nodes[1];
    assert.equal(a.disk.level, 'full');
    assert.equal(a.disk.totalBytes, undefined);
    assert.equal(a.propagation.storedMessages, 4242);
    const b = (await request(figures.port, { path: '/api/public/stats' })).json().nodes[1];
    assert.equal(b.disk.totalBytes, 1000);
    assert.equal(b.disk.freeBytes, 80);
    // Storage is public here, peering and disk are not.
    const c = (await request(partly.port, { path: '/api/public/stats' })).json().nodes[1];
    assert.equal(c.propagation.storedMessages, 4242);
    assert.equal(Object.hasOwn(c.propagation, 'peersTotal'), false);
    assert.equal(Object.hasOwn(c.propagation, 'storedBytes'), false);
    assert.equal(c.disk, null);
  } finally {
    await Promise.all([open.close(), figures.close(), partly.close()]);
  }
});

test('stats: ETag and 304, also with a list and a weak validator', async () => {
  const s = await setup({ createOptions: { publicTtlMs: 60_000 } });
  try {
    const first = await request(s.port, { path: '/api/public/stats' });
    const { etag } = first.headers;
    for (const header of [etag, `W/${etag}`, `"x", ${etag}`, '*']) {
      const r = await request(s.port, { path: '/api/public/stats', headers: { 'if-none-match': header } });
      assert.equal(r.status, 304, header);
      assert.equal(r.text, '');
      assert.equal(r.headers.etag, etag);
      assert.equal(r.headers['access-control-allow-origin'], '*');
      assert.equal(r.headers['cache-control'], 'public, max-age=30');
      assert.equal(r.headers['x-content-type-options'], 'nosniff');
    }
    const miss = await request(s.port, { path: '/api/public/stats', headers: { 'if-none-match': '"other"' } });
    assert.equal(miss.status, 200);
    assert.equal(miss.text, first.text);
  } finally {
    await s.close();
  }
});

test('stats: the answer is served from memory between rebuilds', async () => {
  const s = await setup({ createOptions: { publicTtlMs: 60_000 } });
  try {
    const first = await request(s.port, { path: '/api/public/stats' });
    s.monitor.snapshot = () => assert.fail('snapshot must not be called again');
    const again = await request(s.port, { path: '/api/public/stats' });
    assert.equal(again.text, first.text);
  } finally {
    await s.close();
  }
});

test('stats: HEAD has the headers and no body; other methods are 405 without CORS', async () => {
  const s = await setup();
  try {
    const get = await request(s.port, { path: '/api/public/stats' });
    const head = await request(s.port, { method: 'HEAD', path: '/api/public/stats' });
    assert.equal(head.status, 200);
    assert.equal(head.text, '');
    assert.equal(head.headers['content-length'], String(Buffer.byteLength(get.text)));
    assert.equal(head.headers['access-control-allow-origin'], '*');
    for (const method of ['POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']) {
      const r = await request(s.port, { method, path: '/api/public/stats' });
      assert.equal(r.status, 405, method);
      assert.equal(r.headers.allow, 'GET, HEAD');
      assert.equal(r.headers['access-control-allow-origin'], undefined);
    }
    // A query string changes nothing.
    const q = await request(s.port, { path: '/api/public/stats?host=a.test:1&range=7d' });
    assert.equal(q.status, 200);
    assert.equal(q.headers.etag, get.headers.etag);
  } finally {
    await s.close();
  }
});

test('CORS is on the public routes only', async () => {
  const s = await setup({ users: true });
  try {
    for (const p of ['/api/status', '/api/incidents', '/api/stats?host=a.test:1', '/status', '/', '/healthz', '/site.css', '/api/releases', '/api/public', '/api/public/', '/api/public/other', '/api/public/stats/x']) {
      const r = await request(s.port, { path: p });
      assert.equal(r.headers['access-control-allow-origin'], undefined, p);
    }
    for (const p of ['/api/public/stats', '/api/public/incidents']) {
      assert.equal((await request(s.port, { path: p })).headers['access-control-allow-origin'], '*', p);
    }
    assert.equal((await request(s.port, { path: '/api/public/stats/' })).status, 404);
  } finally {
    await s.close();
  }
});

test('stats: 64 nodes stay small', async () => {
  const list = [];
  for (let i = 1; i <= 64; i++) list.push(`  - address: n${i}.example.org:4242\n    name: Node number ${i}\n    stats_url: https://n${i}.example.org/stats.json`);
  list[0] += `\n    proxy_for: [${Array.from({ length: 10 }, (_, i) => `n${i + 2}.example.org:4242`).join(', ')}]`;
  const s = await setup({ nodes: `${list.join('\n')}\n`, top: 'public_disk_figures: true\n' });
  try {
    const r = await request(s.port, { path: '/api/public/stats' });
    const body = r.json();
    assert.equal(body.nodes.length, 64);
    assert.ok(Buffer.byteLength(r.text) < 72 * 1024, `${Buffer.byteLength(r.text)} bytes`);
    const inc = await request(s.port, { path: '/api/public/incidents' });
    assert.ok(Buffer.byteLength(inc.text) < 64 * 1024);
  } finally {
    await s.close();
  }
});

test('incidents: a down node is listed with only the public fields', async () => {
  const s = await setup();
  try {
    const body = (await request(s.port, { path: '/api/public/incidents' })).json();
    assert.equal(body.version, 1);
    assert.ok(Array.isArray(body.incidents));
    for (const i of body.incidents) assert.deepEqual(Object.keys(i), ['address', 'name', 'start', 'end', 'seconds', 'ongoing']);
  } finally {
    await s.close();
  }
});

test('memoJson builds once per ttl and etagMatches reads the header', () => {
  let t = 0;
  let n = 0;
  const get = memoJson(() => ({ n: ++n }), 1000, () => t);
  const a = get();
  assert.equal(get(), a);
  t = 999;
  assert.equal(get(), a);
  t = 1000;
  assert.notEqual(get().etag, a.etag);
  t = 0;
  assert.equal(get().body, '{"n":3}');
  assert.equal(etagMatches(undefined, '"a"'), false);
  assert.equal(etagMatches('"a"', '"a"'), true);
  assert.equal(etagMatches('"b" , W/"a"', '"a"'), true);
  assert.equal(etagMatches('"b"', '"a"'), false);
});

test('stats: the announce queue is published as four numbers, and null without one', async () => {
  const queued = { queued: 4096, limit: 8192, full: true, fullest: 4096 };
  const s = await setup({ statsFn: async (url) => ({ ok: true, data: { ...statsData(), ...(url.includes('//a.') ? { announceQueue: { ...queued, interfacesFull: 1, extra: 'x' } } : {}) } }) });
  try {
    const nodes = (await request(s.port, { path: '/api/public/stats' })).json().nodes;
    assert.deepEqual(nodes[1].announceQueue, queued);
    assert.equal(nodes[2].announceQueue, null);
    assert.equal(nodes[3].announceQueue, null);
  } finally {
    await s.close();
  }
});

test('the ETag survives a rebuild that finds nothing new, and changes when the content changes', async () => {
  // Rebuilt on every request (ttl 0), with the clock moving: only `generated` differs between the answers.
  const s = await setup();
  try {
    let t = NOW;
    s.monitor.now = () => (t += 10_000);
    const first = await request(s.port, { path: '/api/public/stats' });
    const second = await request(s.port, { path: '/api/public/stats' });
    const third = await request(s.port, { path: '/api/public/stats' });
    assert.notEqual(first.json().generated, second.json().generated);
    assert.notEqual(second.json().generated, third.json().generated);
    assert.equal(first.headers.etag, second.headers.etag);
    assert.equal(first.headers.etag, third.headers.etag);
    // A client that kept the first ETag gets a 304 from a later rebuild.
    const r = await request(s.port, { path: '/api/public/stats', headers: { 'if-none-match': first.headers.etag } });
    assert.equal(r.status, 304);
    // New content (a new check) is a new ETag.
    await s.monitor.checkAll();
    const changed = await request(s.port, { path: '/api/public/stats' });
    assert.notEqual(changed.headers.etag, first.headers.etag);
  } finally {
    await s.close();
  }
});

test('incidents: the same list built at two times has one ETag, a new incident another', () => {
  let list = [{ host: 'a.test:1', name: 'A', start: '2026-01-01T00:00:00.000Z', end: '2026-01-01T00:10:00.000Z', seconds: 600, ongoing: false }];
  let t = 0;
  const get = memoJson(() => publicIncidents(list, new Date(t).toISOString()), 1000, () => t);
  const a = get();
  t = 5000;
  const b = get();
  assert.notEqual(a.body, b.body);
  assert.equal(a.etag, b.etag);
  list = [...list, { ...list[0], start: '2026-01-02T00:00:00.000Z', end: null, ongoing: true }];
  t = 10_000;
  assert.notEqual(get().etag, a.etag);
  assert.equal(typeof publicStats, 'function');
});
