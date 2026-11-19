import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { combineSeries, RANGES } from '../lib/history.js';
import { Monitor } from '../lib/monitor.js';
import { createApp } from '../lib/app.js';
import { loadConfig } from '../lib/config.js';

const publicDir = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'public');
const MIN = 60_000;
const NOW = 1_800_000_000_000;
// [time, clients, rx, tx, peers, lxmf, nomad, prop, announces, uptime, ifaces]
const smp = (t, { rx = 0, tx = 0, up = 1, clients = 1, peers = 10, ann = 1 } = {}) => [t, clients, rx, tx, peers, peers, 0, 0, ann, up, 2];

test('combineSeries adds up aligned samples, rates included', () => {
  const a = [smp(NOW - 10 * MIN, { rx: 0, tx: 0, up: 100 }), smp(NOW - 5 * MIN, { rx: 3000, tx: 600, up: 400, clients: 2, peers: 50, ann: 4 }), smp(NOW, { rx: 6000, tx: 1200, up: 700, clients: 3, peers: 60, ann: 5 })];
  // The second node samples a few seconds later each time.
  const b = [smp(NOW - 10 * MIN + 4000, { rx: 0, tx: 0, up: 50 }), smp(NOW - 5 * MIN + 7000, { rx: 300, tx: 3000, up: 350, clients: 10, peers: 30, ann: 6 }), smp(NOW + 2000, { rx: 600, tx: 6000, up: 650, clients: 20, peers: 90, ann: 7 })];
  const s = combineSeries([a, b], '6h', NOW + 5000);
  assert.equal(s.members, 2);
  assert.equal(s.sampleCount, 3);
  // The nodes' clocks differ by a few seconds, so the rates are close to 11 and 12, not exact.
  const whole = (list) => list.map((p) => (p[1] === null ? null : Math.round(p[1])));
  assert.deepEqual(whole(s.bytesIn), [null, 11, 11]);
  assert.deepEqual(whole(s.bytesOut), [null, 12, 12]);
  assert.deepEqual(s.clients.map((p) => p[1]), [2, 12, 23]);
  assert.deepEqual(s.announces.map((p) => p[1]), [2, 10, 12]);
  assert.deepEqual(s.interfacesOnline.map((p) => p[1]), [4, 4, 4]);
  // Peers: the sum is the upper bound, the largest single node the lower bound.
  assert.deepEqual(s.peers.total.map((p) => p[1]), [20, 80, 150]);
  assert.deepEqual(s.peersLow.total.map((p) => p[1]), [10, 50, 90]);
});

test('combineSeries: a point is a gap unless every member has a sample in it', () => {
  const a = [0, 1, 2, 3].map((i) => smp(NOW - (3 - i) * 5 * MIN, { rx: i * 300, up: i * 300 + 10 }));
  const b = [0, 1, 3].map((i) => smp(NOW - (3 - i) * 5 * MIN + 1000, { rx: i * 300, up: i * 300 + 10 }));
  const s = combineSeries([a, b], '6h', NOW + 10_000);
  assert.equal(s.sampleCount, 3);
  assert.deepEqual(s.clients.map((p) => p[1]), [2, 2, null, 2]);
  // The point with a missing sample is a gap; the one after it is measured across the hole (10 minutes, under the 30 minute limit).
  assert.deepEqual(s.bytesIn.map((p) => p[1]), [null, 2, null, 2]);
});

test('combineSeries: a member restart leaves a gap in the rates, not in the counts', () => {
  const a = [smp(NOW - 10 * MIN, { rx: 1000, up: 1000 }), smp(NOW - 5 * MIN, { rx: 4000, up: 1300 }), smp(NOW, { rx: 7000, up: 1600 })];
  const b = [smp(NOW - 10 * MIN, { rx: 9000, up: 9000 }), smp(NOW - 5 * MIN, { rx: 50, up: 20 }), smp(NOW, { rx: 350, up: 320 })];
  const s = combineSeries([a, b], '24h', NOW);
  assert.deepEqual(s.bytesIn.map((p) => p[1]), [null, null, 11]);
  assert.deepEqual(s.clients.map((p) => p[1]), [2, 2, 2]);
  for (const p of [...s.bytesIn, ...s.bytesOut]) assert.ok(p[1] === null || (Number.isFinite(p[1]) && p[1] >= 0));
});

test('combineSeries: unknown clients in one member make the sum unknown', () => {
  const a = [smp(NOW - 5 * MIN, { clients: null }), smp(NOW, { clients: null })];
  const b = [smp(NOW - 5 * MIN), smp(NOW)];
  assert.deepEqual(combineSeries([a, b], '6h', NOW).clients.map((p) => p[1]), [null, null]);
});

test('combineSeries: range, downsampling and empty inputs', () => {
  const long = (off) => Array.from({ length: 2016 }, (_, i) => smp(NOW - (2015 - i) * 5 * MIN + off, { rx: i * 10, up: i * 300 + 1 }));
  const s = combineSeries([long(0), long(3000)], '7d', NOW + 10_000);
  assert.equal(s.bytesIn.length, 240);
  assert.equal(s.peers.total.length, 240);
  assert.ok(s.sampleCount > 2000);
  const six = combineSeries([long(0), long(3000)], '6h', NOW + 10_000);
  assert.ok(six.clients.every((p) => p[0] >= NOW + 10_000 - RANGES['6h']));
  const none = combineSeries([], '24h', NOW);
  assert.equal(none.sampleCount, 0);
  assert.deepEqual(none.bytesIn, []);
  assert.equal(combineSeries([[], []], '24h', NOW).sampleCount, 0);
  // One member only: the combined series is that member.
  const one = combineSeries([[smp(NOW - 5 * MIN, { clients: 4 }), smp(NOW, { clients: 6 })]], '6h', NOW);
  assert.deepEqual(one.clients.map((p) => p[1]), [4, 6]);
});

const stats = (o = {}) => ({
  rettuiVersion: '2.0.0',
  generatedAt: 1,
  uptimeSeconds: 100,
  interfaces: { total: 2, online: 2, clients: 5, rxBytes: 1000, txBytes: 400 },
  peersHeard: { total: 10, lxmf: 6, nomad: 3, propagation: 1 },
  announcesLastMinute: 4,
  ...o,
});

async function setup(yamlExtra = '') {
  const config = loadConfig(`nodes:
  - address: p.test:1
    name: Door
    stats_url: https://p.test/s
    proxy_for: [a.test:1, b.test:1, n.test:1]
${yamlExtra}
  - address: a.test:1
    stats_url: https://a.test/s
  - address: b.test:1
    stats_url: https://b.test/s
  - address: n.test:1
  - address: z.test:1
    stats_url: https://z.test/s
`);
  let clock = NOW - 30 * MIN;
  const monitor = new Monitor({
    targets: config.targets,
    nodes: config.nodes,
    statsUrls: config.statsUrls,
    dataDir: await fs.mkdtemp(path.join(os.tmpdir(), 'website-')),
    probeFn: async () => ({ up: true, ms: 1 }),
    statsFn: async (url) => ({ ok: true, data: stats({ interfaces: { total: 2, online: 2, clients: 5, rxBytes: (clock - NOW) / 1000 + 1e6, txBytes: 1e6 }, uptimeSeconds: 500 + Math.floor((clock - NOW) / 1000 + 1800) , rettuiVersion: url.includes('b.test') ? '2.1.0' : '2.0.0' }) }),
    now: () => clock,
    sampleIntervalMs: 1000,
  });
  for (let i = 0; i < 6; i++) {
    await monitor.checkAll();
    clock += 5 * MIN;
  }
  // Back to the time of the last fetch, so its stats are not yet stale.
  clock -= 5 * MIN;
  const server = createApp({ monitor, publicDir });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const get = (p, method = 'GET') =>
    new Promise((resolve, reject) => {
      const req = http.request({ host: '127.0.0.1', port: server.address().port, path: p, method }, (res) => {
        let body = '';
        res.on('data', (c) => (body += c));
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
      });
      req.on('error', reject);
      req.end();
    });
  return { monitor, get, close: () => (server.closeAllConnections(), new Promise((r) => server.close(r))) };
}

test('/api/stats?view=combined returns the group, the members and summed series', async () => {
  const s = await setup();
  try {
    const r = await s.get('/api/stats?host=p.test:1&range=6h&view=combined');
    assert.equal(r.status, 200);
    assert.equal(r.headers['cache-control'], 'no-store');
    assert.match(r.headers['content-security-policy'], /connect-src 'self'/);
    const d = JSON.parse(r.body);
    assert.deepEqual(Object.keys(d).sort(), ['excluded', 'generatedAt', 'group', 'host', 'members', 'range', 'sampleIntervalSeconds', 'series', 'view']);
    assert.equal(d.view, 'combined');
    assert.deepEqual(d.members.map((m) => [m.host, m.version, m.hasHistory]), [['a.test:1', '2.0.0', true], ['b.test:1', '2.1.0', true], ['n.test:1', null, false]]);
    assert.deepEqual(d.excluded, ['n.test:1']);
    assert.equal(d.group.nodes, 3);
    assert.equal(d.group.reporting, 2);
    assert.equal(d.group.partial, true);
    assert.equal(d.series.members, 2);
    assert.equal(d.series.sampleCount, 6);
    assert.deepEqual(d.series.clients.map((p) => p[1]), [10, 10, 10, 10, 10, 10]);
    assert.equal(d.series.peers.total.at(-1)[1], 20);
    assert.equal(d.series.peersLow.total.at(-1)[1], 10);
    assert.deepEqual(Object.keys(d.series).sort(), ['announces', 'bytesIn', 'bytesOut', 'clients', 'disk', 'from', 'interfacesOnline', 'members', 'peers', 'peersLow', 'propagation', 'range', 'sampleCount', 'to']);
    // Cached like the single view.
    assert.equal((await s.get('/api/stats?host=p.test:1&range=6h&view=combined')).body, r.body);
    assert.equal((await s.get('/api/stats?host=p.test:1&range=6h&view=combined', 'HEAD')).body, '');
    const single = JSON.parse((await s.get('/api/stats?host=p.test:1&range=6h&view=node')).body);
    assert.equal(single.view, undefined);
    assert.equal(single.host, 'p.test:1');
  } finally {
    await s.close();
  }
});

test('/api/stats view errors: unknown host 404, bad range or view 400, not a proxy 400', async () => {
  const s = await setup();
  try {
    const status = async (q) => (await s.get(`/api/stats${q}`)).status;
    assert.equal(await status('?host=nope.test:1&view=combined'), 404);
    assert.equal(await status('?view=combined'), 404);
    assert.equal(await status('?host=__proto__&view=combined'), 404);
    assert.equal(await status('?host=n.test:1'), 404);
    assert.equal(await status('?host=p.test:1&range=1h&view=combined'), 400);
    for (const v of ['', 'all', 'COMBINED', 'toString', '__proto__']) assert.equal(await status(`?host=p.test:1&view=${v}`), 400, v);
    assert.equal(await status('?host=a.test:1&view=combined'), 400);
    assert.equal(await status('?host=z.test:1&view=combined'), 400);
    assert.equal((await s.get('/api/stats?host=a.test:1&view=combined')).headers['cache-control'], 'no-store');
    assert.equal(await status('?host=p.test:1&view=node'), 200);
    assert.equal(await status('?host=p.test:1'), 200);
  } finally {
    await s.close();
  }
});

test('count_own adds the proxy to the combined series; hasDetail covers proxies', async () => {
  const s = await setup('    count_own: true');
  try {
    const d = JSON.parse((await s.get('/api/stats?host=p.test:1&range=6h&view=combined')).body);
    assert.equal(d.series.members, 3);
    assert.equal(d.series.clients.at(-1)[1], 15);
    assert.deepEqual(d.members.map((m) => m.host), ['p.test:1', 'a.test:1', 'b.test:1', 'n.test:1']);
    const hosts = Object.fromEntries(s.monitor.snapshot().hosts.map((h) => [h.host, h.hasDetail]));
    assert.deepEqual(hosts, { 'p.test': true, 'a.test': true, 'b.test': true, 'n.test': false, 'z.test': true });
  } finally {
    await s.close();
  }
});

test('a proxy without its own stats URL still has a combined view', async () => {
  const config = loadConfig(`nodes:
  - address: p.test:1
    proxy_for: [a.test:1]
  - address: a.test:1
    stats_url: https://a.test/s
`);
  const monitor = new Monitor({
    targets: config.targets,
    nodes: config.nodes,
    statsUrls: config.statsUrls,
    dataDir: await fs.mkdtemp(path.join(os.tmpdir(), 'website-')),
    probeFn: async () => ({ up: true, ms: 1 }),
    statsFn: async () => ({ ok: true, data: stats() }),
  });
  await monitor.checkAll();
  assert.equal(monitor.snapshot().hosts[0].hasDetail, true);
  assert.equal(monitor.detail('p.test:1', '6h'), null);
  assert.equal(monitor.detail('p.test:1', '6h', 'combined').members.length, 1);
});
