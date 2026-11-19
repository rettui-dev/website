import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Monitor } from '../lib/monitor.js';
import { createApp } from '../lib/app.js';
import { MAX_GAP_MS, MAX_VERSIONS, RANGES, buildSeries, cleanSamples, downsample, rates, sampleFrom, validSample } from '../lib/history.js';

const publicDir = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'public');
const tmp = () => fs.mkdtemp(path.join(os.tmpdir(), 'website-'));
const MIN = 60_000;
const NOW = 1_800_000_000_000;

const stats = (over = {}) => ({
  rettuiVersion: '2.0.0',
  generatedAt: 1,
  uptimeSeconds: 1000,
  interfaces: { total: 3, online: 2, clients: 5, rxBytes: 1000, txBytes: 500 },
  peersHeard: { total: 10, lxmf: 6, nomad: 3, propagation: 1 },
  announcesLastMinute: 4,
  ...over,
});

// [time, clients, rx, tx, peers, lxmf, nomad, prop, announces, uptime, ifaces]
const sample = (t, rx, tx, uptime, clients = 1) => [t, clients, rx, tx, 10, 6, 3, 1, 4, uptime, 2];

test('sampleFrom lays out the columns', () => {
  assert.deepEqual(sampleFrom(7, stats()), [7, 5, 1000, 500, 10, 6, 3, 1, 4, 1000, 2]);
  assert.equal(validSample(sampleFrom(7, stats())), true);
  assert.equal(validSample(sampleFrom(7, stats({ interfaces: { total: 1, online: 1, clients: null, rxBytes: 0, txBytes: 0 } }))), true);
});

test('validSample rejects damaged entries', () => {
  const ok = sample(5, 1, 1, 1);
  assert.equal(validSample(ok), true);
  for (const bad of [null, 'x', [], ok.slice(1), [...ok, 1], ok.map((v, i) => (i === 2 ? -1 : v)), ok.map((v, i) => (i === 3 ? NaN : v)), ok.map((v, i) => (i === 4 ? 1.5 : v)), ok.map((v, i) => (i === 0 ? 0 : v)), ok.map((v, i) => (i === 5 ? '3' : v)), ok.map((v, i) => (i === 1 ? undefined : v))]) {
    assert.equal(validSample(bad), false, JSON.stringify(bad));
  }
});

test('cleanSamples drops bad, out of order and old entries and caps the count', () => {
  const list = [sample(NOW - 10 * MIN, 1, 1, 1), 'junk', sample(NOW - 20 * MIN, 1, 1, 1), sample(NOW - 5 * MIN, 2, 2, 2), sample(NOW - 8 * 24 * 3600_000, 1, 1, 1)];
  assert.deepEqual(cleanSamples(list, NOW).map((s) => s[0]), [NOW - 10 * MIN, NOW - 5 * MIN]);
  assert.deepEqual(cleanSamples(list, NOW, 1).map((s) => s[0]), [NOW - 5 * MIN]);
  assert.deepEqual(cleanSamples({}, NOW), []);
});

test('rates: bytes per second between samples', () => {
  const r = rates([sample(0 + 1000, 0, 0, 10), sample(1000 + 10_000, 1000, 500, 20), sample(1000 + 20_000, 1000, 2500, 30)]);
  assert.deepEqual(r, [
    { t: 11_000, rx: 100, tx: 50 },
    { t: 21_000, rx: 0, tx: 200 },
  ]);
  assert.deepEqual(rates([]), []);
  assert.deepEqual(rates([sample(1, 1, 1, 1)]), []);
});

test('rates: a counter or uptime decrease is a restart and is skipped', () => {
  const t = (n) => 1000 + n * MIN;
  const r = rates([sample(t(0), 5000, 5000, 900), sample(t(1), 10, 20, 30), sample(t(2), 70, 80, 90), sample(t(3), 500, 40, 150), sample(t(4), 600, 400, 5)]);
  assert.deepEqual(r.map((x) => [x.rx, x.tx]), [[null, null], [1, 1], [null, null], [null, null]]);
  for (const x of r) for (const v of [x.rx, x.tx]) assert.ok(v === null || (Number.isFinite(v) && v >= 0));
});

test('rates: equal times, backwards time and long gaps give gaps, never NaN or negative', () => {
  const r = rates([sample(1000, 1, 1, 1), sample(1000, 2, 2, 2), sample(500, 3, 3, 3), sample(500 + MAX_GAP_MS + 1, 9, 9, 9), sample(500 + MAX_GAP_MS + 1 + MIN, 69, 9, 10)]);
  assert.deepEqual(r.map((x) => [x.rx, x.tx]), [[null, null], [null, null], [null, null], [1, 0]]);
});

test('downsample keeps short series and averages long ones', () => {
  assert.deepEqual(downsample([[1, 1], [2, null], [3, 3.14159]], 10), [[1, 1], [2, null], [3, 3.14]]);
  const points = Array.from({ length: 1000 }, (_, i) => [i, i % 2]);
  const d = downsample(points, 240);
  assert.equal(d.length, 240);
  assert.ok(d.every((p) => p[1] >= 0 && p[1] <= 1));
  assert.deepEqual(d.map((p) => p[0]), [...d.map((p) => p[0])].sort((a, b) => a - b));
  assert.equal(d.at(-1)[0], 999);
  assert.deepEqual(downsample([[1, null], [2, null], [3, null], [4, 8]], 2), [[2, null], [4, 8]]);
  assert.deepEqual(downsample([[1, 1]], 0), []);
  assert.deepEqual(downsample([], 5), []);
});

test('buildSeries limits to the range and to 240 points', () => {
  const samples = [];
  for (let i = 0; i < 2016; i++) samples.push(sample(NOW - (2015 - i) * 5 * MIN, i * 3000, i * 1000, 100 + i * 300, i % 7));
  for (const range of Object.keys(RANGES)) {
    const s = buildSeries(samples, range, NOW);
    assert.equal(s.range, range);
    assert.ok(s.sampleCount <= 2016);
    for (const list of [s.bytesIn, s.bytesOut, s.clients, s.peers.total, s.peers.lxmf, s.peers.nomad, s.peers.propagation, s.announces, s.interfacesOnline]) {
      assert.ok(list.length <= 240, `${range} has ${list.length}`);
      assert.ok(list.every((p) => p[0] >= NOW - RANGES[range]));
    }
  }
  const six = buildSeries(samples, '6h', NOW);
  assert.equal(six.sampleCount, 73);
  assert.equal(six.bytesIn.length, 73);
  assert.equal(six.bytesIn.at(-1)[1], 10);
  assert.equal(buildSeries(samples, '7d', NOW).bytesIn.length, 240);
});

test('buildSeries with no samples is empty', () => {
  const s = buildSeries([], '24h', NOW);
  assert.equal(s.sampleCount, 0);
  assert.deepEqual(s.bytesIn, []);
  assert.deepEqual(s.peers.total, []);
});

function monitorWith(dataDir, { now, fetcher, interval = 5 * MIN, max } = {}) {
  return new Monitor({
    targets: [{ host: 'a.test', port: 1 }],
    dataDir,
    probeFn: async () => ({ up: true, ms: 1 }),
    statsUrls: new Map([['a.test:1', 'https://a.test/s.json']]),
    statsFn: fetcher,
    now,
    sampleIntervalMs: interval,
    maxSamples: max,
  });
}

test('the monitor samples about every 5 minutes, not every cycle', async () => {
  const dir = await tmp();
  let clock = NOW;
  const m = monitorWith(dir, { now: () => clock, fetcher: async () => ({ ok: true, data: stats() }) });
  for (let i = 0; i < 20; i++) {
    await m.checkAll();
    clock += 30_000;
  }
  const samples = m.statsHistory.get('a.test:1').samples;
  assert.equal(samples.length, 2);
  assert.equal(samples[1][0] - samples[0][0], 300_000);
  assert.deepEqual(samples[0], sampleFrom(NOW, stats()));
});

test('failed fetches are not sampled, and hosts without a stats URL have no history', async () => {
  const dir = await tmp();
  const m = monitorWith(dir, { now: () => NOW, fetcher: async () => ({ ok: false, error: 'network' }) });
  await m.checkAll();
  assert.equal(m.statsHistory.get('a.test:1').samples.length, 0);
  await assert.rejects(fs.stat(path.join(dir, 'stats-history.json')));
  const plain = new Monitor({ targets: [{ host: 'a.test', port: 1 }], dataDir: dir, probeFn: async () => ({ up: true, ms: 1 }) });
  assert.equal(plain.statsHistory.size, 0);
  assert.equal(plain.detail('a.test:1', '24h'), null);
});

test('samples are capped at the maximum', async () => {
  const dir = await tmp();
  let clock = NOW;
  const m = monitorWith(dir, { now: () => clock, fetcher: async () => ({ ok: true, data: stats() }), max: 5 });
  for (let i = 0; i < 12; i++) {
    await m.checkAll();
    clock += 5 * MIN;
  }
  const samples = m.statsHistory.get('a.test:1').samples;
  assert.equal(samples.length, 5);
  assert.equal(samples.at(-1)[0], NOW + 11 * 5 * MIN);
});

test('a clock that goes backwards does not add a sample', async () => {
  const dir = await tmp();
  let clock = NOW;
  const m = monitorWith(dir, { now: () => clock, fetcher: async () => ({ ok: true, data: stats() }) });
  await m.checkAll();
  clock -= 10 * MIN;
  await m.checkAll();
  assert.equal(m.statsHistory.get('a.test:1').samples.length, 1);
});

test('versions seen are listed once per change and capped', async () => {
  const dir = await tmp();
  let clock = NOW;
  let version = '1.0.0';
  const m = monitorWith(dir, { now: () => clock, fetcher: async () => ({ ok: true, data: stats({ rettuiVersion: version }) }) });
  await m.checkAll();
  clock += 30_000;
  await m.checkAll();
  assert.deepEqual(m.statsHistory.get('a.test:1').versions, [['1.0.0', NOW]]);
  for (let i = 0; i < 15; i++) {
    version = `2.${i}.0`;
    clock += 30_000;
    await m.checkAll();
  }
  const v = m.statsHistory.get('a.test:1').versions;
  assert.equal(v.length, MAX_VERSIONS);
  assert.equal(v.at(-1)[0], '2.14.0');
  version = null;
  clock += 30_000;
  await m.checkAll();
  assert.equal(m.statsHistory.get('a.test:1').versions.at(-1)[0], '2.14.0');
});

test('stats history persists in its own file and history.json is unchanged', async () => {
  const dir = await tmp();
  let clock = NOW;
  const m = monitorWith(dir, { now: () => clock, fetcher: async () => ({ ok: true, data: stats() }) });
  await m.checkAll();
  clock += 5 * MIN;
  await m.checkAll();
  assert.deepEqual((await fs.readdir(dir)).sort(), ['history.json', 'stats-history.json']);
  assert.equal(((await fs.stat(path.join(dir, 'stats-history.json'))).mode & 0o777).toString(8), '600');
  const saved = JSON.parse(await fs.readFile(path.join(dir, 'history.json'), 'utf8'));
  assert.deepEqual(Object.keys(saved).sort(), ['hosts', 'version']);
  assert.equal(JSON.stringify(saved).includes('rxBytes'), false);

  const again = monitorWith(dir, { now: () => clock, fetcher: async () => ({ ok: false, error: 'x' }) });
  await again.load();
  assert.deepEqual(again.statsHistory.get('a.test:1'), m.statsHistory.get('a.test:1'));
  assert.equal(again.history.get('a.test:1').length, 2);
});

test('an older history.json without stats still loads, and starts without stats samples', async () => {
  const dir = await tmp();
  await fs.writeFile(path.join(dir, 'history.json'), JSON.stringify({ version: 1, hosts: { 'a.test:1': [[1, 1, 5]] } }));
  const m = monitorWith(dir, { now: () => NOW, fetcher: async () => ({ ok: false, error: 'x' }) });
  await m.load();
  assert.equal(m.history.get('a.test:1').length, 1);
  assert.equal(m.statsHistory.get('a.test:1').samples.length, 0);
});

test('a damaged stats-history.json is handled entry by entry', async () => {
  const dir = await tmp();
  const file = path.join(dir, 'stats-history.json');
  const load = async () => {
    const m = monitorWith(dir, { now: () => NOW, fetcher: async () => ({ ok: false, error: 'x' }) });
    await m.load();
    return m.statsHistory.get('a.test:1');
  };
  const good = sample(NOW - 10 * MIN, 1, 1, 1);
  await fs.writeFile(
    file,
    JSON.stringify({
      version: 1,
      hosts: {
        'a.test:1': { samples: [good, 'x', [1, 2], sample(NOW - 20 * MIN, 1, 1, 1), sample(NOW - 5 * MIN, -1, 1, 1)], versions: [['1.0', 5], ['', 1], [3, 3], ['x'.repeat(40), 1], 'junk'] },
        'gone.test:9': { samples: [good], versions: [] },
      },
    }),
  );
  const h = await load();
  assert.deepEqual(h.samples, [good]);
  assert.deepEqual(h.versions, [['1.0', 5]]);

  for (const bad of ['{not json', '', 'null', '[]', '{"hosts":null}', '{"hosts":[]}', '{"hosts":{"a.test:1":"x"}}', '{"hosts":{"a.test:1":{"samples":5,"versions":{}}}}', '{"hosts":{"__proto__":{}}}']) {
    await fs.writeFile(file, bad);
    const empty = await load();
    assert.deepEqual(empty, { samples: [], versions: [] }, bad);
  }
  await fs.rm(file);
  assert.deepEqual(await load(), { samples: [], versions: [] });
});

test('an oversized stats-history.json is ignored', async () => {
  const dir = await tmp();
  await fs.writeFile(path.join(dir, 'stats-history.json'), JSON.stringify({ hosts: { 'a.test:1': { samples: [sample(NOW - MIN, 1, 1, 1)], versions: [] } } }) + ' '.repeat(9 * 1024 * 1024));
  const m = monitorWith(dir, { now: () => NOW, fetcher: async () => ({ ok: false, error: 'x' }) });
  await m.load();
  assert.equal(m.statsHistory.get('a.test:1').samples.length, 0);
});

test('detail combines current stats, versions and series', async () => {
  const dir = await tmp();
  let clock = NOW;
  const m = monitorWith(dir, { now: () => clock, fetcher: async () => ({ ok: true, data: stats({ uptimeSeconds: 99 }) }) });
  await m.checkAll();
  const d = m.detail('a.test:1', '6h');
  assert.deepEqual(Object.keys(d).sort(), ['generatedAt', 'host', 'range', 'series', 'stats', 'version']);
  assert.equal(d.stats.data.rettuiVersion, '2.0.0');
  assert.deepEqual(d.version, { current: '2.0.0', uptimeSeconds: 99, history: [{ version: '2.0.0', firstSeen: new Date(NOW).toISOString() }] });
  assert.equal(d.series.sampleCount, 1);
  assert.equal(m.detail('a.test:1', '5y'), null);
  assert.equal(m.snapshot().hosts[0].hasDetail, true);
});

async function withApp(fn) {
  const dir = await tmp();
  let clock = Date.now() - 30 * MIN;
  const m = new Monitor({
    targets: [
      { host: 'a.test', port: 1 },
      { host: 'b.test', port: 1 },
    ],
    dataDir: dir,
    probeFn: async () => ({ up: true, ms: 1 }),
    statsUrls: new Map([['a.test:1', 'https://a.test/s.json']]),
    statsFn: async () => ({ ok: true, data: stats({ interfaces: { total: 3, online: 2, clients: 5, rxBytes: clock % 100000, txBytes: 500 } }) }),
    now: () => clock,
    sampleIntervalMs: 1000,
  });
  for (let i = 0; i < 4; i++) {
    await m.checkAll();
    clock += 5 * MIN;
  }
  const server = createApp({ monitor: m, publicDir });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  try {
    await fn(port);
  } finally {
    server.closeAllConnections();
    await new Promise((r) => server.close(r));
  }
}

const get = (port, p, method = 'GET') =>
  new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path: p, method }, (res) => {
      let body = '';
      res.on('data', (c) => (body += c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
    });
    req.on('error', reject);
    req.end();
  });

test('/api/stats returns the detail for a configured host', async () => {
  await withApp(async (port) => {
    const r = await get(port, '/api/stats?host=a.test:1&range=6h');
    assert.equal(r.status, 200);
    assert.match(r.headers['content-type'], /^application\/json/);
    assert.equal(r.headers['cache-control'], 'no-store');
    assert.match(r.headers['content-security-policy'], /connect-src 'self'/);
    const body = JSON.parse(r.body);
    assert.equal(body.host, 'a.test:1');
    assert.equal(body.range, '6h');
    assert.equal(body.stats.ok, true);
    assert.equal(body.version.current, '2.0.0');
    assert.equal(body.series.sampleCount, 4);
    assert.deepEqual(Object.keys(body.series).sort(), ['announces', 'bytesIn', 'bytesOut', 'clients', 'from', 'interfacesOnline', 'peers', 'range', 'sampleCount', 'to']);
    assert.deepEqual(Object.keys(body.series.peers).sort(), ['lxmf', 'nomad', 'propagation', 'total']);
    assert.equal(body.series.bytesIn.length, 3);

    const def = JSON.parse((await get(port, '/api/stats?host=A.test:1')).body);
    assert.equal(def.range, '24h');
    for (const range of ['6h', '24h', '7d']) assert.equal((await get(port, `/api/stats?host=a.test:1&range=${range}`)).status, 200);

    const head = await get(port, '/api/stats?host=a.test:1&range=7d', 'HEAD');
    assert.equal(head.status, 200);
    assert.equal(head.body, '');
    assert.equal((await get(port, '/api/stats?host=a.test:1', 'POST')).status, 405);
  });
});

test('/api/stats: unknown or unconfigured host is 404, bad range is 400', async () => {
  await withApp(async (port) => {
    for (const q of ['', '?host=', '?host=b.test:1', '?host=nope.test:1&range=6h', '?host=a.test', '?host=__proto__', '?host=constructor']) {
      const r = await get(port, `/api/stats${q}`);
      assert.equal(r.status, 404, q);
      assert.equal(r.headers['cache-control'], 'no-store');
      assert.deepEqual(JSON.parse(r.body), { error: 'unknown host' });
    }
    for (const range of ['', '1h', '30d', '6H', 'toString', '__proto__']) {
      const r = await get(port, `/api/stats?host=a.test:1&range=${range}`);
      assert.equal(r.status, 400, range);
      assert.equal(r.headers['cache-control'], 'no-store');
    }
  });
});
