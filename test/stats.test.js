import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { parseStatsUrls, sanitizeStats, fetchStats } from '../lib/stats.js';
import { Monitor, PROBE_INTERVAL_MS } from '../lib/monitor.js';

const targets = [
  { host: 'a.test', port: 4242 },
  { host: 'b.test', port: 4242 },
];

const good = () => ({
  version: 1,
  rettui_version: '2.0.0',
  generated_at: 1763528000,
  uptime_seconds: 12345,
  interfaces: {
    total: 3,
    online: 3,
    clients: 17,
    rx_bytes: 123,
    tx_bytes: 456,
    list: [{ name: 'TCP Server', online: true, clients: null, rx_bytes: 1, tx_bytes: 2 }],
  },
  peers_heard: { total: 100, lxmf: 60, nomad: 30, propagation: 10 },
  announces_last_minute: 12,
});

const respond = (body, init) => async () => new Response(typeof body === 'string' ? body : JSON.stringify(body), init);

test('parseStatsUrls: empty means none', () => {
  assert.equal(parseStatsUrls(undefined, targets).size, 0);
  assert.equal(parseStatsUrls('', targets).size, 0);
});

test('parseStatsUrls accepts pairs for monitored hosts', () => {
  const m = parseStatsUrls(' A.test:4242=https://a.test/stats.json , b.test:4242=http://127.0.0.1:9/s.json,', targets);
  assert.equal(m.get('a.test:4242'), 'https://a.test/stats.json');
  assert.equal(m.get('b.test:4242'), 'http://127.0.0.1:9/s.json');
});

test('parseStatsUrls allows plain http only for loopback and private hosts', () => {
  for (const h of ['localhost', '127.0.0.1', '127.9.9.9', '10.1.2.3', '172.16.0.1', '172.31.255.1', '192.168.1.1', '[::1]']) {
    assert.equal(parseStatsUrls(`a.test:4242=http://${h}:8/s`, targets).size, 1, h);
  }
});

test('parseStatsUrls errors never repeat the URL', () => {
  for (const bad of ['a.test:4242=https://user:SECRET@a.test/s', 'a.test:4242=http://a.test/s?token=SECRET', 'https://x.test/?t=SECRET', 'zzz.test:1=https://a.test/?t=SECRET', 'a.test:4242=ftp://a.test/?t=SECRET']) {
    assert.throws(() => parseStatsUrls(bad, targets), (e) => !e.message.includes('SECRET'), bad);
  }
});

test('parseStatsUrls rejects bad input', () => {
  for (const bad of [
    'a.test:4242',
    '=https://a.test/s',
    'a.test:4242=',
    'a.test:4242=ftp://a.test/s',
    'a.test:4242=file:///etc/passwd',
    'a.test:4242=javascript:alert(1)',
    'a.test:4242=not a url',
    'a.test:4242=https://user:pw@a.test/s',
    'other.test:4242=https://a.test/s',
    'a.test:1=https://a.test/s',
    'a.test:4242=https://a.test/s,a.test:4242=https://a.test/t',
    'a.test:4242=http://a.test/s',
    'a.test:4242=http://8.8.8.8/s',
    'a.test:4242=http://172.32.0.1/s',
    'a.test:4242=http://10.0.0.1.evil.test/s',
  ]) {
    assert.throws(() => parseStatsUrls(bad, targets), Error, bad);
  }
});

test('sanitizeStats gives the fixed shape', () => {
  const d = sanitizeStats(good());
  assert.deepEqual(d, {
    rettuiVersion: '2.0.0',
    generatedAt: 1763528000,
    uptimeSeconds: 12345,
    interfaces: {
      total: 3,
      online: 3,
      clients: 17,
      rxBytes: 123,
      txBytes: 456,
    },
    peersHeard: { total: 100, lxmf: 60, nomad: 30, propagation: 10 },
    announcesLastMinute: 12,
  });
});

test('sanitizeStats clamps numbers and caps strings', () => {
  const p = good();
  p.uptime_seconds = 1e300;
  p.announces_last_minute = -5;
  p.peers_heard.total = 12.9;
  p.interfaces.clients = undefined;
  p.rettui_version = 'v'.repeat(500) + '\u0000\u001b';
  const d = sanitizeStats(p);
  assert.equal(d.uptimeSeconds, Number.MAX_SAFE_INTEGER);
  assert.equal(d.announcesLastMinute, 0);
  assert.equal(d.peersHeard.total, 12);
  assert.equal(d.interfaces.clients, null);
  assert.equal(d.rettuiVersion.length, 32);
});

test('sanitizeStats drops unknown keys', () => {
  const p = { ...good(), extra: 1, __proto__: { x: 1 } };
  p.interfaces.secret = 'x';
  const d = sanitizeStats(p);
  assert.deepEqual(Object.keys(d).sort(), ['announcesLastMinute', 'generatedAt', 'interfaces', 'peersHeard', 'rettuiVersion', 'uptimeSeconds']);
  assert.ok(!('secret' in d.interfaces));
  assert.ok(!('list' in d.interfaces));
});

test('sanitizeStats rejects hostile payloads', () => {
  const cases = {
    'not an object': 'hi',
    null: null,
    array: [],
    'wrong version': { ...good(), version: 2 },
    'string number': { ...good(), uptime_seconds: '12' },
    'null number': { ...good(), uptime_seconds: null },
    'missing interfaces': { ...good(), interfaces: undefined },
    'interfaces array': { ...good(), interfaces: [] },
    'bad clients type': { ...good(), interfaces: { ...good().interfaces, clients: 'many' } },
    'missing peers': { ...good(), peers_heard: undefined },
  };
  for (const [name, payload] of Object.entries(cases)) {
    assert.throws(() => sanitizeStats(payload), Error, name);
  }
});

test('fetchStats returns clean data', async () => {
  const r = await fetchStats('http://x.test/s', { fetchFn: respond(good()) });
  assert.equal(r.ok, true);
  assert.equal(r.data.uptimeSeconds, 12345);
});

test('fetchStats asks not to follow redirects and sets a timeout', async () => {
  let seen;
  await fetchStats('http://x.test/s', {
    fetchFn: async (url, opts) => {
      seen = opts;
      return new Response(JSON.stringify(good()));
    },
  });
  assert.equal(seen.redirect, 'error');
  assert.ok(seen.signal instanceof AbortSignal);
});

test('fetchStats failure codes', async () => {
  const out = async (fetchFn, opts) => (await fetchStats('http://x.test/s', { fetchFn, ...opts }));
  assert.deepEqual(await out(respond('x', { status: 500 })), { ok: false, error: 'http 500' });
  assert.deepEqual(await out(respond('{not json')), { ok: false, error: 'invalid' });
  assert.deepEqual(await out(respond('{}')), { ok: false, error: 'invalid' });
  assert.deepEqual(await out(respond('')), { ok: false, error: 'invalid' });
  assert.deepEqual(await out(async () => { throw new TypeError('fetch failed'); }), { ok: false, error: 'network' });
  assert.deepEqual(await out(async () => { throw new DOMException('t', 'TimeoutError'); }), { ok: false, error: 'timeout' });
});

test('fetchStats refuses an oversized body, by header and by streaming', async () => {
  const big = JSON.stringify({ ...good(), pad: 'x'.repeat(2000) });
  const r1 = await fetchStats('http://x.test/s', { fetchFn: respond(big), maxBytes: 1000 });
  assert.deepEqual(r1, { ok: false, error: 'too large' });
  // No content-length: the reader has to stop on its own.
  let cancelled = false;
  const body = new ReadableStream({
    pull(c) {
      c.enqueue(new Uint8Array(400));
    },
    cancel() {
      cancelled = true;
    },
  });
  const r2 = await fetchStats('http://x.test/s', { fetchFn: async () => new Response(body), maxBytes: 1000 });
  assert.deepEqual(r2, { ok: false, error: 'too large' });
  assert.equal(cancelled, true);
});

test('fetchStats really times out', async () => {
  const hang = (url, { signal }) => new Promise((_, reject) => signal.addEventListener('abort', () => reject(signal.reason)));
  // The timeout timer does not keep the process alive, so this one does.
  const keep = setTimeout(() => {}, 2000);
  const r = await fetchStats('http://x.test/s', { fetchFn: hang, timeoutMs: 20 });
  clearTimeout(keep);
  assert.deepEqual(r, { ok: false, error: 'timeout' });
});

const tmp = () => fs.mkdtemp(path.join(os.tmpdir(), 'website-'));
const up = async () => ({ up: true, ms: 3 });

test('monitor: no stats URLs means stats is null and nothing is fetched', async () => {
  let calls = 0;
  const m = new Monitor({ targets, dataDir: await tmp(), probeFn: up, statsFn: async () => (calls++, { ok: true, data: {} }) });
  await m.checkAll();
  assert.equal(calls, 0);
  assert.equal(m.snapshot().hosts[0].stats, null);
});

test('monitor: stats are per host, and failures stay independent', async () => {
  const statsUrls = parseStatsUrls('a.test:4242=https://a.test/s', targets);
  let ok = true;
  let t = 1_000_000;
  const m = new Monitor({
    targets,
    dataDir: await tmp(),
    probeFn: up,
    now: () => t,
    statsUrls,
    statsFn: async () => (ok ? { ok: true, data: sanitizeStats(good()) } : { ok: false, error: 'timeout' }),
  });
  assert.deepEqual(m.snapshot().hosts[0].stats, { ok: false, fetchedAt: null, stale: false, error: 'not fetched yet' });
  await m.checkAll();
  let s = m.snapshot();
  assert.equal(s.hosts[1].stats, null);
  assert.equal(s.hosts[0].stats.ok, true);
  assert.equal(s.hosts[0].stats.stale, false);
  assert.equal(s.hosts[0].stats.fetchedAt, new Date(1_000_000).toISOString());
  assert.equal(s.hosts[0].stats.data.interfaces.clients, 17);
  assert.equal(s.hosts[0].status, 'up');

  // A failing fetch keeps the last good data and does not touch the probe.
  ok = false;
  t += PROBE_INTERVAL_MS;
  await m.checkAll();
  let st = m.snapshot().hosts[0].stats;
  assert.equal(st.ok, false);
  assert.equal(st.error, 'timeout');
  assert.equal(st.stale, false);
  assert.equal(st.data.uptimeSeconds, 12345);
  assert.equal(m.snapshot().hosts[0].status, 'up');

  // Past three intervals the kept data is marked stale.
  t += 3 * PROBE_INTERVAL_MS;
  st = m.snapshot().hosts[0].stats;
  assert.equal(st.stale, true);
});

test('monitor: stats that never worked have no data, and a throwing fetch is contained', async () => {
  const m = new Monitor({
    targets,
    dataDir: await tmp(),
    probeFn: up,
    statsUrls: parseStatsUrls('a.test:4242=https://a.test/s', targets),
    statsFn: async () => {
      throw new Error('boom');
    },
  });
  await m.checkAll();
  const st = m.snapshot().hosts[0].stats;
  assert.equal(st.ok, false);
  assert.equal(st.error, 'network');
  assert.equal('data' in st, false);
  assert.equal(m.snapshot().hosts[0].status, 'up');
});

test('monitor: stats are never saved to history.json', async () => {
  const dir = await tmp();
  const m = new Monitor({
    targets,
    dataDir: dir,
    probeFn: up,
    statsUrls: parseStatsUrls('a.test:4242=https://a.test/s', targets),
    statsFn: async () => ({ ok: true, data: sanitizeStats(good()) }),
  });
  await m.checkAll();
  const saved = JSON.parse(await fs.readFile(path.join(dir, 'history.json'), 'utf8'));
  assert.deepEqual(Object.keys(saved).sort(), ['hosts', 'version']);
  assert.ok(!JSON.stringify(saved).includes('uptime'));
});
