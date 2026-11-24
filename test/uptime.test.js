import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { UptimeLog, KEEP_DAYS, MAX_INCIDENTS_PER_NODE, MAX_INCIDENTS_TOTAL, MAX_UPTIME_FILE_BYTES, percentOf, dayOf } from '../lib/uptime.js';
import { Monitor } from '../lib/monitor.js';
import { createApp } from '../lib/app.js';

const tmp = () => fs.mkdtemp(path.join(os.tmpdir(), 'website-'));
const publicDir = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'public');
const DAY = 86_400_000;
const T0 = Date.UTC(2026, 10, 19, 12, 0, 0);
const K = 'a.test:1';

// Feeds a list of results (1 up, 0 down) at 30 second steps from `from`; returns all events.
function feed(log, results, from = T0, key = K) {
  const events = [];
  results.forEach((up, i) => events.push(...log.record(key, up === 1, from + i * 30_000)));
  return events;
}

test('one dropped probe is not an incident', () => {
  const log = new UptimeLog([K], { now: () => T0 });
  assert.deepEqual(feed(log, [1, 1, 0, 1, 1, 0, 1]), []);
  assert.deepEqual(log.incidents(K), []);
});

test('two failed checks open an incident that starts at the first failure', () => {
  const log = new UptimeLog([K], { now: () => T0 + 10 * 30_000 });
  const events = feed(log, [1, 0, 0]);
  assert.equal(events.length, 1);
  assert.deepEqual(events[0], { type: 'down', key: K, start: T0 + 30_000, end: null, at: T0 + 60_000 });
  const [i] = log.incidents(K);
  assert.equal(i.ongoing, true);
  assert.equal(i.end, null);
  assert.equal(i.start, new Date(T0 + 30_000).toISOString());
  // The duration of an ongoing incident runs to now.
  assert.equal(i.seconds, 9 * 30);
  assert.deepEqual(log.openIncidents(), [[K, T0 + 30_000]]);
});

test('a long outage is one incident, and two good checks close it at the first good one', () => {
  const log = new UptimeLog([K], { now: () => T0 + 600_000 });
  const events = feed(log, [0, 0, 0, 0, 0, 1, 0, 1, 1]);
  assert.deepEqual(events.map((e) => e.type), ['down', 'recovered']);
  // One good check in the middle does not close it.
  assert.equal(events[1].at, T0 + 8 * 30_000);
  assert.equal(events[1].start, T0);
  // The good check at index 5 was followed by a failure, so the run restarts at index 7.
  assert.equal(events[1].end, T0 + 7 * 30_000);
  const list = log.incidents(K);
  assert.equal(list.length, 1);
  assert.equal(list[0].ongoing, false);
  assert.equal(list[0].seconds, 7 * 30);
  assert.deepEqual(log.openIncidents(), []);
});

test('a second outage is a second incident, newest first', () => {
  const log = new UptimeLog([K], { now: () => T0 + DAY });
  feed(log, [0, 0, 1, 1, 1, 0, 0]);
  const list = log.incidents(K);
  assert.equal(list.length, 2);
  assert.equal(list[0].ongoing, true);
  assert.equal(list[1].ongoing, false);
  assert.ok(Date.parse(list[0].start) > Date.parse(list[1].start));
});

test('unknown nodes and bad times are ignored', () => {
  const log = new UptimeLog([K], { now: () => T0 });
  assert.deepEqual(log.record('nobody:1', false, T0), []);
  assert.deepEqual(log.record(K, false, NaN), []);
  assert.deepEqual(log.record(K, false, 1e300), []);
  assert.deepEqual(log.dayList(K).filter((d) => d !== null), []);
  assert.deepEqual(log.incidents('nobody:1'), []);
  assert.equal(log.percent('nobody:1', 30), null);
});

test('daily percent is rounded down, so 100 means no failed check', () => {
  assert.equal(percentOf(1, 1), 100);
  assert.equal(percentOf(2879, 2880), 99.9);
  assert.equal(percentOf(0, 5), 0);
  assert.equal(percentOf(0, 0), null);
  const log = new UptimeLog([K], { now: () => T0 });
  for (let i = 0; i < 2879; i++) log.record(K, true, T0 + i);
  log.record(K, false, T0 + 3000);
  const days = log.dayList(K, 3);
  assert.deepEqual(days, [null, null, 99.9]);
});

test('percent over 30 and 90 days and the list of days', () => {
  let now = T0;
  const log = new UptimeLog([K], { now: () => now });
  // 40 days ago all good, 10 days ago half down, today all good.
  for (let i = 0; i < 10; i++) log.record(K, true, T0 - 40 * DAY + i);
  for (let i = 0; i < 10; i++) log.record(K, i < 5, T0 - 10 * DAY + i);
  for (let i = 0; i < 10; i++) log.record(K, true, T0 + i);
  assert.equal(log.percent(K, 30), 75);
  assert.equal(log.percent(K, 90), 83.3);
  const days = log.dayList(K);
  assert.equal(days.length, 90);
  assert.equal(days.at(-1), 100);
  assert.equal(days.at(-11), 50);
  assert.equal(days.at(-41), 100);
  assert.equal(days.at(-2), null);
  now = T0 + 91 * DAY;
  assert.equal(log.dayList(K)[0], null);
});

test('days older than the kept range are dropped', () => {
  const log = new UptimeLog([K], { now: () => T0 + 200 * DAY });
  for (let i = 0; i < 200; i++) log.record(K, true, T0 + i * DAY);
  const saved = log.toJSON().hosts[K].days;
  assert.equal(Object.keys(saved).length, KEEP_DAYS);
  assert.equal(saved[dayOf(T0 + 199 * DAY)][1], 1);
  assert.equal(saved[dayOf(T0)], undefined);
});

test('incidents are capped per node and over all nodes, and an open one is kept', () => {
  const log = new UptimeLog([K], { now: () => T0 });
  const pattern = [];
  for (let i = 0; i < MAX_INCIDENTS_PER_NODE + 20; i++) pattern.push(0, 0, 1, 1);
  feed(log, pattern);
  assert.equal(log.incidents(K).length, MAX_INCIDENTS_PER_NODE);
  assert.equal(log.incidents(K, 5).length, 5);

  const keys = Array.from({ length: 30 }, (_, i) => `n${i}.test:1`);
  const many = new UptimeLog(keys, { now: () => T0 });
  for (const k of keys) feed(many, pattern.slice(0, 4 * MAX_INCIDENTS_PER_NODE), T0, k);
  feed(many, [0, 0], T0 + 10_000_000, keys[0]);
  const all = many.allIncidents(5000);
  assert.ok(all.length <= MAX_INCIDENTS_TOTAL);
  assert.ok(all.some((i) => i.host === keys[0] && i.ongoing));
});

test('allIncidents lists the newest first with the host and honours the limit', () => {
  const log = new UptimeLog(['a.test:1', 'b.test:1'], { now: () => T0 + DAY });
  feed(log, [0, 0, 1, 1], T0, 'a.test:1');
  feed(log, [0, 0, 1, 1], T0 + 3_600_000, 'b.test:1');
  const all = log.allIncidents(10);
  assert.deepEqual(all.map((i) => i.host), ['b.test:1', 'a.test:1']);
  assert.deepEqual(Object.keys(all[0]).sort(), ['end', 'host', 'ongoing', 'seconds', 'start']);
  assert.equal(log.allIncidents(1).length, 1);
  assert.deepEqual(log.allIncidents(0), []);
});

test('saved uptime and an open incident survive a restart, without a new down event', async () => {
  const dir = await tmp();
  const file = path.join(dir, 'uptime.json');
  const log = new UptimeLog([K], { now: () => T0 + 600_000 });
  feed(log, [1, 1, 0, 0, 0]);
  await fs.writeFile(file, JSON.stringify(log));
  const again = new UptimeLog([K], { now: () => T0 + 600_000 });
  await again.load(file);
  assert.deepEqual(again.toJSON(), log.toJSON());
  assert.deepEqual(again.openIncidents(), log.openIncidents());
  // Still down after the restart: nothing new opens. Back up: it closes.
  assert.deepEqual(feed(again, [0, 0], T0 + 300_000), []);
  const events = feed(again, [1, 1], T0 + 400_000);
  assert.deepEqual(events.map((e) => e.type), ['recovered']);
  assert.equal(again.incidents(K).length, 1);
});

test('a node removed from the config loses its data', async () => {
  const dir = await tmp();
  const file = path.join(dir, 'uptime.json');
  const log = new UptimeLog([K, 'gone.test:1'], { now: () => T0 });
  feed(log, [0, 0]);
  feed(log, [0, 0], T0, 'gone.test:1');
  await fs.writeFile(file, JSON.stringify(log));
  const again = new UptimeLog([K], { now: () => T0 });
  await again.load(file);
  assert.deepEqual(Object.keys(again.toJSON().hosts), [K]);
  assert.equal(again.incidents('gone.test:1').length, 0);
});

test('a missing, corrupt, oversized or wrongly shaped file means starting empty', async () => {
  const dir = await tmp();
  const file = path.join(dir, 'uptime.json');
  const empty = JSON.stringify(new UptimeLog([K]));
  const bad = [
    null, // no file
    '{not json',
    '[]',
    'null',
    '"text"',
    JSON.stringify({ version: 2, hosts: {} }),
    JSON.stringify({ version: 1, hosts: [] }),
    JSON.stringify({ version: 1, hosts: null }),
    JSON.stringify({ version: 1, hosts: { [K]: 'x' } }),
    JSON.stringify({ version: 1, hosts: { [K]: { days: 5, incidents: 'x' } } }),
    JSON.stringify({ version: 1, hosts: { [K]: { days: [1, 2], incidents: {} } } }),
    JSON.stringify({ version: 1, hosts: {} }) + ' '.repeat(MAX_UPTIME_FILE_BYTES),
  ];
  for (const text of bad) {
    await fs.rm(file, { force: true });
    if (text !== null) await fs.writeFile(file, text);
    const log = new UptimeLog([K], { now: () => T0 });
    await log.load(file);
    assert.equal(JSON.stringify(log), empty, String(text).slice(0, 40));
  }
});

test('bad entries are dropped one by one, good ones stay', async () => {
  const dir = await tmp();
  const file = path.join(dir, 'uptime.json');
  const today = dayOf(T0);
  await fs.writeFile(
    file,
    JSON.stringify({
      version: 1,
      hosts: {
        [K]: {
          days: {
            [today]: [5, 10],
            '2026-11-18': [11, 10], // more up than checks
            '2026-11-17': [-1, 3],
            '2026-11-16': [1.5, 3],
            '2026-11-15': 'x',
            '2026-13-45': [1, 1], // not a date
            '2020-01-01': [1, 1], // too old
            'not a day': [1, 1],
            '2026-11-14': [1, 2, 3],
            '2026-11-13': [1e12, 2e12],
            __proto__: [1, 1],
          },
          incidents: [[T0 - 1000, T0], [T0, T0 - 5], 'x', [null, 5], [NaN, 1], [1, 2, 3], [T0 + 100, null], [-5, 3], [T0 - 5000, null]],
        },
      },
    }),
  );
  const log = new UptimeLog([K], { now: () => T0 });
  await log.load(file);
  const { days, incidents } = log.toJSON().hosts[K];
  assert.deepEqual(days, { [today]: [5, 10] });
  // Valid ones: [T0-1000, T0], [T0+100, null], [T0-5000, null]; only the newest may stay open.
  assert.deepEqual(incidents, [[T0 - 5000, T0 - 5000], [T0 - 1000, T0], [T0 + 100, null]]);
  assert.deepEqual(log.openIncidents(), [[K, T0 + 100]]);
});

test('a huge saved incident list is cut to the cap', async () => {
  const dir = await tmp();
  const file = path.join(dir, 'uptime.json');
  const list = Array.from({ length: 5000 }, (_, i) => [T0 + i * 10, T0 + i * 10 + 5]);
  await fs.writeFile(file, JSON.stringify({ version: 1, hosts: { [K]: { days: {}, incidents: list } } }));
  const log = new UptimeLog([K], { now: () => T0 });
  await log.load(file);
  assert.equal(log.incidents(K).length, MAX_INCIDENTS_PER_NODE);
  assert.equal(log.toJSON().hosts[K].incidents.at(-1)[0], T0 + 4999 * 10);
});

// A monitor with a clock and a probe that follows a list.
function monitorWith(dir, results, extra = {}) {
  let clock = T0;
  let n = 0;
  const m = new Monitor({
    targets: [{ host: 'a.test', port: 1 }],
    dataDir: dir,
    now: () => clock,
    probeFn: async () => (results[n++ % results.length] ? { up: true, ms: 3 } : { up: false, ms: 0, error: 'timeout' }),
    ...extra,
  });
  return { m, tick: async () => { clock += 30_000; await m.checkAll(); } };
}

test('the monitor records uptime, saves uptime.json privately and loads it again', async () => {
  const dir = await tmp();
  const { m, tick } = monitorWith(dir, [1, 1, 0, 0, 0, 1, 1]);
  for (let i = 0; i < 7; i++) await tick();
  const file = path.join(dir, 'uptime.json');
  assert.equal(((await fs.stat(file)).mode & 0o777).toString(8), '600');
  assert.deepEqual((await fs.readdir(dir)).sort(), ['history.json', 'uptime.json']);
  const h = m.snapshot().hosts[0];
  const incidents = m.incidentList();
  assert.equal(incidents.length, 1);
  assert.equal(incidents[0].ongoing, false);
  assert.equal('incidents' in h, false);
  assert.equal(h.days.length, 90);
  assert.equal(h.days.at(-1), 57.1);
  assert.deepEqual(h.uptime90, { percent30: 57.1, percent90: 57.1 });
  const again = new Monitor({ targets: [{ host: 'a.test', port: 1 }], dataDir: dir, now: () => T0 + 400_000 });
  await again.load();
  assert.deepEqual(again.incidentList(), incidents);
});

test('a node without any check has no percent and an empty bar', () => {
  const m = new Monitor({ targets: [{ host: 'a.test', port: 1 }], dataDir: '/nonexistent', now: () => T0 });
  const h = m.snapshot().hosts[0];
  assert.deepEqual(h.uptime90, { percent30: null, percent90: null });
  assert.deepEqual(h.days, new Array(90).fill(null));
  assert.deepEqual(m.incidentList(), []);
});

test('/api/status keeps its additions small', async () => {
  const dir = await tmp();
  const { m, tick } = monitorWith(dir, [0, 0, 1, 1]);
  for (let i = 0; i < 8; i++) await tick();
  const { history, ...rest } = m.snapshot().hosts[0];
  const extra = JSON.stringify({ u: rest.uptime90, d: rest.days }).length;
  assert.ok(extra < 1200, `additions are ${extra} bytes`);
  assert.equal('incidents' in rest, false);
});

async function serve(m) {
  const server = createApp({ monitor: m, publicDir });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return { base: `http://127.0.0.1:${server.address().port}`, port: server.address().port, close: () => new Promise((r) => (server.closeAllConnections(), server.close(r))) };
}

test('/api/incidents lists incidents of all nodes, GET and HEAD only', async () => {
  const dir = await tmp();
  const { m, tick } = monitorWith(dir, [0, 0, 1, 1, 0, 0], { nodes: new Map([['a.test:1', { name: 'Front', proxyFor: [], proxiedBy: null, countOwn: false }]]) });
  for (let i = 0; i < 6; i++) await tick();
  const s = await serve(m);
  try {
    const res = await fetch(`${s.base}/api/incidents`);
    assert.equal(res.status, 200);
    assert.match(res.headers.get('content-type'), /^application\/json/);
    assert.equal(res.headers.get('cache-control'), 'no-store');
    assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
    const body = await res.json();
    assert.deepEqual(Object.keys(body).sort(), ['generatedAt', 'incidents']);
    assert.equal(body.incidents.length, 2);
    assert.deepEqual(Object.keys(body.incidents[0]).sort(), ['end', 'host', 'name', 'ongoing', 'seconds', 'start']);
    assert.equal(body.incidents[0].host, 'a.test:1');
    assert.equal(body.incidents[0].name, 'Front');
    assert.equal(body.incidents[0].ongoing, true);
    assert.equal(body.incidents[1].ongoing, false);

    const head = await fetch(`${s.base}/api/incidents`, { method: 'HEAD' });
    assert.equal(head.status, 200);
    assert.equal(await head.text(), '');
    for (const method of ['POST', 'PUT', 'DELETE', 'PATCH']) {
      const r = await fetch(`${s.base}/api/incidents`, { method });
      assert.equal(r.status, 405, method);
      assert.equal(r.headers.get('allow'), 'GET, HEAD');
    }
    // A query cannot change what is listed.
    const q = await (await fetch(`${s.base}/api/incidents?limit=1&host=zzz`)).json();
    assert.equal(q.incidents.length, 2);
  } finally {
    await s.close();
  }
});

test('/api/incidents is empty without incidents', async () => {
  const dir = await tmp();
  const { m, tick } = monitorWith(dir, [1]);
  await tick();
  const s = await serve(m);
  try {
    const body = await (await fetch(`${s.base}/api/incidents`)).json();
    assert.deepEqual(body.incidents, []);
  } finally {
    await s.close();
  }
});

test('uptime answers stay the same for a node with private details', async () => {
  const dir = await tmp();
  const nodes = new Map([['a.test:1', { name: null, proxyFor: [], proxiedBy: null, countOwn: false, publicDetails: false, requireLogin: ['details', 'storage'] }]]);
  const { m, tick } = monitorWith(dir, [0, 0, 1, 1], { nodes });
  for (let i = 0; i < 4; i++) await tick();
  const s = await serve(m);
  try {
    const status = await (await fetch(`${s.base}/api/status`)).json();
    assert.equal('incidents' in status.hosts[0], false);
    const inc = await (await fetch(`${s.base}/api/incidents`)).json();
    assert.equal(inc.incidents.length, 1);
    // Only up and down times: nothing from the node's stats or the probe error.
    assert.deepEqual(Object.keys(inc.incidents[0]).sort(), ['end', 'host', 'name', 'ongoing', 'seconds', 'start']);
  } finally {
    await s.close();
  }
});

