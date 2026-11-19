import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { Monitor } from '../lib/monitor.js';
import { Alerter } from '../lib/alerts.js';

const tmp = () => fs.mkdtemp(path.join(os.tmpdir(), 'website-'));
const T0 = Date.UTC(2026, 10, 19, 12, 0, 0);
const K = 'a.test:1';

function monitorWith(dir, results, { alerts, start = T0, name = null } = {}) {
  let clock = start;
  let n = 0;
  const m = new Monitor({
    targets: [{ host: 'a.test', port: 1 }],
    dataDir: dir,
    now: () => clock,
    nodes: new Map([[K, { name, proxyFor: [], proxiedBy: null, countOwn: false }]]),
    probeFn: async () => (results[n++] ? { up: true, ms: 3 } : { up: false, ms: 0, error: 'timeout' }),
    alerts,
  });
  return { m, tick: async () => { clock += 30_000; await m.checkAll(); } };
}

function recorder() {
  const events = [];
  return { events, notify: (e) => events.push(['notify', e]), remind: (open, t) => events.push(['remind', open, t]) };
}

test('the monitor tells the alerts about a debounced down and a recovery', async () => {
  const alerts = recorder();
  const { tick } = monitorWith(await tmp(), [1, 0, 1, 0, 0, 0, 1, 1], { alerts });
  for (let i = 0; i < 8; i++) await tick();
  const notes = alerts.events.filter((e) => e[0] === 'notify').map((e) => e[1]);
  assert.deepEqual(notes.map((e) => e.type), ['down', 'recovered']);
  // Down is announced at the second failed check, and counted from the first one of the run.
  assert.equal(notes[0].start, T0 + 4 * 30_000);
  assert.equal(notes[0].at, T0 + 5 * 30_000);
  assert.equal(notes[1].end, T0 + 7 * 30_000);
  assert.equal(notes[1].at, T0 + 8 * 30_000);
  // The open incidents are passed on after each round, for reminders.
  const reminds = alerts.events.filter((e) => e[0] === 'remind');
  assert.equal(reminds.length, 8);
  assert.deepEqual(reminds[4][1], [[K, T0 + 4 * 30_000]]);
  assert.deepEqual(reminds[0][1], []);
});

test('a node that is already down at the start is a new incident, announced once, after the debounce', async () => {
  const alerts = recorder();
  const { tick } = monitorWith(await tmp(), [0, 0, 0, 0, 0], { alerts });
  await tick();
  assert.equal(alerts.events.filter((e) => e[0] === 'notify').length, 0);
  for (let i = 0; i < 4; i++) await tick();
  assert.equal(alerts.events.filter((e) => e[0] === 'notify').length, 1);
});

test('a restart while an incident is open does not announce it again', async () => {
  const dir = await tmp();
  const first = recorder();
  const a = monitorWith(dir, [0, 0, 0], { alerts: first });
  for (let i = 0; i < 3; i++) await a.tick();
  assert.equal(first.events.filter((e) => e[0] === 'notify').length, 1);

  const second = recorder();
  const b = monitorWith(dir, [0, 0, 0, 1, 1], { alerts: second, start: T0 + 10 * 60_000 });
  await b.m.load();
  for (let i = 0; i < 5; i++) await b.tick();
  const notes = second.events.filter((e) => e[0] === 'notify').map((e) => e[1]);
  assert.deepEqual(notes.map((e) => e.type), ['recovered']);
  // The incident keeps its first start across the restart.
  assert.equal(notes[0].start, T0 + 30_000);
});

test('a failing alerts object never fails a check', async () => {
  const alerts = { notify() { throw new Error('boom'); }, remind() { throw new Error('boom'); } };
  const { m, tick } = monitorWith(await tmp(), [0, 0, 1, 1], { alerts });
  const original = console.error;
  const seen = [];
  console.error = (msg) => seen.push(msg);
  try {
    for (let i = 0; i < 4; i++) await tick();
  } finally {
    console.error = original;
  }
  assert.equal(m.snapshot().hosts[0].history.length, 4);
  assert.ok(seen.length >= 4);
  assert.ok(seen.every((s) => !/boom/.test(s)));
});

test('a monitor without alerts works as before', async () => {
  const { m, tick } = monitorWith(await tmp(), [0, 0, 1, 1]);
  for (let i = 0; i < 4; i++) await tick();
  assert.equal(m.alerts, null);
  assert.equal(m.snapshot().hosts[0].incidents.length, 1);
});

test('end to end: a webhook goes out for the down and the recovery, and the probe loop does not wait for it', async () => {
  const bodies = [];
  let release;
  const gate = new Promise((r) => (release = r));
  const alerts = new Alerter({
    channels: [{ type: 'webhook', url: 'https://hooks.example/SECRETPATH', format: 'generic', secret: 'secret-0123456789abcdef' }],
    names: new Map([[K, 'Front']]),
    cooldownMs: 60_000,
    fetchFn: async (url, init) => {
      bodies.push(JSON.parse(init.body));
      await gate;
      return new Response('', { status: 200 });
    },
    log: () => {},
  });
  const dir = await tmp();
  const { m, tick } = monitorWith(dir, [1, 0, 0, 1, 1], { alerts, name: 'Front' });
  for (let i = 0; i < 5; i++) await tick();
  // The checks all finished while the first webhook was still waiting.
  assert.equal(m.snapshot().hosts[0].history.length, 5);
  release();
  await alerts.idle();
  assert.deepEqual(bodies.map((b) => b.event), ['down', 'recovered']);
  assert.match(bodies[0].message, /^Front \(a\.test:1\) is down since 12:01 UTC\.$/);
  // Nothing of the channel is in what the site publishes or saves.
  const published = JSON.stringify(m.snapshot()) + JSON.stringify(m.incidentList()) + JSON.stringify(m);
  const saved = (await Promise.all((await fs.readdir(dir)).map((f) => fs.readFile(path.join(dir, f), 'utf8')))).join('');
  for (const text of [published, saved]) assert.ok(!/SECRETPATH|hooks\.example|secret-0123456789abcdef/.test(text));
});
