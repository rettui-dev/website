import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { Monitor, parseTargets, probe, DEFAULT_TARGETS } from '../lib/monitor.js';

const tmp = () => fs.mkdtemp(path.join(os.tmpdir(), 'website-'));

function listen() {
  return new Promise((resolve) => {
    const server = net.createServer((s) => s.end());
    server.listen(0, '127.0.0.1', () => resolve(server));
  });
}

test('default targets are the four entry points', () => {
  assert.deepEqual(parseTargets(DEFAULT_TARGETS.join(',')).map((t) => `${t.host}:${t.port}`), [
    'rns.rettui.dev:4242',
    'front.rns.rettui.dev:4242',
    'back.rns.rettui.dev:4242',
    'side.rns.rettui.dev:4242',
  ]);
});

test('parseTargets accepts a list, trims and drops duplicates', () => {
  assert.deepEqual(parseTargets(' A.example:1 , a.example:1,b.example:65535,'), [
    { host: 'a.example', port: 1 },
    { host: 'b.example', port: 65535 },
  ]);
});

test('parseTargets rejects bad input', () => {
  for (const bad of ['', ',', 'nohost', 'host:', ':80', 'host:0', 'host:65536', 'host:abc', 'a b:80', 'host/x:80', '-a.com:80', 'a..b:80']) {
    assert.throws(() => parseTargets(bad), Error, bad);
  }
});

test('probe sees a listening port as up', async () => {
  const server = await listen();
  try {
    const r = await probe('127.0.0.1', server.address().port, 1000);
    assert.equal(r.up, true);
    assert.ok(r.ms >= 0);
  } finally {
    server.close();
  }
});

test('probe sees a closed port as down', async () => {
  const server = await listen();
  const { port } = server.address();
  await new Promise((r) => server.close(r));
  const r = await probe('127.0.0.1', port, 1000);
  assert.equal(r.up, false);
  assert.equal(r.error, 'ECONNREFUSED');
});

test('probe times out on a host that never answers', async () => {
  // A listener whose backlog is full leaves further connects hanging on
  // most systems, but that is not portable. A custom timeout of 1 ms against
  // a non-routable address gives the same result without depending on it.
  const r = await probe('10.255.255.1', 9, 1);
  assert.equal(r.up, false);
  assert.ok(['timeout', 'ENETUNREACH', 'EHOSTUNREACH', 'ECONNREFUSED'].includes(r.error), r.error);
});

test('probe never rejects for an unresolvable host', async () => {
  const r = await probe('nonexistent.invalid', 4242, 1000);
  assert.equal(r.up, false);
  assert.equal(typeof r.error, 'string');
});

function fake(results) {
  let n = 0;
  return async () => results[n++ % results.length];
}

test('history is trimmed to the maximum', async () => {
  const dir = await tmp();
  const m = new Monitor({ targets: [{ host: 'a.test', port: 1 }], dataDir: dir, maxHistory: 3, probeFn: fake([{ up: true, ms: 5 }]) });
  for (let i = 0; i < 5; i++) await m.checkAll();
  assert.equal(m.snapshot().hosts[0].checks, 3);
});

test('snapshot reports status, uptime and overall state', async () => {
  const dir = await tmp();
  const targets = [
    { host: 'a.test', port: 1 },
    { host: 'b.test', port: 2 },
  ];
  const m = new Monitor({
    targets,
    dataDir: dir,
    probeFn: async (host) => (host === 'a.test' ? { up: true, ms: 12 } : { up: false, ms: 5000, error: 'timeout' }),
  });
  assert.equal(m.snapshot().overall, 'unknown');
  assert.equal(m.snapshot().hosts[0].status, 'unknown');
  await m.checkAll();
  const s = m.snapshot();
  assert.equal(s.overall, 'degraded');
  assert.equal(s.hosts[0].status, 'up');
  assert.equal(s.hosts[0].latencyMs, 12);
  assert.equal(s.hosts[0].uptimePercent, 100);
  assert.equal(s.hosts[1].status, 'down');
  assert.equal(s.hosts[1].latencyMs, null);
  assert.equal(s.hosts[1].error, 'timeout');
  assert.equal(s.hosts[1].uptimePercent, 0);
});

test('overall is up only when every entry point, proxied ones too, has been checked and is up', async () => {
  const dir = await tmp();
  const targets = [{ host: 'p.test', port: 1 }, { host: 'a.test', port: 2 }, { host: 'b.test', port: 3 }];
  const nodes = new Map([['p.test:1', { name: null, proxyFor: ['a.test:2', 'b.test:3'], proxiedBy: null, countOwn: false }]]);
  let down = '';
  const m = new Monitor({ targets, nodes, dataDir: dir, probeFn: async (host) => (host === down ? { up: false, ms: 1, error: 'x' } : { up: true, ms: 1 }) });
  await m.checkAll();
  assert.equal(m.snapshot().overall, 'up');
  down = 'b.test';
  await m.checkAll();
  assert.equal(m.snapshot().overall, 'degraded');
  // Some not checked yet is not "all reachable".
  const early = new Monitor({ targets, dataDir: await tmp(), probeFn: async () => ({ up: true, ms: 1 }) });
  early.history.get('p.test:1').push([Date.now(), 1, 1]);
  assert.equal(early.snapshot().overall, 'unknown');
});

test('a throwing probe is recorded as down, not a crash', async () => {
  const dir = await tmp();
  const m = new Monitor({
    targets: [{ host: 'a.test', port: 1 }],
    dataDir: dir,
    probeFn: async () => {
      throw new Error('boom');
    },
  });
  await m.checkAll();
  assert.equal(m.snapshot().overall, 'down');
});

test('history persists across restarts and ignores damaged entries', async () => {
  const dir = await tmp();
  const targets = [{ host: 'a.test', port: 1 }];
  const first = new Monitor({ targets, dataDir: dir, probeFn: fake([{ up: true, ms: 7 }, { up: false, ms: 0, error: 'x' }]) });
  await first.checkAll();
  await first.checkAll();
  const second = new Monitor({ targets, dataDir: dir });
  await second.load();
  assert.deepEqual(second.history.get('a.test:1'), first.history.get('a.test:1'));

  const file = path.join(dir, 'history.json');
  const saved = JSON.parse(await fs.readFile(file, 'utf8'));
  saved.hosts['a.test:1'].push('junk', [1, 2, 3], [1, 1]);
  saved.hosts['gone.test:9'] = [[1, 1, 1]];
  await fs.writeFile(file, JSON.stringify(saved));
  const third = new Monitor({ targets, dataDir: dir });
  await third.load();
  assert.equal(third.history.get('a.test:1').length, 2);
  assert.equal(third.history.has('gone.test:9'), false);

  await fs.writeFile(file, '{not json');
  const fourth = new Monitor({ targets, dataDir: dir });
  await fourth.load();
  assert.equal(fourth.history.get('a.test:1').length, 0);
});

test('save leaves no temporary file behind and creates the data dir', async () => {
  const dir = path.join(await tmp(), 'nested', 'data');
  const m = new Monitor({ targets: [{ host: 'a.test', port: 1 }], dataDir: dir, probeFn: fake([{ up: true, ms: 1 }]) });
  await m.checkAll();
  assert.deepEqual((await fs.readdir(dir)).sort(), ['history.json', 'uptime.json']);
});

test('flush waits for a save that is running and writes what came after it', async () => {
  const dir = await tmp();
  const m = new Monitor({ targets: [{ host: 'a.test', port: 1 }], dataDir: dir, probeFn: fake([{ up: true, ms: 5 }]) });
  await m.checkAll();
  m.history.get('a.test:1').push([1, 1, 7]);
  const running = m.save();
  m.history.get('a.test:1').push([2, 1, 8]);
  await m.flush();
  await running;
  const saved = JSON.parse(await fs.readFile(path.join(dir, 'history.json'), 'utf8'));
  assert.deepEqual(saved.hosts['a.test:1'].slice(-2), [[1, 1, 7], [2, 1, 8]]);
});

test('save failure is logged, not thrown', async () => {
  const dir = await tmp();
  const blocker = path.join(dir, 'file');
  await fs.writeFile(blocker, 'x');
  const m = new Monitor({ targets: [{ host: 'a.test', port: 1 }], dataDir: path.join(blocker, 'data'), probeFn: fake([{ up: true, ms: 1 }]) });
  const original = console.error;
  console.error = () => {};
  try {
    await m.checkAll();
  } finally {
    console.error = original;
  }
  assert.equal(m.snapshot().hosts[0].status, 'up');
});
