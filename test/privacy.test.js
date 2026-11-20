import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Monitor, diskLevel, publicData } from '../lib/monitor.js';
import { loadConfig, loadNodes } from '../lib/config.js';
import { aggregateGroup } from '../lib/group.js';
import { createApp } from '../lib/app.js';

const publicDir = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'public');
const MIN = 60_000;
const NOW = 1_800_000_000_000;

const stats = (disk) => ({
  rettuiVersion: '2.0.0', generatedAt: 1, uptimeSeconds: 100,
  interfaces: { total: 1, online: 1, clients: 1, rxBytes: 1, txBytes: 1 },
  peersHeard: { total: 3, lxmf: 2, nomad: 1, propagation: 0 }, announcesLastMinute: 0,
  ...(disk ? { disk } : {}),
});
const GB = 1e9;
const disk = (usedPercent, total = 40 * GB) => ({ dataBytes: 123_456, fsTotalBytes: total, fsFreeBytes: Math.round(total * (1 - usedPercent / 100)) });

test('diskLevel thresholds: 75 high, 90 full', () => {
  assert.equal(diskLevel(0), 'ok');
  assert.equal(diskLevel(74.9), 'ok');
  assert.equal(diskLevel(75), 'high');
  assert.equal(diskLevel(89.9), 'high');
  assert.equal(diskLevel(90), 'full');
  assert.equal(diskLevel(100), 'full');
});

test('publicData: without figures only a level and a share rounded to 5 leave, no byte figure of the file system', () => {
  const d = publicData(stats(disk(92)), false).disk;
  assert.deepEqual(d, { dataBytes: 123_456, level: 'full', usedPercent: 90 });
  assert.equal(publicData(stats(disk(77)), false).disk.usedPercent, 75);
  assert.equal(publicData(stats(disk(83.4)), false).disk.usedPercent, 85);
  assert.equal(publicData(stats(disk(10)), false).disk.level, 'ok');
  const text = JSON.stringify(publicData(stats(disk(50)), false));
  assert.equal(text.includes('fsFreeBytes'), false);
  assert.equal(text.includes('fsTotalBytes'), false);
  assert.equal(text.includes(String(20 * GB)), false);
});

test('publicData: with figures the exact numbers and the share are published', () => {
  const d = publicData(stats(disk(92)), true).disk;
  assert.equal(d.level, 'full');
  assert.equal(d.usedPercent, 92);
  assert.equal(d.fsTotalBytes, 40 * GB);
  assert.equal(d.fsFreeBytes, 40 * GB * 0.08);
});

test('publicData: no disk, no free-space numbers (a node without a token) and odd values are handled', () => {
  assert.equal('disk' in publicData(stats(), false), false);
  assert.deepEqual(publicData(stats({ dataBytes: 5, fsTotalBytes: null, fsFreeBytes: null }), false).disk, { dataBytes: 5, level: null, usedPercent: null });
  assert.deepEqual(publicData(stats({ dataBytes: 5, fsTotalBytes: 0, fsFreeBytes: 0 }), true).disk.level, null);
  assert.equal(publicData(stats({ dataBytes: 5, fsTotalBytes: 10, fsFreeBytes: 50 }), false).disk.usedPercent, 0);
  assert.equal(publicData(stats({ dataBytes: 5, fsTotalBytes: 10, fsFreeBytes: -5 }), false).disk.usedPercent, 100);
});

const yaml = (extra = '', nodeExtra = '', node2 = '') => `${extra}
nodes:
  - address: a.test:1
    stats_url: https://a.test/s
${nodeExtra}
  - address: b.test:1
    stats_url: https://b.test/s
${node2}
`;

test('public_details and public_disk_figures: global default, node override, strict', () => {
  const none = loadConfig(yaml());
  assert.deepEqual(none.defaults, { publicDetails: true, publicDiskFigures: false, publicLogs: false, requireLogin: [] });
  assert.equal(none.nodes.get('a.test:1').publicDetails, true);
  const c = loadConfig(yaml('public_details: false\npublic_disk_figures: true', '    public_details: true\n    public_disk_figures: false'));
  assert.deepEqual(c.defaults, { publicDetails: false, publicDiskFigures: true, publicLogs: false, requireLogin: [] });
  assert.deepEqual([c.nodes.get('a.test:1').publicDetails, c.nodes.get('a.test:1').publicDiskFigures], [true, false]);
  assert.deepEqual([c.nodes.get('b.test:1').publicDetails, c.nodes.get('b.test:1').publicDiskFigures], [false, true]);
  const bad = (text, pattern) => assert.throws(() => loadConfig(text), (e) => pattern.test(e.message));
  bad(yaml('public_details: "no"'), /public_details must be true or false/);
  bad(yaml('public_disk_figures: 1'), /public_disk_figures must be true or false/);
  bad(yaml('', '    public_details: null'), /nodes\[1\]\.public_details must be true or false/);
  bad(yaml('', '    public_disk_figures: yes please'), /public_disk_figures must be true or false/);
});

test('PUBLIC_DETAILS and PUBLIC_DISK_FIGURES in the environment: global only, strict, not with CONFIG_FILE', async () => {
  const n = await loadNodes({});
  assert.deepEqual(n.defaults, { publicDetails: true, publicDiskFigures: false, publicLogs: false, requireLogin: [] });
  assert.deepEqual((await loadNodes({ PUBLIC_DETAILS: 'false', PUBLIC_DISK_FIGURES: 'true' })).defaults, { publicDetails: false, publicDiskFigures: true, publicLogs: false, requireLogin: [] });
  // An empty value is a mistake, never "public".
  await assert.rejects(loadNodes({ PUBLIC_DETAILS: '' }), /PUBLIC_DETAILS is empty/);
  await assert.rejects(loadNodes({ PUBLIC_DISK_FIGURES: '' }), /PUBLIC_DISK_FIGURES is empty/);
  await assert.rejects(loadNodes({ PUBLIC_DETAILS: 'no' }), /PUBLIC_DETAILS must be true or false/);
  await assert.rejects(loadNodes({ PUBLIC_DISK_FIGURES: 'TRUE' }), /PUBLIC_DISK_FIGURES must be true or false/);
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'website-'));
  await fs.writeFile(path.join(dir, 'c.yaml'), yaml());
  await assert.rejects(loadNodes({ CONFIG_FILE: path.join(dir, 'c.yaml'), PUBLIC_DETAILS: 'false' }), /not both/);
  assert.deepEqual((await loadNodes({ CONFIG_FILE: path.join(dir, 'c.yaml') })).defaults, { publicDetails: true, publicDiskFigures: false, publicLogs: false, requireLogin: [] });
});

test('a node with public_logs gets a warning at start, one without gets none', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'website-'));
  await fs.writeFile(path.join(dir, 'c.yaml'), yaml('', '    public_logs: true'));
  const w = (await loadNodes({ CONFIG_FILE: path.join(dir, 'c.yaml') })).warnings.filter((m) => /public_logs/.test(m));
  assert.equal(w.length, 1);
  assert.match(w[0], /a\.test:1 has public_logs: true/);
  await fs.writeFile(path.join(dir, 'd.yaml'), yaml());
  assert.deepEqual((await loadNodes({ CONFIG_FILE: path.join(dir, 'd.yaml') })).warnings.filter((m) => /public_logs/.test(m)), []);
});

test('the group reports the fullest disk by level, and exact free space only from nodes that publish it', () => {
  const m = (key, d, figures) => ({ key, status: 'up', stats: { ok: true, stale: false, data: publicData(stats(d), figures) } });
  const g = aggregateGroup([m('a', disk(40), false), m('b', disk(92), false), m('c', disk(80), true)]).data.disk;
  assert.deepEqual(g.worst, { level: 'full', usedPercent: 90, node: 'b' });
  assert.equal(g.lowestFree.node, 'c');
  assert.equal(g.dataBytes, 3 * 123_456);
  const none = aggregateGroup([m('a', disk(40), false)]).data.disk;
  assert.equal(none.lowestFree, null);
  assert.equal(none.worst.level, 'ok');
});

async function setup({ nodeFlags = '', top = '' } = {}) {
  const config = loadConfig(`${top}
nodes:
  - address: p.test:1
    stats_url: https://p.test/s
    proxy_for: [a.test:1, b.test:1]
  - address: a.test:1
    stats_url: https://a.test/s
${nodeFlags}
  - address: b.test:1
    stats_url: https://b.test/s
`);
  let clock = NOW - 30 * MIN;
  const monitor = new Monitor({
    targets: config.targets, nodes: config.nodes, statsUrls: config.statsUrls, dataDir: await fs.mkdtemp(path.join(os.tmpdir(), 'website-')), publicDetails: config.defaults.publicDetails, publicDiskFigures: config.defaults.publicDiskFigures,
    probeFn: async () => ({ up: true, ms: 1 }),
    statsFn: async () => ({ ok: true, data: { ...stats(disk(92)), propagation: { enabled: true, storedMessages: 5, storedBytes: 5, storageLimitBytes: null, peersConnected: null, peersTotal: 2, peersAlive: 1, peersStatic: null, peersAuto: null, peerLimit: null, staticPeers: null, autopeerDepth: null, messagesReceived: null, messagesServed: null, messagesSentToPeers: 10, messagesReceivedFromPeers: 10, messagesOfferedToPeers: null, unhandledMessages: 1, autopeer: null } } }),
    now: () => clock,
    sampleIntervalMs: 1000,
  });
  for (let i = 0; i < 4; i++) {
    await monitor.checkAll();
    clock += 5 * MIN;
  }
  clock -= 5 * MIN;
  const server = createApp({ monitor, publicDir });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}`;
  return { monitor, base, close: () => (server.closeAllConnections(), new Promise((r) => server.close(r))) };
}

test('no public API carries free or total disk bytes unless public_disk_figures is set', async () => {
  const s = await setup();
  try {
    const bodies = [];
    for (const p of ['/api/status', '/api/stats?host=a.test:1&range=7d', '/api/stats?host=p.test:1&range=7d&view=combined']) bodies.push(await (await fetch(s.base + p)).text());
    for (const b of bodies) {
      assert.equal(/fsFreeBytes|fsTotalBytes|freeBytes|totalBytes/.test(b), false);
      assert.equal(b.includes(String(Math.round(40 * GB * 0.08))), false);
      assert.equal(b.includes(String(40 * GB)), false);
    }
    const status = JSON.parse(bodies[0]);
    assert.deepEqual(status.hosts[1].stats.data.disk, { dataBytes: 123_456, level: 'full', usedPercent: 90 });
    assert.deepEqual(status.hosts[0].group.data.disk.worst.level, 'full');
    assert.equal(JSON.parse(bodies[1]).series.disk, null);
    assert.equal(JSON.parse(bodies[2]).series.disk, null);
  } finally {
    await s.close();
  }
});

test('with public_disk_figures the figures and the free space history are published', async () => {
  const s = await setup({ top: 'public_disk_figures: true' });
  try {
    const status = await (await fetch(`${s.base}/api/status`)).json();
    assert.equal(status.hosts[1].stats.data.disk.fsTotalBytes, 40 * GB);
    assert.equal(status.hosts[1].stats.data.disk.usedPercent, 92);
    assert.ok(status.hosts[0].group.data.disk.lowestFree);
    const d = await (await fetch(`${s.base}/api/stats?host=a.test:1&range=7d`)).json();
    assert.equal(d.series.disk.fsFreeBytes.length, 4);
    const c = await (await fetch(`${s.base}/api/stats?host=p.test:1&range=7d&view=combined`)).json();
    assert.ok(c.series.disk);
  } finally {
    await s.close();
  }
});

test('public_details false: no Details, /api/stats answers 404 like an unknown host, and the node leaves the combined graphs', async () => {
  const s = await setup({ nodeFlags: '    public_details: false' });
  try {
    const status = await (await fetch(`${s.base}/api/status`)).json();
    assert.deepEqual(status.hosts.map((h) => h.hasDetail), [true, false, true]);
    // The node's own line still shows its stats.
    assert.equal(status.hosts[1].stats.ok, true);
    const hidden = await fetch(`${s.base}/api/stats?host=a.test:1&range=6h`);
    assert.equal(hidden.status, 404);
    assert.deepEqual(await hidden.json(), { error: 'unknown host' });
    const unknown = await fetch(`${s.base}/api/stats?host=nope.test:1&range=6h`);
    assert.deepEqual(await unknown.json(), { error: 'unknown host' });
    assert.equal((await fetch(`${s.base}/api/stats?host=a.test:1&view=combined`)).status, 404);
    const c = await (await fetch(`${s.base}/api/stats?host=p.test:1&range=6h&view=combined`)).json();
    assert.deepEqual(c.members.map((m) => m.host), ['b.test:1']);
    assert.equal(c.series.members, 1);
    assert.equal((await fetch(`${s.base}/api/stats?host=b.test:1&range=6h`)).status, 200);
  } finally {
    await s.close();
  }
});

test('public_details: false as the global default hides every Details view', async () => {
  const s = await setup({ top: 'public_details: false' });
  try {
    const status = await (await fetch(`${s.base}/api/status`)).json();
    assert.deepEqual(status.hosts.map((h) => h.hasDetail), [false, false, false]);
    for (const h of ['p.test:1', 'a.test:1', 'b.test:1']) assert.equal((await fetch(`${s.base}/api/stats?host=${h}&range=6h`)).status, 404);
  } finally {
    await s.close();
  }
});

test('with the environment variables the global defaults apply to every node', async () => {
  const m = new Monitor({
    targets: [{ host: 'a.test', port: 1 }], statsUrls: new Map([['a.test:1', 'https://a.test/s']]), dataDir: await fs.mkdtemp(path.join(os.tmpdir(), 'website-')),
    probeFn: async () => ({ up: true, ms: 1 }), statsFn: async () => ({ ok: true, data: stats(disk(80)) }), publicDetails: false,
  });
  await m.checkAll();
  const h = m.snapshot().hosts[0];
  assert.equal(h.hasDetail, false);
  assert.deepEqual(h.stats.data.disk, { dataBytes: 123_456, level: 'high', usedPercent: 80 });
  assert.equal(m.detail('a.test:1', '6h') !== null, true);
});

test('the disk level is worked out from the published, rounded share', () => {
  // 88% is published as 90, so it must also read "full".
  assert.deepEqual([publicData(stats(disk(88)), false).disk.usedPercent, publicData(stats(disk(88)), false).disk.level], [90, 'full']);
  assert.deepEqual([publicData(stats(disk(73)), false).disk.usedPercent, publicData(stats(disk(73)), false).disk.level], [75, 'high']);
  assert.deepEqual([publicData(stats(disk(72)), false).disk.usedPercent, publicData(stats(disk(72)), false).disk.level], [70, 'ok']);
  // With figures the exact (whole) share is the one that counts.
  assert.deepEqual([publicData(stats(disk(89.4)), true).disk.usedPercent, publicData(stats(disk(89.4)), true).disk.level], [89, 'high']);
});

test('the combined view leaves a private node out of its group totals, not only out of the graphs', async () => {
  const s = await setup({ nodeFlags: '    public_details: false' });
  try {
    const all = JSON.parse(await (await fetch(s.base + '/api/status')).text()).hosts[0].group;
    const combined = JSON.parse(await (await fetch(s.base + '/api/stats?host=p.test:1&range=6h&view=combined')).text());
    assert.equal(all.nodes, 2);
    assert.equal(combined.group.nodes, 1);
    assert.equal(combined.group.reporting, 1);
    assert.deepEqual(combined.group.missing, []);
    assert.equal(combined.group.data.propagation.nodes, 1);
    assert.equal(combined.group.data.peersHeard.exact, false);
    assert.equal(JSON.stringify(combined).includes('a.test'), false);
  } finally {
    await s.close();
  }
});
