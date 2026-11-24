import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { aggregateGroup, reports } from '../lib/group.js';
import { Monitor } from '../lib/monitor.js';
import { loadConfig } from '../lib/config.js';

const data = (o = {}) => ({
  rettuiVersion: '2.0.0',
  generatedAt: 1,
  uptimeSeconds: 100,
  interfaces: { total: 2, online: 2, clients: 10, rxBytes: 1000, txBytes: 400 },
  peersHeard: { total: 100, lxmf: 60, nomad: 30, propagation: 10 },
  announcesLastMinute: 5,
  ...o,
});
const member = (key, d, extra = {}) => ({ key, status: 'up', stats: { ok: true, stale: false, fetchedAt: 'x', data: d }, ...extra });

test('aggregateGroup sums the additive numbers and gives peers as a range', () => {
  const g = aggregateGroup([
    member('a', data()),
    member('b', data({ interfaces: { total: 3, online: 1, clients: 5, rxBytes: 50, txBytes: 25 }, peersHeard: { total: 250, lxmf: 10, nomad: 200, propagation: 40 }, announcesLastMinute: 7 })),
  ]);
  assert.deepEqual({ nodes: g.nodes, reporting: g.reporting, partial: g.partial, missing: g.missing }, { nodes: 2, reporting: 2, partial: false, missing: [] });
  assert.deepEqual(g.data.interfaces, { total: 5, online: 3, clients: 15, rxBytes: 1050, txBytes: 425 });
  assert.equal(g.data.announcesLastMinute, 12);
  assert.deepEqual(g.data.peersHeard.sum, { total: 350, lxmf: 70, nomad: 230, propagation: 50 });
  assert.deepEqual(g.data.peersHeard.max, { total: 250, lxmf: 60, nomad: 200, propagation: 40 });
});

test('aggregateGroup: unknown clients stay unknown only when no member knows them', () => {
  const noClients = (c) => data({ interfaces: { total: 1, online: 1, clients: c, rxBytes: 0, txBytes: 0 } });
  assert.equal(aggregateGroup([member('a', noClients(null)), member('b', noClients(null))]).data.interfaces.clients, null);
  assert.equal(aggregateGroup([member('a', noClients(null)), member('b', noClients(4))]).data.interfaces.clients, 4);
  assert.equal(aggregateGroup([member('a', noClients(0))]).data.interfaces.clients, 0);
});

test('aggregateGroup: down, stale and silent members are left out and the result is partial', () => {
  const stale = { key: 's', status: 'up', stats: { ok: false, stale: true, data: data({ announcesLastMinute: 999 }) } };
  const down = member('d', data({ announcesLastMinute: 999 }), { status: 'down' });
  const none = { key: 'n', status: 'up', stats: null };
  const failed = { key: 'f', status: 'up', stats: { ok: false, stale: false, error: 'network' } };
  const g = aggregateGroup([member('a', data()), stale, down, none, failed]);
  assert.equal(g.nodes, 5);
  assert.equal(g.reporting, 1);
  assert.equal(g.partial, true);
  assert.deepEqual(g.missing, ['s', 'd', 'n', 'f']);
  assert.equal(g.data.announcesLastMinute, 5);
  assert.equal(reports(down), false);
  assert.equal(reports(stale), false);
  assert.equal(reports(member('x', data(), { status: 'unknown' })), true);
});

test('aggregateGroup with nothing reporting has no data', () => {
  const g = aggregateGroup([{ key: 'a', status: 'down', stats: null }]);
  assert.deepEqual(g, { nodes: 1, reporting: 0, partial: true, missing: ['a'], data: null });
  assert.equal(aggregateGroup([]).data, null);
  assert.equal(aggregateGroup([]).partial, false);
});

const cfg = (extra = '') => loadConfig(`nodes:
  - address: p.test:1
    name: Front door
    stats_url: https://p.test/s
    proxy_for: [a.test:1, b.test:1]
${extra}
  - address: a.test:1
    stats_url: https://a.test/s
  - address: b.test:1
    stats_url: https://b.test/s
  - address: z.test:1
`);

async function monitor(config, results, { up = {} } = {}) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'website-'));
  return new Monitor({
    targets: config.targets,
    nodes: config.nodes,
    statsUrls: config.statsUrls,
    dataDir: dir,
    probeFn: async (host) => ({ up: up[host] !== false, ms: 3, error: up[host] === false ? 'timeout' : undefined }),
    statsFn: async (url) => results[new URL(url).hostname] ?? { ok: false, error: 'network' },
  });
}

test('snapshot marks proxies, proxied nodes, names and the group', async () => {
  const m = await monitor(cfg(), {
    'p.test': { ok: true, data: data({ announcesLastMinute: 100 }) },
    'a.test': { ok: true, data: data() },
    'b.test': { ok: true, data: data() },
  });
  await m.checkAll();
  const by = Object.fromEntries(m.snapshot().hosts.map((h) => [h.host, h]));
  assert.equal(by['p.test'].role, 'proxy');
  assert.equal(by['p.test'].name, 'Front door');
  assert.deepEqual(by['p.test'].proxy, { for: ['a.test:1', 'b.test:1'] });
  assert.equal(by['p.test'].proxiedBy, null);
  assert.equal(by['a.test'].role, 'node');
  assert.equal(by['a.test'].proxy, null);
  assert.equal(by['a.test'].proxiedBy, 'p.test:1');
  assert.equal(by['a.test'].group, null);
  assert.equal(by['z.test'].proxiedBy, null);
  assert.equal(by['z.test'].name, null);
  const g = by['p.test'].group;
  // count_own defaults to false: the proxy's own 100 announces are not added.
  assert.deepEqual({ nodes: g.nodes, reporting: g.reporting, partial: g.partial, countOwn: g.countOwn }, { nodes: 2, reporting: 2, partial: false, countOwn: false });
  assert.equal(g.data.announcesLastMinute, 10);
  assert.equal(g.data.interfaces.clients, 20);
});

test('count_own adds the proxy itself to its group, once', async () => {
  const m = await monitor(cfg('    count_own: true'), {
    'p.test': { ok: true, data: data({ announcesLastMinute: 100 }) },
    'a.test': { ok: true, data: data() },
    'b.test': { ok: true, data: data() },
  });
  await m.checkAll();
  const g = m.snapshot().hosts[0].group;
  assert.equal(g.nodes, 3);
  assert.equal(g.countOwn, true);
  assert.equal(g.data.announcesLastMinute, 110);
});

test('the group follows its members: a node that is down makes it partial', async () => {
  const m = await monitor(cfg(), { 'a.test': { ok: true, data: data() }, 'b.test': { ok: true, data: data() } }, { up: { 'b.test': false } });
  await m.checkAll();
  const g = m.snapshot().hosts[0].group;
  assert.equal(g.reporting, 1);
  assert.equal(g.partial, true);
  assert.deepEqual(g.missing, ['b.test:1']);
  assert.equal(g.data.announcesLastMinute, 5);
});

test('without a config every host is a plain node', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'website-'));
  const m = new Monitor({ targets: [{ host: 'a.test', port: 1 }], dataDir: dir, probeFn: async () => ({ up: true, ms: 1 }) });
  await m.checkAll();
  const h = m.snapshot().hosts[0];
  assert.deepEqual([h.name, h.role, h.proxy, h.proxiedBy, h.group], [null, 'node', null, null, null]);
});

const prop = (o = {}) => ({
  enabled: true, storedMessages: 100, storedBytes: 1000, storageLimitBytes: 10_000, peersConnected: 1, peersTotal: 4, peersAlive: 3, peersStatic: 1, peersAuto: 3,
  peerLimit: 20, staticPeers: 1, autopeer: true, autopeerDepth: 4, messagesReceived: 5, messagesServed: 6, messagesSentToPeers: 70, messagesReceivedFromPeers: 80,
  messagesOfferedToPeers: 9, unhandledMessages: 2, ...o,
});

test('aggregateGroup adds up the propagation numbers and reports the fullest disk, not summed free space', () => {
  const a = member('a', data({ propagation: prop(), disk: { dataBytes: 500, fsTotalBytes: 1000, fsFreeBytes: 400 } }));
  const b = member('b', data({ propagation: prop({ storedMessages: 50, storedBytes: null, peersAlive: 1, unhandledMessages: null }), disk: { dataBytes: 300, fsTotalBytes: 2000, fsFreeBytes: 200 } }));
  const old = member('old', data());
  const g = aggregateGroup([a, b, old]).data;
  assert.equal(g.propagation.nodes, 2);
  assert.equal(g.propagation.storedMessages, 150);
  assert.equal(g.propagation.storedBytes, 1000);
  assert.equal(g.propagation.peersAlive, 4);
  assert.equal(g.propagation.messagesSentToPeers, 140);
  assert.equal(g.propagation.unhandledMessages, 2);
  assert.equal(g.propagation.unhandledDistinct, null);
  assert.equal(g.disk.nodes, 2);
  assert.equal(g.disk.dataBytes, 800);
  assert.deepEqual(g.disk.lowestFree, { percent: 10, freeBytes: 200, totalBytes: 2000, node: 'b' });
});

test('aggregateGroup: no propagation or disk anywhere gives null, unknown sums stay null', () => {
  const g = aggregateGroup([member('a', data()), member('b', data())]).data;
  assert.equal(g.propagation, null);
  assert.equal(g.disk, null);
  const partial = aggregateGroup([member('a', data({ propagation: prop({ storedBytes: null, peerLimit: null }), disk: { dataBytes: null, fsTotalBytes: 0, fsFreeBytes: 5 } }))]).data;
  assert.equal(partial.propagation.storedBytes, null);
  assert.equal(partial.disk.dataBytes, null);
  assert.equal(partial.disk.lowestFree, null);
});

test('members that are down or stale are left out of the storage sums', () => {
  const a = member('a', data({ propagation: prop() }));
  const down = member('d', data({ propagation: prop({ storedMessages: 999 }) }), { status: 'down' });
  assert.equal(aggregateGroup([a, down]).data.propagation.storedMessages, 100);
});

test('aggregateGroup reports the largest distinct backlog of one node, never a sum', () => {
  const a = member('a', data({ propagation: prop({ unhandledDistinct: 7 }) }));
  const b = member('b', data({ propagation: prop({ unhandledDistinct: 12 }) }));
  const c = member('c', data({ propagation: prop({ unhandledDistinct: null }) }));
  assert.equal(aggregateGroup([a, b, c]).data.propagation.unhandledDistinct, 12);
  assert.equal(aggregateGroup([c]).data.propagation.unhandledDistinct, null);
});
