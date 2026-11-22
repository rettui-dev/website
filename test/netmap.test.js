import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';
import { loadConfig, MAX_UPSTREAMS } from '../lib/config.js';
import { Monitor } from '../lib/monitor.js';
import { createApp } from '../lib/app.js';
import { createLogin } from '../lib/login.js';
import { hashPassword } from '../lib/password.js';
import { fakeHasher } from './helpers/fake-hasher.js';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const publicDir = path.join(root, 'public');

// netmap.js is a browser script; with no document it exposes its pure helpers.
const sandbox = { Date, Math };
sandbox.globalThis = sandbox;
vm.runInNewContext(fs.readFileSync(path.join(publicDir, 'netmap.js'), 'utf8'), sandbox);
const { buildModel, layout, describe, summaryText, listItems, wrap, clip, rowsOf } = sandbox.netmapLogic;

const one = (extra) => `nodes:\n  - address: a.test:1\n${extra}`;
const bad = (text, pattern) => assert.throws(() => loadConfig(text), (e) => e instanceof Error && pattern.test(e.message), text);

// Config: upstreams

test('upstreams are read, trimmed and kept per node; a node without any has no key', () => {
  const c = loadConfig(`nodes:
  - address: a.test:1
    upstreams:
      - name: " Hub A "
        address: Hub.Example.org:4965
      - name: Hub B
  - address: b.test:1
`);
  assert.deepEqual(c.nodes.get('a.test:1').upstreams, [{ name: 'Hub A', address: 'hub.example.org:4965' }, { name: 'Hub B' }]);
  assert.equal(Object.hasOwn(c.nodes.get('b.test:1'), 'upstreams'), false);
  // An upstream is never a target to check.
  assert.deepEqual(c.targets, [{ host: 'a.test', port: 1 }, { host: 'b.test', port: 1 }]);
});

test('upstreams: limits', () => {
  const list = (n) => Array.from({ length: n }, (_, i) => `      - name: U${i}`).join('\n');
  assert.equal(loadConfig(one(`    upstreams:\n${list(MAX_UPSTREAMS)}\n`)).nodes.get('a.test:1').upstreams.length, 8);
  bad(one(`    upstreams:\n${list(MAX_UPSTREAMS + 1)}\n`), /1 to 8 upstreams/);
  bad(one('    upstreams: []\n'), /1 to 8 upstreams/);
  assert.equal(loadConfig(one(`    upstreams:\n      - name: ${'x'.repeat(48)}\n`)).nodes.get('a.test:1').upstreams[0].name.length, 48);
  bad(one(`    upstreams:\n      - name: ${'x'.repeat(49)}\n`), /1 to 48 characters/);
  bad(one('    upstreams:\n      - name: "   "\n'), /1 to 48 characters/);
});

test('upstreams: wrong types, unknown keys, bad addresses and repeats are errors', () => {
  bad(one('    upstreams: hub\n'), /list of 1 to 8/);
  bad(one('    upstreams: {name: x}\n'), /list of 1 to 8/);
  bad(one('    upstreams: [hub]\n'), /upstreams\[1\] must be a map/);
  bad(one('    upstreams:\n      - address: h.test:1\n'), /name must be text/);
  bad(one('    upstreams:\n      - name: 5\n'), /name must be text/);
  bad(one('    upstreams:\n      - name: x\n        stats_url: https://h.test/s\n'), /unknown key "stats_url"/);
  bad(one('    upstreams:\n      - name: x\n        proxy_for: []\n'), /unknown key "proxy_for"/);
  bad(one('    upstreams:\n      - name: "a\\u0007b"\n'), /control characters/);
  bad(one('    upstreams:\n      - name: x\n        address: nohost\n'), /address is not a host:port/);
  bad(one('    upstreams:\n      - name: x\n        address: "h.test:0"\n'), /address/);
  bad(one('    upstreams:\n      - name: x\n        address: [h.test:1]\n'), /address must be one host:port/);
  bad(one('    upstreams:\n      - name: x\n      - name: X\n'), /lists the name "X" twice/);
  // Only in the file, only on a node.
  bad('upstreams: []\nnodes:\n  - address: a.test:1', /unknown key "upstreams" at the top level/);
});

test('upstream addresses are never probed, and no stats are fetched for them', async () => {
  const c = loadConfig(`nodes:
  - address: a.test:1
    stats_url: https://a.test/s
    upstreams:
      - name: Hub
        address: hub.example.org:4965
`);
  const probed = [];
  const fetched = [];
  const monitor = new Monitor({
    targets: c.targets, nodes: c.nodes, statsUrls: c.statsUrls, dataDir: await fsp.mkdtemp(path.join(os.tmpdir(), 'website-')),
    probeFn: async (host, port) => (probed.push(`${host}:${port}`), { up: true, ms: 1 }),
    statsFn: async (url) => (fetched.push(url), { ok: false, error: 'network' }),
  });
  await monitor.checkAll();
  await monitor.checkAll();
  assert.deepEqual([...new Set(probed)], ['a.test:1']);
  assert.deepEqual([...new Set(fetched)], ['https://a.test/s']);
  assert.equal(monitor.history.has('hub.example.org:4965'), false);
  assert.equal(monitor.snapshot().hosts.length, 1);
});

test('the example config documents upstreams in a form that is valid when uncommented', async () => {
  const text = await fsp.readFile(path.join(root, 'config.example.yaml'), 'utf8');
  assert.match(text, /^ {4}# upstreams:$/m);
  const on = text.replace(/^ {4}# ( *)(upstreams:|- name: .*|address: .*:\d+)$/gm, '      $1$2').replace(/^      upstreams:$/m, '    upstreams:');
  const c = loadConfig(on);
  assert.ok([...c.nodes.values()].some((n) => n.upstreams?.length));
});

// API

const statsData = () => ({
  rettuiVersion: '9.8.7', generatedAt: 1, uptimeSeconds: 100,
  interfaces: { total: 1, online: 1, clients: 4, rxBytes: 1, txBytes: 1 },
  peersHeard: { total: 3, lxmf: 2, nomad: 1, propagation: 0 }, announcesLastMinute: 0,
  disk: { dataBytes: 123_456, fsTotalBytes: 1000, fsFreeBytes: 80 },
});

async function serve({ users = false, upstreams = '' } = {}) {
  const hash = users ? await hashPassword('correct horse battery', undefined, fakeHasher) : '';
  const c = loadConfig(`${users ? `users:\n  - name: alice\n    password_hash: '${hash}'\n` : ''}nodes:
  - address: p.test:1
    stats_url: https://p.test/s
    proxy_for: [a.test:1]
    upstreams:
      - name: Edge hub
        address: edge.example.org:4965
  - address: a.test:1
    stats_url: https://a.test/s
${upstreams}
`);
  const monitor = new Monitor({
    targets: c.targets, nodes: c.nodes, statsUrls: c.statsUrls, dataDir: await fsp.mkdtemp(path.join(os.tmpdir(), 'website-')),
    requireLogin: c.defaults.requireLogin, probeFn: async () => ({ up: true, ms: 1 }), statsFn: async () => ({ ok: true, data: statsData() }),
  });
  await monitor.checkAll();
  const login = users ? createLogin({ users: c.users, settings: c.login, hasher: fakeHasher }) : undefined;
  const server = createApp({ monitor, publicDir, ...(login ? { login } : {}) });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}`;
  return { base, close: () => (server.closeAllConnections(), new Promise((r) => server.close(r))) };
}

test('/api/status gives upstreams only to the hosts that have them, with name and address only', async () => {
  const s = await serve();
  try {
    const body = await (await fetch(`${s.base}/api/status`)).json();
    const [p, a] = body.hosts;
    assert.deepEqual(p.upstreams, [{ name: 'Edge hub', address: 'edge.example.org:4965' }]);
    assert.equal(Object.hasOwn(a, 'upstreams'), false);
    // The rest of the shape is what it was.
    assert.deepEqual(Object.keys(p).filter((k) => !Object.hasOwn(a, k)), ['upstreams']);
  } finally {
    await s.close();
  }
});

test('/api/status stays small with the most upstreams a node can have', async () => {
  const many = Array.from({ length: MAX_UPSTREAMS }, (_, i) => `      - name: ${'n'.repeat(48 - 2)}${String(i).padStart(2, '0')}\n        address: ${'h'.repeat(40)}${i}.example.org:4965`).join('\n');
  const text = `nodes:\n  - address: a.test:1\n    upstreams:\n${many}\n`;
  const c = loadConfig(text);
  const monitor = new Monitor({ targets: c.targets, nodes: c.nodes, dataDir: await fsp.mkdtemp(path.join(os.tmpdir(), 'website-')), probeFn: async () => ({ up: true, ms: 1 }) });
  await monitor.checkAll();
  const ups = JSON.stringify(monitor.snapshot().hosts[0].upstreams);
  assert.equal(monitor.snapshot().hosts[0].upstreams.length, 8);
  assert.ok(ups.length < 8 * 140, `upstreams are ${ups.length} bytes`);
});

test('with users and require_login the map adds nothing that is locked', async () => {
  const s = await serve({ users: true });
  try {
    const res = await fetch(`${s.base}/api/status`);
    const text = await res.text();
    const body = JSON.parse(text);
    // The locked parts are not in the answer, with or without the upstreams.
    for (const secret of ['9.8.7', 'dataBytes', 'fsFreeBytes', '123456', 'usedPercent']) assert.equal(text.includes(secret), false, secret);
    assert.deepEqual(body.hosts[0].upstreams, [{ name: 'Edge hub', address: 'edge.example.org:4965' }]);
    // What the map reads (state, clients, connect time, uptime) is public data.
    assert.equal(body.hosts[0].status, 'up');
    assert.equal(body.hosts[0].stats.data.interfaces.clients, 4);
    assert.deepEqual(body.hosts[0].locked.sort(), ['details', 'disk', 'links', 'peers', 'storage', 'versions']);
    // The static files of the map are public too.
    assert.equal((await fetch(`${s.base}/netmap.js`)).status, 200);
  } finally {
    await s.close();
  }
});

test('the page loads the map script from its own origin, with no inline script or style', async () => {
  const html = fs.readFileSync(path.join(publicDir, 'status.html'), 'utf8');
  assert.match(html, /<script src="\/netmap\.js" defer><\/script>/);
  assert.doesNotMatch(html, /<script(?![^>]*\bsrc=)/);
  assert.doesNotMatch(html, /\sstyle=/);
  const js = fs.readFileSync(path.join(publicDir, 'netmap.js'), 'utf8');
  assert.doesNotMatch(js, /innerHTML|insertAdjacentHTML|\.style\b|setAttribute\('style'/);
});

// Model and layout

const host = (port, over = {}) => ({ host: 'h', port, name: null, status: 'up', latencyMs: 5, role: 'node', proxy: null, proxiedBy: null, uptime90: { percent90: 99.5 }, stats: { ok: true, stale: false, data: { interfaces: { clients: 3 } } }, ...over });
const door = host(1, { name: 'Front door', role: 'proxy', proxy: { for: ['h:2', 'h:3'] }, upstreams: [{ name: 'Edge', address: 'e.test:1' }] });
const front = host(2, { name: 'Front', proxiedBy: 'h:1', upstreams: [{ name: 'edge' }, { name: 'Edge', address: 'e.test:1' }] });
const back = host(3, { name: 'Back', proxiedBy: 'h:1', status: 'down', latencyMs: null });

test('buildModel: tiers, shared upstreams, link kinds and down links', () => {
  const m = buildModel([door, front, back]);
  assert.equal(m.empty, false);
  const tier = Object.fromEntries(m.nodes.map((n) => [n.id, n.tier]));
  assert.deepEqual({ ...tier }, { 'h:1': 0, 'h:2': 1, 'h:3': 1, 'ext:edge|e.test:1': 2, 'ext:edge|': 2 });
  const e = m.edges.map((x) => `${x.from}>${x.to}:${x.kind}${x.down ? ':down' : ''}`);
  assert.deepEqual([...e], ['h:1>h:2:proxy', 'h:1>h:3:proxy:down', 'h:1>ext:edge|e.test:1:upstream', 'h:2>ext:edge|:upstream', 'h:2>ext:edge|e.test:1:upstream']);
  assert.deepEqual([...m.nodes.find((n) => n.id === 'ext:edge|e.test:1').usedBy], ['Front door', 'Front']);
});

test('buildModel: nothing to draw without a proxy or an upstream; garbage input is survived', () => {
  assert.equal(buildModel([host(1), host(2)]).empty, true);
  assert.equal(buildModel([]).empty, true);
  assert.equal(buildModel(undefined).empty, true);
  assert.equal(buildModel([host(1, { upstreams: 'x' })]).empty, true);
  // The proxy group alone is a map.
  const m = buildModel([door, front, back].map((h) => ({ ...h, upstreams: undefined })));
  assert.equal(m.empty, false);
  assert.equal(m.nodes.length, 3);
});

test('buildModel: clients only from fresh stats of a node that is not down', () => {
  const n = (over) => buildModel([host(1, { role: 'proxy', proxy: { for: [] }, ...over })]).nodes[0].clients;
  assert.equal(n({}), 3);
  assert.equal(n({ stats: { ok: true, stale: true, data: { interfaces: { clients: 3 } } } }), null);
  assert.equal(n({ stats: null }), null);
  assert.equal(n({ stats: { ok: false } }), null);
  assert.equal(n({ stats: { ok: true, stale: false, data: { interfaces: { clients: null } } } }), null);
  assert.equal(n({ status: 'down' }), null);
});

test('describe: the same words for the title, the name and the list', () => {
  const m = buildModel([door, front, back]);
  const by = Object.fromEntries(m.nodes.map((x) => [x.id, x]));
  assert.equal(describe(by['h:1']), 'Proxy Front door, up, passes visitors to 2 nodes, 3 clients, connect time 5 ms, uptime 99.5% over 90 days.');
  assert.equal(describe(by['h:3']), 'Back: down, uptime 99.5% over 90 days.');
  assert.equal(describe(by['ext:edge|e.test:1']), 'Edge: external backbone peer, not monitored, address e.test:1 (not checked), used by Front door, Front.');
  assert.match(listItems(m)[0], /Connects to Front, Back, Edge\.$/);
  assert.doesNotMatch(listItems(m)[2], /Connects/);
});

test('layout: wide gives a column per tier, inside the box, with a link for each edge', () => {
  const m = buildModel([door, front, back]);
  const l = layout(m, 1000);
  assert.equal(l.mode, 'columns');
  assert.equal(l.nodes.length, 5);
  assert.equal(l.edges.length, 5);
  for (const n of l.nodes) {
    assert.ok(n.x >= 0 && n.x + n.w <= l.width, n.id);
    assert.ok(n.y >= 0 && n.y + n.h <= l.height, n.id);
  }
  const x = (id) => l.nodes.find((n) => n.id === id).x;
  assert.ok(x('h:1') < x('h:2') && x('h:2') < x('ext:edge|e.test:1'));
  assert.ok(l.edges.every((e) => /^M[\d. -]+ C/.test(e.d)));
  // Each node carries its words, and no two nodes overlap.
  assert.ok(l.nodes.every((n) => n.label.length > 0 && n.lines.length >= 2));
  for (const a of l.nodes) for (const b of l.nodes) {
    if (a !== b) assert.ok(a.x + a.w <= b.x || b.x + b.w <= a.x || a.y + a.h <= b.y || b.y + b.h <= a.y, `${a.id} overlaps ${b.id}`);
  }
});

test('layout: narrow stacks the tiers, fits 360px and wraps a crowded tier', () => {
  const ups = Array.from({ length: 8 }, (_, i) => ({ name: `Peer ${i}` }));
  const m = buildModel([door, { ...front, upstreams: ups }, back]);
  for (const w of [360, 320, 280, 100]) {
    const l = layout(m, w);
    assert.equal(l.mode, 'rows');
    assert.ok(l.width >= 280);
    for (const n of l.nodes) assert.ok(n.x >= 0 && n.x + n.w <= l.width + 0.5, `${w}: ${n.id}`);
    const rows = new Set(l.nodes.filter((n) => n.kind === 'external').map((n) => n.y));
    assert.ok(rows.size > 1, 'a tier of 8 wraps');
    const y = (id) => l.nodes.find((n) => n.id === id).y;
    assert.ok(y('h:1') < y('h:2'));
    for (const a of l.nodes) for (const b of l.nodes) {
      if (a !== b) assert.ok(a.x + a.w <= b.x || b.x + b.w <= a.x || a.y + a.h <= b.y || b.y + b.h <= a.y, `${w}: ${a.id} overlaps ${b.id}`);
    }
    for (const n of l.nodes) for (const t of n.lines) assert.ok(t.text.length <= Math.floor((n.w - 10) / 6.8) + 1, t.text);
  }
  // A proxy group alone fits three across at 360.
  const g = layout(buildModel([door, front, back].map((h) => ({ ...h, upstreams: undefined }))), 360);
  assert.equal(new Set(g.nodes.filter((n) => n.tier === undefined && n.kind === 'node').map((n) => n.y)).size, 1);
});

test('layout: a single tier is centred, and a down link is marked', () => {
  const l = layout(buildModel([host(1, { role: 'proxy', proxy: { for: [] }, upstreams: [{ name: 'X' }] })]), 800);
  assert.equal(l.nodes.length, 2);
  const m = layout(buildModel([door, front, back]), 800);
  assert.deepEqual([...m.edges.filter((e) => e.down).map((e) => e.to)], ['h:3']);
});

test('state is in words as well as colour, on every node', () => {
  const l = layout(buildModel([door, front, back]), 800);
  const state = (id) => l.nodes.find((n) => n.id === id).lines.find((t) => t.cls === 'nm-state').text;
  assert.equal(state('h:1'), '● Up');
  assert.equal(state('h:3'), '✕ Down');
  assert.match(state('ext:edge|e.test:1'), /External$/);
  assert.equal(layout(buildModel([host(1, { status: 'unknown', role: 'proxy', proxy: { for: [] } })]), 800).nodes[0].lines.find((t) => t.cls === 'nm-state').text, '? Unknown');
});

test('a proxy is a different kind of box: wider, taller, tagged, and still has its state', () => {
  const m = buildModel([door, front, back]);
  assert.deepEqual([...m.nodes.filter((n) => n.kind !== 'external').map((n) => `${n.id}=${n.kind}`)], ['h:1=proxy', 'h:2=node', 'h:3=node']);
  for (const w of [1000, 360]) {
    const l = layout(m, w);
    const by = Object.fromEntries(l.nodes.map((n) => [n.id, n]));
    assert.ok(by['h:1'].w > by['h:2'].w || w < 400, `${w}: wider`);
    assert.ok(by['h:1'].h > by['h:2'].h, `${w}: taller`);
    // The tag is text, first in the box; the state word and glyph stay.
    assert.deepEqual([...by['h:1'].lines.filter((t) => t.cls === 'nm-tag').map((t) => t.text)], ['Proxy']);
    assert.equal(by['h:1'].lines[0].cls, 'nm-tag');
    assert.equal(by['h:1'].lines.find((t) => t.cls === 'nm-state').text, '● Up');
    assert.equal(by['h:2'].lines.some((t) => t.cls === 'nm-tag'), false);
    assert.equal(by['ext:edge|e.test:1'].lines.some((t) => t.cls === 'nm-tag'), false);
    // Every line is inside its box, and the lines do not collide.
    for (const n of l.nodes) {
      const ys = n.lines.map((t) => t.y);
      assert.ok(ys.every((y, i) => y > 0 && y < n.h && (i === 0 || y - ys[i - 1] >= 15)), `${w}: ${n.id}`);
    }
  }
  // Wide mode: the proxy keeps its centre in line with the nodes, and links start at its right edge.
  const l = layout(m, 1000);
  const door1 = l.nodes.find((n) => n.id === 'h:1');
  assert.ok(l.edges.filter((e) => e.kind === 'proxy').every((e) => e.d.startsWith('M' + (door1.x + door1.w) + ' ')));
  // The same words in the list.
  assert.match(listItems(m)[0], /^Proxy Front door, up, /);
  assert.doesNotMatch(listItems(m)[1], /^Proxy/);
});

test('a proxy with no nodes behind it, and a proxy that is down, are still drawn as a proxy', () => {
  const l = layout(buildModel([host(1, { name: 'Door', role: 'proxy', proxy: { for: [] }, status: 'down', latencyMs: null })]), 800);
  assert.equal(l.nodes[0].kind, 'proxy');
  assert.equal(l.nodes[0].state, 'down');
  assert.equal(l.nodes[0].label, 'Proxy Door, down, passes visitors to 0 nodes, uptime 99.5% over 90 days.');
  assert.deepEqual([...l.nodes[0].lines.map((t) => t.text)], ['Proxy', 'Door', '✕ Down']);
});

test('summaryText says proxies, nodes, external peers and links apart', () => {
  assert.equal(summaryText(buildModel([door, front, back])), '1 proxy, 2 nodes, 2 external peers, 5 links');
  assert.equal(summaryText(buildModel([host(1, { role: 'proxy', proxy: { for: [] } })])), '1 proxy, 0 links');
  assert.equal(summaryText(buildModel([host(1, { upstreams: [{ name: 'A' }, { name: 'B' }] })])), '1 node, 2 external peers, 2 links');
});

test('the page says what the proxy box looks like, and the styles keep its accent and state', () => {
  const html = fs.readFileSync(path.join(publicDir, 'status.html'), 'utf8');
  assert.match(html, /double border and the tag Proxy/);
  const css = fs.readFileSync(path.join(publicDir, 'site.css'), 'utf8');
  assert.match(css, /\.nm-box-inner \{[^}]*stroke: var\(--accent\)/);
  assert.match(css, /\.nm-tag \{[^}]*fill: var\(--accent\)/);
  // State colours stay on the outer box.
  assert.match(css, /\.nm-node\.down \.nm-box \{ stroke: var\(--red\)/);
});

test('wrap, clip and rowsOf', () => {
  assert.deepEqual([...wrap('Amsterdam backbone hub', 14, 2)], ['Amsterdam', 'backbone hub']);
  assert.deepEqual([...wrap('Short', 14, 2)], ['Short']);
  assert.deepEqual([...wrap('a'.repeat(30), 10, 2)], ['aaaaaaaaaa', 'aaaaaaaaa…']);
  assert.deepEqual([...wrap('one two three four five six', 8, 2)], ['one two', 'three f…']);
  assert.deepEqual([...wrap('', 8, 2)], ['']);
  assert.equal(clip('abcdef', 4), 'abc…');
  assert.equal(clip('abc', 4), 'abc');
  assert.equal(clip('abcdef', 0).length, 2);
  assert.deepEqual([...rowsOf(8, 3)], [3, 3, 2]);
  assert.deepEqual([...rowsOf(2, 5)], [2]);
  assert.deepEqual([...rowsOf(3, 2)], [2, 1]);
});
