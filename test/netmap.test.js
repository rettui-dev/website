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

const inside = (n, l, label = '') => assert.ok(n.x >= 0 && n.x + n.w <= l.width && n.y >= 0 && n.y + n.h <= l.height, `${label} ${n.id} outside`);
const apart = (nodes, label = '') => {
  for (const a of nodes) for (const b of nodes) {
    if (a !== b) assert.ok(a.x + a.w <= b.x || b.x + b.w <= a.x || a.y + a.h <= b.y || b.y + b.h <= a.y, `${label} ${a.id} overlaps ${b.id}`);
  }
};

test('layout: wide draws the proxy as a frame around its nodes, with the external peers below it', () => {
  const m = buildModel([door, front, back]);
  const l = layout(m, 1000);
  assert.equal(l.mode, 'frame');
  const frame = l.nodes.find((n) => n.id === 'h:1');
  assert.equal(frame.frame, true);
  const boxes = l.nodes.filter((n) => !n.frame);
  for (const n of l.nodes) inside(n, l);
  apart(boxes);
  for (const id of ['h:2', 'h:3']) {
    const n = l.nodes.find((x) => x.id === id);
    assert.ok(n.x > frame.x && n.x + n.w < frame.x + frame.w && n.y > frame.y && n.y + n.h < frame.y + frame.h, `${id} is inside the frame`);
  }
  for (const n of boxes.filter((x) => x.kind === 'external')) assert.ok(n.y > frame.y + frame.h, `${n.id} is below the frame`);
  // No line from the proxy to its nodes: the frame says it. The peer listed by the proxy and by Front is one box with a line from each.
  assert.equal(l.edges.filter((e) => e.kind === 'proxy').length, 0);
  assert.deepEqual([...l.edges.filter((e) => e.kind === 'upstream').map((e) => `${e.from}>${e.to}`)].sort(), ['h:1>ext:edge|e.test:1', 'h:2>ext:edge|', 'h:2>ext:edge|e.test:1']);
  assert.equal(l.nodes.filter((n) => n.id === 'ext:edge|e.test:1').length, 1);
  // Each line starts at its node (the proxy's at the foot of its frame) and ends at the top of its peer.
  for (const e of l.edges) {
    const from = l.nodes.find((n) => n.id === e.from);
    const to = l.nodes.find((n) => n.id === e.to);
    const [sx, sy] = e.pts[0];
    const [ex, ey] = e.pts.at(-1);
    assert.equal(sy, from.y + from.h, e.from);
    assert.ok(sx >= from.x && sx <= from.x + from.w);
    assert.equal(ey, to.y);
    assert.ok(ex > to.x && ex < to.x + to.w);
  }
  assert.ok(l.nodes.every((n) => n.label.length > 0 && n.lines.length >= 2));
});

test('layout: narrow shows one node at a time, inside the width, from 360 down to 100 pixels', () => {
  const ups = Array.from({ length: 8 }, (_, i) => ({ name: `Peer ${i}` }));
  const m = buildModel([door, { ...front, upstreams: ups }, back]);
  for (const w of [360, 320, 280, 100]) {
    const l = layout(m, w);
    assert.equal(l.mode, 'focus');
    assert.equal(l.reason, 'narrow');
    assert.ok(l.width >= 280);
    assert.equal(l.selected, 'h:2');
    assert.deepEqual([...l.pills.map((p) => p.id)], ['h:2', 'h:3']);
    for (const n of l.nodes) inside(n, l, String(w));
    apart(l.nodes, String(w));
    assert.equal(l.nodes.filter((n) => n.kind === 'external').length, 8);
    for (const n of l.nodes) for (const t of n.lines) assert.ok(t.text.length <= Math.floor((n.w - 10) / 6.8) + 1, t.text);
  }
});

test('layout: a down node greys its lines', () => {
  const l = layout(buildModel([door, front, { ...back, upstreams: [{ name: 'X' }] }]), 1000);
  assert.deepEqual([...l.edges.filter((e) => e.down).map((e) => e.to)], ['ext:x|']);
  const one = layout(buildModel([host(1, { role: 'proxy', proxy: { for: [] }, upstreams: [{ name: 'X' }] })]), 800);
  assert.equal(one.nodes.length, 2);
});

test('state is in words as well as colour, on every node', () => {
  const l = layout(buildModel([door, front, back]), 800);
  const state = (id) => l.nodes.find((n) => n.id === id).lines.find((t) => t.cls === 'nm-state').text;
  assert.equal(state('h:1'), '● Up');
  assert.equal(state('h:3'), '✕ Down');
  assert.match(state('ext:edge|e.test:1'), /External$/);
  assert.equal(layout(buildModel([host(1, { status: 'unknown', role: 'proxy', proxy: { for: [] } })]), 800).nodes[0].lines.find((t) => t.cls === 'nm-state').text, '? Unknown');
});

test('a proxy is a frame with a header in the whole map, and a taller tagged box in the one-node view', () => {
  const m = buildModel([door, front, back]);
  assert.deepEqual([...m.nodes.filter((n) => n.kind !== 'external').map((n) => `${n.id}=${n.kind}`)], ['h:1=proxy', 'h:2=node', 'h:3=node']);
  const wide = layout(m, 1000);
  const frame = wide.nodes.find((n) => n.id === 'h:1');
  assert.deepEqual([...frame.lines.map((t) => t.text)], ['Proxy', 'Front door', '● Up', '3 clients · 5 ms · 99.5% uptime', 'Passes visitors to the 2 nodes inside']);
  assert.equal(frame.lines[0].cls, 'nm-tag');
  for (const t of frame.lines) assert.ok(t.y > 0 && t.y < frame.h && t.x > 0 && t.x < frame.w, t.text);
  const narrow = layout(m, 360);
  const by = Object.fromEntries(narrow.nodes.map((n) => [n.id, n]));
  assert.equal(by['h:1'].frame, undefined);
  assert.ok(by['h:1'].h > 76, 'taller than a node');
  assert.deepEqual([...by['h:1'].lines.filter((t) => t.cls === 'nm-tag').map((t) => t.text)], ['Proxy']);
  assert.equal(by['h:1'].lines.find((t) => t.cls === 'nm-state').text, '● Up');
  // The proxy is above the node, joined by a line that says it passes visitors to it.
  assert.ok(by['h:1'].y + by['h:1'].h < by['h:2'].y);
  assert.deepEqual([...narrow.edges.filter((e) => e.kind === 'proxy').map((e) => `${e.from}>${e.to}`)], ['h:1>h:2']);
  assert.ok(narrow.texts.some((t) => t.text === 'passes visitors to'));
  for (const n of narrow.nodes) {
    const ys = n.lines.map((t) => t.y);
    assert.ok(ys.every((y, i) => y > 0 && y < n.h && (i === 0 || y - ys[i - 1] >= 15)), n.id);
  }
  assert.match(listItems(m)[0], /^Proxy Front door, up, /);
  assert.doesNotMatch(listItems(m)[1], /^Proxy/);
});

test('a proxy with no nodes behind it, and a proxy that is down, are still drawn as a proxy', () => {
  const l = layout(buildModel([host(1, { name: 'Door', role: 'proxy', proxy: { for: [] }, status: 'down', latencyMs: null })]), 800);
  assert.equal(l.nodes[0].kind, 'proxy');
  assert.equal(l.nodes[0].state, 'down');
  assert.equal(l.nodes[0].label, 'Proxy Door, down, passes visitors to 0 nodes, uptime 99.5% over 90 days.');
  assert.deepEqual([...l.nodes[0].lines.map((t) => t.text)], ['Proxy', 'Door', '✕ Down', '99.5% uptime', 'No nodes behind it on this page']);
  const narrow = layout(buildModel([host(1, { name: 'Door', role: 'proxy', proxy: { for: [] }, status: 'down', latencyMs: null })]), 300);
  assert.deepEqual([...narrow.nodes[0].lines.map((t) => t.text)], ['Door', '✕ Down', 'uptime 99.5% over 90 days']);
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

