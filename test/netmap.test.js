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

// The frame and the one-node view, against the design mocks.

const { planRow, focusModel, pickFocus, limits } = sandbox.netmapLogic;
const mock = (port, name, over = {}) => host(port, { name, proxiedBy: 'h:99', ...over });
const dials = (...ports) => ports.map((p) => ({ to: `h:${p}`, dir: 'dials', enabled: true, source: 'detected', conflict: null }));
const rns = (ports) => host(99, { name: 'RNS', role: 'proxy', proxy: { for: ports.map((p) => `h:${p}`) } });
// Three nodes: Front dials Back and Side, Back dials Side, each has one external peer.
const mock3 = () => [rns([1, 2, 3]),
  mock(1, 'Front', { links: dials(2, 3), upstreams: [{ name: 'Ratspeak' }] }),
  mock(2, 'Back', { links: dials(3), upstreams: [{ name: 'RNS Beleth' }] }),
  mock(3, 'Side', { upstreams: [{ name: 'MichMesh' }] })];
// Eight nodes in the order of the mock, with its ten links and one node down.
const ORD = ['E', 'F', 'B', 'S', 'M', 'R', 'A', 'Sp'];
const L8 = [['E', 'F'], ['E', 'M'], ['F', 'B'], ['F', 'S'], ['B', 'S'], ['B', 'R'], ['M', 'R'], ['R', 'A'], ['S', 'A'], ['A', 'Sp']];
const EXT8 = { E: 'Quad4', F: 'Ratspeak', B: 'RNS Beleth', S: 'MichMesh', R: 'Amsterdam' };
const p8 = (k) => ORD.indexOf(k) + 1;
const mock8 = (count = 8) => [rns(Array.from({ length: count }, (_, i) => i + 1)), ...Array.from({ length: count }, (_, i) => {
  const k = ORD[i];
  return mock(i + 1, k ? `Node ${k}` : `Extra ${i}`, {
    status: k === 'Sp' ? 'down' : 'up', links: k ? dials(...L8.filter(([a]) => a === k).map(([, b]) => p8(b))) : [],
    ...(EXT8[k] ? { upstreams: [{ name: EXT8[k] }] } : {}),
  });
})];
const through = (p, q, n) => {
  const [x1, y1] = p;
  const [x2, y2] = q;
  const inX = (x) => x > n.x + 0.5 && x < n.x + n.w - 0.5;
  const inY = (y) => y > n.y + 0.5 && y < n.y + n.h - 0.5;
  if (x1 === x2) return inX(x1) && Math.max(y1, y2) > n.y + 0.5 && Math.min(y1, y2) < n.y + n.h - 0.5;
  if (y1 === y2) return inY(y1) && Math.max(x1, x2) > n.x + 0.5 && Math.min(x1, x2) < n.x + n.w - 0.5;
  return false;
};

test('the three node mock: a frame around the row, arcs above it, peers below it, all inside the width', () => {
  const m = buildModel(mock3());
  for (const w of [1100, 1000, 640]) {
    const l = layout(m, w);
    assert.equal(l.mode, 'frame', String(w));
    const frame = l.nodes.find((n) => n.frame);
    const row = l.nodes.filter((n) => n.kind === 'node');
    const ext = l.nodes.filter((n) => n.kind === 'external');
    assert.equal(row.length, 3);
    assert.equal(ext.length, 3);
    assert.ok(frame.x >= 0 && frame.x + frame.w <= l.width);
    for (const n of row) {
      assert.ok(n.x > frame.x && n.x + n.w < frame.x + frame.w && n.y > frame.y && n.y + n.h < frame.y + frame.h, `${w}: ${n.id} inside the frame`);
      assert.ok(n.w <= 176 && n.w >= 104);
      assert.equal(n.y, row[0].y, 'one row');
    }
    apart([...row, ...ext]);
    // The node's peer is right under it, joined by a straight line that crosses the frame's foot.
    for (const e of l.edges.filter((x) => x.kind === 'upstream')) {
      const a = l.nodes.find((n) => n.id === e.from);
      const b = l.nodes.find((n) => n.id === e.to);
      assert.ok(b.y > frame.y + frame.h);
      assert.equal(e.pts.length, 2, 'straight down');
      assert.equal(e.pts[0][0], a.x + a.w / 2);
      assert.ok(e.pts[0][1] < frame.y + frame.h && e.pts[1][1] > frame.y + frame.h);
    }
    const links = l.edges.filter((x) => x.kind === 'link');
    assert.deepEqual([...links.map((e) => `${e.from}>${e.to}:${e.pts.length}`)].sort(), ['h:1>h:2:2', 'h:1>h:3:4', 'h:2>h:3:2']);
    const arc = links.find((e) => e.pts.length === 4);
    assert.equal(arc.lane, 0);
    assert.ok(arc.pts[1][1] < row[0].y && arc.pts[1][1] > frame.y + 90, 'above the row, under the header');
    for (const e of links) for (const n of row) for (let i = 1; i < e.pts.length; i++) assert.ok(!through(e.pts[i - 1], e.pts[i], n), `${e.from}>${e.to} through ${n.id}`);
  }
});

test('the eight node mock: at most four lanes, no arc through a box, and every arc in its own lane where they overlap', () => {
  const m = buildModel(mock8());
  const nodes = m.nodes.filter((n) => n.kind === 'node');
  const row = planRow(nodes, m.edges.filter((e) => e.kind === 'link'));
  assert.equal(row.near.length + row.skips.length, 10);
  assert.ok(row.lanes <= limits.MAX_LANES, `${row.lanes} lanes`);
  assert.equal(row.lanes, 3);
  for (const a of row.skips) for (const b of row.skips) {
    if (a === b || a.lane !== b.lane) continue;
    const [lo1, hi1] = [Math.min(a.ia, a.ib), Math.max(a.ia, a.ib)];
    const [lo2, hi2] = [Math.min(b.ia, b.ib), Math.max(b.ia, b.ib)];
    assert.ok(hi1 <= lo2 || hi2 <= lo1, 'arcs in one lane do not overlap');
  }
  const l = layout(m, 1100);
  assert.equal(l.mode, 'frame');
  const boxes = l.nodes.filter((n) => n.kind === 'node');
  assert.ok(boxes.every((n) => n.w >= 104 && n.w <= 176));
  apart(l.nodes.filter((n) => !n.frame));
  for (const e of l.edges) for (const n of boxes) for (let i = 1; i < e.pts.length; i++) assert.ok(!through(e.pts[i - 1], e.pts[i], n), `${e.from}>${e.to} through ${n.id}`);
  // Two arcs that meet one node from the same side meet it at different points.
  const tops = l.edges.filter((e) => e.kind === 'link' && e.pts.length === 4).flatMap((e) => [e.pts[0], e.pts[3]].map((p) => p.join()));
  assert.equal(new Set(tops).size, tops.length);
  // The link to the node that is down is grey with slashes.
  const down = l.edges.find((e) => e.to === 'h:8');
  assert.equal(down.down, true);
  assert.equal(down.ticks.length, 2);
});

test('the one-node view takes over below 640 pixels, above 8 nodes in a row, or above 4 lanes', () => {
  assert.deepEqual({ ...limits }, { FOCUS_BELOW: 640, MAX_ROW_NODES: 8, MAX_LANES: 4 });
  const m3 = buildModel(mock3());
  assert.equal(layout(m3, 640).mode, 'frame');
  assert.equal(layout(m3, 639).mode, 'focus');
  assert.equal(layout(m3, 639).reason, 'narrow');
  assert.equal(layout(buildModel(mock8(8)), 1400).mode, 'frame');
  const nine = layout(buildModel(mock8(9)), 1400);
  assert.equal(nine.mode, 'focus');
  assert.equal(nine.reason, 'crowded');
  // Nodes behind no proxy follow the same rule.
  const loose = (n) => buildModel(Array.from({ length: n }, (_, i) => host(i + 1, { name: `N${i}`, upstreams: [{ name: `P${i}` }] })));
  assert.equal(layout(loose(8), 1400).mode, 'frame');
  assert.equal(layout(loose(9), 1400).reason, 'crowded');
  // Five lanes: one node dials each of the others but its neighbour, then the next does too.
  const fan = buildModel([rns([1, 2, 3, 4, 5, 6, 7]), ...Array.from({ length: 7 }, (_, i) => mock(i + 1, `N${i}`, { links: i === 0 ? dials(3, 4, 5, 6, 7) : i === 1 ? dials(4, 5, 6, 7) : [] }))]);
  const lanes = planRow(fan.nodes.filter((n) => n.kind === 'node'), fan.edges.filter((e) => e.kind === 'link')).lanes;
  assert.ok(lanes > 4, `${lanes} lanes`);
  assert.equal(layout(fan, 1400).reason, 'lanes');
  // Eight nodes do not fit in a row at 640: the boxes would be narrower than 104.
  assert.equal(layout(buildModel(mock8(8)), 800).reason, 'fit');
});

test('focus model: a node dialled by two, dialling one, with one external peer', () => {
  const m = buildModel(mock8());
  const f = focusModel(m, 'h:6');
  assert.equal(f.node.name, 'Node R');
  assert.deepEqual([...f.proxies.map((p) => p.id)], ['h:99']);
  assert.deepEqual([...f.dialledBy.map((x) => x.node.name)], ['Node B', 'Node M']);
  assert.deepEqual([...f.dials.map((x) => x.node.name)], ['Node A']);
  assert.deepEqual([...f.externals.map((x) => x.node.name)], ['Amsterdam']);
  assert.equal(focusModel(m, 'h:404'), null);
  for (const w of [1100, 390, 330, 280]) {
    const l = layout(buildModel(mock8(9)), w, 'h:6');
    assert.equal(l.mode, 'focus');
    assert.equal(l.selected, 'h:6');
    const by = Object.fromEntries(l.nodes.map((n) => [n.id, n]));
    const mid = l.nodes.find((n) => n.focus);
    assert.equal(mid.id, 'h:6');
    assert.ok(by['h:99'].y + by['h:99'].h < mid.y, `${w}: the proxy is above`);
    assert.ok(by['ext:amsterdam|'].y > mid.y + mid.h, `${w}: the peer is below`);
    if (w >= 640) {
      assert.ok(by['h:3'].x + by['h:3'].w <= mid.x && by['h:5'].x + by['h:5'].w <= mid.x, 'dialled by: left');
      assert.ok(by['h:7'].x >= mid.x + mid.w, 'dials: right');
      assert.ok(l.texts.some((t) => t.text === 'Dialled by') && l.texts.some((t) => t.text === 'Dials'));
    } else {
      for (const id of ['h:3', 'h:5', 'h:7']) assert.ok(by[id].y > mid.y + mid.h, `${w}: ${id} under the node`);
    }
    for (const n of l.nodes) assert.ok(n.x >= 0 && n.x + n.w <= l.width && n.y + n.h <= l.height, `${w}: ${n.id}`);
    apart(l.nodes, String(w));
    // The arrows: from the nodes that dial it to it, and from it to the node it dials.
    const arrows = [...l.edges.filter((e) => e.kind === 'link')].map((e) => `${e.from}>${e.to}:${e.start}:${e.end}`);
    assert.deepEqual(arrows.sort(), ['h:3>h:6:dot:arrow', 'h:5>h:6:dot:arrow', 'h:6>h:7:dot:arrow']);
    for (const e of l.edges.filter((x) => x.kind === 'link')) {
      const a = by[e.from];
      const [x, y] = e.pts[0];
      assert.ok(x >= a.x - 0.5 && x <= a.x + a.w + 0.5 && y >= a.y - 0.5 && y <= a.y + a.h + 0.5, `${w}: ${e.from} starts at its box`);
    }
  }
});

test('focus: the pick is kept while the node is there, and falls back to the first node with links', () => {
  const m = buildModel(mock8(9));
  assert.equal(pickFocus(m, 'h:4'), 'h:4');
  assert.equal(pickFocus(m, 'h:404'), 'h:1');
  assert.equal(pickFocus(m, null), 'h:1');
  assert.equal(pickFocus(m, 'h:99'), 'h:1', 'the proxy is not a choice while there are nodes');
  assert.equal(pickFocus(m, { toString: () => 'h:4' }), 'h:1');
  const quiet = buildModel([rns([1, 2, 3]), mock(1, 'A'), mock(2, 'B', { links: dials(3) }), mock(3, 'C')]);
  assert.equal(pickFocus(quiet, null), 'h:2');
  assert.equal(pickFocus(buildModel([rns([1]), mock(1, 'A', { upstreams: [{ name: 'X' }] })]), null), 'h:1');
  // A proxy alone is picked itself.
  assert.equal(pickFocus(buildModel([host(1, { role: 'proxy', proxy: { for: [] }, upstreams: [{ name: 'X' }] })]), null), 'h:1');
  assert.equal(pickFocus(buildModel([]), null), null);
  const l = layout(m, 390, 'h:404');
  assert.equal(l.selected, 'h:1');
  assert.deepEqual([...l.pills.map((p) => p.id)], Array.from({ length: 9 }, (_, i) => `h:${i + 1}`));
});

test('focus: many neighbours and peers stay inside the width, and the rest are counted', () => {
  const many = [rns(Array.from({ length: 20 }, (_, i) => i + 1)), ...Array.from({ length: 20 }, (_, i) => mock(i + 1, 'x'.repeat(200), {
    links: i === 0 ? dials(...Array.from({ length: 8 }, (_, k) => k + 2)) : dials(1), upstreams: i === 0 ? Array.from({ length: 8 }, (_, k) => ({ name: `Peer ${k}` })) : undefined,
  }))];
  for (const w of [1400, 800, 640, 500, 390, 320]) {
    const l = layout(buildModel(many), w, 'h:1');
    assert.equal(l.mode, 'focus');
    for (const n of l.nodes) assert.ok(n.x >= 0 && n.x + n.w <= l.width && n.y >= 0 && n.y + n.h <= l.height, `${w}: ${n.id}`);
    for (const e of l.edges) for (const [x, y] of e.pts) assert.ok(x >= 0 && x <= l.width && y >= 0 && y <= l.height, `${w}: ${e.d}`);
    apart(l.nodes, String(w));
    assert.ok(l.texts.some((t) => /^and \d+ more, see the list$/.test(t.text)), `${w}: the rest are counted`);
    for (const n of l.nodes) for (const t of n.lines) assert.ok(t.text.length <= 60, 'long names are clipped');
    assert.ok(l.pills.every((p) => p.name.length <= 32));
  }
});

test('layout survives garbage: no hosts, odd widths, and a node in two proxies is drawn once', () => {
  for (const w of [NaN, -5, 0, undefined, 1e9]) assert.doesNotThrow(() => layout(buildModel(mock3()), w));
  assert.equal(layout(buildModel([]), 800).nodes.length, 0);
  const two = buildModel([rns([1, 2]), host(98, { name: 'Other', role: 'proxy', proxy: { for: ['h:2', 'h:3'] } }), mock(1, 'A'), mock(2, 'B'), mock(3, 'C')]);
  const l = layout(two, 1000);
  assert.equal(l.mode, 'frame');
  assert.equal(l.nodes.filter((n) => n.frame).length, 2);
  assert.equal(l.nodes.filter((n) => n.id === 'h:2').length, 1);
  const [f1, f2] = l.nodes.filter((n) => n.frame);
  assert.ok(f1.y + f1.h < f2.y, 'stacked');
  apart(l.nodes.filter((n) => !n.frame));
});

test('a peer used by several nodes of a row is one box, with a line from each that turns under the frame', () => {
  const shared = [rns([1, 2, 3]), mock(1, 'A', { upstreams: [{ name: 'Hub' }] }), mock(2, 'B'), mock(3, 'C', { upstreams: [{ name: 'Hub' }] })];
  const l = layout(buildModel(shared), 1000);
  const hub = l.nodes.filter((n) => n.id === 'ext:hub|');
  assert.equal(hub.length, 1);
  const frame = l.nodes.find((n) => n.frame);
  const lines = l.edges.filter((e) => e.to === 'ext:hub|');
  assert.equal(lines.length, 2);
  for (const e of lines) {
    assert.ok(e.pts.length === 4 && e.turns, 'an elbow');
    assert.ok(e.pts[1][1] > frame.y + frame.h, 'the turn is under the frame');
    assert.ok(e.pts[3][0] > hub[0].x && e.pts[3][0] < hub[0].x + hub[0].w);
  }
  assert.notEqual(lines[0].pts[3][0], lines[1].pts[3][0], 'each line has its own spot on the box');
  // Turns in one lane never overlap.
  const span = (e) => [Math.min(e.pts[1][0], e.pts[2][0]), Math.max(e.pts[1][0], e.pts[2][0])];
  if (lines[0].pts[1][1] === lines[1].pts[1][1]) assert.ok(span(lines[0])[1] <= span(lines[1])[0] || span(lines[1])[1] <= span(lines[0])[0]);
  // Three nodes sharing two peers: lines whose turns overlap take different lanes.
  const crowd = layout(buildModel([rns([1, 2, 3, 4]), mock(1, 'A', { upstreams: [{ name: 'Hub' }, { name: 'Far' }] }), mock(2, 'B', { upstreams: [{ name: 'Hub' }] }), mock(3, 'C', { upstreams: [{ name: 'Far' }] }), mock(4, 'D', { upstreams: [{ name: 'Hub' }, { name: 'Far' }] })]), 1000);
  const bends = crowd.edges.filter((e) => e.turns);
  assert.ok(bends.length >= 3);
  for (const a of bends) for (const b of bends) {
    if (a !== b && a.pts[1][1] === b.pts[1][1]) assert.ok(span(a)[1] <= span(b)[0] || span(b)[1] <= span(a)[0], `${a.d} and ${b.d}`);
  }
  apart(crowd.nodes.filter((n) => !n.frame));
  // The same peer in two frames is drawn under each, with ids that stay apart.
  const two = layout(buildModel([rns([1]), host(98, { name: 'Other', role: 'proxy', proxy: { for: ['h:2'] } }), mock(1, 'A', { upstreams: [{ name: 'Hub' }] }), mock(2, 'B', { upstreams: [{ name: 'Hub' }] })]), 1000);
  assert.deepEqual([...two.nodes.filter((n) => n.kind === 'external').map((n) => n.id)], ['ext:hub|', 'ext:hub|#2']);
});
