import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { MAX_PEERS, PEERS_MAX_BYTES, sanitizePeers, tokenAllowedFor, unionPeers, validToken } from '../lib/peers.js';
import { fetchStats, isPrivateHost, STATS_MAX_BYTES } from '../lib/stats.js';
import { aggregateGroup } from '../lib/group.js';
import { loadConfig, loadConfigFile, loadNodes } from '../lib/config.js';
import { Monitor } from '../lib/monitor.js';
import { createApp } from '../lib/app.js';

const publicDir = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'public');
const SECRET = 'SECRET-token-0123456789abcdef';
const addr = (n) => n.toString(16).padStart(32, '0');
const peer = (n, type = 'lxmf', name = null) => ({ address: addr(n), type, name });

test('validToken follows the node rule: 16 to 256 printable ASCII, no spaces', () => {
  assert.equal(validToken('a'.repeat(16)), true);
  assert.equal(validToken('a'.repeat(256)), true);
  assert.equal(validToken('!~' + 'x'.repeat(14)), true);
  for (const bad of ['a'.repeat(15), 'a'.repeat(257), 'has space 0123456789', 'tab\t0123456789abcdef', 'new\nline0123456789ab', 'café-0123456789abcdef', '', null, undefined, 5, ['a'.repeat(16)], 'a'.repeat(15) + '\u007f']) {
    assert.equal(validToken(bad), false, JSON.stringify(bad));
  }
});

test('tokenAllowedFor: https, or http to loopback and private addresses only', () => {
  const ok = (u) => tokenAllowedFor(u, isPrivateHost);
  assert.equal(ok('https://a.test/s'), true);
  assert.equal(ok('http://127.0.0.1:9/s'), true);
  assert.equal(ok('http://192.168.1.5/s'), true);
  assert.equal(ok('http://localhost/s'), true);
  assert.equal(ok('http://a.test/s'), false);
  assert.equal(ok('http://8.8.8.8/s'), false);
  assert.equal(ok('ftp://a.test/s'), false);
  assert.equal(ok('not a url'), false);
});

test('sanitizePeers keeps valid entries, drops and counts the rest, merges duplicates', () => {
  const r = sanitizePeers({
    authorised: true,
    peers: [peer(1, 'lxmf', 'Alice'), peer(1, 'nomad'), peer(2, 'propagation'), peer(3, 'lxmf'), peer(3, 'lxmf'),
      { address: addr(10).toUpperCase(), type: 'lxmf' }, { address: 'abc', type: 'lxmf' }, { address: addr(5), type: 'other' }, { address: addr(6) },
      { address: 5, type: 'lxmf' }, null, 'x', [], { address: addr(7), type: '__proto__' }, { address: addr(8), type: 'toString' }],
  });
  assert.equal(r.addrs.length, 3 * 16);
  assert.equal(r.masks.length, 3);
  assert.equal(r.invalid, 10);
  assert.equal(r.truncated, false);
  assert.deepEqual(unionPeers([r]), { total: 3, lxmf: 2, nomad: 1, propagation: 1 });
  // Names are not kept anywhere.
  assert.equal(JSON.stringify(r).includes('Alice'), false);
  assert.equal(Object.keys(r).sort().join(), 'addrs,invalid,masks,truncated');
});

test('sanitizePeers needs the node to say authorised, and a list', () => {
  assert.equal(sanitizePeers({ peers: [peer(1)] }), null);
  assert.equal(sanitizePeers({ authorised: false, peers: [peer(1)] }), null);
  assert.equal(sanitizePeers({ authorised: 'true', peers: [peer(1)] }), null);
  assert.equal(sanitizePeers({ authorised: true }), null);
  assert.equal(sanitizePeers({ authorised: true, peers: {} }), null);
  assert.equal(sanitizePeers(null), null);
  assert.equal(sanitizePeers('x'), null);
  assert.equal(sanitizePeers({ authorised: true, peers: [] }).masks.length, 0);
});

test('sanitizePeers is bounded: at most 20000 entries kept, and the cut is flagged', () => {
  const many = Array.from({ length: MAX_PEERS + 500 }, (_, i) => peer(i + 1));
  const r = sanitizePeers({ authorised: true, peers: many });
  assert.equal(r.masks.length, MAX_PEERS);
  assert.equal(r.addrs.length, MAX_PEERS * 16);
  assert.equal(r.truncated, true);
  assert.equal(sanitizePeers({ authorised: true, peers_truncated: true, peers: [peer(1)] }).truncated, true);
  assert.equal(sanitizePeers({ authorised: true, peers_truncated: 'yes', peers: [peer(1)] }).truncated, false);
});

test('unionPeers: overlap between nodes and between types', () => {
  const list = (...ps) => sanitizePeers({ authorised: true, peers: ps });
  const a = list(peer(1, 'lxmf'), peer(2, 'lxmf'), peer(3, 'nomad'), peer(9, 'propagation'));
  const b = list(peer(2, 'lxmf'), peer(3, 'lxmf'), peer(4, 'nomad'), peer(9, 'propagation'));
  assert.deepEqual(unionPeers([a, b]), { total: 5, lxmf: 3, nomad: 2, propagation: 1 });
  // Address 3 is nomad at one node and lxmf at the other: it counts in both types, once in total.
  assert.deepEqual(unionPeers([a]), { total: 4, lxmf: 2, nomad: 1, propagation: 1 });
  assert.deepEqual(unionPeers([]), { total: 0, lxmf: 0, nomad: 0, propagation: 0 });
  assert.deepEqual(unionPeers([a, a, a]), unionPeers([a]));
});

// ---- fetching ----

const stats = () => ({
  version: 1, rettui_version: '2.0.0', generated_at: 1, uptime_seconds: 1,
  interfaces: { total: 1, online: 1, clients: 1, rx_bytes: 1, tx_bytes: 1 },
  peers_heard: { total: 3, lxmf: 2, nomad: 1, propagation: 0 }, announces_last_minute: 0,
});
const withPeers = (peers, extra = {}) => ({ ...stats(), authorised: true, peers, ...extra });

function spy(body, init) {
  const calls = [];
  const fn = async (url, opts) => {
    calls.push({ url, headers: opts.headers });
    return new Response(typeof body === 'string' ? body : JSON.stringify(body), init);
  };
  fn.calls = calls;
  return fn;
}

test('the Authorization header is sent only when a token is configured, and never in the URL', async () => {
  const plain = spy(stats());
  await fetchStats('https://a.test/s', { fetchFn: plain });
  assert.deepEqual(plain.calls[0].headers, { Accept: 'application/json' });
  const tok = spy(withPeers([peer(1)]));
  const r = await fetchStats('https://a.test/s', { fetchFn: tok, token: SECRET });
  assert.equal(tok.calls[0].headers.Authorization, `Bearer ${SECRET}`);
  assert.equal(tok.calls[0].url, 'https://a.test/s');
  assert.equal(r.ok, true);
  assert.equal(r.peers.masks.length, 1);
  assert.equal(JSON.stringify(r).includes(SECRET), false);
});

test('a token is refused for plain http to a public host, and for a bad token, without a request', async () => {
  const fn = spy(stats());
  assert.deepEqual(await fetchStats('http://a.test/s', { fetchFn: fn, token: SECRET }), { ok: false, error: 'token not allowed' });
  assert.deepEqual(await fetchStats('https://a.test/s', { fetchFn: fn, token: 'short' }), { ok: false, error: 'token not allowed' });
  assert.equal(fn.calls.length, 0);
  assert.equal((await fetchStats('http://127.0.0.1:1/s', { fetchFn: spy(stats()), token: SECRET })).ok, true);
});

test('without a token the peers are never read, even if the node sends them', async () => {
  const r = await fetchStats('https://a.test/s', { fetchFn: spy(withPeers([peer(1)])) });
  assert.equal(r.ok, true);
  assert.equal('peers' in r, false);
  const withToken = await fetchStats('https://a.test/s', { fetchFn: spy(stats()), token: SECRET });
  assert.equal(withToken.ok, true);
  assert.equal('peers' in withToken, false);
  const notAuth = await fetchStats('https://a.test/s', { fetchFn: spy({ ...stats(), authorised: false, peers: [peer(1)] }), token: SECRET });
  assert.equal('peers' in notAuth, false);
});

test('a token allows a larger answer, up to 4 MiB, and no more', async () => {
  const big = withPeers(Array.from({ length: MAX_PEERS }, (_, i) => peer(i + 1, 'lxmf', 'n'.repeat(60))));
  const size = JSON.stringify(big).length;
  assert.ok(size > STATS_MAX_BYTES && size < PEERS_MAX_BYTES, String(size));
  assert.deepEqual(await fetchStats('https://a.test/s', { fetchFn: spy(big) }), { ok: false, error: 'too large' });
  const r = await fetchStats('https://a.test/s', { fetchFn: spy(big), token: SECRET });
  assert.equal(r.ok, true);
  assert.equal(r.peers.masks.length, MAX_PEERS);
  const huge = JSON.stringify(withPeers([peer(1)], { pad: 'x'.repeat(PEERS_MAX_BYTES) }));
  assert.deepEqual(await fetchStats('https://a.test/s', { fetchFn: spy(huge), token: SECRET }), { ok: false, error: 'too large' });
});

test('failures with a token give short codes that do not contain it', async () => {
  const results = [
    await fetchStats('https://a.test/s', { fetchFn: spy('no', { status: 401 }), token: SECRET }),
    await fetchStats('https://a.test/s', { fetchFn: spy('not json'), token: SECRET }),
    await fetchStats('https://a.test/s', { fetchFn: async () => { throw new Error(`boom ${SECRET}`); }, token: SECRET }),
    await fetchStats('https://a.test/s', { fetchFn: spy('{}'), token: SECRET }),
  ];
  assert.deepEqual(results.map((r) => r.error), ['http 401', 'invalid', 'network', 'invalid']);
  assert.equal(JSON.stringify(results).includes(SECRET), false);
});

// ---- groups ----

const data = (o = {}) => ({
  rettuiVersion: '2.0.0', generatedAt: 1, uptimeSeconds: 1,
  interfaces: { total: 1, online: 1, clients: 1, rxBytes: 1, txBytes: 1 },
  peersHeard: { total: 3, lxmf: 2, nomad: 1, propagation: 0 }, announcesLastMinute: 0, ...o,
});
const list = (...ps) => ({ ...sanitizePeers({ authorised: true, peers: ps }), id: Math.random() });
const mem = (key, peers, extra = {}) => ({ key, status: 'up', stats: { ok: true, stale: false, data: data() }, peers, ...extra });

test('a group is exact only when every reporting member supplied a complete list', () => {
  const a = list(peer(1), peer(2), peer(3, 'nomad'));
  const b = list(peer(2), peer(3, 'lxmf'), peer(4, 'propagation'));
  const g = aggregateGroup([mem('a', a), mem('b', b)]).data.peersHeard;
  assert.equal(g.exact, true);
  assert.deepEqual(g.union, { total: 4, lxmf: 3, nomad: 1, propagation: 1 });
  assert.deepEqual(g.lists, { have: 2, of: 2 });
  assert.equal(g.sum.total, 6);

  const missing = aggregateGroup([mem('a', a), mem('b', undefined)]).data.peersHeard;
  assert.equal(missing.exact, false);
  assert.equal(missing.union, null);
  assert.deepEqual(missing.lists, { have: 1, of: 2 });
  assert.equal(missing.max.total, 3);

  const cut = aggregateGroup([mem('a', a), mem('b', { ...b, truncated: true })]).data.peersHeard;
  assert.equal(cut.exact, false);
  assert.deepEqual(cut.lists, { have: 1, of: 2 });
});

test('members that do not report are not needed for exactness, but make the group partial', () => {
  const a = list(peer(1));
  const down = mem('d', undefined, { status: 'down' });
  const g = aggregateGroup([mem('a', a), down]);
  assert.equal(g.partial, true);
  assert.equal(g.data.peersHeard.exact, true);
  assert.deepEqual(g.data.peersHeard.union, { total: 1, lxmf: 1, nomad: 0, propagation: 0 });
});

// ---- the monitor and the API ----

async function setup({ tokens, statsFn, port = 0 } = {}) {
  const config = loadConfig(`nodes:
  - address: p.test:1
    proxy_for: [a.test:1, b.test:1]
  - address: a.test:1
    stats_url: https://a.test/s
  - address: b.test:1
    stats_url: https://b.test/s
`);
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'website-'));
  const calls = [];
  const monitor = new Monitor({
    targets: config.targets, nodes: config.nodes, statsUrls: config.statsUrls, dataDir: dir, tokens,
    probeFn: async () => ({ up: true, ms: 1 }),
    statsFn: async (url, opts) => {
      calls.push([url, opts]);
      return statsFn(new URL(url).hostname);
    },
    sampleIntervalMs: 1000,
  });
  const server = createApp({ monitor, publicDir });
  await new Promise((r) => server.listen(port, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}`;
  return { monitor, dir, calls, base, close: () => (server.closeAllConnections(), new Promise((r) => server.close(r))) };
}

const ok = (peers) => ({ ok: true, data: data(), ...(peers ? { peers: { ...sanitizePeers({ authorised: true, peers }) } } : {}) });

test('the monitor sends the token only for hosts that have one, and de-duplicates exactly', async () => {
  const s = await setup({
    tokens: new Map([['a.test:1', SECRET], ['b.test:1', SECRET]]),
    statsFn: (host) => ok(host === 'a.test' ? [peer(1), peer(2), peer(3, 'nomad')] : [peer(2), peer(3), peer(4, 'propagation')]),
  });
  try {
    await s.monitor.checkAll();
    assert.deepEqual(s.calls.map((c) => c[1]), [{ token: SECRET }, { token: SECRET }]);
    const g = (await (await fetch(`${s.base}/api/status`)).json()).hosts[0].group;
    assert.equal(g.data.peersHeard.exact, true);
    assert.deepEqual(g.data.peersHeard.union, { total: 4, lxmf: 3, nomad: 1, propagation: 1 });
    assert.deepEqual(g.data.peersHeard.lists, { have: 2, of: 2 });
  } finally {
    await s.close();
  }
});

test('without a token the monitor calls statsFn with the URL alone and the group is a range', async () => {
  const s = await setup({ statsFn: () => ok() });
  try {
    await s.monitor.checkAll();
    assert.deepEqual(s.calls.map((c) => c.length === 2 && c[1]), [undefined, undefined].map(() => undefined));
    const g = s.monitor.snapshot().hosts[0].group.data.peersHeard;
    assert.equal(g.exact, false);
    assert.deepEqual(g.lists, { have: 0, of: 2 });
  } finally {
    await s.close();
  }
});

test('one member without a list, or a list that stops arriving, brings back the range', async () => {
  let aList = true;
  const s = await setup({
    tokens: new Map([['a.test:1', SECRET], ['b.test:1', SECRET]]),
    statsFn: (host) => (host === 'a.test' && !aList ? ok() : ok([peer(host === 'a.test' ? 1 : 2)])),
  });
  try {
    await s.monitor.checkAll();
    assert.equal(s.monitor.snapshot().hosts[0].group.data.peersHeard.exact, true);
    aList = false;
    await s.monitor.checkAll();
    const p = s.monitor.snapshot().hosts[0].group.data.peersHeard;
    assert.equal(p.exact, false);
    assert.deepEqual(p.lists, { have: 1, of: 2 });
    assert.equal(s.monitor.peerLists.has('a.test:1'), false);
  } finally {
    await s.close();
  }
});

test('memory stays bounded: one compact list per node, replaced on each fetch', async () => {
  const many = Array.from({ length: MAX_PEERS + 1000 }, (_, i) => peer(i + 1));
  const s = await setup({ tokens: new Map([['a.test:1', SECRET]]), statsFn: () => ok(many) });
  try {
    for (let i = 0; i < 3; i++) await s.monitor.checkAll();
    assert.equal(s.monitor.peerLists.size, 1);
    const l = s.monitor.peerLists.get('a.test:1');
    assert.ok(l.addrs.length <= MAX_PEERS * 16 && l.masks.length <= MAX_PEERS);
    assert.equal(l.truncated, true);
    const p = s.monitor.snapshot().hosts[0].group.data.peersHeard;
    assert.equal(p.exact, false);
  } finally {
    await s.close();
  }
});

test('no token and no peer list appears in any API answer, file or log', async () => {
  const logged = [];
  const original = { error: console.error, log: console.log, warn: console.warn };
  console.error = console.log = console.warn = (...a) => logged.push(a.join(' '));
  const s = await setup({
    tokens: new Map([['a.test:1', SECRET], ['b.test:1', SECRET]]),
    statsFn: (host) => (host === 'b.test' ? { ok: false, error: 'http 401' } : ok([peer(0xabc123, 'lxmf', 'Alice')])),
  });
  try {
    for (let i = 0; i < 2; i++) await s.monitor.checkAll();
    const bodies = [];
    for (const p of ['/api/status', '/api/stats?host=a.test:1&range=7d', '/api/stats?host=p.test:1&range=7d&view=combined', '/api/stats?host=p.test:1&view=combined&range=6h']) {
      bodies.push(await (await fetch(s.base + p)).text());
    }
    for (const f of await fs.readdir(s.dir)) bodies.push(await fs.readFile(path.join(s.dir, f), 'utf8'));
    bodies.push(logged.join('\n'));
    bodies.push(JSON.stringify(s.monitor.snapshot()));
    for (const b of bodies) {
      assert.equal(b.includes(SECRET), false);
      assert.equal(b.includes(addr(0xabc123)), false);
      assert.equal(b.includes('Alice'), false);
      assert.equal(/Bearer/.test(b), false);
    }
    assert.equal(bodies.some((b) => b.includes('"exact"')), true);
  } finally {
    Object.assign(console, original);
    await s.close();
  }
});

// ---- configuration ----

const fileCfg = (extra, nodeExtra = '') => `${extra}
nodes:
  - address: a.test:1
    stats_url: https://a.test/s
${nodeExtra}
  - address: b.test:1
    stats_url: https://b.test/s
  - address: c.test:1
`;

test('stats_token: per node, with a top-level default, and only for nodes with a stats URL', () => {
  const c = loadConfig(fileCfg(`stats_token: ${SECRET}`, '    stats_token: another-token-0123456789'));
  assert.equal(c.tokens.get('a.test:1'), 'another-token-0123456789');
  assert.equal(c.tokens.get('b.test:1'), SECRET);
  assert.equal(c.tokens.has('c.test:1'), false);
  assert.equal(loadConfig(fileCfg('')).tokens.size, 0);
  // The tokens are not part of what the monitor shows.
  assert.equal(JSON.stringify([...c.nodes]).includes('token'), false);
  assert.equal(c.tokenFiles.size, 0);
});

test('stats_token errors name the place and never the token', () => {
  const bad = (text, pattern) => assert.throws(() => loadConfig(text), (e) => pattern.test(e.message) && !e.message.includes('SECRET') && !/tooshort|has space/.test(e.message));
  bad(fileCfg('stats_token: tooshort-SECRET'), /stats_token must be 16 to 256/);
  bad(fileCfg('stats_token: "has space SECRET-0123456789"'), /stats_token must be 16 to 256/);
  bad(fileCfg('stats_token: 12345678901234567890'), /stats_token must be 16 to 256/);
  bad(fileCfg('', '    stats_token: tooshort'), /nodes\[1\]\.stats_token must be/);
  bad(fileCfg(`stats_token: ${SECRET}\nstats_token_file: t.txt`), /either stats_token or stats_token_file/);
  bad(fileCfg('', `    stats_token: ${SECRET}\n    stats_token_file: t.txt`), /both stats_token and stats_token_file/);
  bad(`nodes:\n  - address: a.test:1\n    stats_token: ${SECRET}`, /no stats_url/);
  bad(fileCfg('stats_token_file: 5'), /must be a file path/);
});

test('stats_token_file is read at start, relative to the config file, trimmed and checked', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'website-'));
  await fs.writeFile(path.join(dir, 'tok.txt'), `${SECRET}\n`);
  await fs.writeFile(path.join(dir, 'config.yaml'), fileCfg('stats_token_file: tok.txt', '    stats_token_file: tok.txt'));
  const c = await loadConfigFile(path.join(dir, 'config.yaml'));
  assert.equal(c.tokens.get('a.test:1'), SECRET);
  assert.equal(c.tokens.get('b.test:1'), SECRET);
  assert.equal(c.tokenFiles.size, 0);

  const errorOf = async (name, content) => {
    await fs.writeFile(path.join(dir, 'bad.txt'), content);
    await fs.writeFile(path.join(dir, name), fileCfg('stats_token_file: bad.txt'));
    return loadConfigFile(path.join(dir, name)).then(() => null, (e) => e.message);
  };
  const short = await errorOf('c1.yaml', 'tooshort\n');
  assert.match(short, /stats_token_file must be 16 to 256|token in stats_token_file/);
  assert.equal(short.includes('tooshort'), false);
  assert.match(await errorOf('c2.yaml', 'x'.repeat(2000)), /not a small file/);
  await fs.writeFile(path.join(dir, 'c3.yaml'), fileCfg('stats_token_file: missing.txt'));
  await assert.rejects(loadConfigFile(path.join(dir, 'c3.yaml')), /cannot be read \(ENOENT\)/);
});

test('STATS_TOKEN applies to every stats URL in env mode and is checked; it cannot be mixed with CONFIG_FILE', async () => {
  const env = { STATUS_TARGETS: 'a.test:1,b.test:1', STATS_URLS: 'a.test:1=https://a.test/s,b.test:1=https://b.test/s' };
  const n = await loadNodes({ ...env, STATS_TOKEN: SECRET });
  assert.deepEqual([...n.tokens], [['a.test:1', SECRET], ['b.test:1', SECRET]]);
  assert.equal((await loadNodes(env)).tokens.size, 0);
  await assert.rejects(loadNodes({ ...env, STATS_TOKEN: 'short' }), (e) => /STATS_TOKEN must be/.test(e.message) && !/CONFIG_FILE/.test(e.message) && !e.message.includes('short'));
  await assert.rejects(loadNodes({ ...env, STATS_TOKEN: SECRET, STATS_TOKEN_FILE: '/x' }), /either STATS_TOKEN or STATS_TOKEN_FILE/);
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'website-'));
  await fs.writeFile(path.join(dir, 't'), SECRET);
  assert.equal((await loadNodes({ ...env, STATS_TOKEN_FILE: path.join(dir, 't') })).tokens.get('b.test:1'), SECRET);
  await fs.writeFile(path.join(dir, 'c.yaml'), fileCfg(''));
  await assert.rejects(loadNodes({ CONFIG_FILE: path.join(dir, 'c.yaml'), STATS_TOKEN: SECRET }), (e) => /not both/.test(e.message) && !e.message.includes(SECRET));
});
