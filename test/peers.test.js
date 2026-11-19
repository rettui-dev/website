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

// ---- review follow-ups: shared tokens, token files, limits, eager unions ----

import { limiter, MAX_TOKEN_FETCHES } from '../lib/monitor.js';
import { parseTokenFiles, tokenWarnings } from '../lib/config.js';
import { execFileSync } from 'node:child_process';

const tok = (c) => c.repeat(20);

test('tokenWarnings: one token for different hostnames is a warning that does not name the token', () => {
  const urls = new Map([['a.test:1', 'https://a.test/s'], ['b.test:1', 'https://b.test/s'], ['b.test:2', 'https://b.test/other'], ['c.test:1', 'https://c.test/s']]);
  const same = tokenWarnings(urls, new Map([['a.test:1', tok('x')], ['b.test:1', tok('x')], ['c.test:1', tok('x')]]));
  assert.equal(same.length, 1);
  assert.match(same[0], /3 different hostnames/);
  assert.equal(same[0].includes(tok('x')), false);
  assert.deepEqual(tokenWarnings(urls, new Map([['a.test:1', tok('x')], ['b.test:1', tok('y')]])), []);
  // Two stats URLs on one hostname share a token without a warning.
  assert.deepEqual(tokenWarnings(urls, new Map([['b.test:1', tok('x')], ['b.test:2', tok('x')]])), []);
  assert.deepEqual(tokenWarnings(urls, new Map()), []);
});

test('parseTokenFiles is strict', () => {
  const urls = new Map([['a.test:1', 'https://a.test/s'], ['b.test:1', 'https://b.test/s']]);
  assert.deepEqual([...parseTokenFiles(' A.test:1=/run/a.token , b.test:1=rel/b.token,', urls)], [['a.test:1', '/run/a.token'], ['b.test:1', 'rel/b.token']]);
  assert.equal(parseTokenFiles('', urls).size, 0);
  assert.equal(parseTokenFiles(undefined, urls).size, 0);
  for (const bad of ['a.test:1', 'a.test:1=', '=x', 'a.test:1=x,a.test:1=y', 'c.test:1=x', 'nohost=x']) {
    assert.throws(() => parseTokenFiles(bad, urls), /STATS_TOKEN_FILES/, bad);
  }
});

async function tokenDir() {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'website-'));
  await fs.writeFile(path.join(dir, 'a.token'), `${tok('a')}\n`, { mode: 0o600 });
  await fs.writeFile(path.join(dir, 'b.token'), tok('b'), { mode: 0o600 });
  return dir;
}

const urlsEnv = { STATUS_TARGETS: 'a.test:1,b.test:1,c.test:1', STATS_URLS: 'a.test:1=https://a.test/s,b.test:1=https://b.test/s,c.test:1=https://c.test/s' };

test('STATS_TOKEN_FILES gives each node its own token and overrides the default', async () => {
  const dir = await tokenDir();
  const n = await loadNodes({ ...urlsEnv, STATS_TOKEN_FILES: `a.test:1=${dir}/a.token,b.test:1=${dir}/b.token` });
  assert.deepEqual([...n.tokens], [['a.test:1', tok('a')], ['b.test:1', tok('b')]]);
  assert.deepEqual(n.warnings, []);
  const mixed = await loadNodes({ ...urlsEnv, STATS_TOKEN: SECRET, STATS_TOKEN_FILES: `a.test:1=${dir}/a.token` });
  assert.equal(mixed.tokens.get('a.test:1'), tok('a'));
  assert.equal(mixed.tokens.get('b.test:1'), SECRET);
  assert.equal(mixed.warnings.length, 1);
  assert.match(mixed.warnings[0], /2 different hostnames/);
  await assert.rejects(loadNodes({ ...urlsEnv, STATS_TOKEN_FILES: `a.test:1=${dir}/missing` }), /STATS_TOKEN_FILES cannot be read \(ENOENT\)/);
  await assert.rejects(loadNodes({ ...urlsEnv, STATS_TOKEN_FILES: 'z.test:1=x' }), /not a node with a stats URL/);
  await fs.writeFile(path.join(dir, 'c.yaml'), 'nodes:\n  - address: a.test:1\n');
  await assert.rejects(loadNodes({ CONFIG_FILE: path.join(dir, 'c.yaml'), STATS_TOKEN_FILES: `a.test:1=${dir}/a.token` }), /not both/);
});

test('a config file with one default token warns about it; one token per node does not', async () => {
  const dir = await tokenDir();
  const nodes = '\nnodes:\n  - address: a.test:1\n    stats_url: https://a.test/s\n    NODEA\n  - address: b.test:1\n    stats_url: https://b.test/s\n    NODEB\n';
  await fs.writeFile(path.join(dir, 'one.yaml'), `stats_token_file: a.token${nodes.replace('NODEA', '').replace('NODEB', '')}`);
  const one = await loadConfigFile(path.join(dir, 'one.yaml'));
  assert.equal(one.warnings.length, 1);
  assert.match(one.warnings[0], /2 different hostnames/);
  await fs.writeFile(path.join(dir, 'two.yaml'), nodes.replace('NODEA', 'stats_token_file: a.token').replace('NODEB', 'stats_token_file: b.token'));
  assert.deepEqual((await loadConfigFile(path.join(dir, 'two.yaml'))).warnings, []);
});

test('token files: other users can read it is a warning, and the read is bounded', async () => {
  const dir = await tokenDir();
  await fs.writeFile(path.join(dir, 'a.yaml'), 'nodes:\n  - address: a.test:1\n    stats_url: https://a.test/s\n    stats_token_file: open.token\n');
  await fs.writeFile(path.join(dir, 'open.token'), tok('o'), { mode: 0o644 });
  await fs.chmod(path.join(dir, 'open.token'), 0o644);
  const c = await loadConfigFile(path.join(dir, 'a.yaml'));
  assert.equal(c.tokens.get('a.test:1'), tok('o'));
  if (process.platform !== 'win32') {
    assert.equal(c.warnings.length, 1);
    assert.match(c.warnings[0], /can be read by other users \(mode 644\)/);
    assert.equal(c.warnings[0].includes(tok('o')), false);
  }
  await fs.writeFile(path.join(dir, 'open.token'), 'x'.repeat(5000));
  await assert.rejects(loadConfigFile(path.join(dir, 'a.yaml')), /not a small file/);
  await fs.writeFile(path.join(dir, 'open.token'), 'x'.repeat(1025));
  await assert.rejects(loadConfigFile(path.join(dir, 'a.yaml')), /not a small file/);
  await fs.rm(path.join(dir, 'open.token'));
  await fs.mkdir(path.join(dir, 'open.token'));
  await assert.rejects(loadConfigFile(path.join(dir, 'a.yaml')), /not a small file/);
});

test('a named pipe as a token file is refused, not waited on', { skip: process.platform === 'win32' }, async () => {
  const dir = await tokenDir();
  execFileSync('mkfifo', [path.join(dir, 'pipe.token')]);
  await fs.writeFile(path.join(dir, 'p.yaml'), 'nodes:\n  - address: a.test:1\n    stats_url: https://a.test/s\n    stats_token_file: pipe.token\n');
  await assert.rejects(loadConfigFile(path.join(dir, 'p.yaml')), /not a small file/);
});

test('limiter runs at most the given number of jobs at once, in order', async () => {
  let running = 0;
  let peak = 0;
  const order = [];
  const run = limiter(3);
  await Promise.all(
    Array.from({ length: 10 }, (_, i) =>
      run(async () => {
        order.push(i);
        running++;
        peak = Math.max(peak, running);
        await new Promise((r) => setTimeout(r, 5));
        running--;
        return i;
      }),
    ),
  );
  assert.equal(peak, 3);
  assert.deepEqual(order, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
  // A failing job does not stop the others.
  const run2 = limiter(1);
  const results = await Promise.allSettled([run2(async () => { throw new Error('x'); }), run2(async () => 'ok')]);
  assert.deepEqual(results.map((r) => r.status), ['rejected', 'fulfilled']);
});

test('at most 4 token fetches run at once; fetches without a token are not held back', async () => {
  const lines = Array.from({ length: 10 }, (_, i) => `  - address: n${i}.test:1\n    stats_url: https://n${i}.test/s`).join('\n');
  const config = loadConfig(`nodes:\n${lines}\n  - address: plain.test:1\n    stats_url: https://plain.test/s\n`);
  let running = 0;
  let peak = 0;
  let plainSeen = 0;
  const tokens = new Map(config.targets.filter((t) => t.host !== 'plain.test').map((t) => [`${t.host}:${t.port}`, SECRET]));
  const monitor = new Monitor({
    targets: config.targets, statsUrls: config.statsUrls, tokens, dataDir: await fs.mkdtemp(path.join(os.tmpdir(), 'website-')),
    probeFn: async () => ({ up: true, ms: 1 }),
    statsFn: async (url, opts) => {
      if (!opts) {
        plainSeen = Math.max(plainSeen, running);
        return ok();
      }
      running++;
      peak = Math.max(peak, running);
      await new Promise((r) => setTimeout(r, 10));
      running--;
      return ok();
    },
  });
  await monitor.checkAll();
  assert.equal(MAX_TOKEN_FETCHES, 4);
  assert.equal(peak, 4);
  // The plain fetch started right away, while token fetches were still running.
  assert.ok(plainSeen >= 1);
  assert.equal(monitor.stats.size, 11);
});

test('the union is worked out after the fetches, and a request only reads it', async () => {
  const lists = { a: [peer(1), peer(2)], b: [peer(2), peer(3)] };
  const s = await setup({ tokens: new Map([['a.test:1', SECRET], ['b.test:1', SECRET]]), statsFn: (host) => ok(lists[host === 'a.test' ? 'a' : 'b']) });
  try {
    assert.equal(s.monitor.unionCache.size, 0);
    await s.monitor.fetchStatsAll();
    // Already there, before any request or snapshot.
    assert.deepEqual(s.monitor.unionCache.get('p.test:1').value, { total: 3, lxmf: 3, nomad: 0, propagation: 0 });
    const cached = s.monitor.unionCache.get('p.test:1');
    await s.monitor.checkAll();
    assert.notEqual(s.monitor.unionCache.get('p.test:1').id, cached.id);
    const before = s.monitor.unionCache.get('p.test:1');
    for (let i = 0; i < 3; i++) await (await fetch(`${s.base}/api/status`)).text();
    await (await fetch(`${s.base}/api/stats?host=p.test:1&view=combined`)).text();
    assert.equal(s.monitor.unionCache.get('p.test:1'), before);
    assert.equal(s.monitor.snapshot().hosts[0].group.data.peersHeard.exact, true);
    // A change in who reports, seen by a request before the next refresh, shows the range, not a stale union.
    s.monitor.peerLists.delete('a.test:1');
    assert.equal(s.monitor.groupFor('p.test:1').data.peersHeard.exact, false);
    assert.equal(s.monitor.unionCache.get('p.test:1'), before);
  } finally {
    await s.close();
  }
});

// ---- propagation node and disk numbers ----

import { sanitizeStats } from '../lib/stats.js';
import { cleanName, optCount, sanitizeDisk, sanitizePropagation, sanitizePropagationPeers, summarizePeerRows, MAX_PROPAGATION_PEERS } from '../lib/propagation.js';

const prop = (o = {}) => ({
  enabled: true, stored_messages: 1200, stored_bytes: 3_000_000, storage_limit_bytes: 500_000_000, peers_connected: 2, peers_total: 8, peers_alive: 5,
  peers_static: 3, peers_auto: 5, peer_limit: 20, static_peers: 3, autopeer: true, autopeer_depth: 4, messages_received: 10, messages_served: 20,
  messages_sent_to_peers: 30, messages_received_from_peers: 40, messages_offered_to_peers: 50, unhandled_messages: 6, ...o,
});
const disk = (o = {}) => ({ data_bytes: 5000, fs_total_bytes: 100_000, fs_free_bytes: 40_000, ...o });

test('sanitizeStats keeps the optional propagation and disk objects, and nothing else of them', () => {
  const d = sanitizeStats({ ...stats(), propagation: { ...prop(), secret: 'x' }, disk: { ...disk(), path: '/home/me' } });
  assert.deepEqual(d.propagation, {
    enabled: true, storedMessages: 1200, storedBytes: 3_000_000, storageLimitBytes: 500_000_000, peersConnected: 2, peersTotal: 8, peersAlive: 5,
    peersStatic: 3, peersAuto: 5, peerLimit: 20, staticPeers: 3, autopeerDepth: 4, messagesReceived: 10, messagesServed: 20,
    messagesSentToPeers: 30, messagesReceivedFromPeers: 40, messagesOfferedToPeers: 50, unhandledMessages: 6, autopeer: true,
  });
  assert.deepEqual(d.disk, { dataBytes: 5000, fsTotalBytes: 100_000, fsFreeBytes: 40_000 });
  assert.equal(JSON.stringify(d).includes('secret'), false);
  assert.equal(JSON.stringify(d).includes('/home/me'), false);
});

test('an old node without the new keys gives the same stats as before', () => {
  const d = sanitizeStats(stats());
  assert.equal('propagation' in d, false);
  assert.equal('disk' in d, false);
  assert.deepEqual(Object.keys(d).sort(), ['announcesLastMinute', 'generatedAt', 'interfaces', 'peersHeard', 'rettuiVersion', 'uptimeSeconds']);
});

test('propagation: missing counters become null, wrong types drop only that object', () => {
  const missing = sanitizeStats({ ...stats(), propagation: { enabled: true, stored_messages: 5, stored_bytes: 'lots', peers_alive: NaN, autopeer: 'yes' } }).propagation;
  assert.equal(missing.storedMessages, 5);
  for (const k of ['storedBytes', 'peersAlive', 'peersTotal', 'autopeer', 'unhandledMessages']) assert.equal(missing[k], null, k);
  for (const bad of [null, 5, 'x', [], { enabled: false, stored_messages: 1 }, { enabled: 'true' }, { stored_messages: 1 }, {}]) {
    const d = sanitizeStats({ ...stats(), propagation: bad });
    assert.equal('propagation' in d, false, JSON.stringify(bad));
    assert.equal(d.uptimeSeconds, 1);
  }
  for (const bad of [null, 5, 'x', [], {}, { data_bytes: 'x', fs_free_bytes: null }]) {
    assert.equal('disk' in sanitizeStats({ ...stats(), disk: bad }), false, JSON.stringify(bad));
  }
  assert.deepEqual(sanitizeStats({ ...stats(), disk: { data_bytes: 7 } }).disk, { dataBytes: 7, fsTotalBytes: null, fsFreeBytes: null });
});

test('propagation numbers are clamped like the others', () => {
  const p = sanitizePropagation(prop({ stored_messages: -5, stored_bytes: 1e300, peers_alive: 3.9, peers_total: Infinity }));
  assert.equal(p.storedMessages, 0);
  assert.equal(p.storedBytes, Number.MAX_SAFE_INTEGER);
  assert.equal(p.peersAlive, 3);
  assert.equal(p.peersTotal, null);
  assert.equal(optCount('5'), null);
  assert.equal(optCount(null), null);
  assert.equal(sanitizeDisk({ fs_free_bytes: -1 }).fsFreeBytes, 0);
});

test('the required stats are still required', () => {
  const bad = { ...stats() };
  delete bad.uptime_seconds;
  assert.throws(() => sanitizeStats({ ...bad, propagation: prop(), disk: disk() }));
});

const row = (n, o = {}) => ({ address: addr(n), alive: true, depth: 2, last_heard_seconds_ago: 5, last_sync_seconds_ago: 60, messages_offered: 3, name: 'Node', peering_cost: 18, state: 'idle', static: false, unhandled: 4, ...o });

test('propagation peer rows are cleaned strictly', () => {
  const r = sanitizePropagationPeers({
    authorised: true,
    propagation_peers: [row(1, { name: '‮evil​ name\u0007', static: true }), row(2, { alive: 'yes', state: 'Bad State!', depth: null, unhandled: -9 }), row(2), row(3, { name: 'x'.repeat(200) }),
      { address: 'zz', alive: true }, null, 'x', { alive: true }, row(4, { address: addr(4).toUpperCase().replace(/[0-9]/g, 'A') })],
  });
  assert.equal(r.rows.length, 3);
  assert.equal(r.invalid, 5);
  assert.equal(r.rows[0].name, 'evil name');
  assert.equal(r.rows[0].static, true);
  assert.equal(r.rows[1].alive, false);
  assert.equal(r.rows[1].state, null);
  assert.equal(r.rows[1].depth, null);
  assert.equal(r.rows[1].unhandled, 0);
  assert.equal(r.rows[2].name.length, 48);
  assert.deepEqual(summarizePeerRows(r), { listed: 3, alive: 2, static: 1, unhandled: 4 + 0 + 4, truncated: false });
  for (const none of [{ propagation_peers: [row(1)] }, { authorised: false, propagation_peers: [row(1)] }, { authorised: true }, { authorised: true, propagation_peers: {} }, null]) {
    assert.equal(sanitizePropagationPeers(none), null);
  }
  assert.equal(cleanName('​‮'), null);
  assert.equal(cleanName(5), null);
});

test('propagation peer rows are capped at 256 and flagged', () => {
  const r = sanitizePropagationPeers({ authorised: true, propagation_peers: Array.from({ length: 400 }, (_, i) => row(i + 1)) });
  assert.equal(r.rows.length, MAX_PROPAGATION_PEERS);
  assert.equal(r.truncated, true);
  assert.equal(sanitizePropagationPeers({ authorised: true, propagation_peers_truncated: true, propagation_peers: [row(1)] }).truncated, true);
});

test('rows are read only with a token, kept in memory, and never shown', async () => {
  const body = { ...stats(), propagation: prop(), authorised: true, propagation_peers: [row(1, { name: 'Alice-Node' })] };
  const plain = await fetchStats('https://a.test/s', { fetchFn: spy(body) });
  assert.equal('propagationPeers' in plain, false);
  assert.equal(plain.data.propagation.storedMessages, 1200);
  const s = await setup({
    tokens: new Map([['a.test:1', SECRET]]),
    statsFn: async () => ({ ...(await fetchStats('https://a.test/s', { fetchFn: spy(body), token: SECRET })) }),
  });
  try {
    await s.monitor.checkAll();
    assert.equal(s.monitor.propagationRows.get('a.test:1').rows.length, 1);
    const status = await (await fetch(`${s.base}/api/status`)).text();
    const detail = await (await fetch(`${s.base}/api/stats?host=a.test:1&range=7d`)).text();
    for (const text of [status, detail]) {
      assert.equal(text.includes(addr(1)), false);
      assert.equal(text.includes('Alice-Node'), false);
    }
    const a = JSON.parse(status).hosts.find((h) => h.host === 'a.test');
    assert.deepEqual(a.stats.peerSummary, { listed: 1, alive: 1, static: 0, unhandled: 4, truncated: false });
    assert.equal(JSON.parse(status).hosts[0].stats === null || !('peerSummary' in (JSON.parse(status).hosts[0].stats ?? {})), true);
  } finally {
    await s.close();
  }
});
