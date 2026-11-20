import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Monitor } from '../lib/monitor.js';
import { loadConfig } from '../lib/config.js';
import { createApp, LOGS_NOT_SERVED } from '../lib/app.js';
import { createLogin } from '../lib/login.js';
import { hashPassword } from '../lib/password.js';
import { LogsCache, fetchLogs, logsUrl, parseLogsQuery, sanitizeLogs } from '../lib/logs.js';
import { fakeHasher } from './helpers/fake-hasher.js';

const publicDir = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'public');
const TOKEN = 'tok-'.repeat(6);
const NOW = 1_800_000_000_000;

// ---- the query ----

test('parseLogsQuery: defaults, bounds and refusals', () => {
  const q = (s) => parseLogsQuery(new URLSearchParams(s));
  assert.deepEqual(q(''), { lines: 200, level: 'info' });
  assert.deepEqual(q('lines=1&level=error'), { lines: 1, level: 'error' });
  assert.deepEqual(q('lines=500&level=debug'), { lines: 500, level: 'debug' });
  for (const bad of ['lines=0', 'lines=501', 'lines=-1', 'lines=1.5', 'lines=abc', 'lines=', 'lines=1e2', 'lines=00000', 'lines=1&lines=2', 'level=loud', 'level=trace', 'level=', 'level=INFO', 'level=info&level=warn']) {
    assert.ok(q(bad).error, bad);
  }
});

// ---- the sanitizer ----

test('sanitizeLogs keeps the shape, drops what is not text and cleans the rest', () => {
  const out = sanitizeLogs({
    level: 'warn', truncated: false,
    lines: [
      { time: '2026-01-01T00:00:00Z', level: 'error', text: 'bad‮ thing​ here' },
      { time: 5, level: 'LOUD', text: 'line\nbreak\tand tab' },
      { time: null, level: null, text: 12 },
      null, 'text', [],
      { text: '\u0000\u0007' },
      { level: 'info', text: 'x'.repeat(5000) },
    ],
  });
  assert.equal(out.level, 'warn');
  assert.equal(out.truncated, false);
  assert.deepEqual(out.lines.slice(0, 2), [
    { time: '2026-01-01T00:00:00Z', level: 'error', text: 'bad thing here' },
    { time: null, level: null, text: 'line break and tab' },
  ]);
  assert.equal(out.lines.length, 3);
  assert.equal(out.lines[2].text.length, 1000);
  assert.deepEqual(Object.keys(out.lines[2]).sort(), ['level', 'text', 'time']);
});

test('sanitizeLogs: level tokens come from the allowed set only', () => {
  assert.equal(sanitizeLogs({ level: '<script>', lines: [] }, { level: 'debug' }).level, 'debug');
  assert.equal(sanitizeLogs({ level: 'trace', lines: [] }).level, 'trace');
  const out = sanitizeLogs({ lines: [{ level: 'constructor', text: 'a' }, { level: '__proto__', text: 'b' }, { level: ['error'], text: 'c' }] });
  assert.deepEqual(out.lines.map((l) => l.level), [null, null, null]);
});

test('sanitizeLogs caps the lines (the newest are kept) and says so', () => {
  const lines = Array.from({ length: 700 }, (_, i) => ({ level: 'info', text: `n${i}` }));
  const out = sanitizeLogs({ lines });
  assert.equal(out.lines.length, 500);
  assert.equal(out.lines[0].text, 'n200');
  assert.equal(out.lines[499].text, 'n699');
  assert.equal(out.truncated, true);
  const few = sanitizeLogs({ lines }, { lines: 3 });
  assert.deepEqual(few.lines.map((l) => l.text), ['n697', 'n698', 'n699']);
  assert.equal(few.truncated, true);
  assert.equal(sanitizeLogs({ lines: lines.slice(0, 5) }, { lines: 5 }).truncated, false);
  assert.equal(sanitizeLogs({ truncated: true, lines: [] }).truncated, true);
  assert.equal(sanitizeLogs({ truncated: 'yes', lines: [] }).truncated, false);
});

test('sanitizeLogs refuses what is not a log answer', () => {
  for (const raw of [null, undefined, 5, 'x', [], {}, { lines: 'x' }, { lines: {} }]) assert.equal(sanitizeLogs(raw), null);
  assert.deepEqual(sanitizeLogs({ lines: [] }), { level: 'info', truncated: false, lines: [] });
});

// ---- the fetch ----

const answer = (body, init = {}) => new Response(typeof body === 'string' ? body : JSON.stringify(body), { status: 200, ...init });

test('fetchLogs asks /logs beside the stats URL with the token in a header only', async () => {
  let seen;
  const r = await fetchLogs('https://n.test:8443/some/path/stats.json', {
    token: TOKEN, lines: 50, level: 'warn',
    fetchFn: async (url, init) => ((seen = { url, init }), answer({ level: 'warn', truncated: false, lines: [{ time: null, level: 'warn', text: 'hi' }] })),
  });
  assert.equal(seen.url, 'https://n.test:8443/some/path/logs?lines=50&level=warn');
  assert.equal(seen.init.headers.Authorization, `Bearer ${TOKEN}`);
  assert.equal(seen.init.redirect, 'error');
  assert.equal(seen.url.includes(TOKEN), false);
  assert.deepEqual(r, { ok: true, data: { level: 'warn', truncated: false, lines: [{ time: null, level: 'warn', text: 'hi' }] } });
});

test('fetchLogs maps every failure to a short code, never to the node\'s words', async () => {
  const code = async (fetchFn, extra = {}) => (await fetchLogs('https://n.test/s', { token: TOKEN, fetchFn, ...extra })).error;
  assert.equal(await code(async () => answer('secret text', { status: 404 })), 'not-found');
  assert.equal(await code(async () => answer('secret text', { status: 400 })), 'rejected');
  assert.equal(await code(async () => answer('secret text', { status: 500 })), 'unavailable');
  assert.equal(await code(async () => answer('not json')), 'invalid');
  assert.equal(await code(async () => answer({ nope: 1 })), 'invalid');
  assert.equal(await code(async () => answer('x'.repeat(2 * 1024 * 1024))), 'too-large');
  assert.equal(await code(async () => { throw new Error(`boom ${TOKEN}`); }), 'network');
  assert.equal(await code(async () => { throw Object.assign(new Error('t'), { name: 'TimeoutError' }); }), 'timeout');
  // Not allowed to carry the token: plain http to a public host, or a token of the wrong shape.
  let called = false;
  const spy = async () => ((called = true), answer({ lines: [] }));
  assert.equal((await fetchLogs('http://n.test/s', { token: TOKEN, fetchFn: spy })).error, 'token');
  assert.equal((await fetchLogs('https://n.test/s', { token: 'short', fetchFn: spy })).error, 'token');
  assert.equal((await fetchLogs('https://n.test/s', { fetchFn: spy })).error, 'token');
  assert.equal(called, false);
  assert.equal((await fetchLogs('http://127.0.0.1:9/s', { token: TOKEN, fetchFn: async () => answer({ lines: [] }) })).ok, true);
});

// ---- the cache and the rate limit ----

test('LogsCache: one fetch per node in 5 seconds, same question shared, other questions told to wait', async () => {
  let clock = NOW;
  const cache = new LogsCache({ now: () => clock });
  let n = 0;
  const fetcher = async () => ({ ok: true, data: { n: ++n } });
  const q = { lines: 200, level: 'info' };
  const [a, b] = await Promise.all([cache.get('a', q, fetcher), cache.get('a', q, fetcher)]);
  assert.equal(n, 1);
  assert.deepEqual(a, b);
  assert.equal(a.fetchedAt, NOW);
  clock += 1000;
  const other = await cache.get('a', { lines: 100, level: 'info' }, fetcher);
  assert.deepEqual(other, { ok: false, error: 'rate', retryAfter: 4 });
  // Another node is not held up by it.
  assert.equal((await cache.get('b', q, fetcher)).ok, true);
  assert.equal(n, 2);
  clock += 4000;
  assert.equal((await cache.get('a', { lines: 100, level: 'info' }, fetcher)).data.n, 3);
  // A clock that went backwards does not keep an entry for ever.
  clock -= 60_000;
  assert.equal((await cache.get('a', { lines: 100, level: 'info' }, fetcher)).data.n, 4);
});

test('LogsCache: one viewer asking something new every few seconds does not lock another viewer out', async () => {
  let clock = NOW;
  const waits = [];
  // A turn that has to wait moves the clock, as the real wait would.
  const cache = new LogsCache({ now: () => clock, sleep: async (ms) => { waits.push(ms); clock += ms; } });
  let n = 0;
  const fetcher = async () => ({ ok: true, data: { n: ++n } });
  const q = (lines) => ({ lines, level: 'info' });
  assert.equal((await cache.get('a', q(7), fetcher, 'user:mallory')).ok, true);
  // Mallory asks again at once with another number of lines: she alone is told to wait.
  assert.deepEqual(await cache.get('a', q(8), fetcher, 'user:mallory'), { ok: false, error: 'rate', retryAfter: 5 });
  // Alice asks a different question 100 ms later: not a 429, her turn comes 2 s after Mallory's fetch.
  clock += 100;
  const alice = await cache.get('a', q(200), fetcher, 'user:alice');
  assert.equal(alice.ok, true);
  assert.deepEqual(waits, [1900]);
  assert.equal(n, 2);
  // Mallory keeps changing the question every 5 s: Alice still gets her own and shared answers.
  for (let lines = 8; lines < 14; lines++) {
    clock += 5000;
    assert.equal((await cache.get('a', q(lines), fetcher, 'user:mallory')).ok, true);
    assert.equal((await cache.get('a', q(200), fetcher, 'user:alice')).ok, true);
  }
});

test('LogsCache: the same question from different viewers is one fetch, and a kept answer costs a viewer nothing', async () => {
  let clock = NOW;
  const cache = new LogsCache({ now: () => clock });
  let n = 0;
  const fetcher = async () => ({ ok: true, data: { n: ++n } });
  const q = { lines: 50, level: 'warn' };
  const answers = await Promise.all(['user:a', 'user:b', 'ip:1.2.3.4'].map((v) => cache.get('a', q, fetcher, v)));
  assert.equal(n, 1);
  assert.equal(new Set(answers.map((r) => r.data.n)).size, 1);
  // The same level on another node, or another level on this one, is a different question.
  assert.equal((await cache.get('b', q, fetcher, 'user:a')).data.n, 2);
  clock += 5000;
  assert.equal((await cache.get('a', { lines: 50, level: 'error' }, fetcher, 'user:a')).data.n, 3);
});

test('LogsCache: a node is asked once per 2 s across viewers; fetches wait their turn, and past the queue are told to wait', async () => {
  let clock = NOW;
  const waits = [];
  const cache = new LogsCache({ now: () => clock, queue: 2, sleep: async (ms) => { waits.push(ms); } });
  let fetches = 0;
  const fetcher = async () => (fetches++, { ok: true, data: {} });
  const results = [];
  for (let i = 0; i < 5; i++) results.push(cache.get('a', { lines: i + 1, level: 'info' }, fetcher, `user:${i}`));
  const done = await Promise.all(results);
  // Turns at 0 s, 2 s and 4 s; the two after that are turned away until there is room again.
  assert.deepEqual(done.map((r) => r.ok), [true, true, true, false, false]);
  assert.deepEqual(done[3], { ok: false, error: 'rate', retryAfter: 2 });
  assert.equal(fetches, 3);
  assert.deepEqual(waits, [2000, 4000]);
});

test('LogsCache stays bounded: answers and viewers are capped and expire', async () => {
  let clock = NOW;
  const cache = new LogsCache({ now: () => clock, maxEntries: 5, maxViewers: 5, nodeIntervalMs: 0, sleep: async () => {} });
  const fetcher = async () => ({ ok: true, data: {} });
  for (let i = 0; i < 50; i++) {
    await cache.get('a', { lines: i + 1, level: 'info' }, fetcher, `ip:${i}`);
    assert.ok(cache.entries.size <= 5);
    assert.ok(cache.viewers.size <= 5);
  }
  // Old entries and viewers are dropped once they are over, before newer ones.
  clock += 10_000;
  await cache.get('a', { lines: 500, level: 'info' }, fetcher, 'ip:new');
  assert.equal(cache.entries.size, 1);
  assert.equal(cache.viewers.size, 1);
});

test('LogsCache keeps a failure for the same time and survives a fetcher that throws', async () => {
  let clock = NOW;
  const cache = new LogsCache({ now: () => clock });
  let n = 0;
  const q = { lines: 1, level: 'error' };
  const r = await cache.get('a', q, async () => ((n++), { ok: false, error: 'network' }));
  assert.equal(r.error, 'network');
  assert.equal((await cache.get('a', q, async () => ((n++), { ok: true }))).error, 'network');
  assert.equal(n, 1);
  clock += 5000;
  const t = await cache.get('a', q, async () => { throw new Error('x'); });
  assert.deepEqual(t, { ok: false, error: 'unavailable', fetchedAt: clock });
});

// ---- the endpoint ----

async function setup({ top = '', nodeA = '', users = true, logsEnabled = true, forceLogs = false, logsFn, tokens } = {}) {
  const hash = await hashPassword('correct horse battery', undefined, fakeHasher);
  const config = loadConfig(`${users ? `users:\n  - name: Alice\n    password_hash: '${hash}'\n` : ''}${top}
nodes:
  - address: p.test:1
    stats_url: https://p.test/s
    proxy_for: [a.test:1, b.test:1]
  - address: a.test:1
    stats_url: https://a.test/s
${nodeA}
  - address: b.test:1
    stats_url: https://b.test/s
  - address: c.test:1
`);
  let clock = NOW;
  const calls = [];
  const monitor = new Monitor({
    targets: config.targets, nodes: config.nodes, statsUrls: config.statsUrls, dataDir: await fs.mkdtemp(path.join(os.tmpdir(), 'website-')),
    publicDetails: config.defaults.publicDetails, requireLogin: config.defaults.requireLogin,
    tokens: tokens ?? new Map([['a.test:1', TOKEN], ['b.test:1', TOKEN + 'b'], ['c.test:1', TOKEN]]),
    probeFn: async () => ({ up: true, ms: 1 }),
    statsFn: async () => ({ ok: true, data: { rettuiVersion: '1.0.0', generatedAt: 1, uptimeSeconds: 100, interfaces: { total: 1, online: 1, clients: 4, rxBytes: 1, txBytes: 1 }, peersHeard: { total: 3, lxmf: 2, nomad: 1, propagation: 0 }, announcesLastMinute: 0 } }),
    logsFn: logsFn ?? (async (url, opts) => (calls.push({ url, ...opts }), { ok: true, data: { level: opts.level, truncated: false, lines: [{ time: 't', level: 'info', text: `from ${url}` }] } })),
    logsEnabled,
    publicLogs: config.defaults.publicLogs,
    now: () => clock,
    sampleIntervalMs: 1000,
  });
  await monitor.checkAll();
  const login = createLogin({ users: config.users, settings: config.login, hasher: fakeHasher });
  const server = createApp({ monitor, publicDir, ...(users ? { login } : {}) });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  return { monitor, calls, advance: (ms) => (clock += ms), port, close: () => (server.closeAllConnections(), new Promise((r) => server.close(r))) };
}

function request(port, { method = 'GET', path: p, headers = {}, body }) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path: p, method, headers }, (res) => {
      let text = '';
      res.on('data', (c) => (text += c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text, json: () => JSON.parse(text) }));
    });
    req.on('error', reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}
const FORM = { 'Content-Type': 'application/x-www-form-urlencoded', 'Sec-Fetch-Site': 'same-origin' };
const get = (s, p, cookie) => request(s.port, { path: p, headers: cookie ? { Cookie: cookie } : {} });
async function logIn(s) {
  const r = await request(s.port, { method: 'POST', path: '/login', headers: FORM, body: new URLSearchParams({ name: 'alice', password: 'correct horse battery' }).toString() });
  return (r.headers['set-cookie']?.[0] ?? '').split(';')[0];
}

test('logs are never public by default: no login, no logs', async () => {
  const s = await setup();
  try {
    const r = await get(s, '/api/logs/a.test:1');
    assert.equal(r.status, 401);
    assert.deepEqual(r.json(), { error: 'log in to see the logs' });
    assert.equal(s.calls.length, 0);
    assert.equal(r.headers['cache-control'], 'private, no-store');
    // The detail answer says the node has logs; they stay behind the login.
    const d = (await get(s, '/api/stats?host=a.test:1&range=6h', await logIn(s))).json();
    assert.equal(d.logs, true);
  } finally {
    await s.close();
  }
});

test('a logged-in visitor gets the node\'s lines, with the node\'s own token and URL, and no token in the answer', async () => {
  const s = await setup();
  try {
    const cookie = await logIn(s);
    const r = await get(s, '/api/logs/a.test:1?lines=50&level=warn', cookie);
    assert.equal(r.status, 200);
    const body = r.json();
    assert.deepEqual(body.requested, { lines: 50, level: 'warn' });
    assert.equal(body.level, 'warn');
    assert.equal(body.host, 'a.test:1');
    assert.equal(body.fetchedAt, new Date(NOW).toISOString());
    assert.deepEqual(body.lines, [{ time: 't', level: 'info', text: 'from https://a.test/s' }]);
    assert.equal(s.calls[0].token, TOKEN);
    assert.equal(r.text.includes(TOKEN), false);
    assert.equal(JSON.stringify(r.headers).includes(TOKEN), false);
    // The host may be percent-encoded and in any case.
    assert.equal((await get(s, '/api/logs/A.TEST%3A1?lines=50&level=warn', cookie)).status, 200);
  } finally {
    await s.close();
  }
});

test('an explicit require_login list, even an empty one, never makes logs public', async () => {
  for (const top of ['require_login: [details, disk]\n', 'require_login: []\n', 'require_login: [storage]\n']) {
    const s = await setup({ top, nodeA: '    require_login: []' });
    try {
      for (const host of ['a.test:1', 'b.test:1']) {
        const r = await get(s, `/api/logs/${host}`);
        assert.equal(r.status, 401, `${top} ${host}`);
      }
      assert.equal(s.calls.length, 0);
      // The open details do not say the node has logs, either.
      assert.equal((await get(s, '/api/stats?host=a.test:1&range=6h')).json().logs, undefined);
      assert.equal((await get(s, '/api/logs/a.test:1', await logIn(s))).status, 200);
    } finally {
      await s.close();
    }
  }
});

test('public_logs makes the logs of a node public, a node overrides the top level, and details still apply', async () => {
  const s = await setup({ top: 'public_logs: true\nrequire_login: []\n', nodeA: '    public_logs: false' });
  try {
    assert.equal((await get(s, '/api/logs/a.test:1')).status, 401);
    assert.equal((await get(s, '/api/logs/b.test:1')).status, 200);
    assert.equal((await get(s, '/api/stats?host=a.test:1&range=6h')).json().logs, undefined);
    assert.equal((await get(s, '/api/stats?host=b.test:1&range=6h')).json().logs, true);
    const combined = (await get(s, '/api/stats?host=p.test:1&range=6h&view=combined')).json();
    assert.deepEqual(combined.members.map((m) => [m.host, m.hasLogs]), [['a.test:1', false], ['b.test:1', true]]);
  } finally {
    await s.close();
  }
  // Public logs do not open locked details.
  const t = await setup({ top: 'public_logs: true\n' });
  try {
    assert.equal((await get(t, '/api/logs/a.test:1')).status, 401);
    assert.equal((await get(t, '/api/logs/a.test:1', await logIn(t))).status, 200);
  } finally {
    await t.close();
  }
  // Without users it is the only way to have logs.
  const u = await setup({ users: false, top: 'public_logs: true\n' });
  try {
    assert.equal((await get(u, '/api/logs/a.test:1')).status, 200);
  } finally {
    await u.close();
  }
});

test('public_logs is read strictly, is off by default and warns at start', () => {
  const nodes = (top, node = '') => `${top}nodes:\n  - address: a.test:1\n${node}  - address: b.test:1\n`;
  assert.equal(loadConfig(nodes('')).defaults.publicLogs, false);
  assert.equal(loadConfig(nodes('')).nodes.get('a.test:1').publicLogs, false);
  assert.equal(loadConfig(nodes('public_logs: true\n')).nodes.get('b.test:1').publicLogs, true);
  assert.equal(loadConfig(nodes('public_logs: true\n', '    public_logs: false\n')).nodes.get('a.test:1').publicLogs, false);
  for (const v of ['"yes"', '1', 'null']) assert.throws(() => loadConfig(nodes(`public_logs: ${v}\n`)), /public_logs must be true or false/);
  assert.throws(() => loadConfig(nodes('', '    public_logs: "true"\n')), /nodes\[1\]\.public_logs must be true or false/);
  assert.throws(() => loadConfig(nodes('require_login: [logs]\n')), /must be one of/);
});

test('without users or with logs switched off, a visitor gets no logs', async () => {
  for (const opts of [{ users: false }, { logsEnabled: false }]) {
    const s = await setup(opts);
    try {
      const r = await get(s, '/api/logs/a.test:1');
      assert.equal(r.status, opts.users === false ? 404 : 401);
      assert.equal(s.calls.length, 0);
      const d = await get(s, '/api/stats?host=a.test:1&range=6h', opts.users === false ? undefined : await logIn(s));
      assert.equal(d.json().logs, undefined);
    } finally {
      await s.close();
    }
  }
});

test('an anonymous visitor cannot tell a node without logs from a locked one', async () => {
  for (const opts of [{}, { users: false }, { top: 'require_login: []\n' }]) {
    const s = await setup({ ...opts, tokens: new Map([['a.test:1', TOKEN]]) });
    try {
      // a.test:1 serves logs, b.test:1 (no token) and c.test:1 (no stats URL) do not.
      const answers = [];
      for (const host of ['a.test:1', 'b.test:1', 'c.test:1']) {
        const r = await get(s, `/api/logs/${host}`);
        answers.push([r.status, r.text]);
      }
      assert.deepEqual(answers[1], answers[0]);
      assert.deepEqual(answers[2], answers[0]);
      assert.equal(s.calls.length, 0);
      // Nor does a detail or combined answer say which nodes have logs.
      assert.equal((await get(s, '/api/stats?host=a.test:1&range=6h')).text.includes('"logs"'), false);
      assert.equal((await get(s, '/api/stats?host=p.test:1&range=6h&view=combined')).text.includes('hasLogs":true'), false);
    } finally {
      await s.close();
    }
  }
});

test('level=trace is refused with a 400', async () => {
  const s = await setup();
  try {
    const r = await get(s, '/api/logs/a.test:1?level=trace', await logIn(s));
    assert.equal(r.status, 400);
    assert.match(r.json().error, /level must be one of error, warn, info, debug$/);
    assert.equal(s.calls.length, 0);
  } finally {
    await s.close();
  }
});

test('unknown hosts, nodes without a token or a stats URL, and private details are 404', async () => {
  const s = await setup({ tokens: new Map([['a.test:1', TOKEN]]), nodeA: '' });
  try {
    const cookie = await logIn(s);
    assert.deepEqual((await get(s, '/api/logs/nope.test:1', cookie)).json(), { error: 'unknown host' });
    assert.equal((await get(s, '/api/logs/', cookie)).status, 404);
    assert.equal((await get(s, '/api/logs/%E0%A4%A', cookie)).status, 404);
    const noToken = await get(s, '/api/logs/b.test:1', cookie);
    assert.equal(noToken.status, 404);
    assert.equal(noToken.json().error, LOGS_NOT_SERVED);
    assert.equal((await get(s, '/api/logs/c.test:1', cookie)).json().error, LOGS_NOT_SERVED);
    assert.equal(s.calls.length, 0);
  } finally {
    await s.close();
  }
  const p = await setup({ nodeA: '    public_details: false' });
  try {
    assert.equal((await get(p, '/api/logs/a.test:1', await logIn(p))).status, 404);
  } finally {
    await p.close();
  }
});

test('a bad query is a 400 and costs the node nothing; HEAD checks access without a fetch; POST is 405', async () => {
  const s = await setup();
  try {
    const cookie = await logIn(s);
    for (const bad of ['lines=0', 'lines=501', 'level=loud', 'lines=1&lines=2']) {
      const r = await get(s, `/api/logs/a.test:1?${bad}`, cookie);
      assert.equal(r.status, 400, bad);
      assert.match(r.json().error, /^(lines|level) must be/);
    }
    const head = await request(s.port, { method: 'HEAD', path: '/api/logs/a.test:1', headers: { Cookie: cookie } });
    assert.equal(head.status, 200);
    assert.equal(head.text, '');
    assert.equal((await request(s.port, { method: 'HEAD', path: '/api/logs/a.test:1' })).status, 401);
    assert.equal((await request(s.port, { method: 'POST', path: '/api/logs/a.test:1', headers: { Cookie: cookie } })).status, 405);
    assert.equal(s.calls.length, 0);
  } finally {
    await s.close();
  }
});

test('rate limit: one fetch per node in 5 seconds, the answer is cached, other nodes are free', async () => {
  const s = await setup();
  try {
    const cookie = await logIn(s);
    assert.equal((await get(s, '/api/logs/a.test:1', cookie)).status, 200);
    assert.equal((await get(s, '/api/logs/a.test:1', cookie)).status, 200);
    assert.equal(s.calls.length, 1);
    s.advance(2000);
    const limited = await get(s, '/api/logs/a.test:1?level=debug', cookie);
    assert.equal(limited.status, 429);
    assert.equal(limited.headers['retry-after'], '3');
    assert.equal(limited.json().retryAfter, 3);
    assert.equal(s.calls.length, 1);
    assert.equal((await get(s, '/api/logs/b.test:1?level=debug', cookie)).status, 200);
    assert.equal(s.calls.length, 2);
    s.advance(3000);
    assert.equal((await get(s, '/api/logs/a.test:1?level=debug', cookie)).status, 200);
    assert.equal(s.calls.length, 3);
    // The cache is shared, so it never gives a visitor who may not see the logs anything: access is checked first.
    assert.equal((await get(s, '/api/logs/a.test:1?level=debug')).status, 401);
  } finally {
    await s.close();
  }
});

test('rate limit: one viewer changing the question does not lock another one out', async () => {
  const s = await setup({ top: 'public_logs: true\nrequire_login: []\n' });
  try {
    const cookie = await logIn(s);
    // Alice (logged in) varies the question again and again; every answer after the first is her own 429.
    assert.equal((await get(s, '/api/logs/a.test:1?lines=7', cookie)).status, 200);
    assert.equal((await get(s, '/api/logs/a.test:1?lines=8', cookie)).status, 429);
    s.advance(2000);
    // Someone without a login (the node is public) asks a different question: answered, not 429.
    assert.equal((await get(s, '/api/logs/a.test:1?lines=9')).status, 200);
    assert.equal(s.calls.length, 2);
    // The same question again is the kept answer for both of them.
    assert.equal((await get(s, '/api/logs/a.test:1?lines=9', cookie)).status, 200);
    assert.equal(s.calls.length, 2);
  } finally {
    await s.close();
  }
});

test('upstream errors are mapped to our own words, never echoed', async () => {
  const cases = [
    ['not-found', 404, LOGS_NOT_SERVED],
    ['rejected', 502, 'The node did not answer with logs. Try again later.'],
    ['unavailable', 502, 'The node did not answer with logs. Try again later.'],
    ['network', 502, 'The node did not answer with logs. Try again later.'],
    ['timeout', 502, 'The node did not answer with logs. Try again later.'],
    ['invalid', 502, 'The node did not answer with logs. Try again later.'],
    ['too-large', 502, 'The node did not answer with logs. Try again later.'],
    ['SECRET NODE TEXT', 502, 'The node did not answer with logs. Try again later.'],
  ];
  for (const [error, status, message] of cases) {
    const s = await setup({ logsFn: async () => ({ ok: false, error }) });
    try {
      const r = await get(s, '/api/logs/a.test:1', await logIn(s));
      assert.equal(r.status, status, error);
      assert.deepEqual(r.json(), { error: message }, error);
    } finally {
      await s.close();
    }
  }
  const s = await setup({ logsFn: async () => { throw new Error(`leak ${TOKEN}`); } });
  try {
    const r = await get(s, '/api/logs/a.test:1', await logIn(s));
    assert.equal(r.status, 502);
    assert.equal(r.text.includes('leak'), false);
  } finally {
    await s.close();
  }
});

test('the combined view offers logs for each node, not summed; the token is not in any answer', async () => {
  const s = await setup();
  try {
    const cookie = await logIn(s);
    const d = await get(s, '/api/stats?host=p.test:1&range=6h&view=combined', cookie);
    const body = d.json();
    assert.deepEqual(body.members.map((m) => [m.host, m.hasLogs]), [['a.test:1', true], ['b.test:1', true]]);
    assert.equal('logs' in body, false);
    assert.equal(d.text.includes(TOKEN), false);
    // The proxy has no token, so it has no logs of its own.
    assert.equal((await get(s, '/api/logs/p.test:1', cookie)).status, 404);
    const status = await get(s, '/api/status', cookie);
    assert.equal(status.text.includes(TOKEN), false);
  } finally {
    await s.close();
  }
});

test('the token is not visible by dumping the monitor', async () => {
  const s = await setup();
  try {
    assert.equal(JSON.stringify(s.monitor).includes(TOKEN), false);
  } finally {
    await s.close();
  }
});

test('logsUrl puts /logs beside stats.json, or under a node path', () => {
  assert.equal(logsUrl('https://n.test:8443/stats.json').href, 'https://n.test:8443/logs');
  assert.equal(logsUrl('https://stats.test/front').href, 'https://stats.test/front/logs');
  assert.equal(logsUrl('https://stats.test/front/').href, 'https://stats.test/front/logs');
  assert.equal(logsUrl('https://stats.test/front/stats.json?x=1#y').href, 'https://stats.test/front/logs');
  assert.equal(logsUrl('https://stats.test').href, 'https://stats.test/logs');
});
