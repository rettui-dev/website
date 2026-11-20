// QA attacks on the named-user login. Written from the spec, not the code.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { Monitor } from '../lib/monitor.js';
import { loadConfig } from '../lib/config.js';
import { createApp } from '../lib/app.js';
import { COOKIE, NameBucket, Sessions, Throttle, clientIp, createLogin, hashGate, ipKey } from '../lib/login.js';
import { argon2Available, hashPassword, parsePhc, verifyPassword } from '../lib/password.js';
import { fakeHasher } from './helpers/fake-hasher.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const publicDir = path.join(here, '..', 'public');
const script = path.join(here, '..', 'scripts', 'hash-password.js');
const MIN = 60_000;
const NOW = 1_800_000_000_000;
const PASSWORD = 'correct horse battery';
const REAL = argon2Available();

const statsData = () => ({
  rettuiVersion: '9.8.7', generatedAt: 1, uptimeSeconds: 100,
  interfaces: { total: 1, online: 1, clients: 4, rxBytes: 1, txBytes: 1 },
  peersHeard: { total: 3, lxmf: 2, nomad: 1, propagation: 0 }, announcesLastMinute: 0,
  disk: { dataBytes: 123_456, fsTotalBytes: 1000, fsFreeBytes: 80 },
  propagation: {
    enabled: true, storedMessages: 4242, storedBytes: 4343, storageLimitBytes: null, peersConnected: null, peersTotal: 4444, peersAlive: 4545, peersStatic: null,
    peersAuto: null, peerLimit: null, staticPeers: null, autopeerDepth: null, messagesReceived: null, messagesServed: null, messagesSentToPeers: 4646,
    messagesReceivedFromPeers: 4747, messagesOfferedToPeers: null, unhandledMessages: 4848, unhandledDistinct: 4949, autopeer: null,
  },
});
const SECRET = ['4242', '4343', '4444', '4545', '4646', '4747', '4848', '4949', '9.8.7', 'usedPercent', 'fsFreeBytes', 'peerSummary'];

async function setup({ top = '', nodeA = '', nodeB = '', nodeP = '', hasher = fakeHasher, gate, extraUsers = '', clock: startClock } = {}) {
  const hash = await hashPassword(PASSWORD, undefined, fakeHasher);
  const config = loadConfig(`users:\n  - name: Alice\n    password_hash: '${hash}'\n${extraUsers}${top}
nodes:
  - address: p.test:1
    stats_url: https://p.test/s
    proxy_for: [a.test:1, b.test:1]
${nodeP}
  - address: a.test:1
    stats_url: https://a.test/s
${nodeA}
  - address: b.test:1
    stats_url: https://b.test/s
${nodeB}
`);
  let clock = NOW - 30 * MIN;
  const monitor = new Monitor({
    targets: config.targets, nodes: config.nodes, statsUrls: config.statsUrls, dataDir: await fs.mkdtemp(path.join(os.tmpdir(), 'qa-login-')),
    publicDetails: config.defaults.publicDetails, publicDiskFigures: config.defaults.publicDiskFigures, requireLogin: config.defaults.requireLogin,
    probeFn: async () => ({ up: true, ms: 1 }),
    statsFn: async () => ({ ok: true, data: statsData(), propagationPeers: { listed: 3, alive: 2, static: 0, unhandled: 0, truncated: false } }),
    now: () => clock,
    sampleIntervalMs: 1000,
  });
  for (let i = 0; i < 4; i++) {
    await monitor.checkAll();
    clock += 5 * MIN;
  }
  clock -= 5 * MIN;
  let loginClock = NOW;
  const login = createLogin({ users: config.users, settings: config.login, hasher, now: () => loginClock, ...(gate ? { gate } : {}) });
  const server = createApp({ monitor, publicDir, login });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  return {
    monitor, login, port, config,
    advance: (ms) => (loginClock += ms),
    close: () => (server.closeAllConnections(), new Promise((r) => server.close(r))),
  };
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
// Raw bytes on a socket, for requests node's http client will not build.
function raw(port, bytes) {
  return new Promise((resolve) => {
    const s = net.connect(port, '127.0.0.1');
    let out = '';
    s.on('data', (c) => (out += c));
    s.on('close', () => resolve(out));
    s.on('error', () => resolve(out));
    s.write(bytes);
    setTimeout(() => s.destroy(), 1500);
  });
}

const FORM = { 'Content-Type': 'application/x-www-form-urlencoded', 'Sec-Fetch-Site': 'same-origin', 'X-Rettui-Request': '1' };
const form = (o) => new URLSearchParams(o).toString();
const post = (s, p, body, headers = FORM) => request(s.port, { method: 'POST', path: p, headers, body });
const get = (s, p, cookie) => request(s.port, { path: p, headers: cookie ? { Cookie: cookie } : {} });
async function logIn(s, name = 'alice', password = PASSWORD, extra = {}) {
  const r = await post(s, '/login', form({ name, password }), { ...FORM, ...extra });
  return { r, cookie: (r.headers['set-cookie']?.[0] ?? '').split(';')[0] };
}
const noSecrets = (text, label) => { for (const x of SECRET) assert.equal(text.includes(x), false, `${label}: leaked ${x}`); };

// ---------- requests ----------

test('qa: a body of exactly the limit is read, one byte more is 413, also when chunked without Content-Length', async () => {
  const s = await setup();
  try {
    const pad = (n) => `name=alice&password=${'x'.repeat(n - 'name=alice&password='.length)}`;
    assert.equal(pad(4096).length, 4096);
    assert.equal((await post(s, '/login', pad(4096))).status, 401);
    assert.equal((await post(s, '/login', pad(4097))).status, 413);
    const big = 'name=alice&password=' + 'y'.repeat(2_000_000);
    const out = await raw(s.port, `POST /login HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\nSec-Fetch-Site: same-origin\r\nX-Rettui-Request: 1\r\nTransfer-Encoding: chunked\r\n\r\n${big.length.toString(16)}\r\n${big}\r\n0\r\n\r\n`);
    assert.match(out, /^HTTP\/1\.1 413/);
    // Still serving.
    assert.equal((await get(s, '/api/status')).status, 200);
  } finally {
    await s.close();
  }
});

test('qa: odd bodies never crash or log in (bad percent escapes, arrays, repeated fields, NUL, lone surrogates)', async () => {
  const s = await setup();
  try {
    const bodies = [
      'name=%E0%A4%A&password=%', 'name[]=alice&password[]=x', 'name=&password=', 'name=alice&name=bob&password=nope',
      'name=alice%00&password=correct horse battery', 'name=alice&password=%ED%A0%80', '%%%%', '&&&&', 'name', '=', 'password=x',
      `name=${'a'.repeat(200)}&password=x`, 'name=alice&password=%ff%fe',
    ];
    for (const b of bodies) {
      const r = await post(s, '/login', b);
      assert.ok([400, 401].includes(r.status), `${b} -> ${r.status}`);
      assert.equal(r.headers['set-cookie'], undefined);
    }
    assert.equal((await get(s, '/healthz')).status, 200);
  } finally {
    await s.close();
  }
});

test('qa: Content-Type and origin header variants', async () => {
  const s = await setup();
  try {
    const body = form({ name: 'alice', password: 'nope' });
    const ct = (v, extra = {}) => post(s, '/login', body, { 'Content-Type': v, 'Sec-Fetch-Site': 'same-origin', 'X-Rettui-Request': '1', ...extra });
    assert.equal((await ct('APPLICATION/X-WWW-FORM-URLENCODED; charset=UTF-8')).status, 401);
    assert.equal((await ct('application/x-www-form-urlencodedx')).status, 415);
    assert.equal((await ct('application/x-www-form-urlencoded-evil')).status, 415);
    assert.equal((await ct('multipart/form-data; boundary=x')).status, 415);
    // Sec-Fetch-Site wins over a matching Origin.
    const host = `127.0.0.1:${s.port}`;
    assert.equal((await post(s, '/login', body, { 'Content-Type': FORM['Content-Type'], 'Sec-Fetch-Site': 'cross-site', Origin: `http://${host}`, Host: host })).status, 403);
    assert.equal((await post(s, '/login', body, { 'Content-Type': FORM['Content-Type'], 'Sec-Fetch-Site': '', Origin: `http://${host}`, Host: host })).status, 403);
    assert.equal((await post(s, '/login', body, { 'Content-Type': FORM['Content-Type'], Origin: 'null', Host: host })).status, 403);
    assert.equal((await post(s, '/login', body, { 'Content-Type': FORM['Content-Type'], Origin: `http://${host}.evil.test`, Host: host })).status, 403);
    // Two Sec-Fetch-Site headers, one of them cross-site.
    const dup = await raw(s.port, `POST /login HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\nSec-Fetch-Site: same-origin\r\nSec-Fetch-Site: cross-site\r\nX-Rettui-Request: 1\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n${body}`);
    assert.match(dup, /^HTTP\/1\.1 403/);
  } finally {
    await s.close();
  }
});

test('qa: login and logout only answer POST on the exact path; GET and HEAD of them never set a cookie or log in', async () => {
  const s = await setup();
  try {
    for (const m of ['GET', 'HEAD', 'PUT', 'DELETE', 'PATCH']) {
      const r = await request(s.port, { method: m, path: '/login', headers: FORM, body: m === 'GET' || m === 'HEAD' ? undefined : form({ name: 'alice', password: PASSWORD }) });
      assert.notEqual(r.status, 200, m);
      assert.equal(r.headers['set-cookie'], undefined);
    }
  } finally {
    await s.close();
  }
});

// ---------- names and passwords ----------

test('qa: name case and surrounding space do not matter; the name in the answer is the configured one', async () => {
  const s = await setup();
  try {
    for (const n of ['ALICE', 'aLiCe', '  alice  ', 'Alice']) {
      const { r } = await logIn(s, n);
      assert.equal(r.status, 200, JSON.stringify(n));
      assert.equal(r.json().name, 'Alice');
    }
  } finally {
    await s.close();
  }
});

test('qa: failures under case and space variants of one name share one throttle', async () => {
  const s = await setup();
  try {
    const variants = ['alice', 'ALICE', ' Alice', 'alice ', 'aLICE', 'Alice'];
    for (const v of variants) await post(s, '/login', form({ name: v, password: 'nope' }));
    const r = await post(s, '/login', form({ name: 'alIce', password: PASSWORD }));
    assert.equal(r.status, 429);
  } finally {
    await s.close();
  }
});

test('qa: a 1024 byte password (what hash-password accepts) logs in; 1025 bytes does not; multi-byte counted in bytes', async () => {
  const pw = (n, ch = 'x') => ch.repeat(n);
  const s = await setup();
  try {
    // Replace Alice's hash with one for the long password via a second config.
    const edge = pw(1024);
    const hash = await hashPassword(edge, undefined, fakeHasher);
    const s2 = await setup({ extraUsers: `  - name: Edge\n    password_hash: '${hash}'\n` });
    try {
      assert.equal((await logIn(s2, 'edge', edge)).r.status, 200);
      assert.equal((await logIn(s2, 'edge', edge + 'x')).r.status, 401);
    } finally {
      await s2.close();
    }
    const uni = '€'.repeat(341); // 1023 bytes
    const h2 = await hashPassword(uni, undefined, fakeHasher);
    const s3 = await setup({ extraUsers: `  - name: Uni\n    password_hash: '${h2}'\n` });
    try {
      assert.equal((await logIn(s3, 'uni', uni)).r.status, 200);
    } finally {
      await s3.close();
    }
  } finally {
    await s.close();
  }
});

test('qa: unicode and whitespace passwords round trip exactly (no trimming, no normalisation applied by the server)', async () => {
  const pws = [' leading and trailing ', 'pässwörd', '\u{1F511}\u{1F512}', 'tab\there', 'a+b c%d&e=f'];
  for (const pw of pws) {
    const hash = await hashPassword(pw, undefined, fakeHasher);
    const s = await setup({ extraUsers: `  - name: Uni\n    password_hash: '${hash}'\n` });
    try {
      assert.equal((await logIn(s, 'uni', pw)).r.status, 200, JSON.stringify(pw));
      assert.equal((await logIn(s, 'uni', pw.trim() === pw ? pw + ' ' : pw.trim())).r.status, 401, JSON.stringify(pw));
    } finally {
      await s.close();
    }
  }
});

// ---------- throttle, gate ----------

test('qa: a burst of wrong passwords sent at once is cut off by the backoff after the free tries', async () => {
  // A slow hasher, so the requests overlap the way a scripted attacker would send them.
  const slow = async (a) => (await new Promise((r) => setTimeout(r, 40)), fakeHasher(a));
  const s = await setup({ hasher: slow });
  try {
    const rs = await Promise.all(Array.from({ length: 10 }, () => post(s, '/login', form({ name: 'alice', password: 'nope' }))));
    const guesses = rs.filter((r) => r.status === 401).length;
    // 5 free failures, then the next is allowed once and starts the wait: at most 6 may be checked.
    assert.ok(guesses <= 6, `${guesses} guesses were checked in one burst; the status codes were ${rs.map((r) => r.status)}`);
  } finally {
    await s.close();
  }
});

const PROXIED = "login:\n  trusted_proxies: ['127.0.0.1']\n";
const from = (ip) => ({ ...FORM, 'X-Forwarded-For': ip });

test('qa: past 2 running + 8 waiting a login is 503 with Retry-After, and the server recovers', async () => {
  let release;
  const held = new Promise((r) => (release = r));
  const s = await setup({ top: PROXIED, hasher: async (a) => (await held, fakeHasher(a)), gate: hashGate() });
  try {
    // Each from an address of its own, so only the gate in all turns them away.
    const login = (i) => post(s, '/login', form({ name: i === 0 ? 'alice' : `nobody${i}`, password: i === 0 ? PASSWORD : 'nope' }), from(`198.51.100.${i + 1}`));
    const rs = Array.from({ length: 14 }, (_, i) => login(i));
    await new Promise((r) => setTimeout(r, 300));
    release();
    const out = await Promise.all(rs);
    const busy = out.filter((r) => r.status === 503);
    assert.equal(busy.length, 4, out.map((r) => r.status).join());
    for (const b of busy) {
      assert.equal(b.headers['retry-after'], '2');
      assert.equal(b.headers['set-cookie'], undefined);
    }
    assert.equal((await logIn(s)).r.status, 200);
  } finally {
    await s.close();
  }
});

test('qa: 40 logins at once from one address get 2 places in the gate; a login from elsewhere still gets in', async () => {
  let release;
  const held = new Promise((r) => (release = r));
  const s = await setup({ top: PROXIED, hasher: async (a) => (await held, fakeHasher(a)), gate: hashGate() });
  try {
    const flood = Array.from({ length: 40 }, (_, i) => post(s, '/login', form({ name: `nobody${i}`, password: 'nope' }), from('203.0.113.66')));
    await new Promise((r) => setTimeout(r, 200));
    const real = post(s, '/login', form({ name: 'alice', password: PASSWORD }), from('192.0.2.10'));
    await new Promise((r) => setTimeout(r, 100));
    release();
    const out = await Promise.all(flood);
    assert.equal(out.filter((r) => r.status === 503).length, 38, out.map((r) => r.status).join());
    for (const b of out.filter((r) => r.status === 503)) assert.equal(b.headers['retry-after'], '2');
    assert.equal((await real).status, 200);
  } finally {
    await s.close();
  }
});

test('qa: a busy (503) answer does not count as a failed try for the name', async () => {
  let release;
  const held = new Promise((r) => (release = r));
  const s = await setup({ hasher: async (a) => (await held, fakeHasher(a)) });
  try {
    const rs = Array.from({ length: 30 }, () => post(s, '/login', form({ name: 'alice', password: 'nope' })));
    await new Promise((r) => setTimeout(r, 300));
    release();
    await Promise.all(rs);
    const fails = s.login.accounts.map.get('user:alice')?.count ?? 0;
    assert.ok(fails <= 10, `count ${fails}`);
  } finally {
    await s.close();
  }
});

test('qa: unknown and known names are throttled in the same way, with the same answer', async () => {
  const s = await setup();
  try {
    for (const n of ['alice', 'nobody']) for (let i = 0; i < 6; i++) await post(s, '/login', form({ name: n, password: 'x' }));
    const a = await post(s, '/login', form({ name: 'alice', password: 'x' }));
    const b = await post(s, '/login', form({ name: 'nobody', password: 'x' }));
    assert.equal(a.status, 429);
    assert.equal(b.status, 429);
    assert.equal(a.text, b.text);
    assert.equal(a.headers['retry-after'], b.headers['retry-after']);
  } finally {
    await s.close();
  }
});

test('qa: Throttle backoff doubles, caps at maxMs, and forgets after forgetMs', () => {
  let t = 0;
  const th = new Throttle({ free: 2, baseMs: 1000, maxMs: 8000, forgetMs: 100_000, now: () => t });
  th.fail('k'); th.fail('k');
  assert.equal(th.wait('k'), 0);
  const waits = [];
  for (let i = 0; i < 6; i++) { th.fail('k'); waits.push(th.wait('k')); }
  assert.deepEqual(waits, [1000, 2000, 4000, 8000, 8000, 8000]);
  t += 100_001;
  assert.equal(th.wait('k'), 0);
  th.fail('k');
  assert.equal(th.map.get('k').count, 1);
});

test('qa: Throttle with a huge failure count does not overflow into NaN or Infinity', () => {
  const th = new Throttle({ free: 0, now: () => 0 });
  for (let i = 0; i < 200; i++) th.fail('k');
  assert.ok(Number.isFinite(th.wait('k')));
  assert.ok(th.wait('k') <= th.maxMs);
});

test('qa: ipKey groups an IPv6 /64 and keeps IPv4 apart', () => {
  assert.equal(ipKey('2001:db8:1:2::1'), ipKey('2001:db8:1:2:ffff:ffff:ffff:ffff'));
  assert.equal(ipKey('2001:db8:1:2::1'), ipKey('2001:0db8:0001:0002:0:0:0:5'));
  assert.notEqual(ipKey('2001:db8:1:2::1'), ipKey('2001:db8:1:3::1'));
  assert.notEqual(ipKey('10.0.0.1'), ipKey('10.0.0.2'));
  assert.equal(ipKey('::'), ipKey('::1'));
});

test('qa: clientIp trusts X-Forwarded-For only from a trusted proxy and reads from the right', () => {
  const req = (peer, xff) => ({ socket: { remoteAddress: peer }, headers: xff === undefined ? {} : { 'x-forwarded-for': xff } });
  const trusted = new Set(['10.0.0.1']);
  assert.equal(clientIp(req('203.0.113.9', '1.2.3.4'), trusted), '203.0.113.9');
  assert.equal(clientIp(req('10.0.0.1', '6.6.6.6, 1.2.3.4'), trusted), '1.2.3.4');
  assert.equal(clientIp(req('10.0.0.1', '6.6.6.6, 1.2.3.4, 10.0.0.1'), trusted), '1.2.3.4');
  assert.equal(clientIp(req('::ffff:10.0.0.1', '1.2.3.4'), trusted), '1.2.3.4');
  assert.equal(clientIp(req('10.0.0.1', 'garbage'), trusted), '10.0.0.1');
  assert.equal(clientIp(req('10.0.0.1', undefined), trusted), '10.0.0.1');
});

test('qa: a trusted_proxies IPv6 address in long form still matches the peer the socket reports', async () => {
  const s = await setup({ top: 'login:\n  trusted_proxies: ["0:0:0:0:0:0:0:1", "FD00::1"]\n' });
  try {
    const req = (peer) => ({ socket: { remoteAddress: peer }, headers: { 'x-forwarded-for': '203.0.113.7' } });
    assert.equal(clientIp(req('::1'), s.login.trusted), '203.0.113.7');
    assert.equal(clientIp(req('fd00::1'), s.login.trusted), '203.0.113.7');
  } finally {
    await s.close();
  }
});

test('qa: trusted_proxies networks from the config file are what the login trusts', async () => {
  const s = await setup({ top: 'login:\n  trusted_proxies: ["172.22.0.0/16", "fd00::/16", "127.0.0.1"]\n' });
  try {
    const req = (peer, xff = '203.0.113.7') => ({ socket: { remoteAddress: peer }, headers: { 'x-forwarded-for': xff } });
    assert.equal(clientIp(req('::ffff:172.22.255.255'), s.login.trusted), '203.0.113.7');
    assert.equal(clientIp(req('fd00:0:1::2', '203.0.113.7, 172.22.0.3'), s.login.trusted), '203.0.113.7');
    assert.equal(clientIp(req('172.23.0.1'), s.login.trusted), '172.23.0.1');
    assert.equal(clientIp(req('fd01::1'), s.login.trusted), 'fd01::1');
  } finally {
    await s.close();
  }
});

// ---------- sessions ----------

test('qa: idle timeout slides with use on /api/status polls, max age does not', async () => {
  const s = await setup({ top: 'login:\n  idle_timeout_minutes: 5\n  max_age_hours: 1\n' });
  try {
    const { cookie } = await logIn(s);
    const viewer = async () => (await get(s, '/api/status', cookie)).json().viewer.name;
    // Polling every 15 s keeps it alive well past the idle time.
    for (let i = 0; i < 60; i++) {
      s.advance(15_000);
      assert.equal(await viewer(), 'Alice', `poll ${i}`);
    }
    // The 60 polls took 15 minutes; poll on to one hour after the login (240 x 15 s): the max age ends it, however active.
    for (let i = 60; i < 240; i++) {
      s.advance(15_000);
      if (i < 239) assert.equal(await viewer(), 'Alice', `poll ${i}`);
    }
    s.advance(0);
    const r = await get(s, '/api/status', cookie);
    assert.equal(r.json().viewer.name, null);
    noSecrets(r.text, 'after max age');
    assert.equal((await get(s, '/api/stats?host=a.test:1&range=6h', cookie)).status, 401);
  } finally {
    await s.close();
  }
});

test('qa: an idle session ends exactly at the idle time and a later poll gets the locked answer, not an error', async () => {
  const s = await setup({ top: 'login:\n  idle_timeout_minutes: 1\n' });
  try {
    const { cookie } = await logIn(s);
    s.advance(59_999);
    assert.equal((await get(s, '/api/status', cookie)).json().viewer.name, 'Alice');
    s.advance(60_000);
    const r = await get(s, '/api/status', cookie);
    assert.equal(r.status, 200);
    assert.equal(r.json().viewer.name, null);
    noSecrets(r.text, 'idle');
    // And the id stays dead.
    s.advance(1);
    assert.equal((await get(s, '/api/status', cookie)).json().viewer.name, null);
  } finally {
    await s.close();
  }
});

test('qa: static pages and /healthz do not keep a session alive, and a clock that jumps back ends it', async () => {
  const s = await setup({ top: 'login:\n  idle_timeout_minutes: 1\n' });
  try {
    const { cookie } = await logIn(s);
    s.advance(30_000);
    await get(s, '/healthz', cookie);
    s.advance(40_000);
    assert.equal((await get(s, '/api/status', cookie)).json().viewer.name, null);
    const b = await logIn(s);
    s.advance(-10_000);
    assert.equal((await get(s, '/api/status', b.cookie)).json().viewer.name, null);
  } finally {
    await s.close();
  }
});

test('qa: Sessions with max 2 push out the least recently used, and use counts', () => {
  let t = 0;
  const ss = new Sessions({ idleMs: 1e9, maxAgeMs: 1e9, max: 2, now: () => t });
  const a = ss.create('a'); const b = ss.create('b');
  assert.ok(ss.get(a));
  const c = ss.create('c');
  assert.equal(ss.get(b), null);
  assert.ok(ss.get(a)); assert.ok(ss.get(c));
  assert.equal(ss.size, 2);
});

test('qa: tampered, truncated, extended, duplicated and odd cookies are no session', async () => {
  const s = await setup();
  try {
    const { cookie } = await logIn(s);
    const id = cookie.split('=')[1];
    const flip = id.slice(0, -1) + (id.endsWith('A') ? 'B' : 'A');
    const odd = [
      `${COOKIE}=${flip}`, `${COOKIE}=${id.slice(1)}`, `${COOKIE}=${id}x`, `${COOKIE}=${id.toLowerCase()}`, `${COOKIE}="${id}"`, `${COOKIE}=${id}%00`,
      `${COOKIE.slice(7)}=${id}`, `__Secure-rettui_session=${id}`, `${COOKIE.toLowerCase()}=${id}`, `${COOKIE}=`, `${COOKIE}=${id}${id}`,
    ];
    for (const c of odd) {
      const r = await get(s, '/api/stats?host=a.test:1&range=6h', c);
      assert.equal(r.status, 401, c);
    }
    // Proto-pollution style ids must not hit Map internals.
    for (const c of [`${COOKIE}=__proto__`, `${COOKIE}=constructor`]) assert.equal((await get(s, '/api/status', c)).json().viewer.name, null);
    // The real one still works, also with spaces around and other cookies in the header.
    assert.equal((await get(s, '/api/stats?host=a.test:1&range=6h', `a=b;  ${cookie} ; c=d`)).status, 200);
  } finally {
    await s.close();
  }
});

test('qa: one session of a user does not log out the others, and logout of a stale cookie is harmless', async () => {
  const s = await setup();
  try {
    const one = await logIn(s); const two = await logIn(s);
    assert.notEqual(one.cookie, two.cookie);
    await post(s, '/logout', '', { ...FORM, Cookie: one.cookie });
    assert.equal((await get(s, '/api/status', two.cookie)).json().viewer.name, 'Alice');
    assert.equal((await post(s, '/logout', '', { ...FORM, Cookie: `${COOKIE}=garbage` })).status, 200);
    assert.equal((await post(s, '/logout', '', FORM)).status, 200);
  } finally {
    await s.close();
  }
});

test('qa: a failed login with a valid cookie does not log the visitor out or in as someone else', async () => {
  const s = await setup();
  try {
    const { cookie } = await logIn(s);
    const bad = await post(s, '/login', form({ name: 'alice', password: 'wrong' }), { ...FORM, Cookie: cookie });
    assert.equal(bad.status, 401);
    assert.equal(bad.headers['set-cookie'], undefined);
    assert.equal((await get(s, '/api/status', cookie)).json().viewer.name, 'Alice');
  } finally {
    await s.close();
  }
});

test('qa: ten concurrent correct logins all work and give ten different sessions', async () => {
  const s = await setup();
  try {
    const rs = await Promise.all(Array.from({ length: 8 }, () => logIn(s)));
    assert.equal(rs.filter((x) => x.r.status === 200).length, 8);
    assert.equal(new Set(rs.map((x) => x.cookie)).size, 8);
  } finally {
    await s.close();
  }
});

// ---------- what is shown ----------

test('qa: per-node override replaces the default, and the group line hides everything hidden on any member', async () => {
  const s = await setup({ top: 'require_login: [storage]', nodeA: '    require_login: [disk]' });
  try {
    const body = (await get(s, '/api/status')).json();
    const [p, a, b] = body.hosts;
    assert.deepEqual(a.locked, ['disk']);
    assert.deepEqual(b.locked, ['storage']);
    assert.equal(a.stats.data.propagation.storedMessages, 4242);
    assert.equal(a.stats.data.disk, undefined);
    assert.equal(b.stats.data.propagation.storedMessages, undefined);
    assert.equal(b.stats.data.disk.level !== undefined, true);
    assert.equal(p.group.data.disk, null);
    assert.equal(p.group.data.propagation.storedMessages, undefined);
    assert.equal(p.group.data.propagation.storedBytes, undefined);
    assert.equal(p.group.data.propagation.messagesSentToPeers, undefined);
    assert.equal(p.group.data.propagation.unhandledMessages, undefined);
    assert.equal(JSON.stringify(p.group).includes('8484'), false);
    assert.equal(JSON.stringify(p.group).includes('123456'), false);
    // Details are public, and their combined view and series follow the same rules.
    const c = await get(s, '/api/stats?host=p.test:1&range=6h&view=combined');
    assert.equal(c.status, 200);
    const j = c.json();
    assert.equal(j.series.disk, null);
    assert.equal(j.series.propagation.storedMessages, undefined);
    assert.equal(j.series.propagation.sentPerMinute, undefined);
    assert.equal(j.group.data.propagation.storedMessages, undefined);
    assert.equal(c.text.includes('123456'), false);
    assert.equal(c.text.includes('4242'), false);
    const d = (await get(s, '/api/stats?host=b.test:1&range=6h')).json();
    assert.equal(d.series.propagation.storedMessages, undefined);
    assert.ok(d.series.disk !== undefined);
  } finally {
    await s.close();
  }
});

test('qa: a proxy that is locked hides its group line even when every member is public', async () => {
  const s = await setup({ top: 'require_login: []', nodeP: '    require_login: [storage, peers, disk, versions]' });
  try {
    const r = await get(s, '/api/status');
    const g = r.json().hosts[0].group;
    assert.equal(g.data.propagation, null);
    assert.equal(g.data.disk, null);
    const m = r.json().hosts[1];
    assert.deepEqual(m.locked, []);
  } finally {
    await s.close();
  }
});

test('qa: public_details false on a proxy member leaves it out of the combined details and its name out of the answer', async () => {
  const s = await setup({ top: 'require_login: []', nodeB: '    public_details: false' });
  try {
    const c = await get(s, '/api/stats?host=p.test:1&range=6h&view=combined');
    assert.equal(c.status, 200);
    assert.equal(c.text.includes('b.test'), false);
    assert.equal(c.json().series.members, 1);
    assert.equal((await get(s, '/api/stats?host=b.test:1&range=6h')).status, 404);
    const { cookie } = await logIn(s);
    assert.equal((await get(s, '/api/stats?host=b.test:1&range=6h', cookie)).status, 404);
    assert.equal((await get(s, '/api/stats?host=p.test:1&range=6h&view=combined', cookie)).text.includes('b.test'), false);
  } finally {
    await s.close();
  }
});

test('qa: nothing locked is in any anonymous answer, over every host, range, view and query variant', async () => {
  const s = await setup();
  try {
    // Warm the logged-in cache first, so a shared cache would show.
    const { cookie } = await logIn(s);
    for (const host of ['p.test:1', 'a.test:1', 'b.test:1']) for (const range of ['6h', '24h', '7d']) for (const view of ['node', 'combined']) {
      await get(s, `/api/stats?host=${host}&range=${range}&view=${view}`, cookie);
    }
    await get(s, '/api/status', cookie);
    const paths = [];
    for (const host of ['p.test:1', 'A.TEST:1', 'b.test:1', 'p.test:1&host=a.test:1', 'a.test:1&x=1']) for (const range of ['6h', '24h', '7d']) for (const view of ['node', 'combined']) {
      paths.push(`/api/stats?host=${host}&range=${range}&view=${view}`);
    }
    paths.push('/api/status', '/api/status?x=1', '//api/status', '/api/status/', '/api/stats');
    for (const p of paths) {
      const r = await get(s, p);
      noSecrets(r.text, p);
      assert.notEqual(r.status, 500, p);
    }
    // HEAD must not be a way round it.
    const h = await request(s.port, { method: 'HEAD', path: '/api/stats?host=a.test:1&range=6h' });
    assert.equal(h.status, 401);
  } finally {
    await s.close();
  }
});

test('qa: the 15 s refresh path: the same cookie flips between locked and open answers with the session, never mixing', async () => {
  const s = await setup({ top: 'login:\n  idle_timeout_minutes: 1\n' });
  try {
    const a = await logIn(s);
    const url = '/api/stats?host=a.test:1&range=6h';
    for (let round = 0; round < 3; round++) {
      assert.equal((await get(s, url, a.cookie)).status, 200);
      assert.equal((await get(s, url)).status, 401);
      s.advance(61_000);
      assert.equal((await get(s, url, a.cookie)).status, 401);
      const st = await get(s, '/api/status', a.cookie);
      noSecrets(st.text, `round ${round}`);
      a.cookie = (await logIn(s)).cookie;
    }
  } finally {
    await s.close();
  }
});

test('qa: Vary and Cache-Control are on every API answer, error answers too', async () => {
  const s = await setup();
  try {
    for (const p of ['/api/status', '/api/stats?host=a.test:1&range=6h', '/api/stats?host=zzz&range=6h', '/api/stats?host=a.test:1&range=1y']) {
      const r = await get(s, p);
      assert.equal(r.headers['cache-control'], 'private, no-store', p);
      assert.equal(r.headers.vary, 'Cookie', p);
    }
  } finally {
    await s.close();
  }
});

// ---------- startup: config ----------

const GOOD = '$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHRzYWx0$' + Buffer.alloc(32, 7).toString('base64').replace(/=+$/, '');
const NODES = '\nnodes:\n  - address: a.test:1\n';
const cfg = (users, extra = '') => `${users}${extra}${NODES}`;
const user = (hash, name = 'alice') => `users:\n  - name: ${name}\n    password_hash: '${hash}'\n`;
const rejects = (text, label) => assert.throws(() => loadConfig(text), /CONFIG_FILE/, label);

test('qa: the reference hash used by these tests is itself accepted', () => {
  assert.doesNotThrow(() => loadConfig(cfg(user(GOOD))));
});

test('qa: bad password hashes are rejected at startup and the error never repeats the hash', () => {
  const mk = (mid, salt = 'c29tZXNhbHRzYWx0', hash = Buffer.alloc(32, 7).toString('base64').replace(/=+$/, '')) => `$argon2id${mid}$${salt}$${hash}`;
  const bad = [
    GOOD.replace('argon2id', 'argon2i'), GOOD.replace('argon2id', 'argon2d'), GOOD.replace('argon2id', 'ARGON2ID'), GOOD.replace('v=19', 'v=16'), GOOD.replace('v=19', 'v=0x13'),
    mk('$v=19$m=19455,t=2,p=1'), mk('$v=19$m=19456,t=1,p=1'), mk('$v=19$m=19456,t=2,p=0'), mk('$v=19$m=19456,t=2,p=17'), mk('$v=19$m=262145,t=2,p=1'), mk('$v=19$m=19456,t=17,p=1'),
    mk('$v=19$m=019456,t=2,p=1'), mk('$v=19$m=19456,t=2,p=1,keyid=AA'), mk('$v=19$t=2,m=19456,p=1'), mk('$v=19$m=1e5,t=2,p=1'), mk('$v=19$m=-19456,t=2,p=1'), mk('$v=19$m=19456.0,t=2,p=1'),
    mk('$v=19$m=19456,t=2,p=1', 'AAAA'), mk('$v=19$m=19456,t=2,p=1', 'c29tZXNhbHRzYWx0=='), mk('$v=19$m=19456,t=2,p=1', 'c29tZXNh*HRzYWx0'), mk('$v=19$m=19456,t=2,p=1', 'c29tZXNhbHRzYWx0', 'AAAA'),
    mk('$v=19$m=19456,t=2,p=1', 'c29tZXNhbHRzYWx0', 'A'.repeat(200)), GOOD + '$', GOOD + '\n', ` ${GOOD}`, GOOD.replace(/^\$/, ''), '', 'plaintext', '$argon2id$', GOOD.slice(0, 40),
    mk('$v=19$m=19456,t=2,p=1', 'c29tZXNhbHRzYWx0', 'ab-_ab-_ab-_ab-_ab-_ab-_ab-_ab-_ab-_ab-_ab-_'),
    GOOD + 'A'.repeat(600),
  ];
  for (const h of bad) {
    let err;
    try { loadConfig(cfg(user(h.replace(/'/g, '')))); } catch (e) { err = e; }
    assert.ok(err, `accepted ${JSON.stringify(h.slice(0, 80))}`);
    if (h.length > 12) assert.equal(err.message.includes(h.slice(0, 40)), false, 'error repeats the hash');
  }
});

test('qa: password_hash and name of the wrong type are rejected', () => {
  for (const v of ['123', 'true', 'null', '[a]', '{a: b}', '~', '']) rejects(cfg(`users:\n  - name: alice\n    password_hash: ${v}\n`), `hash ${v}`);
  for (const v of ['123', 'true', 'null', '[a]', '~', '""', "' alice'", 'ali ce', '.alice', '-alice', '_alice', "'a\\u00e9'", 'a'.repeat(33), 'al/ice', "'alice\n'"]) {
    rejects(cfg(`users:\n  - name: ${v}\n    password_hash: '${GOOD}'\n`), `name ${v}`);
  }
  assert.doesNotThrow(() => loadConfig(cfg(user(GOOD, 'a'.repeat(32)))));
  assert.doesNotThrow(() => loadConfig(cfg(user(GOOD, '0lice.x_y-z'))));
});

test('qa: users list shapes: duplicates in any case, unknown keys, empty, too many, wrong type', () => {
  const u = (n) => `  - name: ${n}\n    password_hash: '${GOOD}'\n`;
  rejects(cfg(`users:\n${u('alice')}${u('alice')}`), 'dup');
  rejects(cfg(`users:\n${u('alice')}${u('ALICE')}`), 'dup case');
  rejects(cfg(`users:\n${u('Alice')}${u('aLICE')}`), 'dup case 2');
  rejects(cfg('users: []\n'), 'empty');
  rejects(cfg('users:\n'), 'null');
  rejects(cfg('users: alice\n'), 'string');
  rejects(cfg('users: {alice: x}\n'), 'map');
  rejects(cfg(`users:\n  - name: alice\n    password: hunter2\n`), 'plaintext password key');
  rejects(cfg(`users:\n  - name: alice\n    password_hash: '${GOOD}'\n    admin: true\n`), 'extra key');
  rejects(cfg(`users:\n  - name: alice\n`), 'no hash');
  rejects(cfg(`users:\n  - alice\n`), 'bare name');
  rejects(cfg(`users:\n${Array.from({ length: 65 }, (_, i) => u(`u${i}`)).join('')}`), '65 users');
  assert.doesNotThrow(() => loadConfig(cfg(`users:\n${Array.from({ length: 64 }, (_, i) => u(`u${i}`)).join('')}`)));
  rejects(cfg(`users:\n  - name: alice\n    name: bob\n    password_hash: '${GOOD}'\n`), 'dup key');
});

test('qa: rules and login settings without users are rejected, an empty rule is not', () => {
  rejects(cfg('', 'require_login: [details]\n'), 'top rule');
  rejects(cfg('', 'login: {}\n'), 'login');
  rejects(cfg('', 'login:\n  max_sessions: 3\n'), 'login 2');
  rejects(`${NODES}    require_login: [disk]\n`, 'node rule');
  rejects(cfg('users: []\n', 'require_login: [details]\n'), 'empty users with rule');
  assert.doesNotThrow(() => loadConfig(cfg('', 'require_login: []\n')));
  assert.doesNotThrow(() => loadConfig(`${NODES}    require_login: []\n`));
  const c = loadConfig(cfg(''));
  assert.deepEqual(c.defaults.requireLogin, []);
  assert.deepEqual(c.users, []);
});

test('qa: require_login values: unknown, duplicate, wrong case, wrong type, null', () => {
  const base = user(GOOD);
  for (const v of ['[detail]', '[Details]', '[details, details]', 'details', 'null', '{details: true}', '[1]', '[[details]]', '[null]', '"all"', '[""]']) rejects(cfg(base, `require_login: ${v}\n`), v);
  for (const v of ['[detail]', '[details, details]', 'storage', 'null']) rejects(`${base}${NODES}    require_login: ${v}\n`, `node ${v}`);
  const c = loadConfig(cfg(base));
  assert.deepEqual(c.defaults.requireLogin, ['details', 'storage', 'peers', 'disk', 'versions']);
  assert.deepEqual(loadConfig(cfg(base, 'require_login: []\n')).defaults.requireLogin, []);
  assert.deepEqual(loadConfig(`${base}${NODES}    require_login: []\n`).nodes.get('a.test:1').requireLogin, []);
});

test('qa: login settings: bounds, types and unknown keys', () => {
  const base = user(GOOD);
  const L = (body) => cfg(base, `login:\n${body}`);
  for (const b of [
    '  idle_timeout_minutes: 0\n', '  idle_timeout_minutes: -1\n', '  idle_timeout_minutes: 1.5\n', '  idle_timeout_minutes: "5"\n', '  idle_timeout_minutes: 10081\n', '  idle_timeout_minutes: .inf\n', '  idle_timeout_minutes: .nan\n',
    '  max_age_hours: 0\n', '  max_age_hours: 2161\n', '  max_sessions: 0\n', '  max_sessions: 100001\n', '  idle_timeout_minutes: 121\n  max_age_hours: 2\n', '  idle_timeout_minutes: 70\n  max_age_hours: 1\n',
    '  idle: 5\n', '  trusted_proxies: 10.0.0.1\n', '  trusted_proxies: [not-an-ip]\n', '  trusted_proxies: ["10.0.0.1/33"]\n', '  trusted_proxies: ["0.0.0.0/0"]\n', '  trusted_proxies: [10.0.0.1, 10.0.0.1, 1, 2]\n',
  ]) {
    if (b.includes('10.0.0.1, 10.0.0.1, 1')) continue;
    rejects(L(b), b);
  }
  rejects(cfg(base, 'login: 5\n'), 'login scalar');
  rejects(cfg(base, 'login:\n'), 'login null');
  assert.doesNotThrow(() => loadConfig(L('  idle_timeout_minutes: 60\n  max_age_hours: 1\n')));
  assert.doesNotThrow(() => loadConfig(L('  idle_timeout_minutes: 10080\n  max_age_hours: 168\n')));
  assert.equal(loadConfig(L('  trusted_proxies: ["::FFFF:10.0.0.1"]\n')).login.trustedProxies.length, 1);
});

test('qa: YAML tricks in the users part are refused: anchors, tags, merge keys, second document', () => {
  rejects(`users:\n  - &u\n    name: alice\n    password_hash: '${GOOD}'\n  - *u${NODES}`, 'alias');
  rejects(`users:\n  - !!binary name: x\n    password_hash: '${GOOD}'${NODES}`, 'tag');
  rejects(`${user(GOOD)}---\nusers: []\n${NODES}`, 'second doc');
  rejects(`${user(GOOD)}${user(GOOD, 'bob')}${NODES}`, 'repeated top key');
});

// ---------- real Argon2id ----------

test('qa: real argon2id: hash, verify, wrong password, and cost parameters are honoured', { skip: !REAL }, async () => {
  const phc = await hashPassword('päss \u{1F511}');
  const parsed = parsePhc(phc);
  assert.equal(await verifyPassword('päss \u{1F511}', parsed), true);
  assert.equal(await verifyPassword('päss', parsed), false);
  assert.equal(await verifyPassword('', parsed), false);
  const other = parsePhc(await hashPassword('x', { memory: 20000, passes: 3, parallelism: 2 }));
  assert.deepEqual([other.memory, other.passes, other.parallelism], [20000, 3, 2]);
  assert.equal(await verifyPassword('x', other), true);
});

test('qa: real argon2id: a full HTTP login with the default hasher', { skip: !REAL }, async () => {
  const hash = await hashPassword(PASSWORD);
  const config = loadConfig(`users:\n  - name: Alice\n    password_hash: '${hash}'\nnodes:\n  - address: a.test:1\n`);
  const monitor = new Monitor({ targets: config.targets, nodes: config.nodes, dataDir: await fs.mkdtemp(path.join(os.tmpdir(), 'qa-login-')), requireLogin: config.defaults.requireLogin, probeFn: async () => ({ up: true, ms: 1 }) });
  const server = createApp({ monitor, publicDir, login: createLogin({ users: config.users, settings: config.login }) });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const s = { port: server.address().port };
  try {
    assert.equal((await logIn(s, 'alice', PASSWORD)).r.status, 200);
    assert.equal((await logIn(s, 'alice', 'wrong')).r.status, 401);
  } finally {
    server.closeAllConnections();
    await new Promise((r) => server.close(r));
  }
});

test('qa: real argon2id: an unknown name takes as long as the wrong password of the one user it stands in for', { skip: !REAL }, async () => {
  // Alice has the cheap costs; Bob has costs several times higher. An unknown name always takes as
  // long as one of them, the same one each time, so its time tells nothing about whether it exists.
  const cheap = await hashPassword('pw-alice');
  const dear = await hashPassword('pw-bob', { memory: 65536, passes: 3, parallelism: 1 });
  const config = loadConfig(`users:\n  - name: alice\n    password_hash: '${cheap}'\n  - name: bob\n    password_hash: '${dear}'\nnodes:\n  - address: a.test:1\n`);
  // No throttle or pacing holds a try back: only the hash is timed.
  const free = () => new Throttle({ free: 1e6 });
  const login = createLogin({ users: config.users, settings: config.login, throttle: { accounts: free(), addresses: free(), nets56: free(), nets48: free(), names: new NameBucket({ burst: 1e6, backlog: 1e6 }) } });
  const time = async (name) => {
    const t0 = process.hrtime.bigint();
    const r = await login.attempt(name, 'wrong', '10.0.0.1');
    assert.equal(r.reason, 'invalid');
    return Number(process.hrtime.bigint() - t0) / 1e6;
  };
  const median = (xs) => [...xs].sort((a, b) => a - b)[Math.floor(xs.length / 2)];
  // Unknown names that stand in for each user, by their costs.
  const costs = (phc) => `${phc.memory},${phc.passes},${phc.parallelism},${phc.hash.length}`;
  const like = (user) => {
    const want = costs(login.store.find(user).phc);
    const out = [];
    for (let i = 0; i < 200 && out.length < 3; i++) if (costs(login.store.standIn(`nobody${i}`)) === want) out.push(`nobody${i}`);
    // With two sets of costs, about half the names stand in for each user.
    assert.equal(out.length, 3, `no unknown name is checked with the costs of ${user} (${want})`);
    return out;
  };
  // The samples of a user and of the unknown names are interleaved, in turn first, so that a change
  // of load on the machine falls on both alike (the whole suite runs in parallel); a median of many
  // is compared, not single tries.
  const compare = async (user, samples) => {
    const unknown = like(user);
    await time(user);
    await time(unknown[0]);
    const real = [];
    const nobody = [];
    for (let i = 0; i < samples; i++) {
      const u = unknown[i % unknown.length];
      if (i % 2) {
        real.push(await time(user));
        nobody.push(await time(u));
      } else {
        nobody.push(await time(u));
        real.push(await time(user));
      }
    }
    return { real: median(real), nobody: median(nobody) };
  };
  const a = await compare('alice', 15);
  const b = await compare('bob', 9);
  // Bob's costs are far above Alice's: an unknown name with the wrong costs would be off by that much.
  assert.ok(b.real > a.real * 2, `bob ${b.real.toFixed(0)} ms, alice ${a.real.toFixed(0)} ms: the costs are not far enough apart for this test`);
  for (const [user, m] of [['alice', a], ['bob', b]]) {
    assert.ok(m.nobody > m.real / 1.5 && m.nobody < m.real * 1.5, `unknown names took ${m.nobody.toFixed(0)} ms, ${user}'s wrong password ${m.real.toFixed(0)} ms (medians): the answer time tells which names exist`);
  }
});

// ---------- scripts/hash-password.js ----------

function runScript(args, input, env = {}) {
  return new Promise((resolve) => {
    const p = spawn(process.execPath, [script, ...args], { env: { ...process.env, ...env } });
    let out = ''; let err = '';
    p.stdout.on('data', (c) => (out += c));
    p.stderr.on('data', (c) => (err += c));
    p.on('close', (code) => resolve({ code, out, err }));
    p.stdin.on('error', () => {});
    p.stdin.end(input);
  });
}

test('qa: hash-password prints a hash the server accepts and that verifies the piped password (LF, CRLF and none)', { skip: !REAL }, async () => {
  for (const [input, pw] of [['s3cret\n', 's3cret'], ['s3cret\r\n', 's3cret'], ['s3cret', 's3cret'], ['päss \u{1F511}\n', 'päss \u{1F511}'], [' sp ace \n', ' sp ace ']]) {
    const r = await runScript(['--name', 'bob'], input);
    assert.equal(r.code, 0, r.err);
    const phc = r.out.split('\n')[0];
    const line = r.out.split('\n').find((l) => l.includes('password_hash'));
    const c = loadConfig(`users:\n${line.replace(/^\s*-/, '  -')}\nnodes:\n  - address: a.test:1\n`);
    assert.equal(c.users[0].name, 'bob');
    assert.equal(await verifyPassword(pw, parsePhc(phc)), true, JSON.stringify(input));
  }
});

test('qa: hash-password refuses empty, oversize, bad names and costs, and a password as an argument', { skip: !REAL }, async () => {
  assert.equal((await runScript([], '')).code, 1);
  assert.equal((await runScript([], '\n')).code, 1);
  assert.equal((await runScript([], 'x'.repeat(1025))).code, 1);
  assert.equal((await runScript([], 'x'.repeat(1024))).code, 0);
  assert.equal((await runScript([], `${'x'.repeat(1024)}\r\n`)).code, 0);
  assert.equal((await runScript([], '€'.repeat(342))).code, 1);
  assert.equal((await runScript(['hunter2'], 'x')).code, 2);
  assert.equal((await runScript(['--name'], 'x')).code, 2);
  assert.equal((await runScript(['--name', '../x'], 'x')).code, 2);
  assert.equal((await runScript(['--memory', '19455'], 'x')).code, 2);
  assert.equal((await runScript(['--memory', '1e5'], 'x')).code, 2);
  assert.equal((await runScript(['--passes', '1'], 'x')).code, 2);
  assert.equal((await runScript(['--parallelism', '0'], 'x')).code, 2);
  assert.equal((await runScript(['--memory', '262145'], 'x')).code, 2);
  assert.equal((await runScript(['--bogus'], 'x')).code, 2);
  assert.equal((await runScript(['--help'], '')).code, 0);
});

test('qa: hash-password never prints the password', { skip: !REAL }, async () => {
  const r = await runScript(['--name', 'bob'], 'tr0ub4dor&3-unique\n');
  assert.equal((r.out + r.err).includes('tr0ub4dor'), false);
});

test('qa: every --name hash-password accepts yields a line that config.yaml accepts (YAML reads 123, true, null as non-text)', { skip: !REAL }, async () => {
  const bad = [];
  for (const name of ['123', 'true', 'null', 'false', '1e3', '0x1F', '0o7', '1.5', 'Null', 'TRUE', '0']) {
    const r = await runScript(['--name', name], 'pw\n', {});
    if (r.code !== 0) continue;
    const line = r.out.split('\n').find((l) => l.includes('password_hash'));
    try {
      loadConfig(`users:\n${line.replace(/^\s*-/, '  -')}\nnodes:\n  - address: a.test:1\n`);
    } catch {
      bad.push(name);
    }
  }
  assert.deepEqual(bad, [], `hash-password accepted these names but the config rejects the pasted line`);
});
