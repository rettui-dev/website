// The manage API and page over HTTP: who may see and change what, the checks before a change,
// the budgets, the audit lines, and what a node's answers become. Most tests use a fake client
// (it records what was asked and answers what a test says); the end-to-end ones use the real
// signing client against the stub node in test/helpers/manage-node.js.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { Monitor } from '../lib/monitor.js';
import { loadConfig } from '../lib/config.js';
import { createApp } from '../lib/app.js';
import { createLogin } from '../lib/login.js';
import { hashPassword } from '../lib/password.js';
import { UserStore } from '../lib/users.js';
import { Keyring } from '../lib/keys.js';
import { createAudit, createFailureLog } from '../lib/audit.js';
import { RECENT_AUTH_MS } from '../lib/account.js';
import { MANAGE_READS_PER_NODE, MANAGE_WRITES_PER_USER, cleanAudit, cleanState, skewText } from '../lib/manage-api.js';
import { createManageClient } from '../lib/manage.js';
import { startManageNode } from './helpers/manage-node.js';
import { base32Decode, totp } from '../lib/totp.js';
import { fakeHasher } from './helpers/fake-hasher.js';

const publicDir = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'public');
const NOW = 1_800_000_000_000;
const ALICE = 'correct horse battery';
const BOB = 'bobs own password';
const VIC = 'victors long password';
const KEYS = new Keyring(new Map([[1, crypto.randomBytes(32)]]));
const HOST = 'a.test:1';
const SECRET = 'rettui-manage-test-secret-0123456789abcdef';
const REV = '0123456789abcdef0123456789abcdef';
const ID = '00112233aabbccdd';

const STATE = {
  v: 1,
  node_time: NOW / 1000,
  version: '2.5.0',
  settings_revision: REV,
  settings: [
    { key: 'pn_name', label: 'Propagation node name', help: 'Shown in lists.', kind: 'text', access: 'change', value: 'Hilltop' },
    { key: 'pn_enabled', label: 'Propagation node', help: 'Off only.', kind: 'toggle', access: 'turn_off_only', value: 'true' },
  ],
  network: { state: 'running', shared_instance: false, interfaces_total: 2, interfaces_online: 2 },
  restart: null,
  restart_allowed_at: null,
  pending: null,
};

// A client that records every call and answers with answer(...args) (a fixed state by default).
// A test swaps fake.answer to change what comes next.
function fakeClient(answer = () => ({ ok: true, status: 200, body: STATE })) {
  const fake = {
    calls: [],
    answer,
    call: async (...args) => {
      fake.calls.push(args);
      return fake.answer(...args);
    },
  };
  return fake;
}
// The client setup() gives the app when the test passes none.
let client;

// Alice is an admin in the config file; bob (manage) and victor (viewer) are website users.
// manage: what createApp gets; hasher: for a test that holds a password check.
async function setup({ manage, hasher = fakeHasher, wallClock } = {}) {
  const dataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'manage-'));
  const hash = await hashPassword(ALICE, undefined, fakeHasher);
  const config = loadConfig(`users:\n  - name: Alice\n    password_hash: '${hash}'\n    role: admin\nnodes:\n  - address: ${HOST}\n    name: Hilltop\n  - address: b.test:2\n`);
  const clock = { t: NOW };
  const now = () => clock.t;
  const logs = [];
  const store = await UserStore.open({ keys: KEYS, dataDir, configUsers: config.users, warn: () => {}, now, log: (m) => logs.push(m) });
  const pepper = store.currentPepper();
  await store.createUser({ name: 'bob', role: 'manage', passwordHash: await hashPassword(BOB, undefined, fakeHasher, pepper) });
  await store.createUser({ name: 'victor', role: 'viewer', passwordHash: await hashPassword(VIC, undefined, fakeHasher, pepper) });
  const audit = createAudit({ dataDir, now });
  const failures = createFailureLog({ dataDir, now });
  const login = createLogin({ users: config.users, store, settings: config.login, hasher, now, audit, failures, sleep: async () => {}, log: (m) => logs.push(m) });
  const monitor = new Monitor({ targets: config.targets, nodes: config.nodes, dataDir, probeFn: async () => ({ up: true, ms: 1 }) });
  const server = createApp({ monitor, publicDir, login, manage: manage === undefined ? { client, nodes: [HOST] } : manage, ...(wallClock ? { wallClock } : {}) });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const texts = [];
  return {
    port: server.address().port, clock, store, login, audit, dataDir, logs, texts,
    close: () => (server.closeAllConnections(), new Promise((r) => server.close(r))),
  };
}

function request(s, { method = 'GET', path: p, headers = {}, body }) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port: s.port, path: p, method, headers }, (res) => {
      let text = '';
      res.on('data', (c) => (text += c));
      res.on('end', () => {
        s.texts.push(text);
        resolve({ status: res.statusCode, headers: res.headers, text, json: () => JSON.parse(text) });
      });
    });
    req.on('error', reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}

const FORM = { 'Content-Type': 'application/x-www-form-urlencoded', 'Sec-Fetch-Site': 'same-origin', 'X-Rettui-Request': '1' };
const JSON_HEADERS = { 'Content-Type': 'application/json', 'Sec-Fetch-Site': 'same-origin', 'X-Rettui-Request': '1' };
const api = (s, p, body, cookie, headers = JSON_HEADERS) => request(s, { method: 'POST', path: p, headers: { ...headers, ...(cookie ? { Cookie: cookie } : {}) }, body: typeof body === 'string' ? body : JSON.stringify(body) });
const get = (s, p, cookie, method = 'GET') => request(s, { method, path: p, headers: cookie ? { Cookie: cookie } : {} });
const cookieOf = (r) => (r.headers['set-cookie']?.[0] ?? '').split(';')[0];

async function logIn(s, name, password) {
  const r = await request(s, { method: 'POST', path: '/login', headers: FORM, body: new URLSearchParams({ name, password }).toString() });
  return cookieOf(r);
}

// Turns on the app code for the signed-in user; gives code(), a fresh code each time (the clock
// moves on by 30 seconds after each, so none is used twice).
async function withTotp(s, cookie, password) {
  const sec = (await api(s, '/api/account/totp/setup', { password }, cookie)).json().secret;
  const key = base32Decode(sec);
  assert.equal((await api(s, '/api/account/totp/enable', { code: totp(key, s.clock.t) }, cookie)).status, 200);
  return () => {
    s.clock.t += 30_000;
    return totp(key, s.clock.t);
  };
}

const auditLines = async (s) => {
  await s.audit.flush();
  return (await fs.readFile(s.audit.file, 'utf8').catch(() => '')).trim().split('\n').filter(Boolean).map((l) => JSON.parse(l)).filter((l) => l.event.startsWith('manage-'));
};

const nodeGet = (s, cookie, host = HOST) => get(s, `/api/manage/node?host=${encodeURIComponent(host)}`, cookie);

test('only the manage and admin roles reach the manage page and its API', async () => {
  client = fakeClient();
  const s = await setup();
  try {
    assert.equal((await get(s, '/manage')).status, 404, 'signed out');
    assert.equal((await get(s, '/api/manage')).status, 401);
    assert.equal((await nodeGet(s)).status, 401);
    assert.equal((await api(s, '/api/manage/restart', { host: HOST })).status, 401);
    const v = await logIn(s, 'victor', VIC);
    assert.equal((await get(s, '/manage', v)).status, 404, 'a viewer');
    const denied = await get(s, '/api/manage', v);
    assert.equal(denied.status, 403);
    assert.doesNotMatch(denied.text, /Hilltop|a\.test/);
    assert.equal((await nodeGet(s, v)).status, 403);
    assert.equal((await get(s, `/api/manage/audit?host=${HOST}`, v)).status, 403);
    assert.equal((await api(s, '/api/manage/settings', { host: HOST, revision: REV, changes: { pn_name: 'x' }, password: VIC }, v)).status, 403);
    assert.equal(client.calls.length, 0, 'no node was asked for a viewer');
    assert.equal((await get(s, '/api/account', v)).json().role, 'viewer');
    for (const [name, pw] of [['bob', BOB], ['alice', ALICE]]) {
      const c = await logIn(s, name, pw);
      const page = await get(s, '/manage', c);
      assert.equal(page.status, 200, name);
      assert.equal(page.headers['cache-control'], 'private, no-store');
      assert.match(page.headers['content-security-policy'], /default-src 'none'; script-src 'self'; style-src 'self'/);
      assert.match(page.text, /<h1>Manage nodes<\/h1>/);
      assert.match(page.text, /<title>Manage - rettui<\/title>/);
      assert.equal((await get(s, '/api/manage', c)).status, 200, name);
    }
  } finally {
    await s.close();
  }
});

test('a user who must change a password an admin set gets neither the page nor the API', async () => {
  client = fakeClient();
  const s = await setup();
  try {
    const phc = await hashPassword('temporary password one', undefined, fakeHasher, s.store.currentPepper());
    await s.store.createUser({ name: 'newbie', role: 'manage', passwordHash: phc, mustChangePassword: true });
    const c = await logIn(s, 'newbie', 'temporary password one');
    assert.equal((await get(s, '/manage', c)).status, 404);
    const r = await get(s, '/api/manage', c);
    assert.equal(r.status, 403);
    assert.equal(r.json().mustChangePassword, true);
    assert.equal((await nodeGet(s, c)).status, 403);
    assert.equal(client.calls.length, 0);
  } finally {
    await s.close();
  }
});

test('every spelling of the manage page goes through its gate', async () => {
  client = fakeClient();
  const s = await setup();
  const spellings = ['/manage', '/manage/', '/manage.html', '/%6Danage.html', '/%6danage.html', '/manage.html/', '/manage%2ehtml', '/MANAGE.html', '/Manage.HTML', '/%4Danage.html', '/./manage.html', '/fonts/../manage.html'];
  try {
    const v = await logIn(s, 'victor', VIC);
    for (const p of spellings) {
      for (const [who, cookie] of [['signed out', undefined], ['viewer', v]]) {
        const r = await get(s, p, cookie);
        assert.equal(r.status, 404, `${p} ${who}`);
        assert.doesNotMatch(r.text, /manage-fields|Manage nodes/, `${p} ${who}`);
      }
      assert.equal((await get(s, p, v, 'HEAD')).status, 404, `HEAD ${p}`);
    }
    const b = await logIn(s, 'bob', BOB);
    const page = (await get(s, '/manage', b)).text;
    for (const p of spellings) {
      const r = await get(s, p, b);
      assert.equal(r.status, 200, p);
      assert.equal(r.text, page, p);
      assert.equal(r.headers['cache-control'], 'private, no-store', p);
    }
    // The script is a file, not a page.
    assert.equal((await get(s, '/manage-page.js')).status, 200);
  } finally {
    await s.close();
  }
  // Without users there is no manage page and no API, by any name.
  const dataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'manage-'));
  const monitor = new Monitor({ targets: [{ host: 'a.test', port: 1 }], dataDir, probeFn: async () => ({ up: true, ms: 1 }) });
  const server = createApp({ monitor, publicDir, manage: { client: fakeClient(), nodes: [HOST] } });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const bare = { port: server.address().port, texts: [] };
  try {
    for (const p of [...spellings, '/api/manage', `/api/manage/node?host=${HOST}`]) assert.equal((await get(bare, p)).status, 404, p);
    assert.equal((await api(bare, '/api/manage/settings', { host: HOST })).status, 405);
  } finally {
    server.closeAllConnections();
    await new Promise((r) => server.close(r));
  }
});

test('GET /api/manage says who, whether they can change things, and the nodes by name, never a secret', async () => {
  client = fakeClient();
  const s = await setup({ manage: { client: createManageClient({ nodes: new Map([[HOST, { url: 'http://127.0.0.1:9', secret: SECRET, confirmSeconds: 300 }]]) }), nodes: [HOST, 'b.test:2'] } });
  try {
    const b = await logIn(s, 'bob', BOB);
    const r = await get(s, '/api/manage', b);
    assert.equal(r.status, 200);
    const body = r.json();
    assert.equal(body.me, 'bob');
    assert.equal(body.roleOk, true);
    assert.equal(body.secondFactor, false);
    assert.equal(body.recentSignIn, true);
    assert.equal(typeof body.recentUntil, 'string');
    assert.deepEqual(body.nodes, [{ host: HOST, name: 'Hilltop' }, { host: 'b.test:2', name: 'b.test:2' }]);
    assert.ok(Array.isArray(body.stepUpMethods));
    assert.equal(r.text.includes(SECRET), false);
    assert.doesNotMatch(r.text, /secret|127\.0\.0\.1:9/);
    // No nodes to manage: the page is there and says so; the API lists none.
    const none = await setup({ manage: null });
    try {
      const c = await logIn(none, 'bob', BOB);
      assert.deepEqual((await get(none, '/api/manage', c)).json().nodes, []);
      assert.equal((await get(none, '/manage', c)).status, 200);
      const missing = await nodeGet(none, c);
      assert.equal(missing.status, 404);
    } finally {
      await none.close();
    }
  } finally {
    await s.close();
  }
});

test('reading a node: the state is cleaned, the clock is compared, and an unknown node or HEAD asks nothing', async () => {
  const messy = {
    ...STATE,
    version: '2.5.0‮<script>',
    settings_revision: 'not hex',
    node_time: NOW / 1000 + 150,
    settings: [
      ...STATE.settings,
      { key: 'Bad Key', label: 'x', kind: 'text', access: 'change', value: 'x' },
      { key: 'hub_name', label: '<img src=x onerror=alert(1)>', help: 'h'.repeat(900), kind: 'weird', access: 'change', value: 7 },
      { key: 'log_level', label: 'Log', kind: 'choice', choices: ['info', 'debug', 5], access: 'change', value: 'info' },
      { key: 'pn_name', label: 'twice', kind: 'text', access: 'change', value: 'second' },
      { key: 'x_y', label: 'no access', kind: 'text', access: 'admin', value: '' },
    ],
    network: { state: 'exploded', interfaces_total: -1, interfaces_online: 'two' },
    restart: { id: 'abcdefabcdefabcd', state: 'up', started: 5, problems: ['eth0 offline', 3] },
    extra: 'dropped',
  };
  client = fakeClient(() => ({ ok: true, status: 200, body: messy, skewSeconds: 150 }));
  const s = await setup();
  try {
    const b = await logIn(s, 'bob', BOB);
    const r = await nodeGet(s, b);
    assert.equal(r.status, 200);
    const body = r.json();
    assert.equal(body.host, HOST);
    assert.equal(body.name, 'Hilltop');
    assert.equal(body.version, '2.5.0<script>', 'direction characters are taken out; the page sets it as text');
    assert.equal(body.settings_revision, '');
    assert.deepEqual(body.settings.map((x) => x.key), ['pn_name', 'pn_enabled', 'hub_name', 'log_level']);
    assert.equal(body.settings[0].value, 'Hilltop', 'the first of a key shown twice');
    assert.equal(body.settings[2].kind, 'text');
    assert.equal(body.settings[2].value, '7');
    assert.equal(body.settings[2].help.length, 500);
    assert.deepEqual(body.settings[3].choices, ['info', 'debug']);
    assert.deepEqual(body.network, { state: 'unknown', shared_instance: false, interfaces_total: null, interfaces_online: null });
    assert.deepEqual(body.restart, { id: 'abcdefabcdefabcd', state: 'up', started: 5, problems: ['eth0 offline'] });
    assert.equal('extra' in body, false);
    assert.equal(body.skewSeconds, 150);
    assert.deepEqual(body.clock, { skewMinutes: 3, warning: skewText(3) });
    assert.equal(skewText(3), "This node's clock is 3 minutes off from the website's, so signed requests can't be trusted; fix the node's time.");
    assert.deepEqual(client.calls[0], [HOST, 'GET', '/manage/v1/state', 'bob', undefined]);
    // In step: no warning.
    client.answer = () => ({ ok: true, status: 200, body: STATE, skewSeconds: 10 });
    const fine = (await nodeGet(s, b)).json();
    assert.equal(fine.skewSeconds, 10);
    assert.equal(fine.clock, undefined);
    const calls = client.calls.length;
    assert.equal((await nodeGet(s, b, 'c.test:3')).status, 404);
    assert.equal((await nodeGet(s, b, '')).status, 404);
    assert.equal((await get(s, `/api/manage/node?host=${HOST}`, b, 'HEAD')).status, 200);
    assert.equal(client.calls.length, calls, 'no node was asked');
    // Names are matched without regard to case.
    assert.equal((await nodeGet(s, b, 'A.TEST:1')).status, 200);
  } finally {
    await s.close();
  }
});

test('the audit list: before and limit are checked and passed on, and the entries are cleaned', async () => {
  client = fakeClient(() => ({
    ok: true,
    status: 200,
    body: {
      entries: [
        { seq: 7, time: 100, id: ID, actor: 'bob​', op: 'settings', changes: [{ key: 'pn_name', from: 'a', to: 'b' }, { key: 'BAD', from: 1, to: 2 }], result: 'ok', error: null },
        { seq: 6, time: 90, id: 'nothex', actor: 'x'.repeat(80), op: 'evil', changes: 'no', result: 'what', error: 'e'.repeat(500) },
        { seq: 'x' },
      ],
      more: true,
    },
  }));
  const s = await setup();
  try {
    const b = await logIn(s, 'bob', BOB);
    const r = await get(s, `/api/manage/audit?host=${HOST}`, b);
    assert.equal(r.status, 200);
    const body = r.json();
    assert.equal(body.more, true);
    assert.equal(body.entries.length, 2);
    assert.deepEqual(body.entries[0], { seq: 7, time: 100, id: ID, actor: 'bob', op: 'settings', changes: [{ key: 'pn_name', from: 'a', to: 'b' }], result: 'ok', error: null });
    assert.equal(body.entries[1].id, null);
    assert.equal(body.entries[1].actor.length, 32);
    assert.equal(body.entries[1].op, 'other');
    assert.deepEqual(body.entries[1].changes, []);
    assert.equal(body.entries[1].result, 'other');
    assert.equal(body.entries[1].error.length, 300);
    assert.equal(client.calls[0][2], '/manage/v1/audit?limit=50');
    await get(s, `/api/manage/audit?host=${HOST}&before=7&limit=20`, b);
    assert.equal(client.calls[1][2], '/manage/v1/audit?before=7&limit=20');
    for (const q of ['before=-1', 'before=x', 'limit=0', 'limit=101', 'limit=1e2', 'before=1234567890123456']) {
      assert.equal((await get(s, `/api/manage/audit?host=${HOST}&${q}`, b)).status, 400, q);
    }
    assert.equal(client.calls.length, 2);
    assert.deepEqual(cleanAudit(null), { entries: [], more: false });
    assert.equal(cleanState('nope').settings.length, 0);
  } finally {
    await s.close();
  }
});

test('reads are limited per user and node', async () => {
  client = fakeClient();
  const s = await setup();
  try {
    const b = await logIn(s, 'bob', BOB);
    for (let i = 0; i < MANAGE_READS_PER_NODE; i++) assert.equal((await nodeGet(s, b)).status, 200, `read ${i + 1}`);
    const over = await nodeGet(s, b);
    assert.equal(over.status, 429);
    assert.ok(Number(over.headers['retry-after']) > 0);
    assert.equal((await get(s, `/api/manage/audit?host=${HOST}`, b)).status, 429, 'the audit list counts too');
    assert.equal(client.calls.length, MANAGE_READS_PER_NODE);
    // Another user, and an hour later, may read again.
    const a = await logIn(s, 'alice', ALICE);
    assert.equal((await nodeGet(s, a)).status, 200);
    s.clock.t += 60 * 60_000;
    const b2 = await logIn(s, 'bob', BOB);
    assert.equal((await nodeGet(s, b2)).status, 200);
  } finally {
    await s.close();
  }
});

test('a user without two-step sign-in can look but not change anything', async () => {
  client = fakeClient();
  const s = await setup();
  try {
    const b = await logIn(s, 'bob', BOB);
    assert.equal((await nodeGet(s, b)).status, 200);
    for (const [p, body] of [['/api/manage/settings', { host: HOST, revision: REV, changes: { pn_name: 'x' } }], ['/api/manage/restart', { host: HOST }], ['/api/manage/rollback', { host: HOST, id: ID }]]) {
      const r = await api(s, p, { ...body, password: BOB }, b);
      assert.equal(r.status, 403, p);
      assert.equal(r.json().code, 'second-factor-required', p);
    }
    assert.equal(client.calls.length, 1, 'only the read');
    assert.deepEqual(await auditLines(s), []);
  } finally {
    await s.close();
  }
});

test('changes only come from the page itself, as JSON with the header, after a recent sign in', async () => {
  client = fakeClient();
  const s = await setup();
  try {
    const b = await logIn(s, 'bob', BOB);
    const code = await withTotp(s, b, BOB);
    const p = '/api/manage/settings';
    const body = { host: HOST, revision: REV, changes: { pn_name: 'x' }, password: BOB, code: code() };
    assert.equal((await api(s, p, body, b, { 'Content-Type': 'application/json', 'Sec-Fetch-Site': 'same-origin' })).status, 403, 'no header');
    assert.equal((await api(s, p, body, b, { 'Content-Type': 'application/json', 'Sec-Fetch-Site': 'cross-site', 'X-Rettui-Request': '1' })).status, 403, 'another site');
    assert.equal((await api(s, p, new URLSearchParams({ host: HOST }).toString(), b, FORM)).status, 415);
    assert.equal((await api(s, p, JSON.stringify({ ...body, pad: 'x'.repeat(17_000) }), b)).status, 413);
    assert.equal((await api(s, p, '[1]', b)).status, 400);
    assert.equal((await api(s, '/api/manage/other', body, b)).status, 405, 'not a change');
    s.clock.t += RECENT_AUTH_MS;
    const stale = await api(s, p, { ...body, code: code() }, b);
    assert.equal(stale.status, 403);
    assert.equal(stale.json().reauth, true);
    assert.equal(client.calls.length, 0);
  } finally {
    await s.close();
  }
});

test('a settings change: checked, confirmed with both factors, sent as the user, and written to audit.log without values', async () => {
  client = fakeClient((host, method, target) => {
    if (target === '/manage/v1/settings') return { ok: true, status: 200, body: { id: ID, applied: [{ key: 'pn_name', from: 'Hilltop', to: 'Valley secret value' }], notes: ['Announced again.'], settings_revision: REV.replace('0', 'f') } };
    return { ok: true, status: 200, body: STATE };
  });
  const s = await setup();
  try {
    const b = await logIn(s, 'BOB', BOB);
    const code = await withTotp(s, b, BOB);
    const p = '/api/manage/settings';
    const base = { host: HOST, revision: REV, changes: { pn_name: 'Valley secret value' } };
    // Wrong before any password is asked: nothing is counted or asked of the node.
    const bad = [
      [{ ...base, host: 'c.test:3' }, 404],
      [{ ...base, revision: 'abc' }, 400],
      [{ ...base, changes: [] }, 400],
      [{ ...base, changes: {} }, 400],
      [{ ...base, changes: Object.fromEntries(Array.from({ length: 33 }, (_, i) => [`k${i}`, 'v'])) }, 400],
      [{ ...base, changes: { 'Not A Key': 'v' } }, 400],
      [{ ...base, changes: { pn_name: 5 } }, 400],
      [{ ...base, changes: { pn_name: 'é'.repeat(2049) } }, 400],
    ];
    for (const [body, status] of bad) assert.equal((await api(s, p, { ...body, password: BOB, code: code() }, b)).status, status, JSON.stringify(body).slice(0, 80));
    const pwOnly = await api(s, p, { ...base, password: BOB }, b);
    assert.equal(pwOnly.status, 400);
    assert.equal(pwOnly.json().field, 'code');
    assert.equal((await api(s, p, { ...base, password: 'wrong one', code: code() }, b)).status, 400);
    assert.equal(client.calls.length, 0);
    const ok = await api(s, p, { ...base, password: BOB, code: code() }, b);
    assert.equal(ok.status, 200, ok.text);
    assert.deepEqual(ok.json(), { ok: true, id: ID, applied: [{ key: 'pn_name', from: 'Hilltop', to: 'Valley secret value' }], notes: ['Announced again.'], settingsRevision: REV.replace('0', 'f') });
    assert.deepEqual(client.calls, [[HOST, 'POST', '/manage/v1/settings', 'bob', { revision: REV, changes: { pn_name: 'Valley secret value' } }]], 'the stored name is the actor');
    const lines = await auditLines(s);
    assert.equal(lines.length, 1);
    assert.equal(lines[0].event, 'manage-settings');
    assert.equal(lines[0].actor, 'bob');
    assert.equal(lines[0].host, HOST);
    assert.deepEqual(lines[0].keys, ['pn_name']);
    assert.equal(lines[0].id, ID);
    assert.equal(lines[0].result, 'ok');
    assert.equal(lines[0].with, 'password+code');
    assert.equal(typeof lines[0].address, 'string');
    assert.doesNotMatch(JSON.stringify(lines), /Valley|Hilltop|secret value/);
  } finally {
    await s.close();
  }
});

test("what a node refuses becomes a fixed sentence; only invalid_value and not_allowed pass the node's words on", async () => {
  client = fakeClient();
  const s = await setup();
  try {
    const b = await logIn(s, 'bob', BOB);
    const code = await withTotp(s, b, BOB);
    const send = () => api(s, '/api/manage/settings', { host: HOST, revision: REV, changes: { pn_name: 'x' }, password: BOB, code: code() }, b);
    const cases = [
      [{ ok: true, status: 409, body: { error: 'stale_revision', message: 'NODE WORDS', settings_revision: REV } }, 409, /changed elsewhere/, { code: 'stale_revision', settingsRevision: REV }],
      [{ ok: true, status: 400, body: { error: 'invalid_value', message: `Too long‮ ${'y'.repeat(400)}`, key: 'pn_name' } }, 400, /^Too long y+$/, { code: 'invalid_value', key: 'pn_name' }],
      [{ ok: true, status: 403, body: { error: 'not_allowed', message: 'Only the terminal turns a service on.', key: 'pn_enabled' } }, 403, /^Only the terminal turns a service on\.$/, { code: 'not_allowed', key: 'pn_enabled' }],
      [{ ok: true, status: 403, body: { error: 'not_allowed' } }, 403, /does not allow this change/, { code: 'not_allowed' }],
      [{ ok: true, status: 400, body: { error: 'no_change', message: 'NODE WORDS' } }, 400, /Nothing was changed/, { code: 'no_change' }],
      [{ ok: true, status: 409, body: { error: 'busy', message: 'NODE WORDS' } }, 409, /busy/, { code: 'busy' }],
      [{ ok: true, status: 429, body: { error: 'rate_limited', retry_after: 42, message: 'NODE WORDS' } }, 429, /limiting changes.*42 seconds/, { code: 'rate_limited', retryAfter: 42 }],
      [{ ok: true, status: 504, body: { error: 'timeout', message: 'NODE WORDS' } }, 504, /did not finish in time/, { code: 'timeout' }],
      [{ ok: true, status: 418, body: { error: 'teapot', message: 'NODE WORDS' } }, 502, /answered with an error/, { code: 'node-error' }],
      [{ ok: true, status: 500, body: {} }, 502, /answered with an error/, { code: 'node-error' }],
      [{ ok: false, error: 'timeout' }, 504, /did not answer in time/, { code: 'timeout' }],
      [{ ok: false, error: 'network' }, 502, /could not be reached/, { code: 'network' }],
      [{ ok: false, error: 'unsigned' }, 502, /^The node did not answer with a valid signature: check the secret file on both sides\.$/, { code: 'unsigned' }],
      [{ ok: false, error: 'too-large' }, 502, /too large/, { code: 'too-large' }],
      [{ ok: false, error: 'invalid' }, 502, /could not be read/, { code: 'invalid' }],
      [{ ok: false, error: 'toString' }, 502, /could not be reached/, { code: 'network' }],
      [{ ok: false, error: 'clock', nodeTime: 1, skewSeconds: -3600 }, 502, /^This node's clock is 60 minutes off from the website's, so signed requests can't be trusted; fix the node's time\.$/, { code: 'clock', clock: { skewMinutes: 60 } }],
    ];
    for (const [answer, status, words, extra] of cases) {
      client.answer = () => answer;
      const r = await send();
      assert.equal(r.status, status, JSON.stringify(answer));
      const body = r.json();
      assert.match(body.error, words, JSON.stringify(answer));
      for (const [k, v] of Object.entries(extra)) assert.deepEqual(body[k], v, `${k} of ${JSON.stringify(answer)}`);
      assert.doesNotMatch(r.text, /NODE WORDS/);
      if (status === 429) assert.equal(r.headers['retry-after'], '42');
    }
    const lines = await auditLines(s);
    assert.equal(lines.length, cases.length, 'every change asked of a node is a line');
    assert.deepEqual(lines.map((l) => l.result).slice(0, 3), ['stale_revision', 'invalid_value', 'not_allowed']);
    assert.ok(lines.every((l) => l.id === null && l.keys[0] === 'pn_name'));
    // A client that throws is a node that cannot be reached, and the log says only which node.
    client.answer = () => {
      throw new Error(`boom ${SECRET}`);
    };
    const thrown = await send();
    assert.equal(thrown.status, 502);
    assert.ok(s.texts.every((t) => !t.includes(SECRET)));
  } finally {
    await s.close();
  }
});

test('changes are limited per user, wrong passwords included; a busy node gives the try back', async () => {
  client = fakeClient(() => ({ ok: true, status: 503, body: { error: 'queue_full' } }));
  const s = await setup();
  try {
    const b = await logIn(s, 'bob', BOB);
    const code = await withTotp(s, b, BOB);
    const p = '/api/manage/restart';
    // A busy node: 503, and the try does not count.
    for (let i = 0; i < 3; i++) assert.equal((await api(s, p, { host: HOST, password: BOB, code: code() }, b)).status, 503);
    let throttled = 0;
    for (let i = 0; i < MANAGE_WRITES_PER_USER; i++) {
      const r = await api(s, p, { host: HOST, password: 'wrong one' }, b);
      assert.ok(r.status === 400 || r.status === 429, String(r.status));
      if (r.status === 429) throttled++;
      assert.doesNotMatch(r.text, /too many changes/);
    }
    const over = await api(s, p, { host: HOST, password: BOB, code: code() }, b);
    assert.equal(over.status, 429);
    assert.match(over.json().error, /You made too many changes/);
    assert.ok(Number(over.headers['retry-after']) > 0);
    assert.equal(client.calls.length, 3);
    assert.ok(throttled < MANAGE_WRITES_PER_USER);
  } finally {
    await s.close();
  }
});

test('a user who loses the role or the session while the password is checked changes nothing', async () => {
  client = fakeClient();
  const waiters = [];
  let hold = false;
  const hasher = async (p) => {
    if (hold) await new Promise((r) => waiters.push(r));
    return fakeHasher(p);
  };
  const s = await setup({ hasher });
  try {
    const b = await logIn(s, 'bob', BOB);
    const code = await withTotp(s, b, BOB);
    hold = true;
    const pending = api(s, '/api/manage/restart', { host: HOST, password: BOB, code: code() }, b);
    for (let i = 0; i < 200 && waiters.length === 0; i++) await new Promise((r) => setTimeout(r, 5));
    assert.equal(waiters.length, 1);
    await s.store.setRole('bob', 'viewer');
    hold = false;
    waiters.splice(0).forEach((r) => r());
    const r = await pending;
    assert.equal(r.status, 401);
    assert.equal(client.calls.length, 0);
    assert.deepEqual(await auditLines(s), []);
  } finally {
    await s.close();
  }
});

test('end to end with the stub node: read, save, stale revision, roll back, restart and the audit list', async () => {
  const node = await startManageNode({ secret: SECRET });
  const real = createManageClient({ nodes: new Map([[HOST, { url: node.url, secret: SECRET, confirmSeconds: 300 }]]) });
  const s = await setup({ manage: { client: real, nodes: [HOST] } });
  try {
    const b = await logIn(s, 'bob', BOB);
    const code = await withTotp(s, b, BOB);
    const state = (await nodeGet(s, b)).json();
    assert.equal(state.version, '2.5.0');
    assert.match(state.settings_revision, /^[0-9a-f]{32}$/);
    assert.ok(Math.abs(state.skewSeconds) < 5);
    assert.equal(state.clock, undefined);
    assert.deepEqual(state.settings.map((x) => [x.key, x.access, x.value]), [['display_name', 'change', 'Stub'], ['pn_name', 'change', 'Hilltop'], ['log_level', 'change', 'info'], ['pn_enabled', 'turn_off_only', 'true']]);
    const save = await api(s, '/api/manage/settings', { host: HOST, revision: state.settings_revision, changes: { pn_name: 'Valley' }, password: BOB, code: code() }, b);
    assert.equal(save.status, 200, save.text);
    assert.equal(node.settings.pn_name, 'Valley');
    const last = node.requests.at(-1);
    assert.equal(last.actor, 'bob');
    assert.equal(last.signed, true);
    assert.equal(last.path, '/manage/v1/settings');
    // The old revision is stale now.
    const stale = await api(s, '/api/manage/settings', { host: HOST, revision: state.settings_revision, changes: { pn_name: 'Again' }, password: BOB, code: code() }, b);
    assert.equal(stale.status, 409);
    assert.equal(stale.json().code, 'stale_revision');
    // Turning a service on is refused by the node, with its words.
    const fresh = (await nodeGet(s, b)).json();
    const on = await api(s, '/api/manage/settings', { host: HOST, revision: fresh.settings_revision, changes: { pn_enabled: 'true' }, password: BOB, code: code() }, b);
    assert.equal(on.status, 403);
    assert.equal(on.json().error, 'That can only be turned off remotely.');
    const off = await api(s, '/api/manage/settings', { host: HOST, revision: fresh.settings_revision, changes: { pn_enabled: 'false' }, password: BOB, code: code() }, b);
    assert.equal(off.status, 200);
    assert.equal(node.settings.pn_enabled, 'false');
    // Rolling back the name change.
    const back = await api(s, '/api/manage/rollback', { host: HOST, id: save.json().id, password: BOB, code: code() }, b);
    assert.equal(back.status, 200, back.text);
    assert.deepEqual(back.json().applied, [{ key: 'pn_name', from: 'Valley', to: 'Hilltop' }]);
    assert.equal(node.settings.pn_name, 'Hilltop');
    const unknown = await api(s, '/api/manage/rollback', { host: HOST, id: 'ffffffffffffffff', password: BOB, code: code() }, b);
    assert.equal(unknown.status, 404);
    const restart = await api(s, '/api/manage/restart', { host: HOST, password: BOB, code: code() }, b);
    assert.equal(restart.status, 202);
    assert.equal(restart.json().state, 'restarting');
    assert.equal((await nodeGet(s, b)).json().restart.id, restart.json().id);
    const again = await api(s, '/api/manage/restart', { host: HOST, password: BOB, code: code() }, b);
    assert.equal(again.status, 409);
    assert.equal(again.json().code, 'restarting');
    const list = (await get(s, `/api/manage/audit?host=${HOST}&limit=2`, b)).json();
    assert.deepEqual(list.entries.map((e) => e.op), ['restart', 'rollback']);
    assert.equal(list.more, true);
    const older = (await get(s, `/api/manage/audit?host=${HOST}&before=${list.entries[1].seq}`, b)).json();
    assert.deepEqual(older.entries.map((e) => e.op), ['settings', 'settings']);
    assert.equal(older.more, false);
    const lines = await auditLines(s);
    assert.deepEqual(lines.map((l) => [l.event, l.result]), [['manage-settings', 'ok'], ['manage-settings', 'stale_revision'], ['manage-settings', 'not_allowed'], ['manage-settings', 'ok'], ['manage-rollback', 'ok'], ['manage-rollback', 'unknown_change'], ['manage-restart', 'ok'], ['manage-restart', 'restarting']]);
    assert.equal(lines[4].of, save.json().id);
    assert.deepEqual(lines[4].keys, ['pn_name']);
    assert.doesNotMatch(JSON.stringify(lines), /Valley|Hilltop/);
    assert.ok(s.texts.every((t) => !t.includes(SECRET)), 'the secret is in no answer');
  } finally {
    await s.close();
    await node.close();
  }
});

test('end to end with a misbehaving node: each failure is a fixed sentence and nothing is recorded as done', async () => {
  const node = await startManageNode({ secret: SECRET, slowMs: 400 });
  const real = createManageClient({ nodes: new Map([[HOST, { url: node.url, secret: SECRET, confirmSeconds: 300 }]]), timeoutMs: 200 });
  const s = await setup({ manage: { client: real, nodes: [HOST] } });
  try {
    const b = await logIn(s, 'bob', BOB);
    const code = await withTotp(s, b, BOB);
    const cases = [
      ['wrong-signature', 502, /valid signature/],
      ['unsigned', 502, /valid signature/],
      ['clock_skew', 502, /^This node's clock is 60 minutes off from the website's/],
      ['slow', 504, /did not answer in time/],
      ['oversize', 502, /too large/],
      ['redirect', 502, /could not be reached|could not be read/],
      ['bad-json', 502, /could not be read/],
      ['array', 502, /could not be read/],
    ];
    for (const [mode, status, words] of cases) {
      node.misbehave = mode;
      const r = await nodeGet(s, b);
      assert.equal(r.status, status, mode);
      assert.match(r.json().error, words, mode);
      if (mode === 'clock_skew') assert.deepEqual(r.json().clock, { skewMinutes: 60 });
      const w = await api(s, '/api/manage/restart', { host: HOST, password: BOB, code: code() }, b);
      assert.equal(w.status, status, `write ${mode}`);
    }
    node.misbehave = 'control-chars';
    const cleaned = await nodeGet(s, b);
    assert.equal(cleaned.status, 200);
    assert.doesNotMatch(cleaned.text, /\\u202e|\\u0000|\\u200b/);
    assert.equal(cleaned.json().version, '2.5.0');
    const lines = await auditLines(s);
    assert.equal(lines.length, cases.length);
    assert.ok(lines.every((l) => l.result !== 'ok' && l.id === null));
    assert.ok(s.texts.every((t) => !t.includes(SECRET)));
  } finally {
    await s.close();
    await node.close();
  }
});
