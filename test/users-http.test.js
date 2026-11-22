import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Monitor } from '../lib/monitor.js';
import { loadConfig } from '../lib/config.js';
import { createApp } from '../lib/app.js';
import { createLogin } from '../lib/login.js';
import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { hashPassword } from '../lib/password.js';
import { UserStore } from '../lib/users.js';
import { DB_FILE } from '../lib/userdb.js';
import { Keyring } from '../lib/keys.js';
import { createAudit, createFailureLog } from '../lib/audit.js';
import { RECENT_AUTH_MS } from '../lib/account.js';
import { ADMIN_DELETE_REFUSED, ADMIN_DEMOTE_REFUSED, ADMIN_RESET_REFUSED, USER_CHANGES_PER_ADMIN, newOneTimePassword } from '../lib/admin.js';
import { base32Decode, totp } from '../lib/totp.js';
import { fakeHasher } from './helpers/fake-hasher.js';

const publicDir = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'public');
const NOW = 1_800_000_000_000;
const ALICE = 'correct horse battery';
const BOB = 'bobs own password';
const CAROL = 'carols long password';
const DAVE = 'daves long password';
// The user store needs a key once it has users.
const KEYS = new Keyring(new Map([[1, crypto.randomBytes(32)]]));

// A user's row of the store on disk, read as another program would, or null.
function row(dataDir, name) {
  const sql = new DatabaseSync(path.join(dataDir, DB_FILE), { readOnly: true });
  try {
    return sql.prepare("SELECT * FROM users WHERE kind = 'store' AND name_key = ?").get(name.toLowerCase()) ?? null;
  } finally {
    sql.close();
  }
}
// The bytes of the store on disk, the WAL included (where the last changes are until a checkpoint).
const diskBytes = async (dataDir) => Buffer.concat(await Promise.all([DB_FILE, `${DB_FILE}-wal`].map((f) => fs.readFile(path.join(dataDir, f)).catch(() => Buffer.alloc(0)))));

// Holds the store's write lock from another connection, as scripts/users.js would mid-change,
// until the returned function is called.
function holdLock(dataDir) {
  const other = new DatabaseSync(path.join(dataDir, DB_FILE));
  other.exec('BEGIN IMMEDIATE');
  return () => {
    other.exec('ROLLBACK');
    other.close();
  };
}

// Alice is in the config file (admin unless aliceRole says otherwise); bob (manage) and, with
// carol, carol (admin) are website users. timeoutMs: how long a write waits for another program
// that holds the store.
async function setup({ aliceRole = 'admin', carol = false, hasher = fakeHasher, timeoutMs } = {}) {
  const dataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'users-'));
  const hash = await hashPassword(ALICE, undefined, fakeHasher);
  const config = loadConfig(`users:\n  - name: Alice\n    password_hash: '${hash}'\n    role: ${aliceRole}\nnodes:\n  - address: a.test:1\n`);
  const clock = { t: NOW };
  const now = () => clock.t;
  const logs = [];
  const store = await UserStore.open({ keys: KEYS, dataDir, configUsers: config.users, warn: () => {}, now, log: (m) => logs.push(m), ...(timeoutMs ? { timeoutMs } : {}) });
  // Peppered as the website makes them, so that no sign in here moves them to the current key.
  const pepper = store.currentPepper();
  await store.createUser({ name: 'bob', role: 'manage', passwordHash: await hashPassword(BOB, undefined, fakeHasher, pepper) });
  if (carol) await store.createUser({ name: 'carol', role: 'admin', passwordHash: await hashPassword(CAROL, undefined, fakeHasher, pepper) });
  const audit = createAudit({ dataDir, now });
  const failures = createFailureLog({ dataDir, now });
  const login = createLogin({ users: config.users, store, settings: config.login, hasher, now, audit, failures, sleep: async () => {}, log: (m) => logs.push(m) });
  const monitor = new Monitor({ targets: config.targets, dataDir, probeFn: async () => ({ up: true, ms: 1 }) });
  const server = createApp({ monitor, publicDir, login });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return {
    port: server.address().port, clock, store, login, audit, dataDir, logs,
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

const FORM = { 'Content-Type': 'application/x-www-form-urlencoded', 'Sec-Fetch-Site': 'same-origin', 'X-Rettui-Request': '1' };
const JSON_HEADERS = { 'Content-Type': 'application/json', 'Sec-Fetch-Site': 'same-origin', 'X-Rettui-Request': '1' };
const api = (s, p, body, cookie, headers = JSON_HEADERS) => request(s.port, { method: 'POST', path: p, headers: { ...headers, ...(cookie ? { Cookie: cookie } : {}) }, body: typeof body === 'string' ? body : JSON.stringify(body) });
const get = (s, p, cookie) => request(s.port, { path: p, headers: cookie ? { Cookie: cookie } : {} });
const cookieOf = (r) => (r.headers['set-cookie']?.[0] ?? '').split(';')[0];

async function logIn(s, name, password) {
  const r = await request(s.port, { method: 'POST', path: '/login', headers: FORM, body: new URLSearchParams({ name, password }).toString() });
  return { r, cookie: cookieOf(r) };
}
const alive = (s, cookie) => get(s, '/api/session', cookie).then((r) => r.json().name);
const auditLines = async (s) => {
  await s.audit.flush();
  return (await fs.readFile(s.audit.file, 'utf8').catch(() => '')).trim().split('\n').filter(Boolean).map((l) => JSON.parse(l)).filter((l) => l.event !== 'device-added');
};

function holdable() {
  const waiters = [];
  let on = false;
  return {
    hasher: async (p) => {
      if (on) await new Promise((r) => waiters.push(r));
      return fakeHasher(p);
    },
    hold: () => (on = true),
    let: () => {
      on = false;
      for (const r of waiters.splice(0)) r();
    },
    waiting: () => waiters.length,
  };
}
const until = async (cond) => {
  for (let i = 0; i < 200 && !cond(); i++) await new Promise((r) => setTimeout(r, 5));
  assert.ok(cond());
};

test('only admins reach the users page and its API; nobody else sees the link', async () => {
  const s = await setup();
  try {
    assert.equal((await get(s, '/users')).status, 404, 'signed out');
    assert.equal((await get(s, '/api/users')).status, 401);
    const b = await logIn(s, 'bob', BOB);
    assert.equal((await get(s, '/users', b.cookie)).status, 404, 'not an admin');
    const list = await get(s, '/api/users', b.cookie);
    assert.equal(list.status, 403);
    assert.equal(list.text.includes('alice'), false);
    assert.equal((await get(s, '/api/account', b.cookie)).json().canManageUsers, false);
    const create = await api(s, '/api/users/create', { name: 'eve', role: 'admin', generate: true, password: BOB }, b.cookie);
    assert.equal(create.status, 403);
    assert.equal(s.store.lookup('eve'), null);
    const a = await logIn(s, 'alice', ALICE);
    assert.equal((await get(s, '/api/account', a.cookie)).json().canManageUsers, true);
    const page = await get(s, '/users', a.cookie);
    assert.equal(page.status, 200);
    assert.match(page.headers['content-security-policy'], /script-src 'self'/);
    assert.equal(page.headers['cache-control'], 'private, no-store');
    assert.match(page.text, /<h1>Users<\/h1>/);
    assert.match(page.text, /<title>Users - rettui<\/title>/);
  } finally {
    await s.close();
  }
});

test('with no admin anywhere the users page does not exist, for anyone', async () => {
  const s = await setup({ aliceRole: 'viewer' });
  try {
    const a = await logIn(s, 'alice', ALICE);
    assert.equal((await get(s, '/users', a.cookie)).status, 404);
    assert.equal((await get(s, '/api/users', a.cookie)).status, 404);
    assert.equal((await api(s, '/api/users/create', { name: 'x1', role: 'admin', generate: true, password: ALICE }, a.cookie)).status, 404);
    assert.equal(s.store.lookup('x1'), null);
  } finally {
    await s.close();
  }
});

test('the list has every user with role, source, second factor, devices and times, and no secret', async () => {
  const s = await setup({ carol: true });
  try {
    const a = await logIn(s, 'alice', ALICE);
    const r = await get(s, '/api/users', a.cookie);
    assert.equal(r.status, 200);
    const body = r.json();
    assert.equal(body.me, 'Alice');
    assert.deepEqual(body.roles, ['admin', 'manage', 'viewer']);
    assert.deepEqual(body.users.map((u) => [u.name, u.role, u.source]), [['Alice', 'admin', 'config'], ['bob', 'manage', 'store'], ['carol', 'admin', 'store']]);
    const alice = body.users[0];
    assert.equal(alice.devices, 1, 'this sign in');
    assert.equal(alice.secondFactor, false);
    assert.equal(typeof alice.lastLogin, 'string');
    assert.equal(body.users[1].created, new Date(NOW).toISOString());
    assert.equal(body.users[1].mustChangePassword, false);
    assert.doesNotMatch(r.text, /argon2|passwordHash|secret|hash/i);
  } finally {
    await s.close();
  }
});

test('changes only come from the page itself, as JSON with the header', async () => {
  const s = await setup();
  try {
    const a = await logIn(s, 'alice', ALICE);
    const p = '/api/users/create';
    const body = { name: 'eve', role: 'viewer', generate: true, password: ALICE };
    assert.equal((await api(s, p, body, a.cookie, { 'Content-Type': 'application/json', 'Sec-Fetch-Site': 'same-origin' })).status, 403);
    assert.equal((await api(s, p, body, a.cookie, { ...JSON_HEADERS, 'Sec-Fetch-Site': 'cross-site' })).status, 403);
    assert.equal((await api(s, p, body, a.cookie, { 'Content-Type': 'application/json', 'X-Rettui-Request': '1', Origin: 'https://evil.test', Host: 'example.test' })).status, 403);
    assert.equal((await api(s, p, new URLSearchParams(body).toString(), a.cookie, { ...JSON_HEADERS, 'Content-Type': 'application/x-www-form-urlencoded' })).status, 415);
    assert.equal((await api(s, p, '[1]', a.cookie)).status, 400);
    assert.equal((await api(s, p, body)).status, 401);
    assert.equal((await api(s, '/api/users/nothing', body, a.cookie)).status, 405);
    assert.equal(s.store.lookup('eve'), null);
    assert.equal((await api(s, p, body, a.cookie)).status, 200);
  } finally {
    await s.close();
  }
});

test('every change needs a recent sign in, the password, and with TOTP on a code as well', async () => {
  const s = await setup();
  try {
    const a = await logIn(s, 'alice', ALICE);
    const p = '/api/users/role';
    const none = await api(s, p, { name: 'bob', role: 'viewer' }, a.cookie);
    assert.equal(none.status, 400);
    assert.equal(none.json().field, 'password');
    assert.equal((await api(s, p, { name: 'bob', role: 'viewer', password: 'wrong one' }, a.cookie)).status, 400);
    assert.equal((await api(s, p, { name: 'bob', role: 'viewer', code: '123456' }, a.cookie)).status, 400, 'a code is no password');
    assert.equal(s.store.lookup('bob').role, 'manage');
    // Without TOTP the password alone is enough.
    assert.equal((await api(s, p, { name: 'bob', role: 'viewer', password: ALICE }, a.cookie)).status, 200);
    // With TOTP on: the password alone, or the code alone, is refused; both are needed.
    const setup1 = (await api(s, '/api/account/totp/setup', { password: ALICE }, a.cookie)).json();
    const key = base32Decode(setup1.secret);
    assert.equal((await api(s, '/api/account/totp/enable', { code: totp(key, s.clock.t) }, a.cookie)).status, 200);
    s.clock.t += 30_000;
    const pwOnly = await api(s, p, { name: 'bob', role: 'manage', password: ALICE }, a.cookie);
    assert.equal(pwOnly.status, 400);
    assert.equal(pwOnly.json().field, 'code');
    assert.equal((await api(s, p, { name: 'bob', role: 'manage', code: totp(key, s.clock.t) }, a.cookie)).status, 400);
    assert.equal(s.store.lookup('bob').role, 'viewer');
    const code = totp(key, s.clock.t);
    const both = await api(s, p, { name: 'bob', role: 'manage', password: ALICE, code }, a.cookie);
    assert.equal(both.status, 200, both.text);
    // The same code again is refused.
    const replay = await api(s, p, { name: 'bob', role: 'viewer', password: ALICE, code }, a.cookie);
    assert.equal(replay.status, 400);
    assert.equal(replay.json().field, 'code');
    assert.equal(s.store.lookup('bob').role, 'manage');
    // After 15 minutes the sign in is too old, even with both; reauth makes it recent.
    s.clock.t += RECENT_AUTH_MS;
    const stale = await api(s, p, { name: 'bob', role: 'viewer', password: ALICE, code: totp(key, s.clock.t) }, a.cookie);
    assert.equal(stale.status, 403);
    assert.equal(stale.json().reauth, true);
    assert.equal((await api(s, '/api/account/reauth', { password: ALICE }, a.cookie)).status, 200);
    assert.equal((await api(s, p, { name: 'bob', role: 'viewer', password: ALICE, code: totp(key, s.clock.t) }, a.cookie)).status, 200, 'the code was not used up by the refused request');
    const roles = (await auditLines(s)).filter((l) => l.event === 'user-role-changed');
    assert.deepEqual(roles.map((l) => [l.actor, l.user, l.from, l.to, l.with]), [['Alice', 'bob', 'manage', 'viewer', 'password'], ['Alice', 'bob', 'viewer', 'manage', 'password+code'], ['Alice', 'bob', 'manage', 'viewer', 'password+code']]);
    assert.equal((await get(s, '/api/users', a.cookie)).json().secondFactor, true);
  } finally {
    await s.close();
  }
});

test('create: a one-time password is shown once; the new user can only change it after signing in', async () => {
  const s = await setup();
  try {
    const a = await logIn(s, 'alice', ALICE);
    const weak = await api(s, '/api/users/create', { name: 'eve', role: 'viewer', newPassword: 'short', password: ALICE }, a.cookie);
    assert.equal(weak.status, 400);
    assert.equal(weak.json().field, 'newPassword');
    assert.equal((await api(s, '/api/users/create', { name: 'eve', role: 'viewer', newPassword: 'password1234', password: ALICE }, a.cookie)).status, 400, 'common');
    assert.equal((await api(s, '/api/users/create', { name: '-eve', role: 'viewer', generate: true, password: ALICE }, a.cookie)).status, 400);
    assert.equal((await api(s, '/api/users/create', { name: 'eve', role: 'root', generate: true, password: ALICE }, a.cookie)).status, 400);
    assert.equal((await api(s, '/api/users/create', { name: 'ALICE', role: 'viewer', generate: true, password: ALICE }, a.cookie)).status, 409, 'a config name');
    assert.equal((await api(s, '/api/users/create', { name: 'Bob', role: 'viewer', generate: true, password: ALICE }, a.cookie)).status, 409);
    const made = await api(s, '/api/users/create', { name: 'eve', role: 'manage', generate: true, password: ALICE }, a.cookie);
    assert.equal(made.status, 200);
    const otp = made.json().oneTimePassword;
    assert.match(otp, /^([a-z2-9]{4}-){4}[a-z2-9]{4}$/);
    assert.equal(s.store.lookup('eve').mustChangePassword, true);
    // Never again: the list has no password.
    assert.equal((await get(s, '/api/users', a.cookie)).text.includes(otp), false);
    assert.equal((await diskBytes(s.dataDir)).includes(otp), false);
    assert.equal(row(s.dataDir, 'eve').must_change_password, 1);
    // Signing in: told to change it, and nothing else works until then.
    const e = await logIn(s, 'eve', otp);
    assert.equal(e.r.status, 200);
    assert.deepEqual(e.r.json(), { ok: true, name: 'eve', mustChangePassword: true });
    assert.deepEqual((await get(s, '/api/session', e.cookie)).json(), { enabled: true, name: 'eve', mustChangePassword: true });
    assert.equal((await get(s, '/api/status', e.cookie)).json().viewer.name, null, 'sees what a visitor sees');
    assert.equal((await get(s, '/api/account', e.cookie)).json().mustChangePassword, true);
    const blocked = await api(s, '/api/account/totp/setup', { password: otp }, e.cookie);
    assert.equal(blocked.status, 403);
    assert.equal(blocked.json().mustChangePassword, true);
    assert.equal((await api(s, '/api/account/sign-out-others', {}, e.cookie)).status, 403);
    const changed = await api(s, '/api/account/password', { current: otp, next: 'eves very own password' }, e.cookie);
    assert.equal(changed.status, 200, changed.text);
    assert.equal(s.store.lookup('eve').mustChangePassword, false);
    assert.equal((await get(s, '/api/session', e.cookie)).json().mustChangePassword, undefined);
    assert.equal((await get(s, '/api/status', e.cookie)).json().viewer.name, 'eve');
    assert.equal(row(s.dataDir, 'eve').must_change_password, 0);
    // A typed first password works the same way.
    assert.equal((await api(s, '/api/users/create', { name: 'frank', role: 'viewer', newPassword: 'franks first password', password: ALICE }, a.cookie)).json().oneTimePassword, undefined);
    assert.equal((await logIn(s, 'frank', 'franks first password')).r.json().mustChangePassword, true);
    const lines = (await auditLines(s)).filter((l) => l.event === 'user-created');
    assert.deepEqual(lines.map((l) => [l.actor, l.user, l.role, l.password]), [['Alice', 'eve', 'manage', 'generated'], ['Alice', 'frank', 'viewer', 'typed']]);
    const text = await fs.readFile(s.audit.file, 'utf8');
    assert.equal(text.includes(otp), false);
    assert.equal(text.includes('franks first password'), false);
    assert.equal(text.includes(ALICE), false);
  } finally {
    await s.close();
  }
});

test('an admin who must change their password cannot manage users until they do', async () => {
  const s = await setup();
  try {
    const a = await logIn(s, 'alice', ALICE);
    const otp = (await api(s, '/api/users/create', { name: 'root2', role: 'admin', generate: true, password: ALICE }, a.cookie)).json().oneTimePassword;
    const r = await logIn(s, 'root2', otp);
    assert.equal((await get(s, '/users', r.cookie)).status, 404);
    assert.equal((await get(s, '/api/users', r.cookie)).json().mustChangePassword, true);
    assert.equal((await api(s, '/api/users/delete', { name: 'bob', password: otp }, r.cookie)).status, 403);
    assert.equal((await get(s, '/api/account', r.cookie)).json().canManageUsers, false);
    assert.ok(s.store.lookup('bob'));
  } finally {
    await s.close();
  }
});

test('role, delete, password and second factor: config users are read-only, and each change ends the user\'s sessions', async () => {
  const s = await setup({ carol: true });
  try {
    const c = await logIn(s, 'carol', CAROL);
    for (const [p, body] of [['/api/users/role', { name: 'alice', role: 'viewer' }], ['/api/users/delete', { name: 'alice' }], ['/api/users/reset-password', { name: 'alice', generate: true }]]) {
      const r = await api(s, p, { ...body, password: CAROL }, c.cookie);
      assert.equal(r.status, 409, p);
      assert.match(r.json().error, /config file/);
    }
    assert.equal((await api(s, '/api/users/role', { name: 'nobody', role: 'viewer', password: CAROL }, c.cookie)).status, 404);
    // Role: bob is signed out.
    let b = await logIn(s, 'bob', BOB);
    assert.equal((await api(s, '/api/users/role', { name: 'bob', role: 'viewer', password: CAROL }, c.cookie)).status, 200);
    assert.equal(await alive(s, b.cookie), null);
    assert.equal(s.store.lookup('bob').role, 'viewer');
    // Reset password: the old one stops working; the new one must be changed.
    b = await logIn(s, 'bob', BOB);
    const reset = await api(s, '/api/users/reset-password', { name: 'bob', generate: true, password: CAROL }, c.cookie);
    assert.equal(reset.status, 200);
    assert.equal(await alive(s, b.cookie), null);
    assert.equal((await logIn(s, 'bob', BOB)).r.status, 401);
    const otp = reset.json().oneTimePassword;
    assert.equal((await logIn(s, 'bob', otp)).r.json().mustChangePassword, true);
    assert.equal((await api(s, '/api/users/reset-password', { name: 'carol', generate: true, password: CAROL }, c.cookie)).status, 409, 'not their own');
    // Second factor: bob turns it on; carol resets it; his devices and sessions go.
    const typed = await api(s, '/api/users/reset-password', { name: 'bob', newPassword: BOB, password: CAROL }, c.cookie);
    assert.equal(typed.status, 200);
    b = await logIn(s, 'bob', BOB);
    assert.equal((await api(s, '/api/account/password', { current: BOB, next: 'bobs newer password' }, b.cookie)).status, 200);
    const sec = (await api(s, '/api/account/totp/setup', { password: 'bobs newer password' }, b.cookie)).json().secret;
    assert.ok(sec);
    assert.equal((await api(s, '/api/account/totp/enable', { code: totp(base32Decode(sec), s.clock.t) }, b.cookie)).status, 200);
    assert.equal(s.store.secondFactorEnabled('bob'), true);
    assert.equal(s.store.devices('bob').length, 1);
    assert.equal((await api(s, '/api/users/reset-second-factor', { name: 'bob', password: CAROL }, c.cookie)).status, 200);
    assert.equal(s.store.secondFactorEnabled('bob'), false);
    assert.equal(s.store.factorRecord('bob').recoveryCodes.length, 0);
    assert.equal(s.store.devices('bob').length, 0);
    assert.equal(await alive(s, b.cookie), null);
    // An admin's second factor (alice, in the config file, is one) is not reset here; one's own
    // cannot be either.
    assert.equal((await api(s, '/api/users/reset-second-factor', { name: 'alice', password: CAROL }, c.cookie)).status, 403);
    assert.equal((await api(s, '/api/users/reset-second-factor', { name: 'carol', password: CAROL }, c.cookie)).status, 409);
    // Delete: gone, and signed out.
    b = await logIn(s, 'bob', 'bobs newer password');
    assert.equal((await api(s, '/api/users/delete', { name: 'bob', password: CAROL }, c.cookie)).status, 200);
    assert.equal(s.store.lookup('bob'), null);
    assert.equal(await alive(s, b.cookie), null);
    assert.equal((await logIn(s, 'bob', 'bobs newer password')).r.status, 401);
    const events = (await auditLines(s)).filter((l) => l.actor === 'carol').map((l) => [l.event, l.user ?? l.target]);
    assert.deepEqual(events, [
      ['user-role-changed', 'bob'], ['user-password-reset', 'bob'], ['user-password-reset', 'bob'],
      ['user-second-factor-reset', 'bob'], ['admin-reset-refused', 'Alice'], ['user-deleted', 'bob'],
    ]);
  } finally {
    await s.close();
  }
});

test('the last admin cannot be deleted or demoted, also not by themselves; with another admin they can', async () => {
  const s = await setup({ aliceRole: 'viewer', carol: true });
  try {
    const c = await logIn(s, 'carol', CAROL);
    const demote = await api(s, '/api/users/role', { name: 'carol', role: 'manage', password: CAROL }, c.cookie);
    assert.equal(demote.status, 409);
    assert.match(demote.json().error, /last admin/);
    assert.equal((await api(s, '/api/users/delete', { name: 'carol', password: CAROL }, c.cookie)).status, 409);
    assert.equal(s.store.lookup('carol').role, 'admin');
    // A second admin: now carol may step down, and is signed out at once.
    assert.equal((await api(s, '/api/users/create', { name: 'dave', role: 'admin', newPassword: DAVE, password: CAROL }, c.cookie)).status, 200);
    const self = await api(s, '/api/users/role', { name: 'carol', role: 'viewer', password: CAROL }, c.cookie);
    assert.equal(self.status, 200);
    assert.deepEqual(self.json(), { ok: true, signedOut: true });
    assert.equal(await alive(s, c.cookie), null);
    // Dave is the last admin now.
    await s.store.setPassword('dave', await hashPassword(DAVE, undefined, fakeHasher));
    const d = await logIn(s, 'dave', DAVE);
    assert.equal((await api(s, '/api/users/delete', { name: 'dave', password: DAVE }, d.cookie)).status, 409);
    assert.equal((await api(s, '/api/users/role', { name: 'carol', role: 'admin', password: DAVE }, d.cookie)).status, 200);
    const gone = await api(s, '/api/users/delete', { name: 'dave', password: DAVE }, d.cookie);
    assert.deepEqual(gone.json(), { ok: true, signedOut: true });
    assert.equal(s.store.lookup('dave'), null);
  } finally {
    await s.close();
  }
});

test('changes are limited per admin per hour, wrong passwords included', async () => {
  const s = await setup();
  try {
    const a = await logIn(s, 'alice', ALICE);
    for (let i = 0; i < USER_CHANGES_PER_ADMIN; i++) {
      // Each reauth puts the session wait back; the hour's budget is what is tested here.
      s.login.reauths.clear(`session:${s.login.session({ headers: { cookie: a.cookie } }).id}`);
      await api(s, '/api/users/role', { name: 'bob', role: s.store.lookup('bob').role === 'viewer' ? 'manage' : 'viewer', password: i % 3 ? ALICE : 'wrong one' }, a.cookie);
    }
    const r = await api(s, '/api/users/role', { name: 'bob', role: 'admin', password: ALICE }, a.cookie);
    assert.equal(r.status, 429);
    assert.ok(Number(r.headers['retry-after']) > 0);
    assert.notEqual(s.store.lookup('bob').role, 'admin');
    // A request that is wrong before any password is asked costs nothing. The session is used
    // halfway through the hour, so it is not idle for that long.
    s.clock.t += 40 * 60_000;
    await get(s, '/api/session', a.cookie);
    s.clock.t += 21 * 60_000;
    await api(s, '/api/account/reauth', { password: ALICE }, a.cookie);
    for (let i = 0; i < USER_CHANGES_PER_ADMIN + 5; i++) assert.equal((await api(s, '/api/users/role', { name: 'nobody', role: 'viewer', password: ALICE }, a.cookie)).status, 404);
    assert.equal((await api(s, '/api/users/role', { name: 'bob', role: 'admin', password: ALICE }, a.cookie)).status, 200);
  } finally {
    await s.close();
  }
});

test('an admin whose session ends, or who is demoted, while a change is under way changes nothing', async () => {
  const h = holdable();
  const s = await setup({ carol: true, hasher: h.hasher });
  try {
    let c = await logIn(s, 'carol', CAROL);
    // Ended while the step-up password is checked.
    h.hold();
    let r = api(s, '/api/users/create', { name: 'eve', role: 'admin', generate: true, password: CAROL }, c.cookie);
    await until(() => h.waiting() === 1);
    s.login.endUser('carol');
    h.let();
    r = await r;
    assert.equal(r.status, 401);
    assert.equal(r.text.includes('oneTimePassword'), false);
    assert.equal(s.store.lookup('eve'), null);
    // Demoted while the new user's password is hashed: the session is still there, but the role
    // is asked again too.
    c = await logIn(s, 'carol', CAROL);
    h.hold();
    r = api(s, '/api/users/create', { name: 'eve', role: 'admin', generate: true, password: CAROL }, c.cookie);
    await until(() => h.waiting() === 1);
    h.let();
    // The step-up passed; now hold the hash of the new password.
    h.hold();
    await until(() => h.waiting() === 1);
    await s.store.setRole('carol', 'viewer');
    h.let();
    r = await r;
    assert.equal(r.status, 401);
    assert.equal(r.text.includes('oneTimePassword'), false);
    assert.equal(s.store.lookup('eve'), null);
    await s.store.setRole('carol', 'admin');
    // The store's guard: the admin's session ends right as the write starts, as if it waited for
    // the store meanwhile.
    c = await logIn(s, 'carol', CAROL);
    const db = s.store.db;
    const tx = db.tx;
    db.tx = (fn) => {
      db.tx = tx;
      s.login.endUser('carol');
      return tx.call(db, fn);
    };
    r = await api(s, '/api/users/delete', { name: 'bob', password: CAROL }, c.cookie);
    assert.equal(r.status, 401);
    assert.ok(s.store.lookup('bob'), 'bob is still there');
    assert.equal((await auditLines(s)).filter((l) => l.event === 'user-deleted').length, 0);
  } finally {
    await s.close();
  }
});

test('a change whose write fails changes nothing and signs nobody out', async () => {
  const s = await setup({ carol: true, timeoutMs: 50 });
  try {
    const c = await logIn(s, 'carol', CAROL);
    const b = await logIn(s, 'bob', BOB);
    // Another program holds the store for longer than a write waits.
    const release = holdLock(s.dataDir);
    let r;
    try {
      r = await api(s, '/api/users/role', { name: 'bob', role: 'viewer', password: CAROL }, c.cookie);
    } finally {
      release();
    }
    assert.equal(r.status, 500);
    assert.equal(r.json().error, 'Another program is changing the user store; nothing was changed. Try again.');
    assert.equal(row(s.dataDir, 'bob').role, 'manage');
    assert.equal((await auditLines(s)).filter((l) => l.event === 'user-role-changed').length, 0);
    assert.equal(s.store.lookup('bob').role, 'manage');
    assert.equal(await alive(s, b.cookie), 'bob');
    assert.ok(s.logs.length === 0 || s.logs.every((l) => !l.includes(CAROL)));
  } finally {
    await s.close();
  }
});

test('one-time passwords pass the password rules and differ every time', () => {
  const seen = new Set();
  for (let i = 0; i < 200; i++) {
    const p = newOneTimePassword();
    assert.match(p, /^([a-hjkmnp-z2-9]{4}-){4}[a-hjkmnp-z2-9]{4}$/);
    seen.add(p);
  }
  assert.equal(seen.size, 200);
});

test('every spelling of the users page goes through its gate; every spelling of the account page is the account page', async () => {
  const s = await setup();
  const spellings = ['/users.html', '/%75sers.html', '/users.html/', '/users%2ehtml', '/users%2Ehtml', '/USERS.html', '/Users.HTML', '/%55sers.html', '/./users.html', '/fonts/../users.html'];
  const accounts = ['/account.html', '/%61ccount.html', '/account.html/', '/account%2ehtml', '/ACCOUNT.html', '/Account.Html'];
  try {
    const b = await logIn(s, 'bob', BOB);
    for (const p of spellings) {
      for (const [who, cookie] of [['signed out', undefined], ['bob', b.cookie]]) {
        const r = await get(s, p, cookie);
        assert.equal(r.status, 404, `${p} ${who}`);
        assert.doesNotMatch(r.text, /users-rows|<h1>Users/, `${p} ${who}`);
      }
    }
    const a = await logIn(s, 'alice', ALICE);
    const page = (await get(s, '/users', a.cookie)).text;
    for (const p of spellings) {
      const r = await get(s, p, a.cookie);
      assert.equal(r.status, 200, p);
      assert.equal(r.text, page, p);
      assert.equal(r.headers['cache-control'], 'private, no-store', p);
    }
    const account = (await get(s, '/account')).text;
    for (const p of accounts) {
      const r = await get(s, p);
      assert.equal(r.status, 200, p);
      assert.equal(r.text, account, `${p} is rendered like /account`);
    }
    // The page scripts are not pages: they are served as files.
    assert.equal((await get(s, '/users-page.js')).status, 200);
    assert.equal((await get(s, '/account-page.js')).status, 200);
  } finally {
    await s.close();
  }
  // Without users there is no account page and no users page, by any name.
  const dataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'users-'));
  const monitor = new Monitor({ targets: [{ host: 'a.test', port: 1 }], dataDir, probeFn: async () => ({ up: true, ms: 1 }) });
  const server = createApp({ monitor, publicDir });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  try {
    for (const p of [...spellings, ...accounts]) assert.equal((await request(server.address().port, { path: p })).status, 404, p);
  } finally {
    server.closeAllConnections();
    await new Promise((r) => server.close(r));
  }
});

test('an admin\'s password and second factor are never reset here, only on the command line; each refusal is audited', async () => {
  const s = await setup({ carol: true });
  try {
    const a = await logIn(s, 'alice', ALICE);
    const before = s.store.find('carol').phc;
    // Carol (a website admin) with and without a second factor; every way of asking.
    const refusedBodies = [
      ['/api/users/reset-password', { name: 'carol', newPassword: 'alice knows this one', password: ALICE }, 'password'],
      ['/api/users/reset-password', { name: 'carol', generate: true, password: ALICE }, 'password'],
      ['/api/users/reset-password', { name: 'CAROL', generate: true }, 'password'],
      ['/api/users/reset-second-factor', { name: 'carol', password: ALICE }, 'second-factor'],
    ];
    const ask = async () => {
      for (const [p, body] of refusedBodies) {
        const r = await api(s, p, body, a.cookie);
        assert.deepEqual([r.status, r.json()], [403, { error: ADMIN_RESET_REFUSED, code: 'admin-target' }], `${p} ${JSON.stringify(body)}`);
      }
    };
    await ask();
    await s.store.beginTotp('carol');
    const h = s.store.home('carol');
    s.store.commit(h.map, h.k, (cur) => ({ ...cur, totp: { ...cur.totp, enabled: true } }));
    await ask();
    assert.deepEqual(s.store.find('carol').phc, before);
    assert.equal(s.store.secondFactorEnabled('carol'), true);
    assert.equal((await logIn(s, 'carol', 'alice knows this one')).r.status, 401);
    // No password was checked for a refusal.
    assert.equal(s.login.reauths.count(`session:${s.login.session({ headers: { cookie: a.cookie } }).id}`), 0);
    // The same with a second factor on the acting admin's side (carol acting on alice, a config admin).
    s.store.commit(h.map, h.k, (cur) => ({ ...cur, totp: null }));
    const c = await logIn(s, 'carol', CAROL);
    const r = await api(s, '/api/users/reset-second-factor', { name: 'alice', password: CAROL }, c.cookie);
    assert.equal(r.status, 403);
    // The existing rules stay first: one's own, and a config user's password.
    assert.equal((await api(s, '/api/users/reset-password', { name: 'alice', generate: true, password: ALICE }, a.cookie)).status, 409);
    assert.equal((await api(s, '/api/users/reset-second-factor', { name: 'alice', password: ALICE }, a.cookie)).status, 409);
    // Other users still get a typed or a one-time password, and a reset of their second factor.
    assert.equal((await api(s, '/api/users/reset-password', { name: 'bob', newPassword: 'a typed password for bob', password: ALICE }, a.cookie)).status, 200);
    const otp = await api(s, '/api/users/reset-password', { name: 'bob', generate: true, password: ALICE }, a.cookie);
    assert.equal(otp.status, 200);
    assert.equal((await api(s, '/api/users/reset-second-factor', { name: 'bob', password: ALICE }, a.cookie)).status, 200);
    const lines = await auditLines(s);
    const refused = lines.filter((l) => l.event === 'admin-reset-refused');
    assert.equal(refused.length, 9);
    assert.deepEqual({ ...refused[0], time: undefined }, { time: undefined, event: 'admin-reset-refused', actor: 'Alice', target: 'carol', what: 'password', address: '127.0.0.1' });
    assert.deepEqual(refused.map((l) => l.what), ['password', 'password', 'password', 'second-factor', 'password', 'password', 'password', 'second-factor', 'second-factor']);
    assert.deepEqual({ ...refused[8], time: undefined }, { time: undefined, event: 'admin-reset-refused', actor: 'carol', target: 'Alice', what: 'second-factor', address: '127.0.0.1' });
    assert.equal(lines.some((l) => l.event === 'admin-reset-admin'), false);
    assert.equal(JSON.stringify(lines).includes(otp.json().oneTimePassword), false);
  } finally {
    await s.close();
  }
});

test('a user made an admin while a reset of them waits is refused, and nothing changed', async () => {
  for (const [p, extra, what] of [['/api/users/reset-password', { newPassword: 'carol knows this one' }, 'password'], ['/api/users/reset-password', { generate: true }, 'password'], ['/api/users/reset-second-factor', {}, 'second-factor']]) {
    const h = holdable();
    const s = await setup({ carol: true, hasher: h.hasher });
    try {
      const c = await logIn(s, 'carol', CAROL);
      await s.store.beginTotp('bob');
      const home = s.store.home('bob');
      s.store.commit(home.map, home.k, (cur) => ({ ...cur, totp: { ...cur.totp, enabled: true } }));
      const old = s.store.find('bob').phc;
      h.hold();
      const r = api(s, p, { name: 'bob', ...extra, password: CAROL }, c.cookie);
      await until(() => h.waiting() === 1);
      await s.store.setRole('bob', 'admin');
      h.let();
      const done = await r;
      assert.deepEqual([done.status, done.json()], [403, { error: ADMIN_RESET_REFUSED, code: 'admin-target' }], p);
      assert.deepEqual(s.store.find('bob').phc, old);
      assert.equal(s.store.secondFactorEnabled('bob'), true);
      const line = (await auditLines(s)).find((l) => l.event === 'admin-reset-refused');
      assert.deepEqual([line.actor, line.target, line.what], ['carol', 'bob', what]);
    } finally {
      await s.close();
    }
  }
});

test('a role change audits the role the user had right before it, also when it changed meanwhile', async () => {
  const h = holdable();
  const s = await setup({ hasher: h.hasher });
  try {
    const a = await logIn(s, 'alice', ALICE);
    h.hold();
    const r = api(s, '/api/users/role', { name: 'bob', role: 'admin', password: ALICE }, a.cookie);
    await until(() => h.waiting() === 1);
    await s.store.setRole('bob', 'viewer');
    h.let();
    assert.equal((await r).status, 200);
    const line = (await auditLines(s)).find((l) => l.event === 'user-role-changed');
    assert.deepEqual([line.from, line.to], ['viewer', 'admin']);
  } finally {
    await s.close();
  }
});

test('another admin is never demoted here, only on the command line; each refusal is audited', async () => {
  const s = await setup({ carol: true });
  try {
    const a = await logIn(s, 'alice', ALICE);
    for (const body of [{ name: 'carol', role: 'manage', password: ALICE }, { name: 'CAROL', role: 'viewer', password: ALICE }, { name: 'carol', role: 'viewer' }]) {
      const r = await api(s, '/api/users/role', body, a.cookie);
      assert.deepEqual([r.status, r.json()], [403, { error: ADMIN_DEMOTE_REFUSED, code: 'admin-demote' }], JSON.stringify(body));
    }
    assert.equal(s.store.lookup('carol').role, 'admin');
    // Refused before any password was checked; it counts in the hourly budget.
    assert.equal(s.login.reauths.count(`session:${s.login.session({ headers: { cookie: a.cookie } }).id}`), 0);
    // Carol still signs in, as an admin: her sessions were not ended.
    const c = await logIn(s, 'carol', CAROL);
    assert.equal((await get(s, '/api/users', c.cookie)).status, 200);
    // The existing rules stay: making someone an admin, other role changes, one's own role, delete.
    assert.equal((await api(s, '/api/users/role', { name: 'bob', role: 'viewer', password: ALICE }, a.cookie)).status, 200);
    assert.equal((await api(s, '/api/users/role', { name: 'bob', role: 'admin', password: ALICE }, a.cookie)).status, 200);
    // Now bob is an admin too, and carol cannot demote him either.
    assert.equal((await api(s, '/api/users/role', { name: 'bob', role: 'manage', password: CAROL }, c.cookie)).status, 403);
    assert.equal(s.store.lookup('bob').role, 'admin');
    // A config admin (alice) is refused as a config user, as before.
    assert.equal((await api(s, '/api/users/role', { name: 'alice', role: 'viewer', password: CAROL }, c.cookie)).json().code, 'config');
    // Carol gives herself another role: allowed while another admin exists, and she is signed out.
    const self = await api(s, '/api/users/role', { name: 'carol', role: 'manage', password: CAROL }, c.cookie);
    assert.deepEqual([self.status, self.json()], [200, { ok: true, signedOut: true }]);
    assert.equal(s.store.lookup('carol').role, 'manage');
    const lines = await auditLines(s);
    const refused = lines.filter((l) => l.event === 'admin-demote-refused');
    assert.deepEqual(refused.map((l) => ({ ...l, time: undefined })), [
      { time: undefined, event: 'admin-demote-refused', actor: 'Alice', target: 'carol', address: '127.0.0.1' },
      { time: undefined, event: 'admin-demote-refused', actor: 'Alice', target: 'carol', address: '127.0.0.1' },
      { time: undefined, event: 'admin-demote-refused', actor: 'Alice', target: 'carol', address: '127.0.0.1' },
      { time: undefined, event: 'admin-demote-refused', actor: 'carol', target: 'bob', address: '127.0.0.1' },
    ]);
    assert.deepEqual(lines.filter((l) => l.event === 'user-role-changed').map((l) => [l.actor, l.user, l.from, l.to]), [['Alice', 'bob', 'manage', 'viewer'], ['Alice', 'bob', 'viewer', 'admin'], ['carol', 'carol', 'admin', 'manage']]);
  } finally {
    await s.close();
  }
});

test('a user made an admin while a role change of them waits is refused, and keeps the admin role', async () => {
  const h = holdable();
  const s = await setup({ carol: true, hasher: h.hasher });
  try {
    const c = await logIn(s, 'carol', CAROL);
    h.hold();
    const r = api(s, '/api/users/role', { name: 'bob', role: 'viewer', password: CAROL }, c.cookie);
    await until(() => h.waiting() === 1);
    await s.store.setRole('bob', 'admin');
    h.let();
    const done = await r;
    assert.deepEqual([done.status, done.json()], [403, { error: ADMIN_DEMOTE_REFUSED, code: 'admin-demote' }]);
    assert.equal(s.store.lookup('bob').role, 'admin');
    const lines = await auditLines(s);
    assert.equal(lines.some((l) => l.event === 'user-role-changed'), false);
    const line = lines.find((l) => l.event === 'admin-demote-refused');
    assert.deepEqual([line.actor, line.target, line.address], ['carol', 'bob', '127.0.0.1']);
  } finally {
    await s.close();
  }
});

test('another admin is never deleted here, only on the command line; each refusal is audited', async () => {
  const s = await setup({ carol: true });
  try {
    const a = await logIn(s, 'alice', ALICE);
    const c = await logIn(s, 'carol', CAROL);
    for (const body of [{ name: 'carol', password: ALICE }, { name: 'CAROL', password: ALICE }, { name: 'carol' }]) {
      const r = await api(s, '/api/users/delete', body, a.cookie);
      assert.deepEqual([r.status, r.json()], [403, { error: ADMIN_DELETE_REFUSED, code: 'admin-delete' }], JSON.stringify(body));
    }
    assert.equal(s.store.lookup('carol').role, 'admin');
    // Refused before any password was checked; carol's sessions were not ended.
    assert.equal(s.login.reauths.count(`session:${s.login.session({ headers: { cookie: a.cookie } }).id}`), 0);
    assert.notEqual(await alive(s, c.cookie), null);
    // Each refusal counts in the hourly budget: 30 in all, then 429.
    for (let i = 3; i < USER_CHANGES_PER_ADMIN; i++) assert.equal((await api(s, '/api/users/delete', { name: 'carol' }, a.cookie)).status, 403);
    assert.equal((await api(s, '/api/users/delete', { name: 'carol' }, a.cookie)).status, 429);
    // Other users are deleted as before, and an admin deletes themselves while another admin exists.
    assert.equal((await api(s, '/api/users/delete', { name: 'bob', password: CAROL }, c.cookie)).status, 200);
    const self = await api(s, '/api/users/delete', { name: 'carol', password: CAROL }, c.cookie);
    assert.deepEqual([self.status, self.json()], [200, { ok: true, signedOut: true }]);
    assert.equal(s.store.lookup('carol'), null);
    const lines = await auditLines(s);
    const refused = lines.filter((l) => l.event === 'admin-delete-refused');
    assert.equal(refused.length, USER_CHANGES_PER_ADMIN);
    assert.deepEqual({ ...refused[0], time: undefined }, { time: undefined, event: 'admin-delete-refused', actor: 'Alice', target: 'carol', address: '127.0.0.1' });
    assert.deepEqual(lines.filter((l) => l.event === 'user-deleted').map((l) => [l.actor, l.user]), [['carol', 'bob'], ['carol', 'carol']]);
  } finally {
    await s.close();
  }
});

test('a user made an admin while a delete of them waits is refused, and is still there', async () => {
  const h = holdable();
  const s = await setup({ carol: true, hasher: h.hasher });
  try {
    const c = await logIn(s, 'carol', CAROL);
    h.hold();
    const r = api(s, '/api/users/delete', { name: 'bob', password: CAROL }, c.cookie);
    await until(() => h.waiting() === 1);
    await s.store.setRole('bob', 'admin');
    h.let();
    const done = await r;
    assert.deepEqual([done.status, done.json()], [403, { error: ADMIN_DELETE_REFUSED, code: 'admin-delete' }]);
    assert.equal(s.store.lookup('bob').role, 'admin');
    const lines = await auditLines(s);
    assert.equal(lines.some((l) => l.event === 'user-deleted'), false);
    const line = lines.find((l) => l.event === 'admin-delete-refused');
    assert.deepEqual([line.actor, line.target, line.address], ['carol', 'bob', '127.0.0.1']);
  } finally {
    await s.close();
  }
});

test('too many hashes at once from the admin\'s own requests (503) do not count against the hourly limit', async () => {
  const h = holdable();
  const s = await setup({ hasher: h.hasher });
  try {
    const a = await logIn(s, 'alice', ALICE);
    const role = () => (s.store.lookup('bob').role === 'viewer' ? 'manage' : 'viewer');
    h.hold();
    const held = [api(s, '/api/users/role', { name: 'bob', role: role(), password: ALICE }, a.cookie), api(s, '/api/users/role', { name: 'bob', role: role(), password: ALICE }, a.cookie)];
    await until(() => h.waiting() === 2);
    let busy = 0;
    for (let i = 0; i < USER_CHANGES_PER_ADMIN; i++) if ((await api(s, '/api/users/role', { name: 'bob', role: role(), password: ALICE }, a.cookie)).status === 503) busy++;
    assert.equal(busy, USER_CHANGES_PER_ADMIN);
    h.let();
    await Promise.all(held);
    // Two changes were counted; the rest of the hour's budget is still there.
    for (let i = 2; i < USER_CHANGES_PER_ADMIN; i++) assert.equal((await api(s, '/api/users/role', { name: 'bob', role: role(), password: ALICE }, a.cookie)).status, 200, `change ${i + 1}`);
    assert.equal((await api(s, '/api/users/role', { name: 'bob', role: role(), password: ALICE }, a.cookie)).status, 429);
  } finally {
    await s.close();
  }
});

test('a full user store refuses the change with a 500 that says so, and changes nothing', async () => {
  const s = await setup({ carol: true });
  try {
    const c = await logIn(s, 'carol', CAROL);
    // The database takes no more users than it has now.
    const before = await diskBytes(s.dataDir);
    s.store.db.maxUsers = 2;
    const full = await api(s, '/api/users/create', { name: 'eve', role: 'viewer', generate: true, password: CAROL }, c.cookie);
    assert.equal(full.status, 500);
    assert.equal(full.json().error, 'The user store is full, so nothing was changed. Delete users that are not needed any more.');
    assert.equal(s.store.lookup('eve'), null);
    assert.equal(row(s.dataDir, 'eve'), null);
    assert.deepEqual(await diskBytes(s.dataDir), before);
    assert.equal((await auditLines(s)).filter((l) => l.event === 'user-created').length, 0);
    s.store.db.maxUsers = 500;
    assert.equal((await api(s, '/api/users/create', { name: 'eve', role: 'viewer', generate: true, password: CAROL }, c.cookie)).status, 200);
  } finally {
    await s.close();
  }
});

test('a change made by the command line while the server runs is picked up: the user is signed out, it is audited, and a change on top of it is kept', async () => {
  const s = await setup({ carol: true });
  try {
    const c = await logIn(s, 'carol', CAROL);
    const b = await logIn(s, 'bob', BOB);
    const other = await UserStore.open({ keys: KEYS, dataDir: s.dataDir, warn: () => {} });
    try {
      await other.setRole('bob', 'viewer');
    } finally {
      other.close();
    }
    // Found at the next write (the server also looks once a second).
    const r = await api(s, '/api/users/role', { name: 'bob', role: 'admin', password: CAROL }, c.cookie);
    assert.equal(r.status, 200, r.text);
    assert.equal(s.store.lookup('bob').role, 'admin');
    assert.equal(row(s.dataDir, 'bob').role, 'admin');
    assert.equal(await alive(s, b.cookie), null, 'bob was signed out');
    assert.equal(await alive(s, c.cookie), 'carol', 'nobody else was');
    const lines = await auditLines(s);
    assert.deepEqual(lines.filter((l) => l.event === 'user-changed-elsewhere').map((l) => [l.user, l.what]), [['bob', ['role']]]);
    const changed = lines.find((l) => l.event === 'user-role-changed');
    assert.deepEqual([changed.from, changed.to], ['viewer', 'admin'], 'made on top of the change made elsewhere');
  } finally {
    await s.close();
  }
});

// ---- a password reset that removes the user's passkeys ----

const passkeyRecord = (label) => ({
  id: crypto.randomBytes(32).toString('base64url'),
  publicKey: crypto.randomBytes(77).toString('base64url'),
  counter: 0,
  transports: ['internal'],
  name: label,
  backupEligible: true,
  backedUp: true,
  rpId: 'status.example.org',
});

// Carol (an admin) signed in, and bob with two passkeys.
async function carolAndBobWithPasskeys() {
  const s = await setup({ carol: true });
  await s.store.addPasskey('bob', passkeyRecord('Phone'));
  await s.store.addPasskey('bob', passkeyRecord('Planted'));
  assert.equal(s.store.passkeys('bob').length, 2);
  return { s, c: await logIn(s, 'carol', CAROL) };
}

test('reset password: removePasskeys true removes every passkey in the same write, ends their sessions, says how many and writes the count', async () => {
  const { s, c } = await carolAndBobWithPasskeys();
  try {
    // Two passkeys make two-step sign-in on: bob's sign in has a second step now, and none after the reset.
    assert.equal((await logIn(s, 'bob', BOB)).r.json().secondFactor, true);
    const r = await api(s, '/api/users/reset-password', { name: 'bob', generate: true, removePasskeys: true, password: CAROL }, c.cookie);
    assert.equal(r.status, 200, r.text);
    assert.equal(r.json().removedPasskeys, 2);
    assert.ok(r.json().oneTimePassword);
    assert.equal(s.store.passkeys('bob').length, 0);
    assert.equal(s.store.secondFactorEnabled('bob'), false);
    // The new password signs in, with no second step, and must be changed.
    assert.equal((await logIn(s, 'bob', r.json().oneTimePassword)).r.json().mustChangePassword, true);
    const line = (await auditLines(s)).find((l) => l.event === 'user-password-reset');
    assert.equal(line.passkeys, 2);
    assert.equal(line.actor, 'carol');
    assert.equal(line.user, 'bob');
    // No credential id or key in the log.
    const text = await fs.readFile(s.audit.file, 'utf8');
    assert.equal(text.includes('publicKey'), false);
  } finally {
    await s.close();
  }
});

test('reset password: without the flag, or with anything but the boolean true, the passkeys stay (an old page or a script)', async () => {
  const { s, c } = await carolAndBobWithPasskeys();
  try {
    for (const flag of [undefined, false, 'true', 1, 'yes', null, [true], { a: 1 }]) {
      const body = { name: 'bob', newPassword: `a typed password ${String(JSON.stringify(flag))}`, password: CAROL };
      if (flag !== undefined) body.removePasskeys = flag;
      const r = await api(s, '/api/users/reset-password', body, c.cookie);
      assert.equal(r.status, 200, `${JSON.stringify(flag)}: ${r.text}`);
      assert.equal(Object.hasOwn(r.json(), 'removedPasskeys'), false);
      assert.equal(s.store.passkeys('bob').length, 2, JSON.stringify(flag));
    }
    const lines = (await auditLines(s)).filter((l) => l.event === 'user-password-reset');
    assert.equal(lines.length, 8);
    assert.equal(lines.some((l) => Object.hasOwn(l, 'passkeys')), false);
  } finally {
    await s.close();
  }
});

test('reset password: a user without passkeys says 0 removed; the app code and recovery codes stay', async () => {
  const { s, c } = await carolAndBobWithPasskeys();
  try {
    const first = await api(s, '/api/users/reset-password', { name: 'bob', generate: true, removePasskeys: true, password: CAROL }, c.cookie);
    assert.equal(first.json().removedPasskeys, 2);
    // Turn the app code on for bob through the store, then reset again with the flag.
    const secret = await s.store.beginTotp('bob');
    const codes = await s.store.enableTotp('bob', totp(base32Decode(secret), s.clock.t));
    assert.ok(codes.length > 0);
    s.clock.t += 60_000;
    const again = await api(s, '/api/users/reset-password', { name: 'bob', generate: true, removePasskeys: true, password: CAROL }, c.cookie);
    assert.equal(again.status, 200, again.text);
    assert.equal(again.json().removedPasskeys, 0);
    assert.equal(s.store.secondFactors('bob').totp, true);
    assert.equal(s.store.factorRecord('bob').recoveryCodes.length, codes.length);
    assert.equal((await auditLines(s)).filter((l) => l.event === 'user-password-reset').at(-1).passkeys, 0);
  } finally {
    await s.close();
  }
});

test('reset password: the flag changes nothing without the admin\'s password, from a non-admin, or for an admin or config user', async () => {
  const { s, c } = await carolAndBobWithPasskeys();
  try {
    // A wrong password for the admin, and none at all.
    assert.equal((await api(s, '/api/users/reset-password', { name: 'bob', generate: true, removePasskeys: true, password: 'not carols' }, c.cookie)).status, 400);
    assert.equal((await api(s, '/api/users/reset-password', { name: 'bob', generate: true, removePasskeys: true }, c.cookie)).status, 400);
    // Nobody signed in, and a user who is not an admin.
    assert.equal((await api(s, '/api/users/reset-password', { name: 'bob', generate: true, removePasskeys: true, password: CAROL })).status, 401);
    await s.store.createUser({ name: 'dave', role: 'viewer', passwordHash: await hashPassword(DAVE, undefined, fakeHasher, s.store.currentPepper()) });
    const d = await logIn(s, 'dave', DAVE);
    assert.equal((await api(s, '/api/users/reset-password', { name: 'bob', generate: true, removePasskeys: true, password: DAVE }, d.cookie)).status, 403);
    assert.equal(s.store.passkeys('bob').length, 2);
    assert.equal((await logIn(s, 'bob', BOB)).r.status, 200, 'the password is still bob\'s');
    // An admin (carol herself, alice in the config file) is not reset here, flag or not.
    await s.store.addPasskey('carol', passkeyRecord('Carols'));
    assert.equal((await api(s, '/api/users/reset-password', { name: 'carol', generate: true, removePasskeys: true, password: CAROL }, c.cookie)).status, 409);
    assert.equal((await api(s, '/api/users/reset-password', { name: 'alice', generate: true, removePasskeys: true, password: CAROL }, c.cookie)).status, 409);
    assert.equal(s.store.passkeys('carol').length, 1);
    assert.equal((await auditLines(s)).some((l) => l.event === 'user-password-reset'), false);
  } finally {
    await s.close();
  }
});

test('reset password: when the write fails, the password and the passkeys are both as they were, and nobody is signed out', async () => {
  const { s, c } = await carolAndBobWithPasskeys();
  try {
    const put = s.store.db.put.bind(s.store.db);
    // The write that takes passkeys away fails; one that only changes the password would not.
    s.store.db.put = (kind, rec) => {
      if (rec.name === 'bob' && (rec.credentials ?? []).length < 2) throw new Error('disk full');
      return put(kind, rec);
    };
    const r = await api(s, '/api/users/reset-password', { name: 'bob', generate: true, removePasskeys: true, password: CAROL }, c.cookie);
    assert.equal(r.status, 500, r.text);
    s.store.db.put = put;
    assert.equal(s.store.passkeys('bob').length, 2);
    assert.equal((await logIn(s, 'bob', BOB)).r.status, 200);
    assert.equal((await auditLines(s)).some((l) => l.event === 'user-password-reset'), false);
  } finally {
    await s.close();
  }
});
