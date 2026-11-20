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
import { hashPassword } from '../lib/password.js';
import { STORE_FILE, UserStore } from '../lib/users.js';
import { createAudit, createFailureLog } from '../lib/audit.js';
import { RECENT_AUTH_MS } from '../lib/account.js';
import { USER_CHANGES_PER_ADMIN, newOneTimePassword } from '../lib/admin.js';
import { base32Decode, totp } from '../lib/totp.js';
import { fakeHasher } from './helpers/fake-hasher.js';

const publicDir = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'public');
const NOW = 1_800_000_000_000;
const ALICE = 'correct horse battery';
const BOB = 'bobs own password';
const CAROL = 'carols long password';
const DAVE = 'daves long password';

// Alice is in the config file (admin unless aliceRole says otherwise); bob (manage) and, with
// carol, carol (admin) are website users.
async function setup({ aliceRole = 'admin', carol = false, hasher = fakeHasher } = {}) {
  const dataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'users-'));
  const hash = await hashPassword(ALICE, undefined, fakeHasher);
  const config = loadConfig(`users:\n  - name: Alice\n    password_hash: '${hash}'\n    role: ${aliceRole}\nnodes:\n  - address: a.test:1\n`);
  const clock = { t: NOW };
  const now = () => clock.t;
  const logs = [];
  const store = await UserStore.open({ dataDir, configUsers: config.users, warn: () => {}, now, log: (m) => logs.push(m) });
  await store.createUser({ name: 'bob', role: 'manage', passwordHash: await hashPassword(BOB, undefined, fakeHasher) });
  if (carol) await store.createUser({ name: 'carol', role: 'admin', passwordHash: await hashPassword(CAROL, undefined, fakeHasher) });
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
    const disk = await fs.readFile(path.join(s.dataDir, STORE_FILE), 'utf8');
    assert.equal(disk.includes(otp), false);
    assert.match(disk, /"mustChangePassword": true/);
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
    assert.doesNotMatch(await fs.readFile(path.join(s.dataDir, STORE_FILE), 'utf8'), /mustChangePassword/);
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
    // A config user's second factor can be reset; one's own cannot, here.
    assert.equal((await api(s, '/api/users/reset-second-factor', { name: 'alice', password: CAROL }, c.cookie)).status, 200);
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
      ['user-second-factor-reset', 'bob'], ['admin-reset-admin', 'Alice'], ['user-deleted', 'bob'],
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
    // The store's guard: the write waits behind another, and the admin's session ends meanwhile.
    c = await logIn(s, 'carol', CAROL);
    let unblock;
    const before = s.store.saving;
    s.store.saving = new Promise((res) => (unblock = res)).then(() => before);
    r = api(s, '/api/users/delete', { name: 'bob', password: CAROL }, c.cookie);
    await new Promise((res) => setTimeout(res, 50));
    s.login.endUser('carol');
    unblock();
    r = await r;
    assert.equal(r.status, 401);
    assert.ok(s.store.lookup('bob'), 'bob is still there');
    assert.equal((await auditLines(s)).filter((l) => l.event === 'user-deleted').length, 0);
  } finally {
    await s.close();
  }
});

test('a change whose write fails changes nothing and signs nobody out', async () => {
  const s = await setup({ carol: true });
  try {
    const c = await logIn(s, 'carol', CAROL);
    const b = await logIn(s, 'bob', BOB);
    // users.json becomes a folder: the rename over it fails.
    await fs.rm(path.join(s.dataDir, STORE_FILE));
    await fs.mkdir(path.join(s.dataDir, STORE_FILE, 'x'), { recursive: true });
    const r = await api(s, '/api/users/role', { name: 'bob', role: 'viewer', password: CAROL }, c.cookie);
    assert.equal(r.status, 500);
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

test('an admin cannot take over another admin: their password is only reset to a one-time password, and it is audited apart', async () => {
  const s = await setup({ carol: true });
  try {
    const a = await logIn(s, 'alice', ALICE);
    const before = s.store.find('carol').phc;
    const typed = await api(s, '/api/users/reset-password', { name: 'carol', newPassword: 'alice knows this one', password: ALICE }, a.cookie);
    assert.equal(typed.status, 400);
    assert.equal(typed.json().field, 'newPassword');
    assert.match(typed.json().error, /one-time password/);
    assert.deepEqual(s.store.find('carol').phc, before);
    assert.equal((await logIn(s, 'carol', 'alice knows this one')).r.status, 401);
    const otp = await api(s, '/api/users/reset-password', { name: 'carol', generate: true, password: ALICE }, a.cookie);
    assert.equal(otp.status, 200);
    assert.equal((await logIn(s, 'carol', otp.json().oneTimePassword)).r.json().mustChangePassword, true);
    assert.equal((await api(s, '/api/users/reset-second-factor', { name: 'carol', password: ALICE }, a.cookie)).status, 200);
    // Other users may still get a typed password.
    assert.equal((await api(s, '/api/users/reset-password', { name: 'bob', newPassword: 'a typed password for bob', password: ALICE }, a.cookie)).status, 200);
    const lines = (await auditLines(s)).filter((l) => l.actor === 'Alice');
    assert.deepEqual(lines.map((l) => [l.event, l.target ?? l.user, l.what]), [['admin-reset-admin', 'carol', 'password'], ['admin-reset-admin', 'carol', 'second-factor'], ['user-password-reset', 'bob', undefined]]);
    assert.equal(JSON.stringify(lines).includes(otp.json().oneTimePassword), false);
    // Made an admin while a typed reset waits: it is refused, and nothing changed.
    const h = holdable();
    const s2 = await setup({ carol: true, hasher: h.hasher });
    try {
      const c = await logIn(s2, 'carol', CAROL);
      const old = s2.store.find('bob').phc;
      h.hold();
      const r = api(s2, '/api/users/reset-password', { name: 'bob', newPassword: 'carol knows this one', password: CAROL }, c.cookie);
      await until(() => h.waiting() === 1);
      await s2.store.setRole('bob', 'admin');
      h.let();
      const done = await r;
      assert.equal(done.status, 400);
      assert.deepEqual(s2.store.find('bob').phc, old);
    } finally {
      await s2.close();
    }
  } finally {
    await s.close();
  }
});

test('a role change audits the role the user had right before it, also when it changed meanwhile', async () => {
  const h = holdable();
  const s = await setup({ hasher: h.hasher });
  try {
    const a = await logIn(s, 'alice', ALICE);
    h.hold();
    const r = api(s, '/api/users/role', { name: 'bob', role: 'viewer', password: ALICE }, a.cookie);
    await until(() => h.waiting() === 1);
    await s.store.setRole('bob', 'admin');
    h.let();
    assert.equal((await r).status, 200);
    const line = (await auditLines(s)).find((l) => l.event === 'user-role-changed');
    assert.deepEqual([line.from, line.to], ['admin', 'viewer']);
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

test('a full user store, or one changed on disk, refuses the change with a 500 that says so, and changes nothing', async () => {
  const s = await setup({ carol: true });
  try {
    const c = await logIn(s, 'carol', CAROL);
    const file = path.join(s.dataDir, STORE_FILE);
    s.store.maxBytes = (await fs.stat(file)).size + 10;
    const full = await api(s, '/api/users/create', { name: 'eve', role: 'viewer', generate: true, password: CAROL }, c.cookie);
    assert.equal(full.status, 500);
    assert.match(full.json().error, /user store is full/);
    assert.equal(s.store.lookup('eve'), null);
    s.store.maxBytes = 8 * 1024 * 1024;
    // Changed by the command line while the server runs.
    const other = await UserStore.open({ dataDir: s.dataDir, warn: () => {} });
    await other.setRole('bob', 'viewer');
    const theirs = await fs.readFile(file, 'utf8');
    for (let i = 0; i < 2; i++) {
      const r = await api(s, '/api/users/role', { name: 'bob', role: 'admin', password: CAROL }, c.cookie);
      assert.equal(r.status, 500);
      assert.match(r.json().error, /user store changed on disk.*Restart the website/);
    }
    assert.equal(s.store.lookup('bob').role, 'manage');
    // The account page says the same; signing in still works, and writes nothing.
    const pw = await api(s, '/api/account/password', { password: CAROL, next: 'carols newer password' }, c.cookie);
    assert.equal(pw.status, 500);
    assert.match(pw.json().error, /changed on disk/);
    assert.equal((await logIn(s, 'bob', BOB)).r.status, 200);
    assert.equal(await fs.readFile(file, 'utf8'), theirs);
    assert.equal(s.logs.filter((l) => l.includes('users.json changed on disk; restart the website to load it')).length >= 1, true);
    assert.equal(s.logs.filter((l) => l.startsWith('error: users.json changed on disk')).length, 1, 'once a minute');
  } finally {
    await s.close();
  }
});
