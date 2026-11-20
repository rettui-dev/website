import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Monitor } from '../lib/monitor.js';
import { loadConfig } from '../lib/config.js';
import { CODE_EXPIRED, CODE_FAILED, LOGIN_FAILED, createApp } from '../lib/app.js';
import { CODE_USER_FREE, COOKIE, DEVICE_BURST, DEVICE_COOKIE, PENDING_MS, createLogin, deviceHash, ipKey, newDeviceId } from '../lib/login.js';
import { hashPassword } from '../lib/password.js';
import { DatabaseSync } from 'node:sqlite';
import { MAX_DEVICES, UserStore } from '../lib/users.js';
import { DB_FILE } from '../lib/userdb.js';
import { Keyring } from '../lib/keys.js';
import { createAudit, createFailureLog } from '../lib/audit.js';
import { REAUTHS_PER_SESSION, REAUTHS_PER_USER, RECENT_AUTH_MS } from '../lib/account.js';
import { base32Decode, hotp, stepAt, totp } from '../lib/totp.js';
import { fakeHasher } from './helpers/fake-hasher.js';

const publicDir = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'public');
const NOW = 1_800_000_000_000;
const PASSWORD = 'correct horse battery';
const BOB_PASSWORD = 'bobs own password';
// The user store needs a key once it has users.
const KEYS = new Keyring(new Map([[1, crypto.randomBytes(32)]]));

// Reads the store on disk, as another program would: the rows of a query.
function rows(dataDir, query, ...params) {
  const sql = new DatabaseSync(path.join(dataDir, DB_FILE), { readOnly: true });
  try {
    return sql.prepare(query).all(...params);
  } finally {
    sql.close();
  }
}
// A user's row on disk (kind 'config' for the second-factor record of a config user), or null.
const row = (dataDir, name, kind = 'store') => rows(dataDir, 'SELECT * FROM users WHERE kind = ? AND name_key = ?', kind, name.toLowerCase())[0] ?? null;
// The devices of a user on disk.
const diskDevices = (dataDir, name, kind = 'store') => rows(dataDir, 'SELECT d.* FROM devices d JOIN users u ON u.id = d.user_id WHERE u.kind = ? AND u.name_key = ? ORDER BY d.rowid', kind, name.toLowerCase());
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

// timeoutMs: how long a write waits for another program that holds the store.
async function setup({ users = true, storeUsers = true, mode = 'full', site, hasher = fakeHasher, timeoutMs } = {}) {
  const dataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'account-'));
  const hash = await hashPassword(PASSWORD, undefined, fakeHasher);
  const config = loadConfig(`${users ? `users:\n  - name: Alice\n    password_hash: '${hash}'\n    role: admin\n` : ''}nodes:\n  - address: a.test:1\n`);
  const clock = { t: NOW };
  const now = () => clock.t;
  const warnings = [];
  const store = await UserStore.open({ keys: KEYS, dataDir, configUsers: config.users, warn: (w) => warnings.push(w), now, ...(timeoutMs ? { timeoutMs } : {}) });
  // Peppered as the website makes it, so that no sign in here moves it to the current key.
  if (storeUsers) await store.createUser({ name: 'bob', role: 'manage', passwordHash: await hashPassword(BOB_PASSWORD, undefined, fakeHasher, store.currentPepper()) });
  const audit = createAudit({ dataDir, now });
  const failures = createFailureLog({ dataDir, now });
  // The pace of a name under attack is tested in login.test.js; here it does not hold tests back.
  const login = createLogin({ users: config.users, store, settings: config.login, hasher, now, audit, failures, sleep: async () => {} });
  const monitor = new Monitor({ targets: config.targets, dataDir, probeFn: async () => ({ up: true, ms: 1 }) });
  const server = createApp({ monitor, publicDir, login, mode, ...(site ? { site } : {}) });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  return {
    port, clock, store, login, audit, failures, dataDir, warnings,
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
const form = (o) => new URLSearchParams(o).toString();
const postForm = (s, p, fields, cookie) => request(s.port, { method: 'POST', path: p, headers: { ...FORM, ...(cookie ? { Cookie: cookie } : {}) }, body: form(fields) });
const api = (s, p, body, cookie, headers = JSON_HEADERS) => request(s.port, { method: 'POST', path: p, headers: { ...headers, ...(cookie ? { Cookie: cookie } : {}) }, body: typeof body === 'string' ? body : JSON.stringify(body) });
const get = (s, p, cookie) => request(s.port, { path: p, headers: cookie ? { Cookie: cookie } : {} });
const cookieOf = (r) => (r.headers['set-cookie']?.[0] ?? '').split(';')[0];
// The known-device cookie a sign in set, as "name=value".
const deviceOf = (r) => (r.headers['set-cookie'] ?? []).map((c) => c.split(';')[0]).find((c) => c.startsWith(`${DEVICE_COOKIE}=`)) ?? '';

// device: a known-device cookie to send along.
async function logIn(s, name = 'alice', password = PASSWORD, device = null) {
  const r = await postForm(s, '/login', { name, password }, device);
  return { r, cookie: cookieOf(r), device: deviceOf(r) };
}

// Turns TOTP on for the signed-in user; returns the secret and the recovery codes. The clock then
// moves on a step, so the code used to turn it on is not the one the next sign in needs.
async function enableTotp(s, cookie, password = PASSWORD) {
  const setup = await api(s, '/api/account/totp/setup', { password }, cookie);
  assert.equal(setup.status, 200, setup.text);
  const { secret } = setup.json();
  const on = await api(s, '/api/account/totp/enable', { code: totp(base32Decode(secret), s.clock.t) }, cookie);
  assert.equal(on.status, 200, on.text);
  s.clock.t += 30_000;
  return { secret, codes: on.json().recoveryCodes };
}

const codeNow = (s, secret, offset = 0) => hotp(base32Decode(secret), stepAt(s.clock.t) + offset);
const auditLines = async (s) => (await fs.readFile(s.audit.file, 'utf8').catch(() => '')).trim().split('\n').filter(Boolean).map((l) => JSON.parse(l));
// The audit lines without the devices added by each sign in (every sign in here is from a new browser).
const changeLines = async (s) => (await auditLines(s)).filter((l) => l.event !== 'device-added');
const failureLines = async (s) => {
  await s.failures.flush();
  return (await fs.readFile(s.failures.file, 'utf8').catch(() => '')).trim().split('\n').filter(Boolean).map((l) => JSON.parse(l));
};

// A full sign in with a second factor: password, then code. Gives the cookie.
async function logInWithCode(s, secret, name = 'alice', password = PASSWORD) {
  const first = await postForm(s, '/login', { name, password });
  assert.equal(first.status, 200);
  const second = await postForm(s, '/login/code', { pending: first.json().pending, code: codeNow(s, secret) });
  assert.equal(second.status, 200, second.text);
  return cookieOf(second);
}

test('without a second factor the login is as before, and /api/account says who is signed in, without secrets', async () => {
  const s = await setup();
  try {
    const { r, cookie } = await logIn(s);
    assert.equal(r.status, 200);
    assert.deepEqual(r.json(), { ok: true, name: 'Alice' });
    const a = await get(s, '/api/account', cookie);
    assert.equal(a.status, 200);
    assert.equal(a.headers['cache-control'], 'private, no-store');
    const body = a.json();
    assert.equal(body.name, 'Alice');
    assert.equal(body.role, 'admin');
    assert.equal(body.managedByConfig, true);
    assert.equal(body.canChangePassword, false);
    assert.equal(body.recentSignIn, true);
    assert.deepEqual(body.totp, { enabled: false, recoveryCodesLeft: 0 });
    assert.equal(body.sessions.length, 1);
    assert.equal(body.sessions[0].current, true);
    assert.equal(a.text.includes(cookie.split('=')[1]), false, 'no session id in the answer');
    const b = await logIn(s, 'bob', BOB_PASSWORD);
    const bob = (await get(s, '/api/account', b.cookie)).json();
    assert.equal(bob.role, 'manage');
    assert.equal(bob.managedByConfig, false);
    assert.equal(bob.canChangePassword, true);
    assert.equal((await get(s, '/api/account')).status, 401);
  } finally {
    await s.close();
  }
});

test('the /account page is served with the strict policy on a site with users, and not without', async () => {
  const s = await setup();
  try {
    const page = await get(s, '/account');
    assert.equal(page.status, 200);
    assert.match(page.headers['content-security-policy'], /script-src 'self'/);
    assert.match(page.text, /<h1>Account<\/h1>/);
    assert.match(page.text, /src="\/account-page\.js"/);
    assert.equal((await get(s, '/account/')).status, 200);
  } finally {
    await s.close();
  }
  const none = await setup({ users: false, storeUsers: false });
  try {
    assert.equal((await get(none, '/account')).status, 404);
    assert.equal((await get(none, '/api/account')).status, 404);
    assert.equal((await api(none, '/api/account/reauth', { password: 'x' })).status, 405);
    assert.equal((await postForm(none, '/login/code', { pending: 'x', code: '123456' })).status, 405);
  } finally {
    await none.close();
  }
});

test('the account page of a status-only site links to nothing that is not there', async () => {
  const s = await setup({ mode: 'status', site: { name: 'Mesh <b>', logo: null, links: [], description: null, footer: null, url: null } });
  try {
    const page = await get(s, '/account');
    assert.equal(page.status, 200);
    assert.match(page.text, /<title>Account - Mesh &lt;b&gt;<\/title>/);
    const nav = /<nav class="links"[^>]*>([\s\S]*?)<\/nav>/.exec(page.text)[1];
    assert.doesNotMatch(nav, /\/join|\/downloads/);
    assert.doesNotMatch(/<footer>[\s\S]*<\/footer>/.exec(page.text)[0], /\/join|\/downloads/);
  } finally {
    await s.close();
  }
});

test('website users can sign in, and with only website users the site has a login', async () => {
  const s = await setup({ users: false });
  try {
    assert.deepEqual((await get(s, '/api/session')).json(), { enabled: true, name: null });
    const { r } = await logIn(s, 'BOB', BOB_PASSWORD);
    assert.deepEqual(r.json(), { ok: true, name: 'bob' });
    assert.equal((await logIn(s, 'bob', 'wrong')).r.status, 401);
  } finally {
    await s.close();
  }
});

test('with TOTP on, the password gives a second step and no session; the right code signs in', async () => {
  const s = await setup();
  try {
    const { cookie } = await logIn(s);
    const { secret } = await enableTotp(s, cookie);
    const first = await postForm(s, '/login', { name: 'alice', password: PASSWORD });
    assert.equal(first.status, 200);
    assert.equal(first.headers['set-cookie'], undefined);
    const body = first.json();
    assert.equal(body.ok, false);
    assert.equal(body.secondFactor, true);
    assert.match(body.pending, /^[A-Za-z0-9_-]{43}$/);
    assert.equal(body.expiresIn, PENDING_MS / 1000);
    // A wrong password gets the same answer as before: nothing says a second factor is on.
    const wrong = await postForm(s, '/login', { name: 'alice', password: 'nope' });
    assert.equal(wrong.status, 401);
    assert.deepEqual(wrong.json(), { error: LOGIN_FAILED });
    const bad = await postForm(s, '/login/code', { pending: body.pending, code: codeNow(s, secret, 5) });
    assert.equal(bad.status, 401);
    assert.deepEqual(bad.json(), { error: CODE_FAILED });
    const good = await postForm(s, '/login/code', { pending: body.pending, code: codeNow(s, secret) });
    assert.equal(good.status, 200);
    assert.deepEqual(good.json(), { ok: true, name: 'Alice' });
    const c = cookieOf(good);
    assert.match(good.headers['set-cookie'][0], /HttpOnly; Secure; SameSite=Strict/);
    assert.deepEqual((await get(s, '/api/session', c)).json(), { enabled: true, name: 'Alice' });
    // The token is used up.
    const again = await postForm(s, '/login/code', { pending: body.pending, code: codeNow(s, secret, 1) });
    assert.equal(again.status, 401);
    assert.equal(again.json().restart, true);
    // The sign in time is kept for the account page.
    assert.equal((await get(s, '/api/account', c)).json().lastLogin, new Date(s.clock.t).toISOString());
  } finally {
    await s.close();
  }
});

test('a used code is refused (replay), also from the step before; the next step works', async () => {
  const s = await setup();
  try {
    const { cookie } = await logIn(s);
    const { secret } = await enableTotp(s, cookie);
    const code = codeNow(s, secret);
    await logInWithCode(s, secret);
    const first = await postForm(s, '/login', { name: 'alice', password: PASSWORD });
    const replay = await postForm(s, '/login/code', { pending: first.json().pending, code });
    assert.equal(replay.status, 401);
    // The code before the used one is older still: refused too.
    const older = await postForm(s, '/login/code', { pending: first.json().pending, code: codeNow(s, secret, -1) });
    assert.equal(older.status, 401);
    s.clock.t += 30_000;
    const next = await postForm(s, '/login/code', { pending: first.json().pending, code: codeNow(s, secret) });
    assert.equal(next.status, 200);
  } finally {
    await s.close();
  }
});

test('two requests at once with one right code: only one signs in', async () => {
  const s = await setup();
  try {
    const { cookie } = await logIn(s);
    const { secret } = await enableTotp(s, cookie);
    const a = (await postForm(s, '/login', { name: 'alice', password: PASSWORD })).json().pending;
    const b = (await postForm(s, '/login', { name: 'alice', password: PASSWORD })).json().pending;
    const code = codeNow(s, secret);
    const [ra, rb] = await Promise.all([postForm(s, '/login/code', { pending: a, code }), postForm(s, '/login/code', { pending: b, code })]);
    assert.deepEqual([ra.status, rb.status].sort(), [200, 401]);
  } finally {
    await s.close();
  }
});

test('wrong codes: five per second step, then the wait per user starts, and they count for the address', async () => {
  const s = await setup();
  try {
    const { cookie } = await logIn(s);
    const { secret } = await enableTotp(s, cookie);
    const pending = async () => (await postForm(s, '/login', { name: 'alice', password: PASSWORD })).json().pending;
    const wrong = codeNow(s, secret, 7);
    const p1 = await pending();
    for (let i = 0; i < 4; i++) assert.equal((await postForm(s, '/login/code', { pending: p1, code: wrong })).status, 401);
    // The fifth wrong code ends this second step: back to the password.
    const fifth = await postForm(s, '/login/code', { pending: p1, code: wrong });
    assert.equal(fifth.status, 401);
    assert.deepEqual(fifth.json(), { error: CODE_EXPIRED, restart: true });
    assert.equal(s.login.addresses.count(ipKey('127.0.0.1')), 5);
    // A new password does not start the count again: the sixth wrong code starts the wait.
    const p2 = await pending();
    assert.equal((await postForm(s, '/login/code', { pending: p2, code: wrong })).status, 401);
    const waiting = await postForm(s, '/login/code', { pending: p2, code: codeNow(s, secret) });
    assert.equal(waiting.status, 429);
    assert.ok(Number(waiting.headers['retry-after']) >= 1);
    // The wrong codes are summed up in the failures log, without the codes; not in the audit log.
    const lines = await failureLines(s);
    assert.deepEqual(lines.map((l) => [l.event, l.user, l.failures, l.addresses]), [['second-factor-failures', 'Alice', 6, 1]]);
    assert.equal(JSON.stringify(lines).includes(wrong), false);
    assert.equal((await auditLines(s)).some((l) => l.event.includes('failures')), false);
    // After the wait the right code works, and it clears the count.
    s.clock.t += 2000;
    assert.equal((await postForm(s, '/login/code', { pending: p2, code: codeNow(s, secret) })).status, 200);
    assert.equal(s.login.codeUsers.count('user:alice'), 0);
    assert.equal(s.login.codes.count(`user:alice|${ipKey('127.0.0.1')}`), 0);
  } finally {
    await s.close();
  }
});

test('the second step ends after 5 minutes, and only works from the address that gave the password', async () => {
  const s = await setup();
  try {
    const { cookie } = await logIn(s);
    const { secret } = await enableTotp(s, cookie);
    const p = (await postForm(s, '/login', { name: 'alice', password: PASSWORD })).json().pending;
    s.clock.t += PENDING_MS;
    const late = await postForm(s, '/login/code', { pending: p, code: codeNow(s, secret) });
    assert.equal(late.status, 401);
    assert.equal(late.json().restart, true);
    for (const bad of ['', 'x', 'a'.repeat(43), 'a'.repeat(5000)]) {
      const r = await postForm(s, '/login/code', { pending: bad, code: codeNow(s, secret) });
      assert.ok([400, 401, 413].includes(r.status), `${bad.length}: ${r.status}`);
    }
    // Another address with the token gets nothing.
    const { token, methods } = s.login.startSecondFactor('Alice', '192.0.2.1', { epoch: s.login.epochOf('alice') });
    assert.deepEqual(methods, ['totp', 'recovery']);
    assert.deepEqual(await s.login.finishSecondFactor(token, { code: codeNow(s, secret) }, '192.0.2.2'), { ok: false, reason: 'expired' });
    const r = await s.login.finishSecondFactor(token, { code: codeNow(s, secret) }, '192.0.2.1');
    assert.equal(r.ok, true);
    // Only a few second steps are open per user: older ones are dropped.
    const tokens = Array.from({ length: 7 }, () => s.login.startSecondFactor('Alice', '192.0.2.1', { epoch: s.login.epochOf('alice') }).token);
    assert.equal([...s.login.pending.values()].filter((x) => x.name === 'Alice').length, 5);
    assert.equal(s.login.pending.has(tokens[0]), false);
    assert.equal(s.login.pending.has(tokens[6]), true);
  } finally {
    await s.close();
  }
});

test('a recovery code signs in once, is counted down, and its use is in the audit log', async () => {
  const s = await setup();
  try {
    const { cookie } = await logIn(s);
    const { codes } = await enableTotp(s, cookie);
    const p = (await postForm(s, '/login', { name: 'alice', password: PASSWORD })).json().pending;
    const ok = await postForm(s, '/login/code', { pending: p, recovery: codes[0].toUpperCase() });
    assert.equal(ok.status, 200);
    const c = cookieOf(ok);
    assert.equal((await get(s, '/api/account', c)).json().totp.recoveryCodesLeft, 9);
    const p2 = (await postForm(s, '/login', { name: 'alice', password: PASSWORD })).json().pending;
    const again = await postForm(s, '/login/code', { pending: p2, recovery: codes[0] });
    assert.equal(again.status, 401);
    const used = (await auditLines(s)).filter((l) => l.event === 'recovery-code-used');
    assert.equal(used.length, 1);
    assert.equal(used[0].left, 9);
    assert.equal((await fs.readFile(s.audit.file, 'utf8')).includes(codes[0]), false);
    assert.equal((await postForm(s, '/login/code', { pending: p2 })).status, 400);
  } finally {
    await s.close();
  }
});

test('account changes only come from the page itself, as JSON with the header, from a signed-in user', async () => {
  const s = await setup();
  try {
    const { cookie } = await logIn(s);
    const p = '/api/account/totp/setup';
    const noHeader = { 'Content-Type': 'application/json', 'Sec-Fetch-Site': 'same-origin' };
    assert.equal((await api(s, p, {}, cookie, noHeader)).status, 403);
    assert.equal((await api(s, p, {}, cookie, { ...JSON_HEADERS, 'Sec-Fetch-Site': 'cross-site' })).status, 403);
    assert.equal((await api(s, p, {}, cookie, { 'Content-Type': 'application/json', 'X-Rettui-Request': '1', Origin: 'https://evil.test', Host: 'example.test' })).status, 403);
    assert.equal((await api(s, p, 'a=1', cookie, { ...JSON_HEADERS, 'Content-Type': 'application/x-www-form-urlencoded' })).status, 415);
    assert.equal((await api(s, p, 'text/plain', cookie, { ...JSON_HEADERS, 'Content-Type': 'text/plain' })).status, 415);
    assert.equal((await api(s, p, '{oops', cookie)).status, 400);
    assert.equal((await api(s, p, '[1]', cookie)).status, 400);
    // A new passkey's answer is several kilobytes: the limit is 16 KiB.
    assert.notEqual((await api(s, p, JSON.stringify({ x: 'y'.repeat(5000) }), cookie)).status, 413);
    assert.equal((await api(s, p, JSON.stringify({ x: 'y'.repeat(16384) }), cookie)).status, 413);
    assert.equal((await api(s, p, {})).status, 401);
    assert.equal((await api(s, p, {}, `${COOKIE}=${'a'.repeat(43)}`)).status, 401);
    assert.equal((await api(s, '/api/account/nothing', {}, cookie)).status, 405);
    // None of them changed anything.
    assert.equal(s.store.factorRecord('alice').totp, null);
    assert.equal((await api(s, p, { password: PASSWORD }, cookie)).status, 200);
  } finally {
    await s.close();
  }
});

test('changes need a sign in from the last 15 minutes; the password again makes it recent', async () => {
  const s = await setup();
  try {
    const { cookie } = await logIn(s);
    s.clock.t += RECENT_AUTH_MS;
    const stale = await api(s, '/api/account/totp/setup', {}, cookie);
    assert.equal(stale.status, 403);
    assert.deepEqual(stale.json(), { error: 'Enter your password again to do this.', reauth: true });
    assert.equal((await get(s, '/api/account', cookie)).json().recentSignIn, false);
    const wrong = await api(s, '/api/account/reauth', { password: 'nope' }, cookie);
    assert.equal(wrong.status, 400);
    assert.equal((await api(s, '/api/account/reauth', {}, cookie)).status, 400);
    const ok = await api(s, '/api/account/reauth', { password: PASSWORD }, cookie);
    assert.equal(ok.status, 200);
    assert.equal(ok.json().recentUntil, new Date(s.clock.t + RECENT_AUTH_MS).toISOString());
    assert.equal((await api(s, '/api/account/totp/setup', { password: PASSWORD }, cookie)).status, 200);
    // Wrong passwords here count, for this session.
    for (let i = 0; i < 6; i++) await api(s, '/api/account/reauth', { password: 'nope' }, cookie);
    assert.equal((await api(s, '/api/account/reauth', { password: PASSWORD }, cookie)).status, 429);
  } finally {
    await s.close();
  }
});

test('set up gives the secret once, to its owner, and never again; it turns on only with a right code', async () => {
  const s = await setup();
  try {
    const { cookie } = await logIn(s);
    // The password is needed in the request itself, not only a recent sign in.
    assert.equal((await api(s, '/api/account/totp/setup', {}, cookie)).status, 400);
    assert.equal((await api(s, '/api/account/totp/setup', { password: 'nope' }, cookie)).status, 400);
    assert.equal(s.store.factorRecord('alice').totp, null);
    const setup = await api(s, '/api/account/totp/setup', { password: PASSWORD }, cookie);
    const { secret, uri, qr } = setup.json();
    assert.match(secret, /^[A-Z2-7]{32}$/);
    assert.equal(uri, `otpauth://totp/rettui%20status:Alice?secret=${secret}&issuer=rettui%20status&algorithm=SHA1&digits=6&period=30`);
    assert.ok(qr.size >= 21);
    assert.equal(qr.rows.length, qr.size);
    assert.match(qr.rows[0], /^[01]+$/);
    assert.equal(setup.headers['cache-control'], 'no-store');
    const after = await get(s, '/api/account', cookie);
    assert.equal(after.text.includes(secret), false);
    assert.equal(after.json().totp.enabled, false);
    // Turning on needs the code; a wrong one is refused and counted.
    const bad = await api(s, '/api/account/totp/enable', { code: '000000' }, cookie);
    assert.equal(bad.status, 400);
    assert.equal(s.login.codeUsers.count('user:alice'), 1);
    assert.equal((await api(s, '/api/account/totp/enable', { code: 123456 }, cookie)).status, 400);
    const on = await api(s, '/api/account/totp/enable', { code: totp(base32Decode(secret), s.clock.t) }, cookie);
    assert.equal(on.status, 200);
    assert.equal(on.json().recoveryCodes.length, 10);
    assert.equal((await api(s, '/api/account/totp/setup', { password: PASSWORD }, cookie)).status, 409);
    assert.equal((await api(s, '/api/account/totp/enable', { code: '000000' }, cookie)).status, 409);
    // Kept in the store under the config user's name, encrypted; the secret is never in the audit log.
    const disk = row(s.dataDir, 'alice', 'config');
    assert.equal(disk.name, 'Alice');
    assert.equal(disk.totp_enabled, 1);
    const raw = base32Decode(secret);
    assert.equal((await diskBytes(s.dataDir)).includes(raw), false, 'the secret is not on disk as it is');
    assert.equal((await diskBytes(s.dataDir)).includes(Buffer.from(secret)), false);
    const audit = await fs.readFile(s.audit.file, 'utf8');
    assert.equal(audit.includes(secret), false);
    assert.deepEqual((await changeLines(s)).map((l) => l.event), ['totp-enabled']);
    if (process.platform !== 'win32') assert.equal((await fs.stat(s.audit.file)).mode & 0o777, 0o600);
    // Enable without a set up first.
    const b = await logIn(s, 'bob', BOB_PASSWORD);
    assert.equal((await api(s, '/api/account/totp/enable', { code: '123456' }, b.cookie)).status, 409);
  } finally {
    await s.close();
  }
});

test('with TOTP on, sensitive changes need the password AND a code (or a recovery code); neither alone', async () => {
  const s = await setup();
  try {
    const { cookie } = await logIn(s);
    const { secret, codes } = await enableTotp(s, cookie);
    const p = '/api/account/recovery-codes';
    // The password alone, or a code alone: refused, and nothing changes. (At most five of these
    // an hour from one session: the rest is asked from a second one.)
    const pwOnly = await api(s, p, { password: PASSWORD }, cookie);
    assert.equal(pwOnly.status, 400);
    assert.deepEqual(pwOnly.json(), { error: 'Enter the code from your app as well, or a recovery code.', field: 'code', secondFactor: true, methods: ['totp', 'recovery'] });
    const codeOnly = await api(s, p, { code: codeNow(s, secret) }, cookie);
    assert.equal(codeOnly.status, 400);
    assert.equal(codeOnly.json().field, 'password');
    // A wrong password does not use up the code; a wrong code counts like one at sign in.
    assert.equal((await api(s, p, { password: 'nope', code: codeNow(s, secret) }, cookie)).status, 400);
    assert.equal(s.login.codeUsers.count('user:alice'), 0);
    const wrongCode = await api(s, p, { password: PASSWORD, code: codeNow(s, secret, 4) }, cookie);
    assert.equal(wrongCode.status, 400);
    assert.equal(wrongCode.json().field, 'code');
    assert.equal(s.login.codeUsers.count('user:alice'), 1);
    assert.equal(s.store.useRecoveryCode('alice', codes[0]).ok, true, 'the old codes still work: nothing changed');
    // Both: new codes.
    const code = codeNow(s, secret);
    const fresh = await api(s, p, { password: PASSWORD, code }, cookie);
    assert.equal(fresh.status, 200, fresh.text);
    const newCodes = fresh.json().recoveryCodes;
    assert.equal(newCodes.length, 10);
    assert.equal(s.store.useRecoveryCode('alice', codes[1]).ok, false);
    // The same code again is a replay, refused (also from another session).
    s.clock.t += 30_000;
    const c2 = await logInWithCode(s, secret);
    const replay = await api(s, p, { password: PASSWORD, code }, c2);
    assert.equal(replay.status, 400);
    assert.equal(replay.json().field, 'code');
    // Turning it off: the same rules; a recovery code works instead of the app's code, once.
    assert.equal((await api(s, '/api/account/totp/disable', { password: PASSWORD }, c2)).status, 400);
    assert.equal((await api(s, '/api/account/totp/disable', { code: codeNow(s, secret, 1) }, c2)).status, 400);
    assert.equal((await api(s, '/api/account/totp/disable', { password: PASSWORD, recovery: 'aaaa-bbbb-cccc-dddd' }, c2)).status, 400);
    assert.equal(s.store.secondFactorEnabled('alice'), true);
    const off = await api(s, '/api/account/totp/disable', { password: PASSWORD, recovery: newCodes[0] }, c2);
    assert.equal(off.status, 200, off.text);
    assert.equal(s.store.secondFactorEnabled('alice'), false);
    assert.equal((await api(s, p, { password: PASSWORD }, c2)).status, 409);
    // On again, and off with the password and the app's code.
    s.clock.t += 30_000;
    const again = await enableTotp(s, c2);
    assert.equal((await api(s, '/api/account/totp/disable', { password: PASSWORD, code: codeNow(s, again.secret) }, c2)).status, 200);
    const events = (await changeLines(s)).map((l) => `${l.event}${l.with ? `:${l.with}` : ''}`);
    assert.deepEqual(events, ['totp-enabled', 'recovery-codes-regenerated:password+code', 'recovery-code-used', 'totp-disabled:password+recovery', 'totp-enabled', 'totp-disabled:password+code']);
    // Off again: the password alone signs in.
    assert.deepEqual((await logIn(s)).r.json(), { ok: true, name: 'Alice' });
  } finally {
    await s.close();
  }
});

test('without TOTP, the password alone confirms a password change; with it, the code is needed too', async () => {
  const s = await setup();
  try {
    const b = await logIn(s, 'bob', BOB_PASSWORD);
    // The password from the step-up dialog (password); the older field name (current) still works.
    assert.equal((await api(s, '/api/account/password', { password: BOB_PASSWORD, next: 'bobs second password' }, b.cookie)).status, 200);
    assert.equal((await api(s, '/api/account/password', { current: 'bobs second password', next: 'bobs third password' }, b.cookie)).status, 200);
    const { secret } = await enableTotp(s, b.cookie, 'bobs third password');
    const pwOnly = await api(s, '/api/account/password', { password: 'bobs third password', next: 'bobs fourth password' }, b.cookie);
    assert.equal(pwOnly.status, 400);
    assert.equal(pwOnly.json().field, 'code');
    assert.equal((await api(s, '/api/account/password', { code: codeNow(s, secret), next: 'bobs fourth password' }, b.cookie)).status, 400);
    assert.equal((await logIn(s, 'bob', 'bobs fourth password')).r.status, 401);
    const both = await api(s, '/api/account/password', { password: 'bobs third password', code: codeNow(s, secret), next: 'bobs fourth password' }, b.cookie);
    assert.equal(both.status, 200, both.text);
    const lines = (await changeLines(s)).filter((l) => l.event === 'password-changed').map((l) => l.with);
    assert.deepEqual(lines, ['password', 'password', 'password+code']);
  } finally {
    await s.close();
  }
});

test('password change: website users only, with the current password; other sessions end', async () => {
  const s = await setup();
  try {
    const alice = await logIn(s);
    const cfg = await api(s, '/api/account/password', { current: PASSWORD, next: 'something new 1' }, alice.cookie);
    assert.equal(cfg.status, 409);
    const b1 = await logIn(s, 'bob', BOB_PASSWORD);
    const b2 = await logIn(s, 'bob', BOB_PASSWORD);
    assert.equal((await api(s, '/api/account/password', { current: BOB_PASSWORD, next: 'short' }, b1.cookie)).status, 400);
    assert.equal((await api(s, '/api/account/password', { current: BOB_PASSWORD, next: BOB_PASSWORD }, b1.cookie)).status, 400);
    assert.equal((await api(s, '/api/account/password', { current: BOB_PASSWORD, next: 'x'.repeat(1025) }, b1.cookie)).status, 400);
    const wrong = await api(s, '/api/account/password', { current: 'nope', next: 'a brand new one' }, b1.cookie);
    assert.equal(wrong.status, 400);
    assert.equal(wrong.json().error, 'The current password is wrong.');
    const ok = await api(s, '/api/account/password', { current: BOB_PASSWORD, next: 'a brand new one' }, b1.cookie);
    assert.equal(ok.status, 200);
    assert.deepEqual((await get(s, '/api/session', b1.cookie)).json().name, 'bob');
    assert.deepEqual((await get(s, '/api/session', b2.cookie)).json().name, null);
    assert.equal((await logIn(s, 'bob', BOB_PASSWORD)).r.status, 401);
    assert.equal((await logIn(s, 'bob', 'a brand new one')).r.status, 200);
    // Kept on disk.
    const again = await UserStore.open({ keys: KEYS, dataDir: s.dataDir, warn: () => {} });
    assert.ok(again.find('bob'));
    const lines = await changeLines(s);
    assert.deepEqual(lines.map((l) => [l.event, l.user]), [['password-changed', 'bob']]);
    assert.equal(JSON.stringify(lines).includes('a brand new one'), false);
  } finally {
    await s.close();
  }
});

test('sessions of the user are listed, and nobody else\'s', async () => {
  const s = await setup();
  try {
    const a1 = await logIn(s);
    s.clock.t += 1000;
    await logIn(s);
    await logIn(s, 'bob', BOB_PASSWORD);
    const list = (await get(s, '/api/account', a1.cookie)).json().sessions;
    assert.equal(list.length, 2);
    assert.deepEqual(list.map((x) => x.current), [true, false]);
    for (const x of list) assert.deepEqual(Object.keys(x).sort(), ['created', 'current', 'lastSeen']);
  } finally {
    await s.close();
  }
});

test('outsiders failing a name cannot hold back the signed-in owner, whose own wrong passwords count for the session', async () => {
  const s = await setup();
  try {
    const { cookie, device } = await logIn(s);
    // Wrong passwords for alice from many addresses, enough to use up the pace of the name.
    for (let i = 0; i < 40; i++) await s.login.attempt('alice', 'nope', `198.51.100.${i}`);
    assert.equal((await api(s, '/api/account/reauth', { password: PASSWORD }, cookie)).status, 200);
    // A browser she never signed in from waits like everyone else...
    const paced = await logIn(s);
    assert.equal(paced.r.status, 429);
    assert.match(paced.r.json().error, /^Too many sign ins for this name right now\. Try again in \d+ seconds?\.$/);
    // ...but the one she signed in from before, a known device, gets in at once.
    assert.equal((await logIn(s, 'alice', PASSWORD, device)).r.status, 200);
    // Her own wrong passwords in the session start a wait for that session only.
    for (let i = 0; i < 6; i++) assert.equal((await api(s, '/api/account/reauth', { password: 'nope' }, cookie)).status, 400);
    const held = await api(s, '/api/account/reauth', { password: PASSWORD }, cookie);
    assert.equal(held.status, 429);
    assert.ok(Number(held.headers['retry-after']) >= 1);
    const other = await logIn(s, 'alice', PASSWORD, device);
    assert.equal((await api(s, '/api/account/reauth', { password: PASSWORD }, other.cookie)).status, 200);
  } finally {
    await s.close();
  }
});

test('turning TOTP on or off, and changing the password, sign out every other session; the button does it on its own', async () => {
  const s = await setup();
  try {
    const a1 = await logIn(s);
    const a2 = await logIn(s);
    const { secret } = await enableTotp(s, a1.cookie);
    assert.equal((await get(s, '/api/session', a2.cookie)).json().name, null, 'ended when TOTP was turned on');
    assert.equal((await get(s, '/api/session', a1.cookie)).json().name, 'Alice');
    const a3 = await logInWithCode(s, secret);
    s.clock.t += 30_000;
    assert.equal((await api(s, '/api/account/totp/disable', { password: PASSWORD, code: codeNow(s, secret) }, a1.cookie)).status, 200);
    assert.equal((await get(s, '/api/session', a3)).json().name, null, 'ended when TOTP was turned off');
    // Sign out other sessions.
    const b1 = await logIn(s, 'bob', BOB_PASSWORD);
    const b2 = await logIn(s, 'bob', BOB_PASSWORD);
    const b3 = await logIn(s, 'bob', BOB_PASSWORD);
    const ended = await api(s, '/api/account/sign-out-others', {}, b2.cookie);
    assert.equal(ended.status, 200);
    assert.deepEqual(ended.json(), { ok: true, ended: 2 });
    assert.equal((await get(s, '/api/session', b1.cookie)).json().name, null);
    assert.equal((await get(s, '/api/session', b3.cookie)).json().name, null);
    assert.equal((await get(s, '/api/session', b2.cookie)).json().name, 'bob');
    assert.equal((await get(s, '/api/session', a1.cookie)).json().name, 'Alice', 'nobody else is signed out');
    const events = (await auditLines(s)).filter((l) => l.event === 'sessions-ended');
    assert.deepEqual(events.map((l) => [l.user, l.ended]), [['bob', 2]]);
    // It needs a recent sign in like any change.
    s.clock.t += RECENT_AUTH_MS;
    assert.equal((await api(s, '/api/account/sign-out-others', {}, b2.cookie)).json().reauth, true);
  } finally {
    await s.close();
  }
});

test('an open second step from the old password is dropped by a password change or by turning TOTP off', async () => {
  const s = await setup();
  try {
    const b = await logIn(s, 'bob', BOB_PASSWORD);
    const { secret } = await enableTotp(s, b.cookie, BOB_PASSWORD);
    // Someone who has the old password gets as far as the code step.
    const stolen = (await postForm(s, '/login', { name: 'bob', password: BOB_PASSWORD })).json().pending;
    assert.ok(stolen);
    assert.equal((await api(s, '/api/account/password', { password: BOB_PASSWORD, code: codeNow(s, secret), next: 'a brand new one' }, b.cookie)).status, 200);
    s.clock.t += 30_000;
    const late = await postForm(s, '/login/code', { pending: stolen, code: codeNow(s, secret) });
    assert.equal(late.status, 401);
    assert.equal(late.json().restart, true);
    assert.equal(late.headers['set-cookie'], undefined);
    // The same after TOTP is turned off.
    const p = (await postForm(s, '/login', { name: 'bob', password: 'a brand new one' })).json().pending;
    s.clock.t += 30_000;
    assert.equal((await api(s, '/api/account/totp/disable', { password: 'a brand new one', code: codeNow(s, secret) }, b.cookie)).status, 200);
    assert.equal(s.login.pending.size, 0);
    s.clock.t += 30_000;
    assert.equal((await postForm(s, '/login/code', { pending: p, code: codeNow(s, secret) })).json().restart, true);
  } finally {
    await s.close();
  }
});

test('endUser ends sessions and second steps; a deleted user\'s session is dead, and the role shown is the current one', async () => {
  const s = await setup();
  try {
    const b1 = await logIn(s, 'bob', BOB_PASSWORD);
    const b2 = await logIn(s, 'bob', BOB_PASSWORD);
    assert.equal((await get(s, '/api/account', b1.cookie)).json().role, 'manage');
    await s.store.setRole('bob', 'viewer');
    assert.equal((await get(s, '/api/account', b1.cookie)).json().role, 'viewer');
    // Deleted from the store: the session is dead even before endUser is called.
    await s.store.deleteUser('bob');
    assert.equal((await get(s, '/api/session', b1.cookie)).json().name, null);
    assert.equal((await get(s, '/api/account', b2.cookie)).status, 401);
    assert.equal((await api(s, '/api/account/reauth', { password: BOB_PASSWORD }, b2.cookie)).status, 401);
    assert.equal(s.login.sessions.list('bob').length, 0, 'and the dead sessions are gone');
    // endUser: all sessions, or all but one, and the open second steps.
    const a1 = await logIn(s);
    const a2 = await logIn(s);
    s.login.startSecondFactor('Alice', '192.0.2.1', { epoch: s.login.epochOf('alice') });
    assert.equal(s.login.endUser('alice', s.login.session({ headers: { cookie: a1.cookie } }).id), 1);
    assert.equal(s.login.pending.size, 0);
    assert.equal((await get(s, '/api/session', a2.cookie)).json().name, null);
    assert.equal(s.login.endUser('Alice'), 1);
    assert.equal((await get(s, '/api/session', a1.cookie)).json().name, null);
  } finally {
    await s.close();
  }
});

test('turning TOTP on before it is set up is refused without touching the count of wrong codes', async () => {
  const s = await setup();
  try {
    const { cookie } = await logIn(s);
    for (let i = 0; i < 3; i++) s.login.codeUsers.fail('user:alice');
    const r = await api(s, '/api/account/totp/enable', { code: '123456' }, cookie);
    assert.equal(r.status, 409);
    assert.deepEqual(r.json(), { error: 'Set up two-step sign-in first.' });
    assert.equal(s.login.codeUsers.count('user:alice'), 3);
  } finally {
    await s.close();
  }
});

test('when wrong codes hold the code step back, the right password is told how long, and the password step is not blocked', async () => {
  const s = await setup();
  try {
    const { cookie, device } = await logIn(s);
    const { secret } = await enableTotp(s, cookie);
    // Someone with the password spends the free codes from one address, and one more: that address waits.
    for (let i = 0; i < 6; i++) await s.login.checkCode('Alice', '000000', '198.51.100.1');
    assert.equal((await s.login.checkCode('Alice', '000000', '198.51.100.1')).reason, 'throttled');
    // The owner, from her own address, is not held back by it.
    const fine = await postForm(s, '/login', { name: 'alice', password: PASSWORD });
    assert.equal(fine.status, 200);
    assert.equal(fine.json().codeWait, undefined);
    // From many addresses, past the free codes of the user: every browser that is not a known device waits.
    for (let i = 0; i < CODE_USER_FREE; i++) await s.login.checkCode('Alice', '000000', `203.0.113.${i}`);
    const short = await postForm(s, '/login', { name: 'alice', password: PASSWORD });
    assert.equal(short.status, 200);
    const body = short.json();
    assert.equal(body.secondFactor, true);
    assert.ok(body.codeWait >= 1);
    assert.match(body.notice, /^Too many wrong codes were entered for this account\. You can enter a code in \d+ seconds?\.$/);
    const now = await postForm(s, '/login/code', { pending: body.pending, code: codeNow(s, secret) });
    assert.equal(now.status, 429);
    assert.match(now.json().error, /^Too many wrong codes\. Try again in \d+ seconds?\.$/);
    // Her known device is not held back by the others' wrong codes.
    const mine = (await logIn(s, 'alice', PASSWORD, device)).r.json();
    assert.equal(mine.codeWait, undefined);
    // Once the wait is over the same token works.
    s.clock.t += body.codeWait * 1000;
    assert.equal((await postForm(s, '/login/code', { pending: body.pending, code: codeNow(s, secret) })).status, 200);
    // A wait longer than a second step can last: no token, a clear answer with the time.
    for (let i = 0; i < CODE_USER_FREE + 12; i++) {
      s.clock.t += s.login.codeUsers.wait('user:alice');
      await s.login.checkCode('Alice', '000000', `192.0.2.${i}`);
    }
    const long = await postForm(s, '/login', { name: 'alice', password: PASSWORD });
    assert.equal(long.status, 429);
    assert.equal(long.json().pending, undefined);
    assert.match(long.json().error, /^Too many wrong codes were entered for this account\. Sign in again in \d+ minutes\.$/);
    assert.ok(Number(long.headers['retry-after']) > PENDING_MS / 1000);
    // The password step itself was not counted as a failure.
    assert.equal(s.login.accounts.count(`user:alice|${ipKey('127.0.0.1')}`), 0);
    // The known device still signs in, password and code, up to the ceiling of wrong codes for the user.
    s.clock.t += 30_000;
    const first = await postForm(s, '/login', { name: 'alice', password: PASSWORD }, device);
    assert.equal(first.status, 200);
    const done = await postForm(s, '/login/code', { pending: first.json().pending, code: codeNow(s, secret) }, device);
    assert.equal(done.status, 200);
    // The device cookie alone is no sign in: a wrong password from it is refused.
    assert.equal((await logIn(s, 'alice', 'nope', device)).r.status, 401);
  } finally {
    await s.close();
  }
});

test('new recovery codes and TOTP changes are limited per session and per user; the answer says when to try again', async () => {
  const s = await setup();
  try {
    const a1 = await logIn(s);
    const { secret } = await enableTotp(s, a1.cookie);
    // Each with the password and a new code (a code works once).
    const both = () => {
      s.clock.t += 30_000;
      return { password: PASSWORD, code: codeNow(s, secret) };
    };
    for (let i = 0; i < 5; i++) assert.equal((await api(s, '/api/account/recovery-codes', both(), a1.cookie)).status, 200);
    const sixth = await api(s, '/api/account/recovery-codes', both(), a1.cookie);
    assert.equal(sixth.status, 429);
    assert.match(sixth.json().error, /^You did this too often\. Try again in \d+ minutes\.$/);
    assert.ok(Number(sixth.headers['retry-after']) > 0);
    // Wrong passwords count too, so they cannot be used to get round it.
    s.clock.t += 30_000;
    const a2 = { cookie: await logInWithCode(s, secret) };
    for (let i = 0; i < 4; i++) await api(s, '/api/account/recovery-codes', { password: 'nope', code: '000000' }, a2.cookie);
    assert.equal((await api(s, '/api/account/recovery-codes', both(), a2.cookie)).status, 200);
    // Ten for the user in all, whichever session asks.
    s.clock.t += 30_000;
    const a3 = { cookie: await logInWithCode(s, secret) };
    assert.equal((await api(s, '/api/account/recovery-codes', both(), a3.cookie)).status, 429);
    const regenerated = (await auditLines(s)).filter((l) => l.event === 'recovery-codes-regenerated');
    assert.equal(regenerated.length, 6);
    // Another action has its own count.
    assert.equal((await api(s, '/api/account/totp/disable', both(), a3.cookie)).status, 200);
  } finally {
    await s.close();
  }
});

test('a password change whose write fails changes nothing: old password, other sessions and second steps all stay', async () => {
  const s = await setup({ timeoutMs: 50 });
  try {
    const b1 = await logIn(s, 'bob', BOB_PASSWORD);
    const b2 = await logIn(s, 'bob', BOB_PASSWORD);
    // Another program holds the store for longer than a write waits.
    const release = holdLock(s.dataDir);
    let r;
    try {
      r = await api(s, '/api/account/password', { current: BOB_PASSWORD, next: 'a brand new one' }, b1.cookie);
    } finally {
      release();
    }
    assert.equal(r.status, 500);
    assert.equal(r.json().error, 'Another program is changing the user store; nothing was changed. Try again.');
    assert.equal((await get(s, '/api/session', b2.cookie)).json().name, 'bob');
    assert.equal((await logIn(s, 'bob', 'a brand new one')).r.status, 401);
    assert.equal((await logIn(s, 'bob', BOB_PASSWORD)).r.status, 200);
    assert.deepEqual((await changeLines(s)).map((l) => l.event), []);
    assert.equal((await api(s, '/api/account/password', { current: BOB_PASSWORD, next: 'a brand new one' }, b1.cookie)).status, 200);
    assert.equal((await get(s, '/api/session', b2.cookie)).json().name, null);
  } finally {
    await s.close();
  }
});

// A hasher that can be held: while hold() is in force, every check waits until let() is called.
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
// Ends a user's sessions right before the store's next write runs, as if they ended while it
// waited for the store.
function endAtNextWrite(s, name) {
  const db = s.store.db;
  const tx = db.tx;
  db.tx = (fn) => {
    db.tx = tx;
    s.login.endUser(name);
    return tx.call(db, fn);
  };
}
const devCookie = (r) => r.headers['set-cookie'].find((c) => c.startsWith(`${DEVICE_COOKIE}=`));
const both = (a) => `${a.cookie}; ${a.device}`;

test('a sign in sets the known-device cookie; only its SHA-256 is kept; the account page lists devices and removes them', async () => {
  const s = await setup();
  try {
    const b1 = await logIn(s, 'bob', BOB_PASSWORD);
    assert.match(devCookie(b1.r), new RegExp(`^${DEVICE_COOKIE}=[A-Za-z0-9_-]{22}; Path=/; Max-Age=15552000; HttpOnly; Secure; SameSite=Strict$`));
    const id = b1.device.split('=')[1];
    assert.equal((await diskBytes(s.dataDir)).includes(id), false, 'the id itself is never written');
    assert.deepEqual(diskDevices(s.dataDir, 'bob').map((d) => d.hash), [crypto.createHash('sha256').update(id).digest('hex')]);
    // Signing in again with it: the same device, its cookie renewed, no second one.
    s.clock.t += 60_000;
    const again = await logIn(s, 'bob', BOB_PASSWORD, b1.device);
    assert.equal(again.device, b1.device);
    assert.equal(s.store.devices('bob').length, 1);
    assert.equal(s.store.devices('bob')[0].lastUsed, new Date(s.clock.t).toISOString());
    // Two more browsers.
    const b2 = await logIn(s, 'bob', BOB_PASSWORD);
    const b3 = await logIn(s, 'bob', BOB_PASSWORD);
    const list = (await get(s, '/api/account', both(again))).json().devices;
    assert.equal(list.length, 3);
    for (const d of list) assert.deepEqual(Object.keys(d).sort(), ['created', 'current', 'id', 'lastUsed']);
    assert.deepEqual(list.map((d) => d.current), [true, false, false]);
    assert.equal(JSON.stringify(list).includes(id), false);
    // Remove one; a bad or unknown id is refused.
    assert.equal((await api(s, '/api/account/devices/remove', { device: 'nope' }, both(again))).status, 400);
    assert.equal((await api(s, '/api/account/devices/remove', { device: '0123456789abcdef' }, both(again))).status, 404);
    const gone = await api(s, '/api/account/devices/remove', { device: list[1].id }, both(again));
    assert.deepEqual(gone.json(), { ok: true, removed: 1, ended: 1 });
    assert.equal(s.store.hasDevice('bob', deviceHash(b2.device.split('=')[1])), false);
    // The removed device is signed out too; the others stay signed in.
    assert.equal((await get(s, '/api/session', b2.cookie)).json().name, null);
    assert.equal((await get(s, '/api/session', b3.cookie)).json().name, 'bob');
    // Remove all other devices keeps this browser only, and signs the others out.
    const b4 = await logIn(s, 'bob', BOB_PASSWORD);
    const others = await api(s, '/api/account/devices/remove-others', {}, both(again));
    assert.deepEqual(others.json(), { ok: true, removed: 2, ended: 2 });
    for (const b of [b3, b4]) assert.equal((await get(s, '/api/session', b.cookie)).json().name, null);
    assert.equal((await get(s, '/api/session', again.cookie)).json().name, 'bob');
    assert.deepEqual(s.store.devices('bob').map((d) => d.hash), [deviceHash(id)]);
    assert.equal(s.store.hasDevice('bob', deviceHash(b3.device.split('=')[1])), false);
    // On disk too.
    const after = await UserStore.open({ keys: KEYS, dataDir: s.dataDir, warn: () => {} });
    assert.equal(after.devices('bob').length, 1);
    const lines = await auditLines(s);
    // Only the first new device of the day is an audit line; the others are summed up in failures.log.
    assert.deepEqual(lines.filter((l) => l.event.startsWith('device')).map((l) => l.event), ['device-added', 'device-removed', 'devices-removed']);
    assert.deepEqual(lines.filter((l) => l.event.startsWith('device')).map((l) => l.ended), [undefined, 1, 2]);
    const added = (await failureLines(s)).filter((l) => l.event === 'device-added');
    assert.deepEqual(added.map((l) => [l.user, l.failures]), [['bob', 3]]);
    assert.equal(JSON.stringify(lines).includes(id), false);
    // They need a recent sign in like any change.
    s.clock.t += RECENT_AUTH_MS;
    assert.equal((await api(s, '/api/account/devices/remove-others', {}, both(again))).json().reauth, true);
  } finally {
    await s.close();
  }
});

test('devices: at most ten per user, the least recently used goes; a config user keeps them in its own record', async () => {
  const s = await setup();
  try {
    const first = await logIn(s);
    for (let i = 0; i < MAX_DEVICES + 2; i++) {
      s.clock.t += 1000;
      await logIn(s);
    }
    assert.equal(s.store.devices('alice').length, MAX_DEVICES);
    assert.equal(s.store.hasDevice('alice', deviceHash(first.device.split('=')[1])), false);
    assert.equal(row(s.dataDir, 'alice', 'config').name, 'Alice');
    assert.equal(row(s.dataDir, 'alice'), null, 'no website user is made for her');
    assert.equal(diskDevices(s.dataDir, 'alice', 'config').length, MAX_DEVICES);
  } finally {
    await s.close();
  }
});

test('a password change forgets every other device but this one; endUser forgets them all', async () => {
  const s = await setup();
  try {
    const b1 = await logIn(s, 'bob', BOB_PASSWORD);
    const b2 = await logIn(s, 'bob', BOB_PASSWORD);
    assert.equal(s.store.devices('bob').length, 2);
    assert.equal((await api(s, '/api/account/password', { current: BOB_PASSWORD, next: 'a brand new one' }, both(b1))).status, 200);
    assert.deepEqual(s.store.devices('bob').map((d) => d.hash), [deviceHash(b1.device.split('=')[1])]);
    // The forgotten one is no device any more: it waits like any other browser when the name is busy.
    for (let i = 0; i < 20; i++) await s.login.attempt('bob', 'nope', `198.51.100.${i}`);
    assert.equal((await logIn(s, 'bob', 'a brand new one', b2.device)).r.status, 429);
    assert.equal((await logIn(s, 'bob', 'a brand new one', b1.device)).r.status, 200);
    s.login.endUser('bob');
    assert.deepEqual(s.store.devices('bob'), []);
    assert.equal((await logIn(s, 'bob', 'a brand new one', b1.device)).r.status, 429);
  } finally {
    await s.close();
  }
});

test('new passwords need 12 characters, and not one of the most common ones or the name', async () => {
  const s = await setup();
  try {
    const b = await logIn(s, 'bob', BOB_PASSWORD);
    const change = (next) => api(s, '/api/account/password', { current: BOB_PASSWORD, next }, b.cookie);
    const short = await change('elevenchars');
    assert.equal(short.status, 400);
    assert.equal(short.json().error, 'The new password must be at least 12 characters.');
    for (const common of ['password1234', 'Password1234', '123456789012', 'QWERTY123456']) {
      const r = await change(common);
      assert.equal(r.status, 400, common);
      assert.match(r.json().error, /most common/);
    }
    assert.match((await change('zzzzzzzzzzzzzz')).json().error, /one character/);
    assert.match((await change('bob-bob-bob1')).json().error, /your name/);
    // Characters, not bytes: 12 letters of any script are enough.
    assert.equal((await change('ääääääöööööü')).status, 200);
  } finally {
    await s.close();
  }
});

test('a session ended while its change is under way changes nothing, hands out no secret, and gets 401', async () => {
  const h = holdable();
  const s = await setup({ hasher: h.hasher });
  try {
    const bob = () => s.login.session({ headers: { cookie: b.cookie } });
    let b = await logIn(s, 'bob', BOB_PASSWORD);
    // Set up: the password is being checked when the session ends.
    h.hold();
    let r = api(s, '/api/account/totp/setup', { password: BOB_PASSWORD }, b.cookie);
    await until(() => h.waiting() === 1);
    s.login.endUser('bob');
    h.let();
    r = await r;
    assert.equal(r.status, 401);
    assert.equal(r.json().signIn, true);
    assert.equal(r.text.includes('secret'), false);
    assert.equal(s.store.factorRecord('bob').totp, null);
    // Password change: ended while the new hash is made.
    b = await logIn(s, 'bob', BOB_PASSWORD);
    assert.ok(bob());
    h.hold();
    r = api(s, '/api/account/password', { current: BOB_PASSWORD, next: 'a brand new one' }, b.cookie);
    await until(() => h.waiting() === 1);
    h.let();
    // Let the current password pass, then hold the hash of the new one.
    h.hold();
    await until(() => h.waiting() === 1);
    s.login.endUser('bob');
    h.let();
    r = await r;
    assert.equal(r.status, 401);
    assert.equal((await logIn(s, 'bob', 'a brand new one')).r.status, 401);
    b = await logIn(s, 'bob', BOB_PASSWORD);
    assert.equal(b.r.status, 200);
    // Turning it on: the session ends right as the write starts, after the code was found right.
    const { secret } = (await api(s, '/api/account/totp/setup', { password: BOB_PASSWORD }, b.cookie)).json();
    endAtNextWrite(s, 'bob');
    r = await api(s, '/api/account/totp/enable', { code: totp(base32Decode(secret), s.clock.t) }, b.cookie);
    assert.equal(r.status, 401);
    assert.equal(r.text.includes('recoveryCodes'), false);
    assert.equal(s.store.secondFactorEnabled('bob'), false);
    assert.equal(s.login.codeUsers.count('user:bob'), 0, 'not counted as a wrong code');
    // Sign out others and devices of a session that is gone: nothing ends.
    b = await logIn(s, 'bob', BOB_PASSWORD);
    const other = await logIn(s, 'bob', BOB_PASSWORD);
    s.login.sessions.destroy(s.login.session({ headers: { cookie: b.cookie } }).id);
    assert.equal((await api(s, '/api/account/sign-out-others', {}, b.cookie)).status, 401);
    assert.equal((await get(s, '/api/session', other.cookie)).json().name, 'bob');
    // Reauth: the password is right, but the session ended while it was checked.
    s.clock.t += RECENT_AUTH_MS;
    h.hold();
    r = api(s, '/api/account/reauth', { password: BOB_PASSWORD }, other.cookie);
    await until(() => h.waiting() === 1);
    s.login.endUser('bob');
    h.let();
    assert.equal((await r).status, 401);
    const events = (await changeLines(s)).map((l) => l.event);
    assert.deepEqual(events, [], 'nothing was changed');
  } finally {
    await s.close();
  }
});

test('a sign in whose user changed while the password was checked gets no session', async () => {
  const h = holdable();
  const s = await setup({ hasher: h.hasher });
  try {
    h.hold();
    const r = postForm(s, '/login', { name: 'bob', password: BOB_PASSWORD });
    await until(() => h.waiting() === 1);
    await s.store.setPassword('bob', await hashPassword('a brand new one', undefined, fakeHasher));
    s.login.endUser('bob');
    h.let();
    const out = await r;
    assert.equal(out.status, 401);
    assert.equal(out.headers['set-cookie'], undefined);
    assert.equal(s.login.sessions.list('bob').length, 0);
  } finally {
    await s.close();
  }
});

test('asking for the password again is limited per session and per user; a right password does not reset it', async () => {
  const s = await setup();
  try {
    const a1 = await logIn(s);
    const reauth = (cookie, password = PASSWORD) => api(s, '/api/account/reauth', { password }, cookie);
    for (let i = 0; i < 3; i++) assert.equal((await reauth(a1.cookie, 'nope')).status, 400);
    for (let i = 3; i < REAUTHS_PER_SESSION; i++) assert.equal((await reauth(a1.cookie)).status, 200);
    const over = await reauth(a1.cookie);
    assert.equal(over.status, 429);
    assert.match(over.json().error, /^You did this too often\. Try again in \d+ minutes\.$/);
    assert.ok(Number(over.headers['retry-after']) > 0);
    // Other sessions of the user have their own count, up to the user's.
    const a2 = await logIn(s);
    for (let i = REAUTHS_PER_SESSION; i < REAUTHS_PER_USER; i++) assert.equal((await reauth(a2.cookie)).status, 200);
    const a3 = await logIn(s);
    assert.equal((await reauth(a3.cookie)).status, 429);
    // Another user is not held back by it.
    const b = await logIn(s, 'bob', BOB_PASSWORD);
    assert.equal((await reauth(b.cookie, BOB_PASSWORD)).status, 200);
    // An hour later it may be asked again.
    s.clock.t += 60 * 60_000;
    assert.equal((await reauth(a1.cookie)).status, 401, 'the session itself ended meanwhile');
  } finally {
    await s.close();
  }
});

test('a known device that signs in over and over is paced; its sign in times are written at most once a minute', async () => {
  const s = await setup();
  try {
    const first = await logIn(s, 'bob', BOB_PASSWORD);
    await s.store.flush();
    let writes = 0;
    const save = s.store.save.bind(s.store);
    s.store.save = (...args) => (writes++, save(...args));
    for (let i = 0; i < DEVICE_BURST; i++) assert.equal((await logIn(s, 'bob', BOB_PASSWORD, first.device)).r.status, 200);
    const paced = await logIn(s, 'bob', BOB_PASSWORD, first.device);
    assert.equal(paced.r.status, 429);
    assert.match(paced.r.json().error, /^Too many sign ins from this browser right now\. Try again in \d+ seconds?\.$/);
    assert.equal(writes, 0, 'the first sign in wrote the times this minute');
    // The times are in memory all the same, and written once the minute is over.
    s.clock.t += 60_000;
    assert.equal((await logIn(s, 'bob', BOB_PASSWORD, first.device)).r.status, 200);
    assert.equal(writes, 1);
    assert.equal(row(s.dataDir, 'bob').last_login, new Date(s.clock.t).toISOString());
    assert.equal(diskDevices(s.dataDir, 'bob')[0].last_used, new Date(s.clock.t).toISOString());
  } finally {
    await s.close();
  }
});

test('removing the device of this browser signs this browser out too', async () => {
  const s = await setup();
  try {
    const b1 = await logIn(s, 'bob', BOB_PASSWORD);
    const mine = (await get(s, '/api/account', both(b1))).json().devices.find((d) => d.current);
    const r = await api(s, '/api/account/devices/remove', { device: mine.id }, both(b1));
    assert.equal(r.status, 401);
    assert.equal(r.json().signIn, true);
    assert.equal((await get(s, '/api/session', b1.cookie)).json().name, null);
    assert.equal(s.store.devices('bob').length, 0);
  } finally {
    await s.close();
  }
});

test('the code step keeps the device id only when it is the device the password step found', async () => {
  const s = await setup();
  try {
    const a = await logIn(s);
    const { secret } = await enableTotp(s, both(a));
    const steps = async (loginCookie, codeCookie) => {
      const first = await postForm(s, '/login', { name: 'alice', password: PASSWORD }, loginCookie);
      assert.equal(first.status, 200);
      const second = await postForm(s, '/login/code', { pending: first.json().pending, code: codeNow(s, secret) }, codeCookie);
      assert.equal(second.status, 200, second.text);
      s.clock.t += 30_000;
      return second;
    };
    const idRe = new RegExp(`^${DEVICE_COOKIE}=[A-Za-z0-9_-]{22}$`);
    // The cookie dropped between the steps: a new device id, never "null".
    const dropped = await steps(a.device, undefined);
    assert.match(deviceOf(dropped), idRe);
    assert.notEqual(deviceOf(dropped), a.device);
    // Swapped for another id: a new one too, not the one sent.
    const other = `${DEVICE_COOKIE}=${newDeviceId()}`;
    const swapped = await steps(a.device, other);
    assert.match(deviceOf(swapped), idRe);
    assert.notEqual(deviceOf(swapped), other);
    assert.notEqual(deviceOf(swapped), a.device);
    // Unchanged: the same device.
    assert.equal(deviceOf(await steps(a.device, a.device)), a.device);
    for (const r of [dropped, swapped]) assert.equal(r.headers['set-cookie'].some((c) => c.includes('=null')), false);
  } finally {
    await s.close();
  }
});
