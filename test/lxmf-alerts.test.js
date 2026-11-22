// Users' own LXMF alert addresses: the storage (the meta table of users.db, no schema change), the confirm code and
// the limits (lxmf-alerts.js), the account API, and what is sent where (the account alerts, the node alerts),
// against a fake bridge.
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import { Monitor } from '../lib/monitor.js';
import { loadConfig } from '../lib/config.js';
import { createApp } from '../lib/app.js';
import { createLogin } from '../lib/login.js';
import { hashPassword } from '../lib/password.js';
import { UserStore } from '../lib/users.js';
import { DB_FILE, MIGRATIONS, SCHEMA_VERSION, UserDb, checkSchema } from '../lib/userdb.js';
import { Keyring } from '../lib/keys.js';
import { createAudit, createFailureLog } from '../lib/audit.js';
import { RECENT_AUTH_MS } from '../lib/account.js';
import { createPasskeys } from '../lib/passkeys.js';
import { Alerter } from '../lib/alerts.js';
import { CODES_PER_HOUR, CODES_PER_USER, CODE_TRIES, CODE_TTL_MS, LxmfAlerts, NEW_DEVICE_ALERT_MS, accountMessage, lxmfPrefix, normaliseLxmfAddress } from '../lib/lxmf-alerts.js';
import { base32Decode, totp } from '../lib/totp.js';
import { SoftAuthenticator } from './helpers/soft-authenticator.js';
import { fakeHasher } from './helpers/fake-hasher.js';
import { NO_SITE } from '../lib/site.js';
import { DEVICE_COOKIE } from '../lib/login.js';

const publicDir = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'public');
const NOW = 1_800_000_000_000;
const ORIGIN = 'https://status.example.org';
const ALICE = 'correct horse battery';
const BOB = 'bobs own password';
const CAROL = 'carols long password';
const KEYS = new Keyring(new Map([[1, crypto.randomBytes(32)]]));
const HOOK_SECRET = 'a-secret-of-some-length-0123456789';
const A1 = '0123456789abcdef0123456789abcdef';
const A2 = 'fedcba9876543210fedcba9876543210';
const A3 = '00112233445566778899aabbccddeeff';

// ---- the address as typed ----

test('an LXMF address: 32 hex digits, angle brackets and spaces around it and capitals are fine, and it is kept in lower case', () => {
  assert.equal(normaliseLxmfAddress(A1), A1);
  assert.equal(normaliseLxmfAddress(`<${A1}>`), A1);
  assert.equal(normaliseLxmfAddress(`  <${A1.toUpperCase()}>  `), A1);
  assert.equal(normaliseLxmfAddress(`< ${A1} >`), A1);
  assert.equal(normaliseLxmfAddress('0123456789ABCDEF0123456789abcdef'), A1);
  assert.equal(lxmfPrefix(A1), '01234567');
});

test('an LXMF address: anything else is refused (length, characters, brackets, spaces inside, not text)', () => {
  for (const bad of ['', ' ', A1.slice(1), `${A1}0`, `${A1.slice(0, 31)}g`, `<${A1}`, `${A1}>`, `<<${A1}>>`, `${A1.slice(0, 16)} ${A1.slice(16)}`, `0x${A1.slice(2)}`, `${A1}\n${A1}`, 'a'.repeat(81), `${' '.repeat(100)}${A1}`, '０１２３４５６７８９ａｂｃｄｅｆ0123456789abcdef']) {
    assert.equal(normaliseLxmfAddress(bad), null, JSON.stringify(bad).slice(0, 50));
  }
  for (const notText of [null, undefined, 12, {}, [A1], true]) assert.equal(normaliseLxmfAddress(notText), null);
});

// ---- the messages ----

test('the account messages say what happened and when, and for an admin\'s action which admin, with no id, secret or address', () => {
  const at = Date.UTC(2026, 10, 19, 12, 3);
  const m = (kind, d = {}) => accountMessage(kind, 'bob', d, at, 'rettui status');
  assert.equal(m('passkey_added', { passkey: 'Work laptop' }), '[rettui status] A passkey named "Work laptop" was added to your account bob at 2026-11-19 12:03 UTC. If this was not you, change your password and remove the passkey.');
  assert.match(m('passkey_removed', { passkey: 'Old', secondFactorOff: true }), /removed from your account bob at 2026-11-19 12:03 UTC\. It was your last second step, so two-step sign-in is now off\./);
  assert.doesNotMatch(m('passkey_removed', { passkey: 'Old', secondFactorOff: false }), /last second step/);
  assert.match(m('password_changed', { removedPasskeys: 2 }), /was changed at 2026-11-19 12:03 UTC\. 2 passkeys were removed with it\./);
  assert.match(m('password_changed', { removedPasskeys: 1 }), /1 passkey was removed with it\./);
  assert.doesNotMatch(m('password_changed', { removedPasskeys: 0 }), /removed with it/);
  assert.doesNotMatch(m('password_changed', { removedPasskeys: null }), /removed with it/);
  assert.match(m('password_reset', { actor: 'alice', removedPasskeys: 1 }), /The admin alice reset the password of your account bob at 2026-11-19 12:03 UTC\. 1 passkey was removed with it\./);
  assert.match(m('second_factor_off', { secondFactorOff: true }), /The app code .* was turned off at .* Two-step sign-in is now off\./);
  assert.match(m('second_factor_off', { secondFactorOff: false }), /Your passkeys still work as your second step\./);
  assert.match(m('second_factor_reset', { actor: 'alice' }), /The admin alice reset the two-step sign-in of your account bob at .* Your app code, passkeys and recovery codes were removed\./);
  assert.match(m('recovery_codes_new'), /New recovery codes were made for your account bob at .* The old ones no longer work\./);
  assert.equal(m('lxmf_address_changed', { what: 'added', address: A1 }), '[rettui status] The LXMF address starting 01234567 was added to the alerts of your account bob at 2026-11-19 12:03 UTC. It gets alerts once the code sent to it is typed in. If this was not you, change your password.');
  assert.equal(m('lxmf_address_changed', { what: 'removed', address: A1 }), '[rettui status] The LXMF address starting 01234567 was removed from the alerts of your account bob at 2026-11-19 12:03 UTC. It gets no more alerts. If this was not you, change your password.');
  assert.equal(m('sign_in_new_device', { siteUrl: 'https://status.example.org' }), '[rettui status] The password of your account bob was just used to sign in to https://status.example.org from a new browser at 2026-11-19 12:03 UTC. If this was not you, change your password.');
  assert.equal(m('sign_in_new_device'), '[rettui status] The password of your account bob was just used to sign in from a new browser at 2026-11-19 12:03 UTC. If this was not you, change your password.');
  assert.doesNotMatch(m('lxmf_address_changed', { what: 'added', address: A1 }), new RegExp(A1));
  assert.throws(() => m('nonsense'), /unknown alert kind/);
  // A passkey name is typed by the user: it is a quoted JSON string, so a quote cannot end it.
  assert.match(m('passkey_added', { passkey: 'x" and then "y' }), /named "x\\" and then \\"y" was added/);
});

// ---- the bridge, and the website around it ----

// A fake bridge: every POST is recorded; the status it answers can be set, or chosen per body.
function fakeBridge() {
  const b = { calls: [], status: 202, headers: {}, down: false, statusFor: null };
  b.fetch = async (url, opts) => {
    if (b.down) throw new Error('connection refused');
    const body = JSON.parse(opts.body);
    b.calls.push({ url, headers: opts.headers, raw: opts.body, body });
    const status = b.statusFor ? b.statusFor(body) : b.status;
    return { ok: status >= 200 && status < 300, status, headers: new Headers(b.headers), body: null };
  };
  // What was sent to one address (the channel's own alerts have no `to`).
  b.to = (address) => b.calls.filter((c) => c.body.to === address);
  b.named = () => b.calls.filter((c) => c.body.to !== undefined);
  b.listed = () => b.calls.filter((c) => c.body.to === undefined);
  return b;
}

const channel = (extra = {}) => ({ type: 'webhook', url: 'http://172.28.0.10:8742/alert', format: 'generic', secret: HOOK_SECRET, userAddresses: true, perAddressPerHour: 10, addressesPerHour: 50, ...extra });

// Alice (admin) is in the config file; bob (manage), carol (viewer) and dave (admin) are website users.
// userAddresses: false has the channel without the setting (the feature is off).
async function setup({ userAddresses = true, channelExtra = {}, siteUrl = ORIGIN, lxmfExtra = {}, site = null } = {}) {
  const dataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'lxmf-'));
  const hash = await hashPassword(ALICE, undefined, fakeHasher);
  const config = loadConfig(`users:\n  - name: Alice\n    password_hash: '${hash}'\n    role: admin\nnodes:\n  - address: a.test:1\n`);
  const clock = { t: NOW };
  const now = () => clock.t;
  const logs = [];
  const store = await UserStore.open({ keys: KEYS, dataDir, configUsers: config.users, warn: () => {}, now, log: (m) => logs.push(m) });
  const pepper = store.currentPepper();
  await store.createUser({ name: 'bob', role: 'manage', passwordHash: await hashPassword(BOB, undefined, fakeHasher, pepper) });
  await store.createUser({ name: 'carol', role: 'viewer', passwordHash: await hashPassword(CAROL, undefined, fakeHasher, pepper) });
  const audit = createAudit({ dataDir, now });
  const failures = createFailureLog({ dataDir, now });
  const passkeys = siteUrl ? createPasskeys({ siteUrl, rpName: 'Status', store, now }) : undefined;
  const login = createLogin({ users: config.users, store, settings: config.login, hasher: fakeHasher, now, audit, failures, sleep: async () => {}, log: (m) => logs.push(m), ...(passkeys ? { passkeys } : {}) });
  const bridge = fakeBridge();
  const codes = [];
  const lxmf = userAddresses
    ? new LxmfAlerts({ channel: channel(channelExtra), store, issuer: 'rettui status', now, fetchFn: bridge.fetch, sleep: async () => {}, log: (m) => logs.push(m), randomCode: () => codes.shift() ?? '123456', ...lxmfExtra })
    : null;
  const alerts = new Alerter({ channels: [channel({ userAddresses: undefined })].map((c) => (userAddresses ? channel(channelExtra) : c)), events: ['down', 'recovered', 'announce_queue'], lxmf, now, fetchFn: bridge.fetch, sleep: async () => {}, retryDelays: [0, 0], log: (m) => logs.push(m) });
  const monitor = new Monitor({ targets: config.targets, dataDir, probeFn: async () => ({ up: true, ms: 1 }) });
  const server = createApp({ monitor, publicDir, login, alerts, ...(site ? { site: { ...NO_SITE, ...site } } : {}) });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return {
    port: server.address().port, clock, store, login, audit, dataDir, logs, bridge, codes, lxmf, alerts,
    close: () => (alerts.stop(), server.closeAllConnections(), new Promise((r) => server.close(r))),
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
const postForm = (s, p, fields, cookie) => request(s.port, { method: 'POST', path: p, headers: { ...FORM, ...(cookie ? { Cookie: cookie } : {}) }, body: new URLSearchParams(fields).toString() });
// Who each session cookie belongs to, so that the changes that need the password (the step-up of adding, confirming
// and removing an address) can be sent with it.
const WHO = new Map();
const STEP_UP_PATHS = new Set(['/api/account/lxmf/set', '/api/account/lxmf/confirm', '/api/account/lxmf/remove']);
const rawApi = (s, p, body, cookie) => request(s.port, { method: 'POST', path: p, headers: { ...JSON_HEADERS, ...(cookie ? { Cookie: cookie } : {}) }, body: JSON.stringify(body) });
const api = (s, p, body, cookie) => {
  const who = WHO.get(cookie);
  const needs = STEP_UP_PATHS.has(p) && who !== undefined && body !== null && typeof body === 'object' && !('password' in body);
  return rawApi(s, p, needs ? { ...body, password: PASSWORDS[who] } : body, cookie);
};
const lconfirm = (s, cookie, code, address = A1, extra = {}) => api(s, '/api/account/lxmf/confirm', { address, lxmfCode: code, ...extra }, cookie);
const get = (s, p, cookie) => request(s.port, { path: p, headers: cookie ? { Cookie: cookie } : {} });
const cookieOf = (r) => (r.headers['set-cookie']?.[0] ?? '').split(';')[0];
const PASSWORDS = { alice: ALICE, bob: BOB, carol: CAROL };
async function logIn(s, name = 'bob') {
  const r = await postForm(s, '/login', { name, password: PASSWORDS[name] });
  assert.equal(r.status, 200, r.text);
  const cookie = cookieOf(r);
  WHO.set(cookie, name);
  return cookie;
}
const auditLines = async (s) => {
  await s.audit.flush();
  return (await fs.readFile(s.audit.file, 'utf8').catch(() => '')).trim().split('\n').filter(Boolean).map((l) => JSON.parse(l)).filter((l) => l.event !== 'device-added');
};
// A new sign in an hour later: the budgets of the changes (5 an hour for a session, 10 for a user) are fresh.
const later = async (s, name = 'bob') => {
  s.clock.t += 61 * 60_000;
  return logIn(s, name);
};
const lxmfView = async (s, cookie) => (await get(s, '/api/account', cookie)).json().lxmf;

// Sets an address and confirms it with the code the fake bridge was given: the session's account.
async function confirmAddress(s, cookie, name = 'bob', address = A1) {
  s.codes.push('424242');
  const set = await api(s, '/api/account/lxmf/set', { address }, cookie);
  assert.equal(set.status, 200, set.text);
  const done = await lconfirm(s, cookie, '424242', address);
  assert.equal(done.status, 200, done.text);
  assert.equal(s.store.lxmfOf(name).addresses.find((e) => e.address === address).confirmed, true);
  await s.lxmf.idle();
  s.bridge.calls.length = 0;
}

// ---- off without the channel setting ----

test('without user_addresses the feature is off: the account page is told so, and every route is a 404', async () => {
  const s = await setup({ userAddresses: false });
  try {
    const cookie = await logIn(s);
    assert.deepEqual(await lxmfView(s, cookie), { available: false });
    for (const p of ['set', 'resend', 'confirm', 'remove', 'node-alerts']) {
      const r = await api(s, `/api/account/lxmf/${p}`, { address: A1, code: '123456', enabled: true }, cookie);
      assert.equal(r.status, 404, p);
    }
    assert.equal(s.bridge.calls.length, 0);
    // The other changes still work and send nothing to any user address.
    assert.equal((await api(s, '/api/account/recovery-codes', { password: BOB }, cookie)).status, 409, 'no second factor, so nothing to remake');
    assert.equal(s.bridge.named().length, 0);
    // The page has its card hidden in the file and shows it only when the server says it is available.
    assert.match(await fs.readFile(path.join(publicDir, 'account.html'), 'utf8'), /<section id="acct-lxmf"[^>]*hidden>/);
  } finally {
    await s.close();
  }
});

test('with the setting the account page is told the feature is there, with nothing set', async () => {
  const s = await setup();
  try {
    const cookie = await logIn(s);
    assert.deepEqual(await lxmfView(s, cookie), { available: true, set: false, hidden: false, count: 0, max: 3, addresses: [], confirmed: false, canNodeAlerts: true, nodeAlerts: false });
    // A viewer is not offered the node alerts.
    assert.equal((await lxmfView(s, await logIn(s, 'carol'))).canNodeAlerts, false);
    // Not signed in: nothing.
    assert.equal((await get(s, '/api/account')).status, 401);
    assert.equal((await api(s, '/api/account/lxmf/set', { address: A1 })).status, 401);
  } finally {
    await s.close();
  }
});

// ---- the confirm flow ----

test('confirm flow: the address is normalised, a code goes to it through the bridge, and only the right code confirms it', async () => {
  const s = await setup();
  try {
    const cookie = await logIn(s);
    s.codes.push('073519');
    const set = await api(s, '/api/account/lxmf/set', { address: `  <${A1.toUpperCase()}> ` }, cookie);
    assert.equal(set.status, 200, set.text);
    const body = set.json();
    assert.equal(body.ok, true);
    assert.equal(body.address, A1);
    assert.equal(body.codeSent, true);
    assert.equal(body.expiresAt, new Date(NOW + CODE_TTL_MS).toISOString());
    assert.equal(JSON.stringify(body).includes('073519'), false, 'the code is never in an answer');
    // One signed message to that address only, with the code in it.
    assert.equal(s.bridge.calls.length, 1);
    const call = s.bridge.calls[0];
    assert.equal(call.url, 'http://172.28.0.10:8742/alert');
    assert.equal(call.body.to, A1);
    assert.equal(call.body.event, 'lxmf_check');
    assert.match(call.body.message, /^\[rettui status\] Your code to confirm this address is 073519\. It works for 15 minutes\./);
    const stamp = call.headers['X-Rettui-Timestamp'];
    assert.equal(call.headers['X-Rettui-Signature'], `sha256=${crypto.createHmac('sha256', HOOK_SECRET).update(`${stamp}.${call.raw}`).digest('hex')}`);
    // Kept, not confirmed.
    assert.deepEqual(s.store.lxmfOf('bob'), { addresses: [{ address: A1, confirmed: false }], nodeAlerts: false });
    assert.deepEqual(await lxmfView(s, cookie), { available: true, set: true, hidden: false, count: 1, max: 3, addresses: [{ address: A1, confirmed: false, codeExpiresAt: new Date(NOW + CODE_TTL_MS).toISOString() }], confirmed: false, canNodeAlerts: true, nodeAlerts: false });
    // A wrong code does not confirm it, a right one does, once.
    const wrong = await lconfirm(s, cookie, '111111');
    assert.equal(wrong.status, 400);
    assert.deepEqual(wrong.json(), { error: 'That code is not right. Check the digits, or send a new code.', field: 'lxmfCode', reason: 'wrong' });
    assert.equal(s.store.lxmfOf('bob').addresses[0].confirmed, false);
    const right = await lconfirm(s, cookie, '073 519');
    assert.equal(right.status, 200, right.text);
    assert.deepEqual(s.store.lxmfOf('bob'), { addresses: [{ address: A1, confirmed: true }], nodeAlerts: false });
    assert.equal((await lxmfView(s, cookie)).confirmed, true);
    assert.equal((await lconfirm(s, cookie, '073519')).status, 409, 'confirmed already');
    // The setting survives the server reading the store again.
    s.store.reload();
    assert.equal(s.store.lxmfOf('bob').addresses[0].confirmed, true);
  } finally {
    await s.close();
  }
});

test('confirm flow: bad input is refused before anything is sent (not an address, not text, the same address again, an unknown field)', async () => {
  const s = await setup();
  try {
    let cookie = await logIn(s);
    const bad = ['', 'hello', A1.slice(1), `${A1}00`, 12, null, [A1], { a: A1 }, `<${A1}`];
    for (const [i, address] of bad.entries()) {
      // Every change counts against 5 an hour for the session: a fresh sign in now and then.
      if (i > 0 && i % 4 === 0) cookie = await later(s);
      const r = await api(s, '/api/account/lxmf/set', { address }, cookie);
      assert.equal(r.status, 400, JSON.stringify(address));
      assert.equal(r.json().field, 'address');
    }
    cookie = await later(s);
    assert.equal((await api(s, '/api/account/lxmf/set', {}, cookie)).status, 400);
    assert.equal(s.bridge.calls.length, 0);
    assert.equal(s.store.lxmfOf('bob'), null);
    // Nothing to confirm, resend or remove without that address.
    assert.equal((await lconfirm(s, cookie, '123456')).status, 409);
    assert.equal((await api(s, '/api/account/lxmf/resend', { address: A1 }, cookie)).status, 409);
    assert.equal((await api(s, '/api/account/lxmf/resend', {}, cookie)).status, 400, 'no address named');
    assert.equal((await api(s, '/api/account/lxmf/remove', { address: A1 }, cookie)).status, 409);
    assert.equal((await api(s, '/api/account/lxmf/node-alerts', { enabled: true }, cookie)).status, 409);
    // A code that is not 6 digits is refused without counting as a try.
    cookie = await later(s);
    s.codes.push('123456');
    assert.equal((await api(s, '/api/account/lxmf/set', { address: A1 }, cookie)).status, 200);
    const codes = ['', '12345', '1234567', 'abcdef'];
    for (const code of codes) {
      const r = await lconfirm(s, cookie, code);
      assert.equal(r.status, 400, JSON.stringify(code));
      assert.equal(r.json().field, 'lxmfCode');
      assert.equal(r.json().reason, undefined, 'not a wrong try');
    }
    cookie = await later(s);
    s.codes.push('123456');
    await api(s, '/api/account/lxmf/resend', { address: A1 }, cookie);
    for (const code of ['12 34 5', 123456, null, 'x'.repeat(100)]) {
      const r = await lconfirm(s, cookie, code);
      assert.equal(r.status, 400, JSON.stringify(code));
      assert.equal(r.json().reason, undefined, 'not a wrong try');
    }
    const first = await lconfirm(s, cookie, '000000');
    assert.equal(first.json().reason, 'wrong');
    assert.match(first.json().error, /not right\. Check the digits/, 'a wrong code is refused before the step-up and uses no try');
    // A confirmed address is not set again, the same one.
    s.lxmf.checkCode('bob', A1, '123456');
    await s.store.confirmLxmf('bob', A1);
    cookie = await later(s);
    assert.equal((await api(s, '/api/account/lxmf/set', { address: A1 }, cookie)).status, 409);
    assert.equal((await api(s, '/api/account/lxmf/resend', { address: A1 }, cookie)).status, 409);
  } finally {
    await s.close();
  }
});

test('confirm flow: a wrong code is refused before the step-up and uses no try, and the code ends with the time; a new code starts again', async () => {
  const s = await setup();
  try {
    const cookie = await logIn(s);
    s.codes.push('111222');
    await api(s, '/api/account/lxmf/set', { address: A1 }, cookie);
    const reasons = [];
    for (let i = 0; i < CODE_TRIES; i++) {
      const r = await lconfirm(s, cookie, '999999');
      assert.equal(r.status, 400);
      reasons.push(r.json().reason);
      assert.match(r.json().error, /^That code is not right\./);
      assert.equal(r.json().left, undefined);
    }
    assert.deepEqual(reasons, ['wrong', 'wrong', 'wrong', 'wrong', 'wrong']);
    // The code is still there with all its tries: a guess before the step-up costs none (the route's own limit bounds the guesses).
    assert.deepEqual(s.lxmf.peekCode('bob', A1, '111222'), { ok: true });
    assert.equal(s.lxmf.peekCode('bob', A1, '000000').left, CODE_TRIES);
    const again = await logIn(s);
    // A new code works.
    s.codes.push('333444');
    assert.equal((await api(s, '/api/account/lxmf/resend', { address: A1 }, again)).status, 200);
    // After 15 minutes it has run out, however right.
    s.clock.t += CODE_TTL_MS;
    await api(s, '/api/account/reauth', { password: BOB }, again);
    const old = await lconfirm(s, again, '333444');
    assert.equal(old.status, 400);
    assert.equal(old.json().reason, 'expired');
    assert.match(old.json().error, /run out/);
    assert.equal(s.store.lxmfOf('bob').addresses[0].confirmed, false);
    // One minute before the end it still works.
    s.codes.push('555666');
    assert.equal((await api(s, '/api/account/lxmf/resend', { address: A1 }, again)).status, 200);
    s.clock.t += CODE_TTL_MS - 60_000;
    await api(s, '/api/account/reauth', { password: BOB }, again);
    assert.equal((await lconfirm(s, again, '555666')).status, 200);
  } finally {
    await s.close();
  }
});

test('confirm flow: at most 3 codes an hour for a user, a small number for everyone, and a new code replaces the old one', async () => {
  const s = await setup();
  try {
    const cookie = await logIn(s);
    const next = { n: 100_000 };
    const resend = () => (s.codes.push(String(next.n++)), api(s, '/api/account/lxmf/resend', { address: A1 }, cookie));
    s.codes.push('100000');
    next.n = 100_001;
    assert.equal((await api(s, '/api/account/lxmf/set', { address: A1 }, cookie)).status, 200);
    assert.equal((await resend()).status, 200);
    assert.equal((await resend()).status, 200);
    assert.equal(CODES_PER_USER, 3);
    const fourth = await resend();
    assert.equal(fourth.status, 429);
    assert.match(fourth.json().error, /You asked for 3 codes in the last hour, the most allowed\. Try again in \d+ minutes\./);
    assert.ok(Number(fourth.headers['retry-after']) > 0);
    assert.equal(fourth.json().retryAfter, Number(fourth.headers['retry-after']));
    assert.equal(s.bridge.named().length, 3, 'the fourth was not sent');
    // The first code stopped working when the second came; the third is the one that counts.
    assert.equal((await lconfirm(s, cookie, '100000')).json().reason, 'wrong');
    assert.equal((await lconfirm(s, cookie, '100001')).json().reason, 'wrong');
    assert.equal((await lconfirm(s, cookie, '100002')).status, 200);
    // An hour later there is room again (for another address, to be rid of the confirmed one).
    s.clock.t += 60 * 60_000;
    const later = await logIn(s, 'bob');
    s.codes.push('777777');
    assert.equal((await api(s, '/api/account/lxmf/set', { address: A2 }, later)).status, 200);
  } finally {
    await s.close();
  }
});

test('confirm limits: the cap for everyone, an address that has had its hour\'s messages, and too many different addresses', async () => {
  const s = await setup({ channelExtra: { perAddressPerHour: 6, addressesPerHour: 10 } });
  try {
    // Codes take new addresses up to half of the 10 an hour: 5 addresses, and a 6th is held.
    const bob = await logIn(s, 'bob');
    const carol = await logIn(s, 'carol');
    const alice = await logIn(s, 'alice');
    assert.equal((await api(s, '/api/account/lxmf/set', { address: A1 }, bob)).status, 200);
    assert.equal((await api(s, '/api/account/lxmf/set', { address: A2 }, carol)).status, 200);
    assert.equal((await api(s, '/api/account/lxmf/set', { address: A3 }, alice)).status, 200);
    for (const [i, n] of ['u4', 'u5'].entries()) assert.equal((await s.lxmf.sendCode(n, `${i}${i}${A1.slice(2)}`)).ok, true);
    await s.lxmf.idle();
    const dave = '77777777777777777777777777777777';
    const many = await api(s, '/api/account/lxmf/set', { address: dave }, bob);
    assert.equal(many.status, 429);
    assert.match(many.json().error, /That address has had the most messages allowed for now\./);
    assert.equal(s.store.lxmfOf('bob').addresses[0].address, A1, 'nothing changed');
    // An address that already had messages only counts against its own limit (2 codes an hour at a budget of 6): one more is fine, the next is not.
    assert.equal((await api(s, '/api/account/lxmf/resend', { address: A1 }, bob)).status, 200);
    const third = await api(s, '/api/account/lxmf/resend', { address: A1 }, bob);
    assert.equal(third.status, 429);
    assert.equal(s.bridge.to(A1).length, 2);
    // After the hour the room is back.
    s.clock.t += 60 * 60_000 + 1;
    assert.equal((await api(s, '/api/account/lxmf/set', { address: dave }, await logIn(s, 'bob'))).status, 200);
  } finally {
    await s.close();
  }
  // The cap for everyone.
  const t = await setup({ channelExtra: { perAddressPerHour: 100, addressesPerHour: 1000 }, lxmfExtra: {} });
  try {
    for (let i = 0; i < CODES_PER_HOUR; i++) assert.deepEqual((await t.lxmf.sendCode(`user${i}`, `${String(i).padStart(2, '0')}${A1.slice(2)}`)).ok, true, `code ${i}`);
    const over = await t.lxmf.sendCode('another', A2);
    assert.equal(over.ok, false);
    assert.equal(over.status, 429);
    assert.match(over.error, /Too many codes were sent from this site in the last hour\./);
  } finally {
    await t.close();
  }
});

test('the code is never in the logs, the audit log, the store or an answer; it is compared in constant time', async () => {
  const s = await setup();
  try {
    const cookie = await logIn(s);
    s.codes.push('918273');
    await api(s, '/api/account/lxmf/set', { address: A1 }, cookie);
    const wrong = await lconfirm(s, cookie, '918274');
    const right = await lconfirm(s, cookie, '918273');
    for (const text of [wrong.text, right.text, s.logs.join('\n'), JSON.stringify(await auditLines(s)), (await fs.readFile(path.join(s.dataDir, DB_FILE))).toString('latin1')]) {
      assert.equal(text.includes('918273'), false);
      assert.equal(text.includes('918274'), false);
    }
    // Only the message to the address has it.
    assert.equal(JSON.stringify(s.bridge.calls).includes('918273'), true);
    const src = await fs.readFile(path.join(publicDir, '..', 'lib', 'lxmf-alerts.js'), 'utf8');
    assert.match(src, /crypto\.timingSafeEqual\(have, p\.digest\)/);
  } finally {
    await s.close();
  }
});

// ---- what the bridge says ----

test('the bridge\'s refusals are shown plainly, and a refused address is not kept', async () => {
  const s = await setup();
  try {
    let cookie = await logIn(s);
    const set = async (status, headers = {}) => {
      s.bridge.status = status;
      s.bridge.headers = headers;
      return api(s, '/api/account/lxmf/set', { address: A1 }, cookie);
    };
    const off = await set(403);
    assert.equal(off.status, 502);
    assert.equal(off.json().code, 'bridge-off');
    assert.match(off.json().error, /The alert bridge has addresses named by the website turned off, so it cannot send to your address\. Ask whoever runs this site to turn on website_recipients in the bridge\./);
    const limited = await set(429, { 'Retry-After': '1800' });
    assert.equal(limited.status, 429);
    assert.equal(limited.headers['retry-after'], '1800');
    assert.equal(limited.json().retryAfter, 1800);
    assert.match(limited.json().error, /sent the most messages it allows to this address for now\. Try again in 30 minutes\./);
    // The bridge said when: nothing more goes to that address until then, and the website answers without asking.
    const calls = s.bridge.calls.length;
    const held = await set(202);
    assert.equal(held.status, 429);
    assert.equal(s.bridge.calls.length, calls);
    // (An hour on: the changes of an hour are limited, 5 for a session.)
    s.clock.t += 61 * 60_000;
    cookie = await logIn(s);
    assert.match((await set(429)).json().error, /Try again later\./);
    const busy = await set(503);
    assert.equal(busy.status, 503);
    assert.equal(busy.json().code, 'bridge-busy');
    assert.match(busy.json().error, /The alert bridge is busy with other messages\. Try again in 60 seconds\./);
    assert.equal(busy.headers['retry-after'], '60');
    assert.match((await set(503, { 'Retry-After': '120' })).json().error, /Try again in 2 minutes\./);
    cookie = await logIn(s);
    const own = await set(422);
    assert.equal(own.status, 400);
    assert.equal(own.json().field, 'address');
    assert.match(own.json().error, /bridge's own address/);
    const bad = await set(400);
    assert.equal(bad.json().field, 'address');
    const secret = await set(401);
    assert.equal(secret.status, 502);
    assert.match(secret.json().error, /did not accept the website's signature/);
    const other = await set(500);
    assert.equal(other.status, 502);
    assert.match(other.json().error, /it answered 500/);
    // Nothing was kept, and nothing the bridge refused counted against the website's own limits: after all those
    // refusals the three codes an hour are still there.
    assert.equal(s.store.lxmfOf('bob'), null);
    s.bridge.status = 202;
    s.bridge.headers = {};
    for (let i = 0; i < CODES_PER_USER; i++) assert.equal((await api(s, '/api/account/lxmf/resend', { address: A1 }, cookie)).status, 409, 'no address yet');
    s.clock.t += 0;
    // The bridge answers again: the set works.
    assert.equal((await api(s, '/api/account/lxmf/set', { address: A1 }, cookie)).status, 200);
  } finally {
    await s.close();
  }
});

test('a bridge that cannot be reached (or times out) is said so, and the address is not kept; a code in flight keeps the earlier one', async () => {
  const s = await setup();
  try {
    const cookie = await logIn(s);
    s.codes.push('121212');
    assert.equal((await api(s, '/api/account/lxmf/set', { address: A1 }, cookie)).status, 200);
    s.bridge.down = true;
    const r = await api(s, '/api/account/lxmf/resend', { address: A1 }, cookie);
    assert.equal(r.status, 502);
    assert.equal(r.json().code, 'bridge-unreachable');
    assert.match(r.json().error, /could not be reached/);
    // The code that was sent before still stands.
    s.bridge.down = false;
    assert.equal((await lconfirm(s, cookie, '121212')).status, 200);
    // The URL and the secret are in no answer and no log.
    for (const text of [r.text, s.logs.join('\n')]) {
      assert.equal(text.includes('172.28.0.10'), false);
      assert.equal(text.includes(HOOK_SECRET), false);
    }
  } finally {
    await s.close();
  }
});

// ---- recent password, and a session made with a passkey alone ----

test('every change needs the password from the last 15 minutes: after that the answer asks for it, and nothing is sent', async () => {
  const s = await setup();
  try {
    const cookie = await logIn(s);
    s.clock.t += RECENT_AUTH_MS + 1;
    for (const [p, body] of [['set', { address: A1 }], ['resend', { address: A1 }], ['confirm', { address: A1, lxmfCode: '123456' }], ['remove', { address: A1 }], ['node-alerts', { enabled: true }]]) {
      const r = await api(s, `/api/account/lxmf/${p}`, body, cookie);
      assert.equal(r.status, 403, p);
      assert.deepEqual(r.json(), { error: 'Enter your password again to do this.', reauth: true }, p);
    }
    assert.equal(s.bridge.calls.length, 0);
    assert.equal(s.store.lxmfOf('bob'), null);
    assert.equal((await api(s, '/api/account/reauth', { password: BOB }, cookie)).status, 200);
    assert.equal((await api(s, '/api/account/lxmf/set', { address: A1 }, cookie)).status, 200);
    // A wrong password does not make it recent.
    s.clock.t += RECENT_AUTH_MS + 1;
    assert.equal((await api(s, '/api/account/reauth', { password: 'not it' }, cookie)).status, 400);
    assert.equal((await api(s, '/api/account/lxmf/remove', { address: A1 }, cookie)).status, 403);
    assert.deepEqual(s.store.lxmfOf('bob'), { addresses: [{ address: A1, confirmed: false }], nodeAlerts: false });
    // The address is only read with a session, and what it asks is the same as for the other changes (the other site check).
    assert.equal((await request(s.port, { method: 'POST', path: '/api/account/lxmf/remove', headers: { ...JSON_HEADERS, 'Sec-Fetch-Site': 'cross-site', Cookie: cookie }, body: '{}' })).status, 403);
    assert.equal((await request(s.port, { method: 'POST', path: '/api/account/lxmf/remove', headers: { 'Content-Type': 'application/json', 'Sec-Fetch-Site': 'same-origin', Cookie: cookie }, body: '{}' })).status, 403);
  } finally {
    await s.close();
  }
});

// A passkey-only session of bob's: he has one passkey, and signs in with it alone.
async function passkeyOnlyBob(s) {
  const cookie = await logIn(s, 'bob');
  const begin = await api(s, '/api/account/passkeys/begin', { password: BOB }, cookie);
  assert.equal(begin.status, 200, begin.text);
  const { options } = begin.json();
  const a = new SoftAuthenticator();
  const credential = a.create({ challenge: options.challenge, origin: ORIGIN, rpId: options.rp.id, fmt: 'none' });
  assert.equal((await api(s, '/api/account/passkeys/finish', { credential }, cookie)).status, 200);
  const begun = await request(s.port, { method: 'POST', path: '/login/passkey/begin', headers: FORM, body: '' });
  const { token, options: o } = begun.json();
  const done = await postForm(s, '/login/passkey/finish', { token, credential: JSON.stringify(a.get({ challenge: o.challenge, origin: ORIGIN, rpId: o.rpId, userHandle: options.user.id })) });
  assert.equal(done.status, 200, done.text);
  WHO.set(cookieOf(done), 'bob');
  return { a, password: cookie, passkey: cookieOf(done), handle: options.user.id };
}

test('a session made with a passkey alone gives the password first: the address is not shown, and every change asks for it', async () => {
  const s = await setup();
  try {
    await confirmAddress(s, await logIn(s, 'bob'), 'bob', A1);
    const { passkey, a } = await passkeyOnlyBob(s);
    const account = (await get(s, '/api/account', passkey)).json();
    assert.equal(account.signedInWith, 'passkey');
    assert.equal(account.recentSignIn, false);
    assert.deepEqual(account.lxmf, { available: true, set: true, hidden: true, count: 1, max: 3, addresses: [], confirmed: true, canNodeAlerts: true, nodeAlerts: false });
    assert.equal(JSON.stringify(account).includes(A1), false);
    s.bridge.calls.length = 0;
    for (const [p, body] of [['set', { address: A2 }], ['resend', { address: A1 }], ['confirm', { address: A1, lxmfCode: '123456' }], ['remove', { address: A1 }], ['node-alerts', { enabled: true }]]) {
      const r = await api(s, `/api/account/lxmf/${p}`, body, passkey);
      assert.equal(r.status, 403, p);
      assert.equal(r.json().reauth, true, p);
    }
    assert.equal(s.bridge.calls.length, 0);
    assert.equal(s.store.lxmfOf('bob').addresses[0].address, A1);
    // With the password given, it is shown and a change goes through.
    assert.equal((await api(s, '/api/account/reauth', { password: BOB }, passkey)).status, 200);
    assert.deepEqual((await get(s, '/api/account', passkey)).json().lxmf.addresses, [{ address: A1, confirmed: true, codeExpiresAt: null }]);
    // Bob has a passkey, so the step-up needs it too (the password alone is not enough).
    s.codes.push('909090');
    assert.equal((await api(s, '/api/account/lxmf/set', { address: A2 }, passkey)).json().secondFactor, true);
    const c = await api(s, '/api/account/passkeys/challenge', {}, passkey);
    const proof = a.get({ challenge: c.json().options.challenge, origin: ORIGIN, rpId: c.json().options.rpId });
    assert.equal((await api(s, '/api/account/lxmf/set', { address: A2, passkey: proof }, passkey)).status, 200);
  } finally {
    await s.close();
  }
});

// ---- who is sent what ----

test('only a confirmed address gets alerts: none before the code, none after it is removed, and no message at all without an address', async () => {
  const s = await setup();
  try {
    const cookie = await logIn(s);
    // No address: a recovery-code change (a passkey makes the codes) sends nothing to anyone.
    s.lxmf.notifyUser('bob', 'password_changed', {});
    await s.lxmf.idle();
    assert.equal(s.bridge.calls.length, 0);
    // Set but not confirmed: the code, and nothing else.
    s.codes.push('123123');
    await api(s, '/api/account/lxmf/set', { address: A1 }, cookie);
    await s.lxmf.idle();
    s.lxmf.notifyUser('bob', 'password_changed', {});
    s.lxmf.notifyNode({ type: 'down', key: 'a.test:1', start: NOW, end: null, at: NOW }, 'a.test:1 is down');
    await s.lxmf.idle();
    assert.deepEqual(s.bridge.to(A1).map((c) => c.body.event), ['lxmf_check']);
    // Confirmed: the alerts about the account arrive.
    await lconfirm(s, cookie, '123123');
    s.bridge.calls.length = 0;
    s.lxmf.notifyUser('bob', 'password_changed', {});
    await s.lxmf.idle();
    assert.deepEqual(s.bridge.to(A1).map((c) => c.body.event), ['password_changed']);
    // Removed: nothing more, and only the removed address was told (it was the user's only one).
    s.bridge.calls.length = 0;
    assert.equal((await api(s, '/api/account/lxmf/remove', { address: A1 }, cookie)).status, 200);
    s.lxmf.notifyUser('bob', 'password_changed', {});
    await s.lxmf.idle();
    assert.deepEqual(s.bridge.named().map((c) => [c.body.to, c.body.event]), [[A1, 'lxmf_address_changed']]);
    assert.match(s.bridge.named()[0].body.message, /starting 01234567 was removed from the alerts of your account bob at/);
    assert.equal(s.store.lxmfOf('bob'), null);
    // Someone else's address is never told about bob's account.
    s.lxmf.notifyUser('carol', 'password_changed', {});
    await s.lxmf.idle();
    assert.equal(s.bridge.named().length, 1);
  } finally {
    await s.close();
  }
});

test('up to 3 addresses: each is added and confirmed on its own with its own code, a 4th is refused, and every confirmed one gets the alerts', async () => {
  const s = await setup();
  try {
    const cookie = await logIn(s);
    await confirmAddress(s, cookie, 'bob', A1);
    // A second address: its own code goes to it, and the first (confirmed) one is told that it was added.
    s.codes.push('565656');
    const second = await api(s, '/api/account/lxmf/set', { address: A2 }, cookie);
    assert.equal(second.status, 200, second.text);
    await s.lxmf.idle();
    assert.deepEqual(s.store.lxmfOf('bob'), { addresses: [{ address: A1, confirmed: true }, { address: A2, confirmed: false }], nodeAlerts: false });
    assert.deepEqual(s.bridge.named().map((c) => [c.body.to, c.body.event]).sort(), [[A1, 'lxmf_address_changed'], [A2, 'lxmf_check']]);
    assert.match(s.bridge.to(A1)[0].body.message, /The LXMF address starting fedcba98 was added to the alerts of your account bob at 2027-01-15 08:00 UTC\. It gets alerts once the code sent to it is typed in\./);
    assert.equal(s.bridge.to(A1)[0].body.message.includes(A2), false, 'only the start of the address');
    // Until it is confirmed it gets no alerts; the first address does.
    s.bridge.calls.length = 0;
    s.lxmf.notifyUser('bob', 'password_changed', {});
    await s.lxmf.idle();
    assert.deepEqual(s.bridge.named().map((c) => c.body.to), [A1]);
    // Each address has its own code: the code of one does not confirm another, and a wrong try is that code's own.
    const view = await lxmfView(s, cookie);
    assert.deepEqual(view.addresses.map((a) => [a.address, a.confirmed, a.codeExpiresAt !== null]), [[A1, true, false], [A2, false, true]]);
    s.codes.push('787878');
    assert.equal((await api(s, '/api/account/lxmf/set', { address: A3 }, cookie)).status, 200);
    const third = await logIn(s);
    assert.equal((await lconfirm(s, third, '565656', A3)).json().reason, 'wrong', 'the code of A2 is not the code of A3');
    assert.equal((await lconfirm(s, third, '565656', A2)).status, 200);
    assert.equal((await lconfirm(s, third, '787878', A3)).status, 200);
    assert.deepEqual(s.store.lxmfOf('bob').addresses.map((e) => e.confirmed), [true, true, true]);
    // The 4th is refused with a plain message, before anything is sent or counted.
    s.bridge.calls.length = 0;
    const codesBefore = s.lxmf.codesPerUser.recent('bob').length;
    const fourth = await api(s, '/api/account/lxmf/set', { address: '77777777777777777777777777777777' }, third);
    assert.equal(fourth.status, 409);
    assert.deepEqual(fourth.json(), { error: 'You have 3 LXMF addresses, the most allowed. Remove one first.', field: 'address' });
    assert.equal(s.bridge.calls.length, 0);
    assert.equal(s.lxmf.codesPerUser.recent('bob').length, codesBefore);
    assert.equal(s.store.lxmfOf('bob').addresses.length, 3);
    // Every confirmed address gets an account alert, once each.
    s.lxmf.notifyUser('bob', 'password_changed', {});
    await s.lxmf.idle();
    assert.deepEqual(s.bridge.named().map((c) => [c.body.to, c.body.event]).sort(), [[A1, 'password_changed'], [A2, 'password_changed'], [A3, 'password_changed']].sort());
    // Removing one tells the others and the removed one; it gets no more alerts, and the room is back for another.
    s.bridge.calls.length = 0;
    assert.equal((await api(s, '/api/account/lxmf/remove', { address: A2 }, third)).status, 200);
    await s.lxmf.idle();
    assert.deepEqual(s.bridge.named().map((c) => [c.body.to, c.body.event]).sort(), [[A1, 'lxmf_address_changed'], [A2, 'lxmf_address_changed'], [A3, 'lxmf_address_changed']].sort());
    for (const c of s.bridge.named()) assert.match(c.body.message, /starting fedcba98 was removed from the alerts of your account bob/);
    s.bridge.calls.length = 0;
    s.lxmf.notifyUser('bob', 'password_changed', {});
    await s.lxmf.idle();
    assert.deepEqual(s.bridge.named().map((c) => c.body.to).sort(), [A1, A3].sort());
    // Removing an address that was never confirmed tells nobody (it never got alerts), and a stranger's address is no address of ours.
    assert.equal((await api(s, '/api/account/lxmf/remove', { address: A2 }, third)).status, 409);
    // Audit lines hold the 8 digit start of the address, how it was confirmed, and never the address.
    const lines = await auditLines(s);
    assert.ok(lines.filter((l) => l.event.startsWith('lxmf-')).length >= 6);
    assert.equal(JSON.stringify(lines).includes(A2), false);
    assert.equal(lines.find((l) => l.event === 'lxmf-address-removed').lxmf, 'fedcba98');
  } finally {
    await s.close();
  }
});

test('an address that waits for its code is told neither of its own adding nor of others', async () => {
  const s = await setup();
  try {
    const cookie = await logIn(s);
    s.codes.push('111000', '222000');
    assert.equal((await api(s, '/api/account/lxmf/set', { address: A1 }, cookie)).status, 200);
    assert.equal((await api(s, '/api/account/lxmf/set', { address: A2 }, cookie)).status, 200);
    await s.lxmf.idle();
    assert.deepEqual(s.bridge.named().map((c) => c.body.event), ['lxmf_check', 'lxmf_check'], 'no confirmed address, so nobody to tell');
    // Removing one that was never confirmed tells nobody.
    s.bridge.calls.length = 0;
    assert.equal((await api(s, '/api/account/lxmf/remove', { address: A2 }, cookie)).status, 200);
    await s.lxmf.idle();
    assert.equal(s.bridge.calls.length, 0);
    // Adding the same address again while it waits sends a new code and does not add another.
    s.codes.push('333000');
    assert.equal((await api(s, '/api/account/lxmf/set', { address: A1 }, cookie)).status, 200);
    assert.equal(s.store.lxmfOf('bob').addresses.length, 1);
    assert.equal((await lconfirm(s, cookie, '333000')).status, 200);
  } finally {
    await s.close();
  }
});

// Adds a passkey to the signed-in user (password alone, or with the step-up fields). Gives the authenticator.
async function addPasskey(s, cookie, password, stepUp = {}, name) {
  const begin = await api(s, '/api/account/passkeys/begin', { password, ...stepUp }, cookie);
  assert.equal(begin.status, 200, begin.text);
  const { options } = begin.json();
  const a = new SoftAuthenticator();
  const credential = a.create({ challenge: options.challenge, origin: ORIGIN, rpId: options.rp.id, fmt: 'none' });
  const finish = await api(s, '/api/account/passkeys/finish', name === undefined ? { credential } : { credential, name }, cookie);
  assert.equal(finish.status, 200, finish.text);
  return { a, ref: finish.json().passkey.id, recoveryCodes: finish.json().recoveryCodes };
}

test('the account alerts: a passkey added and removed, the password changed, the app code off, new recovery codes, each with what and when', async () => {
  const s = await setup();
  try {
    const cookie = await logIn(s, 'bob');
    await confirmAddress(s, cookie, 'bob', A1);
    const sent = async () => {
      await s.lxmf.idle();
      const out = s.bridge.named().map((c) => c.body);
      s.bridge.calls.length = 0;
      return out;
    };
    // A passkey added.
    const { a, ref } = await addPasskey(s, cookie, BOB, {}, 'Work laptop');
    let [m] = await sent();
    assert.equal(m.to, A1);
    assert.equal(m.event, 'passkey_added');
    assert.equal(m.message, '[rettui status] A passkey named "Work laptop" was added to your account bob at 2027-01-15 08:00 UTC. If this was not you, change your password and remove the passkey.');
    // The app code on, then off (with the passkey on as the second step, it needs that second step too).
    const stepUp = async () => {
      const c = await api(s, '/api/account/passkeys/challenge', {}, cookie);
      return { passkey: a.get({ challenge: c.json().options.challenge, origin: ORIGIN, rpId: c.json().options.rpId }) };
    };
    const setup1 = await api(s, '/api/account/totp/setup', { password: BOB, ...(await stepUp()) }, cookie);
    assert.equal(setup1.status, 200, setup1.text);
    const on = await api(s, '/api/account/totp/enable', { code: totp(base32Decode(setup1.json().secret), s.clock.t) }, cookie);
    assert.equal(on.status, 200, on.text);
    s.clock.t += 30_000;
    assert.deepEqual(await sent(), [], 'turning it on is not one of the alerts');
    // New recovery codes.
    assert.equal((await api(s, '/api/account/recovery-codes', { password: BOB, ...(await stepUp()) }, cookie)).status, 200);
    [m] = await sent();
    assert.equal(m.event, 'recovery_codes_new');
    assert.match(m.message, /New recovery codes were made for your account bob at 2027-01-15 08:00 UTC\. The old ones no longer work\./);
    // The app code off: the passkey still is a second step.
    assert.equal((await api(s, '/api/account/totp/disable', { password: BOB, ...(await stepUp()) }, cookie)).status, 200);
    [m] = await sent();
    assert.equal(m.event, 'second_factor_off');
    assert.match(m.message, /The app code of your account bob was turned off at .* Your passkeys still work as your second step\./);
    // The password changed, with the other passkeys removed (the one that confirms it is kept).
    await addPasskey(s, cookie, BOB, await stepUp());
    await sent();
    const changed = await api(s, '/api/account/password', { password: BOB, next: 'a brand new long password', removeOtherPasskeys: true, ...(await stepUp()) }, cookie);
    assert.equal(changed.status, 200, changed.text);
    [m] = await sent();
    assert.equal(m.event, 'password_changed');
    assert.match(m.message, /The password of your account bob was changed at .* 1 passkey was removed with it\./);
    // The address stays when the password changes: that is when the alert matters most.
    assert.equal(s.store.lxmfOf('bob').addresses[0].address, A1);
    assert.equal(s.store.passkeys('bob').length, 1);
    // The last passkey removed: two-step sign-in goes off with it, and the same message says so.
    const last = s.store.passkeys('bob')[0].ref;
    assert.equal((await api(s, '/api/account/passkeys/remove', { id: last, password: 'a brand new long password', ...(await stepUp()) }, cookie)).status, 200);
    [m] = await sent();
    assert.equal(m.event, 'passkey_removed');
    assert.match(m.message, /A passkey named "Work laptop" was removed from your account bob at .* It was your last second step, so two-step sign-in is now off\./);
    assert.equal(s.store.lxmfOf('bob').addresses[0].address, A1, 'kept when a passkey is removed too');
    // Nothing sent holds an id, an address or a secret.
    assert.equal(s.bridge.calls.length, 0);
  } finally {
    await s.close();
  }
});

// ---- an admin's reset, and a user without a passkey ----

test('an admin\'s reset of a password or of two-step sign-in tells the user, with which admin; the address stays', async () => {
  const s = await setup();
  try {
    const bob = await logIn(s, 'bob');
    await confirmAddress(s, bob, 'bob', A1);
    // Bob has a passkey, so the reset has something to take away.
    await addPasskey(s, bob, BOB);
    s.bridge.calls.length = 0;
    const alice = await logIn(s, 'alice');
    const reset = await api(s, '/api/users/reset-password', { name: 'bob', generate: true, password: ALICE, removePasskeys: true }, alice);
    assert.equal(reset.status, 200, reset.text);
    await s.lxmf.idle();
    const [m] = s.bridge.named();
    assert.equal(m.body.to, A1);
    assert.equal(m.body.event, 'password_reset');
    assert.match(m.body.message, /^\[rettui status\] The admin Alice reset the password of your account bob at 2027-01-15 08:00 UTC\. 1 passkey was removed with it\. You choose a new one when you next sign in\.$/);
    // The one-time password is not in it, nor is anything of the admin but the name.
    assert.equal(m.raw.includes(reset.json().oneTimePassword), false);
    s.bridge.calls.length = 0;
    // Two-step sign-in reset (carol has none, but still gets the message once she has an address).
    const carol = await logIn(s, 'carol');
    await confirmAddress(s, carol, 'carol', A2);
    const r2 = await api(s, '/api/users/reset-second-factor', { name: 'carol', password: ALICE }, alice);
    assert.equal(r2.status, 200, r2.text);
    await s.lxmf.idle();
    const [n] = s.bridge.named();
    assert.equal(n.body.to, A2);
    assert.equal(n.body.event, 'second_factor_reset');
    assert.match(n.body.message, /The admin Alice reset the two-step sign-in of your account carol at 2027-01-15 08:00 UTC\./);
    // The addresses are kept.
    assert.equal(s.store.lxmfOf('bob').addresses[0].address, A1);
    assert.equal(s.store.lxmfOf('carol').addresses[0].address, A2);
    // A user without an address: the reset sends nothing, and still works.
    s.bridge.calls.length = 0;
    await s.store.setPassword('bob', (await hashPassword(BOB, undefined, fakeHasher, s.store.currentPepper())));
    await s.store.clearLxmf('bob', A1);
    const again = await api(s, '/api/users/reset-password', { name: 'bob', generate: true, password: ALICE }, alice);
    assert.equal(again.status, 200, again.text);
    await s.lxmf.idle();
    assert.equal(s.bridge.named().length, 0);
  } finally {
    await s.close();
  }
});

// ---- node alerts ----

const DOWN = { type: 'down', key: 'a.test:1', start: NOW - 120_000, end: null, at: NOW };

test('node alerts go only to admins and managers who confirmed an address and ticked the box, in the words the channels get', async () => {
  const s = await setup();
  try {
    const bob = await logIn(s, 'bob');
    const carol = await logIn(s, 'carol');
    const alice = await logIn(s, 'alice');
    await confirmAddress(s, bob, 'bob', A1);
    await confirmAddress(s, carol, 'carol', A2);
    await confirmAddress(s, alice, 'alice', A3);
    // Nobody ticked it yet: the channel gets the alert, and no user.
    s.alerts.notify(DOWN);
    await s.alerts.idle();
    await s.lxmf.idle();
    assert.equal(s.bridge.listed().length, 1);
    assert.equal(s.bridge.named().length, 0);
    // A viewer cannot tick it, and the answer says so; bob and alice (a config user) can.
    assert.equal((await api(s, '/api/account/lxmf/node-alerts', { enabled: true }, carol)).status, 403);
    assert.equal(s.store.lxmfOf('carol').nodeAlerts, false);
    for (const bad of [{}, { enabled: 'yes' }, { enabled: 1 }, { enabled: null }]) assert.equal((await api(s, '/api/account/lxmf/node-alerts', bad, bob)).status, 400, JSON.stringify(bad));
    assert.equal((await api(s, '/api/account/lxmf/node-alerts', { enabled: true }, bob)).status, 200);
    assert.equal((await api(s, '/api/account/lxmf/node-alerts', { enabled: true }, alice)).status, 200);
    assert.equal((await lxmfView(s, bob)).nodeAlerts, true);
    s.bridge.calls.length = 0;
    s.clock.t += 60 * 60_000;
    s.alerts.notify({ ...DOWN, at: s.clock.t });
    s.alerts.notify({ type: 'recovered', key: 'a.test:1', start: DOWN.start, end: s.clock.t, at: s.clock.t });
    await s.alerts.idle();
    await s.lxmf.idle();
    const to = (a) => s.bridge.to(a).map((c) => [c.body.event, c.body.message]);
    // The same text the channel got.
    const listed = s.bridge.listed().map((c) => [c.body.event, c.body.message]);
    assert.equal(listed.length, 2);
    assert.deepEqual(to(A1), listed);
    assert.deepEqual(to(A3), listed);
    assert.deepEqual(to(A2), [], 'a viewer gets none');
    assert.match(listed[0][1], /is down since/);
    // Turned off again: none. (An hour has passed: bob signs in again.)
    const bob2 = await logIn(s, 'bob');
    assert.equal((await api(s, '/api/account/lxmf/node-alerts', { enabled: false }, bob2)).status, 200);
    s.bridge.calls.length = 0;
    s.clock.t += 60 * 60_000;
    s.alerts.notify({ ...DOWN, at: s.clock.t });
    await s.alerts.idle();
    await s.lxmf.idle();
    assert.deepEqual(to(A1), []);
    assert.equal(to(A3).length, 1);
    // The role lowered since: bob ticked it earlier, and gets none, whatever he ticked.
    await api(s, '/api/account/lxmf/node-alerts', { enabled: true }, bob2);
    await s.store.setRole('bob', 'viewer');
    s.bridge.calls.length = 0;
    s.clock.t += 60 * 60_000;
    s.alerts.notify({ ...DOWN, at: s.clock.t });
    await s.alerts.idle();
    await s.lxmf.idle();
    assert.deepEqual(to(A1), []);
    assert.deepEqual(s.store.lxmfNodeRecipients().map((r) => r.name), ['Alice']);
    // The events the config lists are the ones sent: the queue alert is listed here, the passkey one never goes out to users.
    s.bridge.calls.length = 0;
    s.alerts.observeQueue('a.test:1', { full: true, queued: 4096 });
    s.alerts.observeQueue('a.test:1', { full: true, queued: 4096 });
    s.alerts.observeQueue('a.test:1', { full: true, queued: 4096 });
    await s.alerts.idle();
    await s.lxmf.idle();
    assert.deepEqual(to(A3).map((x) => x[0]), ['announce_queue_full']);
  } finally {
    await s.close();
  }
});

test('node alerts: an event the config does not list is not sent to anyone, and a node event is sent without the account address of a user who did not tick', async () => {
  const s = await setup();
  try {
    const bob = await logIn(s, 'bob');
    await confirmAddress(s, bob, 'bob', A1);
    await api(s, '/api/account/lxmf/node-alerts', { enabled: true }, bob);
    // The config of this test lists down, recovered and announce_queue: a passkey alert for the operator is not one of them
    // and never reaches a user address (the account alerts have their own path).
    s.alerts.notifyPasskey({ user: 'carol', role: 'viewer', passkey: 'x', at: NOW });
    await s.alerts.idle();
    await s.lxmf.idle();
    assert.equal(s.bridge.named().length, 0);
    // A stopped alerter sends nothing.
    s.alerts.stop();
    s.alerts.notify(DOWN);
    await s.lxmf.idle();
    assert.equal(s.bridge.named().length, 0);
  } finally {
    await s.close();
  }
});

// ---- the website's own limits, and a bridge that fails ----

test('the website keeps under the bridge\'s limits: an address gets at most per_address_per_hour messages an hour, then it is dropped and logged without the address', async () => {
  const s = await setup({ channelExtra: { perAddressPerHour: 6 } });
  try {
    const cookie = await logIn(s, 'bob');
    await confirmAddress(s, cookie, 'bob', A1);
    // The code message counted: 1 of 6 used (confirmAddress cleared the record of calls, not the count).
    for (let i = 0; i < 8; i++) s.lxmf.notifyUser('bob', 'password_changed', {});
    await s.lxmf.idle();
    assert.equal(s.bridge.to(A1).length, 5, '6 an hour, one of them the code');
    const dropped = s.logs.filter((l) => l.includes('dropped to keep under the limit'));
    assert.equal(dropped.length, 3);
    for (const l of s.logs) assert.equal(l.includes(A1), false, 'only the first 8 digits are logged');
    assert.match(dropped[0], /a message to 01234567 was dropped to keep under the limit/);
    // An hour later it sends again.
    s.clock.t += 60 * 60_000;
    s.bridge.calls.length = 0;
    s.lxmf.notifyUser('bob', 'password_changed', {});
    await s.lxmf.idle();
    assert.equal(s.bridge.to(A1).length, 1);
  } finally {
    await s.close();
  }
});

test('a message the bridge refuses counts for nothing against the website\'s limit, and a refusal is not tried again', async () => {
  const s = await setup({ channelExtra: { perAddressPerHour: 6 } });
  try {
    const cookie = await logIn(s, 'bob');
    await confirmAddress(s, cookie, 'bob', A1);
    s.bridge.status = 403;
    for (let i = 0; i < 6; i++) {
      s.lxmf.notifyUser('bob', 'password_changed', {});
      await s.lxmf.idle();
    }
    assert.equal(s.bridge.to(A1).length, 6, 'one try each: a refusal is not a reason to try again, and counts for nothing');
    s.bridge.status = 202;
    s.bridge.calls.length = 0;
    for (let i = 0; i < 6; i++) s.lxmf.notifyUser('bob', 'password_changed', {});
    await s.lxmf.idle();
    // 6 an hour, the code's message was one, and the refused ones were nothing: five are left.
    assert.equal(s.bridge.to(A1).length, 5);
  } finally {
    await s.close();
  }
});

test('a bridge that is down, slow or full is tried 3 times and then given up on, and never fails or delays what the user did', async () => {
  const s = await setup();
  try {
    const cookie = await logIn(s, 'bob');
    await confirmAddress(s, cookie, 'bob', A1);
    // Down: the passkey is added all the same, and the answer comes at once.
    s.bridge.down = true;
    const added = await addPasskey(s, cookie, BOB, {}, 'Work laptop');
    assert.equal(s.store.passkeys('bob').length, 1);
    assert.ok(added.ref);
    await s.lxmf.idle();
    // An alert about the account is not tried again after the bridge was unreachable: it may have got through.
    assert.equal(s.bridge.calls.length, 0);
    assert.equal(s.logs.filter((l) => l.includes('bridge-unreachable') && l.includes('try 2 of 3 follows')).length, 0);
    assert.equal(s.logs.filter((l) => l.includes('bridge-unreachable') && l.includes('giving up')).length, 1);
    // Full (503): the same.
    s.bridge.down = false;
    s.bridge.status = 503;
    s.bridge.calls.length = 0;
    s.lxmf.notifyUser('bob', 'password_changed', {});
    await s.lxmf.idle();
    assert.equal(s.bridge.to(A1).length, 3);
    // A bridge that throws something else is no worse: it is a failure of that message, logged, and no more.
    s.lxmf.fetchFn = async () => {
      throw new TypeError('boom');
    };
    s.lxmf.notifyUser('bob', 'password_changed', {});
    await s.lxmf.idle();
    assert.ok(s.logs.some((l) => l.includes('bridge-unreachable')));
  } finally {
    await s.close();
  }
  const t = await setup();
  try {
    const cookie = await logIn(t, 'bob');
    await confirmAddress(t, cookie, 'bob', A1);
    let n = 0;
    t.bridge.statusFor = () => (++n === 1 ? 500 : 202);
    t.lxmf.notifyUser('bob', 'password_changed', {});
    await t.lxmf.idle();
    assert.equal(t.bridge.to(A1).length, 2, 'the second try went through');
  } finally {
    await t.close();
  }
});

test('a password change, a passkey and a reset are made and answered when the bridge hangs: nothing waits for it', async () => {
  const s = await setup();
  try {
    const cookie = await logIn(s, 'bob');
    await confirmAddress(s, cookie, 'bob', A1);
    // A bridge that never answers (the fetch promise is never settled).
    s.lxmf.fetchFn = () => new Promise(() => {});
    const t0 = Date.now();
    const r = await api(s, '/api/account/password', { password: BOB, next: 'a brand new long password' }, cookie);
    assert.equal(r.status, 200, r.text);
    assert.ok(Date.now() - t0 < 2000);
    // The change is on; the message is still waiting.
    const login = await postForm(s, '/login', { name: 'bob', password: 'a brand new long password' });
    assert.equal(login.status, 200);
  } finally {
    // A message that hangs holds close() up: it is only the test's own fetch that never settles.
    s.lxmf.stop();
    await s.close();
  }
});

// ---- the per-address budget is split, a retry counts, a 429 is obeyed ----

const addUser = async (s, name) => s.store.createUser({ name, role: 'manage', passwordHash: await hashPassword(BOB, undefined, fakeHasher, s.store.currentPepper()) });
const confirmDirect = async (s, name, address, nodeAlerts = false) => {
  await s.store.setLxmf(name, address);
  await s.store.confirmLxmf(name, address);
  if (nodeAlerts) await s.store.setLxmfNodeAlerts(name, true);
};

test('four users fill an address with codes: the cap is 3 an hour for the address, and its owner\'s account alerts still go out', async () => {
  const s = await setup();
  try {
    for (const n of ['dave', 'erin']) await addUser(s, n);
    const answers = [];
    for (const n of ['carol', 'alice', 'dave', 'erin']) answers.push(await s.lxmf.sendCode(n, A2));
    assert.deepEqual(answers.map((a) => a.ok), [true, true, true, false]);
    assert.equal(answers[3].status, 429);
    assert.equal(s.bridge.to(A2).length, 3);
    // The owner (who confirmed it by now) is still told: the codes took 3 of the 10, the rest is for the account.
    await confirmDirect(s, 'bob', A2);
    for (let i = 0; i < 10; i++) s.lxmf.notifyUser('bob', 'password_changed', {});
    await s.lxmf.idle();
    assert.equal(s.bridge.to(A2).length, 10, 'all 10 an hour: 3 codes and 7 account alerts');
    // A small budget (6): the codes' cap is 2, never more than the budget less 4.
    const t = await setup({ channelExtra: { perAddressPerHour: 6 } });
    try {
      assert.deepEqual([(await t.lxmf.sendCode('carol', A2)).ok, (await t.lxmf.sendCode('alice', A2)).ok, (await t.lxmf.sendCode('bob', A2)).ok], [true, true, false]);
    } finally {
      await t.close();
    }
  } finally {
    await s.close();
  }
});

test('node alerts in a burst use at most the budget less 3 of an address: the account alerts keep their share', async () => {
  const s = await setup();
  try {
    await confirmDirect(s, 'bob', A1, true);
    for (let i = 0; i < 20; i++) s.lxmf.notifyNode('down', 'a.test:1 is down');
    await s.lxmf.idle();
    assert.equal(s.bridge.to(A1).length, 7, 'P - 3 of 10');
    for (let i = 0; i < 5; i++) s.lxmf.notifyUser('bob', 'password_changed', {});
    await s.lxmf.idle();
    assert.equal(s.bridge.to(A1).length, 10, 'the 3 left are the account alerts\'');
    assert.equal(s.bridge.to(A1).filter((c) => c.body.event === 'password_changed').length, 3);
    // Codes and node alerts share the P - 3: with the codes in, the node alerts get that much less.
    const t = await setup();
    try {
      await confirmDirect(t, 'bob', A1, true);
      assert.equal((await t.lxmf.sendCode('carol', A1)).ok, true, 'answered as sent, and counted');
      for (let i = 0; i < 20; i++) t.lxmf.notifyNode('down', 'a.test:1 is down');
      await t.lxmf.idle();
      assert.equal(t.bridge.to(A1).length, 6, 'the code that was not sent still took 1 of the 7');
    } finally {
      await t.close();
    }
  } finally {
    await s.close();
  }
});

test('a code asked for an address another user has confirmed is answered as if sent, and is not sent, counted or logged', async () => {
  const s = await setup();
  try {
    const bob = await logIn(s, 'bob');
    await confirmAddress(s, bob, 'bob', A1);
    const carol = await logIn(s, 'carol');
    const logsBefore = s.logs.length;
    s.codes.push('555555');
    const asked = await api(s, '/api/account/lxmf/set', { address: A1 }, carol);
    assert.equal(asked.status, 200);
    assert.deepEqual(Object.keys(asked.json()).sort(), ['address', 'codeSent', 'expiresAt', 'ok']);
    assert.equal(asked.json().codeSent, true);
    assert.equal(s.bridge.to(A1).length, 0, 'nothing was sent');
    assert.equal(s.logs.length, logsBefore, 'nothing was logged');
    assert.equal(s.lxmf.perAddress.recent(A1).length, 2, 'the owner\'s code and the asker\'s count, as for a real send');
    // The asker's page and limits look as for any code.
    assert.notEqual((await lxmfView(s, carol)).addresses[0].codeExpiresAt, null);
    assert.equal(s.lxmf.codesPerUser.recent('carol').length, 1);
    // The real owner's address is still theirs, confirmed.
    assert.equal(s.store.lxmfOf('bob').addresses[0].confirmed, true);
    assert.equal(s.store.lxmfOf('carol').addresses[0].confirmed, false);
  } finally {
    await s.close();
  }
});

test('a retry takes the count again and is dropped when that is over the limit', async () => {
  const s = await setup({ channelExtra: { perAddressPerHour: 6 } });
  try {
    await confirmDirect(s, 'bob', A1);
    s.bridge.status = 500;
    s.lxmf.notifyUser('bob', 'password_changed', {});
    await s.lxmf.idle();
    assert.equal(s.bridge.to(A1).length, 3);
    assert.equal(s.lxmf.perAddress.recent(A1).length, 3, 'each of the 3 tries counted');
    // The second message gets 3 of the 3 left, and a third has none: its first try is dropped.
    s.lxmf.notifyUser('bob', 'password_changed', {});
    await s.lxmf.idle();
    assert.equal(s.bridge.to(A1).length, 6);
    s.lxmf.notifyUser('bob', 'password_changed', {});
    await s.lxmf.idle();
    assert.equal(s.bridge.to(A1).length, 6);
    // One left only: the first try goes, the retry is dropped and logged.
    s.clock.t += 60 * 60_000;
    for (let i = 0; i < 4; i++) s.lxmf.perAddress.take(A1);
    s.lxmf.perAddress.take(A1);
    s.bridge.calls.length = 0;
    s.lxmf.notifyUser('bob', 'password_changed', {});
    await s.lxmf.idle();
    assert.equal(s.bridge.to(A1).length, 1, 'the retry was dropped');
    assert.ok(s.logs.some((l) => l.includes('dropped to keep under the limit')));
  } finally {
    await s.close();
  }
});

test('a node alert is retried after the bridge was unreachable, an account alert is not', async () => {
  const s = await setup();
  try {
    await confirmDirect(s, 'bob', A1, true);
    s.bridge.down = true;
    s.lxmf.notifyNode('down', 'a.test:1 is down');
    await s.lxmf.idle();
    assert.equal(s.logs.filter((l) => l.includes('bridge-unreachable') && l.includes('try 2 of 3 follows')).length, 1);
    assert.equal(s.logs.filter((l) => l.includes('bridge-unreachable') && l.includes('giving up')).length, 1);
    s.logs.length = 0;
    s.lxmf.notifyUser('bob', 'password_changed', {});
    await s.lxmf.idle();
    assert.equal(s.logs.filter((l) => l.includes('try 2 of 3 follows')).length, 0);
    assert.equal(s.logs.filter((l) => l.includes('giving up')).length, 1);
    // Three tries of the node alert and one of the account alert counted.
    assert.equal(s.lxmf.perAddress.recent(A1).length, 4);
  } finally {
    await s.close();
  }
});

test('a bridge 429 with Retry-After stops all sending to that address until then, and not to others', async () => {
  const s = await setup();
  try {
    await confirmDirect(s, 'bob', A1);
    await confirmDirect(s, 'carol', A2);
    s.bridge.status = 429;
    s.bridge.headers = { 'Retry-After': '600' };
    s.lxmf.notifyUser('bob', 'password_changed', {});
    await s.lxmf.idle();
    assert.equal(s.bridge.to(A1).length, 1, 'a 429 is not tried again');
    s.bridge.status = 202;
    s.bridge.headers = {};
    s.lxmf.notifyUser('bob', 'password_changed', {});
    s.lxmf.notifyUser('carol', 'password_changed', {});
    await s.lxmf.idle();
    assert.equal(s.bridge.to(A1).length, 1, 'held back');
    assert.equal(s.bridge.to(A2).length, 1, 'another address is not');
    assert.ok(s.logs.some((l) => /a message to 01234567 was dropped .*\(10 minutes to go\)/.test(l)));
    // A code too is held back, with the bridge's wait.
    const held = await s.lxmf.sendCode('bob', A1);
    assert.equal(held.status, 429);
    assert.equal(s.bridge.to(A1).length, 1);
    s.clock.t += 601_000;
    s.lxmf.notifyUser('bob', 'password_changed', {});
    await s.lxmf.idle();
    assert.equal(s.bridge.to(A1).length, 2, 'sent again once the time has passed');
  } finally {
    await s.close();
  }
});

test('overlapping sendCode calls: one that fails does not put back an old code over the code of a later call', async () => {
  const s = await setup();
  try {
    const gates = [];
    const calls = [];
    s.lxmf.fetchFn = (url, opts) => new Promise((resolve) => {
      calls.push(JSON.parse(opts.body));
      gates.push((status) => resolve({ ok: status < 300, status, headers: new Headers(), body: null }));
    });
    // The user has a code already (to A1), then asks again for A2 while a resend to A2 is in flight.
    s.codes.push('111111', '222222', '333333');
    const first = s.lxmf.sendCode('bob', A1);
    gates[0](202);
    assert.equal((await first).ok, true);
    const second = s.lxmf.sendCode('bob', A2);
    const third = s.lxmf.sendCode('bob', A2);
    await new Promise((r) => setImmediate(r));
    assert.equal(calls.length, 3);
    // The earlier of the two fails after the later one went through: the later code stands.
    gates[2](202);
    assert.equal((await third).ok, true);
    gates[1](503);
    assert.equal((await second).ok, false);
    assert.deepEqual(s.lxmf.checkCode('bob', A2, '333333'), { ok: true, address: A2 });
    // And when it is still its own entry, the old code comes back (an hour on: the user's 3 codes are free again).
    s.clock.t += 60 * 60_000;
    s.codes.push('444444', '555555');
    const fine = s.lxmf.sendCode('bob', A1);
    gates[3](202);
    await fine;
    const bad = s.lxmf.sendCode('bob', A1);
    await new Promise((r) => setImmediate(r));
    gates[4](403);
    assert.equal((await bad).ok, false);
    assert.deepEqual(s.lxmf.checkCode('bob', A1, '444444'), { ok: true, address: A1 });
  } finally {
    await s.close();
  }
});

// ---- stale rows ----

test('at start the LXMF rows with no user, or of a user made again, are deleted; the others stay', async () => {
  const dataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'lxmf-'));
  const warnings = [];
  const open = (extra = {}) => UserStore.open({ keys: KEYS, dataDir, configUsers: [], warn: (m) => warnings.push(m), now: () => NOW, log: () => {}, ...extra });
  let store = await open();
  await store.createUser({ name: 'bob', role: 'manage', passwordHash: await hashPassword(BOB, undefined, fakeHasher, store.currentPepper()) });
  await store.createUser({ name: 'carol', role: 'viewer', passwordHash: await hashPassword(CAROL, undefined, fakeHasher, store.currentPepper()) });
  await store.setLxmf('bob', A1);
  await store.confirmLxmf('bob', A1);
  await store.setLxmf('carol', A2);
  store.close();
  const sql = new DatabaseSync(path.join(dataDir, DB_FILE));
  const value = (created) => JSON.stringify({ address: A3, confirmed: true, nodeAlerts: false, created });
  const put = sql.prepare('INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)');
  put.run('lxmf|store|ghost', value(null));
  put.run('lxmf|config|nobody', value('2020-01-01T00:00:00.000Z'));
  put.run('lxmf|store|carol', value('1999-01-01T00:00:00.000Z'));
  put.run('lxmf|store|', 'not json');
  put.run('lxmf|junk', '{}');
  const before = sql.prepare("SELECT count(*) AS n FROM meta WHERE key LIKE 'lxmf|%'").get().n;
  assert.equal(before, 6);
  sql.close();
  store = await open();
  assert.equal(store.lxmfOf('bob').addresses[0].address, A1, 'a live row stays');
  assert.equal(store.lxmfOf('carol'), null, 'a row of an older user of the same name is not hers');
  store.close();
  const after = new DatabaseSync(path.join(dataDir, DB_FILE), { readOnly: true });
  assert.deepEqual(after.prepare("SELECT key FROM meta WHERE key LIKE 'lxmf|%' ORDER BY key").all().map((r) => r.key), ['lxmf|store|bob']);
  after.close();
  assert.deepEqual(warnings.filter((m) => m.includes('LXMF address rows')), []);
  // Rows of live users that still do not fit in what is read (only another program could have made so many): said.
  store = await open();
  store.db.maxUsers = 0;
  store.db.pruneLxmf();
  store.close();
  assert.equal(warnings.filter((m) => m.includes('LXMF address rows')).length, 1);
});

// ---- audit ----

test('audit: setting, confirming and removing an address are lines with the user and the first 8 digits, never the address or the code', async () => {
  const s = await setup();
  try {
    const cookie = await logIn(s, 'bob');
    s.codes.push('314159');
    await api(s, '/api/account/lxmf/set', { address: A1 }, cookie);
    await lconfirm(s, cookie, '314159');
    await api(s, '/api/account/lxmf/node-alerts', { enabled: true }, cookie);
    s.codes.push('271828');
    await api(s, '/api/account/lxmf/set', { address: A2 }, cookie);
    await api(s, '/api/account/lxmf/resend', { address: A2 }, cookie);
    await api(s, '/api/account/lxmf/remove', { address: A2 }, cookie);
    const lines = (await auditLines(s)).filter((l) => l.event.startsWith('lxmf-'));
    assert.deepEqual(lines.map((l) => ({ ...l, time: undefined })), [
      { event: 'lxmf-address-set', user: 'bob', lxmf: '01234567', with: 'password' },
      { event: 'lxmf-address-confirmed', user: 'bob', lxmf: '01234567', with: 'password', address: '127.0.0.1' },
      { event: 'lxmf-node-alerts', user: 'bob', enabled: true, lxmf: '01234567' },
      { event: 'lxmf-address-set', user: 'bob', lxmf: 'fedcba98', with: 'password' },
      { event: 'lxmf-code-sent', user: 'bob', lxmf: 'fedcba98' },
      { event: 'lxmf-address-removed', user: 'bob', lxmf: 'fedcba98', with: 'password', address: '127.0.0.1' },
    ].map((l) => ({ ...l, time: undefined })));
    const text = await fs.readFile(s.audit.file, 'utf8');
    for (const secret of [A1, A2, '314159', '271828']) assert.equal(text.includes(secret), false, secret);
    // A refused attempt is no line: nothing was set.
    s.bridge.status = 403;
    await api(s, '/api/account/lxmf/set', { address: A3 }, await logIn(s, 'bob'));
    assert.equal((await auditLines(s)).filter((l) => l.event.startsWith('lxmf-')).length, 6);
  } finally {
    await s.close();
  }
});

// ---- storage ----

async function openStore(dataDir, { configUsers = [], now = () => NOW } = {}) {
  return UserStore.open({ keys: KEYS, dataDir, configUsers, warn: () => {}, now });
}
const hashFor = async (store, pw = BOB) => hashPassword(pw, undefined, fakeHasher, store.currentPepper());
const sqlRows = (dataDir, query, ...params) => {
  const sql = new DatabaseSync(path.join(dataDir, DB_FILE), { readOnly: true });
  try {
    return sql.prepare(query).all(...params);
  } finally {
    sql.close();
  }
};

test('storage: the address, whether it is confirmed and the node alerts are kept per user, for website users and config users, across restarts', async () => {
  const dataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'lxmf-store-'));
  const hash = await hashPassword(ALICE, undefined, fakeHasher);
  const config = loadConfig(`users:\n  - name: Alice\n    password_hash: '${hash}'\n    role: admin\nnodes:\n  - address: a.test:1\n`);
  let store = await openStore(dataDir, { configUsers: config.users });
  await store.createUser({ name: 'bob', role: 'manage', passwordHash: await hashFor(store) });
  assert.equal(store.lxmfOf('bob'), null);
  assert.equal(store.lxmfOf('nobody'), null);
  await store.setLxmf('bob', A1);
  assert.deepEqual(store.lxmfOf('bob'), { addresses: [{ address: A1, confirmed: false }], nodeAlerts: false });
  // The config user has no record of their own until something is kept for them; this makes it.
  assert.equal(store.factorRecord('alice'), null);
  await store.setLxmf('Alice', A2);
  await store.confirmLxmf('alice', A2);
  await store.setLxmfNodeAlerts('alice', true);
  assert.deepEqual(store.lxmfOf('alice'), { addresses: [{ address: A2, confirmed: true }], nodeAlerts: true });
  // Another user's, and a user that is not there: refused, and nothing is made.
  await assert.rejects(() => store.setLxmf('nobody', A3), { code: 'unknown' });
  await assert.rejects(() => store.confirmLxmf('bob', A2), { code: 'unknown' }, 'not the address that was set');
  await assert.rejects(() => store.setLxmfNodeAlerts('bob', true), { code: 'unknown' }, 'not confirmed');
  await assert.rejects(() => store.clearLxmf('carol', A1), { code: 'unknown' });
  await assert.rejects(() => store.clearLxmf('bob', A2), { code: 'unknown' }, 'not an address of bob');
  store.close();
  // On disk: one meta row each, with the address and the state, and no other row or column.
  const rows = sqlRows(dataDir, "SELECT key, value FROM meta WHERE key LIKE 'lxmf|%' ORDER BY key");
  assert.deepEqual(rows.map((r) => r.key), ['lxmf|config|alice', 'lxmf|store|bob']);
  assert.deepEqual(JSON.parse(rows[1].value), { created: new Date(NOW).toISOString(), nodeAlerts: false, addresses: [{ address: A1, confirmed: false }] });
  // A new start reads them again.
  store = await openStore(dataDir, { configUsers: config.users });
  assert.deepEqual(store.lxmfOf('bob'), { addresses: [{ address: A1, confirmed: false }], nodeAlerts: false });
  assert.deepEqual(store.lxmfOf('alice'), { addresses: [{ address: A2, confirmed: true }], nodeAlerts: true });
  assert.deepEqual(store.lxmfNodeRecipients(), [{ name: 'Alice', role: 'admin', address: A2 }]);
  // Logging in (a write of the record) leaves it alone.
  await store.recordLogin('bob');
  await store.recordLogin('alice');
  assert.deepEqual(store.lxmfOf('bob').addresses[0].address, A1);
  // Taking it away.
  await store.clearLxmf('bob', A1);
  assert.equal(store.lxmfOf('bob'), null);
  assert.deepEqual(sqlRows(dataDir, "SELECT key FROM meta WHERE key LIKE 'lxmf|%'").map((r) => r.key), ['lxmf|config|alice']);
  store.close();
});

test('storage: deleting a user clears the address; so does a config user who left the config file', async () => {
  const dataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'lxmf-store-'));
  const hash = await hashPassword(ALICE, undefined, fakeHasher);
  const config = loadConfig(`users:\n  - name: Alice\n    password_hash: '${hash}'\n    role: admin\n  - name: Zed\n    password_hash: '${hash}'\nnodes:\n  - address: a.test:1\n`);
  const store = await openStore(dataDir, { configUsers: config.users });
  await store.createUser({ name: 'bob', role: 'manage', passwordHash: await hashFor(store) });
  await store.setLxmf('bob', A1);
  await store.setLxmf('zed', A2);
  store.close();
  let again = await openStore(dataDir, { configUsers: config.users });
  await again.deleteUser('bob');
  assert.deepEqual(sqlRows(dataDir, "SELECT key FROM meta WHERE key LIKE 'lxmf|%'").map((r) => r.key), ['lxmf|config|zed']);
  // Zed is not in the config file any more: the record of their second factor, and the address, go (forgetOrphans).
  again.close();
  const gone = await UserStore.open({ keys: KEYS, dataDir, configUsers: loadConfig(`users:\n  - name: Alice\n    password_hash: '${hash}'\n    role: admin\nnodes:\n  - address: a.test:1\n`).users, warn: () => {}, now: () => NOW, dropOrphans: true });
  assert.equal(gone.forgetOrphans(), 1);
  assert.deepEqual(sqlRows(dataDir, "SELECT key FROM meta WHERE key LIKE 'lxmf|%'"), []);
  // A new user with the name of a deleted one has no address.
  await gone.createUser({ name: 'bob', role: 'viewer', passwordHash: await hashFor(gone) });
  assert.equal(gone.lxmfOf('bob'), null);
  gone.close();
});

test('storage: a row left behind by a release that deleted the user is not given to a new user of the same name, and a damaged row is no address', async () => {
  const dataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'lxmf-store-'));
  let t = NOW;
  const store = await openStore(dataDir, { now: () => t });
  await store.createUser({ name: 'bob', role: 'manage', passwordHash: await hashFor(store) });
  await store.setLxmf('bob', A1);
  await store.confirmLxmf('bob', A1);
  store.close();
  // As a release without this feature would leave it: the user deleted, the meta row still there.
  const sql = new DatabaseSync(path.join(dataDir, DB_FILE));
  sql.exec("DELETE FROM users WHERE name_key = 'bob'");
  assert.equal(sql.prepare("SELECT count(*) AS n FROM meta WHERE key = 'lxmf|store|bob'").get().n, 1);
  sql.close();
  t += 60_000;
  const again = await openStore(dataDir, { now: () => t });
  await again.createUser({ name: 'bob', role: 'manage', passwordHash: await hashFor(again) });
  assert.equal(again.lxmfOf('bob'), null, 'a new bob is not the old bob');
  // The new one sets their own; the old row is overwritten.
  await again.setLxmf('bob', A2);
  assert.equal(JSON.parse(sqlRows(dataDir, "SELECT value FROM meta WHERE key = 'lxmf|store|bob'")[0].value).addresses[0].address, A2);
  again.close();
  // Damaged rows: not JSON, the wrong shape, an address that is not hex, too long. The store still opens, and the user has none.
  const list = (addresses, extra = {}) => JSON.stringify({ created: null, nodeAlerts: false, addresses, ...extra });
  const entry = (address, confirmed = true) => ({ address, confirmed });
  const more = ['0'.repeat(32), '1'.repeat(32)];
  for (const value of [
    '{not json', '[]', 'null',
    JSON.stringify({ address: 'zz', confirmed: true, nodeAlerts: false, created: null }),
    JSON.stringify({ address: A1, confirmed: 'yes', nodeAlerts: false, created: null }),
    JSON.stringify({ address: A1, confirmed: true, nodeAlerts: false, created: 5 }),
    `{"address":"${A1}","confirmed":true,"nodeAlerts":false,"created":null,"x":"${'y'.repeat(300)}"}`,
    // The list shape, damaged: empty, not a list, 4 entries, the same address twice, a bad address or flag, node alerts with
    // nothing confirmed, an entry that is not an object, a created that is not text, and a row longer than 3 entries need.
    list([]), list('x'), list({}), list([entry(A1), entry(A2), entry(A3), entry(more[0])]), list([entry(A1), entry(A1, false)]),
    list([entry('zz')]), list([entry(A1.toUpperCase())]), list([{ address: A1, confirmed: 1 }]), list([null]), list([A1]),
    list([entry(A1, false)], { nodeAlerts: true }), list([entry(A1)], { nodeAlerts: 'yes' }), list([entry(A1)], { created: 5 }),
    list([entry(A1)], { x: 'y'.repeat(300) }),
  ]) {
    const db = new DatabaseSync(path.join(dataDir, DB_FILE));
    db.prepare("UPDATE meta SET value = ? WHERE key = 'lxmf|store|bob'").run(value);
    db.close();
    const reopened = await openStore(dataDir, { now: () => t });
    assert.equal(reopened.lxmfOf('bob'), null, value.slice(0, 30));
    reopened.close();
  }
});

test('storage: no schema change, so a release without this feature still reads the store: the schema version and tables are the same, and the rows are ones it ignores', async () => {
  const dataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'lxmf-store-'));
  const store = await openStore(dataDir);
  await store.createUser({ name: 'bob', role: 'manage', passwordHash: await hashFor(store) });
  const before = sqlRows(dataDir, 'SELECT type, name, sql FROM sqlite_schema ORDER BY name');
  const versionBefore = sqlRows(dataDir, 'PRAGMA user_version')[0].user_version;
  await store.setLxmf('bob', A1);
  await store.confirmLxmf('bob', A1);
  assert.deepEqual(sqlRows(dataDir, 'SELECT type, name, sql FROM sqlite_schema ORDER BY name'), before);
  assert.equal(sqlRows(dataDir, 'PRAGMA user_version')[0].user_version, versionBefore);
  assert.equal(SCHEMA_VERSION, 2);
  // The schema check of every version this release knows still passes with the rows in place.
  const sql = new DatabaseSync(path.join(dataDir, DB_FILE));
  checkSchema(sql, MIGRATIONS, versionBefore);
  // What the release without the feature reads of meta: its own rows, and no row of ours, so more users with an
  // address can never push them out of its first 32 rows.
  for (let i = 0; i < 40; i++) sql.prepare('INSERT INTO meta (key, value) VALUES (?, ?)').run(`lxmf|store|u${i}`, '{}');
  sql.close();
  store.close();
  const db = new DatabaseSync(path.join(dataDir, DB_FILE));
  const reader = new UserDb(db, { keys: KEYS });
  assert.deepEqual(Object.keys(reader.meta()), ['created']);
  db.close();
  // The store opens with 40 junk rows beside the real one.
  const reopened = await openStore(dataDir);
  assert.equal(reopened.lxmfOf('bob').addresses[0].address, A1);
  reopened.close();
});

test('storage: a store without a database keeps the address in memory, and a record with a bad address is refused when written', async () => {
  const store = new UserStore({ db: null, data: null, configUsers: [] });
  await store.createUser({ name: 'bob', role: 'viewer', passwordHash: await hashPassword(BOB, undefined, fakeHasher) });
  await store.setLxmf('bob', A1);
  await store.confirmLxmf('bob', A1);
  assert.equal(store.lxmfOf('bob').addresses[0].confirmed, true);
  await store.clearLxmf('bob', A1);
  assert.equal(store.lxmfOf('bob'), null);
  const dataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'lxmf-store-'));
  const real = await openStore(dataDir);
  await real.createUser({ name: 'bob', role: 'viewer', passwordHash: await hashFor(real) });
  for (const bad of ['', 'zz', A1.toUpperCase(), `${A1}0`, null, 5]) {
    await assert.rejects(() => real.setLxmf('bob', bad), /lxmf must be a list of 1 to 3 different 32 digit lower-case hex addresses/, String(bad));
  }
  assert.equal(real.lxmfOf('bob'), null);
  real.close();
});

test('storage: up to 3 addresses in one row, the 4th refused, each confirmed on its own, and node alerts follow the confirmed ones', async () => {
  const dataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'lxmf-store-'));
  let store = await openStore(dataDir);
  await store.createUser({ name: 'bob', role: 'manage', passwordHash: await hashFor(store) });
  const A4 = '77777777777777777777777777777777';
  await store.setLxmf('bob', A1);
  await store.setLxmf('bob', A2);
  await store.setLxmf('bob', A3);
  await store.setLxmf('bob', A2);
  assert.equal(store.lxmfOf('bob').addresses.length, 3, 'one the user has is not added twice');
  await assert.rejects(() => store.setLxmf('bob', A4), { code: 'limit' });
  assert.equal(store.lxmfOf('bob').addresses.length, 3);
  await assert.rejects(() => store.setLxmfNodeAlerts('bob', true), { code: 'unknown' }, 'none is confirmed');
  await store.confirmLxmf('bob', A2);
  await assert.rejects(() => store.confirmLxmf('bob', A4), { code: 'unknown' });
  await store.confirmLxmf('bob', A3);
  await store.setLxmfNodeAlerts('bob', true);
  assert.deepEqual(store.lxmfOf('bob'), { addresses: [{ address: A1, confirmed: false }, { address: A2, confirmed: true }, { address: A3, confirmed: true }], nodeAlerts: true });
  assert.deepEqual(store.lxmfNodeRecipients().map((r) => [r.name, r.address]), [['bob', A2], ['bob', A3]], 'one for each confirmed address');
  assert.equal(store.lxmfConfirmedElsewhere(A2, 'carol'), true);
  assert.equal(store.lxmfConfirmedElsewhere(A2, 'bob'), false);
  assert.equal(store.lxmfConfirmedElsewhere(A1, 'carol'), false, 'not confirmed');
  // One row, of the longest length a user can make, which is still read.
  const rows = sqlRows(dataDir, "SELECT key, value FROM meta WHERE key LIKE 'lxmf|%'");
  assert.deepEqual(rows.map((r) => r.key), ['lxmf|store|bob']);
  assert.ok(rows[0].value.length <= 274);
  store.close();
  store = await openStore(dataDir);
  assert.equal(store.lxmfOf('bob').addresses.length, 3);
  assert.equal(store.lxmfOf('bob').nodeAlerts, true);
  // Taking away the unconfirmed one keeps the rest; taking the confirmed ones away turns the node alerts off.
  await store.clearLxmf('bob', A1);
  assert.equal(store.lxmfOf('bob').nodeAlerts, true);
  await store.clearLxmf('bob', A2);
  assert.equal(store.lxmfOf('bob').nodeAlerts, true, 'one confirmed is left');
  await store.setLxmf('bob', A1);
  await store.clearLxmf('bob', A3);
  assert.deepEqual(store.lxmfOf('bob'), { addresses: [{ address: A1, confirmed: false }], nodeAlerts: false });
  await store.clearLxmf('bob', A1);
  assert.equal(store.lxmfOf('bob'), null);
  assert.deepEqual(sqlRows(dataDir, "SELECT key FROM meta WHERE key LIKE 'lxmf|%'"), []);
  store.close();
});

test('storage: the row of the first version (one address) is read as a list of one, and is written in the list shape when it changes', async () => {
  const dataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'lxmf-store-'));
  const store = await openStore(dataDir);
  await store.createUser({ name: 'bob', role: 'manage', passwordHash: await hashFor(store) });
  await store.createUser({ name: 'carol', role: 'viewer', passwordHash: await hashFor(store, CAROL) });
  await store.createUser({ name: 'dave', role: 'manage', passwordHash: await hashFor(store) });
  store.close();
  const sql = new DatabaseSync(path.join(dataDir, DB_FILE));
  const created = (n) => sql.prepare('SELECT created FROM users WHERE name_key = ?').get(n).created;
  const old = (n, confirmed, nodeAlerts, address = A1) => sql.prepare('INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)').run(`lxmf|store|${n}`, JSON.stringify({ address, confirmed, nodeAlerts, created: created(n) }));
  old('bob', true, true);
  old('carol', false, false, A2);
  old('dave', false, true, A3);
  sql.close();
  const again = await openStore(dataDir);
  assert.deepEqual(again.lxmfOf('bob'), { addresses: [{ address: A1, confirmed: true }], nodeAlerts: true });
  assert.deepEqual(again.lxmfOf('carol'), { addresses: [{ address: A2, confirmed: false }], nodeAlerts: false });
  assert.equal(again.lxmfOf('dave'), null, 'node alerts without a confirmed address was never made, and is no address');
  assert.deepEqual(again.lxmfNodeRecipients().map((r) => r.address), [A1]);
  // A change brings the list shape, with the old address kept.
  await again.setLxmf('bob', A2);
  const row = JSON.parse(sqlRows(dataDir, "SELECT value FROM meta WHERE key = 'lxmf|store|bob'")[0].value);
  assert.deepEqual(row.addresses, [{ address: A1, confirmed: true }, { address: A2, confirmed: false }]);
  assert.equal(row.address, undefined);
  assert.equal(row.nodeAlerts, true);
  again.close();
  // The longest row 3 addresses need is read, and one longer is not.
  const sql2 = new DatabaseSync(path.join(dataDir, DB_FILE));
  const longest = JSON.stringify({ created: created2(sql2, 'carol'), nodeAlerts: false, addresses: [A1, A2, A3].map((a) => ({ address: a, confirmed: false })) });
  assert.ok(longest.length <= 274);
  sql2.prepare('UPDATE meta SET value = ? WHERE key = ?').run(longest, 'lxmf|store|carol');
  sql2.close();
  const third = await openStore(dataDir);
  assert.equal(third.lxmfOf('carol').addresses.length, 3);
  third.close();
});
function created2(sql, n) {
  return sql.prepare('SELECT created FROM users WHERE name_key = ?').get(n).created;
}

test('four codes an hour to a fresh address and to one another user confirmed get the same answers, 429 and Retry-After included', async () => {
  const s = await setup();
  try {
    for (const n of ['dave', 'erin']) await addUser(s, n);
    await confirmDirect(s, 'bob', A2);
    const asks = async (address) => {
      const out = [];
      for (const n of ['carol', 'alice', 'dave', 'erin']) out.push(await s.lxmf.sendCode(n, address));
      return out.map((a) => ({ ...a, expiresAt: undefined, error: a.error?.replace(/in \d+ \w+\./, 'in N.') }));
    };
    const fresh = await asks(A1);
    s.clock.t += 60 * 60_000 + 1;
    const confirmed = await asks(A2);
    assert.deepEqual(confirmed, fresh);
    assert.deepEqual(fresh.map((a) => a.ok), [true, true, true, false]);
    assert.equal(fresh[3].status, 429);
    assert.equal(typeof fresh[3].retryAfter, 'number');
    assert.equal(s.bridge.to(A2).length, 0, 'nothing was posted for the confirmed one');
    assert.equal(s.bridge.to(A1).length, 3);
    // Through the page too: the same status, body and Retry-After for a 429.
    const page = async (address, user) => api(s, '/api/account/lxmf/set', { address }, await logIn(s, user));
    s.clock.t += 60 * 60_000 + 1;
    const a = await page(A1, 'carol');
    const b = await page(A2, 'alice');
    assert.equal(a.status, b.status);
    assert.deepEqual(Object.keys(a.json()).sort(), Object.keys(b.json()).sort());
  } finally {
    await s.close();
  }
});

test('a code to an address another user confirmed waits a short random time; a real send does not', async () => {
  const waits = [];
  const s = await setup({ lxmfExtra: { sleep: async (ms) => void waits.push(ms) } });
  try {
    await confirmDirect(s, 'bob', A2);
    await s.lxmf.sendCode('carol', A1);
    assert.deepEqual(waits, [], 'no wait for a real send');
    for (let i = 0; i < 20; i++) await s.lxmf.sendCode(`u${i}`, A2);
    assert.equal(waits.length, 20);
    for (const ms of waits) assert.ok(ms >= 20 && ms <= 150, String(ms));
  } finally {
    await s.close();
  }
});

test('different addresses an hour: codes take at most half, node alerts leave 5, and the pentest case still delivers the account alert', async () => {
  const s = await setup({ channelExtra: { perAddressPerHour: 10, addressesPerHour: 10 } });
  try {
    for (const n of ['dave', 'erin', 'frank']) await addUser(s, n);
    await addUser(s, 'hank');
    await confirmDirect(s, 'hank', A3);
    const hex = (i) => String(i).padStart(2, '0').repeat(16);
    const results = [];
    // Four users ask codes for 10 different addresses.
    for (let i = 0; i < 10; i++) results.push((await s.lxmf.sendCode(['dave', 'erin', 'frank', 'carol'][i % 4], hex(i))).ok);
    assert.deepEqual(results, [true, true, true, true, true, false, false, false, false, false], 'half of 10');
    await s.lxmf.idle();
    s.lxmf.notifyUser('hank', 'password_changed', {});
    await s.lxmf.idle();
    assert.equal(s.bridge.to(A3).filter((c) => c.body.event === 'password_changed').length, 1);
    // Node alerts to new addresses stop 5 short of the 10 (the codes' 5 already count).
    await confirmDirect(s, 'bob', A1, true);
    s.lxmf.notifyNode('down', 'a.test:1 is down');
    await s.lxmf.idle();
    assert.equal(s.bridge.to(A1).length, 0, 'the codes hold 5 of the 10 addresses, so node alerts may not take another and 5 stay for account alerts');
  } finally {
    await s.close();
  }
  const t = await setup({ channelExtra: { perAddressPerHour: 10, addressesPerHour: 15 } });
  try {
    // 15: codes up to 7, codes and node alerts up to 10.
    const ok = [];
    for (let i = 0; i < 9; i++) ok.push((await t.lxmf.sendCode(`u${i % 3}x${Math.floor(i / 3)}`, String(i).padStart(2, '0').repeat(16))).ok);
    assert.equal(ok.filter(Boolean).length, 7);
  } finally {
    await t.close();
  }
  assert.throws(() => new LxmfAlerts({ channel: channel({ addressesPerHour: 9 }), store: {}, fetchFn: async () => ({}) }), /addresses_per_hour must be a whole number of at least 10/);
});

// ---- the step-up of adding, confirming and removing an address ----

test('adding, confirming and removing an address need the password (and the second step when one is on), and are limited like the other factor changes', async () => {
  const s = await setup();
  try {
    let cookie = await logIn(s);
    s.codes.push('246810', '135791');
    // No password, a wrong one: refused, nothing is sent or kept.
    const noPassword = await rawApi(s, '/api/account/lxmf/set', { address: A1 }, cookie);
    assert.equal(noPassword.status, 400);
    assert.equal(noPassword.json().field, 'password');
    const wrong = await rawApi(s, '/api/account/lxmf/set', { address: A1, password: 'not it' }, cookie);
    assert.equal(wrong.status, 400);
    assert.equal(wrong.json().field, 'password');
    assert.equal(s.bridge.calls.length, 0);
    assert.equal(s.store.lxmfOf('bob'), null);
    // The password given: it goes through, and the audit line says how it was confirmed.
    assert.equal((await rawApi(s, '/api/account/lxmf/set', { address: A1, password: BOB }, cookie)).status, 200);
    // Confirming asks for it too: the right code with no password confirms nothing.
    assert.equal((await rawApi(s, '/api/account/lxmf/confirm', { address: A1, lxmfCode: '246810' }, cookie)).json().field, 'password');
    assert.equal(s.store.lxmfOf('bob').addresses[0].confirmed, false);
    // A new code needs only the recent password: no step-up.
    assert.equal((await rawApi(s, '/api/account/lxmf/resend', { address: A1 }, cookie)).status, 200);
    assert.equal((await rawApi(s, '/api/account/lxmf/confirm', { address: A1, lxmfCode: '135791', password: BOB }, cookie)).status, 200);
    // Removing asks for it.
    const removeWithout = await rawApi(s, '/api/account/lxmf/remove', { address: A1 }, cookie);
    assert.equal(removeWithout.status, 400);
    assert.equal(removeWithout.json().field, 'password');
    assert.equal(s.store.lxmfOf('bob').addresses.length, 1);
    assert.equal((await rawApi(s, '/api/account/lxmf/remove', { address: A1, password: BOB }, cookie)).status, 200);
    // The node alerts box is not one of them: the recent password is enough.
    await confirmAddress(s, await later(s), 'bob', A1);
    assert.equal((await rawApi(s, '/api/account/lxmf/node-alerts', { enabled: true }, await later(s))).status, 200);
    // They are limited, like the passkey changes: 5 an hour for a session.
    cookie = await later(s);
    s.codes.push('111111');
    const results = [];
    for (let i = 0; i < 6; i++) results.push((await rawApi(s, '/api/account/lxmf/remove', { address: A2, password: BOB }, cookie)).status);
    assert.deepEqual(results, [409, 409, 409, 409, 409, 429]);
  } finally {
    await s.close();
  }
});

test('with two-step sign-in on, an address is changed only with the second step as well: a code from the app, or a passkey', async () => {
  const s = await setup();
  try {
    const cookie = await logIn(s, 'bob');
    const { a } = await addPasskey(s, cookie, BOB, {}, 'Work laptop');
    const stepUp = async () => {
      const c = await api(s, '/api/account/passkeys/challenge', {}, cookie);
      return { passkey: a.get({ challenge: c.json().options.challenge, origin: ORIGIN, rpId: c.json().options.rpId }) };
    };
    s.codes.push('654321');
    const without = await rawApi(s, '/api/account/lxmf/set', { address: A1, password: BOB }, cookie);
    assert.equal(without.status, 400);
    assert.equal(without.json().secondFactor, true);
    assert.equal(s.bridge.calls.length, 0);
    assert.equal(s.store.lxmfOf('bob'), null);
    // A wrong code is told as one, and sends nothing.
    const bad = await rawApi(s, '/api/account/lxmf/set', { address: A1, password: BOB, code: '000000' }, cookie);
    assert.equal(bad.status, 400);
    assert.equal(bad.json().field, 'code');
    // The passkey confirms it.
    const done = await rawApi(s, '/api/account/lxmf/set', { address: A1, password: BOB, ...(await stepUp()) }, cookie);
    assert.equal(done.status, 200, done.text);
    // Confirming and removing need it too (the LXMF code is its own field, lxmfCode).
    assert.equal((await rawApi(s, '/api/account/lxmf/confirm', { address: A1, lxmfCode: '654321', password: BOB }, cookie)).json().secondFactor, true);
    assert.equal((await rawApi(s, '/api/account/lxmf/confirm', { address: A1, lxmfCode: '654321', password: BOB, ...(await stepUp()) }, cookie)).status, 200);
    assert.equal((await rawApi(s, '/api/account/lxmf/remove', { address: A1, password: BOB }, cookie)).json().secondFactor, true);
    assert.equal(s.store.lxmfOf('bob').addresses.length, 1);
    assert.equal((await rawApi(s, '/api/account/lxmf/remove', { address: A1, password: BOB, ...(await stepUp()) }, cookie)).status, 200);
    assert.equal(s.store.lxmfOf('bob'), null);
    const lines = (await auditLines(s)).filter((l) => l.event.startsWith('lxmf-'));
    assert.deepEqual(lines.map((l) => l.with), ['password+passkey', 'password+passkey', 'password+passkey']);
  } finally {
    await s.close();
  }
});

// ---- the password used from a new browser ----

const deviceCookieOf = (r) => (r.headers['set-cookie'] ?? []).map((c) => c.split(';')[0]).find((c) => c.startsWith(`${DEVICE_COOKIE}=`));
const loginFrom = (s, name, password, device) => request(s.port, { method: 'POST', path: '/login', headers: { ...FORM, ...(device ? { Cookie: device } : {}) }, body: new URLSearchParams({ name, password }).toString() });
const newDeviceAlerts = (s) => s.bridge.named().filter((c) => c.body.event === 'sign_in_new_device');

test('a right password from a browser that is not a known device is told to every confirmed address of the user, with the site address and no IP address or device id', async () => {
  const s = await setup({ site: { url: ORIGIN } });
  try {
    await confirmDirect(s, 'bob', A1);
    await confirmDirect(s, 'bob', A2);
    await s.store.setLxmf('bob', A3);
    const first = await loginFrom(s, 'bob', BOB);
    assert.equal(first.status, 200, first.text);
    await s.lxmf.idle();
    const sent = newDeviceAlerts(s);
    assert.deepEqual(sent.map((c) => c.body.to).sort(), [A1, A2].sort(), 'every confirmed address, not the one that waits for its code');
    assert.equal(sent[0].body.message, '[rettui status] The password of your account bob was just used to sign in to https://status.example.org from a new browser at 2027-01-15 08:00 UTC. If this was not you, change your password.');
    const device = deviceCookieOf(first);
    assert.ok(device);
    for (const c of sent) {
      assert.equal(c.raw.includes('127.0.0.1'), false, 'no IP address');
      assert.equal(c.raw.includes(device.split('=')[1]), false, 'no device id');
    }
    // The browser is known now: signing in from it again says nothing.
    s.bridge.calls.length = 0;
    s.clock.t += 20 * 60_000;
    assert.equal((await loginFrom(s, 'bob', BOB, device)).status, 200);
    await s.lxmf.idle();
    assert.equal(newDeviceAlerts(s).length, 0);
    // Without the site address the words stay as they are.
    assert.equal(accountMessage('sign_in_new_device', 'bob', {}, NOW, 'x').includes('undefined'), false);
  } finally {
    await s.close();
  }
});

test('the alert about a new browser is sent before the second step, whether or not it is completed, and a wrong password, a user with no confirmed address and a passkey alone send none', async () => {
  const s = await setup();
  try {
    // A user who has an address that is not confirmed: nothing.
    await s.store.setLxmf('carol', A2);
    assert.equal((await loginFrom(s, 'carol', CAROL)).status, 200);
    await s.lxmf.idle();
    assert.equal(s.bridge.named().length, 0);
    // A wrong password: nothing.
    await confirmDirect(s, 'bob', A1);
    assert.equal((await loginFrom(s, 'bob', 'not it')).status, 401);
    await s.lxmf.idle();
    assert.equal(s.bridge.named().length, 0);
    // With a passkey as the second step the password alone is not a sign in, and is told all the same.
    const { a, handle } = await passkeyOnlyBob(s);
    await confirmDirect(s, 'bob', A1);
    await s.lxmf.idle();
    s.bridge.calls.length = 0;
    s.clock.t += 20 * 60_000;
    const step = await loginFrom(s, 'bob', BOB);
    assert.equal(step.status, 200);
    assert.equal(step.json().secondFactor, true, 'the second step is still to come');
    await s.lxmf.idle();
    assert.equal(newDeviceAlerts(s).length, 1, 'told although the second step is never completed');
    // A passkey alone: it is not the password, so nothing is sent.
    s.clock.t += 20 * 60_000;
    s.bridge.calls.length = 0;
    const begin = await request(s.port, { method: 'POST', path: '/login/passkey/begin', headers: FORM, body: '' });
    const { token, options } = begin.json();
    const done = await postForm(s, '/login/passkey/finish', { token, credential: JSON.stringify(a.get({ challenge: options.challenge, origin: ORIGIN, rpId: options.rpId, userHandle: handle })) });
    assert.equal(done.status, 200, done.text);
    await s.lxmf.idle();
    assert.equal(s.bridge.named().length, 0, 'a passkey alone is no password');
  } finally {
    await s.close();
  }
});

test('the alert about a new browser is at most one in 15 minutes for a user, takes the share of the account alerts, and never delays or fails the sign in', async () => {
  const s = await setup();
  try {
    await confirmDirect(s, 'bob', A1);
    for (let i = 0; i < 5; i++) assert.equal((await loginFrom(s, 'bob', BOB)).status, 200);
    await s.lxmf.idle();
    assert.equal(newDeviceAlerts(s).length, 1, 'five sign ins from new browsers, one alert');
    s.clock.t += NEW_DEVICE_ALERT_MS - 1000;
    await loginFrom(s, 'bob', BOB);
    await s.lxmf.idle();
    assert.equal(newDeviceAlerts(s).length, 1);
    s.clock.t += 1000;
    await loginFrom(s, 'bob', BOB);
    await s.lxmf.idle();
    assert.equal(newDeviceAlerts(s).length, 2, '15 minutes on, another');
    // Another user has a count of their own.
    await confirmDirect(s, 'carol', A2);
    await loginFrom(s, 'carol', CAROL);
    await s.lxmf.idle();
    assert.equal(newDeviceAlerts(s).length, 3);
  } finally {
    await s.close();
  }
  // An account alert: it goes out when the node alerts have used up their share of the address.
  const t = await setup();
  try {
    await confirmDirect(t, 'bob', A1, true);
    for (let i = 0; i < 20; i++) t.lxmf.notifyNode('down', 'a.test:1 is down');
    await t.lxmf.idle();
    assert.equal(t.bridge.to(A1).length, 7);
    assert.equal((await loginFrom(t, 'bob', BOB)).status, 200);
    await t.lxmf.idle();
    assert.equal(newDeviceAlerts(t).length, 1);
  } finally {
    await t.close();
  }
  // A bridge that never answers, and a queue that throws: the sign in is answered at once all the same.
  const u = await setup();
  try {
    await confirmDirect(u, 'bob', A1);
    u.lxmf.fetchFn = () => new Promise(() => {});
    const t0 = Date.now();
    assert.equal((await loginFrom(u, 'bob', BOB)).status, 200);
    assert.ok(Date.now() - t0 < 2000);
    u.clock.t += NEW_DEVICE_ALERT_MS;
    u.lxmf.notifyUser = () => {
      throw new Error('boom');
    };
    assert.equal((await loginFrom(u, 'bob', BOB)).status, 200);
  } finally {
    u.lxmf.stop();
    await u.close();
  }
});

// ---- races and the second step ----

test('a resend whose post is still on its way when the address is removed does not bring the address back', async () => {
  const s = await setup();
  try {
    const cookie = await logIn(s);
    s.codes.push('111111', '222222');
    assert.equal((await api(s, '/api/account/lxmf/set', { address: A1 }, cookie)).status, 200);
    // The bridge holds the next post open.
    let release;
    let started;
    const reached = new Promise((r) => (started = r));
    const realFetch = s.lxmf.fetchFn;
    s.lxmf.fetchFn = (url, opts) => {
      started();
      return new Promise((resolve) => (release = () => resolve(realFetch(url, opts))));
    };
    const resend = api(s, '/api/account/lxmf/resend', { address: A1 }, cookie);
    await reached;
    assert.equal((await api(s, '/api/account/lxmf/remove', { address: A1 }, cookie)).status, 200);
    release();
    const answer = await resend;
    assert.equal(answer.status, 409);
    assert.deepEqual(answer.json(), { error: 'Your LXMF addresses changed meanwhile. Reload the page.' });
    assert.equal(s.store.lxmfOf('bob'), null, 'still removed, and nobody asked for the password to add it');
    assert.equal(s.lxmf.pendingFor('bob', A1), null, 'the code that went out is no good');
    assert.equal(s.lxmf.peekCode('bob', A1, '222222').reason, 'none');
  } finally {
    await s.close();
  }
});

test('two adds at once with 2 addresses saved: only one goes on, and only one code is sent', async () => {
  const s = await setup();
  try {
    await confirmDirect(s, 'bob', A1);
    await s.store.setLxmf('bob', A2);
    const a = await logIn(s);
    const b = await logIn(s);
    s.codes.push('121212', '343434');
    const [x, y] = await Promise.all([api(s, '/api/account/lxmf/set', { address: A3 }, a), api(s, '/api/account/lxmf/set', { address: '77777777777777777777777777777777' }, b)]);
    assert.deepEqual([x.status, y.status].sort(), [200, 409]);
    await s.lxmf.idle();
    assert.equal(s.bridge.named().filter((c) => c.body.event === 'lxmf_check').length, 1);
    assert.equal(s.store.lxmfOf('bob').addresses.length, 3);
    // The same address twice at once: one code too.
    const t = await setup();
    try {
      const c = await logIn(t);
      const d = await logIn(t);
      t.codes.push('565656', '787878');
      const [p, q] = await Promise.all([api(t, '/api/account/lxmf/set', { address: A1 }, c), api(t, '/api/account/lxmf/set', { address: A1 }, d)]);
      assert.equal(t.store.lxmfOf('bob').addresses.length, 1);
      assert.equal([p.status, q.status].filter((n) => n === 200).length >= 1, true);
    } finally {
      await t.close();
    }
  } finally {
    await s.close();
  }
});

test('a mistyped LXMF code does not spend the second step: the recovery code sent with it is still good', async () => {
  const s = await setup();
  try {
    const cookie = await logIn(s, 'bob');
    const { a, recoveryCodes } = await addPasskey(s, cookie, BOB, {}, 'Work laptop');
    assert.ok(recoveryCodes.length > 0);
    const stepUp = async () => {
      const c = await api(s, '/api/account/passkeys/challenge', {}, cookie);
      return { passkey: a.get({ challenge: c.json().options.challenge, origin: ORIGIN, rpId: c.json().options.rpId }) };
    };
    s.codes.push('456456');
    assert.equal((await rawApi(s, '/api/account/lxmf/set', { address: A1, password: BOB, ...(await stepUp()) }, cookie)).status, 200);
    const recovery = recoveryCodes[0];
    const wrong = await rawApi(s, '/api/account/lxmf/confirm', { address: A1, lxmfCode: '000000', password: BOB, recovery }, cookie);
    assert.equal(wrong.status, 400);
    assert.equal(wrong.json().field, 'lxmfCode');
    assert.equal(wrong.json().reason, 'wrong');
    // The recovery code was never looked at, so it still works, with the right LXMF code.
    const right = await rawApi(s, '/api/account/lxmf/confirm', { address: A1, lxmfCode: '456456', password: BOB, recovery }, cookie);
    assert.equal(right.status, 200, right.text);
    const lines = (await auditLines(s)).filter((l) => l.event === 'recovery-code-used');
    assert.deepEqual(lines.map((l) => l.left), [recoveryCodes.length - 1], 'used once, by the confirm that worked');
    assert.equal((await auditLines(s)).find((l) => l.event === 'lxmf-address-confirmed').with, 'password+recovery');
  } finally {
    await s.close();
  }
});

test('the alert about a new browser is queued after the reply: a slow store lookup cannot hold the sign in', async () => {
  const s = await setup();
  try {
    await confirmDirect(s, 'bob', A1);
    let called = false;
    s.lxmf.notifyUser = () => {
      called = true;
    };
    const reply = await loginFrom(s, 'bob', BOB);
    assert.equal(reply.status, 200);
    await new Promise((r) => setImmediate(r));
    assert.equal(called, true, 'queued once the reply was sent');
    assert.match(await fs.readFile(path.join(publicDir, '..', 'lib', 'app.js'), 'utf8'), /setImmediate\(\(\) => \{\s*try \{\s*alerts\?\.lxmf\?\.notifyUser\(who, 'sign_in_new_device'/);
  } finally {
    await s.close();
  }
});

test('the limit of the confirm route stops guessing: the 6th wrong code in an hour from one session is refused, and a new session is limited per user', async () => {
  const s = await setup();
  try {
    const cookie = await logIn(s);
    s.codes.push('808080');
    assert.equal((await api(s, '/api/account/lxmf/set', { address: A1 }, cookie)).status, 200);
    const other = await logIn(s);
    const answers = [];
    for (let i = 0; i < 6; i++) answers.push((await lconfirm(s, cookie, '000000')).status);
    assert.deepEqual(answers, [400, 400, 400, 400, 400, 429], 'the 6th is refused before the code is looked at');
    // The right code is refused too while the session is held (the guess and the answer cost the same).
    assert.equal((await lconfirm(s, cookie, '808080')).status, 429);
    // Another session of the same user: 5 more, but the user's 10 an hour are shared (the first session used 5 of them).
    const more = [];
    for (let i = 0; i < 6; i++) more.push((await lconfirm(s, other, '000000')).status);
    assert.deepEqual(more, [400, 400, 400, 400, 400, 429]);
    assert.equal(s.store.lxmfOf('bob').addresses[0].confirmed, false);
    // An hour on the room is back, and the code (15 minutes) has run out: a new one is needed.
    const later1 = await later(s);
    assert.equal((await lconfirm(s, later1, '808080')).json().reason, 'expired');
  } finally {
    await s.close();
  }
});
