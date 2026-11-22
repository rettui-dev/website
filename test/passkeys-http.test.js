// Passkeys through HTTP, as the pages use them: the second sign-in step (POST /login and
// /login/passkey), the account API (add, rename, remove, confirm a change), the users API, with a
// software authenticator (helpers/soft-authenticator.js) in place of a browser.
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
import { CODE_EXPIRED, PASSKEY_FAILED, PASSKEY_SIGNIN_EXPIRED, PASSKEY_SIGNIN_FAILED, createApp } from '../lib/app.js';
import { CODE_USER_FREE, DEVICE_AUDIT_MS, MAX_FORM_BYTES, MAX_PASSKEY_FORM_BYTES, PASSKEY_SIGNIN_BURST, PASSKEY_SIGNIN_INTERVAL_MS, PENDING_MS, PENDING_TRIES, SIGNIN_BEGIN_BURST, createLogin, ipKey } from '../lib/login.js';
import { hashPassword } from '../lib/password.js';
import { UserStore } from '../lib/users.js';
import { Keyring } from '../lib/keys.js';
import { createAudit, createFailureLog } from '../lib/audit.js';
import { CHALLENGES_PER_SESSION, RECENT_AUTH_MS, REAUTHS_PER_PASSKEY_USER, REAUTH_PASSKEY_WINDOW_MS } from '../lib/account.js';
import { MAX_PASSKEYS, NO_PASSKEYS, createPasskeys, passkeyRef } from '../lib/passkeys.js';
import { base32Decode, hotp, stepAt, totp } from '../lib/totp.js';
import { SoftAuthenticator } from './helpers/soft-authenticator.js';
import { fakeHasher } from './helpers/fake-hasher.js';
import { FIRST_FACTOR_HOLD_MS, createFactorHolds } from '../lib/factor-hold.js';

const publicDir = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'public');
const NOW = 1_800_000_000_000;
const ORIGIN = 'https://status.example.org';
const RP_ID = 'status.example.org';
const ALICE = 'correct horse battery';
const BOB = 'bobs own password';
const KEYS = new Keyring(new Map([[1, crypto.randomBytes(32)]]));
const IP = '127.0.0.1';

// Alice (admin) is in the config file, bob (manage) a website user. siteUrl: the site's address,
// which passkeys are made for; null for none (passkeys off).
// manage: what createApp gets for the nodes managed from the website (none by default).
// loginSettings: over the login settings of the config (passkeySignIn: false turns off signing in with a passkey alone).
async function setup({ siteUrl = ORIGIN, manage = null, loginSettings = {} } = {}) {
  const dataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'passkeys-http-'));
  const hash = await hashPassword(ALICE, undefined, fakeHasher);
  const config = loadConfig(`users:\n  - name: Alice\n    password_hash: '${hash}'\n    role: admin\nnodes:\n  - address: a.test:1\n`);
  const clock = { t: NOW };
  const now = () => clock.t;
  const store = await UserStore.open({ keys: KEYS, dataDir, configUsers: config.users, warn: () => {}, now });
  await store.createUser({ name: 'bob', role: 'manage', passwordHash: await hashPassword(BOB, undefined, fakeHasher, store.currentPepper()) });
  const audit = createAudit({ dataDir, now });
  const failures = createFailureLog({ dataDir, now });
  const passkeys = siteUrl ? createPasskeys({ siteUrl, rpName: 'Status', store, now }) : NO_PASSKEYS;
  const logs = [];
  const login = createLogin({ users: config.users, store, settings: { ...config.login, ...loginSettings }, hasher: fakeHasher, now, audit, failures, sleep: async () => {}, passkeys, log: (m) => logs.push(m) });
  const monitor = new Monitor({ targets: config.targets, dataDir, probeFn: async () => ({ up: true, ms: 1 }) });
  const holds = createFactorHolds({ dataDir, now });
  const server = createApp({ monitor, publicDir, login, manage, holds });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return {
    port: server.address().port, clock, store, login, audit, failures, dataDir, logs, passkeys, holds,
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
const postForm = (s, p, fields, cookie) => request(s.port, { method: 'POST', path: p, headers: { ...FORM, ...(cookie ? { Cookie: cookie } : {}) }, body: new URLSearchParams(fields).toString() });
const api = (s, p, body, cookie) => request(s.port, { method: 'POST', path: p, headers: { ...JSON_HEADERS, ...(cookie ? { Cookie: cookie } : {}) }, body: typeof body === 'string' ? body : JSON.stringify(body) });
const get = (s, p, cookie) => request(s.port, { path: p, headers: cookie ? { Cookie: cookie } : {} });
const cookieOf = (r) => (r.headers['set-cookie']?.[0] ?? '').split(';')[0];
const alive = (s, cookie) => get(s, '/api/session', cookie).then((r) => r.json().name);
const auditLines = async (s) => {
  await s.audit.flush();
  return (await fs.readFile(s.audit.file, 'utf8').catch(() => '')).trim().split('\n').filter(Boolean).map((l) => JSON.parse(l)).filter((l) => l.event !== 'device-added');
};
const codeNow = (s, secret) => hotp(base32Decode(secret), stepAt(s.clock.t));

// A sign in with the password only (no second factor on): the session cookie.
async function logIn(s, name = 'bob', password = BOB) {
  const r = await postForm(s, '/login', { name, password });
  assert.equal(r.status, 200, r.text);
  assert.equal(r.json().ok, true, r.text);
  return cookieOf(r);
}

// The password step of a user with a second factor: the answer (pending, methods, passkey options).
async function passwordStep(s, name = 'bob', password = BOB) {
  const r = await postForm(s, '/login', { name, password });
  assert.equal(r.status, 200, r.text);
  assert.equal(r.json().secondFactor, true, r.text);
  return r.json();
}

// What the browser sends for a sign-in prompt: the authenticator's answer to the options' challenge.
const answer = (a, options, extra = {}) => a.get({ challenge: options.challenge, origin: ORIGIN, rpId: options.rpId ?? RP_ID, ...extra });
const sendPasskey = (s, pending, credential) => postForm(s, '/login/passkey', { pending, credential: typeof credential === 'string' ? credential : JSON.stringify(credential) });

// A full sign in with a passkey: the session cookie.
async function logInWithPasskey(s, a, name = 'bob', password = BOB) {
  const step = await passwordStep(s, name, password);
  const r = await sendPasskey(s, step.pending, answer(a, step.passkey));
  assert.equal(r.status, 200, r.text);
  return cookieOf(r);
}

// The step-up fields for a passkey: the challenge of passkeys/challenge, answered by a.
async function stepUpPasskey(s, cookie, a, extra = {}) {
  const c = await api(s, '/api/account/passkeys/challenge', {}, cookie);
  assert.equal(c.status, 200, c.text);
  return answer(a, c.json().options, extra);
}

// Adds a passkey through the account API: begin (with step-up), the authenticator, finish. stepUp:
// the step-up fields besides the password. Gives the authenticator and the answer of finish.
async function addPasskey(s, cookie, { password = BOB, stepUp = {}, name, fmt = 'none', authOptions = {}, a = new SoftAuthenticator(authOptions) } = {}) {
  const begin = await api(s, '/api/account/passkeys/begin', { password, ...stepUp }, cookie);
  assert.equal(begin.status, 200, begin.text);
  const { options } = begin.json();
  const credential = a.create({ challenge: options.challenge, origin: ORIGIN, rpId: options.rp.id, fmt });
  const finish = await api(s, '/api/account/passkeys/finish', name === undefined ? { credential } : { credential, name }, cookie);
  return { a, finish, options };
}

// Turns TOTP on for the signed-in user (with the step-up fields when a second factor is on): the secret.
async function enableTotp(s, cookie, password, stepUp = {}) {
  const setup = await api(s, '/api/account/totp/setup', { password, ...stepUp }, cookie);
  assert.equal(setup.status, 200, setup.text);
  const { secret } = setup.json();
  const on = await api(s, '/api/account/totp/enable', { code: totp(base32Decode(secret), s.clock.t) }, cookie);
  assert.equal(on.status, 200, on.text);
  s.clock.t += 30_000;
  return { secret, codes: on.json().recoveryCodes };
}

test('passkeys: the first one is added with the password alone, brings recovery codes and ends other sessions; then it signs in', async () => {
  const s = await setup();
  try {
    const cookie = await logIn(s);
    const other = await logIn(s);
    const account = (await get(s, '/api/account', cookie)).json();
    assert.equal(account.secondFactor, false);
    assert.deepEqual(account.stepUpMethods, []);
    assert.equal(account.recoveryCodesLeft, 0);
    assert.deepEqual(account.passkeys, { available: true, reason: null, origin: ORIGIN, rpId: RP_ID, max: MAX_PASSKEYS, signIn: true, list: [] });

    const { a, finish, options } = await addPasskey(s, cookie, { authOptions: { counter: 5 } });
    assert.equal(finish.status, 200, finish.text);
    const body = finish.json();
    assert.equal(body.ok, true);
    assert.equal(body.recoveryCodes.length, 10);
    assert.deepEqual(body.passkey, { id: passkeyRef(a.id), name: 'Passkey 1', created: new Date(NOW).toISOString(), lastUsed: null, synced: false, here: true });
    assert.equal(options.rp.id, RP_ID);
    assert.equal(options.authenticatorSelection.userVerification, 'required');
    // The first second factor ends every other session; this one stays.
    assert.equal(await alive(s, other), null);
    assert.equal(await alive(s, cookie), 'bob');

    const after = (await get(s, '/api/account', cookie)).json();
    assert.equal(after.secondFactor, true);
    assert.equal(after.recoveryCodesLeft, 10);
    assert.deepEqual(after.stepUpMethods, ['passkey', 'recovery']);
    assert.deepEqual(after.passkeys.list, [body.passkey]);
    assert.equal(after.totp.enabled, false);

    // A second one, named, with the first as the step-up: no codes, and no session ends.
    const third = await logIn(s, 'bob', BOB).catch(() => null);
    assert.equal(third, null, 'a passkey user no longer signs in with the password alone');
    const keep = await logInWithPasskey(s, a);
    const named = await addPasskey(s, cookie, { stepUp: { passkey: await stepUpPasskey(s, cookie, a) }, name: '  Work laptop ', authOptions: { alg: -8, backupEligible: true, backedUp: true } });
    assert.equal(named.finish.status, 200, named.finish.text);
    assert.equal(named.finish.json().recoveryCodes, undefined);
    assert.equal(named.finish.json().passkey.name, 'Work laptop');
    assert.equal(named.finish.json().passkey.synced, true);
    assert.equal(await alive(s, keep), 'bob');
    assert.equal(s.store.secondFactors('bob').recoveryCodesLeft, 10);

    // The sign in: password, then the passkey, with the options the first answer carried.
    const step = await passwordStep(s);
    assert.deepEqual(step.methods, ['passkey', 'recovery']);
    assert.equal(step.passkeyUnavailable, undefined);
    assert.equal(step.passkey.rpId, RP_ID);
    assert.equal(step.passkey.userVerification, 'required');
    assert.deepEqual(step.passkey.allowCredentials.map((c) => c.id).sort(), [a.id, named.a.id].sort());
    const done = await sendPasskey(s, step.pending, answer(named.a, step.passkey));
    assert.equal(done.status, 200, done.text);
    assert.deepEqual(done.json(), { ok: true, name: 'bob' });
    assert.equal(await alive(s, cookieOf(done)), 'bob');
    // The counter (two uses since it was added: a sign in and a step-up) and the time of use are kept.
    assert.equal(s.store.passkeyById('bob', a.id).counter, 7);
    assert.equal(s.store.passkeyById('bob', named.a.id).lastUsed, new Date(NOW).toISOString());

    const lines = await auditLines(s);
    assert.deepEqual(lines.filter((l) => l.event === 'passkey-added').map(({ event, user, passkey, first, address }) => ({ event, user, passkey, first, address })), [
      { event: 'passkey-added', user: 'bob', passkey: 'Passkey 1', first: true, address: IP },
      { event: 'passkey-added', user: 'bob', passkey: 'Work laptop', first: false, address: IP },
    ]);
  } finally {
    await s.close();
  }
});

test('passkeys: the second step falls back to the app code and to recovery codes', async () => {
  const s = await setup();
  try {
    const cookie = await logIn(s);
    const { a, finish } = await addPasskey(s, cookie);
    const codes = finish.json().recoveryCodes;
    // The app code is added with the passkey as the second factor of the step-up.
    const noFactor = await api(s, '/api/account/totp/setup', { password: BOB }, cookie);
    assert.equal(noFactor.status, 400);
    assert.equal(noFactor.json().secondFactor, true);
    const { secret, codes: newCodes } = await enableTotp(s, cookie, BOB, { passkey: await stepUpPasskey(s, cookie, a) });
    // Turning the app code on makes new recovery codes in place of the passkey's.
    assert.equal(newCodes.length, 10);
    assert.notDeepEqual(newCodes, codes);
    assert.equal(s.store.secondFactors('bob').recoveryCodesLeft, 10);

    const step = await passwordStep(s);
    assert.deepEqual(step.methods, ['passkey', 'totp', 'recovery']);
    assert.ok(step.passkey);
    const byCode = await postForm(s, '/login/code', { pending: step.pending, code: codeNow(s, secret) });
    assert.equal(byCode.status, 200, byCode.text);

    const again = await passwordStep(s);
    const old = await postForm(s, '/login/code', { pending: again.pending, recovery: codes[0] });
    assert.equal(old.status, 401, 'the codes of the passkey were replaced');
    const byRecovery = await postForm(s, '/login/code', { pending: again.pending, recovery: newCodes[0] });
    assert.equal(byRecovery.status, 200, byRecovery.text);
    assert.equal(s.store.secondFactors('bob').recoveryCodesLeft, 9);
  } finally {
    await s.close();
  }
});

test('passkeys: a passkey that does not work counts as a wrong code: the waits, the tries of the step, the failures log', async () => {
  const s = await setup();
  try {
    const cookie = await logIn(s);
    const { a } = await addPasskey(s, cookie);
    const stranger = new SoftAuthenticator();
    const step = await passwordStep(s);
    const pair = `user:bob|${ipKey(IP)}`;
    const before = { pair: s.login.codes.count(pair), user: s.login.codeUsers.count('user:bob'), address: s.login.addresses.count(ipKey(IP)) };
    let options = step.passkey;
    for (let i = 1; i < PENDING_TRIES; i++) {
      const r = await sendPasskey(s, step.pending, answer(stranger, options));
      assert.equal(r.status, 401, r.text);
      assert.equal(r.json().error, PASSKEY_FAILED);
      // Each failure comes with a new prompt, whose challenge is not the old one.
      assert.ok(r.json().passkey);
      assert.notEqual(r.json().passkey.challenge, options.challenge);
      options = r.json().passkey;
    }
    assert.equal(s.login.codes.count(pair), before.pair + PENDING_TRIES - 1);
    assert.equal(s.login.codeUsers.count('user:bob'), before.user + PENDING_TRIES - 1);
    assert.equal(s.login.addresses.count(ipKey(IP)), before.address + PENDING_TRIES - 1);
    // The last try of the step ends it, even with the right passkey after.
    const last = await sendPasskey(s, step.pending, answer(stranger, options));
    assert.equal(last.status, 401);
    assert.deepEqual(last.json(), { error: CODE_EXPIRED, restart: true });
    assert.deepEqual((await sendPasskey(s, step.pending, answer(a, options))).json(), { error: CODE_EXPIRED, restart: true });
    // Past the free tries the next step waits, as after wrong codes, for a passkey too.
    const next = await passwordStep(s);
    assert.equal(next.codeWait, undefined);
    assert.equal((await sendPasskey(s, next.pending, answer(stranger, next.passkey))).status, 401);
    const held = await passwordStep(s);
    assert.ok(held.codeWait > 0, JSON.stringify(held));
    const r = await sendPasskey(s, held.pending, answer(a, held.passkey));
    assert.equal(r.status, 429);
    assert.match(r.json().error, /^Too many wrong codes\. Try again in /);
    await s.failures.flush();
    const failures = (await fs.readFile(s.failures.file, 'utf8')).trim().split('\n').map((l) => JSON.parse(l));
    assert.ok(failures.some((l) => l.kind === 'second-factor-failures' || l.event === 'second-factor-failures'), JSON.stringify(failures));
  } finally {
    await s.close();
  }
});

test('passkeys: wrong passkeys from many addresses add up for the user', async () => {
  const s = await setup();
  try {
    const cookie = await logIn(s);
    await addPasskey(s, cookie);
    const stranger = new SoftAuthenticator();
    for (let i = 0; i < CODE_USER_FREE; i++) {
      const step = s.login.startSecondFactor('bob', `198.51.100.${i}`, { epoch: s.login.epochOf('bob') });
      const r = await s.login.finishSecondFactor(step.token, { passkey: answer(stranger, step.passkey) }, `198.51.100.${i}`);
      assert.equal(r.reason, 'invalid');
    }
    assert.equal(s.login.codeUsers.count('user:bob'), CODE_USER_FREE);
    const step = s.login.startSecondFactor('bob', '203.0.113.9', { epoch: s.login.epochOf('bob') });
    assert.equal((await s.login.finishSecondFactor(step.token, { passkey: answer(stranger, step.passkey) }, '203.0.113.9')).reason, 'invalid');
    assert.ok(s.login.codeUsers.wait('user:bob') > 0, 'the user is held back past the free tries');
  } finally {
    await s.close();
  }
});

test('passkeys: a challenge is used once: a replayed or old one fails, and so does a step that took too long', async () => {
  const s = await setup();
  try {
    const cookie = await logIn(s);
    const { a } = await addPasskey(s, cookie);
    const step = await passwordStep(s);
    const first = answer(a, step.passkey);
    // A broken answer uses the challenge up; the good answer to it is no good after.
    const broken = { ...first, response: { ...first.response, signature: Buffer.from('nope').toString('base64url') } };
    const r1 = await sendPasskey(s, step.pending, broken);
    assert.equal(r1.status, 401);
    const replay = await sendPasskey(s, step.pending, first);
    assert.equal(replay.status, 401);
    assert.equal(replay.json().error, PASSKEY_FAILED);
    const good = await sendPasskey(s, step.pending, answer(a, replay.json().passkey));
    assert.equal(good.status, 200, good.text);
    // The token is used up with the sign in.
    assert.deepEqual((await sendPasskey(s, step.pending, answer(a, replay.json().passkey))).json(), { error: CODE_EXPIRED, restart: true });
    // A step older than PENDING_MS is over.
    const late = await passwordStep(s);
    s.clock.t += PENDING_MS;
    assert.deepEqual((await sendPasskey(s, late.pending, answer(a, late.passkey))).json(), { error: CODE_EXPIRED, restart: true });
    // From another address the token is nothing.
    s.clock.t += 60_000;
    const away = await passwordStep(s);
    assert.equal((await s.login.finishSecondFactor(away.pending, { passkey: answer(a, away.passkey) }, '192.0.2.77')).reason, 'expired');
  } finally {
    await s.close();
  }
});

test('passkeys: endUser drops the open second steps with their challenges, and the account challenges', async () => {
  const s = await setup();
  try {
    const cookie = await logIn(s);
    const { a } = await addPasskey(s, cookie);
    const step = await passwordStep(s);
    const pending = s.login.pending.get(step.pending);
    assert.match(pending.challenge, /^[A-Za-z0-9_-]{43}$/);
    assert.equal(pending.challenge, step.passkey.challenge);
    // The step-up and registration challenges of the account page go too.
    const session = await logInWithPasskey(s, a);
    await api(s, '/api/account/passkeys/challenge', {}, session);
    const begin = await api(s, '/api/account/passkeys/begin', { password: BOB, passkey: await stepUpPasskey(s, session, a) }, session);
    assert.equal(begin.status, 200, begin.text);
    await api(s, '/api/account/passkeys/challenge', {}, session);
    assert.equal(s.passkeys.challengeCount, 2);
    const sid = s.login.session({ headers: { cookie: session } }).id;
    s.login.endUser('bob', sid);
    assert.equal(s.passkeys.challengeCount, 0);
    assert.equal(s.login.pending.size, 0);
    assert.deepEqual((await sendPasskey(s, step.pending, answer(a, step.passkey))).json(), { error: CODE_EXPIRED, restart: true });
    const b = new SoftAuthenticator();
    const finish = await api(s, '/api/account/passkeys/finish', { credential: b.create({ challenge: begin.json().options.challenge, origin: ORIGIN, rpId: RP_ID }) }, session);
    assert.equal(finish.status, 409);
    assert.deepEqual(finish.json(), { error: 'Adding the passkey took too long, or something changed meanwhile. Start again.' });
    assert.equal(s.store.passkeys('bob').length, 1);
  } finally {
    await s.close();
  }
});

test('passkeys: a counter that goes back is refused and is an audit line; a passkey of another user and a wrong user handle are refused', async () => {
  const s = await setup();
  try {
    const cookie = await logIn(s);
    const { a } = await addPasskey(s, cookie, { authOptions: { counter: 10 } });
    // Alice (a config user) has a passkey of her own.
    const aliceCookie = await logIn(s, 'alice', ALICE);
    const { a: hers, finish } = await addPasskey(s, aliceCookie, { password: ALICE });
    assert.equal(finish.status, 200, finish.text);

    let step = await passwordStep(s);
    const back = await sendPasskey(s, step.pending, answer(a, step.passkey, { counter: 3 }));
    assert.equal(back.status, 401);
    assert.equal(back.json().error, PASSKEY_FAILED);
    assert.equal(s.store.passkeyById('bob', a.id).counter, 10);
    const lines = await auditLines(s);
    const counter = lines.filter((l) => l.event === 'passkey-counter-error');
    assert.equal(counter.length, 1);
    assert.deepEqual({ ...counter[0], time: undefined }, { time: undefined, event: 'passkey-counter-error', user: 'bob', passkey: 'Passkey 1', address: IP });

    // Alice's passkey answering bob's prompt.
    const theirs = await sendPasskey(s, step.pending, answer(hers, back.json().passkey));
    assert.equal(theirs.status, 401);
    // A user handle that is not bob's.
    const handle = await sendPasskey(s, step.pending, answer(a, theirs.json().passkey, { userHandle: crypto.randomBytes(32).toString('base64url') }));
    assert.equal(handle.status, 401);
    // Bob's own user handle is fine.
    step = await passwordStep(s);
    const own = await sendPasskey(s, step.pending, answer(a, step.passkey, { userHandle: s.store.factorRecord('bob').passkeyUserId, counter: 20 }));
    assert.equal(own.status, 200, own.text);
  } finally {
    await s.close();
  }
});

test('passkeys: the form of /login/passkey: size, an empty or unreadable credential, no token', async () => {
  const s = await setup();
  try {
    const cookie = await logIn(s);
    const { a } = await addPasskey(s, cookie);
    const step = await passwordStep(s);
    assert.equal((await sendPasskey(s, step.pending, '')).status, 400);
    assert.equal(s.login.pending.get(step.pending).tries, 0, 'an empty answer is no try');
    const big = await postForm(s, '/login/passkey', { pending: step.pending, credential: 'x'.repeat(MAX_PASSKEY_FORM_BYTES) });
    assert.equal(big.status, 413);
    // Text that is not JSON counts as a passkey that did not work.
    const junk = await sendPasskey(s, step.pending, '{not json');
    assert.equal(junk.status, 401);
    assert.equal(junk.json().error, PASSKEY_FAILED);
    assert.equal(s.login.pending.get(step.pending).tries, 1);
    const array = await sendPasskey(s, step.pending, '[1,2]');
    assert.equal(array.status, 401);
    // Without a token (or with a made-up one) it is the same answer as for a code.
    assert.deepEqual((await sendPasskey(s, 'a'.repeat(43), answer(a, junk.json().passkey))).json(), { error: CODE_EXPIRED, restart: true });
    assert.deepEqual((await postForm(s, '/login/passkey', { credential: '{}' })).json(), { error: CODE_EXPIRED, restart: true });
    // Not from the page: refused before anything is read.
    const cross = await request(s.port, { method: 'POST', path: '/login/passkey', headers: { ...FORM, 'Sec-Fetch-Site': 'cross-site' }, body: 'pending=x&credential=%7B%7D' });
    assert.equal(cross.status, 403);
    // A wrong password says nothing of passkeys.
    const wrong = await postForm(s, '/login', { name: 'bob', password: 'not the password' });
    assert.equal(wrong.status, 401);
    assert.deepEqual(Object.keys(wrong.json()), ['error']);
    const nobody = await postForm(s, '/login', { name: 'nobody', password: 'not the password' });
    assert.deepEqual(nobody.json(), wrong.json());
  } finally {
    await s.close();
  }
});

test('passkeys: without the site address passkeys are off; a user who has one signs in with a recovery code', async () => {
  const s = await setup({ siteUrl: null });
  try {
    // A passkey made while the address was set (another server on the same store).
    const cookie = await logIn(s);
    const elsewhere = createPasskeys({ siteUrl: ORIGIN, store: s.store, now: () => s.clock.t });
    const a = new SoftAuthenticator();
    const o = await elsewhere.registrationOptions('bob', { sessionId: 'x', epoch: 0 });
    const { recoveryCodes } = await elsewhere.finishRegistration('bob', a.create({ challenge: o.challenge, origin: ORIGIN, rpId: RP_ID }), { sessionId: 'x', epoch: 0 });
    const account = (await get(s, '/api/account', cookie)).json();
    assert.deepEqual({ ...account.passkeys, list: undefined }, { available: false, reason: 'no-address', origin: null, rpId: null, max: MAX_PASSKEYS, signIn: false, list: undefined });
    assert.equal(account.passkeys.list[0].here, false);
    assert.deepEqual(account.stepUpMethods, ['recovery']);
    const begin = await api(s, '/api/account/passkeys/begin', { password: BOB, recovery: recoveryCodes[0] }, cookie);
    assert.equal(begin.status, 409);
    assert.deepEqual(begin.json(), { error: "Passkeys need this site's https address in the config file (site.url, or SITE_URL)." });
    assert.equal(s.store.secondFactors('bob').recoveryCodesLeft, 10, 'refused before the step-up, so no code was used');
    assert.equal((await api(s, '/api/account/passkeys/challenge', {}, cookie)).status, 409);

    // The passkey still counts: the password alone is not enough.
    const step = await passwordStep(s);
    assert.deepEqual(step.methods, ['recovery']);
    assert.equal(step.passkeyUnavailable, true);
    assert.equal(step.passkey, undefined);
    const tried = await sendPasskey(s, step.pending, a.get({ challenge: 'x'.repeat(43), origin: ORIGIN, rpId: RP_ID }));
    assert.equal(tried.status, 401);
    assert.equal(tried.json().passkey, undefined);
    const r = await postForm(s, '/login/code', { pending: step.pending, recovery: recoveryCodes[1] });
    assert.equal(r.status, 200, r.text);
  } finally {
    await s.close();
  }
});

test('passkeys: a passkey made for another address is listed but not offered', async () => {
  const s = await setup({ siteUrl: 'http://localhost:8080' });
  try {
    const cookie = await logIn(s);
    const elsewhere = createPasskeys({ siteUrl: ORIGIN, store: s.store, now: () => s.clock.t });
    const a = new SoftAuthenticator();
    const o = await elsewhere.registrationOptions('bob', { sessionId: 'x', epoch: 0 });
    await elsewhere.finishRegistration('bob', a.create({ challenge: o.challenge, origin: ORIGIN, rpId: RP_ID }), { sessionId: 'x', epoch: 0 });
    const account = (await get(s, '/api/account', cookie)).json();
    assert.equal(account.passkeys.available, true);
    assert.equal(account.passkeys.rpId, 'localhost');
    assert.equal(account.passkeys.list[0].here, false);
    const step = await passwordStep(s);
    assert.deepEqual(step.methods, ['recovery']);
    assert.equal(step.passkeyUnavailable, true);
  } finally {
    await s.close();
  }
});

test('passkeys: adding one refuses a certificate, a bad answer, a duplicate, a bad name, and a finish without a begin', async () => {
  const s = await setup();
  try {
    const cookie = await logIn(s);
    const noBegin = await api(s, '/api/account/passkeys/finish', { credential: new SoftAuthenticator().create({ challenge: 'x'.repeat(43), origin: ORIGIN, rpId: RP_ID }) }, cookie);
    assert.deepEqual([noBegin.status, noBegin.json()], [409, { error: 'Adding the passkey took too long, or something changed meanwhile. Start again.' }]);
    const x5c = await addPasskey(s, cookie, { fmt: 'packed-x5c' });
    assert.deepEqual([x5c.finish.status, x5c.finish.json()], [400, { error: 'This security key sent a certificate, which this site does not accept. Try another passkey.' }]);
    const begin = await api(s, '/api/account/passkeys/begin', { password: BOB }, cookie);
    const wrongOrigin = new SoftAuthenticator().create({ challenge: begin.json().options.challenge, origin: 'https://evil.example', rpId: RP_ID });
    const bad = await api(s, '/api/account/passkeys/finish', { credential: wrongOrigin }, cookie);
    assert.deepEqual([bad.status, bad.json()], [400, { error: 'The passkey could not be checked, so it was not added. Try again.' }]);
    // A bad name is refused before the challenge is used: the same begin still works after. (In a
    // session of its own: each try counts in the hourly budget of a session.)
    const fresh = await logIn(s);
    const again = await api(s, '/api/account/passkeys/begin', { password: BOB }, fresh);
    const a = new SoftAuthenticator();
    const made = a.create({ challenge: again.json().options.challenge, origin: ORIGIN, rpId: RP_ID });
    for (const name of ['x'.repeat(65), 'tab\there', 42]) {
      const r = await api(s, '/api/account/passkeys/finish', { credential: made, name }, fresh);
      assert.deepEqual([r.status, r.json()], [400, { error: 'Give the passkey a name of up to 64 characters.', field: 'name' }], String(name));
    }
    assert.equal((await api(s, '/api/account/passkeys/finish', { credential: made, name: 'Key' }, fresh)).status, 200);
    // The same authenticator again (the account page's other session, with its own cookie).
    const second = await logInWithPasskey(s, a);
    const dup = await addPasskey(s, second, { stepUp: { passkey: await stepUpPasskey(s, second, a) }, a });
    assert.deepEqual([dup.finish.status, dup.finish.json()], [409, { error: 'This passkey is added already.' }]);
    assert.equal(s.store.passkeys('bob').length, 1);
    // The JSON body takes a passkey's answer, and no more than 16 KiB.
    const huge = await api(s, '/api/account/passkeys/finish', { credential: made, pad: 'y'.repeat(16384) }, second);
    assert.equal(huge.status, 413);
  } finally {
    await s.close();
  }
});

test('passkeys: at most 10 per user', async () => {
  const s = await setup();
  try {
    const cookie = await logIn(s);
    const { a } = await addPasskey(s, cookie);
    for (let i = 1; i < MAX_PASSKEYS; i++) {
      const o = await s.passkeys.registrationOptions('bob', { sessionId: 'fill', epoch: s.login.epochOf('bob') });
      await s.passkeys.finishRegistration('bob', new SoftAuthenticator().create({ challenge: o.challenge, origin: ORIGIN, rpId: RP_ID }), { sessionId: 'fill', epoch: s.login.epochOf('bob') });
    }
    assert.equal(s.store.passkeys('bob').length, MAX_PASSKEYS);
    const before = s.login.reauths.count(`session:${s.login.session({ headers: { cookie } }).id}`);
    const full = await api(s, '/api/account/passkeys/begin', { password: BOB, passkey: await stepUpPasskey(s, cookie, a) }, cookie);
    assert.deepEqual([full.status, full.json()], [409, { error: 'You have 10 passkeys, the most allowed. Remove one first.' }]);
    assert.equal(s.login.reauths.count(`session:${s.login.session({ headers: { cookie } }).id}`), before, 'no password was checked');
    assert.equal((await get(s, '/api/account', cookie)).json().passkeys.list.length, MAX_PASSKEYS);
  } finally {
    await s.close();
  }
});

test('passkeys: rename and remove; removing the last second factor turns two-step sign-in off and clears the codes', async () => {
  const s = await setup();
  try {
    const cookie = await logIn(s);
    const one = await addPasskey(s, cookie, { name: 'Phone' });
    const ref1 = one.finish.json().passkey.id;
    const two = await addPasskey(s, cookie, { stepUp: { passkey: await stepUpPasskey(s, cookie, one.a) }, name: 'Key' });
    const ref2 = two.finish.json().passkey.id;

    // Rename: no step-up, a ref and a good name.
    assert.deepEqual((await api(s, '/api/account/passkeys/rename', { id: ref1, name: ' Old phone ' }, cookie)).json(), { ok: true });
    assert.equal(s.store.passkeyByRef('bob', ref1).name, 'Old phone');
    assert.equal((await api(s, '/api/account/passkeys/rename', { id: 'nope', name: 'x' }, cookie)).status, 400);
    assert.equal((await api(s, '/api/account/passkeys/rename', { id: one.a.id, name: 'x' }, cookie)).status, 400, 'a credential id is not a ref');
    assert.equal((await api(s, '/api/account/passkeys/rename', { id: '0'.repeat(16), name: 'x' }, cookie)).status, 404);
    const badName = await api(s, '/api/account/passkeys/rename', { id: ref1, name: '' }, cookie);
    assert.deepEqual([badName.status, badName.json()], [400, { error: 'Give the passkey a name of up to 64 characters.', field: 'name' }]);

    // Remove one of two: the other sessions end, two-step sign-in stays.
    const other = await logInWithPasskey(s, two.a);
    const missing = await api(s, '/api/account/passkeys/remove', { id: ref1, password: BOB }, cookie);
    assert.equal(missing.status, 400);
    assert.deepEqual(missing.json(), { error: 'Confirm with your passkey, or enter the code from your app or a recovery code.', field: 'code', secondFactor: true, methods: ['passkey', 'recovery'] });
    const r1 = await api(s, '/api/account/passkeys/remove', { id: ref1, password: BOB, passkey: await stepUpPasskey(s, cookie, two.a) }, cookie);
    assert.deepEqual(r1.json(), { ok: true, secondFactorOff: false });
    assert.equal(await alive(s, other), null);
    assert.equal(await alive(s, cookie), 'bob');
    assert.equal(s.store.secondFactors('bob').recoveryCodesLeft, 10);

    // Remove the last one, confirmed with itself: off, and the codes go.
    const r2 = await api(s, '/api/account/passkeys/remove', { id: ref2, password: BOB, passkey: await stepUpPasskey(s, cookie, two.a) }, cookie);
    assert.deepEqual(r2.json(), { ok: true, secondFactorOff: true });
    assert.equal(s.store.secondFactorEnabled('bob'), false);
    assert.equal(s.store.secondFactors('bob').recoveryCodesLeft, 0);
    const account = (await get(s, '/api/account', cookie)).json();
    assert.equal(account.secondFactor, false);
    assert.deepEqual(account.stepUpMethods, []);
    assert.equal((await api(s, '/api/account/passkeys/remove', { id: ref2, password: BOB }, cookie)).status, 404);
    await logIn(s);

    const lines = await auditLines(s);
    assert.deepEqual(lines.filter((l) => l.event === 'passkey-renamed').map(({ time, ...l }) => l), [{ event: 'passkey-renamed', user: 'bob', from: 'Phone', to: 'Old phone' }]);
    assert.deepEqual(lines.filter((l) => l.event === 'passkey-removed').map(({ time, ...l }) => l), [
      { event: 'passkey-removed', user: 'bob', passkey: 'Old phone', with: 'password+passkey', ended: 1, secondFactorOff: false, address: IP },
      { event: 'passkey-removed', user: 'bob', passkey: 'Key', with: 'password+passkey', ended: 0, secondFactorOff: true, address: IP },
    ]);
  } finally {
    await s.close();
  }
});

test('passkeys: the step-up of every sensitive change takes a passkey, the app code or a recovery code', async () => {
  const s = await setup();
  try {
    let cookie = await logIn(s);
    const { a, finish } = await addPasskey(s, cookie);
    const codes = finish.json().recoveryCodes;
    const challenge = () => stepUpPasskey(s, cookie, a);

    // A wrong passkey: a 400 on the passkey, and it counts as a wrong code.
    const stranger = new SoftAuthenticator();
    const wrong = await api(s, '/api/account/recovery-codes', { password: BOB, passkey: await stepUpPasskey(s, cookie, stranger) }, cookie);
    assert.deepEqual([wrong.status, wrong.json()], [400, { field: 'passkey', error: 'That passkey did not work. Try again.' }]);
    assert.equal(s.login.codeUsers.count('user:bob'), 1);
    // Without a challenge first, the passkey is no good either.
    const noChallenge = await api(s, '/api/account/recovery-codes', { password: BOB, passkey: a.get({ challenge: 'x'.repeat(43), origin: ORIGIN, rpId: RP_ID }) }, cookie);
    assert.equal(noChallenge.json().field, 'passkey');
    // A wrong password uses no challenge and no code.
    const pk = await challenge();
    assert.equal((await api(s, '/api/account/recovery-codes', { password: 'wrong', passkey: pk }, cookie)).json().field, 'password');

    // New recovery codes with a passkey.
    const fresh = await api(s, '/api/account/recovery-codes', { password: BOB, passkey: await challenge() }, cookie);
    assert.equal(fresh.status, 200, fresh.text);
    assert.equal(fresh.json().recoveryCodes.length, 10);
    // The password, with a recovery code.
    const pw = await api(s, '/api/account/password', { password: BOB, next: 'a brand new password', recovery: fresh.json().recoveryCodes[0] }, cookie);
    assert.equal(pw.status, 200, pw.text);
    assert.equal((await api(s, '/api/account/password', { password: 'a brand new password', next: 'another new password', recovery: codes[1] }, cookie)).json().field, 'recovery', 'the old codes are gone');
    const pw2 = await api(s, '/api/account/password', { password: 'a brand new password', next: 'another new password', passkey: await challenge() }, cookie);
    assert.equal(pw2.status, 200, pw2.text);
    const password = 'another new password';

    // The app code on (with the passkey), and off again (with the passkey): the passkey and the
    // codes stay.
    const { secret } = await enableTotp(s, cookie, password, { passkey: await challenge() });
    assert.equal((await api(s, '/api/account/totp/setup', { password, passkey: await challenge() }, cookie)).status, 409);
    const account = (await get(s, '/api/account', cookie)).json();
    assert.deepEqual(account.stepUpMethods, ['passkey', 'totp', 'recovery']);
    assert.equal(account.totp.enabled, true);
    // A passkey added with the app code as the step-up.
    const added = await addPasskey(s, cookie, { password, stepUp: { code: codeNow(s, secret) } });
    assert.equal(added.finish.status, 200, added.finish.text);
    assert.equal(added.finish.json().recoveryCodes, undefined);
    s.clock.t += 30_000;
    const off = await api(s, '/api/account/totp/disable', { password, passkey: await challenge() }, cookie);
    assert.deepEqual(off.json(), { ok: true, secondFactorOff: false });
    assert.equal(s.store.secondFactors('bob').totp, false);
    assert.equal(s.store.secondFactors('bob').recoveryCodesLeft, 10);
    assert.equal((await api(s, '/api/account/totp/disable', { password, passkey: await challenge() }, cookie)).status, 409);
    // A passkey removed with a recovery code.
    const codesNow = (await api(s, '/api/account/recovery-codes', { password, passkey: await challenge() }, cookie)).json().recoveryCodes;
    const removed = await api(s, '/api/account/passkeys/remove', { id: added.finish.json().passkey.id, password, recovery: codesNow[0] }, cookie);
    assert.deepEqual(removed.json(), { ok: true, secondFactorOff: false });

    const how = (await auditLines(s)).filter((l) => l.with).map((l) => [l.event, l.with]);
    assert.deepEqual(how, [
      ['recovery-codes-regenerated', 'password+passkey'],
      ['password-changed', 'password+recovery'],
      ['password-changed', 'password+passkey'],
      ['totp-disabled', 'password+passkey'],
      ['recovery-codes-regenerated', 'password+passkey'],
      ['passkey-removed', 'password+recovery'],
    ]);
    // Signing in again works with the passkey that is left.
    cookie = await logInWithPasskey(s, a, 'bob', password);
    assert.equal(await alive(s, cookie), 'bob');
  } finally {
    await s.close();
  }
});

test('passkeys: the step-up challenge: only with a passkey here, single use, for this session, and limited', async () => {
  const s = await setup();
  try {
    const cookie = await logIn(s);
    const none = await api(s, '/api/account/passkeys/challenge', {}, cookie);
    assert.deepEqual([none.status, none.json()], [409, { error: 'You have no passkey to confirm with.' }]);
    const { a } = await addPasskey(s, cookie);
    // Another session's challenge is not this one's.
    const other = await logInWithPasskey(s, a);
    const theirs = await stepUpPasskey(s, other, a);
    const r = await api(s, '/api/account/recovery-codes', { password: BOB, passkey: theirs }, cookie);
    assert.equal(r.json().field, 'passkey');
    // Used once.
    const mine = await stepUpPasskey(s, cookie, a);
    assert.equal((await api(s, '/api/account/recovery-codes', { password: BOB, passkey: mine }, cookie)).status, 200);
    assert.equal((await api(s, '/api/account/recovery-codes', { password: BOB, passkey: mine }, cookie)).json().field, 'passkey');
    // Like every change, it needs a recent sign in.
    s.clock.t += RECENT_AUTH_MS;
    const stale = await api(s, '/api/account/passkeys/challenge', {}, cookie);
    assert.deepEqual([stale.status, stale.json().reauth], [403, true]);
    // At most CHALLENGES_PER_SESSION an hour.
    const fresh = await logInWithPasskey(s, a);
    for (let i = 0; i < CHALLENGES_PER_SESSION; i++) assert.equal((await api(s, '/api/account/passkeys/challenge', {}, fresh)).status, 200);
    const over = await api(s, '/api/account/passkeys/challenge', {}, fresh);
    assert.equal(over.status, 429);
    assert.ok(Number(over.headers['retry-after']) > 0);
  } finally {
    await s.close();
  }
});

test('passkeys: the users page counts passkeys, takes a passkey as the step-up, and its reset clears them', async () => {
  const s = await setup();
  try {
    const bob = await logIn(s);
    await addPasskey(s, bob);
    const alice = await logIn(s, 'alice', ALICE);
    const { a } = await addPasskey(s, alice, { password: ALICE });
    const list = (await get(s, '/api/users', alice)).json();
    assert.deepEqual(list.stepUpMethods, ['passkey', 'recovery']);
    assert.equal(list.secondFactor, true);
    const row = (n) => list.users.find((u) => u.name === n);
    assert.deepEqual([row('bob').passkeys, row('bob').totp, row('bob').secondFactor], [1, false, true]);
    assert.deepEqual([row('Alice').passkeys, row('Alice').totp], [1, false]);

    const missing = await api(s, '/api/users/reset-second-factor', { name: 'bob', password: ALICE }, alice);
    assert.equal(missing.status, 400);
    assert.deepEqual(missing.json().methods, ['passkey', 'recovery']);
    const reset = await api(s, '/api/users/reset-second-factor', { name: 'bob', password: ALICE, passkey: await stepUpPasskey(s, alice, a) }, alice);
    assert.deepEqual(reset.json(), { ok: true });
    assert.equal(s.store.secondFactorEnabled('bob'), false);
    assert.deepEqual(s.store.passkeys('bob'), []);
    assert.equal(await alive(s, bob), null);
    assert.ok(s.store.factorRecord('bob').passkeyUserId, 'the user handle stays');
    const line = (await auditLines(s)).find((l) => l.event === 'user-second-factor-reset');
    assert.deepEqual({ ...line, time: undefined }, { time: undefined, event: 'user-second-factor-reset', actor: 'Alice', user: 'bob', passkeys: 1, ended: 1, with: 'password+passkey', address: IP });
    // Bob signs in with the password alone again.
    await logIn(s);
  } finally {
    await s.close();
  }
});

test('passkeys: another admin\'s passkeys are not reset on the users page (only on the command line)', async () => {
  const s = await setup();
  try {
    await s.store.setRole('bob', 'admin');
    const bob = await logIn(s);
    const { a } = await addPasskey(s, bob);
    await addPasskey(s, bob, { stepUp: { passkey: await stepUpPasskey(s, bob, a) } });
    const alice = await logIn(s, 'alice', ALICE);
    const reset = await api(s, '/api/users/reset-second-factor', { name: 'bob', password: ALICE }, alice);
    assert.equal(reset.status, 403);
    assert.match(reset.json().error, /command line/);
    assert.equal(s.store.passkeys('bob').length, 2);
    assert.equal(await alive(s, bob), 'bob');
    const line = (await auditLines(s)).find((l) => l.event === 'admin-reset-refused');
    assert.deepEqual({ ...line, time: undefined }, { time: undefined, event: 'admin-reset-refused', actor: 'Alice', target: 'bob', what: 'second-factor', address: IP });
  } finally {
    await s.close();
  }
});

test('passkeys: the audit and failure logs never hold a credential id, public key or ref', async () => {
  const s = await setup();
  try {
    const cookie = await logIn(s);
    const { a } = await addPasskey(s, cookie, { authOptions: { counter: 4 } });
    const step = await passwordStep(s);
    await sendPasskey(s, step.pending, answer(a, step.passkey, { counter: 1 }));
    await sendPasskey(s, step.pending, answer(new SoftAuthenticator(), step.passkey));
    await api(s, '/api/account/passkeys/rename', { id: passkeyRef(a.id), name: 'Renamed' }, cookie);
    await s.audit.flush();
    await s.failures.flush();
    const text = (await fs.readFile(s.audit.file, 'utf8')) + (await fs.readFile(s.failures.file, 'utf8').catch(() => ''));
    const rec = s.store.passkeyById('bob', a.id);
    for (const secret of [a.id, rec.publicKey, passkeyRef(a.id), a.cose.toString('base64'), s.store.factorRecord('bob').passkeyUserId]) assert.equal(text.includes(secret), false);
    assert.match(text, /passkey-counter-error/);
    assert.equal(s.logs.join('\n').includes(a.id), false);
  } finally {
    await s.close();
  }
});

test('passkeys: an id another user has is not told apart from a passkey that did not check out, and is noted without the id', async () => {
  const s = await setup();
  try {
    const alice = await logIn(s, 'alice', ALICE);
    const { a, finish } = await addPasskey(s, alice, { password: ALICE });
    assert.equal(finish.status, 200, finish.text);
    // Bob sends alice's credential id with a key of his own (any authenticator can say any id).
    const bob = await logIn(s);
    const copy = new SoftAuthenticator({ id: a.rawId });
    const r = await addPasskey(s, bob, { a: copy });
    assert.deepEqual([r.finish.status, r.finish.json()], [400, { error: 'The passkey could not be checked, so it was not added. Try again.' }]);
    assert.deepEqual(s.store.passkeys('bob'), []);
    assert.equal(s.store.passkeys('Alice').length, 1);
    await s.failures.flush();
    const text = await fs.readFile(s.failures.file, 'utf8');
    const line = text.trim().split('\n').map((l) => JSON.parse(l)).find((l) => l.event === 'passkey-id-taken');
    assert.ok(line, text);
    assert.equal(line.user, 'bob');
    for (const secret of [a.id, passkeyRef(a.id)]) assert.equal(text.includes(secret), false);
    // Their own passkey again is "added already", as before.
    const again = await addPasskey(s, alice, { password: ALICE, stepUp: { passkey: await stepUpPasskey(s, alice, a) }, a });
    assert.deepEqual([again.finish.status, again.finish.json()], [409, { error: 'This passkey is added already.' }]);
  } finally {
    await s.close();
  }
});

test('passkeys: every answer allows passkeys for this site only (Permissions-Policy)', async () => {
  const s = await setup();
  try {
    for (const p of ['/', '/account', '/api/session']) {
      const policy = (await get(s, p)).headers['permissions-policy'];
      assert.match(policy, /(^|, )publickey-credentials-get=\(self\)(,|$)/, p);
      assert.match(policy, /(^|, )publickey-credentials-create=\(self\)(,|$)/, p);
      assert.match(policy, /camera=\(\)/, p);
    }
  } finally {
    await s.close();
  }
});

test('a first passkey starts the wait before node changes and is audited; a factor added while one is on starts none', async () => {
  const calls = [];
  const manage = { client: { call: async (...args) => (calls.push(args), { ok: true, status: 202, body: { id: '00112233aabbccdd' } }) }, nodes: ['a.test:1'] };
  const s = await setup({ manage });
  try {
    const c = await logIn(s);
    const { a, finish } = await addPasskey(s, c);
    assert.equal(finish.status, 200, finish.text);
    const until = NOW + FIRST_FACTOR_HOLD_MS;
    assert.equal(s.holds.until('bob'), until);
    assert.equal((await get(s, '/api/manage', c)).json().nodeChangesFrom, new Date(until).toISOString());
    const w = await api(s, '/api/manage/restart', { host: 'a.test:1', password: BOB, passkey: await stepUpPasskey(s, c, a) }, c);
    assert.equal(w.status, 403, w.text);
    assert.equal(w.json().code, 'second-factor-new');
    assert.equal(calls.length, 0);
    // The app code, confirmed by the passkey, and a second passkey, confirmed by the app code: no new wait.
    s.clock.t += 60_000;
    const { secret } = await enableTotp(s, c, BOB, { passkey: await stepUpPasskey(s, c, a) });
    const more = await addPasskey(s, c, { stepUp: { code: codeNow(s, secret) } });
    assert.equal(more.finish.status, 200, more.finish.text);
    assert.equal(s.holds.until('bob'), until, 'the wait is the one of the first passkey');
    const firsts = (await auditLines(s)).filter((l) => l.event === 'second-factor-first');
    assert.deepEqual(firsts.map((l) => [l.user, l.role, l.method, l.nodeChangesFrom]), [['bob', 'manage', 'passkey', new Date(until).toISOString()]]);
  } finally {
    await s.close();
  }
});

// ---- signing in with a passkey alone (POST /login/passkey/begin and /login/passkey/finish) ----

const beginSignIn = (s, { headers = {}, body = '' } = {}) => request(s.port, { method: 'POST', path: '/login/passkey/begin', headers: { ...FORM, ...headers }, body });
const finishSignIn = (s, token, credential, cookie, fields = {}) => postForm(s, '/login/passkey/finish', { ...(token === undefined ? {} : { token }), ...(credential === undefined ? {} : { credential: typeof credential === 'string' ? credential : JSON.stringify(credential) }), ...fields }, cookie);
const rawLines = async (file) => (await fs.readFile(file, 'utf8').catch(() => '')).trim().split('\n').filter(Boolean).map((l) => JSON.parse(l));

// Bob signs in with the password and adds a passkey: the authenticator, the user handle it carries, and his session.
async function bobWithPasskey(s, authOptions = {}) {
  const cookie = await logIn(s);
  const { a, finish, options } = await addPasskey(s, cookie, { authOptions });
  assert.equal(finish.status, 200, finish.text);
  return { a, handle: options.user.id, cookie };
}

// A whole sign in with a passkey alone: begin, the authenticator's answer, finish. extra bends the answer.
async function passkeyOnly(s, a, handle, { cookie, extra = {} } = {}) {
  const begun = await beginSignIn(s);
  assert.equal(begun.status, 200, begun.text);
  const { token, options } = begun.json();
  return finishSignIn(s, token, answer(a, options, { userHandle: handle, ...extra }), cookie);
}

// A cookie header or Set-Cookie value without its value, to compare the attributes.
const shape = (r) => r.headers['set-cookie'].map((c) => c.replace(/^([^=]+)=[^;]*/, '$1=<value>'));

test('passkey sign in: begin and finish sign in with the passkey alone, with the cookies of /login, a new session id, and no name sent or answered but the user\'s own', async () => {
  const s = await setup();
  try {
    const { a, handle } = await bobWithPasskey(s);
    const begun = await beginSignIn(s);
    assert.equal(begun.status, 200, begun.text);
    assert.equal(begun.headers['cache-control'], 'no-store');
    const b = begun.json();
    assert.deepEqual(Object.keys(b).sort(), ['expiresIn', 'options', 'token']);
    assert.match(b.token, /^[A-Za-z0-9_-]{43}$/);
    assert.equal(b.expiresIn, 300);
    assert.deepEqual(b.options, { challenge: b.options.challenge, rpId: RP_ID, timeout: 120_000, userVerification: 'required' });
    assert.match(b.options.challenge, /^[A-Za-z0-9_-]{43}$/);
    // Nothing names a user or a credential.
    for (const secret of ['bob', 'Bob', a.id, handle]) assert.equal(begun.text.includes(secret), false, secret);

    // The same cookies as a password sign in, and a new session; a planted or old one never carries over.
    const old = await logIn(s, 'Alice', ALICE);
    const pw = await postForm(s, '/login', { name: 'Alice', password: ALICE });
    const done = await finishSignIn(s, b.token, answer(a, b.options, { userHandle: handle }), old);
    assert.equal(done.status, 200, done.text);
    assert.equal(done.headers['cache-control'], 'no-store');
    assert.deepEqual(done.json(), { ok: true, name: 'bob' });
    assert.deepEqual(shape(done), shape(pw));
    assert.deepEqual(shape(done), ['__Host-rettui_session=<value>; Path=/; Max-Age=43200; HttpOnly; Secure; SameSite=Strict', `__Host-rettui_device=<value>; Path=/; Max-Age=${180 * 24 * 60 * 60}; HttpOnly; Secure; SameSite=Strict`]);
    const cookie = cookieOf(done);
    assert.match(cookie, /^__Host-rettui_session=[A-Za-z0-9_-]{43}$/);
    assert.notEqual(cookie, old);
    assert.equal(await alive(s, cookie), 'bob');
    assert.equal(await alive(s, old), null, 'the session the request came with ended');
    // Nobody else's session was touched, and the passkey was used.
    assert.equal(s.store.passkeyById('bob', a.id).lastUsed, new Date(NOW).toISOString());

    // The same token again: used up.
    const again = await finishSignIn(s, b.token, answer(a, b.options, { userHandle: handle }));
    assert.equal(again.status, 401);
    assert.deepEqual(again.json(), { error: PASSKEY_SIGNIN_EXPIRED, restart: true });
    assert.equal(again.headers['set-cookie'], undefined);

    // With the device cookie of the first sign in, the same device is kept, not a new one made.
    const deviceCookie = done.headers['set-cookie'][1].split(';')[0];
    const second = await beginSignIn(s);
    const sb = second.json();
    const kept = await postForm(s, '/login/passkey/finish', { token: sb.token, credential: JSON.stringify(answer(a, sb.options, { userHandle: handle })) }, deviceCookie);
    assert.equal(kept.status, 200, kept.text);
    assert.equal(kept.headers['set-cookie'][1].split(';')[0], deviceCookie);
    assert.equal(s.store.devices('bob').length, 2, 'the password sign in made the first, this one the second, and the third came with its id');
  } finally {
    await s.close();
  }
});

test('passkey sign in: the audit line of a new device says it was a passkey, and nothing else is written for a sign in', async () => {
  const s = await setup();
  try {
    const { a, handle } = await bobWithPasskey(s);
    // A day later, so that this device is the first of that day.
    s.clock.t += DEVICE_AUDIT_MS + 1000;
    const r = await passkeyOnly(s, a, handle);
    assert.equal(r.status, 200, r.text);
    await s.audit.flush();
    const lines = await rawLines(s.audit.file);
    const added = lines.filter((l) => l.event === 'device-added' && l.with !== undefined);
    assert.deepEqual(added.map(({ time, ...rest }) => rest), [{ event: 'device-added', user: 'bob', address: IP, with: 'passkey' }]);
    assert.deepEqual(lines.filter((l) => !['device-added', 'passkey-added', 'second-factor-first', 'passkey-sign-in'].includes(l.event)), []);
  } finally {
    await s.close();
  }
});

test('passkey sign in: the same guards as /login: same origin, the request header, the form type and the sizes', async () => {
  const s = await setup();
  try {
    await bobWithPasskey(s);
    const send = (path, { headers = FORM, body = '' } = {}) => request(s.port, { method: 'POST', path, headers, body });
    for (const path of ['/login/passkey/begin', '/login/passkey/finish']) {
      const without = Object.fromEntries(Object.entries(FORM).filter(([k]) => k !== 'X-Rettui-Request'));
      assert.equal((await send(path, { headers: without })).status, 403, `${path} without the header`);
      assert.equal((await send(path, { headers: { ...FORM, 'X-Rettui-Request': '0' } })).status, 403, `${path} with another value`);
      assert.equal((await send(path, { headers: { ...FORM, 'Sec-Fetch-Site': 'cross-site' } })).status, 403, `${path} cross-site`);
      assert.equal((await send(path, { headers: { ...FORM, 'Sec-Fetch-Site': 'same-site' } })).status, 403, `${path} same-site`);
      assert.equal((await send(path, { headers: { ...FORM, 'Sec-Fetch-Site': 'none' } })).status, 403, `${path} typed in`);
      const noFetch = Object.fromEntries(Object.entries(FORM).filter(([k]) => k !== 'Sec-Fetch-Site'));
      assert.equal((await send(path, { headers: { ...noFetch, Origin: 'https://evil.example.org', Host: 'status.example.org' } })).status, 403, `${path} with another Origin`);
      assert.equal((await send(path, { headers: noFetch })).status, 403, `${path} with no Origin either`);
      assert.equal((await send(path, { headers: { ...FORM, 'Content-Type': 'application/json' }, body: '{}' })).status, 415, `${path} as JSON`);
      assert.equal((await send(path, { headers: { ...FORM, 'Content-Type': 'text/plain' }, body: '' })).status, 415, `${path} as text`);
    }
    assert.equal((await send('/login/passkey/begin', { body: 'x'.repeat(MAX_FORM_BYTES + 1) })).status, 413);
    assert.equal((await send('/login/passkey/finish', { body: `credential=${'x'.repeat(MAX_PASSKEY_FORM_BYTES)}` })).status, 413);
    // Begin takes the small limit, finish the larger one: a body of that size is not too large for finish.
    assert.equal((await send('/login/passkey/begin', { body: `x=${'x'.repeat(MAX_FORM_BYTES)}` })).status, 413);
    assert.equal((await send('/login/passkey/finish', { body: `token=x&credential=${'x'.repeat(MAX_FORM_BYTES + 100)}` })).status, 401);
    // A refused request opened no prompt, and counted for nobody.
    assert.equal(s.login.signInChallenges.size, 0);
    assert.equal(s.login.addresses.count(ipKey(IP)), 0);
    // Other methods are not these routes.
    assert.notEqual((await get(s, '/login/passkey/begin')).status, 200);
    assert.notEqual((await get(s, '/login/passkey/finish')).status, 200);
  } finally {
    await s.close();
  }
});

test('passkey sign in: off, both routes answer 404 and /api/session and /api/account say nothing of it', async () => {
  for (const options of [{ loginSettings: { passkeySignIn: false } }, { siteUrl: null }]) {
    const s = await setup(options);
    try {
      const begun = await beginSignIn(s);
      assert.equal(begun.status, 404);
      assert.deepEqual(begun.json(), { error: 'Signing in with a passkey alone is off on this site.' });
      const done = await finishSignIn(s, 'A'.repeat(43), '{}');
      assert.equal(done.status, 404);
      assert.deepEqual(done.json(), { error: 'Signing in with a passkey alone is off on this site.' });
      assert.equal(begun.headers['set-cookie'], undefined);
      assert.equal(s.login.signInChallenges.size, 0);
      assert.deepEqual((await get(s, '/api/session')).json(), { enabled: true, name: null });
      const cookie = await logIn(s);
      assert.deepEqual((await get(s, '/api/session', cookie)).json(), { enabled: true, name: 'bob' });
      assert.equal((await get(s, '/api/account', cookie)).json().passkeys.signIn, false);
      // The guards come first, as for every login route.
      assert.equal((await request(s.port, { method: 'POST', path: '/login/passkey/begin', headers: { ...FORM, 'X-Rettui-Request': '0' }, body: '' })).status, 403);
    } finally {
      await s.close();
    }
  }
  // Off for passkeys alone, but passkeys as the second step still work.
  const s = await setup({ loginSettings: { passkeySignIn: false } });
  try {
    const cookie = await logIn(s);
    const { a } = await addPasskey(s, cookie);
    assert.ok(await logInWithPasskey(s, a));
  } finally {
    await s.close();
  }
});

test('passkey sign in: /api/session says it is offered, with the address it works at, and /api/account says it too', async () => {
  const s = await setup();
  try {
    assert.deepEqual((await get(s, '/api/session')).json(), { enabled: true, name: null, passkeySignIn: true, passkeyOrigin: ORIGIN });
    const cookie = await logIn(s);
    assert.deepEqual((await get(s, '/api/session', cookie)).json(), { enabled: true, name: 'bob', passkeySignIn: true, passkeyOrigin: ORIGIN });
    assert.equal((await get(s, '/api/account', cookie)).json().passkeys.signIn, true);
    assert.match((await get(s, '/api/session')).headers['cache-control'], /no-store/);
  } finally {
    await s.close();
  }
  // A site without users has no sign in at all.
  const local = await setup({ siteUrl: 'http://localhost:8080' });
  try {
    assert.equal((await get(local, '/api/session')).json().passkeyOrigin, 'http://localhost:8080');
  } finally {
    await local.close();
  }
});

test('passkey sign in: every failure that depends on the user is the same 401, byte for byte, with no cookie', async () => {
  const s = await setup();
  try {
    const { a, handle } = await bobWithPasskey(s, { counter: 3 });
    const alicesHandle = await s.store.ensurePasskeyUserId('Alice');
    const stranger = new SoftAuthenticator();
    const bad = {
      'unknown credential': (opts) => answer(stranger, opts, { userHandle: handle }),
      'a bad signature': (opts) => {
        const c = answer(a, opts, { userHandle: handle });
        c.response.signature = Buffer.alloc(70, 5).toString('base64url');
        return c;
      },
      'no user verification': (opts) => answer(a, opts, { userHandle: handle, uv: false }),
      'the wrong origin': (opts) => answer(a, opts, { userHandle: handle, origin: 'https://evil.example.org' }),
      'a frame of another site': (opts) => answer(a, opts, { userHandle: handle, crossOrigin: true }),
      'another user\'s handle': (opts) => answer(a, opts, { userHandle: alicesHandle }),
      'no handle': (opts) => answer(a, opts, { userHandle: null }),
      'a counter that went back': (opts) => answer(a, opts, { userHandle: handle, counter: 1 }),
      'not an answer': () => 'not json',
    };
    await s.store.createUser({ name: 'carol', role: 'viewer', passwordHash: await hashPassword('carols password', undefined, fakeHasher) });
    const c = await addPasskey(s, await logIn(s, 'carol', 'carols password'), { password: 'carols password' });
    // What the waits hold before the passkey failures, for the password sign ins above.
    const sizes = () => [s.login.accounts, s.login.codes, s.login.codeUsers, s.login.devices, s.login.names].map((t) => t.size);
    const before = sizes();
    const results = [];
    for (const [what, make] of Object.entries(bad)) {
      const b = (await beginSignIn(s)).json();
      const r = await finishSignIn(s, b.token, make(b.options));
      results.push([what, r]);
    }
    // A passkey that was removed, and a user who was deleted, after the prompt was started.
    const prompt = (await beginSignIn(s)).json();
    const kept = answer(a, prompt.options, { userHandle: handle, counter: 50 });
    await s.store.removePasskey('bob', s.store.passkeys('bob')[0].ref);
    results.push(['a removed passkey', await finishSignIn(s, prompt.token, kept)]);
    s.clock.t += 10_000;
    const carolPrompt = (await beginSignIn(s)).json();
    const carolAnswer = answer(c.a, carolPrompt.options, { userHandle: c.options.user.id });
    await s.store.deleteUser('carol');
    results.push(['a deleted user', await finishSignIn(s, carolPrompt.token, carolAnswer)]);
    const expected = JSON.stringify({ error: PASSKEY_SIGNIN_FAILED });
    for (const [what, r] of results) {
      assert.equal(r.status, 401, what);
      assert.equal(r.text, expected, what);
      assert.equal(r.headers['content-length'], String(Buffer.byteLength(expected)), what);
      assert.equal(r.headers['set-cookie'], undefined, what);
      assert.equal(r.headers['retry-after'], undefined, what);
    }
    assert.equal(results.length, Object.keys(bad).length + 2);
    assert.equal(PASSKEY_SIGNIN_FAILED, 'That passkey did not work. Try again, or sign in with your name and password.');
    // It counted for the address, and for no user or credential.
    await s.failures.flush();
    const summed = (await rawLines(s.failures.file)).filter((l) => l.event === 'passkey-sign-in-failures');
    assert.deepEqual(summed.map((l) => [l.user, l.failures, l.lastAddress]), [[null, results.length, IP]]);
    assert.ok(s.login.addresses.count(ipKey(IP)) > 0);
    assert.deepEqual(sizes(), before);
    assert.equal(s.login.codeUsers.count('user:bob'), 0);
    assert.equal(s.login.codes.size, 0);
  } finally {
    await s.close();
  }
});

test('passkey sign in: a missing credential is a 400 that keeps the token; a missing, wrong or used token is the same 401 "expired"', async () => {
  const s = await setup();
  try {
    const { a, handle } = await bobWithPasskey(s);
    const b = (await beginSignIn(s)).json();
    for (const credential of [undefined, '', '   ']) {
      const r = await finishSignIn(s, b.token, credential);
      assert.equal(r.status, 400, String(credential));
      assert.deepEqual(r.json(), { error: 'Use your passkey.' });
    }
    // The token was not used up by that.
    assert.equal(s.login.signInChallenges.size, 1);
    const expired = JSON.stringify({ error: PASSKEY_SIGNIN_EXPIRED, restart: true });
    for (const token of [undefined, '', 'x', 'A'.repeat(43), `${b.token}x`, 'a b']) {
      const r = await finishSignIn(s, token, answer(a, b.options, { userHandle: handle }));
      assert.equal(r.status, 401, String(token));
      assert.equal(r.text, expired, String(token));
    }
    assert.equal(PASSKEY_SIGNIN_EXPIRED, 'That took too long, or your connection changed. Try again.');
    // A token that is too old.
    s.clock.t += 5 * 60_000;
    const old = await finishSignIn(s, b.token, answer(a, b.options, { userHandle: handle }));
    assert.equal(old.text, expired);
    // Unreadable answers are checked all the same: the 401 of a passkey that did not work.
    for (const credential of ['not json', 'null', '[]', '42', '"text"', '{}', '{"id":1}']) {
      const fresh = (await beginSignIn(s)).json();
      const r = await finishSignIn(s, fresh.token, credential);
      assert.equal(r.status, 401, credential);
      assert.deepEqual(r.json(), { error: PASSKEY_SIGNIN_FAILED }, credential);
    }
  } finally {
    await s.close();
  }
});

test('passkey sign in: begin is paced per address with a 429 and Retry-After, and failed answers hold the address back with a 429 too', async () => {
  const s = await setup();
  try {
    const { a, handle } = await bobWithPasskey(s);
    for (let n = 0; n < SIGNIN_BEGIN_BURST; n++) assert.equal((await beginSignIn(s)).status, 200);
    const paced = await beginSignIn(s);
    assert.equal(paced.status, 429);
    assert.match(paced.json().error, /^Too many sign ins from here right now\. Try again in \d+ seconds?\.$/);
    assert.equal(typeof paced.json().retryAfter, 'number');
    assert.ok(paced.json().retryAfter >= 1 && paced.json().retryAfter <= 2);
    assert.equal(paced.headers['retry-after'], String(paced.json().retryAfter));
    assert.equal(s.login.signInChallenges.size, 5, 'at most five open for one address');
    s.clock.t += 2000;
    assert.equal((await beginSignIn(s)).status, 200);

    // Failed answers from this address: first the free tries, then a wait that refuses even a right passkey.
    for (let n = 0; n < 30; n++) s.login.addresses.fail(ipKey(IP));
    s.clock.t += 60_000;
    for (let n = 0; n < 5; n++) s.login.addresses.fail(ipKey(IP));
    const b = (await beginSignIn(s)).json();
    const r = await finishSignIn(s, b.token, answer(a, b.options, { userHandle: handle }));
    assert.equal(r.status, 429, r.text);
    assert.match(r.json().error, /^Too many failed sign ins from here\. Try again in \d+ (seconds?|minutes?)\.$/);
    assert.equal(r.headers['retry-after'], String(r.json().retryAfter));
    assert.ok(r.json().retryAfter >= 1);
    assert.equal(r.headers['set-cookie'], undefined);
    assert.equal(s.store.passkeyById('bob', a.id).lastUsed, null, 'the passkey was not even checked');
    // The password form of this address is held back by the same count.
    assert.equal((await postForm(s, '/login', { name: 'Alice', password: ALICE })).status, 429);
  } finally {
    await s.close();
  }
});

test('passkey sign in: a store that cannot be read is a 503 on both routes', async () => {
  const s = await setup();
  try {
    const { a, handle } = await bobWithPasskey(s);
    const b = (await beginSignIn(s)).json();
    const answerNow = answer(a, b.options, { userHandle: handle });
    const err = new Error('cannot be read');
    s.store.unreadable = err;
    s.store.onUnreadable(err);
    const begun = await beginSignIn(s);
    assert.equal(begun.status, 503);
    assert.deepEqual(begun.json(), { error: 'Signing in is not possible right now. Try again later.' });
    assert.equal(begun.headers['retry-after'], '30');
    const done = await finishSignIn(s, b.token, answerNow);
    assert.equal(done.status, 503);
    assert.deepEqual(done.json(), { error: 'Signing in is not possible right now. Try again later.' });
    // The same words as /login.
    assert.deepEqual((await postForm(s, '/login', { name: 'Alice', password: ALICE })).json(), done.json());
    assert.equal(done.headers['set-cookie'], undefined);
  } finally {
    await s.close();
  }
});

test('passkey sign in: a user who must change their password gets the limited session', async () => {
  const s = await setup();
  try {
    const { a, handle } = await bobWithPasskey(s);
    await s.store.setPassword('bob', await hashPassword('a password an admin chose', undefined, fakeHasher, s.store.currentPepper()), { mustChangePassword: true });
    const r = await passkeyOnly(s, a, handle);
    assert.equal(r.status, 200, r.text);
    assert.deepEqual(r.json(), { ok: true, name: 'bob', mustChangePassword: true });
    const cookie = cookieOf(r);
    assert.deepEqual((await get(s, '/api/session', cookie)).json(), { enabled: true, name: 'bob', mustChangePassword: true, passkeySignIn: true, passkeyOrigin: ORIGIN });
    assert.equal((await get(s, '/api/account', cookie)).json().mustChangePassword, true);
    // Seen as nobody everywhere else.
    assert.equal((await get(s, '/api/status', cookie)).json().viewer.name, null);
    const manage = await get(s, '/api/manage', cookie);
    assert.notEqual(manage.status, 200);
    // A sign in with the password the admin chose gives the same.
    assert.deepEqual(await alive(s, cookie), 'bob');
  } finally {
    await s.close();
  }
});

test('passkey sign in: a change that needs a step-up still needs the password, and a recent sign in lasts only as long as for a password', async () => {
  const calls = [];
  const manage = { client: { call: async (...args) => (calls.push(args), { ok: true, status: 202, body: { id: '00112233aabbccdd' } }) }, nodes: ['a.test:1'] };
  const s = await setup({ manage });
  try {
    const { a, handle } = await bobWithPasskey(s);
    const r = await passkeyOnly(s, a, handle);
    assert.equal(r.status, 200, r.text);
    const cookie = cookieOf(r);
    // A passkey alone has not given the password: every change asks for it first.
    const first = await api(s, '/api/account/passkeys/begin', { password: BOB }, cookie);
    assert.equal(first.status, 403, first.text);
    assert.equal(first.json().reauth, true);
    assert.equal((await api(s, '/api/account/reauth', { password: BOB }, cookie)).status, 200);
    // Adding a passkey: the passkey that signed in is no step-up without the password.
    const noPassword = await api(s, '/api/account/passkeys/begin', { passkey: await stepUpPasskey(s, cookie, a) }, cookie);
    assert.equal(noPassword.status, 400, noPassword.text);
    assert.equal(noPassword.json().field, 'password');
    assert.equal((await api(s, '/api/account/passkeys/begin', {}, cookie)).status, 400);
    const wrong = await api(s, '/api/account/passkeys/begin', { password: 'not it', passkey: await stepUpPasskey(s, cookie, a) }, cookie);
    assert.equal(wrong.status, 400, wrong.text);
    assert.equal(wrong.json().field, 'password');
    const onlyPassword = await api(s, '/api/account/passkeys/begin', { password: BOB }, cookie);
    assert.equal(onlyPassword.status, 400);
    assert.equal(onlyPassword.json().secondFactor, true);
    const both = await api(s, '/api/account/passkeys/begin', { password: BOB, passkey: await stepUpPasskey(s, cookie, a) }, cookie);
    assert.equal(both.status, 200, both.text);
    // Turning the second factor off or setting up the app code: the same.
    assert.equal((await api(s, '/api/account/totp/setup', { passkey: await stepUpPasskey(s, cookie, a) }, cookie)).status, 400);
    assert.equal(s.store.totpPending('bob'), false);

    // A passkey alone is a sign in that passes the rule for managing nodes (two-step is on), and is
    // still held back by the wait after the first second factor.
    const w = await api(s, '/api/manage/restart', { host: 'a.test:1', password: BOB, passkey: await stepUpPasskey(s, cookie, a) }, cookie);
    assert.equal(w.status, 403, w.text);
    assert.equal(w.json().code, 'second-factor-new');
    assert.equal(calls.length, 0);
    // Past the 15 minutes of a recent sign in, the page asks for the password again, as after a password sign in.
    s.clock.t += RECENT_AUTH_MS + 1000;
    const later = await api(s, '/api/manage/restart', { host: 'a.test:1', password: BOB }, cookie);
    assert.equal(later.status, 403);
    assert.equal(later.json().reauth, true);
    const reauth = await api(s, '/api/account/reauth', { password: BOB }, cookie);
    assert.equal(reauth.status, 200, reauth.text);
  } finally {
    await s.close();
  }
});

test('passkey sign in: an admin signing in with a passkey alone passes the rule for managed nodes, and the wait of the first second factor holds', async () => {
  const manage = { client: { call: async () => ({ ok: true, status: 202, body: {} }) }, nodes: ['a.test:1'] };
  const s = await setup({ manage });
  try {
    const cookie = await logIn(s, 'Alice', ALICE);
    // Without a second factor the rule refuses.
    const refused = await api(s, '/api/users/reset-second-factor', { name: 'bob', password: ALICE }, cookie);
    assert.equal(refused.status, 403);
    assert.equal(refused.json().code, 'second-factor-required');
    const { a, options } = await addPasskey(s, cookie, { password: ALICE });
    const r = await passkeyOnly(s, a, options.user.id);
    assert.equal(r.status, 200, r.text);
    assert.deepEqual(r.json(), { ok: true, name: 'Alice' });
    assert.equal((await api(s, '/api/account/reauth', { password: ALICE }, cookieOf(r))).status, 200);
    const held = await api(s, '/api/users/reset-second-factor', { name: 'bob', password: ALICE }, cookieOf(r));
    assert.equal(held.status, 403, held.text);
    assert.equal(held.json().code, 'second-factor-new', 'two-step is on, but the wait after the first passkey runs');
    // Once it is over, the step-up is the password and the passkey, not the sign in.
    s.clock.t += FIRST_FACTOR_HOLD_MS + 1000;
    const again = await passkeyOnly(s, a, options.user.id);
    const fresh = cookieOf(again);
    assert.equal((await api(s, '/api/account/reauth', { password: ALICE }, fresh)).status, 200);
    const missing = await api(s, '/api/users/reset-second-factor', { name: 'bob', password: ALICE }, fresh);
    assert.equal(missing.status, 400, missing.text);
    assert.equal(missing.json().secondFactor, true);
  } finally {
    await s.close();
  }
});

test('passkey sign in: a user ended while the check runs gets "expired" and no cookie; a password reset or a removed passkey ends the session of one that was made', async () => {
  const s = await setup();
  try {
    const { a, handle } = await bobWithPasskey(s);
    const b = (await beginSignIn(s)).json();
    const credential = answer(a, b.options, { userHandle: handle });
    const running = finishSignIn(s, b.token, credential);
    s.login.endUser('bob');
    const r = await running;
    // The server answers one request at a time here, so the change may land before or after the
    // check; the sign in is never both a success and ended.
    if (r.status === 200) assert.equal(await alive(s, cookieOf(r)), 'bob');
    else assert.deepEqual([r.status, r.json().restart], [401, true]);

    const second = await passkeyOnly(s, a, handle);
    assert.equal(second.status, 200, second.text);
    const cookie = cookieOf(second);
    assert.equal(await alive(s, cookie), 'bob');
    await s.store.setPassword('bob', await hashPassword('another password', undefined, fakeHasher, s.store.currentPepper()));
    s.login.endUser('bob');
    assert.equal(await alive(s, cookie), null);
    // The passkey itself still signs in: a password reset does not end it (the account page says so).
    const third = await passkeyOnly(s, a, handle);
    assert.equal(third.status, 200, third.text);
    // Removing it, or resetting the second factor, does.
    await s.store.resetSecondFactor('bob');
    s.login.endUser('bob');
    assert.equal(await alive(s, cookieOf(third)), null);
    const fourth = await passkeyOnly(s, a, handle);
    assert.equal(fourth.status, 401);
    assert.equal(fourth.text, JSON.stringify({ error: PASSKEY_SIGNIN_FAILED }));
  } finally {
    await s.close();
  }
});

test('passkey sign in: audit.log and failures.log never hold a credential id, a user handle, a token or a challenge', async () => {
  const s = await setup();
  try {
    const { a, handle } = await bobWithPasskey(s, { counter: 10 });
    const seen = [a.id, a.rawId.toString('hex'), handle];
    // A good sign in, bad ones of several kinds, and a counter that went back.
    const good = await beginSignIn(s);
    seen.push(good.json().token, good.json().options.challenge);
    assert.equal((await finishSignIn(s, good.json().token, answer(a, good.json().options, { userHandle: handle }))).status, 200);
    for (const extra of [{ uv: false }, { origin: 'https://evil.example.org' }, { counter: 2 }, { userHandle: null }]) {
      const b = (await beginSignIn(s)).json();
      seen.push(b.token, b.options.challenge);
      assert.equal((await finishSignIn(s, b.token, answer(a, b.options, { userHandle: handle, ...extra }))).status, 401);
    }
    const stranger = new SoftAuthenticator();
    seen.push(stranger.id);
    const b = (await beginSignIn(s)).json();
    assert.equal((await finishSignIn(s, b.token, answer(stranger, b.options, { userHandle: handle }))).status, 401);
    await s.audit.flush();
    await s.failures.flush();
    const auditText = await fs.readFile(s.audit.file, 'utf8');
    const failuresText = await fs.readFile(s.failures.file, 'utf8');
    for (const [what, text] of [['audit.log', auditText], ['failures.log', failuresText]]) {
      for (const secret of seen) assert.equal(text.includes(secret), false, `${what} holds ${secret.slice(0, 8)}...`);
    }
    const audit = await rawLines(s.audit.file);
    const counter = audit.filter((l) => l.event === 'passkey-counter-error');
    assert.deepEqual(counter.map(({ time, ...rest }) => rest), [{ event: 'passkey-counter-error', user: 'bob', passkey: 'Passkey 1', address: IP, step: 'sign-in' }]);
    const failed = (await rawLines(s.failures.file)).filter((l) => l.event === 'passkey-sign-in-failures');
    assert.equal(failed.length, 1);
    assert.equal(failed[0].user, null, 'no user name');
    assert.equal(failed[0].failures, 5);
    assert.equal(failed[0].lastAddress, IP);
    assert.deepEqual(Object.keys(failed[0]).sort(), ['addresses', 'event', 'failures', 'from', 'lastAddress', 'time', 'to', 'user']);
    // A sign in is not a security event of its own.
    assert.equal(audit.some((l) => l.event === 'login' || l.event === 'sign-in'), false);
  } finally {
    await s.close();
  }
});

// Every account route that changes something, with a body that would work once the password is
// given: from a session made with a passkey alone, none runs before the password is entered.
const CHANGES = ['password', 'totp/setup', 'totp/enable', 'totp/disable', 'recovery-codes', 'sign-out-others', 'devices/remove', 'devices/remove-others', 'passkeys/challenge', 'passkeys/begin', 'passkeys/finish', 'passkeys/rename', 'passkeys/remove'];

test('passkey sign in: a session made with a passkey alone is asked for the password on every account change, and one made with the password is not', async () => {
  const s = await setup();
  try {
    const { a, handle, cookie: first } = await bobWithPasskey(s);
    const pk = cookieOf(await passkeyOnly(s, a, handle));
    const before = (await get(s, '/api/account', pk)).json();
    assert.equal(before.signedInWith, 'passkey');
    assert.equal(before.recentSignIn, false);
    const ref = before.passkeys.list[0].id;
    const deviceId = before.devices[0].id;
    for (const route of CHANGES) {
      const r = await api(s, `/api/account/${route}`, { password: BOB, next: 'a brand new password!', id: ref, device: deviceId, name: 'x', code: '123456' }, pk);
      assert.equal(r.status, 403, `${route}: ${r.text}`);
      assert.equal(r.json().reauth, true, route);
    }
    // Nothing changed: the other session, the devices and the passkey are all still there.
    assert.equal(await alive(s, first), 'bob');
    const after = (await get(s, '/api/account', pk)).json();
    assert.equal(after.devices.length, before.devices.length);
    assert.equal(after.passkeys.list.length, 1);
    assert.equal(after.sessions.length, before.sessions.length);
    // Given the password, the same session can go on (for 15 minutes).
    assert.equal((await api(s, '/api/account/reauth', { password: BOB }, pk)).status, 200);
    assert.equal((await get(s, '/api/account', pk)).json().recentSignIn, true);
    assert.equal((await api(s, '/api/account/sign-out-others', {}, pk)).status, 200);
    assert.equal(await alive(s, first), null);
    // A session made with the password and a passkey (the usual way) has just given the password.
    const usual = await logInWithPasskey(s, a);
    assert.equal((await get(s, '/api/account', usual)).json().signedInWith, 'password');
    assert.equal((await api(s, '/api/account/passkeys/rename', { id: ref, name: 'Phone' }, usual)).status, 200);
  } finally {
    await s.close();
  }
});

test('passkey sign in: a thief of a passkey cannot lock the owner out of the password by using up the tries at reauth', async () => {
  const s = await setup();
  try {
    const { a, handle } = await bobWithPasskey(s);
    const mine = await logInWithPasskey(s, a);
    // Sessions made with the passkey alone, each with its own tries, together past the user's.
    let tries = 0;
    for (let i = 0; i < 4; i++) {
      // A minute apart: successful passkey sign ins are paced per user.
      s.clock.t += PASSKEY_SIGNIN_INTERVAL_MS;
      const thief = cookieOf(await passkeyOnly(s, a, handle));
      for (let k = 0; k < 10; k++) {
        const r = await api(s, '/api/account/reauth', { password: 'not the password' }, thief);
        assert.ok([400, 429].includes(r.status), r.text);
        tries++;
      }
    }
    assert.equal(tries, 40);
    // The owner's own session still has its tries, and the password still works.
    const ok = await api(s, '/api/account/reauth', { password: BOB }, mine);
    assert.equal(ok.status, 200, ok.text);
  } finally {
    await s.close();
  }
});

test('passkey sign in: a manage user\'s sign in with a passkey alone is an audit line with the label, with no credential id or handle', async () => {
  const s = await setup();
  try {
    const { a, handle } = await bobWithPasskey(s);
    const r = await passkeyOnly(s, a, handle);
    assert.equal(r.status, 200, r.text);
    const lines = (await auditLines(s)).filter((l) => l.event === 'passkey-sign-in');
    assert.equal(lines.length, 1);
    assert.equal(lines[0].user, 'bob');
    assert.equal(lines[0].role, 'manage');
    assert.equal(lines[0].address, IP);
    assert.equal(typeof lines[0].passkey, 'string');
    const text = JSON.stringify(lines[0]);
    assert.equal(text.includes(a.id.toString('base64url')), false);
    assert.equal(text.includes(handle), false);
  } finally {
    await s.close();
  }
});

// Bob with two passkeys, signed in with the password and the first: a (kept when it confirms), b.
async function bobWithTwo(s) {
  const first = await bobWithPasskey(s);
  const cookie = await logInWithPasskey(s, first.a);
  const second = await addPasskey(s, cookie, { stepUp: { passkey: await stepUpPasskey(s, cookie, first.a) } });
  assert.equal(second.finish.status, 200, second.finish.text);
  const cur = await logInWithPasskey(s, first.a);
  return { a: first.a, b: second.a, cookie: cur };
}
const passkeyCount = (s) => s.store.passkeys('bob').length;
const NEW_PW = 'a brand new password!';

test('password change: the box "also remove my other passkeys" removes all but the passkey that confirmed it, ends other sessions, writes a count and says how many', async () => {
  const s = await setup();
  try {
    const { a, b, cookie } = await bobWithTwo(s);
    const other = await logInWithPasskey(s, b);
    assert.equal(passkeyCount(s), 2);
    const r = await api(s, '/api/account/password', { password: BOB, next: NEW_PW, passkey: await stepUpPasskey(s, cookie, a), removeOtherPasskeys: true }, cookie);
    assert.equal(r.status, 200, r.text);
    assert.deepEqual(r.json(), { ok: true, removedPasskeys: 1 });
    const left = s.store.passkeys('bob');
    assert.equal(left.length, 1);
    assert.equal(s.store.passkeyById('bob', a.id) !== null, true);
    assert.equal(s.store.passkeyById('bob', b.id), null);
    assert.equal(await alive(s, cookie), 'bob');
    assert.equal(await alive(s, other), null);
    const lines = (await auditLines(s)).filter((l) => l.event === 'passkeys-removed-with-password');
    assert.equal(lines.length, 1);
    assert.equal(lines[0].count, 1);
    assert.equal(lines[0].with, 'password+passkey');
    assert.equal(JSON.stringify(lines[0]).includes(b.id.toString('base64url')), false);
    // The removed passkey signs nobody in any more.
    assert.notEqual((await passkeyOnly(s, b, s.store.passkeyUserId('bob'))).status, 200);
  } finally {
    await s.close();
  }
});

test('password change: unticked (or not true) removes no passkey, as before', async () => {
  const s = await setup();
  try {
    const { a, cookie } = await bobWithTwo(s);
    let pw = BOB;
    let c = cookie;
    for (const flag of [undefined, false, 'true', 1, 'yes']) {
      const next = pw === BOB ? NEW_PW : BOB;
      const body = { password: pw, next, passkey: await stepUpPasskey(s, c, a) };
      if (flag !== undefined) body.removeOtherPasskeys = flag;
      const r = await api(s, '/api/account/password', body, c);
      assert.equal(r.status, 200, `${flag}: ${r.text}`);
      assert.deepEqual(r.json(), { ok: true });
      assert.equal(passkeyCount(s), 2, String(flag));
      pw = next;
      c = await logInWithPasskey(s, a, 'bob', pw);
    }
    assert.equal((await auditLines(s)).some((l) => l.event === 'passkeys-removed-with-password'), false);
  } finally {
    await s.close();
  }
});

test('password change: confirmed with an app code or a recovery code, the box removes every passkey, and the recovery codes go with the last second factor', async () => {
  for (const how of ['code', 'recovery']) {
    const s = await setup();
    try {
      const { a, cookie } = await bobWithTwo(s);
      const { secret, codes } = await enableTotp(s, cookie, BOB, { passkey: await stepUpPasskey(s, cookie, a) });
      const fresh = await logInWithPasskey(s, a);
      s.clock.t += 30_000;
      const stepUp = how === 'code' ? { code: codeNow(s, secret) } : { recovery: codes[0] };
      const r = await api(s, '/api/account/password', { password: BOB, next: NEW_PW, removeOtherPasskeys: true, ...stepUp }, fresh);
      assert.equal(r.status, 200, r.text);
      assert.deepEqual(r.json(), { ok: true, removedPasskeys: 2 }, how);
      assert.equal(passkeyCount(s), 0);
      // The app code is still there, so two-step sign-in stays on.
      assert.equal(s.store.secondFactorEnabled('bob'), true);
      assert.equal((await auditLines(s)).find((l) => l.event === 'passkeys-removed-with-password').with, `password+${how}`);
    } finally {
      await s.close();
    }
  }
});

test('password change: a forged request cannot remove passkeys without the step-up, with a wrong password, or with the wrong second factor', async () => {
  const s = await setup();
  try {
    const { a, cookie } = await bobWithTwo(s);
    const forged = [
      // No second factor at all.
      { password: BOB, next: NEW_PW, removeOtherPasskeys: true },
      // No password.
      { next: NEW_PW, removeOtherPasskeys: true, passkey: await stepUpPasskey(s, cookie, a) },
      // A wrong password.
      { password: 'not it', next: NEW_PW, removeOtherPasskeys: true, passkey: await stepUpPasskey(s, cookie, a) },
      // A wrong code.
      { password: BOB, next: NEW_PW, removeOtherPasskeys: true, code: '000000' },
      // A wrong recovery code.
      { password: BOB, next: NEW_PW, removeOtherPasskeys: true, recovery: 'aaaa-bbbb-cccc' },
      // The passkey flag alone.
      { removeOtherPasskeys: true },
    ];
    for (const body of forged) {
      const r = await api(s, '/api/account/password', body, cookie);
      assert.equal(r.status, 400, r.text);
      assert.equal(passkeyCount(s), 2, JSON.stringify(Object.keys(body)));
    }
    // A passkey session that has not given the password is refused before anything runs.
    const pk = cookieOf(await passkeyOnly(s, a, s.store.passkeyUserId('bob')));
    const r = await api(s, '/api/account/password', { password: BOB, next: NEW_PW, removeOtherPasskeys: true }, pk);
    assert.equal(r.status, 403);
    assert.equal(passkeyCount(s), 2);
    // The password is still the old one.
    assert.equal((await postForm(s, '/login', { name: 'bob', password: BOB })).json().secondFactor, true);
  } finally {
    await s.close();
  }
});

test('password change: when the write of the password and the removed passkeys fails, nothing changed: old password, both passkeys, other sessions, no audit line', async () => {
  const s = await setup();
  try {
    const { a, b, cookie } = await bobWithTwo(s);
    const other = await logInWithPasskey(s, b);
    // The write that takes passkeys away fails (a full disk, say); one that only changes the password would not.
    const put = s.store.db.put.bind(s.store.db);
    s.store.db.put = (kind, rec) => {
      if (rec.name === 'bob' && (rec.credentials ?? []).length < 2) throw new Error('disk full');
      return put(kind, rec);
    };
    const r = await api(s, '/api/account/password', { password: BOB, next: NEW_PW, passkey: await stepUpPasskey(s, cookie, a), removeOtherPasskeys: true }, cookie);
    assert.equal(r.status, 500, r.text);
    assert.equal(r.json().error, 'The change could not be saved, so nothing was changed. Try again later.');
    s.store.db.put = put;
    assert.equal(passkeyCount(s), 2);
    assert.equal(await alive(s, cookie), 'bob');
    assert.equal(await alive(s, other), 'bob', 'nobody was signed out');
    assert.equal((await postForm(s, '/login', { name: 'bob', password: NEW_PW })).status, 401);
    assert.equal((await auditLines(s)).some((l) => l.event === 'password-changed' || l.event === 'passkeys-removed-with-password'), false);
    // The same request works once the disk does.
    const again = await api(s, '/api/account/password', { password: BOB, next: NEW_PW, passkey: await stepUpPasskey(s, cookie, a), removeOtherPasskeys: true }, cookie);
    assert.deepEqual(again.json(), { ok: true, removedPasskeys: 1 });
    assert.equal(await alive(s, other), null);
  } finally {
    await s.close();
  }
});

test('passkey sign in: past three at once, a user\'s passkey sign ins are a 429 with a wait, one a minute after, and the password is not held back', async () => {
  const s = await setup();
  try {
    const { a, handle } = await bobWithPasskey(s);
    for (let i = 0; i < PASSKEY_SIGNIN_BURST; i++) assert.equal((await passkeyOnly(s, a, handle)).status, 200, `sign in ${i + 1}`);
    const refused = await passkeyOnly(s, a, handle);
    assert.equal(refused.status, 429, refused.text);
    assert.equal(refused.headers['set-cookie'], undefined);
    assert.ok(Number(refused.headers['retry-after']) > 0 && Number(refused.headers['retry-after']) <= PASSKEY_SIGNIN_INTERVAL_MS / 1000);
    assert.equal(refused.json().retryAfter, Number(refused.headers['retry-after']));
    assert.match(refused.json().error, /sign in with the password/);
    // The password works, and so does a passkey after the wait.
    assert.equal((await postForm(s, '/login', { name: 'bob', password: BOB })).status, 200);
    s.clock.t += PASSKEY_SIGNIN_INTERVAL_MS;
    assert.equal((await passkeyOnly(s, a, handle)).status, 200);
    assert.equal((await passkeyOnly(s, a, handle)).status, 429);
  } finally {
    await s.close();
  }
});

test('passkey sign in: a wrong password asked again in a session made by a passkey is noted in failures.log by user; the daily budget of 20 is only for those sessions', async () => {
  const s = await setup();
  try {
    const { a, handle } = await bobWithPasskey(s);
    const mine = await logInWithPasskey(s, a);
    const thief = [];
    for (let i = 0; i < 3; i++) thief.push(cookieOf(await passkeyOnly(s, a, handle)));
    // A wrong password in the owner's own session is not noted.
    assert.equal((await api(s, '/api/account/reauth', { password: 'not it' }, mine)).status, 400);
    await s.failures.flush();
    assert.equal((await rawLines(s.failures.file)).some((l) => l.event === 'reauth-failures'), false);
    // From passkey sessions it is: 20 a day in all, then a 429, whichever session asks.
    let wrong = 0;
    for (const c of thief.slice(0, 2)) {
      for (let k = 0; k < 10; k++) {
        // The wait of the session after wrong tries is its own matter; here it is the budget that is looked at.
        s.login.reauths.map.clear();
        const r = await api(s, '/api/account/reauth', { password: 'not it' }, c);
        assert.equal(r.status, 400, r.text);
        wrong++;
      }
    }
    assert.equal(wrong, REAUTHS_PER_PASSKEY_USER);
    s.login.reauths.map.clear();
    const cut = await api(s, '/api/account/reauth', { password: BOB }, thief[2]);
    assert.equal(cut.status, 429, cut.text);
    assert.ok(Number(cut.headers['retry-after']) > 3600, 'a wait of hours, not minutes');
    await s.failures.flush();
    const lines = (await rawLines(s.failures.file)).filter((l) => l.event === 'reauth-failures');
    assert.deepEqual(lines.map((l) => [l.user, l.failures]), [['bob', 20]]);
    assert.equal(JSON.stringify(lines).includes('not it'), false);
    // The owner's session has its own tries, and the next day a passkey session has them again.
    assert.equal((await api(s, '/api/account/reauth', { password: BOB }, mine)).status, 200);
    s.clock.t += REAUTH_PASSKEY_WINDOW_MS + 1000;
    const next = cookieOf(await passkeyOnly(s, a, handle));
    assert.equal((await api(s, '/api/account/reauth', { password: BOB }, next)).status, 200);
  } finally {
    await s.close();
  }
});
