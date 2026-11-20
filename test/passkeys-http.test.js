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
import { CODE_EXPIRED, PASSKEY_FAILED, createApp } from '../lib/app.js';
import { CODE_USER_FREE, MAX_PASSKEY_FORM_BYTES, PENDING_MS, PENDING_TRIES, createLogin, ipKey } from '../lib/login.js';
import { hashPassword } from '../lib/password.js';
import { UserStore } from '../lib/users.js';
import { Keyring } from '../lib/keys.js';
import { createAudit, createFailureLog } from '../lib/audit.js';
import { CHALLENGES_PER_SESSION, RECENT_AUTH_MS } from '../lib/account.js';
import { MAX_PASSKEYS, NO_PASSKEYS, createPasskeys, passkeyRef } from '../lib/passkeys.js';
import { base32Decode, hotp, stepAt, totp } from '../lib/totp.js';
import { SoftAuthenticator } from './helpers/soft-authenticator.js';
import { fakeHasher } from './helpers/fake-hasher.js';

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
async function setup({ siteUrl = ORIGIN } = {}) {
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
  const login = createLogin({ users: config.users, store, settings: config.login, hasher: fakeHasher, now, audit, failures, sleep: async () => {}, passkeys, log: (m) => logs.push(m) });
  const monitor = new Monitor({ targets: config.targets, dataDir, probeFn: async () => ({ up: true, ms: 1 }) });
  const server = createApp({ monitor, publicDir, login });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return {
    port: server.address().port, clock, store, login, audit, failures, dataDir, logs, passkeys,
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
    assert.deepEqual(account.passkeys, { available: true, reason: null, origin: ORIGIN, rpId: RP_ID, max: MAX_PASSKEYS, list: [] });

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
    assert.deepEqual({ ...account.passkeys, list: undefined }, { available: false, reason: 'no-address', origin: null, rpId: null, max: MAX_PASSKEYS, list: undefined });
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
