import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { Keyring } from '../lib/keys.js';
import { hashPassword } from '../lib/password.js';
import { DatabaseSync } from 'node:sqlite';
import { UserStore, goodPasskeyName, passkeyLabel, passkeyRef as storeRef } from '../lib/users.js';
import { DB_FILE } from '../lib/userdb.js';
import {
  ALGS, CHALLENGE_MS, LIMITS, MIN_RSA_BITS, goodEd25519, keyAlg, passkeyOriginProblem, MAX_CHALLENGES, MAX_PASSKEYS, NO_PASSKEYS, PasskeyError, TIMEOUT_MS, createPasskeys, fromB64url, passkeyName, passkeyOrigin, passkeyRef, readCredential,
} from '../lib/passkeys.js';
import { SoftAuthenticator, cbor, coseKey } from './helpers/soft-authenticator.js';
import { fakeHasher } from './helpers/fake-hasher.js';

const ROOT = path.join(path.dirname(new URL(import.meta.url).pathname), '..');
const FIXTURES = JSON.parse(await fs.readFile(path.join(ROOT, 'test/fixtures/passkeys.json'), 'utf8'));
const NOW = 1_800_000_000_000;
const ORIGIN = 'https://status.example.org';
const RP_ID = 'status.example.org';
const KEYS = new Keyring(new Map([[1, crypto.randomBytes(32)]]));
const b64url = (buf) => Buffer.from(buf).toString('base64url');

// A user store in a temp directory of its own, with alice and bob, and the passkeys of a site.
async function setup({ siteUrl = ORIGIN, users = ['alice', 'bob'], newChallenge } = {}) {
  const dataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'passkeys-'));
  const clock = { t: NOW };
  const store = await UserStore.open({ dataDir, keys: KEYS, warn: () => {}, now: () => clock.t });
  for (const name of users) await store.createUser({ name, passwordHash: await hashPassword('a good password', undefined, fakeHasher) });
  const pk = createPasskeys({ siteUrl, rpName: 'Status', store, now: () => clock.t, ...(newChallenge ? { newChallenge } : {}) });
  return { dataDir, clock, store, pk, origin: pk.origin ?? ORIGIN, rpId: pk.rpId ?? RP_ID };
}

// Registers a new authenticator for a user through the module, as the account page does.
async function register(ctx, name, { alg = -7, fmt = 'none', session = 's1', epoch = 0, label = '', ...auth } = {}) {
  const a = new SoftAuthenticator({ alg, ...auth });
  const options = await ctx.pk.registrationOptions(name, { sessionId: session, epoch });
  const done = await ctx.pk.finishRegistration(name, a.create({ challenge: options.challenge, origin: ctx.origin, rpId: ctx.rpId, fmt }), { sessionId: session, epoch, label });
  return { a, options, done };
}

// A sign-in assertion of a, with a challenge the caller keeps (as the pending entry does).
function assertion(ctx, a, name, opts = {}) {
  const { challenge } = ctx.pk.loginOptions(name);
  return { challenge, response: a.get({ challenge, origin: ctx.origin, rpId: ctx.rpId, ...opts }) };
}

// Runs fn, which must throw a PasskeyError, and gives its code.
async function code(fn) {
  try {
    await fn();
  } catch (err) {
    assert.ok(err instanceof PasskeyError, `expected a PasskeyError, got ${err}`);
    return err.code;
  }
  assert.fail('expected a PasskeyError');
}

test('passkeys: the origin and rpId come from the site address; http works only for localhost, and an IP address never', () => {
  assert.deepEqual(passkeyOrigin('https://example.org'), { available: true, reason: null, origin: 'https://example.org', rpId: 'example.org' });
  assert.deepEqual(passkeyOrigin('https://status.example.org:8443'), { available: true, reason: null, origin: 'https://status.example.org:8443', rpId: 'status.example.org' });
  assert.deepEqual(passkeyOrigin('http://localhost:8080'), { available: true, reason: null, origin: 'http://localhost:8080', rpId: 'localhost' });
  assert.deepEqual(passkeyOrigin('http://localhost'), { available: true, reason: null, origin: 'http://localhost', rpId: 'localhost' });
  assert.equal(passkeyOrigin('https://localhost').rpId, 'localhost');
  // The default port is not part of the origin, as browsers write it.
  assert.equal(passkeyOrigin('https://example.org:443').origin, 'https://example.org');
  const none = { available: false, reason: 'no-address', origin: null, rpId: null };
  for (const bad of [null, undefined, '', 42, 'not a url', 'http://example.org', 'ftp://example.org', 'http://127.0.0.1', 'https://127.0.0.1', 'https://[::1]', 'http://[::1]:8080',
    'https://192.168.1.10:8443', 'https://example.org.', 'https://example.org/path', 'https://example.org/?q', 'https://user:pw@example.org', 'http://localhost.example.org', `https://${'a'.repeat(300)}.org`]) {
    assert.deepEqual(passkeyOrigin(bad), none, String(bad));
  }
});

test('passkeys: without a usable address nothing works, and NO_PASSKEYS is that state', async () => {
  for (const pk of [NO_PASSKEYS, createPasskeys({ siteUrl: 'http://example.org', store: null })]) {
    assert.equal(pk.available, false);
    assert.equal(pk.reason, 'no-address');
    assert.equal(pk.origin, null);
    assert.equal(pk.rpId, null);
    assert.equal(await code(() => pk.registrationOptions('alice', { sessionId: 's', epoch: 0 })), 'unavailable');
    assert.equal(await code(() => pk.finishRegistration('alice', {}, { sessionId: 's', epoch: 0 })), 'unavailable');
    assert.equal(pk.loginOptions('alice'), null);
    assert.equal(pk.stepUpOptions('alice', 's'), null);
    assert.deepEqual(await pk.verify('alice', {}, 'challenge'), { ok: false });
    assert.equal((await pk.verifyStepUp('alice', 's', {})).ok, false);
    pk.dropSession('s');
    pk.dropUser('alice');
  }
  assert.ok(Object.isFrozen(NO_PASSKEYS));
});

test('passkeys: registration options ask for user verification and no attestation, with the allowed algorithms and a stable user id', async () => {
  const ctx = await setup();
  const o = await ctx.pk.registrationOptions('alice', { sessionId: 's1', epoch: 0 });
  assert.equal(o.attestation, 'none');
  assert.deepEqual(o.authenticatorSelection, { residentKey: 'preferred', userVerification: 'required', requireResidentKey: false });
  assert.deepEqual(o.pubKeyCredParams.map((p) => p.alg), ALGS);
  assert.deepEqual(ALGS, [-8, -7, -257]);
  assert.equal(o.timeout, TIMEOUT_MS);
  assert.deepEqual(o.rp, { name: 'Status', id: RP_ID });
  assert.equal(o.user.name, 'alice');
  assert.deepEqual(o.excludeCredentials, []);
  assert.match(o.challenge, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(fromB64url(o.user.id).length, 32);
  // The user id is made once and kept; every call has a new challenge.
  const again = await ctx.pk.registrationOptions('alice', { sessionId: 's1', epoch: 0 });
  assert.equal(again.user.id, o.user.id);
  assert.notEqual(again.challenge, o.challenge);
  assert.equal(o.user.id, await ctx.store.ensurePasskeyUserId('alice'));
  assert.notEqual((await ctx.pk.registrationOptions('bob', { sessionId: 's2', epoch: 0 })).user.id, o.user.id);
  // The challenge of the second call replaced that of the first: one per session.
  assert.equal(ctx.pk.challengeCount, 2);
  // Passkeys the user has are excluded, with their transports, so one cannot be added twice.
  const { a } = await register(ctx, 'alice');
  const o2 = await ctx.pk.registrationOptions('alice', { sessionId: 's1', epoch: 0 });
  assert.deepEqual(o2.excludeCredentials, [{ id: a.id, type: 'public-key', transports: ['hybrid', 'internal'] }]);
  await assert.rejects(ctx.pk.registrationOptions('alice', {}), /session id/);
  await assert.rejects(ctx.pk.registrationOptions('nobody', { sessionId: 's3', epoch: 0 }), (err) => err.code === 'unknown');
});

test('passkeys: ES256, EdDSA and RS256 passkeys are added and then sign in; the first one brings recovery codes', async () => {
  const ctx = await setup();
  const first = await register(ctx, 'alice', { alg: -7, fmt: 'none', counter: 7 });
  assert.equal(first.done.first, true);
  assert.equal(first.done.recoveryCodes.length, 10);
  const r = first.done.record;
  assert.equal(first.done.ref, storeRef(first.a.id));
  assert.equal(first.done.ref, passkeyRef(first.a.id));
  assert.deepEqual(Object.keys(r).sort(), ['backedUp', 'backupEligible', 'counter', 'created', 'id', 'lastUsed', 'name', 'publicKey', 'rpId', 'transports', 'type']);
  assert.equal(r.type, 'passkey');
  assert.equal(r.id, first.a.id);
  assert.equal(r.publicKey, first.a.cose.toString('base64url'));
  assert.equal(r.counter, 7);
  assert.deepEqual(r.transports, ['hybrid', 'internal']);
  assert.equal(r.name, 'Passkey 1');
  assert.equal(r.created, new Date(NOW).toISOString());
  assert.equal(r.lastUsed, null);
  assert.equal(r.rpId, RP_ID);
  assert.equal(r.backupEligible, false);
  assert.equal(r.backedUp, false);

  const second = await register(ctx, 'alice', { alg: -8, fmt: 'packed', backupEligible: true, backedUp: true, label: '  Laptop  ' });
  assert.equal(second.done.first, false);
  assert.equal(second.done.recoveryCodes, null);
  assert.equal(second.done.record.name, 'Laptop');
  assert.equal(second.done.record.backupEligible, true);
  assert.equal(second.done.record.backedUp, true);
  const third = await register(ctx, 'alice', { alg: -257 });
  assert.equal(third.done.record.name, 'Passkey 3');
  assert.deepEqual(ctx.store.passkeys('alice').map((p) => p.name), ['Passkey 1', 'Laptop', 'Passkey 3']);
  assert.equal(ctx.store.secondFactorEnabled('alice'), true);

  for (const { a } of [first, second, third]) {
    const { challenge, response } = assertion(ctx, a, 'alice');
    const v = await ctx.pk.verify('alice', response, challenge);
    assert.equal(v.ok, true);
    assert.equal(v.ref, storeRef(a.id));
    await v.saved;
  }
  assert.equal(ctx.store.passkeyById('alice', first.a.id).counter, 8);
  assert.equal(ctx.store.passkeyById('alice', first.a.id).lastUsed, new Date(NOW).toISOString());
  // The new counter is written to the store, not only kept in memory.
  const again = await UserStore.open({ dataDir: ctx.dataDir, keys: KEYS, warn: () => {} });
  assert.equal(again.passkeyById('alice', first.a.id).counter, 8);
  again.close();
  ctx.store.close();
});

test('passkeys: sign-in options name only the passkeys made at this address, ask for user verification, and are null without one', async () => {
  const ctx = await setup();
  assert.equal(ctx.pk.loginOptions('alice'), null);
  assert.equal(ctx.pk.loginOptions('nobody'), null);
  const { a } = await register(ctx, 'alice');
  const { options, challenge } = ctx.pk.loginOptions('alice');
  assert.deepEqual(options, { challenge, rpId: RP_ID, allowCredentials: [{ id: a.id, type: 'public-key', transports: ['hybrid', 'internal'] }], timeout: TIMEOUT_MS, userVerification: 'required' });
  assert.notEqual(ctx.pk.loginOptions('alice').challenge, challenge);
  // The same store seen from another address: the passkey is still a second factor, but not usable.
  const elsewhere = createPasskeys({ siteUrl: 'https://other.example.net', store: ctx.store });
  assert.equal(elsewhere.loginOptions('alice'), null);
  assert.equal(elsewhere.stepUpOptions('alice', 's1'), null);
  const response = a.get({ challenge: 'Y2hhbGxlbmdl', origin: 'https://other.example.net', rpId: 'other.example.net' });
  assert.deepEqual(await elsewhere.verify('alice', response, 'Y2hhbGxlbmdl'), { ok: false });
  ctx.store.close();
});

test('passkeys: the fixture vectors are made again by the soft authenticator and accepted', async () => {
  const { origin, rpId, userId } = FIXTURES;
  for (const [label, f] of Object.entries(FIXTURES.credentials)) {
    const a = new SoftAuthenticator({ alg: f.alg, privateKey: f.privateKey, id: fromB64url(f.id), counter: f.counter, backupEligible: f.alg === -8, backedUp: f.alg === -8 });
    assert.equal(a.cose.toString('base64url'), f.publicKey, label);
    assert.equal(coseKey(crypto.createPublicKey({ key: f.privateKey, format: 'jwk' }), f.alg).toString('base64url'), f.publicKey, label);
    const reg = a.create({ challenge: f.registrationChallenge, origin, rpId, fmt: f.fmt, transports: ['internal'] });
    const get = a.get({ challenge: f.assertionChallenge, origin, rpId, userHandle: userId });
    // Ed25519 signatures are deterministic: the vectors come out byte for byte.
    if (f.alg === -8) {
      assert.deepEqual(reg, f.registration, label);
      assert.deepEqual(get, f.assertion, label);
    } else {
      assert.equal(reg.response.clientDataJSON, f.registration.response.clientDataJSON);
      assert.equal(get.response.authenticatorData, f.assertion.response.authenticatorData);
    }
  }

  // Through the module, with the fixtures' challenges, at the fixtures' address.
  const challenges = [];
  const ctx = await setup({ siteUrl: origin, newChallenge: () => challenges.shift() });
  for (const f of Object.values(FIXTURES.credentials)) {
    challenges.push(f.registrationChallenge);
    await ctx.pk.registrationOptions('alice', { sessionId: 's1', epoch: 0 });
    const { record } = await ctx.pk.finishRegistration('alice', f.registration, { sessionId: 's1', epoch: 0 });
    assert.equal(record.id, f.id);
    assert.equal(record.publicKey, f.publicKey);
    assert.equal(record.counter, f.counter);
  }
  // The user handle of the fixtures is not alice's: refused. Without it, both sign in.
  const f0 = FIXTURES.credentials.es256;
  assert.deepEqual(await ctx.pk.verify('alice', f0.assertion, f0.assertionChallenge), { ok: false });
  for (const f of Object.values(FIXTURES.credentials)) {
    const response = structuredClone(f.assertion);
    response.response.userHandle = null;
    const v = await ctx.pk.verify('alice', response, f.assertionChallenge);
    assert.equal(v.ok, true);
    await v.saved;
    assert.equal(ctx.store.passkeyById('alice', f.id).counter, f.assertionCounter);
  }
  ctx.store.close();
});

test('passkeys: a user handle, when sent, must be the user\'s own', async () => {
  const ctx = await setup();
  const { a, options } = await register(ctx, 'alice');
  let s = assertion(ctx, a, 'alice', { userHandle: options.user.id });
  assert.equal((await ctx.pk.verify('alice', s.response, s.challenge)).ok, true);
  const bobs = await ctx.store.ensurePasskeyUserId('bob');
  s = assertion(ctx, a, 'alice', { userHandle: bobs });
  assert.deepEqual(await ctx.pk.verify('alice', s.response, s.challenge), { ok: false });
  s = assertion(ctx, a, 'alice', { userHandle: b64url(crypto.randomBytes(32)) });
  assert.deepEqual(await ctx.pk.verify('alice', s.response, s.challenge), { ok: false });
  ctx.store.close();
});

test('passkeys: the counter must go up, unless both are 0 (synced passkeys); a counter that went back is told apart', async () => {
  const ctx = await setup();
  const { a } = await register(ctx, 'alice', { counter: 10 });
  let s = assertion(ctx, a, 'alice');
  assert.equal((await ctx.pk.verify('alice', s.response, s.challenge)).ok, true);
  assert.equal(ctx.store.passkeyById('alice', a.id).counter, 11);
  // The same counter again, and a lower one: a copy of the authenticator, maybe.
  for (const counter of [11, 3, 0]) {
    s = assertion(ctx, a, 'alice', { counter });
    assert.deepEqual(await ctx.pk.verify('alice', s.response, s.challenge), { ok: false, counterError: true, ref: storeRef(a.id) });
  }
  assert.equal(ctx.store.passkeyById('alice', a.id).counter, 11);
  // A counter that went back is only reported for a right signature: a wrong one is just invalid.
  s = assertion(ctx, a, 'alice', { counter: 2 });
  s.response.response.signature = b64url(crypto.randomBytes(70));
  assert.deepEqual(await ctx.pk.verify('alice', s.response, s.challenge), { ok: false });
  s = assertion(ctx, a, 'alice', { counter: 500 });
  assert.equal((await ctx.pk.verify('alice', s.response, s.challenge)).ok, true);
  assert.equal(ctx.store.passkeyById('alice', a.id).counter, 500);

  const synced = (await register(ctx, 'bob', { alg: -8, counter: 0, backupEligible: true, backedUp: true })).a;
  for (let i = 0; i < 3; i++) {
    s = assertion(ctx, synced, 'bob');
    const v = await ctx.pk.verify('bob', s.response, s.challenge);
    assert.equal(v.ok, true);
    await v.saved;
  }
  assert.equal(ctx.store.passkeyById('bob', synced.id).counter, 0);
  // Once a passkey sent a counter, 0 is a counter that went back.
  s = assertion(ctx, synced, 'bob', { counter: 4 });
  assert.equal((await ctx.pk.verify('bob', s.response, s.challenge)).ok, true);
  s = assertion(ctx, synced, 'bob', { counter: 0 });
  assert.equal((await ctx.pk.verify('bob', s.response, s.challenge)).counterError, true);
  ctx.store.close();
});

test('passkeys: assertions with the wrong origin, rpId, type, flags, challenge, frame or signature are refused', async () => {
  const ctx = await setup();
  const { a } = await register(ctx, 'alice', { counter: 1 });
  const bad = {
    'wrong origin': { origin: 'https://evil.example.org' },
    'origin with another port': { origin: `${ORIGIN}:8443` },
    'http origin': { origin: `http://${RP_ID}` },
    'wrong rpId hash': { rpIdHash: crypto.createHash('sha256').update('evil.example.org').digest() },
    'parent domain rpId': { rpId: 'example.org' },
    'user verification off': { uv: false },
    'user presence off': { up: false },
    'cross-origin frame': { crossOrigin: true },
    'top origin without cross origin': { extra: { topOrigin: 'https://evil.example.org' } },
    'registration type': { type: 'webauthn.create' },
  };
  for (const [what, opts] of Object.entries(bad)) {
    const s = assertion(ctx, a, 'alice', opts);
    assert.deepEqual(await ctx.pk.verify('alice', s.response, s.challenge), { ok: false }, what);
  }
  let s = assertion(ctx, a, 'alice');
  assert.deepEqual(await ctx.pk.verify('alice', s.response, ctx.pk.loginOptions('alice').challenge), { ok: false }, 'another challenge');
  assert.deepEqual(await ctx.pk.verify('alice', s.response, ''), { ok: false }, 'no challenge');
  assert.deepEqual(await ctx.pk.verify('alice', s.response, null), { ok: false }, 'no challenge');
  // Signed by another key.
  const other = new SoftAuthenticator({ id: a.rawId, counter: 50 });
  s = assertion(ctx, other, 'alice');
  assert.deepEqual(await ctx.pk.verify('alice', s.response, s.challenge), { ok: false }, 'another key');
  // A right one still works after all that, and no counter moved meanwhile.
  assert.equal(ctx.store.passkeyById('alice', a.id).counter, 1);
  s = assertion(ctx, a, 'alice');
  assert.equal((await ctx.pk.verify('alice', s.response, s.challenge)).ok, true);
  ctx.store.close();
});

test('passkeys: a passkey signs in only as its own user, and an unknown one not at all', async () => {
  const ctx = await setup();
  const alices = (await register(ctx, 'alice')).a;
  await register(ctx, 'bob', { session: 's2' });
  const { challenge } = ctx.pk.loginOptions('bob');
  const response = alices.get({ challenge, origin: ctx.origin, rpId: ctx.rpId });
  assert.deepEqual(await ctx.pk.verify('bob', response, challenge), { ok: false });
  assert.deepEqual(await ctx.pk.verify('BOB', response, challenge), { ok: false });
  assert.deepEqual(await ctx.pk.verify('nobody', response, challenge), { ok: false });
  const stranger = new SoftAuthenticator();
  assert.deepEqual(await ctx.pk.verify('alice', stranger.get({ challenge, origin: ctx.origin, rpId: ctx.rpId }), challenge), { ok: false });
  // The same credential cannot be added for a second user. That is answered as a passkey that
  // could not be checked (marked taken for the caller's log), never as "added already", which would
  // tell bob that someone has this id.
  const o = await ctx.pk.registrationOptions('bob', { sessionId: 's2', epoch: 0 });
  const err = await ctx.pk.finishRegistration('bob', alices.create({ challenge: o.challenge, origin: ctx.origin, rpId: ctx.rpId }), { sessionId: 's2', epoch: 0 }).catch((e) => e);
  assert.ok(err instanceof PasskeyError);
  assert.equal(err.code, 'invalid');
  assert.equal(err.taken, true);
  assert.equal(err.message.includes(alices.id), false);
  assert.equal(ctx.store.passkeys('bob').length, 1);
  ctx.store.close();
});

test('passkeys: the browser\'s answer is checked for shape and size before anything parses it', async () => {
  const ctx = await setup();
  const { a } = await register(ctx, 'alice', { counter: 1 });
  const { challenge } = ctx.pk.loginOptions('alice');
  const good = a.get({ challenge, origin: ctx.origin, rpId: ctx.rpId });
  assert.ok(readCredential(good, 'get'));
  assert.ok(readCredential(JSON.stringify(good), 'get'));
  const edit = (fn) => {
    const c = structuredClone(good);
    fn(c);
    return c;
  };
  const pad = (n) => 'A'.repeat(n);
  const bad = {
    'malformed JSON': '{"id": ',
    'JSON text too long': JSON.stringify({ ...good, padding: pad(9000) }),
    'JSON array': '[]',
    'not an object': 42,
    null: null,
    'no response': edit((c) => delete c.response),
    'wrong type': edit((c) => (c.type = 'password')),
    'rawId differs': edit((c) => (c.rawId = b64url(crypto.randomBytes(32)))),
    'id not a string': edit((c) => (c.id = 7)),
    'id too long': edit((c) => (c.id = c.rawId = pad(LIMITS.id + 4))),
    'clientDataJSON too long': edit((c) => (c.response.clientDataJSON = pad(LIMITS.clientDataJSON + 4))),
    'authenticatorData too long': edit((c) => (c.response.authenticatorData = pad(LIMITS.authenticatorData + 4))),
    'signature too long': edit((c) => (c.response.signature = pad(LIMITS.signature + 4))),
    'userHandle too long': edit((c) => (c.response.userHandle = pad(LIMITS.userHandle + 4))),
    'userHandle not a string': edit((c) => (c.response.userHandle = 5)),
    'padded base64': edit((c) => (c.response.signature += '==')),
    'plain base64': edit((c) => (c.response.clientDataJSON = Buffer.from(Buffer.from(c.response.clientDataJSON, 'base64url')).toString('base64').replace(/=+$/, '') + '+/')),
    'leftover bits': edit((c) => (c.response.signature = 'AB')),
    'one character': edit((c) => (c.response.signature = 'A')),
    'empty signature': edit((c) => (c.response.signature = '')),
    'spaces': edit((c) => (c.response.authenticatorData = ` ${c.response.authenticatorData}`)),
    'clientDataJSON not JSON': edit((c) => (c.response.clientDataJSON = b64url(Buffer.from('not json')))),
    'clientDataJSON an array': edit((c) => (c.response.clientDataJSON = b64url(Buffer.from('[]')))),
    'short authenticatorData': edit((c) => (c.response.authenticatorData = b64url(crypto.randomBytes(10)))),
  };
  for (const [what, response] of Object.entries(bad)) assert.deepEqual(await ctx.pk.verify('alice', response, challenge), { ok: false }, what);
  // The good one still passes: nothing above used the challenge up (the caller does that).
  assert.equal((await ctx.pk.verify('alice', good, challenge)).ok, true);
  // Extra fields are dropped, not passed on.
  const copy = readCredential({ ...good, extra: 1, response: { ...good.response, extra: 2 }, clientExtensionResults: { appid: true } }, 'get');
  assert.deepEqual(Object.keys(copy).sort(), ['clientExtensionResults', 'id', 'rawId', 'response', 'type']);
  assert.deepEqual(copy.clientExtensionResults, {});
  assert.deepEqual(Object.keys(copy.response).sort(), ['authenticatorData', 'clientDataJSON', 'signature']);
  // Transports are a hint: unknown ones are left out.
  const made = readCredential({ id: 'AAAA', rawId: 'AAAA', type: 'public-key', response: { clientDataJSON: 'AAAA', attestationObject: 'AAAA', transports: ['usb', 'warp', 7, 'usb', 'nfc'] } }, 'create');
  assert.deepEqual(made.response.transports, ['nfc', 'usb']);
  assert.equal(readCredential({ id: 'AAAA', rawId: 'AAAA', type: 'public-key', response: { clientDataJSON: 'AAAA', attestationObject: pad(LIMITS.attestationObject + 4) } }, 'create'), null);
  ctx.store.close();
});

test('passkeys: only \'none\' attestation, or \'packed\' signed by the key itself, is taken; certificates are refused before the library reads them', async () => {
  const ctx = await setup();
  const fetches = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (...args) => {
    fetches.push(args);
    throw new Error('no network in tests');
  };
  try {
    const attempt = async (fmt, opts = {}) => {
      const o = await ctx.pk.registrationOptions('alice', { sessionId: 's1', epoch: 0 });
      const a = new SoftAuthenticator({ alg: opts.alg ?? -7 });
      return code(() => ctx.pk.finishRegistration('alice', a.create({ challenge: o.challenge, origin: ctx.origin, rpId: ctx.rpId, fmt, ...opts }), { sessionId: 's1', epoch: 0 }));
    };
    assert.equal(await attempt('packed-x5c'), 'attestation');
    assert.equal(await attempt('packed-ecdaa'), 'attestation');
    for (const fmt of ['fido-u2f', 'tpm', 'android-key', 'android-safetynet', 'apple', 'made-up']) assert.equal(await attempt(fmt), 'attestation', fmt);
    // A packed statement must name the key's own algorithm, and be signed by it.
    assert.equal(await attempt('packed', { statementAlg: -257 }), 'invalid');
    // An attestation object that is not CBOR is a throw from the library's decoder: invalid.
    const o = await ctx.pk.registrationOptions('alice', { sessionId: 's1', epoch: 0 });
    const a = new SoftAuthenticator();
    const c = a.create({ challenge: o.challenge, origin: ctx.origin, rpId: ctx.rpId });
    c.response.attestationObject = b64url(Buffer.from([0xff, 0x00, 0x13]));
    assert.equal(await code(() => ctx.pk.finishRegistration('alice', c, { sessionId: 's1', epoch: 0 })), 'invalid');
    // A 'none' statement that is not empty.
    const o2 = await ctx.pk.registrationOptions('alice', { sessionId: 's1', epoch: 0 });
    const c2 = a.create({ challenge: o2.challenge, origin: ctx.origin, rpId: ctx.rpId });
    const authData = Buffer.from(fromB64url(c2.response.attestationObject).subarray(-a.authData({ rpId: RP_ID, attested: true }).length));
    c2.response.attestationObject = b64url(cbor(new Map([['fmt', 'none'], ['attStmt', new Map([['sig', Buffer.alloc(8)]])], ['authData', authData]])));
    assert.equal(await code(() => ctx.pk.finishRegistration('alice', c2, { sessionId: 's1', epoch: 0 })), 'invalid');
    assert.deepEqual(ctx.store.passkeys('alice'), []);
    // The good kinds still go in.
    for (const fmt of ['none', 'packed']) assert.equal((await register(ctx, 'alice', { fmt })).done.record.rpId, RP_ID);
  } finally {
    globalThis.fetch = realFetch;
  }
  assert.deepEqual(fetches, [], 'the library never fetched anything');
  ctx.store.close();
});

test('passkeys: registrations with the wrong origin, rpId, flags, algorithm or id are refused, and nothing is stored', async () => {
  const ctx = await setup();
  const bad = {
    'wrong origin': { origin: 'https://evil.example.org' },
    'wrong rpId hash': { rpId: 'evil.example.org' },
    'user verification off': { uv: false },
    'user presence off': { up: false },
    'cross-origin frame': { crossOrigin: true },
    'top origin': { extra: { topOrigin: ORIGIN } },
    'sign-in type': { type: 'webauthn.get' },
    'ES384 is not allowed': { alg: -35 },
    'another challenge': { challenge: b64url(crypto.randomBytes(32)) },
    'id in authData differs': { idBytes: crypto.randomBytes(32) },
    'id over 512 bytes': { id: crypto.randomBytes(513) },
    'public key not COSE': { cose: Buffer.from([0xa0]) },
  };
  for (const [what, opts] of Object.entries(bad)) {
    const o = await ctx.pk.registrationOptions('alice', { sessionId: 's1', epoch: 0 });
    const a = new SoftAuthenticator({ alg: opts.alg ?? -7, ...(opts.id ? { id: opts.id } : {}) });
    const response = a.create({ challenge: o.challenge, origin: ctx.origin, rpId: ctx.rpId, ...opts });
    assert.equal(await code(() => ctx.pk.finishRegistration('alice', response, { sessionId: 's1', epoch: 0 })), 'invalid', what);
  }
  assert.deepEqual(ctx.store.passkeys('alice'), []);
  assert.equal(ctx.store.secondFactorEnabled('alice'), false);
  ctx.store.close();
});

test('passkeys: a registration challenge is single use, short lived, and only good for its session, user and epoch', async () => {
  const ctx = await setup();
  const a = new SoftAuthenticator();
  const finish = (name, challenge, opts) => ctx.pk.finishRegistration(name, a.create({ challenge, origin: ctx.origin, rpId: ctx.rpId }), opts);
  // Replayed: the first try used it up, whatever its result.
  let o = await ctx.pk.registrationOptions('alice', { sessionId: 's1', epoch: 3 });
  assert.equal(await code(() => ctx.pk.finishRegistration('alice', { junk: true }, { sessionId: 's1', epoch: 3 })), 'invalid');
  assert.equal(await code(() => finish('alice', o.challenge, { sessionId: 's1', epoch: 3 })), 'expired');
  // Another session, user or epoch.
  o = await ctx.pk.registrationOptions('alice', { sessionId: 's1', epoch: 3 });
  assert.equal(await code(() => finish('alice', o.challenge, { sessionId: 's2', epoch: 3 })), 'expired');
  o = await ctx.pk.registrationOptions('alice', { sessionId: 's1', epoch: 3 });
  assert.equal(await code(() => finish('bob', o.challenge, { sessionId: 's1', epoch: 3 })), 'expired');
  o = await ctx.pk.registrationOptions('alice', { sessionId: 's1', epoch: 3 });
  assert.equal(await code(() => finish('alice', o.challenge, { sessionId: 's1', epoch: 4 })), 'expired');
  assert.equal(await code(() => finish('alice', o.challenge, { sessionId: 's1', epoch: 3 })), 'expired', 'the wrong epoch used it up');
  assert.equal(await code(() => finish('alice', o.challenge, { epoch: 3 })), 'expired');
  // Too old.
  o = await ctx.pk.registrationOptions('alice', { sessionId: 's1', epoch: 3 });
  ctx.clock.t += CHALLENGE_MS;
  assert.equal(await code(() => finish('alice', o.challenge, { sessionId: 's1', epoch: 3 })), 'expired');
  // Just in time, and the name is not case sensitive.
  o = await ctx.pk.registrationOptions('alice', { sessionId: 's1', epoch: 3 });
  ctx.clock.t += CHALLENGE_MS - 1;
  assert.equal((await finish('Alice', o.challenge, { sessionId: 's1', epoch: 3 })).first, true);
  // A newer challenge for the session replaces the older one: an answer to the older one does not
  // match it, and uses it up.
  const b = new SoftAuthenticator();
  const o1 = await ctx.pk.registrationOptions('alice', { sessionId: 's1', epoch: 3 });
  const o2 = await ctx.pk.registrationOptions('alice', { sessionId: 's1', epoch: 3 });
  assert.equal(await code(() => ctx.pk.finishRegistration('alice', b.create({ challenge: o1.challenge, origin: ctx.origin, rpId: ctx.rpId }), { sessionId: 's1', epoch: 3 })), 'invalid');
  assert.equal(await code(() => ctx.pk.finishRegistration('alice', b.create({ challenge: o2.challenge, origin: ctx.origin, rpId: ctx.rpId }), { sessionId: 's1', epoch: 3 })), 'expired');
  // dropSession and dropUser take challenges away.
  o = await ctx.pk.registrationOptions('alice', { sessionId: 's1', epoch: 3 });
  ctx.pk.dropSession('s1');
  assert.equal(await code(() => finish('alice', o.challenge, { sessionId: 's1', epoch: 3 })), 'expired');
  o = await ctx.pk.registrationOptions('alice', { sessionId: 's1', epoch: 3 });
  await ctx.pk.registrationOptions('bob', { sessionId: 's2', epoch: 0 });
  ctx.pk.dropUser('ALICE');
  assert.equal(ctx.pk.challengeCount, 1);
  assert.equal(await code(() => finish('alice', o.challenge, { sessionId: 's1', epoch: 3 })), 'expired');
  ctx.store.close();
});

test('passkeys: names are checked before the challenge is used; at most MAX_PASSKEYS per user', async () => {
  const ctx = await setup();
  assert.equal(passkeyName('  Phone '), 'Phone');
  assert.equal(passkeyName('x'.repeat(64)), 'x'.repeat(64));
  assert.equal(passkeyName('\u{1f511}'.repeat(64)), '\u{1f511}'.repeat(64));
  for (const bad of ['', '   ', 'x'.repeat(65), 'a\nb', 'a\u0000b', 'a\u202eb', 'a\u2028b', 'a\u2066b', 7, null]) {
    assert.equal(passkeyName(bad), null, JSON.stringify(bad));
  }
  // Every name taken here is one the store keeps.
  for (const ok of ['Phone', 'x'.repeat(64), '\u{1f511}'.repeat(64), '\u041a\u043b\u044e\u0447']) assert.ok(goodPasskeyName(passkeyName(ok)));

  const a = new SoftAuthenticator();
  const o = await ctx.pk.registrationOptions('alice', { sessionId: 's1', epoch: 0 });
  const response = a.create({ challenge: o.challenge, origin: ctx.origin, rpId: ctx.rpId });
  assert.equal(await code(() => ctx.pk.finishRegistration('alice', response, { sessionId: 's1', epoch: 0, label: 'x'.repeat(65) })), 'name');
  assert.equal(await code(() => ctx.pk.finishRegistration('alice', response, { sessionId: 's1', epoch: 0, label: 42 })), 'name');
  assert.equal((await ctx.pk.finishRegistration('alice', response, { sessionId: 's1', epoch: 0, label: 'Phone' })).record.name, 'Phone');
  // Added twice: the second is refused.
  const o2 = await ctx.pk.registrationOptions('alice', { sessionId: 's1', epoch: 0 });
  assert.equal(await code(() => ctx.pk.finishRegistration('alice', a.create({ challenge: o2.challenge, origin: ctx.origin, rpId: ctx.rpId }), { sessionId: 's1', epoch: 0 })), 'duplicate');

  for (let i = 1; i < MAX_PASSKEYS; i++) await register(ctx, 'alice');
  assert.equal(ctx.store.passkeys('alice').length, MAX_PASSKEYS);
  assert.equal(await code(() => ctx.pk.registrationOptions('alice', { sessionId: 's1', epoch: 0 })), 'full');
  // Full by the time the answer comes (another tab added one meanwhile).
  ctx.clock.t += 1;
  const store2 = ctx.store;
  const removed = store2.passkeys('alice')[0].ref;
  await store2.removePasskey('alice', removed);
  const o3 = await ctx.pk.registrationOptions('alice', { sessionId: 's1', epoch: 0 });
  await register(ctx, 'alice', { session: 's9' });
  const late = new SoftAuthenticator();
  assert.equal(await code(() => ctx.pk.finishRegistration('alice', late.create({ challenge: o3.challenge, origin: ctx.origin, rpId: ctx.rpId }), { sessionId: 's1', epoch: 0 })), 'full');
  ctx.store.close();
});

test('passkeys: step-up challenges are kept per session, single use, short lived and for one user', async () => {
  const ctx = await setup();
  assert.equal(ctx.pk.stepUpOptions('alice', 's1'), null, 'no passkey yet');
  const { a } = await register(ctx, 'alice', { counter: 1 });
  assert.equal(ctx.pk.stepUpOptions('alice', ''), null);
  const run = (session, opts, name = 'alice') => ctx.pk.verifyStepUp(name, session, a.get({ challenge: opts.challenge, origin: ctx.origin, rpId: ctx.rpId }));

  let o = ctx.pk.stepUpOptions('alice', 's1');
  assert.deepEqual(o, { challenge: o.challenge, rpId: RP_ID, allowCredentials: [{ id: a.id, type: 'public-key', transports: ['hybrid', 'internal'] }], timeout: TIMEOUT_MS, userVerification: 'required' });
  const ok = await run('s1', o);
  assert.equal(ok.ok, true);
  assert.equal(ok.ref, storeRef(a.id));
  await ok.saved;
  assert.deepEqual(await run('s1', o), { ok: false, expired: true }, 'replayed');
  o = ctx.pk.stepUpOptions('alice', 's1');
  assert.deepEqual(await run('s2', o), { ok: false, expired: true }, 'another session');
  assert.equal((await run('s1', o)).ok, true, 'the session\'s own challenge is still there');
  o = ctx.pk.stepUpOptions('alice', 's1');
  assert.deepEqual(await run('s1', o, 'bob'), { ok: false, expired: true }, 'another user');
  assert.deepEqual(await run('s1', o), { ok: false, expired: true }, 'the try as another user used it up');
  o = ctx.pk.stepUpOptions('alice', 's1');
  ctx.clock.t += CHALLENGE_MS;
  assert.deepEqual(await run('s1', o), { ok: false, expired: true }, 'too old');
  // A wrong answer uses it up too.
  o = ctx.pk.stepUpOptions('alice', 's1');
  assert.deepEqual(await ctx.pk.verifyStepUp('alice', 's1', '{'), { ok: false });
  assert.deepEqual(await run('s1', o), { ok: false, expired: true });
  // A registration and a step-up challenge of one session are kept apart.
  o = ctx.pk.stepUpOptions('alice', 's1');
  const r = await ctx.pk.registrationOptions('alice', { sessionId: 's1', epoch: 0 });
  assert.deepEqual(await ctx.pk.verifyStepUp('alice', 's1', a.get({ challenge: r.challenge, origin: ctx.origin, rpId: ctx.rpId })), { ok: false });
  ctx.pk.stepUpOptions('alice', 's1');
  ctx.pk.dropSession('s1');
  assert.equal(ctx.pk.challengeCount, 0);
  o = ctx.pk.stepUpOptions('alice', 's1');
  ctx.pk.dropUser('alice');
  assert.deepEqual(await run('s1', o), { ok: false, expired: true });
  ctx.store.close();
});

test('passkeys: the challenge store is bounded; the oldest go first, and old ones are swept', async () => {
  const records = [{ id: 'AAAA', ref: 'r1', rpId: RP_ID, transports: [] }];
  const store = { passkeys: () => [{ ref: 'r1' }], passkeyByRef: () => records[0] };
  const clock = { t: NOW };
  const pk = createPasskeys({ siteUrl: ORIGIN, store, now: () => clock.t });
  const first = pk.stepUpOptions('alice', 'session-0');
  for (let i = 1; i < MAX_CHALLENGES; i++) pk.stepUpOptions('alice', `session-${i}`);
  assert.equal(pk.challengeCount, MAX_CHALLENGES);
  pk.stepUpOptions('alice', 'one-more');
  assert.equal(pk.challengeCount, MAX_CHALLENGES);
  assert.deepEqual(await pk.verifyStepUp('alice', 'session-0', { challenge: first.challenge }), { ok: false, expired: true }, 'the oldest went');
  clock.t += CHALLENGE_MS;
  pk.stepUpOptions('alice', 'later');
  assert.equal(pk.challengeCount, 1, 'the old ones were swept');
});

test('passkeys: errors and results never hold what the browser sent', async () => {
  const ctx = await setup();
  const seen = [];
  const keep = (err) => {
    seen.push(err);
    return true;
  };
  const a = new SoftAuthenticator();
  for (const opts of [{ origin: 'https://evil.example.org' }, { fmt: 'packed-x5c' }, { uv: false }]) {
    const o = await ctx.pk.registrationOptions('alice', { sessionId: 's1', epoch: 0 });
    const response = a.create({ challenge: o.challenge, origin: ctx.origin, rpId: ctx.rpId, ...opts });
    await assert.rejects(ctx.pk.finishRegistration('alice', response, { sessionId: 's1', epoch: 0 }), keep);
    for (const err of seen) {
      for (const secret of [o.challenge, a.id, response.response.attestationObject, response.response.clientDataJSON, 'evil']) assert.ok(!err.message.includes(secret), err.message);
      assert.equal(err.cause, undefined);
    }
  }
  const { challenge } = ctx.pk.loginOptions('alice') ?? { challenge: 'Y2hhbGxlbmdl' };
  const v = await ctx.pk.verify('alice', a.get({ challenge, origin: 'https://evil.example.org', rpId: ctx.rpId }), challenge);
  assert.deepEqual(v, { ok: false });
  assert.deepEqual(Object.keys(new PasskeyError('invalid')).sort(), ['code']);
  ctx.store.close();
});

test('passkeys: the library is pinned exactly, at 14.1.0 or later, and only lib/passkeys.js imports it', async () => {
  const pkg = JSON.parse(await fs.readFile(path.join(ROOT, 'package.json'), 'utf8'));
  const pin = pkg.dependencies['@simplewebauthn/server'];
  assert.match(pin, /^\d+\.\d+\.\d+$/, 'an exact version, without ^ or ~');
  const [major, minor] = pin.split('.').map(Number);
  assert.ok(major > 14 || (major === 14 && minor >= 1), `${pin} is 14.1.0 or later`);
  const lock = JSON.parse(await fs.readFile(path.join(ROOT, 'package-lock.json'), 'utf8'));
  assert.equal(lock.packages['node_modules/@simplewebauthn/server'].version, pin);
  assert.equal(lock.packages[''].dependencies['@simplewebauthn/server'], pin);
  const importers = [];
  const walk = async (dir) => {
    for (const e of await fs.readdir(path.join(ROOT, dir), { withFileTypes: true })) {
      const rel = path.join(dir, e.name);
      if (e.isDirectory()) await walk(rel);
      else if (/\.(js|mjs|cjs)$/.test(e.name) && (await fs.readFile(path.join(ROOT, rel), 'utf8')).includes('@simplewebauthn')) importers.push(rel);
    }
  };
  for (const dir of ['lib', 'scripts', 'public']) await walk(dir);
  if ((await fs.readFile(path.join(ROOT, 'server.js'), 'utf8')).includes('@simplewebauthn')) importers.push('server.js');
  assert.deepEqual(importers, [path.join('lib', 'passkeys.js')]);
});

test('passkeys: a registration is taken as the browser\'s own toJSON() gives it, or as built by hand; extra fields and unknown transports are left out', async () => {
  const ctx = await setup();
  const shapes = {
    // What PublicKeyCredential.toJSON() gives: also the public key (SPKI), the authenticator data and
    // the algorithm, which the server does not use; it reads them from the attestation object.
    native: (a, c) => ({
      ...c,
      response: { ...c.response, publicKey: a.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url'), publicKeyAlgorithm: a.alg, authenticatorData: b64url(crypto.randomBytes(200)), transports: ['internal', 'hybrid'] },
      authenticatorAttachment: 'platform',
      clientExtensionResults: { credProps: { rk: true } },
    }),
    manual: (a, c) => ({ id: c.id, rawId: c.rawId, type: c.type, clientExtensionResults: {}, authenticatorAttachment: 'cross-platform', response: { clientDataJSON: c.response.clientDataJSON, attestationObject: c.response.attestationObject, transports: ['usb'] } }),
    'no transports': (a, c) => ({ ...c, response: { clientDataJSON: c.response.clientDataJSON, attestationObject: c.response.attestationObject } }),
    'odd transports': (a, c) => ({ ...c, response: { ...c.response, transports: ['usb', 'smoke-signal', { x: 1 }, 'nfc', 'usb'] } }),
    'transports not a list': (a, c) => ({ ...c, response: { ...c.response, transports: 'usb' } }),
    'as JSON text': (a, c) => JSON.stringify(c),
  };
  const want = { native: ['hybrid', 'internal'], manual: ['usb'], 'no transports': [], 'odd transports': ['nfc', 'usb'], 'transports not a list': [], 'as JSON text': ['hybrid', 'internal'] };
  for (const [what, shape] of Object.entries(shapes)) {
    const a = new SoftAuthenticator({ alg: what === 'manual' ? -8 : -7 });
    const o = await ctx.pk.registrationOptions('alice', { sessionId: 's1', epoch: 0 });
    const { record } = await ctx.pk.finishRegistration('alice', shape(a, a.create({ challenge: o.challenge, origin: ctx.origin, rpId: ctx.rpId })), { sessionId: 's1', epoch: 0 });
    assert.deepEqual(record.transports, want[what], what);
    assert.equal(record.publicKey, a.cose.toString('base64url'), what);
    // And it signs in, with the browser's toJSON() shape of an assertion too.
    const s = assertion(ctx, a, 'alice');
    const native = { ...s.response, authenticatorAttachment: 'platform', clientExtensionResults: { appid: false } };
    assert.equal((await ctx.pk.verify('alice', native, s.challenge)).ok, true, what);
  }
  // Extra fields are ignored, but the fields that are read still have their types and sizes checked.
  const a = new SoftAuthenticator();
  for (const broken of [(c) => (c.response.attestationObject = 7), (c) => (c.response.clientDataJSON = 'A'.repeat(LIMITS.clientDataJSON + 4)), (c) => (c.response.attestationObject = `${c.response.attestationObject}=`)]) {
    const o = await ctx.pk.registrationOptions('alice', { sessionId: 's1', epoch: 0 });
    const c = shapes.native(a, a.create({ challenge: o.challenge, origin: ctx.origin, rpId: ctx.rpId }));
    broken(c);
    assert.equal(await code(() => ctx.pk.finishRegistration('alice', c, { sessionId: 's1', epoch: 0 })), 'invalid');
  }
  ctx.store.close();
});

test('passkeys: the user handle is only read when a sign in is checked; a user without one cannot send one', async () => {
  const ctx = await setup();
  const { a } = await register(ctx, 'alice');
  const handle = ctx.store.passkeyUserId('alice');
  assert.match(handle, /^[A-Za-z0-9_-]{43}$/);
  // Nothing may be written before the signature is checked.
  const ensure = ctx.store.ensurePasskeyUserId;
  ctx.store.ensurePasskeyUserId = () => assert.fail('verify must not write the user handle');
  try {
    let { challenge, response } = assertion(ctx, a, 'alice', { userHandle: handle });
    assert.equal((await ctx.pk.verify('alice', response, challenge)).ok, true);
    ({ challenge, response } = assertion(ctx, a, 'alice', { userHandle: b64url(crypto.randomBytes(32)) }));
    assert.deepEqual(await ctx.pk.verify('alice', response, challenge), { ok: false });
    // No handle kept (as if it were lost): one sent is refused, none sent is fine.
    const kept = ctx.store.passkeyUserId;
    ctx.store.passkeyUserId = () => null;
    ({ challenge, response } = assertion(ctx, a, 'alice', { userHandle: handle }));
    assert.deepEqual(await ctx.pk.verify('alice', response, challenge), { ok: false });
    ({ challenge, response } = assertion(ctx, a, 'alice'));
    assert.equal((await ctx.pk.verify('alice', response, challenge)).ok, true);
    ctx.store.passkeyUserId = kept;
  } finally {
    ctx.store.ensurePasskeyUserId = ensure;
  }
  ctx.store.close();
});

test('passkeys: one rule for names: no lone surrogates, zero-width or bidi characters, or long runs of marks, on add and rename; a name it refuses in the database is read as "Passkey N"', async () => {
  const bad = ['a\ud800b', 'a\udc00', 'a\u200bb', 'a\u200cb', 'a\u200db', 'a\u2060b', 'a\ufeffb', 'a\u061cb', 'a\u200eb', 'a\u200fb', 'a\u202ab', 'a\u2069b', `e${'\u0301'.repeat(4)}`, 'a\u2028b', 'a\u0085b'];
  for (const name of bad) {
    assert.equal(passkeyName(name), null, JSON.stringify(name));
    assert.equal(passkeyLabel(name), null, JSON.stringify(name));
    assert.equal(goodPasskeyName(name), false, JSON.stringify(name));
  }
  for (const ok of [`e${'\u0301'.repeat(3)}`, 'Caf\u00e9', '\u{1f511} key', 'Schl\u00fcssel']) assert.equal(passkeyName(ok), ok);
  // passkeys.js and users.js share it.
  assert.equal(passkeyName, passkeyLabel);

  const ctx = await setup();
  const { done } = await register(ctx, 'alice', { label: 'Phone' });
  for (const name of ['a\u200bb', 'a\ud800b', 'a\u200eb']) {
    await assert.rejects(ctx.store.renamePasskey('alice', done.ref, name), (e) => e.code === 'bad-label', JSON.stringify(name));
    await assert.rejects(ctx.store.addPasskey('alice', { ...done.record, id: b64url(crypto.randomBytes(32)), name }), (e) => e.code === 'bad-label', JSON.stringify(name));
    const o = await ctx.pk.registrationOptions('alice', { sessionId: 'n', epoch: 0 });
    assert.equal(await code(() => ctx.pk.finishRegistration('alice', new SoftAuthenticator().create({ challenge: o.challenge, origin: ctx.origin, rpId: ctx.rpId }), { sessionId: 'n', epoch: 0, label: name })), 'name');
  }
  const second = (await register(ctx, 'alice', { label: 'Laptop' })).done;
  const third = (await register(ctx, 'alice', { label: 'Key' })).done;
  ctx.store.close();
  // A name the rule refuses, put into the database by something else (or saved under a looser rule
  // before), is read as "Passkey N" by its place, and the store opens all the same; so is a name too
  // long to read.
  const sql = new DatabaseSync(path.join(ctx.dataDir, DB_FILE));
  const ids = sql.prepare('SELECT id FROM credentials ORDER BY id').all().map((r) => r.id);
  sql.prepare('UPDATE credentials SET name = ? WHERE id = ?').run('a\u200bb', ids[0]);
  sql.prepare('UPDATE credentials SET name = ? WHERE id = ?').run('x'.repeat(5000), ids[2]);
  sql.close();
  const store = await UserStore.open({ dataDir: ctx.dataDir, keys: KEYS, warn: () => {} });
  assert.deepEqual(store.passkeys('alice').map((k) => k.name), ['Passkey 1', 'Laptop', 'Passkey 3']);
  assert.ok(store.passkeyByRef('alice', done.ref), 'the passkey itself is kept');
  // The next change of the user writes the names as read.
  await store.renamePasskey('alice', second.ref, 'Old laptop');
  store.close();
  const after = new DatabaseSync(path.join(ctx.dataDir, DB_FILE));
  assert.deepEqual(after.prepare('SELECT name FROM credentials ORDER BY id').all().map((r) => r.name), ['Passkey 1', 'Old laptop', 'Passkey 3']);
  after.close();
  assert.ok(third.ref);
});

// The 8 Ed25519 points of small order (canonical encodings), and encodings that are not canonical.
const ED_SMALL_ORDER = [
  '0100000000000000000000000000000000000000000000000000000000000000',
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  '0000000000000000000000000000000000000000000000000000000000000000',
  '0000000000000000000000000000000000000000000000000000000000000080',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85',
];
const ED_NOT_CANONICAL = [
  '0100000000000000000000000000000000000000000000000000000000000080',
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
  'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
];

test('passkeys: an Ed25519 key of small order, or not encoded the one way, is refused; real keys are taken', () => {
  for (const h of [...ED_SMALL_ORDER, ...ED_NOT_CANONICAL]) assert.equal(goodEd25519(Buffer.from(h, 'hex')), false, h);
  for (let i = 0; i < 50; i++) {
    const x = Buffer.from(crypto.generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' }).x, 'base64url');
    assert.equal(goodEd25519(x), true, x.toString('hex'));
  }
  assert.equal(goodEd25519(Buffer.alloc(31)), false);
});

test('passkeys: a key must be what its algorithm says, on its curve, and RSA of at least 2048 bits', async () => {
  const gen = (type, opts) => crypto.generateKeyPairSync(type, opts).publicKey;
  const p256 = gen('ec', { namedCurve: 'P-256' });
  const good = coseKey(p256, -7);
  assert.equal(keyAlg(good), -7);
  assert.equal(keyAlg(coseKey(gen('ed25519', {}), -8)), -8);
  assert.equal(keyAlg(coseKey(gen('rsa', { modulusLength: 2048 }), -257)), -257);
  assert.equal(MIN_RSA_BITS, 2048);
  const jwk = p256.export({ format: 'jwk' });
  const raw = (v) => Buffer.from(v, 'base64url');
  const offCurve = Buffer.from(raw(jwk.y));
  offCurve[31] ^= 1;
  const ed = gen('ed25519', {}).export({ format: 'jwk' });
  const p384 = gen('ec', { namedCurve: 'P-384' }).export({ format: 'jwk' });
  const rsa1024 = gen('rsa', { modulusLength: 1024 });
  const rsaN = raw(gen('rsa', { modulusLength: 2048 }).export({ format: 'jwk' }).n);
  const rsaWith = (e) => cbor(new Map([[1, 3], [3, -257], [-1, rsaN], [-2, Buffer.from(e)]]));
  assert.equal(keyAlg(rsaWith([1, 0, 1])), -257);
  const edKey = (h) => cbor(new Map([[1, 1], [3, -8], [-1, 6], [-2, Buffer.from(h, 'hex')]]));
  const wrong = {
    'a point off the curve': cbor(new Map([[1, 2], [3, -7], [-1, 1], [-2, raw(jwk.x)], [-3, offCurve]])),
    'ES256 named, an OKP key': cbor(new Map([[1, 1], [3, -7], [-1, 6], [-2, raw(ed.x)]])),
    'ES256 named, a P-384 key': cbor(new Map([[1, 2], [3, -7], [-1, 2], [-2, raw(p384.x)], [-3, raw(p384.y)]])),
    'ES256 named, the wrong kty': cbor(new Map([[1, 3], [3, -7], [-1, 1], [-2, raw(jwk.x)], [-3, raw(jwk.y)]])),
    'EdDSA named, an EC2 key': cbor(new Map([[1, 2], [3, -8], [-1, 1], [-2, raw(jwk.x)], [-3, raw(jwk.y)]])),
    'EdDSA named, Ed448': cbor(new Map([[1, 1], [3, -8], [-1, 7], [-2, crypto.randomBytes(57)]])),
    'RS256 of 1024 bits': coseKey(rsa1024, -257),
    'RS256 with the exponent 3': rsaWith([3]),
    'RS256 with the exponent 65537 and a leading zero': rsaWith([0, 1, 0, 1]),
    'RS256 with the exponent 65539': rsaWith([1, 0, 3]),
    'RS256 with the exponent 2^64 + 1': rsaWith([1, 0, 0, 0, 0, 0, 0, 0, 1]),
    ...Object.fromEntries(ED_SMALL_ORDER.map((h) => [`EdDSA of small order ${h}`, edKey(h)])),
    ...Object.fromEntries(ED_NOT_CANONICAL.map((h) => [`EdDSA not canonical ${h}`, edKey(h)])),
    'RS256 named, an EC2 key': cbor(new Map([[1, 2], [3, -257], [-1, 1], [-2, raw(jwk.x)], [-3, raw(jwk.y)]])),
    'no key at all': cbor(new Map([[1, 2], [3, -7]])),
  };
  for (const [what, cose] of Object.entries(wrong)) assert.equal(keyAlg(cose), null, what);

  // Refused when the passkey is added, through the library and all.
  const ctx = await setup();
  for (const [what, cose] of Object.entries(wrong)) {
    const alg = what.startsWith('RS256 ') ? -257 : what.startsWith('EdDSA ') ? -8 : -7;
    const o = await ctx.pk.registrationOptions('alice', { sessionId: 'k', epoch: 0 });
    const a = new SoftAuthenticator({ alg });
    assert.equal(await code(() => ctx.pk.finishRegistration('alice', a.create({ challenge: o.challenge, origin: ctx.origin, rpId: ctx.rpId, cose }), { sessionId: 'k', epoch: 0 })), 'invalid', what);
  }
  assert.deepEqual(ctx.store.passkeys('alice'), []);
  ctx.store.close();
});

test('passkeys: why passkeys are off is said for the operator', () => {
  assert.equal(passkeyOriginProblem('https://status.example.org'), null);
  assert.equal(passkeyOriginProblem('http://localhost:8080'), null);
  assert.match(passkeyOriginProblem(null), /https address is not set/);
  assert.match(passkeyOriginProblem(''), /https address is not set/);
  assert.match(passkeyOriginProblem('https://192.0.2.1'), /is an IP address; passkeys need a host name/);
  assert.match(passkeyOriginProblem('https://[2001:db8::1]:8443'), /is an IP address/);
  assert.match(passkeyOriginProblem('http://status.example.org'), /is not https/);
  assert.match(passkeyOriginProblem('https://status.example.org.'), /ends with a dot/);
  assert.match(passkeyOriginProblem('not a url'), /is not a URL/);
  for (const u of ['https://192.0.2.1', 'http://status.example.org']) assert.equal(passkeyOriginProblem(u).includes(u), false);
});
