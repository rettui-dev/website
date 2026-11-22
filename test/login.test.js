import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { Keyring } from '../lib/keys.js';
import { Busy, CODE_MAX_WAIT_MS, CODE_USER_FREE, DEVICE_AUDIT_MS, DEVICE_BURST, DEVICE_INTERVAL_MS, MAX_QUEUED_HASHES, NAME_BACKLOG, NAME_BURST, NAME_INTERVAL_MS, NET48_FREE, NET56_FREE, NameBucket, Sessions, Throttle, clientIp, cookieValue, createLogin, deviceHash, hashGate, ipKey, isFormType, netKeys, newDeviceId, normalIp, proxyMatcher, sameOrigin, untrustedProxy, viaHttps, waitText } from '../lib/login.js';
import { DEFAULTS, hashPassword, parsePhc } from '../lib/password.js';
import { LOGIN_WRITE_MS, MAX_DEVICES, MAX_PASSKEY_DEVICES, UserStore } from '../lib/users.js';
import { ACTION_WINDOW_MS, REAUTHS_PER_SESSION, REAUTHS_PER_USER, needsPassword } from '../lib/account.js';
import { fakeHasher } from './helpers/fake-hasher.js';
import { DEVICE_USER_CEILING, LOGIN_DEFAULTS, MAX_PASSKEY_SESSIONS_PER_USER, PASSKEY_AUDIT_MS, PASSKEY_SIGNIN_BURST, PASSKEY_SIGNIN_INTERVAL_MS, SIGNIN_BEGIN_BURST, SIGNIN_BEGIN_INTERVAL_MS, SIGNIN_CHALLENGES_MAX, SIGNIN_CHALLENGES_PER_ADDRESS, SIGNIN_NET48_BURST, SIGNIN_NET56_BURST, SIGNIN_NET56_INTERVAL_MS } from '../lib/login.js';
import { CHALLENGE_MS, NO_PASSKEYS, createPasskeys } from '../lib/passkeys.js';
import { SoftAuthenticator } from './helpers/soft-authenticator.js';

const MIN = 60_000;

test('sessions have a random 256-bit id and end when idle or too old', () => {
  let t = 0;
  const s = new Sessions({ idleMs: 10 * MIN, maxAgeMs: 30 * MIN, max: 10, now: () => t });
  const id = s.create('alice');
  assert.match(id, /^[A-Za-z0-9_-]{43}$/);
  assert.notEqual(s.create('alice'), id);
  assert.equal(s.get(id).name, 'alice');
  t += 9 * MIN;
  assert.equal(s.get(id).name, 'alice');
  t += 9 * MIN;
  // Used 9 minutes ago: still there, and kept alive by the use.
  assert.equal(s.get(id).name, 'alice');
  t += 10 * MIN;
  assert.equal(s.get(id), null, 'idle for 10 minutes');
  const b = s.create('bob');
  for (let i = 0; i < 6; i++) {
    t += 5 * MIN;
    assert.equal(s.get(b)?.name, i < 5 ? 'bob' : undefined, `after ${(i + 1) * 5} minutes`);
  }
});

test('sessions: bad ids, destroy, a clock that goes back, and the cap pushes out the least recently used', () => {
  let t = 1000;
  const s = new Sessions({ idleMs: MIN, maxAgeMs: 10 * MIN, max: 3, now: () => t });
  for (const bad of [undefined, null, '', 'x', 'a'.repeat(44), '../'.repeat(15)]) assert.equal(s.get(bad), null);
  const a = s.create('a');
  const b = s.create('b');
  const c = s.create('c');
  s.get(a);
  const d = s.create('d');
  assert.equal(s.size, 3);
  assert.equal(s.get(b), null, 'least recently used goes first');
  assert.ok(s.get(a) && s.get(c) && s.get(d));
  s.destroy(a);
  assert.equal(s.get(a), null);
  t = 0;
  assert.equal(s.get(c), null, 'created in the future');
  t = 1000 + 2 * MIN;
  s.sweep();
  assert.equal(s.size, 0);
});

test('throttle: free tries, then a doubling wait up to a cap, forgotten after a while', () => {
  let t = 0;
  const th = new Throttle({ free: 3, baseMs: 1000, maxMs: 8000, forgetMs: 60 * MIN, now: () => t });
  for (let i = 0; i < 3; i++) {
    assert.equal(th.wait('k'), 0);
    th.fail('k');
  }
  assert.equal(th.wait('k'), 0);
  th.fail('k');
  assert.equal(th.wait('k'), 1000);
  th.fail('k');
  assert.equal(th.wait('k'), 2000);
  th.fail('k');
  th.fail('k');
  th.fail('k');
  assert.equal(th.wait('k'), 8000, 'capped');
  assert.equal(th.wait('other'), 0);
  t += 8000;
  assert.equal(th.wait('k'), 0);
  th.clear('k');
  assert.equal(th.size, 0);
  th.fail('x');
  t += 61 * MIN;
  assert.equal(th.wait('x'), 0);
  assert.equal(th.size, 0, 'forgotten');
  // A failure long after the last one starts the count again.
  for (let i = 0; i < 4; i++) th.fail('y');
  t += 61 * MIN;
  th.fail('y');
  assert.equal(th.wait('y'), 0);
});

test('throttle memory is bounded', () => {
  const th = new Throttle({ maxEntries: 100 });
  for (let i = 0; i < 1000; i++) th.fail(`k${i}`);
  assert.equal(th.size, 100);
  assert.equal(th.wait('k0'), 0);
});

test('throttle: a full map never refuses a new key; it forgets the entry with the fewest failures, the oldest of those', () => {
  let t = 0;
  const th = new Throttle({ free: 1, baseMs: 1000, maxMs: 60_000, maxEntries: 3, now: () => t });
  // A locked key with many failures, then the map filled with keys that have fewer.
  for (let i = 0; i < 5; i++) th.fail('locked');
  assert.equal(th.wait('locked'), 8000);
  th.fail('a');
  th.fail('a');
  th.fail('b');
  assert.equal(th.size, 3);
  // A new key is never told to wait because the map is full.
  assert.equal(th.wait('new0'), 0);
  // It pushes out b (one failure), not a (two) nor the locked key.
  th.fail('new0');
  assert.deepEqual([...th.map.keys()].sort(), ['a', 'locked', 'new0']);
  // A flood of new keys only pushes out each other: the locked key stays locked.
  for (let i = 1; i < 100; i++) {
    assert.equal(th.wait(`new${i}`), 0);
    th.fail(`new${i}`);
  }
  assert.equal(th.size, 3);
  assert.equal(th.wait('locked'), 8000);
  assert.deepEqual([...th.map.keys()].sort(), ['a', 'locked', 'new99']);
  // A forgotten entry goes before any other, even one with fewer failures.
  t += 61 * MIN;
  th.fail('locked');
  th.fail('c');
  assert.equal(th.map.has('locked'), true);
  assert.equal(th.count('locked'), 1, 'counted from the start again, after an hour');
});

test('hashGate runs a few at once, queues a few and turns the rest away', async () => {
  const gate = hashGate(2, 1);
  const releases = [];
  const job = () => new Promise((r) => releases.push(r));
  const a = gate(job);
  const b = gate(job);
  const c = gate(job);
  await new Promise((r) => setImmediate(r));
  assert.deepEqual(gate.load(), { running: 2, waiting: 1, keys: 0 });
  await assert.rejects(gate(job), Busy);
  releases[0]('a');
  assert.equal(await a, 'a');
  await new Promise((r) => setImmediate(r));
  assert.deepEqual(gate.load(), { running: 2, waiting: 0, keys: 0 });
  releases[1]('b');
  releases[2]('c');
  assert.deepEqual([await b, await c], ['b', 'c']);
  // A job that fails frees its place too.
  await assert.rejects(gate(async () => { throw new Error('boom'); }), /boom/);
  assert.deepEqual(gate.load(), { running: 0, waiting: 0, keys: 0 });
});

test('hashGate: one key gets at most its share, running or waiting; other keys still get in', async () => {
  const gate = hashGate(1, 10, 2);
  const releases = [];
  const job = () => new Promise((r) => releases.push(r));
  const a1 = gate(job, 'ip:a');
  const a2 = gate(job, 'ip:a');
  await assert.rejects(gate(job, 'ip:a'), Busy);
  const b = gate(job, 'ip:b');
  await new Promise((r) => setImmediate(r));
  assert.deepEqual(gate.load(), { running: 1, waiting: 2, keys: 2 });
  releases[0]('a1');
  assert.equal(await a1, 'a1');
  // Its place is free again once a job of the key has settled.
  await new Promise((r) => setImmediate(r));
  const a3 = gate(job, 'ip:a');
  await new Promise((r) => setImmediate(r));
  releases[1]('a2');
  await new Promise((r) => setImmediate(r));
  releases[2]('b');
  await new Promise((r) => setImmediate(r));
  releases[3]('a3');
  assert.deepEqual([await a2, await b, await a3], ['a2', 'b', 'a3']);
  assert.deepEqual(gate.load(), { running: 0, waiting: 0, keys: 0 });
  // A job that fails gives its key's place back too.
  await assert.rejects(gate(async () => { throw new Error('boom'); }, 'ip:a'), /boom/);
  assert.equal(gate.load().keys, 0);
});

test('clientIp trusts X-Forwarded-For only from a trusted proxy', () => {
  const req = (remote, xff) => ({ socket: { remoteAddress: remote }, headers: xff === undefined ? {} : { 'x-forwarded-for': xff } });
  const none = new Set();
  const proxy = new Set(['10.0.0.1', '::1']);
  assert.equal(clientIp(req('::ffff:192.0.2.7', '203.0.113.9'), none), '192.0.2.7');
  assert.equal(clientIp(req('10.0.0.1', '203.0.113.9'), proxy), '203.0.113.9');
  assert.equal(clientIp(req('10.0.0.1', 'spoofed, 203.0.113.9'), proxy), '203.0.113.9');
  assert.equal(clientIp(req('10.0.0.1', '203.0.113.9, 10.0.0.1'), proxy), '203.0.113.9');
  assert.equal(clientIp(req('10.0.0.1', 'not-an-ip'), proxy), '10.0.0.1');
  assert.equal(clientIp(req('10.0.0.1'), proxy), '10.0.0.1');
  assert.equal(clientIp(req('::1', '2001:db8::1'), proxy), '2001:db8::1');
  assert.equal(clientIp({ socket: {}, headers: {} }, none), '');
  assert.equal(normalIp('::FFFF:127.0.0.1'), '127.0.0.1');
});

test('normalIp gives one spelling of an address, so trusted_proxies match however they are written', () => {
  const cases = [
    ['0:0:0:0:0:0:0:1', '::1'],
    ['::1', '::1'],
    ['0000:0000:0000:0000:0000:0000:0000:0001', '::1'],
    ['FD00::1', 'fd00::1'],
    ['fd00:0:0:0:0:0:0:1', 'fd00::1'],
    ['2001:DB8:0:0:1:0:0:1', '2001:db8::1:0:0:1'],
    ['2001:db8:0:1:1:1:1:1', '2001:db8:0:1:1:1:1:1'],
    ['1:2:3:4:5:6:7::', '1:2:3:4:5:6:7:0'],
    ['::', '::'],
    ['::ffff:7f00:1', '127.0.0.1'],
    ['0:0:0:0:0:FFFF:192.0.2.1', '192.0.2.1'],
    ['::1.2.3.4', '::102:304'],
    ['fe80::0001%ETH0', 'fe80::1%eth0'],
    ['192.0.2.1', '192.0.2.1'],
    ['not an ip', 'not an ip'],
    ['', ''],
  ];
  for (const [input, out] of cases) assert.equal(normalIp(input), out, input);
  assert.equal(normalIp(undefined), '');
  assert.equal(normalIp(5), '');
  const req = (peer, xff) => ({ socket: { remoteAddress: peer }, headers: { 'x-forwarded-for': xff } });
  const trusted = new Set(['0:0:0:0:0:0:0:1', 'FD00::0:1'].map(normalIp));
  assert.equal(clientIp(req('::1', '2001:db8::7'), trusted), '2001:db8::7');
  assert.equal(clientIp(req('fd00::1', '2001:0db8:0:0:0:0:0:7, fd00:0::1'), trusted), '2001:db8::7');
});

test('untrustedProxy: X-Forwarded-For from a local address that is not trusted', () => {
  const req = (peer, xff) => ({ socket: { remoteAddress: peer }, headers: xff === undefined ? {} : { 'x-forwarded-for': xff } });
  const none = new Set();
  for (const peer of ['127.0.0.1', '::1', '::ffff:10.1.2.3', '172.17.0.1', '192.168.1.1', 'fd00::5', 'fe80::1%eth0', '100.64.0.1']) {
    assert.equal(untrustedProxy(req(peer, '203.0.113.9'), none), normalIp(peer), peer);
  }
  assert.equal(untrustedProxy(req('127.0.0.1'), none), null, 'no header');
  assert.equal(untrustedProxy(req('203.0.113.9', '1.2.3.4'), none), null, 'a public peer is a client, not a proxy');
  assert.equal(untrustedProxy(req('2001:db8::1', '1.2.3.4'), none), null);
  assert.equal(untrustedProxy(req('127.0.0.1', '1.2.3.4'), new Set(['127.0.0.1'])), null, 'trusted');
  assert.equal(untrustedProxy({ socket: {}, headers: { 'x-forwarded-for': '1.2.3.4' } }, none), null);
});

test('ipKey groups IPv6 by /64', () => {
  assert.equal(ipKey('192.0.2.1'), 'ip:192.0.2.1');
  assert.equal(ipKey('2001:db8:1:2:aaaa::1'), ipKey('2001:db8:1:2:bbbb:cccc:dddd:eeee'));
  assert.notEqual(ipKey('2001:db8:1:2::1'), ipKey('2001:db8:1:3::1'));
  assert.equal(ipKey('::1'), 'ip:0000:0000:0000:0000::/64');
  assert.equal(ipKey(''), 'ip:');
  assert.equal(ipKey('2001:DB8:1:2::1'), ipKey('2001:0db8:0001:0002:0:0:0:5'));
  assert.equal(ipKey('::ffff:1.2.3.4'), 'ip:0000:0000:0000:0000::/64');
});

test('sameOrigin: Sec-Fetch-Site first, else Origin against Host', () => {
  assert.equal(sameOrigin({ 'sec-fetch-site': 'same-origin' }), true);
  assert.equal(sameOrigin({ 'sec-fetch-site': 'same-site', origin: 'https://x.test', host: 'x.test' }), false);
  assert.equal(sameOrigin({ 'sec-fetch-site': 'cross-site' }), false);
  assert.equal(sameOrigin({ 'sec-fetch-site': 'none' }), false);
  assert.equal(sameOrigin({ origin: 'https://status.test', host: 'status.test' }), true);
  assert.equal(sameOrigin({ origin: 'https://status.test:8443', host: 'status.test:8443' }), true);
  assert.equal(sameOrigin({ origin: 'https://evil.test', host: 'status.test' }), false);
  assert.equal(sameOrigin({ origin: 'null', host: 'status.test' }), false);
  assert.equal(sameOrigin({ origin: 'not a url', host: 'status.test' }), false);
  assert.equal(sameOrigin({ host: 'status.test' }), false);
  assert.equal(sameOrigin({}), false);
});

test('sameOrigin refuses an Origin with a user part, a path or another spelling, which no browser sends', () => {
  // The URL parser drops the user part, so these would otherwise name the host.
  assert.equal(sameOrigin({ origin: 'http://evil.example@127.0.0.1:8091', host: '127.0.0.1:8091' }), false);
  assert.equal(sameOrigin({ origin: 'https://evil.test:x@status.test', host: 'status.test' }), false);
  assert.equal(sameOrigin({ origin: 'https://@status.test', host: 'status.test' }), false);
  assert.equal(sameOrigin({ origin: 'https://status.test/', host: 'status.test' }), false);
  assert.equal(sameOrigin({ origin: 'https://status.test/path', host: 'status.test' }), false);
  assert.equal(sameOrigin({ origin: 'https://STATUS.test', host: 'status.test' }), false);
  assert.equal(sameOrigin({ origin: 'https://status.test:443', host: 'status.test' }), false);
  // What browsers send still passes, with a Host in any case.
  assert.equal(sameOrigin({ origin: 'http://127.0.0.1:8091', host: '127.0.0.1:8091' }), true);
  assert.equal(sameOrigin({ origin: 'https://status.test', host: 'Status.Test' }), true);
  assert.equal(sameOrigin({ origin: 'http://[::1]:8080', host: '[::1]:8080' }), true);
});

test('viaHttps: a TLS connection, or a trusted proxy whose X-Forwarded-Proto says https; nobody else', () => {
  const trusted = proxyMatcher(['10.0.0.1']);
  const req = (remoteAddress, headers = {}, encrypted = undefined) => ({ socket: { remoteAddress, encrypted }, headers });
  assert.equal(viaHttps(req('192.0.2.9', {}, true), trusted), true);
  assert.equal(viaHttps(req('10.0.0.1', { 'x-forwarded-proto': 'https' }), trusted), true);
  assert.equal(viaHttps(req('::ffff:10.0.0.1', { 'x-forwarded-proto': 'HTTPS ' }), trusted), true);
  // The last value is the nearest proxy's.
  assert.equal(viaHttps(req('10.0.0.1', { 'x-forwarded-proto': 'http, https' }), trusted), true);
  assert.equal(viaHttps(req('10.0.0.1', { 'x-forwarded-proto': 'https, http' }), trusted), false);
  assert.equal(viaHttps(req('10.0.0.1', { 'x-forwarded-proto': 'http' }), trusted), false);
  assert.equal(viaHttps(req('10.0.0.1', {}), trusted), false);
  // Plain http from anyone else, whatever they claim.
  assert.equal(viaHttps(req('192.0.2.9', { 'x-forwarded-proto': 'https' }), trusted), false);
  assert.equal(viaHttps(req('10.0.0.1', { 'x-forwarded-proto': 'https' }), proxyMatcher([])), false);
  assert.equal(viaHttps(req('192.0.2.9'), trusted), false);
  assert.equal(viaHttps({ headers: {} }, trusted), false);
});

test('isFormType and cookieValue', () => {
  assert.equal(isFormType('application/x-www-form-urlencoded'), true);
  assert.equal(isFormType('application/x-www-form-urlencoded;charset=UTF-8'), true);
  assert.equal(isFormType('application/json'), false);
  assert.equal(isFormType('text/plain'), false);
  assert.equal(isFormType('application/x-www-form-urlencodedX'), false);
  assert.equal(isFormType(undefined), false);
  assert.equal(cookieValue('a=1; __Host-rettui_session=abc; b=2', '__Host-rettui_session'), 'abc');
  assert.equal(cookieValue('x__Host-rettui_session=abc', '__Host-rettui_session'), null);
  assert.equal(cookieValue(undefined, 'a'), null);
});

async function login({ hasher = fakeHasher, gate, now, sleep, audit, failures, throttle, users } = {}) {
  const calls = [];
  const counting = async (p) => {
    calls.push(p);
    return hasher(p);
  };
  const phc = parsePhc(await hashPassword('right password', { ...DEFAULTS, memory: 32768 }, fakeHasher));
  const slept = [];
  const l = createLogin({
    users: users ?? [{ name: 'Alice', phc }], hasher: counting, ...(gate ? { gate } : {}), ...(now ? { now } : {}), ...(audit ? { audit } : {}), ...(failures ? { failures } : {}), ...(throttle ? { throttle } : {}),
    sleep: sleep ?? (async (ms) => { slept.push(ms); }),
  });
  return { l, calls, slept };
}
const pair = (name, ip) => `user:${name}|${ipKey(ip)}`;

test('attempt: a right password logs in, by name in any case', async () => {
  const { l } = await login();
  assert.deepEqual(await l.attempt('alice', 'right password', '192.0.2.1'), { ok: true, name: 'Alice', epoch: 0, device: null });
  assert.deepEqual(await l.attempt('  ALICE ', 'right password', '192.0.2.1'), { ok: true, name: 'Alice', epoch: 0, device: null });
  assert.equal(l.enabled, true);
});

test('attempt: an unknown name and a wrong password give the same answer and both work out a hash', async () => {
  const { l, calls } = await login();
  const wrong = await l.attempt('alice', 'wrong', '192.0.2.1');
  const unknown = await l.attempt('mallory', 'wrong', '192.0.2.2');
  assert.deepEqual(wrong, unknown);
  assert.deepEqual(wrong, { ok: false, reason: 'invalid' });
  assert.equal(calls.length, 2);
  // The stand-in has the costs of the real user.
  assert.deepEqual(calls.map((c) => c.memory), [32768, 32768]);
  assert.deepEqual(calls.map((c) => c.length), [32, 32]);
});

test('attempt: too long a password or name is refused at once, and counts nowhere: it is not a guess', async () => {
  const lines = [];
  const failures = { note: (event, key) => lines.push([event, key]) };
  const gate = hashGate(1, 0);
  let release;
  // The gate is full: a too long input never gets that far.
  const holding = gate(() => new Promise((r) => (release = r)));
  const { l, calls } = await login({ failures, gate });
  for (let i = 0; i < 50; i++) {
    assert.deepEqual(await l.attempt('alice', 'x'.repeat(1025), '192.0.2.1'), { ok: false, reason: 'invalid' });
    assert.deepEqual(await l.attempt('x'.repeat(65), 'pw', '2001:db8::1'), { ok: false, reason: 'invalid' });
  }
  assert.deepEqual(await l.attempt('alice', undefined, '192.0.2.1'), { ok: false, reason: 'invalid' });
  assert.equal(calls.length, 0);
  for (const th of [l.accounts, l.addresses, l.nets56, l.nets48, l.devices, l.names]) assert.equal(th.size, 0);
  assert.deepEqual(lines, []);
  assert.deepEqual(gate.load(), { running: 1, waiting: 0, keys: 0 });
  release();
  await holding;
});

test('attempt: failures make that address wait for that name; the owner from another address is not held back', async () => {
  const { l, calls } = await login();
  // Five failures from one address are free; the sixth starts the wait, for that address and name.
  for (let i = 0; i < 6; i++) assert.equal((await l.attempt('alice', 'wrong', '203.0.113.9')).reason, 'invalid');
  const t = await l.attempt('alice', 'right password', '203.0.113.9');
  assert.equal(t.reason, 'throttled');
  assert.ok(t.retryAfterMs > 0 && t.retryAfterMs <= 1000);
  assert.equal(calls.length, 6, 'no hash while throttled');
  // Alice, from her own address, signs in at once.
  assert.deepEqual(await l.attempt('alice', 'right password', '192.0.2.200'), { ok: true, name: 'Alice', epoch: 0, device: null });
  // The same for a name that does not exist: no way to tell names apart.
  for (let i = 0; i < 6; i++) await l.attempt('nobody', 'wrong', '198.51.100.1');
  assert.equal((await l.attempt('nobody', 'x', '198.51.100.1')).reason, 'throttled');
  assert.equal((await l.attempt('nobody', 'x', '198.51.100.2')).reason, 'invalid');
  // One address trying many names is slowed down too (20 free).
  for (let i = 0; i < 21; i++) await l.attempt(`user${i}`, 'wrong', '203.0.113.5');
  assert.equal((await l.attempt('someone', 'x', '203.0.113.5')).reason, 'throttled');
  assert.equal((await l.attempt('alice', 'right password', '203.0.113.5')).reason, 'throttled');
});

test('attempt: tries at one name are a token bucket: a burst, then one a second, and past a short backlog a refusal', async () => {
  let t = 1_000_000;
  const { l, slept } = await login({ now: () => t });
  // NAME_BURST tries from as many addresses go at once.
  for (let i = 0; i < NAME_BURST; i++) assert.equal((await l.attempt('alice', 'wrong', `198.51.100.${i}`)).reason, 'invalid');
  assert.deepEqual(slept, []);
  // The next NAME_BACKLOG wait for their turn, a second apart.
  for (let i = 0; i < NAME_BACKLOG; i++) assert.equal((await l.attempt('alice', 'wrong', `203.0.113.${i}`)).reason, 'invalid');
  assert.deepEqual(slept, Array.from({ length: NAME_BACKLOG }, (_, i) => (i + 1) * NAME_INTERVAL_MS));
  // Past that the backlog is full: refused at once, with the time until a turn is free, without a hash.
  const refused = await l.attempt('alice', 'right password', '192.0.2.50');
  assert.equal(refused.reason, 'paced');
  assert.equal(refused.retryAfterMs, NAME_INTERVAL_MS);
  // The same for a name that does not exist, so the answer tells nothing.
  for (let i = 0; i < NAME_BURST + NAME_BACKLOG; i++) await l.attempt('nobody', 'wrong', `198.51.100.${100 + i}`);
  assert.equal((await l.attempt('nobody', 'wrong', '192.0.2.51')).reason, 'paced');
  // The bucket is per name: another name goes at once.
  slept.length = 0;
  assert.equal((await l.attempt('bob', 'wrong', '192.0.2.52')).reason, 'invalid');
  assert.deepEqual(slept, []);
  // A second later one more turn is free; in all it is one a second, never more.
  t += NAME_INTERVAL_MS;
  assert.equal((await l.attempt('alice', 'right password', '192.0.2.50')).ok, true);
  assert.equal((await l.attempt('alice', 'right password', '192.0.2.50')).reason, 'paced');
  let tries = 0;
  for (let s = 0; s < 3600; s++) {
    t += NAME_INTERVAL_MS / 2;
    if ((await l.attempt('alice', 'wrong', `10.${s >> 8}.${s & 255}.1`)).reason !== 'paced') tries++;
  }
  assert.ok(tries <= 1800 + 1, `${tries} tries in 30 minutes`);
  assert.ok(tries >= 1790, `${tries} tries in 30 minutes`);
});

test('name bucket: bounded, and a full map forgets the buckets closest to full first', () => {
  let t = 0;
  const b = new NameBucket({ intervalMs: 1000, burst: 2, backlog: 1, maxEntries: 3, now: () => t });
  for (let i = 0; i < 3; i++) b.take('busy');
  assert.equal(b.take('busy').ok, false);
  b.take('x');
  b.take('y');
  // A flood of new names pushes out each other and x, y, never the busy one.
  for (let i = 0; i < 50; i++) assert.equal(b.take(`n${i}`).ok, true);
  assert.equal(b.size, 3);
  assert.equal(b.take('busy').ok, false);
  // count() never waits, and never fills the bucket past the backlog.
  for (let i = 0; i < 100; i++) b.count('dev');
  assert.deepEqual(b.take('dev'), { ok: false, retryAfterMs: 1000 });
  t += 1000;
  assert.deepEqual(b.take('dev'), { ok: true, delayMs: 1000 });
});

test('attempt: a success from an address only halves its count, so it cannot wipe its own failures', async () => {
  const { l } = await login();
  for (let i = 0; i < 18; i++) await l.attempt(`user${i}`, 'wrong', '203.0.113.5');
  assert.equal(l.addresses.count(ipKey('203.0.113.5')), 18);
  assert.equal((await l.attempt('alice', 'right password', '203.0.113.5')).ok, true);
  assert.equal(l.addresses.count(ipKey('203.0.113.5')), 9);
  // So after its own login works, the address gets 12 more tries before the wait, not 21.
  for (let i = 0; i < 12; i++) assert.equal((await l.attempt(`more${i}`, 'wrong', '203.0.113.5')).reason, 'invalid');
  assert.equal((await l.attempt('x', 'wrong', '203.0.113.5')).reason, 'throttled');
});

test('attempt: a password asked again in a session counts for the session, not for the name', async () => {
  const { l } = await login();
  // Someone outside spends every try on the name, from many addresses.
  for (let i = 0; i < 30; i++) await l.attempt('alice', 'wrong', `198.51.100.${i}`);
  // The signed-in owner is neither refused nor slowed down by it.
  assert.deepEqual(await l.attempt('alice', 'right password', '192.0.2.1', { session: 'sess-a' }), { ok: true, name: 'Alice', epoch: 0, device: null });
  // Wrong passwords in the session count, for the session.
  for (let i = 0; i < 6; i++) assert.equal((await l.attempt('alice', 'wrong', '192.0.2.1', { session: 'sess-a' })).reason, 'invalid');
  assert.equal((await l.attempt('alice', 'right password', '192.0.2.1', { session: 'sess-a' })).reason, 'throttled');
  // They count in a throttle of their own: no flood of other keys can push them out.
  assert.equal(l.reauths.count('session:sess-a'), 6);
  assert.equal(l.accounts.count('session:sess-a'), 0);
  assert.equal(l.addresses.count(ipKey('192.0.2.1')), 0, 'nor for the address');
  // Another session of the same user is not held back.
  assert.equal((await l.attempt('alice', 'right password', '192.0.2.1', { session: 'sess-b' })).ok, true);
});

test('attempt: with every hash slot and the queue full the answer is busy', async () => {
  const gate = hashGate(1, 0);
  let release;
  const slow = new Promise((r) => (release = r));
  const held = gate(() => slow);
  const { l } = await login({ gate });
  assert.deepEqual(await l.attempt('alice', 'right password', '192.0.2.1'), { ok: false, reason: 'busy', retryAfterMs: 2000 });
  release();
  await held;
  // The slot is given back once the job has settled.
  await new Promise((r) => setImmediate(r));
  assert.equal((await l.attempt('alice', 'right password', '192.0.2.1')).ok, true);
});

// A hasher that holds every check until released, to send requests that overlap.
function held(hasher = fakeHasher) {
  let release;
  const gate = new Promise((r) => (release = r));
  const calls = [];
  return { calls, release: () => release(), hasher: async (p) => (calls.push(p), await gate, hasher(p)) };
}

test('attempt: a burst of wrong passwords sent at once is checked only up to the free tries and one more', async () => {
  const h = held();
  const { l } = await login({ hasher: h.hasher, gate: hashGate(10, 10, 10) });
  const all = Promise.all(Array.from({ length: 10 }, () => l.attempt('alice', 'wrong', '192.0.2.1')));
  await new Promise((r) => setImmediate(r));
  assert.equal(h.calls.length, 5, 'the free tries run at once, the rest wait for them');
  h.release();
  const out = await all;
  assert.equal(h.calls.length, 6);
  // The tenth is past the backlog of the name's bucket.
  assert.deepEqual(out.map((r) => r.reason).sort(), [...Array(6).fill('invalid'), 'paced', ...Array(3).fill('throttled')]);
  assert.equal(l.accounts.count(pair('alice', '192.0.2.1')), 6);
});

test('attempt: a burst of right passwords all log in', async () => {
  const h = held();
  const { l } = await login({ hasher: h.hasher, gate: hashGate(10, 10, 10) });
  const n = NAME_BURST + NAME_BACKLOG;
  const all = Promise.all(Array.from({ length: n }, () => l.attempt('alice', 'right password', '192.0.2.1')));
  await new Promise((r) => setImmediate(r));
  h.release();
  const out = await all;
  assert.deepEqual(out.map((r) => r.ok), Array(n).fill(true));
  assert.equal(l.accounts.count(pair('alice', '192.0.2.1')), 0);
});

test('attempt: a success in a burst clears the failures before it', async () => {
  const h = held();
  const { l } = await login({ hasher: h.hasher, gate: hashGate(10, 10, 10) });
  const tries = ['wrong', 'wrong', 'wrong', 'wrong', 'right password', 'wrong', 'wrong'].map((pw) => l.attempt('alice', pw, '192.0.2.1'));
  h.release();
  const out = await Promise.all(tries);
  assert.equal(out[4].ok, true);
  assert.equal(out.filter((r) => r.reason === 'throttled').length, 0);
  assert.ok(l.accounts.count(pair('alice', '192.0.2.1')) <= 2);
});

test('attempt: too many waiting for one name and address are turned away as busy, and that does not count as a failure', async () => {
  const h = held();
  const { l } = await login({ hasher: h.hasher, gate: hashGate(100, 100, 100), throttle: { names: new NameBucket({ burst: 100 }) } });
  const tries = Array.from({ length: 5 + MAX_QUEUED_HASHES + 3 }, () => l.attempt('alice', 'wrong', '192.0.2.1'));
  await new Promise((r) => setImmediate(r));
  h.release();
  const out = await Promise.all(tries);
  assert.equal(out.filter((r) => r.reason === 'busy').length, 3);
  assert.ok(out.filter((r) => r.reason === 'busy').every((r) => r.retryAfterMs === 2000));
  assert.equal(l.accounts.count(pair('alice', '192.0.2.1')), 6);
});

test('attempt: a busy answer from the gate does not count as a failure', async () => {
  const gate = hashGate(1, 0);
  let release;
  const holding = gate(() => new Promise((r) => (release = r)));
  const { l } = await login({ gate });
  for (let i = 0; i < 9; i++) assert.equal((await l.attempt('alice', 'wrong', '192.0.2.1')).reason, 'busy');
  assert.equal(l.accounts.count(pair('alice', '192.0.2.1')), 0);
  assert.equal(l.addresses.count('ip:192.0.2.1'), 0);
  release();
  await holding;
});

test('attempt: an unknown name is checked with the costs of one of the users, the same each time', async () => {
  const calls = [];
  const counting = async (p) => (calls.push(p), fakeHasher(p));
  const users = [
    { name: 'cheap', phc: parsePhc(await hashPassword('a', DEFAULTS, fakeHasher)) },
    { name: 'memory', phc: parsePhc(await hashPassword('b', { ...DEFAULTS, memory: 65536 }, fakeHasher)) },
    { name: 'passes', phc: parsePhc(await hashPassword('c', { ...DEFAULTS, passes: 7, parallelism: 4 }, fakeHasher)) },
  ];
  const l = createLogin({ users, hasher: counting });
  const costs = (c) => [c.memory, c.passes, c.parallelism, c.length];
  const stored = users.map((u) => JSON.stringify([u.phc.memory, u.phc.passes, u.phc.parallelism, u.phc.hash.length]));
  for (const name of ['nobody', 'someone', 'x']) {
    assert.equal((await l.attempt(name, 'x', '192.0.2.1')).reason, 'invalid');
    assert.equal((await l.attempt(name, 'y', '192.0.2.2')).reason, 'invalid');
    const [a, b] = calls.splice(0);
    assert.ok(stored.includes(JSON.stringify(costs(a))), name);
    assert.deepEqual(costs(a), costs(b), `${name}: the same costs every time`);
  }
});

test('attempt: a hasher that fails is an error, not a login', async () => {
  const { l } = await login({ hasher: async () => { throw new Error('out of memory'); } });
  await assert.rejects(l.attempt('alice', 'right password', '192.0.2.1'), /out of memory/);
});

test('without users there is no login and nobody is a viewer', () => {
  const l = createLogin({ users: [] });
  assert.equal(l.enabled, false);
  assert.equal(l.viewer({ headers: { cookie: '__Host-rettui_session=x' } }), null);
});

test('sessions: one user has at most maxPerUser; past it a new sign in ends their own least used one', () => {
  let t = 0;
  const s = new Sessions({ idleMs: 10 * MIN, maxAgeMs: 30 * MIN, max: 100, maxPerUser: 3, now: () => t });
  const bob = s.create('bob');
  const a = [s.create('alice'), s.create('ALICE'), s.create('alice')];
  t += 1;
  s.get(a[0]);
  const a4 = s.create('Alice');
  assert.equal(s.list('alice').length, 3);
  assert.equal(s.get(a[1]), null, 'her least used session ended');
  assert.ok(s.get(a[0]) && s.get(a[2]) && s.get(a4));
  assert.ok(s.get(bob), 'nobody else lost a session');
});

test('sessions: with the cap reached, a new sign in ends a session of whoever has the most, not of anyone else', () => {
  let t = 0;
  const s = new Sessions({ idleMs: 10 * MIN, maxAgeMs: 30 * MIN, max: 6, maxPerUser: 20, now: () => t });
  const bob = s.create('bob');
  const carol = s.create('carol');
  // Mallory fills the rest, and goes on signing in.
  const m = [];
  for (let i = 0; i < 10; i++) {
    t += 1;
    m.push(s.create('mallory'));
  }
  assert.equal(s.size, 6);
  assert.ok(s.get(bob) && s.get(carol), 'the flood ends only the flooder\'s own sessions');
  assert.equal(s.list('mallory').length, 4);
  // A new user signing in takes a place from the one with the most.
  const dave = s.create('dave');
  assert.ok(s.get(dave) && s.get(bob) && s.get(carol));
  assert.equal(s.list('mallory').length, 3);
  // destroyOthers is by name in any case, and says how many ended.
  assert.equal(s.destroyOthers('MALLORY', m[9]), 2);
  assert.deepEqual(s.list('mallory').map((x) => x.id), [m[9]]);
  assert.equal(s.destroyOthers('mallory'), 1);
});

test('throttle: decay halves a count, and drops a key it brings to zero', () => {
  const th = new Throttle({ free: 2, now: () => 0 });
  for (let i = 0; i < 7; i++) th.fail('k');
  th.decay('k');
  assert.equal(th.count('k'), 3);
  th.decay('k');
  th.decay('k');
  assert.equal(th.size, 0);
  th.decay('nothing');
  assert.equal(th.size, 0);
});

test('waitText says a wait in seconds, minutes or hours', () => {
  assert.equal(waitText(0), '1 second');
  assert.equal(waitText(1000), '1 second');
  assert.equal(waitText(1001), '2 seconds');
  assert.equal(waitText(89_000), '89 seconds');
  assert.equal(waitText(90_000), '2 minutes');
  assert.equal(waitText(60 * MIN), '60 minutes');
  assert.equal(waitText(90 * MIN), '2 hours');
  assert.equal(waitText(24 * 60 * MIN), '24 hours');
});

test('codes: wrong codes per user and address are remembered for a day and wait up to an hour; each is in the failures log', async () => {
  let t = 1_000_000;
  const lines = [];
  const failures = { note: (event, key, fields) => lines.push({ event, key, ...fields }) };
  const { l } = await login({ now: () => t, failures });
  const pairKey = `user:alice|${ipKey('192.0.2.1')}`;
  const wrong = (ip = '192.0.2.1') => l.checkCode('Alice', '000000', ip, { check: async () => ({ ok: false }) });
  for (let i = 0; i < 5; i++) assert.equal((await wrong()).reason, 'invalid');
  assert.ok(l.codes.wait(pairKey) === 0);
  assert.equal((await wrong()).reason, 'invalid');
  assert.equal((await wrong()).reason, 'throttled');
  // Another address is not held back by them.
  assert.equal((await wrong('198.51.100.7')).reason, 'invalid');
  const waits = [];
  for (let i = 0; i < 14; i++) {
    t += l.codes.wait(pairKey);
    assert.equal((await wrong()).reason, 'invalid');
    waits.push(l.codes.wait(pairKey));
  }
  assert.equal(lines.length, 21);
  assert.ok(lines.every((x) => x.event === 'second-factor-failures' && x.user === 'Alice' && x.key === 'user:alice'));
  assert.equal(Math.max(...waits), CODE_MAX_WAIT_MS);
  // Two quiet hours later the count is still there: no fresh free tries.
  t += 2 * 60 * MIN;
  assert.equal((await wrong()).reason, 'invalid');
  assert.equal(l.codes.wait(pairKey), CODE_MAX_WAIT_MS);
  // A day after the last one it is forgotten.
  t += CODE_MAX_WAIT_MS + 24 * 60 * MIN;
  assert.equal(l.codes.wait(pairKey), 0);
  assert.equal(l.codes.count(pairKey), 0);
});

test('codes: from many addresses, past CODE_USER_FREE for the user, everyone but a known device waits; past the ceiling the device too', async () => {
  let t = 1_000_000;
  const { l } = await login({ now: () => t });
  const wrong = (ip, device = null) => l.checkCode('Alice', '000000', ip, { check: async () => ({ ok: false }), device });
  for (let i = 0; i < CODE_USER_FREE; i++) assert.equal((await wrong(`198.51.100.${i}`)).reason, 'invalid');
  assert.equal(l.codeUsers.wait('user:alice'), 0);
  assert.equal((await wrong('203.0.113.1')).reason, 'invalid');
  assert.equal((await wrong('203.0.113.2')).reason, 'throttled', 'a fresh address waits too');
  const device = 'd'.repeat(64);
  assert.equal((await wrong('203.0.113.3', device)).reason, 'invalid', 'a known device does not');
  // A device is not held back by its address either, but by its own count.
  for (let i = 0; i < 5; i++) await wrong('203.0.113.3', device);
  assert.equal((await wrong('203.0.113.3', device)).reason, 'throttled');
  // Past the ceiling for the user, the device waits for the user too.
  for (let n = l.codeUsers.count('user:alice'); n < 200; n++) l.codeUsers.fail('user:alice');
  t += CODE_MAX_WAIT_MS;
  assert.equal((await wrong('203.0.113.4', 'e'.repeat(64))).reason, 'invalid');
  assert.equal((await wrong('203.0.113.4', 'e'.repeat(64))).reason, 'throttled');
});

test('hashGate: one place is kept for passwords asked while signed in and for known devices; a public flood never takes it', async () => {
  const gate = hashGate(2, 2, 10, { reserved: 1, laneQueue: 1, lanePerKey: 1 });
  const releases = [];
  const job = (tag) => () => new Promise((r) => releases.push(() => r(tag)));
  // The public lane fills its two places and its queue; more is turned away.
  const pub = [gate(job('p1'), 'ip:a'), gate(job('p2'), 'ip:b'), gate(job('p3'), 'ip:c'), gate(job('p4'), 'ip:d')];
  assert.equal(gate.wouldAccept('ip:e'), false);
  await assert.rejects(gate(job('p5'), 'ip:e'), Busy);
  await new Promise((r) => setImmediate(r));
  assert.deepEqual(gate.load(), { running: 2, waiting: 2, keys: 4 });
  // A session still runs at once, in the reserved place.
  assert.equal(gate.wouldAccept('session:x', 'session'), true);
  const sess = gate(job('s1'), 'session:x', 'session');
  await new Promise((r) => setImmediate(r));
  assert.equal(gate.load().running, 3);
  // One more per session is too many; a device waits in its own queue, and a second device is turned away.
  assert.equal(gate.wouldAccept('session:x', 'session'), false);
  await assert.rejects(gate(job('s2'), 'session:x', 'session'), Busy);
  const dev = gate(job('d1'), 'device:1', 'device');
  assert.equal(gate.wouldAccept('device:2', 'device'), false);
  await assert.rejects(gate(job('d2'), 'device:2', 'device'), Busy);
  // A public place that frees goes to the public queue, not to the device: the lanes have their
  // reserved place only while sign ins from outside wait.
  releases[0]();
  assert.equal(await pub[0], 'p1');
  await new Promise((r) => setImmediate(r));
  assert.equal(releases.length, 4, 'p3 started, the device did not');
  assert.deepEqual(gate.load(), { running: 3, waiting: 2, keys: 5 });
  // The reserved place frees: the device takes it.
  releases[2]();
  assert.equal(await sess, 's1');
  await new Promise((r) => setImmediate(r));
  assert.equal(releases.length, 5, 'the device started');
  releases[4]();
  assert.equal(await dev, 'd1');
  releases[1]();
  releases[3]();
  assert.deepEqual(await Promise.all([pub[1], pub[2]]), ['p2', 'p3']);
  await new Promise((r) => setImmediate(r));
  releases[5]();
  assert.equal(await pub[3], 'p4');
  await new Promise((r) => setImmediate(r));
  assert.deepEqual(gate.load(), { running: 0, waiting: 0, keys: 0 });
});

test('hashGate: sessions and devices use the public places only while nobody from outside waits, so they cannot starve sign ins', async () => {
  const gate = hashGate(2, 4, 10, { reserved: 1, laneQueue: 10, lanePerKey: 10 });
  const releases = [];
  const started = [];
  const job = (tag) => () => new Promise((r) => (started.push(tag), releases.push(() => r(tag))));
  // With nobody from outside waiting, signed-in checks may use every place.
  const lane = [gate(job('s1'), 's', 'session'), gate(job('d1'), 'd', 'device'), gate(job('s2'), 's', 'session')];
  await new Promise((r) => setImmediate(r));
  assert.equal(gate.load().running, 3);
  // A sign in from outside is queued, not turned away, and more signed-in checks wait behind it.
  assert.equal(gate.wouldAccept('ip:a'), true);
  const pub = gate(job('p1'), 'ip:a');
  const more = [gate(job('s3'), 's', 'session'), gate(job('d2'), 'd', 'device')];
  await new Promise((r) => setImmediate(r));
  assert.deepEqual(gate.load(), { running: 3, waiting: 3, keys: 3 });
  // The first place that frees goes to it, though the signed-in checks were there first.
  releases[0]();
  await new Promise((r) => setImmediate(r));
  assert.equal(started.at(-1), 'p1');
  // While it runs and nobody else from outside waits, the lanes may fill the places again.
  releases[1]();
  await new Promise((r) => setImmediate(r));
  assert.equal(started.at(-1), 's3');
  // A steady stream of signed-in checks never holds a waiting sign in back for more than one place.
  const pub2 = gate(job('p2'), 'ip:b');
  const flood = Array.from({ length: 5 }, (_, i) => gate(job(`s${i + 4}`), 's', 'session'));
  releases[2]();
  await new Promise((r) => setImmediate(r));
  assert.equal(started.at(-1), 'p2');
  let done = false;
  const all = Promise.all([...lane, pub, ...more, pub2, ...flood]).then(() => (done = true));
  while (!done) {
    for (const r of releases.splice(0)) r();
    await new Promise((r) => setImmediate(r));
  }
  await all;
  assert.equal(started.length, 12);
  await new Promise((r) => setImmediate(r));
  assert.deepEqual(gate.load(), { running: 0, waiting: 0, keys: 0 });
});

test('attempt: a signed-in password check gets the reserved place while outsiders fill the gate', async () => {
  let release;
  const held = new Promise((r) => (release = r));
  const gate = hashGate(1, 0);
  const holding = gate(() => held, 'ip:x');
  const { l } = await login({ gate });
  assert.equal((await l.attempt('alice', 'right password', '192.0.2.1')).reason, 'busy');
  assert.equal((await l.attempt('alice', 'right password', '192.0.2.1', { session: 's1' })).ok, true);
  release();
  await holding;
});

test('netKeys and the IPv6 network counts: a /56 and a /48 get more free tries than a /64, then wait', async () => {
  assert.equal(netKeys('192.0.2.1'), null);
  assert.equal(netKeys('not an ip'), null);
  assert.deepEqual(netKeys('2001:db8:1:2ab::1'), { net56: 'net:2001:0db8:0001:0200::/56', net48: 'net:2001:0db8:0001::/48' });
  assert.equal(netKeys('2001:db8:1:2ff::1').net56, netKeys('2001:db8:1:200::9').net56);
  assert.notEqual(netKeys('2001:db8:1:300::1').net56, netKeys('2001:db8:1:200::1').net56);
  const { l } = await login({ throttle: { names: new NameBucket({ burst: 100_000 }) } });
  // Each failure from a new /64 of one /56: the /64s never wait, the /56 does once past its free tries.
  for (let i = 0; i < NET56_FREE + 1; i++) assert.equal((await l.attempt(`u${i}`, 'wrong', `2001:db8:1:2${(i % 256).toString(16).padStart(2, '0')}::1`)).reason, 'invalid');
  assert.equal((await l.attempt('alice', 'right password', '2001:db8:1:2ee::5')).reason, 'throttled');
  // Another /56 of the same /48 is not held back yet...
  assert.equal((await l.attempt('alice', 'right password', '2001:db8:1:300::5')).ok, true);
  // That sign in halved the counts of its networks, as for an address.
  const k48 = netKeys('2001:db8:1::1').net48;
  assert.equal(l.nets48.count(k48), Math.floor((NET56_FREE + 1) / 2));
  // ...until the /48 has had its free tries, from however many /56s.
  for (let i = 0; l.nets48.count(k48) <= NET48_FREE; i++) await l.attempt(`v${i}`, 'wrong', `2001:db8:1:${(0x400 + 0x100 * (i % 200)).toString(16)}::1`);
  assert.equal((await l.attempt('alice', 'right password', '2001:db8:1:300::5')).reason, 'throttled');
  // Another /48 is free, and IPv4 has no such counts.
  assert.equal((await l.attempt('alice', 'right password', '2001:db8:2::5')).ok, true);
  assert.equal(l.nets56.size + l.nets48.size > 0, true);
});

async function storeLogin(opts = {}) {
  const store = new UserStore({ now: opts.now ?? Date.now, warn: () => {} });
  await store.createUser({ name: 'bob', role: 'viewer', passwordHash: await hashPassword('bobs password!', undefined, fakeHasher) });
  const l = createLogin({ users: [], store, hasher: opts.hasher ?? fakeHasher, sleep: async () => {}, ...(opts.gate ? { gate: opts.gate } : {}), ...(opts.now ? { now: opts.now } : {}), ...(opts.audit ? { audit: opts.audit } : {}), ...(opts.failures ? { failures: opts.failures } : {}) });
  return { l, store };
}

test('devices: a known device skips the pace of the name and the waits others caused, but still needs the password', async () => {
  const { l, store } = await storeLogin();
  const id = newDeviceId();
  assert.match(id, /^[A-Za-z0-9_-]{22}$/);
  const hash = deviceHash(id);
  assert.match(hash, /^[0-9a-f]{64}$/);
  for (const bad of [null, '', 'x', 'a'.repeat(23), `${'a'.repeat(21)}!`]) assert.equal(deviceHash(bad), null);
  await store.addDevice('bob', hash);
  // Others use up the pace of the name, the wait of the address and of the name and address.
  for (let i = 0; i < 30; i++) await l.attempt('bob', 'wrong', i < 25 ? '203.0.113.9' : `198.51.100.${i}`);
  assert.equal((await l.attempt('bob', 'bobs password!', '203.0.113.9')).reason, 'throttled');
  assert.equal((await l.attempt('bob', 'bobs password!', '192.0.2.1')).reason, 'paced');
  // From the same address, with the device: in, and the answer names the device.
  assert.deepEqual(await l.attempt('bob', 'bobs password!', '203.0.113.9', { device: id }), { ok: true, name: 'bob', epoch: 0, device: hash });
  // The device is no password: a wrong one is refused, and counts for the device.
  for (let i = 0; i < 6; i++) assert.equal((await l.attempt('bob', 'wrong', '203.0.113.9', { device: id })).reason, 'invalid');
  assert.equal((await l.attempt('bob', 'bobs password!', '203.0.113.9', { device: id })).reason, 'throttled');
  assert.equal(l.devices.count(`device:${hash}`), 6);
  // A device of another user, or an unknown one, is no device for this name.
  const other = newDeviceId();
  assert.equal((await l.attempt('bob', 'bobs password!', '192.0.2.2', { device: other })).reason, 'paced');
});

test('devices: endUser forgets them all, but the one of the session it keeps', async () => {
  const { l, store } = await storeLogin();
  const [a, b, c] = [newDeviceId(), newDeviceId(), newDeviceId()].map(deviceHash);
  for (const h of [a, b, c]) await store.addDevice('bob', h);
  const keep = l.sessions.create('bob', { device: b });
  l.sessions.create('bob', { device: a });
  assert.equal(l.endUser('bob', keep), 1);
  assert.deepEqual(store.devices('bob').map((d) => d.hash), [b]);
  l.endUser('BOB');
  assert.deepEqual(store.devices('bob'), []);
});

test('signIn: a session and a device, and nothing when the user changed since the password was checked', async () => {
  const { l, store } = await storeLogin();
  const r = await l.attempt('bob', 'bobs password!', '192.0.2.1');
  const done = await l.signIn('bob', { epoch: r.epoch, device: r.device });
  assert.match(done.deviceId, /^[A-Za-z0-9_-]{22}$/);
  assert.equal(l.sessions.map.get(done.id).device, deviceHash(done.deviceId));
  assert.equal(store.hasDevice('bob', deviceHash(done.deviceId)), true);
  // With the device again: the same id, and no second device.
  const again = await l.attempt('bob', 'bobs password!', '192.0.2.1', { device: done.deviceId });
  const second = await l.signIn('bob', { epoch: again.epoch, device: again.device, deviceId: done.deviceId, old: done.id });
  assert.equal(second.deviceId, done.deviceId);
  assert.equal(store.devices('bob').length, 1);
  assert.equal(l.sessions.map.has(done.id), false, 'the old session of the request ended');
  // The password changed after the check: no session.
  const stale = await l.attempt('bob', 'bobs password!', '192.0.2.1');
  l.endUser('bob');
  assert.equal(await l.signIn('bob', { epoch: stale.epoch, device: null }), null);
  assert.equal(l.sessions.list('bob').length, 0);
  assert.throws(() => l.startSecondFactor('bob', '192.0.2.1'), /epoch/);
});

test('attempt: a password changed (and endUser called) while it is checked does not sign in with the old one', async () => {
  const h = held();
  const { l, store } = await storeLogin({ hasher: h.hasher, gate: hashGate(10, 10, 10) });
  const pending = l.attempt('bob', 'bobs password!', '192.0.2.1');
  await new Promise((r) => setImmediate(r));
  assert.equal(h.calls.length, 1, 'the check of the old password is under way');
  await store.setPassword('bob', await hashPassword('a whole new password', undefined, fakeHasher));
  l.endUser('bob');
  h.release();
  assert.deepEqual(await pending, { ok: false, reason: 'invalid' });
  // It is not a failure of anyone's: nothing counted.
  assert.equal(l.accounts.count(`user:bob|${ipKey('192.0.2.1')}`), 0);
  // The same when only the hash changed, without endUser (a caller that forgot it).
  const h2 = held();
  const { l: l2, store: s2 } = await storeLogin({ hasher: h2.hasher, gate: hashGate(10, 10, 10) });
  const p2 = l2.attempt('bob', 'bobs password!', '192.0.2.1');
  await new Promise((r) => setImmediate(r));
  await s2.setPassword('bob', await hashPassword('a whole new password', undefined, fakeHasher));
  h2.release();
  assert.deepEqual(await p2, { ok: false, reason: 'invalid' });
});

test('the numbers wiki/Logins.md gives: wrong codes per day, from one address and for a user in all', () => {
  // A guesser who tries again the moment each wait is over.
  const guesses = (free, hours) => {
    let t = 0;
    const th = new Throttle({ free, maxMs: CODE_MAX_WAIT_MS, forgetMs: 24 * 60 * MIN, now: () => t });
    let n = 0;
    for (;;) {
      t += th.wait('k');
      if (t >= hours * 60 * MIN) return n;
      th.fail('k');
      n++;
    }
  };
  assert.equal(guesses(5, 24), 40, 'one address, first day');
  assert.equal(guesses(5, 48) - guesses(5, 24), 24, 'one address, each day after');
  assert.equal(guesses(CODE_USER_FREE, 24), 65, 'a user from every address together, first day');
  assert.equal(guesses(CODE_USER_FREE, 48) - guesses(CODE_USER_FREE, 24), 24);
  // Passwords: one name gets NAME_BURST + NAME_BACKLOG at once, then one a second.
  let t = 0;
  const b = new NameBucket({ now: () => t });
  let n = 0;
  for (; t < 60 * MIN; t += 100) while (b.take('user:x').ok) n++;
  assert.ok(n >= 3600 && n <= 3600 + NAME_BURST + NAME_BACKLOG, `${n} tries in an hour`);
  // Known devices: three sign ins at once, then one every 3 seconds; a new one is an audit line once a day.
  assert.deepEqual([DEVICE_BURST, DEVICE_INTERVAL_MS, DEVICE_AUDIT_MS], [3, 3000, 24 * 60 * MIN]);
  // The password asked again: 10 an hour per session, 20 per user; sign in times written once a minute.
  assert.deepEqual([REAUTHS_PER_SESSION, REAUTHS_PER_USER, ACTION_WINDOW_MS, LOGIN_WRITE_MS], [10, 20, 60 * MIN, MIN]);
});

test('attempt: requests the gate turns away cost no turn of the name, before or after the turn is taken', async () => {
  let t = 1_000_000;
  const now = () => t;
  const names = new NameBucket({ now });
  // The gate is full: busy at once, and the name's bucket is not touched.
  const gate = hashGate(1, 0);
  let release;
  const holding = gate(() => new Promise((r) => (release = r)), 'ip:x');
  const { l, calls } = await login({ gate, now, throttle: { names } });
  for (let i = 0; i < 50; i++) assert.equal((await l.attempt('alice', 'wrong', `198.51.100.${i}`)).reason, 'busy');
  assert.equal(names.size, 0);
  assert.equal(names.due('user:alice'), t);
  assert.equal(calls.length, 0);
  release();
  await holding;
  await new Promise((r) => setImmediate(r));
  // The gate fills while a try waits for its turn: the turn it took is given back.
  const gate2 = hashGate(1, 0);
  let release2 = null;
  const names2 = new NameBucket({ now, burst: 1 });
  const { l: l2 } = await login({ gate: gate2, now, throttle: { names: names2 }, sleep: async () => {
    if (release2 === null) gate2(() => new Promise((r) => (release2 = r)), 'ip:y');
  } });
  names2.take('user:alice');
  const before = names2.due('user:alice');
  for (let i = 0; i < 3; i++) assert.equal((await l2.attempt('alice', 'wrong', `203.0.113.${i}`)).reason, 'busy');
  assert.equal(names2.due('user:alice'), before);
  release2();
  // Throttled after the wait for its turn: given back too.
  const accounts = new Throttle({ now });
  const names3 = new NameBucket({ now, burst: 1 });
  const { l: l3 } = await login({ now, throttle: { names: names3, accounts }, sleep: async () => {
    for (let i = 0; i < 10; i++) accounts.fail(pair('alice', '192.0.2.9'));
  } });
  names3.take('user:alice');
  const before3 = names3.due('user:alice');
  assert.equal((await l3.attempt('alice', 'wrong', '192.0.2.9')).reason, 'throttled');
  assert.equal(names3.due('user:alice'), before3);
});

test('attempt: tries turned away while they wait for others with the same key give their turn back', async () => {
  const h = held();
  let t = 1_000_000;
  const names = new NameBucket({ burst: 100, now: () => t });
  const { l } = await login({ hasher: h.hasher, gate: hashGate(100, 100, 100), now: () => t, throttle: { names } });
  const n = 5 + MAX_QUEUED_HASHES + 3;
  const tries = Array.from({ length: n }, () => l.attempt('alice', 'wrong', '192.0.2.1'));
  await new Promise((r) => setImmediate(r));
  h.release();
  const out = await Promise.all(tries);
  const busy = out.filter((r) => r.reason === 'busy').length;
  assert.equal(busy, 3);
  // Only the tries that got to their hash keep a turn: the busy ones, and those that waited and
  // were then throttled, gave theirs back.
  const checked = out.filter((r) => r.reason === 'invalid').length;
  assert.equal(checked, 6);
  assert.equal(out.filter((r) => r.reason === 'throttled').length, n - busy - checked);
  assert.equal(names.due('user:alice'), t + checked * NAME_INTERVAL_MS);
});

test('name bucket: refund gives a turn back, never below now; a full map makes room for many keys at once', () => {
  let t = 10_000;
  const b = new NameBucket({ intervalMs: 1000, burst: 2, backlog: 1, maxEntries: 100, now: () => t });
  b.take('k');
  b.take('k');
  assert.equal(b.due('k'), t + 2000);
  b.refund('k');
  assert.equal(b.due('k'), t + 1000);
  b.refund('k');
  b.refund('k');
  assert.equal(b.due('k'), t);
  assert.equal(b.size, 0, 'a bucket back to full is no key');
  b.refund('nobody');
  assert.equal(b.size, 0);
  // Pruning a full map is one pass that frees a tenth of it, not two passes for every new key.
  let prunes = 0;
  const prune = b.prune.bind(b);
  b.prune = (at) => (prunes++, prune(at));
  for (let i = 0; i < 1000; i++) b.take(`n${i}`);
  assert.ok(b.size <= 100);
  assert.ok(prunes <= 91, `${prunes} prunes for 900 keys past the cap`);
});

test('devices: sign ins that work from one known device are paced, before the hash; failures and the name are not', async () => {
  let t = 1_000_000;
  const now = () => t;
  const { l, store } = await storeLogin({ now });
  const id = newDeviceId();
  await store.addDevice('bob', deviceHash(id));
  for (let i = 0; i < DEVICE_BURST; i++) assert.equal((await l.attempt('bob', 'bobs password!', '192.0.2.1', { device: id })).ok, true);
  const paced = await l.attempt('bob', 'bobs password!', '192.0.2.1', { device: id });
  assert.deepEqual(paced, { ok: false, reason: 'paced', retryAfterMs: DEVICE_INTERVAL_MS, scope: 'device' });
  // Another browser is not held back by it.
  assert.equal((await l.attempt('bob', 'bobs password!', '192.0.2.2')).ok, true);
  t += DEVICE_INTERVAL_MS;
  assert.equal((await l.attempt('bob', 'bobs password!', '192.0.2.1', { device: id })).ok, true);
  assert.equal((await l.attempt('bob', 'bobs password!', '192.0.2.1', { device: id })).reason, 'paced');
});

test('signIn: a new device is an audit line only when it is the first in a day or pushes out an older one', async () => {
  let t = 1_800_000_000_000;
  const now = () => t;
  const lines = [];
  const noted = [];
  const audit = { file: null, write: async (event, fields) => lines.push({ event, ...fields }), flush: async () => {} };
  const failures = { note: async (event, key, fields) => noted.push({ event, key, ...fields }) };
  const { l, store } = await storeLogin({ now, audit, failures });
  const signIn = async () => {
    const r = await l.attempt('bob', 'bobs password!', '192.0.2.1');
    t += 1000;
    return l.signIn('bob', { epoch: r.epoch, device: r.device, ip: '192.0.2.1' });
  };
  const first = await signIn();
  for (let i = 0; i < MAX_DEVICES + 5; i++) await signIn();
  // The first is a line; the rest, pushing out devices of the same day, are summed up.
  assert.deepEqual(lines, [{ event: 'device-added', user: 'bob', address: '192.0.2.1' }]);
  assert.equal(noted.length, MAX_DEVICES + 5);
  assert.deepEqual(noted[0], { event: 'device-added', key: 'user:bob', user: 'bob', address: '192.0.2.1' });
  assert.equal(store.hasDevice('bob', deviceHash(first.deviceId)), false);
  // A day later: a line again, and one for each device older than a day that is pushed out.
  t += DEVICE_AUDIT_MS;
  await signIn();
  assert.deepEqual(lines.at(-1), { event: 'device-added', user: 'bob', pushedOut: 1, address: '192.0.2.1' });
  await signIn();
  assert.equal(lines.at(-1).pushedOut, 1);
  // With a known device there is no line at all.
  const before = lines.length + noted.length;
  const known = await signIn();
  const r = await l.attempt('bob', 'bobs password!', '192.0.2.1', { device: known.deviceId });
  assert.equal((await l.signIn('bob', { epoch: r.epoch, device: r.device, deviceId: known.deviceId })).deviceId, known.deviceId);
  assert.equal(lines.length + noted.length, before + 1);
});

test('signIn: a device id that is not the device found is a new browser, never a cookie without an id', async () => {
  const { l, store } = await storeLogin();
  const id = newDeviceId();
  await store.addDevice('bob', deviceHash(id));
  const r = await l.attempt('bob', 'bobs password!', '192.0.2.1', { device: id });
  for (const deviceId of [null, newDeviceId(), 'null']) {
    const done = await l.signIn('bob', { epoch: r.epoch, device: r.device, deviceId });
    assert.match(done.deviceId, /^[A-Za-z0-9_-]{22}$/);
    assert.notEqual(done.deviceId, id);
    assert.equal(l.sessions.map.get(done.id).device, deviceHash(done.deviceId));
  }
});

test('sessions: destroyDevices ends the sessions made on those devices only', () => {
  const s = new Sessions({ idleMs: MIN, maxAgeMs: 10 * MIN, max: 10 });
  const a = s.create('bob', { device: 'a'.repeat(64) });
  const b = s.create('bob', { device: 'b'.repeat(64) });
  const none = s.create('bob');
  const other = s.create('carol', { device: 'a'.repeat(64) });
  assert.equal(s.destroyDevices('BOB', ['a'.repeat(64), 'c'.repeat(64)]), 1);
  assert.equal(s.get(a), null);
  assert.ok(s.get(b) && s.get(none) && s.get(other));
  assert.equal(s.destroyDevices('bob', []), 0);
});

// A login on a user store on disk with a key, as the server has it: Alice in the config file, bob
// a website user whose hash was made before there was a key (as users.json had it). Gives every
// hash worked out in calls, and the audit lines in lines.
async function keyedLogin({ hasher = fakeHasher, gate } = {}) {
  const dataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'login-'));
  const keys = new Keyring(new Map([[1, crypto.randomBytes(32)]]));
  const users = [{ name: 'Alice', phc: parsePhc(await hashPassword('alices password', undefined, fakeHasher)), role: 'admin' }];
  const store = await UserStore.open({ dataDir, configUsers: users, keys, warn: () => {} });
  await store.createUser({ name: 'bob', role: 'viewer', passwordHash: await hashPassword('bobs password!', { ...DEFAULTS, passes: 3 }, fakeHasher), mustChangePassword: true });
  const calls = [];
  const lines = [];
  const logged = [];
  const audit = { write: async (event, fields) => lines.push([event, fields]), flush: async () => {} };
  const l = createLogin({ users, store, hasher: async (p) => (calls.push(p), hasher(p)), audit, log: (m) => logged.push(m), sleep: async () => {}, ...(gate ? { gate } : {}) });
  return { l, store, keys, users, dataDir, calls, lines, logged };
}
const settle = async (cond) => {
  for (let i = 0; i < 200 && !cond(); i++) await new Promise((r) => setTimeout(r, 2));
};

test('pepper: a right password moves a website user\'s hash to the current key, in the background; sessions stay', async () => {
  const { l, store, keys, users, dataDir, calls, lines } = await keyedLogin();
  const old = store.find('bob').phc;
  assert.equal(old.keyid, null);
  // A wrong password moves nothing.
  assert.equal((await l.attempt('bob', 'wrong', '192.0.2.1')).ok, false);
  await settle(() => false);
  assert.equal(calls.length, 1);
  assert.equal(store.find('bob').phc.keyid, null);
  // A right one: signed in, and the hash made again with the pepper, at the same costs.
  const r = await l.attempt('bob', 'bobs password!', '192.0.2.1');
  assert.equal(r.ok, true);
  const session = await l.signIn('bob', { epoch: r.epoch, device: r.device });
  await settle(() => store.find('bob').phc.keyid !== null);
  const now = store.find('bob').phc;
  assert.equal(now.keyid, keys.current);
  assert.deepEqual([now.memory, now.passes, now.parallelism], [old.memory, old.passes, old.parallelism]);
  assert.equal(calls.length, 3);
  assert.deepEqual(calls[2].secret, keys.pepper(keys.current));
  // It is not a change: the session, the epoch and the password to change all stay, and nothing is audited.
  assert.ok(l.sessions.get(session.id));
  assert.equal(l.epochOf('bob'), 0);
  assert.equal(store.lookup('bob').mustChangePassword, true);
  assert.deepEqual(lines.filter(([e]) => e !== 'device-added'), []);
  // On disk too, and the same password signs in with it, without moving it again.
  const again = await UserStore.open({ dataDir, configUsers: users, keys, warn: () => {} });
  assert.equal(again.find('bob').phc.keyid, keys.current);
  again.close();
  assert.equal((await l.attempt('bob', 'bobs password!', '192.0.2.2')).ok, true);
  await settle(() => false);
  assert.equal(calls.length, 4);
  assert.equal((await l.attempt('bob', 'wrong', '192.0.2.2')).ok, false);
  store.close();
});

test('pepper: a user in the config file is never moved to the key, whose file the server cannot write', async () => {
  const { l, store, calls } = await keyedLogin();
  for (let i = 0; i < 3; i++) assert.equal((await l.attempt('alice', 'alices password', '192.0.2.1')).ok, true);
  await settle(() => false);
  assert.equal(calls.length, 3, 'one hash for each check, none more');
  assert.ok(calls.every((c) => c.secret === null));
  assert.equal(store.find('alice').phc.keyid, null);
  assert.equal(store.factorRecord('alice'), null, 'nothing was written for her');
  store.close();
});

test('pepper: a sign in checked against the old hash while the new one is written still counts', async () => {
  // The hashes that held(p) says wait until waiting[i]() lets the i-th one go on: at first the
  // checks against the hash without a pepper, not the new hash.
  const waiting = [];
  let held = (p) => p.secret === null;
  const hasher = async (p) => {
    if (held(p)) await new Promise((r) => waiting.push(r));
    return fakeHasher(p);
  };
  const { l, store } = await keyedLogin({ hasher });
  const first = l.attempt('bob', 'bobs password!', '192.0.2.1');
  const second = l.attempt('bob', 'bobs password!', '192.0.2.2');
  await settle(() => waiting.length === 2);
  assert.equal(waiting.length, 2);
  waiting[0]();
  assert.equal((await first).ok, true);
  await settle(() => store.find('bob').phc.keyid !== null);
  assert.notEqual(store.find('bob').phc.keyid, null, 'the new hash is in place');
  waiting[1]();
  assert.equal((await second).ok, true);
  // A real change after the upgrade is not mistaken for it.
  held = () => true;
  const third = l.attempt('bob', 'bobs password!', '192.0.2.3');
  await settle(() => waiting.length === 3);
  await store.setPassword('bob', await hashPassword('a whole new password', undefined, fakeHasher, store.currentPepper()));
  waiting[2]();
  assert.deepEqual(await third, { ok: false, reason: 'invalid' });
  store.close();
});

test('pepper: no move while the hash places are busy, and a move that fails is only logged', async () => {
  // The gate turns away whatever is not a sign in: the move is skipped, the sign in works.
  const gate = hashGate(2, 8, 2, { reserved: 1, laneQueue: 0, lanePerKey: 0 });
  const busy = await keyedLogin({ gate });
  assert.equal((await busy.l.attempt('bob', 'bobs password!', '192.0.2.1')).ok, true);
  await settle(() => false);
  assert.equal(busy.calls.length, 1);
  assert.equal(busy.store.find('bob').phc.keyid, null);
  assert.deepEqual(busy.logged, []);
  busy.store.close();
  // The store cannot be written: the old hash stays and keeps working.
  const failing = await keyedLogin();
  failing.store.upgradePassword = () => {
    throw new Error('disk full');
  };
  assert.equal((await failing.l.attempt('bob', 'bobs password!', '192.0.2.1')).ok, true);
  await settle(() => failing.logged.length > 0);
  assert.deepEqual(failing.logged, ["could not move bob's password hash to the current key: disk full"]);
  assert.equal(failing.store.find('bob').phc.keyid, null);
  assert.equal((await failing.l.attempt('bob', 'bobs password!', '192.0.2.1')).ok, true);
  failing.store.close();
});

test('a user changed by another program is signed out and it is audited; other users are not', async () => {
  const { l, store, keys, users, dataDir, lines } = await keyedLogin();
  const sign = async (name, password) => {
    const r = await l.attempt(name, password, '192.0.2.1');
    return (await l.signIn(r.name, { epoch: r.epoch, device: r.device })).id;
  };
  const bob = await sign('bob', 'bobs password!');
  const alice = await sign('alice', 'alices password');
  await settle(() => store.find('bob').phc.keyid !== null);
  // scripts/users.js changes bob's role while the server runs; the server looks (as watch does).
  const other = await UserStore.open({ dataDir, configUsers: users, keys, warn: () => {} });
  await other.setRole('bob', 'manage');
  other.close();
  assert.equal(store.refresh(), true);
  assert.equal(l.sessions.get(bob), null, 'bob was signed out');
  assert.ok(l.sessions.get(alice), 'alice was not');
  assert.equal(l.epochOf('bob'), 1, 'a sign in under way for bob ends too');
  assert.equal(store.lookup('bob').role, 'manage');
  await settle(() => lines.some(([e]) => e === 'user-changed-elsewhere'));
  assert.deepEqual(lines.filter(([e]) => e === 'user-changed-elsewhere'), [['user-changed-elsewhere', { user: 'bob', what: ['role'] }]]);
  // Removed elsewhere: the same, once.
  const third = await UserStore.open({ dataDir, configUsers: users, keys, warn: () => {} });
  await third.deleteUser('bob', { force: true });
  third.close();
  assert.equal(store.refresh(), true);
  assert.equal(store.refresh(), false);
  assert.equal(store.lookup('bob'), null);
  await settle(() => lines.filter(([e]) => e === 'user-changed-elsewhere').length === 2);
  assert.deepEqual(lines.filter(([e]) => e === 'user-changed-elsewhere').at(-1), ['user-changed-elsewhere', { user: 'bob', what: ['deleted'] }]);
  store.close();
});

// ---- signing in with a passkey alone ----

const PK_ORIGIN = 'https://status.example.org';
const PK_RP = 'status.example.org';
const PK_NOW = 1_800_000_000_000;

// A login over an in-memory store with bob and carol, passkeys at PK_ORIGIN (siteUrl null: none),
// and an audit and a failures log that only collect what they are given.
async function passkeyLogin({ siteUrl = PK_ORIGIN, settings = {}, names = ['bob', 'carol'] } = {}) {
  const clock = { t: PK_NOW };
  const now = () => clock.t;
  const store = new UserStore({ now, warn: () => {} });
  for (const name of names) await store.createUser({ name, role: 'viewer', passwordHash: await hashPassword('a good password', undefined, fakeHasher) });
  const passkeys = siteUrl ? createPasskeys({ siteUrl, store, now }) : NO_PASSKEYS;
  const events = [];
  const notes = [];
  const logs = [];
  const audit = { write: async (event, fields) => void events.push([event, fields]), flush: async () => {} };
  const failures = { note: (event, key, fields) => void notes.push([event, key, fields]), flushDue: async () => {}, flush: async () => {}, start() {}, stop() {}, size: 0 };
  const l = createLogin({ users: [], store, hasher: fakeHasher, now, audit, failures, passkeys, settings: { ...LOGIN_DEFAULTS, ...settings }, sleep: async () => {}, log: (m) => logs.push(m) });
  return { l, store, passkeys, clock, events, notes, logs };
}

// Adds a passkey for a user the way the account page does; the authenticator and the user handle.
async function enroll(ctx, name, opts = {}, passkeys = ctx.passkeys) {
  const a = new SoftAuthenticator(opts);
  const sessionId = `session-${name}-${a.id}`;
  const epoch = ctx.l.epochOf(name);
  const o = await passkeys.registrationOptions(name, { sessionId, epoch });
  await passkeys.finishRegistration(name, a.create({ challenge: o.challenge, origin: passkeys.origin, rpId: passkeys.rpId }), { sessionId, epoch });
  return { a, handle: o.user.id };
}

// What the browser answers to a prompt of startPasskeySignIn.
const pkAnswer = (a, started, handle, extra = {}) => a.get({ challenge: started.options.challenge, origin: PK_ORIGIN, rpId: PK_RP, userHandle: handle, ...extra });
const INVALID = { ok: false, reason: 'invalid' };

test('passkey sign in: start gives a token and options with no user and no allowCredentials, for this address only', async () => {
  const ctx = await passkeyLogin();
  assert.equal(ctx.l.passkeySignIn, true);
  const r = ctx.l.startPasskeySignIn('192.0.2.1');
  assert.match(r.token, /^[A-Za-z0-9_-]{43}$/);
  assert.deepEqual(Object.keys(r).sort(), ['expiresIn', 'options', 'token']);
  assert.equal(r.expiresIn, 300);
  assert.equal(r.expiresIn * 1000, CHALLENGE_MS);
  assert.deepEqual(r.options, { challenge: r.options.challenge, rpId: PK_RP, timeout: 120_000, userVerification: 'required' });
  assert.match(r.options.challenge, /^[A-Za-z0-9_-]{43}$/);
  const again = ctx.l.startPasskeySignIn('192.0.2.1');
  assert.notEqual(again.token, r.token);
  assert.notEqual(again.options.challenge, r.options.challenge);
  // The token is not the challenge, and what is kept names no user.
  assert.notEqual(r.token, r.options.challenge);
  assert.deepEqual(Object.keys(ctx.l.signInChallenges.get(r.token)).sort(), ['addressKey', 'challenge', 'created', 'netKey']);
  assert.equal(ctx.l.signInChallenges.get(r.token).addressKey, ipKey('192.0.2.1'));
});

test('passkey sign in: a right passkey gives {name, epoch, device}, and the token is good once', async () => {
  const ctx = await passkeyLogin({ names: ['Bob', 'carol'] });
  const { a, handle } = await enroll(ctx, 'Bob', { counter: 5 });
  const started = ctx.l.startPasskeySignIn('192.0.2.1');
  const credential = pkAnswer(a, started, handle);
  assert.deepEqual(await ctx.l.finishPasskeySignIn(started.token, credential, '192.0.2.1', {}), { ok: true, name: 'Bob', epoch: 0, device: null, ref: ctx.store.passkeyById('Bob', a.id).ref });
  assert.equal(ctx.store.passkeyById('Bob', a.id).counter, 6);
  assert.equal(ctx.store.passkeyById('Bob', a.id).lastUsed, new Date(PK_NOW).toISOString());
  assert.equal(ctx.l.signInChallenges.size, 0);
  // The same answer again, with the same token or a new one made for it: not a sign in.
  assert.deepEqual(await ctx.l.finishPasskeySignIn(started.token, credential, '192.0.2.1', {}), { ok: false, reason: 'expired' });
  const second = ctx.l.startPasskeySignIn('192.0.2.1');
  assert.deepEqual(await ctx.l.finishPasskeySignIn(second.token, credential, '192.0.2.1', {}), INVALID);
  // The result is what signIn takes.
  const r = await ctx.l.finishPasskeySignIn(ctx.l.startPasskeySignIn('192.0.2.1').token, '{}', '192.0.2.1');
  assert.equal(r.ok, false);
  const fresh = ctx.l.startPasskeySignIn('192.0.2.1');
  const done = await ctx.l.finishPasskeySignIn(fresh.token, pkAnswer(a, fresh, handle), '192.0.2.1', { deviceId: null });
  const session = await ctx.l.signIn(done.name, { epoch: done.epoch, device: done.device, deviceId: null, ip: '192.0.2.1', via: 'passkey' });
  assert.ok(session);
  assert.equal(ctx.l.sessions.get(session.id).name, 'Bob');
  // The audit line of the new device says how the user signed in, and nothing else is written.
  assert.deepEqual(ctx.events, [['device-added', { user: 'Bob', address: '192.0.2.1', with: 'passkey' }]]);
});

test('passkey sign in: every failure that depends on the user is the same answer, and counts for the address only', async () => {
  const ctx = await passkeyLogin();
  const bob = await enroll(ctx, 'bob');
  const carol = await enroll(ctx, 'carol');
  // A passkey made for another address of the same store: it cannot sign in here.
  const elsewhere = createPasskeys({ siteUrl: 'https://other.example.net', store: ctx.store, now: () => ctx.clock.t });
  const other = await enroll(ctx, 'bob', {}, elsewhere);
  const stranger = new SoftAuthenticator();
  const sha = (text) => crypto.createHash('sha256').update(text).digest();
  const cases = {
    'unknown credential': (st) => pkAnswer(stranger, st, bob.handle),
    'another key under the id': (st) => pkAnswer(new SoftAuthenticator({ id: bob.a.rawId }), st, bob.handle),
    'user verification off': (st) => pkAnswer(bob.a, st, bob.handle, { uv: false }),
    'user presence off': (st) => pkAnswer(bob.a, st, bob.handle, { up: false }),
    'wrong origin': (st) => pkAnswer(bob.a, st, bob.handle, { origin: 'https://evil.example.org' }),
    'wrong rpId hash': (st) => pkAnswer(bob.a, st, bob.handle, { rpIdHash: sha('evil.example.org') }),
    'cross origin frame': (st) => pkAnswer(bob.a, st, bob.handle, { crossOrigin: true }),
    'top origin': (st) => pkAnswer(bob.a, st, bob.handle, { extra: { topOrigin: 'https://evil.example.org' } }),
    'wrong type': (st) => pkAnswer(bob.a, st, bob.handle, { type: 'webauthn.create' }),
    'the handle of another user': (st) => pkAnswer(bob.a, st, carol.handle),
    'a random handle': (st) => pkAnswer(bob.a, st, crypto.randomBytes(32).toString('base64url')),
    'no handle': (st) => pkAnswer(bob.a, st, null),
    'an empty handle': (st) => pkAnswer(bob.a, st, ''),
    'a passkey made for another rpId': (st) => pkAnswer(other.a, st, other.handle),
    'another challenge': (st) => pkAnswer(bob.a, { options: { challenge: ctx.l.startPasskeySignIn('203.0.113.250').options.challenge } }, bob.handle),
    'nothing': () => '{}',
    'not JSON': () => '{',
    'a list': () => [],
  };
  let i = 0;
  for (const [what, make] of Object.entries(cases)) {
    // One address for each, so that the waits of one case do not reach the next.
    const ip = `192.0.2.${++i}`;
    const st = ctx.l.startPasskeySignIn(ip);
    const credential = make(st);
    assert.deepEqual(await ctx.l.finishPasskeySignIn(st.token, credential, ip, {}), INVALID, what);
    assert.equal(ctx.l.addresses.count(ipKey(ip)), 1, `${what} counts for the address`);
  }
  // A user who is gone: the passkey is not found at all.
  const gone = ctx.l.startPasskeySignIn('198.51.100.1');
  const answer = pkAnswer(carol.a, gone, carol.handle);
  await ctx.store.deleteUser('carol', { force: true });
  assert.deepEqual(await ctx.l.finishPasskeySignIn(gone.token, answer, '198.51.100.1', {}), INVALID, 'a deleted user');
  // Never against the user, the name or the credential.
  for (const th of [ctx.l.accounts, ctx.l.codes, ctx.l.codeUsers, ctx.l.devices, ctx.l.reauths]) assert.equal(th.size, 0);
  assert.equal(ctx.l.names.size, 0);
  assert.equal(ctx.l.deviceTurns.size, 0);
  // The failures log has the address only: no user, no credential id, no handle.
  assert.equal(ctx.notes.length, Object.keys(cases).length + 1);
  for (const [event, key, fields] of ctx.notes) {
    assert.equal(event, 'passkey-sign-in-failures');
    assert.match(key, /^ip:/);
    assert.deepEqual(Object.keys(fields), ['address']);
  }
  const text = JSON.stringify([ctx.notes, ctx.events]);
  for (const secret of [bob.a.id, carol.a.id, other.a.id, bob.handle, carol.handle, other.handle]) assert.equal(text.includes(secret), false);
  assert.deepEqual(ctx.events, []);
  // A passkey that works still works after all of that, from another address.
  const ok = ctx.l.startPasskeySignIn('203.0.113.1');
  assert.equal((await ctx.l.finishPasskeySignIn(ok.token, pkAnswer(bob.a, ok, bob.handle), '203.0.113.1', {})).ok, true);
  // And the failures of the user's own address did not hold them back: it is the address that waits.
  assert.equal(ctx.l.codeUsers.count('user:bob'), 0);
});

test('passkey sign in: a failure for a passkey of a user does not hold that user back from anywhere else', async () => {
  const ctx = await passkeyLogin();
  const bob = await enroll(ctx, 'bob');
  // Someone who learned the credential id fails over and over from their own address.
  const bad = new SoftAuthenticator({ id: bob.a.rawId });
  for (let n = 0; n < 40; n++) {
    ctx.clock.t += SIGNIN_BEGIN_INTERVAL_MS;
    const st = ctx.l.startPasskeySignIn('203.0.113.9');
    const r = await ctx.l.finishPasskeySignIn(st.token, pkAnswer(bad, st, bob.handle), '203.0.113.9', {});
    assert.ok(r.reason === 'invalid' || r.reason === 'throttled', r.reason);
  }
  assert.equal(ctx.l.addresses.wait(ipKey('203.0.113.9')) > 0 || ctx.l.addresses.count(ipKey('203.0.113.9')) > 20, true);
  // The owner signs in with the passkey from elsewhere, and with the password too.
  const st = ctx.l.startPasskeySignIn('192.0.2.77');
  assert.equal((await ctx.l.finishPasskeySignIn(st.token, pkAnswer(bob.a, st, bob.handle), '192.0.2.77', {})).ok, true);
  assert.equal((await ctx.l.attempt('bob', 'a good password', '192.0.2.78')).secondFactor, true);
});

test('passkey sign in: a token is good for the address it was made for, for CHALLENGE_MS, and for one answer', async () => {
  const ctx = await passkeyLogin();
  const { a, handle } = await enroll(ctx, 'bob');
  const expired = { ok: false, reason: 'expired' };
  // Another address: expired, and the token is gone for the right one too.
  let st = ctx.l.startPasskeySignIn('192.0.2.1');
  assert.deepEqual(await ctx.l.finishPasskeySignIn(st.token, pkAnswer(a, st, handle), '192.0.2.2', {}), expired);
  assert.deepEqual(await ctx.l.finishPasskeySignIn(st.token, pkAnswer(a, st, handle), '192.0.2.1', {}), expired);
  // The same /64 is the same address; the same IPv4 address in its mapped form too.
  st = ctx.l.startPasskeySignIn('2001:db8:1:2:aaaa::1');
  assert.equal((await ctx.l.finishPasskeySignIn(st.token, pkAnswer(a, st, handle), '2001:db8:1:2:bbbb::9', {})).ok, true);
  // CHALLENGE_MS: one millisecond short is in time, the whole time is not.
  st = ctx.l.startPasskeySignIn('192.0.2.1');
  ctx.clock.t += CHALLENGE_MS - 1;
  assert.equal((await ctx.l.finishPasskeySignIn(st.token, pkAnswer(a, st, handle), '192.0.2.1', {})).ok, true);
  ctx.clock.t += SIGNIN_BEGIN_INTERVAL_MS;
  st = ctx.l.startPasskeySignIn('192.0.2.1');
  ctx.clock.t += CHALLENGE_MS;
  assert.deepEqual(await ctx.l.finishPasskeySignIn(st.token, pkAnswer(a, st, handle), '192.0.2.1', {}), expired);
  assert.equal(ctx.l.signInChallenges.size, 0, 'taken out whatever the result');
  // A clock that went back is not a token that is young.
  st = ctx.l.startPasskeySignIn('192.0.2.1');
  ctx.clock.t -= 60_000;
  assert.deepEqual(await ctx.l.finishPasskeySignIn(st.token, pkAnswer(a, st, handle), '192.0.2.1', {}), expired);
  ctx.clock.t += 60_000;
  // Not tokens at all.
  for (const token of [undefined, null, '', 'x', 42, {}, [], 'A'.repeat(43), `${st.token}x`, st.token.slice(1)]) {
    assert.deepEqual(await ctx.l.finishPasskeySignIn(token, pkAnswer(a, st, handle), '192.0.2.1', {}), expired, String(token));
  }
  // Expired answers are not failures: nothing counts for the address.
  assert.equal(ctx.l.addresses.count(ipKey('192.0.2.1')), 0);
  assert.equal(ctx.notes.length, 0);
});

test('passkey sign in: a change to the user while the check runs ends in expired, never a sign in', async () => {
  const ip = '192.0.2.1';
  const changes = {
    'a role change or a password reset (endUser)': (ctx) => ctx.l.endUser('bob'),
    'a passkey removed': (ctx) => {
      ctx.store.removePasskey('bob', ctx.store.passkeys('bob')[0].ref);
      ctx.l.endUser('bob');
    },
    'a user deleted': (ctx) => {
      ctx.store.deleteUser('bob', { force: true });
      ctx.l.endUser('bob');
    },
    'the second factor reset': (ctx) => {
      ctx.store.resetSecondFactor('bob');
      ctx.l.endUser('bob');
    },
    'a change made by another program': (ctx) => ctx.store.onExternalChange('bob', ['role']),
  };
  for (const [what, change] of Object.entries(changes)) {
    const ctx = await passkeyLogin();
    const { a, handle } = await enroll(ctx, 'bob');
    const st = ctx.l.startPasskeySignIn(ip);
    // Started, not awaited: the check is under way when the change comes.
    const running = ctx.l.finishPasskeySignIn(st.token, pkAnswer(a, st, handle), ip, {});
    change(ctx);
    assert.deepEqual(await running, { ok: false, reason: 'expired' }, what);
    assert.equal(ctx.l.sessions.size, 0, what);
    // Not a failure of the address either: the user changed, the answer was not wrong.
    assert.equal(ctx.l.addresses.count(ipKey(ip)), 0, what);
    assert.equal(ctx.notes.length, 0, what);
    assert.equal(ctx.l.epochOf('bob'), 1, what);
  }
  // Ended after the check, while the used passkey was being saved: signIn itself refuses it.
  const ctx = await passkeyLogin();
  const { a, handle } = await enroll(ctx, 'bob');
  const st = ctx.l.startPasskeySignIn(ip);
  const done = await ctx.l.finishPasskeySignIn(st.token, pkAnswer(a, st, handle), ip, {});
  assert.equal(done.ok, true);
  ctx.l.endUser('bob');
  assert.equal(await ctx.l.signIn(done.name, { epoch: done.epoch, device: done.device, ip, via: 'passkey' }), null);
  assert.equal(ctx.l.sessions.size, 0);
});

test('passkey sign in: a counter that went back is refused, and is an audit line with the label of the passkey and the step', async () => {
  const ctx = await passkeyLogin();
  const { a, handle } = await enroll(ctx, 'bob', { counter: 10 });
  const ip = '192.0.2.1';
  let st = ctx.l.startPasskeySignIn(ip);
  assert.equal((await ctx.l.finishPasskeySignIn(st.token, pkAnswer(a, st, handle), ip, {})).ok, true);
  ctx.clock.t += SIGNIN_BEGIN_INTERVAL_MS;
  st = ctx.l.startPasskeySignIn(ip);
  assert.deepEqual(await ctx.l.finishPasskeySignIn(st.token, pkAnswer(a, st, handle, { counter: 4 }), ip, {}), INVALID);
  assert.deepEqual(ctx.events, [['passkey-counter-error', { user: 'bob', passkey: 'Passkey 1', address: ip, step: 'sign-in' }]]);
  assert.equal(ctx.store.passkeyById('bob', a.id).counter, 11, 'the counter stays');
  assert.equal(ctx.l.addresses.count(ipKey(ip)), 1);
  assert.equal(JSON.stringify(ctx.events).includes(a.id), false);
  assert.equal(JSON.stringify(ctx.events).includes(handle), false);
  // Synced passkeys always send 0, which is fine.
  const synced = await enroll(ctx, 'carol', { counter: 0, backupEligible: true, backedUp: true });
  for (let n = 0; n < 3; n++) {
    ctx.clock.t += SIGNIN_BEGIN_INTERVAL_MS;
    const s2 = ctx.l.startPasskeySignIn('192.0.2.2');
    assert.equal((await ctx.l.finishPasskeySignIn(s2.token, pkAnswer(synced.a, s2, synced.handle), '192.0.2.2', {})).ok, true);
  }
  assert.equal(ctx.events.length, 1);
});

test('passkey sign in: 500 counter errors write one audit line a day for the user and passkey, and the rest are failures.log notes', async () => {
  const ctx = await passkeyLogin();
  const { a, handle } = await enroll(ctx, 'bob', { counter: 10 });
  const other = await enroll(ctx, 'carol', { counter: 10 });
  for (let n = 0; n < 500; n++) {
    const ip = `198.51.${Math.floor(n / 250)}.${(n % 250) + 1}`;
    ctx.clock.t += SIGNIN_BEGIN_INTERVAL_MS;
    const st = ctx.l.startPasskeySignIn(ip);
    assert.deepEqual(await ctx.l.finishPasskeySignIn(st.token, pkAnswer(a, st, handle, { counter: 4 }), ip, {}), INVALID);
  }
  const lines = () => ctx.events.filter(([e]) => e === 'passkey-counter-error');
  assert.equal(lines().length, 1);
  assert.equal(ctx.notes.filter(([e]) => e === 'passkey-counter-error').length, 499);
  // Another passkey has its own line, and the first one is a line again after a day.
  const st = ctx.l.startPasskeySignIn('203.0.113.9');
  await ctx.l.finishPasskeySignIn(st.token, pkAnswer(other.a, st, other.handle, { counter: 4 }), '203.0.113.9', {});
  assert.equal(lines().length, 2);
  ctx.clock.t += PASSKEY_AUDIT_MS;
  const st2 = ctx.l.startPasskeySignIn('203.0.113.10');
  await ctx.l.finishPasskeySignIn(st2.token, pkAnswer(a, st2, handle, { counter: 4 }), '203.0.113.10', {});
  assert.equal(lines().length, 3);
});

test('passkey sign in: the waits of the address come before the check; a known device of the passkey\'s owner is held back by its own wait only', async () => {
  const ctx = await passkeyLogin();
  const bob = await enroll(ctx, 'bob');
  const carol = await enroll(ctx, 'carol');
  const ip = '203.0.113.5';
  const device = newDeviceId();
  await ctx.store.addDevice('bob', deviceHash(device));
  const others = newDeviceId();
  await ctx.store.addDevice('carol', deviceHash(others));
  for (let n = 0; n < 30; n++) ctx.l.addresses.fail(ipKey(ip));
  // Throttled without the passkey being looked at: its counter does not move, and the token is used up.
  let st = ctx.l.startPasskeySignIn(ip);
  const answer = pkAnswer(bob.a, st, bob.handle);
  const r = await ctx.l.finishPasskeySignIn(st.token, answer, ip, {});
  assert.equal(r.reason, 'throttled');
  assert.ok(r.retryAfterMs > 0);
  assert.equal(ctx.store.passkeyById('bob', bob.a.id).lastUsed, null);
  assert.deepEqual(await ctx.l.finishPasskeySignIn(st.token, answer, ip, {}), { ok: false, reason: 'expired' });
  const before = ctx.l.addresses.count(ipKey(ip));
  assert.equal(ctx.notes.length, 0, 'a throttled try is not a failure');
  // Someone else's device, or a made up one, does not help.
  for (const deviceId of [others, newDeviceId(), 'junk', null]) {
    ctx.clock.t += SIGNIN_BEGIN_INTERVAL_MS;
    st = ctx.l.startPasskeySignIn(ip);
    assert.equal((await ctx.l.finishPasskeySignIn(st.token, pkAnswer(bob.a, st, bob.handle), ip, { deviceId })).reason, 'throttled', String(deviceId));
  }
  assert.equal(ctx.l.addresses.count(ipKey(ip)), before);
  // Bob's own device gets past the address, and the answer names it.
  ctx.clock.t += SIGNIN_BEGIN_INTERVAL_MS;
  st = ctx.l.startPasskeySignIn(ip);
  assert.deepEqual(await ctx.l.finishPasskeySignIn(st.token, pkAnswer(bob.a, st, bob.handle), ip, { deviceId: device }), { ok: true, name: 'bob', epoch: 0, device: deviceHash(device), ref: ctx.store.passkeyById('bob', bob.a.id).ref });
  // A wrong answer with the device counts for the device (and the address), not the user.
  ctx.clock.t += SIGNIN_BEGIN_INTERVAL_MS;
  st = ctx.l.startPasskeySignIn(ip);
  assert.deepEqual(await ctx.l.finishPasskeySignIn(st.token, pkAnswer(bob.a, st, bob.handle, { uv: false }), ip, { deviceId: device }), INVALID);
  assert.equal(ctx.l.pkDevices.count(`pkdevice:${deviceHash(device)}`), 1);
  assert.equal(ctx.l.devices.count(`device:${deviceHash(device)}`), 0, 'the wait of the device for passwords is not touched');
  assert.equal(ctx.l.codeUsers.size, 0);
  // Enough of them and the device waits, though the address would not.
  const ip2 = '198.51.100.40';
  for (let n = 0; n < 12; n++) ctx.l.pkDevices.fail(`pkdevice:${deviceHash(device)}`);
  ctx.clock.t += SIGNIN_BEGIN_INTERVAL_MS;
  st = ctx.l.startPasskeySignIn(ip2);
  assert.equal((await ctx.l.finishPasskeySignIn(st.token, pkAnswer(bob.a, st, bob.handle), ip2, { deviceId: device })).reason, 'throttled');
  // Carol's passkey is not held back by that, nor by the wait of bob's device.
  ctx.clock.t += SIGNIN_BEGIN_INTERVAL_MS;
  st = ctx.l.startPasskeySignIn(ip2);
  assert.equal((await ctx.l.finishPasskeySignIn(st.token, pkAnswer(carol.a, st, carol.handle), ip2, { deviceId: device })).ok, true);
  // A right passkey is not held back by the user's wrong codes either.
  for (let n = 0; n < 60; n++) ctx.l.codeUsers.fail('user:carol');
  assert.ok(ctx.l.codeUsers.wait('user:carol') > 0);
  ctx.clock.t += SIGNIN_BEGIN_INTERVAL_MS;
  st = ctx.l.startPasskeySignIn('192.0.2.200');
  assert.equal((await ctx.l.finishPasskeySignIn(st.token, pkAnswer(carol.a, st, carol.handle), '192.0.2.200', {})).ok, true);
});

test('passkey sign in: starting is paced per address, with a burst and no backlog; and the open tokens are capped, the oldest going first', async () => {
  const ctx = await passkeyLogin();
  const ip = '192.0.2.1';
  const tokens = [];
  for (let n = 0; n < SIGNIN_BEGIN_BURST; n++) tokens.push(ctx.l.startPasskeySignIn(ip).token);
  const paced = ctx.l.startPasskeySignIn(ip);
  assert.equal(paced.ok, false);
  assert.equal(paced.reason, 'paced');
  assert.ok(paced.retryAfterMs > 0 && paced.retryAfterMs <= SIGNIN_BEGIN_INTERVAL_MS, String(paced.retryAfterMs));
  assert.equal(Object.hasOwn(paced, 'token'), false);
  // Per address: the first five of ten are gone, the last five are there.
  assert.deepEqual([...ctx.l.signInChallenges.keys()], tokens.slice(-SIGNIN_CHALLENGES_PER_ADDRESS));
  assert.equal(SIGNIN_CHALLENGES_PER_ADDRESS, 5);
  // Another address, and another IPv6 /64, have their own pace and their own five.
  assert.ok(ctx.l.startPasskeySignIn('192.0.2.2').token);
  assert.ok(ctx.l.startPasskeySignIn('2001:db8::1').token);
  assert.equal(ctx.l.startPasskeySignIn('2001:db8::2').ok, undefined, 'the same /64 shares its pace');
  assert.equal(ctx.l.signInChallenges.size, SIGNIN_CHALLENGES_PER_ADDRESS + 3);
  // One more turn each interval.
  ctx.clock.t += SIGNIN_BEGIN_INTERVAL_MS;
  assert.ok(ctx.l.startPasskeySignIn(ip).token);
  assert.equal(ctx.l.startPasskeySignIn(ip).reason, 'paced');
  // Open tokens in all: the oldest go, whoever they are for.
  const many = await passkeyLogin();
  const first = many.l.startPasskeySignIn('10.0.0.1');
  const all = [];
  for (let n = 1; n < SIGNIN_CHALLENGES_MAX + 20; n++) all.push(many.l.startPasskeySignIn(`10.${(n >> 8) & 255}.${n & 255}.2`));
  assert.ok(all.every((r) => typeof r.token === 'string'));
  assert.equal(many.l.signInChallenges.size, SIGNIN_CHALLENGES_MAX);
  assert.equal(many.l.signInChallenges.has(first.token), false, 'the oldest went first');
  assert.equal(many.l.signInChallenges.has(all.at(-1).token), true);
  assert.equal(many.l.signInChallenges.has(all[0].token), false);
  // Old ones are swept by the next start, not kept for ever.
  many.clock.t += CHALLENGE_MS;
  many.l.startPasskeySignIn('192.0.2.1');
  assert.equal(many.l.signInChallenges.size, 1);
});

test('passkey sign in: off gives null and unavailable; so do passkeys that are off, and a store that cannot be read, which also clears the tokens', async () => {
  const off = await passkeyLogin({ settings: { passkeySignIn: false } });
  const { a, handle } = await enroll(off, 'bob');
  assert.equal(off.l.passkeySignIn, false);
  assert.equal(off.l.startPasskeySignIn('192.0.2.1'), null);
  const fake = { options: { challenge: 'x' } };
  assert.deepEqual(await off.l.finishPasskeySignIn('A'.repeat(43), pkAnswer(a, fake, handle), '192.0.2.1', {}), { ok: false, reason: 'unavailable' });
  assert.equal(off.l.signInChallenges.size, 0);
  // A settings object without the field (older callers) is on.
  assert.equal((await passkeyLogin({ settings: { passkeySignIn: undefined } })).l.passkeySignIn, true);
  // No passkeys at this site: off, whatever the switch says.
  const none = await passkeyLogin({ siteUrl: null });
  assert.equal(none.l.passkeySignIn, false);
  assert.equal(none.l.startPasskeySignIn('192.0.2.1'), null);
  assert.deepEqual(await none.l.finishPasskeySignIn('A'.repeat(43), {}, '192.0.2.1', {}), { ok: false, reason: 'unavailable' });

  const ctx = await passkeyLogin();
  const bob = await enroll(ctx, 'bob');
  const ip = '192.0.2.1';
  const before = ctx.l.startPasskeySignIn(ip);
  const answer = pkAnswer(bob.a, before, bob.handle);
  const err = new Error('cannot be read');
  ctx.store.unreadable = err;
  ctx.store.onUnreadable(err);
  assert.equal(ctx.l.signInChallenges.size, 0);
  assert.deepEqual(ctx.l.startPasskeySignIn(ip), { ok: false, reason: 'unavailable' });
  assert.deepEqual(await ctx.l.finishPasskeySignIn(before.token, answer, ip, {}), { ok: false, reason: 'unavailable' });
  assert.equal(ctx.l.addresses.count(ipKey(ip)), 0);
  // Lost while the check ran: expired, and no sign in.
  ctx.store.unreadable = null;
  ctx.clock.t += SIGNIN_BEGIN_INTERVAL_MS * 2;
  const st = ctx.l.startPasskeySignIn(ip);
  const running = ctx.l.finishPasskeySignIn(st.token, pkAnswer(bob.a, st, bob.handle), ip, {});
  ctx.store.unreadable = err;
  assert.deepEqual(await running, { ok: false, reason: 'expired' });
  ctx.store.unreadable = null;
  ctx.clock.t += SIGNIN_BEGIN_INTERVAL_MS * 2;
  const back = ctx.l.startPasskeySignIn(ip);
  assert.equal((await ctx.l.finishPasskeySignIn(back.token, pkAnswer(bob.a, back, bob.handle), ip, {})).ok, true);
});

test('passkey sign in: a device made by a passkey alone is not a known device for password tries, and a password sign in there gets a device of its own', async () => {
  const ctx = await passkeyLogin();
  const ip = '203.0.113.9';
  const epoch = ctx.l.epochOf('bob');
  const made = await ctx.l.signIn('bob', { epoch, ip, via: 'passkey' });
  assert.match(made.deviceId, /^pk[A-Za-z0-9_-]{20}$/);
  assert.equal(ctx.store.hasDevice('bob', deviceHash(made.deviceId)), true);
  assert.equal(ctx.l.sessions.map.get(made.id).via, 'passkey');
  assert.equal(ctx.l.sessions.map.get(made.id).authAt, -Infinity);
  // Wrong passwords with that device count as a stranger's: for the address and the name, not the device.
  for (let n = 0; n < 3; n++) assert.equal((await ctx.l.attempt('bob', 'not it', ip, { device: made.deviceId })).reason, 'invalid');
  assert.equal(ctx.l.devices.count(`device:${deviceHash(made.deviceId)}`), 0);
  assert.equal(ctx.l.addresses.count(ipKey(ip)), 3);
  // The right password there is no device either: the sign in that follows makes a new one.
  const r = await ctx.l.attempt('bob', 'a good password', ip, { device: made.deviceId });
  assert.equal(r.ok, true);
  assert.equal(r.device, null);
  const again = await ctx.l.signIn('bob', { epoch, device: r.device, deviceId: made.deviceId, ip });
  assert.doesNotMatch(again.deviceId, /^pk/);
  assert.equal(ctx.l.sessions.map.get(again.id).via, 'password');
  assert.notEqual(again.deviceId, made.deviceId);
  // A passkey sign in on its own device reuses it.
  const reused = await ctx.l.signIn('bob', { epoch, device: deviceHash(made.deviceId), deviceId: made.deviceId, ip, via: 'passkey' });
  assert.equal(reused.deviceId, made.deviceId);
});

test('known devices: the wrong passwords of all of a user\'s known devices together are held back past a ceiling, and a stranger cannot use it to lock the user out', async () => {
  const ctx = await passkeyLogin();
  const device = newDeviceId();
  await ctx.store.addDevice('bob', deviceHash(device));
  // A user has at most a few known devices, each held back by its own waits; the ceiling is for all
  // of them together. Wrong passwords from addresses that hold no known device never count for it.
  for (let n = 0; n < 3; n++) assert.equal((await ctx.l.attempt('bob', 'not it', `198.51.100.${n}`, { device: 'x'.repeat(22) })).reason, 'invalid');
  assert.equal(ctx.l.deviceUsers.count('devuser:user:bob'), 0);
  // Measured: the guesses a known device gets before and after the ceiling is reached, from fresh addresses.
  let guesses = 0;
  for (let n = 0; n < DEVICE_USER_CEILING; n++) ctx.l.deviceUsers.fail('devuser:user:bob');
  const before = await ctx.l.attempt('bob', 'not it', '203.0.113.1', { device });
  assert.equal(before.reason, 'invalid');
  assert.equal(ctx.l.deviceUsers.count('devuser:user:bob'), DEVICE_USER_CEILING + 1);
  ctx.l.devices.clear(`device:${deviceHash(device)}`);
  for (let n = 0; n < 5; n++) {
    const r = await ctx.l.attempt('bob', 'not it', `203.0.113.${10 + n}`, { device });
    if (r.reason === 'invalid') guesses++;
    else assert.equal(r.reason, 'throttled');
  }
  assert.equal(guesses, 0, 'past the ceiling the known device is held back');
  // The right password from the known device waits too, but a new address, a stranger and the owner elsewhere do not.
  assert.equal((await ctx.l.attempt('bob', 'a good password', '203.0.113.50', { device })).reason, 'throttled');
  assert.equal((await ctx.l.attempt('bob', 'a good password', '198.51.100.200', {})).ok, true);
});

test('passkey sign in: it clears the passkey wait of the device only, and leaves the waits of the address, the name and the device for passwords as they are', async () => {
  const ctx = await passkeyLogin();
  const bob = await enroll(ctx, 'bob');
  const ip = '203.0.113.20';
  const device = newDeviceId();
  await ctx.store.addDevice('bob', deviceHash(device));
  for (let n = 0; n < 8; n++) ctx.l.addresses.fail(ipKey(ip));
  ctx.l.devices.fail(`device:${deviceHash(device)}`);
  ctx.l.pkDevices.fail(`pkdevice:${deviceHash(device)}`);
  ctx.l.accounts.fail(`user:bob|${ipKey(ip)}`);
  const st = ctx.l.startPasskeySignIn(ip);
  assert.equal((await ctx.l.finishPasskeySignIn(st.token, pkAnswer(bob.a, st, bob.handle), ip, { deviceId: device })).ok, true);
  assert.equal(ctx.l.addresses.count(ipKey(ip)), 8);
  assert.equal(ctx.l.accounts.count(`user:bob|${ipKey(ip)}`), 1);
  assert.equal(ctx.l.pkDevices.count(`pkdevice:${deviceHash(device)}`), 0, 'the passkey wait of the device is cleared');
  assert.equal(ctx.l.devices.count(`device:${deviceHash(device)}`), 1, 'the wait of the device for passwords is not');
});

test('passkey sign in: begins are paced for a whole /56 and a whole /48, with larger bursts, and a refused one gives back the turns taken before it', async () => {
  const ctx = await passkeyLogin();
  const l = ctx.l;
  // Many /64s of one /56: each has turns of its own, the /56 runs out after its burst.
  let ok = 0;
  let denied = null;
  for (let n = 0; n < SIGNIN_NET56_BURST + 5; n++) {
    const r = l.startPasskeySignIn(`2001:db8:1:ab${n.toString(16).padStart(2, '0')}::1`);
    if (r.token) ok++;
    else denied ??= r;
  }
  assert.equal(ok, SIGNIN_NET56_BURST);
  assert.equal(denied.reason, 'paced');
  assert.ok(denied.retryAfterMs > 0 && denied.retryAfterMs <= SIGNIN_NET56_INTERVAL_MS);
  // The refused address kept its own turn (it can begin after the wait with its full burst).
  const refused = '2001:db8:1:abff::1';
  assert.equal(l.signInTurns.take(ipKey(refused)).ok, true);
  // Another /56 of the same /48 still works; the /48 runs out after its burst, over all its /56s.
  let total = SIGNIN_NET56_BURST;
  let stopped = null;
  for (let block = 0; block < 6 && !stopped; block++) {
    for (let n = 0; n < SIGNIN_NET56_BURST && !stopped; n++) {
      if (block === 0) continue;
      const r = l.startPasskeySignIn(`2001:db8:1:${(0xb0 + block).toString(16)}${n.toString(16).padStart(2, '0')}::1`);
      if (r.token) total++;
      else stopped = r;
    }
  }
  assert.equal(total, SIGNIN_NET48_BURST);
  assert.equal(stopped.reason, 'paced');
  // Past the wait, begins work again, and an address of another network was never held back.
  assert.ok(l.startPasskeySignIn('2001:db8:2::1').token);
  ctx.clock.t += 10_000;
  assert.ok(l.startPasskeySignIn('2001:db8:1:ab01::9').token);
});

test('passkey sign in: with the token map full, the oldest token of the network that holds the most goes, not the oldest of all', async () => {
  const ctx = await passkeyLogin();
  const l = ctx.l;
  for (let n = 0; n < SIGNIN_CHALLENGES_MAX; n++) {
    const net = n < 100 ? 'other' : 'flood';
    l.signInChallenges.set(`t${n}`, { challenge: 'c', addressKey: `a${n}`, netKey: net, created: ctx.clock.t });
  }
  const r = l.startPasskeySignIn('192.0.2.77');
  assert.ok(r.token);
  assert.equal(l.signInChallenges.size, SIGNIN_CHALLENGES_MAX);
  // The oldest of all (t0, of the small network) is still there; the oldest of the flood went.
  assert.equal(l.signInChallenges.has('t0'), true);
  assert.equal(l.signInChallenges.has('t100'), false);
});

// ---- a planted passkey cannot push the owner out (sessions, devices, pacing, the audit log) ----

test('sessions: passkey sessions have a cap of their own and push out only each other, whatever the sign ins', () => {
  let t = 0;
  const s = new Sessions({ idleMs: 10 * MIN, maxAgeMs: 30 * MIN, max: 1000, now: () => t });
  const mine = [];
  for (let i = 0; i < 20; i++) {
    t += 1;
    mine.push(s.create('bob'));
  }
  for (let i = 0; i < 25; i++) {
    t += 1;
    s.create('Bob', { via: 'passkey' });
  }
  assert.equal(s.list('bob').filter((x) => !mine.includes(x.id)).length, MAX_PASSKEY_SESSIONS_PER_USER, 'at most five passkey sessions');
  assert.ok(mine.every((id) => s.get(id)), 'not one session made with the password ended');
  // A password sign in past the cap pushes out the user's least used one, as before.
  s.create('bob');
  assert.equal(s.get(mine[0]), null);
});

test('sessions: with the cap of all sessions reached, a passkey sign in ends a passkey session of its user, or someone else\'s, never its user\'s password session', () => {
  let t = 0;
  const s = new Sessions({ idleMs: 10 * MIN, maxAgeMs: 30 * MIN, max: 6, now: () => t });
  const pw = [s.create('bob'), s.create('bob'), s.create('bob'), s.create('bob')];
  s.create('carol');
  s.create('carol');
  for (let i = 0; i < 10; i++) {
    t += 1;
    s.create('bob', { via: 'passkey' });
  }
  assert.ok(pw.every((id) => s.get(id)), 'bob\'s password sessions all stay');
  assert.equal(s.size, 6);
  // Bob has the most; with no passkey session of his own to push out, one of carol's goes (not his).
  const only = new Sessions({ idleMs: 10 * MIN, maxAgeMs: 30 * MIN, max: 4, now: () => t });
  const bobs = [only.create('bob'), only.create('bob'), only.create('bob')];
  const carol = only.create('carol');
  only.create('bob', { via: 'passkey' });
  assert.ok(bobs.every((id) => only.get(id)));
  assert.equal(only.get(carol), null);
});

test('passkey sign in: 25 sign ins by passkey do not end a session made with the password', async () => {
  const ctx = await passkeyLogin();
  const epoch = ctx.l.epochOf('bob');
  const first = await ctx.l.signIn('bob', { epoch, ip: '203.0.113.1' });
  const others = [];
  for (let i = 0; i < 19; i++) others.push(await ctx.l.signIn('bob', { epoch, ip: '203.0.113.1' }));
  for (let i = 0; i < 25; i++) {
    ctx.clock.t += 1;
    assert.ok(await ctx.l.signIn('bob', { epoch, ip: '198.51.100.7', via: 'passkey' }));
  }
  assert.ok(ctx.l.sessions.get(first.id), 'the first session of the password is still there');
  assert.ok(others.every((x) => ctx.l.sessions.get(x.id)));
  assert.equal(ctx.l.sessions.list('bob').length, 20 + MAX_PASSKEY_SESSIONS_PER_USER);
});

test('passkey sign in: 15 sign ins without a device cookie do not make the user forget a device made with the password', async () => {
  const ctx = await passkeyLogin();
  const epoch = ctx.l.epochOf('bob');
  const made = [];
  for (let i = 0; i < 8; i++) {
    const id = newDeviceId();
    await ctx.store.addDevice('bob', deviceHash(id));
    made.push(deviceHash(id));
    ctx.clock.t += 1000;
  }
  for (let i = 0; i < 15; i++) {
    ctx.clock.t += 1000;
    const r = await ctx.l.signIn('bob', { epoch, ip: '198.51.100.7', via: 'passkey' });
    assert.match(r.deviceId, /^pk/);
    assert.ok(made.every((h) => ctx.store.hasDevice('bob', h)), `after sign in ${i + 1}`);
  }
  const pk = ctx.store.devices('bob').filter((d) => !made.includes(d.hash));
  assert.equal(pk.length, 2, 'only what room is left: 8 + 2 of the 10');
  // With the list full of devices made with the password, a new passkey device is not kept at all.
  for (const h of [newDeviceId(), newDeviceId()]) await ctx.store.addDevice('bob', deviceHash(h));
  const none = await ctx.l.signIn('bob', { epoch, ip: '198.51.100.7', via: 'passkey' });
  assert.ok(none.id);
  assert.equal(ctx.store.devices('bob').length, MAX_DEVICES);
  assert.ok(made.every((h) => ctx.store.hasDevice('bob', h)));
});

test('passkey sign in: at most three devices made by a passkey, pushing out each other; a password device pushes those out first', async () => {
  const ctx = await passkeyLogin();
  const epoch = ctx.l.epochOf('bob');
  const ids = [];
  for (let i = 0; i < 6; i++) {
    ctx.clock.t += 1000;
    ids.push((await ctx.l.signIn('bob', { epoch, ip: '198.51.100.7', via: 'passkey' })).deviceId);
  }
  assert.equal(ctx.store.devices('bob').length, MAX_PASSKEY_DEVICES);
  assert.deepEqual(ids.slice(3).map((id) => ctx.store.hasDevice('bob', deviceHash(id))), [true, true, true]);
  assert.deepEqual(ids.slice(0, 3).map((id) => ctx.store.hasDevice('bob', deviceHash(id))), [false, false, false]);
  // Seven devices of the password fill the rest; the next one takes the place of a passkey device.
  const pw = [];
  for (let i = 0; i < 7; i++) {
    ctx.clock.t += 1000;
    pw.push(deviceHash((await ctx.l.signIn('bob', { epoch, ip: '203.0.113.1' })).deviceId));
  }
  assert.equal(ctx.store.devices('bob').length, MAX_DEVICES);
  ctx.clock.t += 1000;
  const next = await ctx.l.signIn('bob', { epoch, ip: '203.0.113.1' });
  assert.equal(ctx.store.devices('bob').length, MAX_DEVICES);
  assert.ok(pw.every((h) => ctx.store.hasDevice('bob', h)) && ctx.store.hasDevice('bob', deviceHash(next.deviceId)));
  assert.equal(ctx.store.devices('bob').filter((d) => ids.some((id) => deviceHash(id) === d.hash)).length, 2);
});

test('passkey sign in: after a restart the cap of three still holds for the devices whose browsers come back, and no password device is forgotten', async () => {
  const { l, store, keys, users, dataDir } = await keyedLogin();
  const pw = [];
  for (let i = 0; i < 4; i++) pw.push(deviceHash((await l.signIn('bob', { epoch: l.epochOf('bob') })).deviceId));
  const cookies = [];
  for (let i = 0; i < 3; i++) cookies.push((await l.signIn('bob', { epoch: l.epochOf('bob'), via: 'passkey' })).deviceId);
  assert.equal(store.devices('bob').length, 7);
  store.close();
  // A restart: the tags are not on disk, so a new store does not know which devices those are.
  const again = await UserStore.open({ dataDir, configUsers: users, keys, warn: () => {} });
  const l2 = createLogin({ users, store: again, hasher: fakeHasher, audit: { write: async () => {}, flush: async () => {} }, log: () => {}, sleep: async () => {} });
  const epoch = l2.epochOf('bob');
  // The browsers that come back with their cookie are tagged again.
  for (const deviceId of cookies) assert.ok(await l2.signIn('bob', { epoch, device: deviceHash(deviceId), deviceId, via: 'passkey' }));
  assert.equal(again.devices('bob').length, 7);
  const made = [];
  for (let i = 0; i < 3; i++) made.push((await l2.signIn('bob', { epoch, via: 'passkey' })).deviceId);
  const left = again.devices('bob').map((d) => d.hash);
  assert.ok(pw.every((h) => left.includes(h)), 'no device made with the password is forgotten');
  assert.deepEqual(left.filter((h) => !pw.includes(h)).sort(), made.map(deviceHash).sort(), 'only the three newest passkey devices are left');
  assert.equal(left.length, 7);
  again.close();
});

test('passkey sign in: 100 sign ins when the list is full of devices made with the password write at most one audit line', async () => {
  const ctx = await passkeyLogin();
  await ctx.store.setRole('bob', 'admin', { force: true });
  await enroll(ctx, 'bob');
  const ref = ctx.store.passkeys('bob')[0].ref;
  const epoch = ctx.l.epochOf('bob');
  const old = [];
  for (let i = 0; i < MAX_DEVICES; i++) {
    const h = deviceHash(newDeviceId());
    await ctx.store.addDevice('bob', h);
    old.push(h);
  }
  ctx.clock.t += 3 * 86_400_000;
  for (let i = 0; i < 100; i++) {
    ctx.clock.t += 1000;
    assert.ok(await ctx.l.signIn('bob', { epoch, ip: '198.51.100.7', via: 'passkey', ref }));
  }
  assert.deepEqual(ctx.store.devices('bob').map((d) => d.hash), old);
  assert.equal(ctx.events.filter(([e]) => e === 'device-added').length, 0, 'nothing was added');
  assert.ok(ctx.events.length <= 1, JSON.stringify(ctx.events));
  assert.equal(ctx.notes.filter(([e]) => e === 'device-added').length, 100);
});

test('device ids: those made for the password never start with the passkey prefix, those for a passkey always do', () => {
  for (let i = 0; i < 60_000; i++) assert.doesNotMatch(newDeviceId(), /^pk/);
  for (let i = 0; i < 100; i++) assert.match(newDeviceId(true), /^pk[A-Za-z0-9_-]{20}$/);
  assert.equal(newDeviceId().length, 22);
});

test('passkey sign in: successful sign ins are paced per user, with a 3 burst and a minute each; the password and other users are not held back', async () => {
  const ctx = await passkeyLogin();
  const bob = await enroll(ctx, 'bob');
  const carol = await enroll(ctx, 'carol');
  const sign = async (who, ip) => {
    const st = ctx.l.startPasskeySignIn(ip);
    return ctx.l.finishPasskeySignIn(st.token, pkAnswer(who.a, st, who.handle), ip, {});
  };
  let n = 0;
  const ip = () => `198.51.100.${(n++ % 200) + 1}`;
  for (let i = 0; i < PASSKEY_SIGNIN_BURST; i++) assert.equal((await sign(bob, ip())).ok, true, `sign in ${i + 1}`);
  const refused = await sign(bob, ip());
  assert.equal(refused.ok, false);
  assert.equal(refused.reason, 'paced');
  assert.ok(refused.retryAfterMs > 0 && refused.retryAfterMs <= PASSKEY_SIGNIN_INTERVAL_MS);
  assert.deepEqual(ctx.notes.filter(([e]) => e === 'passkey-sign-in-paced').map(([, k]) => k), ['user:bob']);
  // A refused one is no failed try for the address or the name, and the password is not held back.
  assert.equal(ctx.l.addresses.size, 0);
  assert.equal((await ctx.l.attempt('bob', 'a good password', '203.0.113.60')).ok, true);
  assert.equal((await sign(carol, ip())).ok, true, 'another user\'s passkey is not held back');
  // A minute later one more.
  ctx.clock.t += PASSKEY_SIGNIN_INTERVAL_MS;
  assert.equal((await sign(bob, ip())).ok, true);
  assert.equal((await sign(bob, ip())).reason, 'paced');
  // Wrong answers do not take a turn.
  ctx.clock.t += PASSKEY_SIGNIN_INTERVAL_MS * 3;
  for (let i = 0; i < 5; i++) {
    const at = ip();
    const st = ctx.l.startPasskeySignIn(at);
    assert.deepEqual(await ctx.l.finishPasskeySignIn(st.token, pkAnswer(bob.a, st, bob.handle, { uv: false }), at, {}), INVALID);
  }
  assert.equal((await sign(bob, ip())).ok, true, 'the turns were all still there');
});

test('passkey sign in: 1,000 sign ins of an admin write one passkey-sign-in audit line a day for the user and passkey, the rest are counted in failures.log', async () => {
  const ctx = await passkeyLogin();
  await ctx.store.setRole('bob', 'admin', { force: true });
  await enroll(ctx, 'bob');
  const ref = ctx.store.passkeys('bob')[0].ref;
  const epoch = ctx.l.epochOf('bob');
  const lines = () => ctx.events.filter(([e]) => e === 'passkey-sign-in');
  for (let i = 0; i < 1000; i++) {
    ctx.clock.t += 1000;
    assert.ok(await ctx.l.signIn('bob', { epoch, ip: '198.51.100.7', via: 'passkey', ref }));
  }
  assert.equal(lines().length, 1);
  assert.equal(lines()[0][1].passkey, ctx.store.passkeyByRef('bob', ref).name);
  assert.equal(ctx.notes.filter(([e]) => e === 'passkey-sign-in').length, 999);
  // A day later: one more. Another passkey of the same user is its own.
  ctx.clock.t += PASSKEY_AUDIT_MS;
  // (The devices of yesterday are forgotten, so that their being pushed out is no audit line of its own.)
  ctx.store.dropDevices('bob');
  await ctx.l.signIn('bob', { epoch, ip: '198.51.100.7', via: 'passkey', ref });
  await ctx.l.signIn('bob', { epoch, ip: '198.51.100.7', via: 'passkey', ref });
  assert.equal(lines().length, 2);
  await ctx.l.signIn('bob', { epoch, ip: '198.51.100.7', via: 'passkey', ref: 'f'.repeat(16) });
  assert.equal(lines().length, 3);
  // A viewer's are never audit lines.
  const carol = await ctx.l.signIn('carol', { epoch: ctx.l.epochOf('carol'), ip: '198.51.100.7', via: 'passkey', ref });
  assert.ok(carol);
  assert.equal(lines().length, 3);
});

test('sessions: only a session made with a passkey alone is held back from reads that need the password, until it is given', () => {
  const sessions = new Sessions({ idleMs: 60_000, maxAgeMs: 600_000, max: 10 });
  const byPassword = sessions.map.get(sessions.create('bob'));
  const byPasskey = sessions.map.get(sessions.create('bob', { via: 'passkey' }));
  assert.equal(byPassword.passwordGiven, true);
  assert.equal(byPasskey.passwordGiven, false);
  assert.equal(needsPassword(byPassword), false);
  assert.equal(needsPassword(byPasskey), true);
  // Given in this session (reauth sets it): open for the rest of the session, however old the sign in.
  byPasskey.passwordGiven = true;
  byPasskey.authAt = 1;
  assert.equal(needsPassword(byPasskey), false);
  // Only the boolean true counts, and a record without the field (kept from before) is a passkey one held back.
  for (const v of [undefined, false, 1, 'true', null]) assert.equal(needsPassword({ via: 'passkey', passwordGiven: v }), true, String(v));
  assert.equal(needsPassword({ via: 'password' }), false);
});
