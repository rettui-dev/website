import test from 'node:test';
import assert from 'node:assert/strict';
import { Busy, MAX_QUEUED_HASHES, Sessions, Throttle, clientIp, cookieValue, createLogin, hashGate, ipKey, isFormType, normalIp, sameOrigin } from '../lib/login.js';
import { DEFAULTS, hashPassword, parsePhc } from '../lib/password.js';
import { fakeHasher } from './helpers/fake-hasher.js';

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

test('throttle: a full map never pushes out a key that is still waiting', () => {
  let t = 0;
  const th = new Throttle({ free: 1, baseMs: 1000, maxMs: 60_000, maxEntries: 3, now: () => t });
  // A locked key, then the map filled with keys that are waiting too.
  th.fail('locked');
  th.fail('locked');
  assert.equal(th.wait('locked'), 1000);
  for (const k of ['a', 'b']) {
    th.fail(k);
    th.fail(k);
  }
  assert.equal(th.size, 3);
  // A flood of new keys: none gets in, each is told to wait, and the locked key stays locked.
  for (let i = 0; i < 100; i++) {
    assert.ok(th.wait(`new${i}`) > 0);
    th.fail(`new${i}`);
  }
  assert.equal(th.size, 3);
  assert.equal(th.wait('locked'), 1000);
  assert.equal(th.wait('new0'), 1000, 'the wait is until the first entry may go');
  // A known key still counts on.
  th.fail('locked');
  assert.equal(th.wait('locked'), 2000);
  // Once the waits of a and b are over, new keys push those out, oldest first, and not the locked key.
  t += 1000;
  assert.equal(th.wait('new1'), 0);
  th.fail('new1');
  th.fail('new2');
  assert.deepEqual([...th.map.keys()].sort(), ['locked', 'new1', 'new2']);
  assert.equal(th.wait('locked'), 1000);
  // Entries within their free tries have no wait, so they can make room.
  th.fail('new3');
  assert.equal(th.size, 3);
  assert.equal(th.map.has('locked'), true);
});

test('hashGate runs a few at once, queues a few and turns the rest away', async () => {
  const gate = hashGate(2, 1);
  const releases = [];
  const job = () => new Promise((r) => releases.push(r));
  const a = gate(job);
  const b = gate(job);
  const c = gate(job);
  await new Promise((r) => setImmediate(r));
  assert.deepEqual(gate.load(), { running: 2, waiting: 1 });
  await assert.rejects(gate(job), Busy);
  releases[0]('a');
  assert.equal(await a, 'a');
  await new Promise((r) => setImmediate(r));
  assert.deepEqual(gate.load(), { running: 2, waiting: 0 });
  releases[1]('b');
  releases[2]('c');
  assert.deepEqual([await b, await c], ['b', 'c']);
  // A job that fails frees its place too.
  await assert.rejects(gate(async () => { throw new Error('boom'); }), /boom/);
  assert.deepEqual(gate.load(), { running: 0, waiting: 0 });
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

test('ipKey groups IPv6 by /64', () => {
  assert.equal(ipKey('192.0.2.1'), 'ip:192.0.2.1');
  assert.equal(ipKey('2001:db8:1:2:aaaa::1'), ipKey('2001:db8:1:2:bbbb:cccc:dddd:eeee'));
  assert.notEqual(ipKey('2001:db8:1:2::1'), ipKey('2001:db8:1:3::1'));
  assert.equal(ipKey('::1'), 'ip:0000:0000:0000:0000::/64');
  assert.equal(ipKey(''), 'ip:');
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

async function login({ hasher = fakeHasher, gate } = {}) {
  const calls = [];
  const counting = async (p) => {
    calls.push(p);
    return hasher(p);
  };
  const phc = parsePhc(await hashPassword('right password', { ...DEFAULTS, memory: 32768 }, fakeHasher));
  const l = createLogin({ users: [{ name: 'Alice', phc }], hasher: counting, ...(gate ? { gate } : {}) });
  return { l, calls };
}

test('attempt: a right password logs in, by name in any case', async () => {
  const { l } = await login();
  assert.deepEqual(await l.attempt('alice', 'right password', '192.0.2.1'), { ok: true, name: 'Alice' });
  assert.deepEqual(await l.attempt('  ALICE ', 'right password', '192.0.2.1'), { ok: true, name: 'Alice' });
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

test('attempt: too long a password is refused without a hash, and counts as a failure', async () => {
  const { l, calls } = await login();
  assert.equal((await l.attempt('alice', 'x'.repeat(1025), '192.0.2.1')).reason, 'invalid');
  assert.equal((await l.attempt('x'.repeat(65), 'pw', '192.0.2.1')).reason, 'invalid');
  assert.equal(calls.length, 0);
  assert.equal(l.accounts.size, 2);
});

test('attempt: failures slow down the account and the address, a success clears them', async () => {
  const { l, calls } = await login();
  // Five failures are free; the sixth starts the wait.
  for (let i = 0; i < 6; i++) assert.equal((await l.attempt('alice', 'wrong', `192.0.2.${i}`)).reason, 'invalid');
  const t = await l.attempt('alice', 'right password', '192.0.2.99');
  assert.equal(t.reason, 'throttled');
  assert.ok(t.retryAfterMs > 0 && t.retryAfterMs <= 1000);
  assert.equal(calls.length, 6, 'no hash while throttled');
  // The same for a name that does not exist: no way to tell names apart.
  for (let i = 0; i < 6; i++) await l.attempt('nobody', 'wrong', `198.51.100.${i}`);
  assert.equal((await l.attempt('nobody', 'x', '198.51.100.99')).reason, 'throttled');
  // One address trying many names is slowed down too (20 free).
  for (let i = 0; i < 21; i++) await l.attempt(`user${i}`, 'wrong', '203.0.113.5');
  assert.equal((await l.attempt('someone', 'x', '203.0.113.5')).reason, 'throttled');
  // A success clears the account.
  l.accounts.clear('user:alice');
  assert.equal((await l.attempt('alice', 'right password', '192.0.2.200')).ok, true);
  assert.equal(l.accounts.wait('user:alice'), 0);
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
  const { l } = await login({ hasher: h.hasher, gate: hashGate(10, 10) });
  const all = Promise.all(Array.from({ length: 10 }, () => l.attempt('alice', 'wrong', '192.0.2.1')));
  await new Promise((r) => setImmediate(r));
  assert.equal(h.calls.length, 5, 'the free tries run at once, the rest wait for them');
  h.release();
  const out = await all;
  assert.equal(h.calls.length, 6);
  assert.deepEqual(out.map((r) => r.reason).sort(), [...Array(6).fill('invalid'), ...Array(4).fill('throttled')]);
  assert.equal(l.accounts.count('user:alice'), 6);
});

test('attempt: a burst of right passwords all log in', async () => {
  const h = held();
  const { l } = await login({ hasher: h.hasher });
  const all = Promise.all(Array.from({ length: 10 }, () => l.attempt('alice', 'right password', '192.0.2.1')));
  await new Promise((r) => setImmediate(r));
  h.release();
  const out = await all;
  assert.deepEqual(out.map((r) => r.ok), Array(10).fill(true));
  assert.equal(l.accounts.count('user:alice'), 0);
});

test('attempt: a success in a burst clears the failures before it', async () => {
  const h = held();
  const { l } = await login({ hasher: h.hasher });
  const tries = ['wrong', 'wrong', 'wrong', 'wrong', 'right password', 'wrong', 'wrong'].map((pw) => l.attempt('alice', pw, '192.0.2.1'));
  h.release();
  const out = await Promise.all(tries);
  assert.equal(out[4].ok, true);
  assert.equal(out.filter((r) => r.reason === 'throttled').length, 0);
  assert.ok(l.accounts.count('user:alice') <= 2);
});

test('attempt: too many waiting for one name are turned away as busy, and that does not count as a failure', async () => {
  const h = held();
  const { l } = await login({ hasher: h.hasher, gate: hashGate(100, 100) });
  const tries = Array.from({ length: 5 + MAX_QUEUED_HASHES + 3 }, (_, i) => l.attempt('alice', 'wrong', `192.0.2.${i}`));
  await new Promise((r) => setImmediate(r));
  h.release();
  const out = await Promise.all(tries);
  assert.equal(out.filter((r) => r.reason === 'busy').length, 3);
  assert.ok(out.filter((r) => r.reason === 'busy').every((r) => r.retryAfterMs === 2000));
  assert.equal(l.accounts.count('user:alice'), 6);
});

test('attempt: a busy answer from the gate does not count as a failure', async () => {
  const gate = hashGate(1, 0);
  let release;
  const holding = gate(() => new Promise((r) => (release = r)));
  const { l } = await login({ gate });
  for (let i = 0; i < 10; i++) assert.equal((await l.attempt('alice', 'wrong', '192.0.2.1')).reason, 'busy');
  assert.equal(l.accounts.count('user:alice'), 0);
  assert.equal(l.addresses.count('ip:192.0.2.1'), 0);
  release();
  await holding;
});

test('attempt: an unknown name is checked with the highest costs of any user', async () => {
  const calls = [];
  const counting = async (p) => (calls.push(p), fakeHasher(p));
  const users = [
    { name: 'cheap', phc: parsePhc(await hashPassword('a', DEFAULTS, fakeHasher)) },
    { name: 'memory', phc: parsePhc(await hashPassword('b', { ...DEFAULTS, memory: 65536 }, fakeHasher)) },
    { name: 'passes', phc: parsePhc(await hashPassword('c', { ...DEFAULTS, passes: 7, parallelism: 4 }, fakeHasher)) },
  ];
  const l = createLogin({ users, hasher: counting });
  assert.equal((await l.attempt('nobody', 'x', '192.0.2.1')).reason, 'invalid');
  assert.deepEqual([calls[0].memory, calls[0].passes, calls[0].parallelism, calls[0].length], [65536, 7, 4, 32]);
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
