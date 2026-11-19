import test from 'node:test';
import assert from 'node:assert/strict';
import { DEFAULTS, MAX_MEMORY_KIB, argon2Available, argon2id, checkCosts, costliest, dummyPhc, formatPhc, hashPassword, parsePhc, verifyPassword } from '../lib/password.js';
import { fromPipe, parseArgs } from '../scripts/hash-password.js';
import { fakeHasher } from './helpers/fake-hasher.js';


const REAL = argon2Available() ? false : `crypto.argon2 needs Node.js 24.7 or later; this is ${process.version}`;

// The reference implementation's test vector for argon2id (password "password", salt "somesalt").
const VECTOR = '$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc';

test('parsePhc reads a valid Argon2id string', () => {
  const p = parsePhc(VECTOR);
  assert.deepEqual([p.memory, p.passes, p.parallelism], [65536, 2, 1]);
  assert.equal(p.salt.toString(), 'somesalt');
  assert.equal(p.hash.length, 32);
  assert.equal(formatPhc(p), VECTOR);
});

test('parsePhc refuses other variants, versions, forms and cheap or costly settings', () => {
  const salt = 'c29tZXNhbHQ';
  const hash = 'CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc';
  const bad = (text, pattern) => assert.throws(() => parsePhc(text), pattern, String(text));
  bad(undefined, /not an Argon2id hash/);
  bad(42, /not an Argon2id hash/);
  bad('', /in the form/);
  bad('x'.repeat(600), /not an Argon2id hash/);
  bad(`$argon2i$v=19$m=65536,t=2,p=1$${salt}$${hash}`, /must be argon2id/);
  bad(`$argon2d$v=19$m=65536,t=2,p=1$${salt}$${hash}`, /must be argon2id/);
  bad(`$scrypt$v=19$m=65536,t=2,p=1$${salt}$${hash}`, /must be argon2id/);
  bad(`$argon2id$v=16$m=65536,t=2,p=1$${salt}$${hash}`, /version 19/);
  bad(`$argon2id$m=65536,t=2,p=1$${salt}$${hash}`, /in the form/);
  bad(`$argon2id$v=19$t=2,m=65536,p=1$${salt}$${hash}`, /m=\.\.\.,t=\.\.\.,p=\.\.\./);
  bad(`$argon2id$v=19$m=65536,t=2,p=1,keyid=x$${salt}$${hash}`, /m=\.\.\.,t=\.\.\.,p=\.\.\./);
  bad(`$argon2id$v=19$m=065536,t=2,p=1$${salt}$${hash}`, /whole number/);
  bad(`$argon2id$v=19$m=19455,t=2,p=1$${salt}$${hash}`, /too cheap/);
  bad(`$argon2id$v=19$m=19456,t=1,p=1$${salt}$${hash}`, /too cheap/);
  bad(`$argon2id$v=19$m=${MAX_MEMORY_KIB + 1},t=2,p=1$${salt}$${hash}`, /too costly/);
  bad(`$argon2id$v=19$m=4294967295,t=2,p=1$${salt}$${hash}`, /too costly/);
  bad(`$argon2id$v=19$m=65536,t=17,p=1$${salt}$${hash}`, /too costly/);
  bad(`$argon2id$v=19$m=65536,t=2,p=17$${salt}$${hash}`, /too costly/);
  bad(`$argon2id$v=19$m=65536,t=2,p=1$${salt}=$${hash}`, /salt/);
  bad(`$argon2id$v=19$m=65536,t=2,p=1$c29t$${hash}`, /salt/);
  bad(`$argon2id$v=19$m=65536,t=2,p=1$${salt}$${hash}=`, /hash/);
  bad(`$argon2id$v=19$m=65536,t=2,p=1$${salt}$${hash.replace('C', '-')}`, /hash/);
  bad(`$argon2id$v=19$m=65536,t=2,p=1$${salt}$AAAA`, /hash/);
  bad(`$argon2id$v=19$m=65536,t=2,p=1$${salt}`, /in the form/);
  bad(`$argon2id$v=19$m=65536,t=2,p=1$${salt}$${hash}$`, /in the form/);
  bad(`x$argon2id$v=19$m=65536,t=2,p=1$${salt}$${hash}`, /in the form/);
});

test('parsePhc errors never repeat the string', () => {
  const secret = '$argon2id$v=19$m=1,t=2,p=1$c2VjcmV0c2FsdA$c2VjcmV0aGFzaHNlY3JldGhhc2g';
  try {
    parsePhc(secret);
    assert.fail('accepted');
  } catch (err) {
    assert.equal(err.message.includes('c2VjcmV0'), false);
  }
});

test('hashPassword and verifyPassword agree, and a wrong password or salt does not match', async () => {
  const phc = await hashPassword('correct horse', DEFAULTS, fakeHasher);
  assert.match(phc, /^\$argon2id\$v=19\$m=19456,t=2,p=1\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$/);
  const parsed = parsePhc(phc);
  assert.equal(await verifyPassword('correct horse', parsed, fakeHasher), true);
  assert.equal(await verifyPassword('correct hors', parsed, fakeHasher), false);
  assert.equal(await verifyPassword('', parsed, fakeHasher), false);
  assert.equal(await verifyPassword(undefined, parsed, fakeHasher), false);
  // A random salt each time.
  assert.notEqual(await hashPassword('correct horse', DEFAULTS, fakeHasher), phc);
  // A hasher that answers with the wrong length never matches (and never throws in timingSafeEqual).
  assert.equal(await verifyPassword('correct horse', parsed, async () => Buffer.alloc(8)), false);
  assert.equal(await verifyPassword('correct horse', parsed, async () => 'text'), false);
});

test('hashPassword refuses bad costs and empty or long passwords', async () => {
  await assert.rejects(hashPassword('pw', { memory: 1024 }, fakeHasher), /memory/);
  await assert.rejects(hashPassword('pw', { passes: 1 }, fakeHasher), /passes/);
  await assert.rejects(hashPassword('pw', { parallelism: 0 }, fakeHasher), /parallelism/);
  await assert.rejects(hashPassword('', DEFAULTS, fakeHasher), /1 to 1024 bytes/);
  await assert.rejects(hashPassword('x'.repeat(1025), DEFAULTS, fakeHasher), /1 to 1024 bytes/);
  assert.throws(() => checkCosts({ memory: 19456, passes: 2, parallelism: 16 * 1024 }), /parallelism/);
  assert.throws(() => checkCosts({ memory: 1.5, passes: 2, parallelism: 1 }), /memory/);
});

test('dummyPhc has the costs of a real user and matches no password', async () => {
  const real = parsePhc(VECTOR);
  const d = dummyPhc(real);
  assert.deepEqual([d.memory, d.passes, d.parallelism, d.hash.length], [65536, 2, 1, 32]);
  assert.equal(await verifyPassword('password', d, fakeHasher), false);
  assert.deepEqual([dummyPhc().memory, dummyPhc().passes], [19456, 2]);
});

test('costliest takes the highest of each cost, so a stand-in is never cheaper than a real user', () => {
  const phc = (memory, passes, parallelism, length) => ({ memory, passes, parallelism, salt: Buffer.alloc(16), hash: Buffer.alloc(length) });
  const c = costliest([phc(19456, 9, 1, 16), phc(65536, 2, 1, 32), phc(20000, 3, 8, 64)]);
  assert.deepEqual([c.memory, c.passes, c.parallelism, c.hash.length], [65536, 9, 8, 64]);
  const d = dummyPhc(c);
  assert.deepEqual([d.memory, d.passes, d.parallelism, d.hash.length], [65536, 9, 8, 64]);
  const none = costliest([]);
  assert.deepEqual([none.memory, none.passes, none.parallelism, none.hash.length], [19456, 2, 1, 32]);
});

test('the real Argon2id matches the reference test vector', { skip: REAL }, async () => {
  assert.equal(await verifyPassword('password', parsePhc(VECTOR), argon2id), true);
  assert.equal(await verifyPassword('Password', parsePhc(VECTOR), argon2id), false);
  const phc = await hashPassword('a fresh one', DEFAULTS);
  assert.equal(await verifyPassword('a fresh one', parsePhc(phc)), true);
});

test('without crypto.argon2 the hasher says what it needs', { skip: argon2Available() ? 'this Node.js has crypto.argon2' : false }, async () => {
  await assert.rejects(argon2id({ password: Buffer.from('x'), salt: Buffer.alloc(16), memory: 19456, passes: 2, parallelism: 1, length: 32 }), /Node.js 24.7/);
});

test('hash-password takes options but never a password on the command line', () => {
  assert.deepEqual(parseArgs([]), { name: 'name', costs: DEFAULTS, help: false });
  assert.deepEqual(parseArgs(['--name', 'alice', '--memory', '65536', '--passes', '3', '--parallelism', '2']).costs, { memory: 65536, passes: 3, parallelism: 2 });
  assert.equal(parseArgs(['--help']).help, true);
  assert.throws(() => parseArgs(['hunter2']), /cannot be given as an argument/);
  assert.throws(() => parseArgs(['--password', 'hunter2']), /unknown option/);
  assert.throws(() => parseArgs(['--name']), /needs a value/);
  assert.throws(() => parseArgs(['--name', 'bad name']), /--name/);
  assert.throws(() => parseArgs(['--memory', '1000']), /memory must be/);
  assert.throws(() => parseArgs(['--passes', 'x']), /whole number/);
  assert.equal(fromPipe('secret\n'), 'secret');
  assert.equal(fromPipe('secret\r\n'), 'secret');
  assert.equal(fromPipe('secret \n\n'), 'secret \n');
  assert.equal(fromPipe('secret'), 'secret');
});
