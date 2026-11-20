import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { DEFAULTS, MAX_MEMORY_KIB, argon2Available, argon2id, checkCosts, costliest, dummyPhc, formatPhc, hashPassword, parsePhc, verifyPassword } from '../lib/password.js';
import { fromPipe, parseArgs, usersLine } from '../scripts/hash-password.js';
import { loadConfig } from '../lib/config.js';
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
  bad(`$argon2id$v=19$m=65536,t=2,p=1,keyid=x$${salt}$${hash}`, /keyid/);
  bad(`$argon2id$v=19$m=65536,t=2,p=1,data=x$${salt}$${hash}`, /m=\.\.\.,t=\.\.\.,p=\.\.\./);
  bad(`$argon2id$v=19$m=65536,t=2,p=1,keyid=AAAAAQ,keyid=AAAAAQ$${salt}$${hash}`, /m=\.\.\.,t=\.\.\.,p=\.\.\./);
  bad(`$argon2id$v=19$keyid=AAAAAQ,m=65536,t=2,p=1$${salt}$${hash}`, /m=\.\.\.,t=\.\.\.,p=\.\.\./);
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

const PEPPER = Buffer.alloc(32, 7);

test('a keyid round trips through hashPassword, parsePhc and formatPhc', async () => {
  const phc = await hashPassword('correct horse', DEFAULTS, fakeHasher, { keyid: 1, secret: PEPPER });
  assert.match(phc, /^\$argon2id\$v=19\$m=19456,t=2,p=1,keyid=AAAAAQ\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$/);
  const parsed = parsePhc(phc);
  assert.equal(parsed.keyid, 1);
  assert.equal(formatPhc(parsed), phc);
  const top = formatPhc({ ...parsed, keyid: 65535 });
  assert.match(top, /,keyid=AAD\/\/w\$/);
  assert.equal(parsePhc(top).keyid, 65535);
  // A hash without one says so, and is written back without one.
  assert.equal(parsePhc(VECTOR).keyid, null);
  assert.equal(formatPhc({ ...parsePhc(VECTOR), keyid: null }), VECTOR);
});

test('parsePhc refuses a keyid that is not a key version', () => {
  const rest = 'c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc';
  const bad = (keyid) => assert.throws(() => parsePhc(`$argon2id$v=19$m=65536,t=2,p=1,keyid=${keyid}$${rest}`), /has a keyid that is not a key version from 1 to 65535/, keyid);
  bad('');
  bad('AAAAAA'); // 0
  bad('AAEAAA'); // 65536
  bad('/////w'); // 2^32 - 1
  bad('AAAB'); // 3 bytes
  bad('AAAAAAE'); // 5 bytes
  bad('AAAAAQ=='); // padded
  bad('AAAA-Q'); // base64url, not base64
});

test('the same password with a different secret does not verify', async () => {
  const phc = parsePhc(await hashPassword('correct horse', DEFAULTS, fakeHasher, { keyid: 3, secret: PEPPER }));
  assert.equal(await verifyPassword('correct horse', phc, fakeHasher, PEPPER), true);
  assert.equal(await verifyPassword('correct horse', phc, fakeHasher, Buffer.alloc(32, 8)), false);
  assert.equal(await verifyPassword('correct hors', phc, fakeHasher, PEPPER), false);
  // Without its secret a peppered hash could never match, so that is an error and not a "no".
  await assert.rejects(verifyPassword('correct horse', phc, fakeHasher), /needs the pepper of key version 3/);
  await assert.rejects(verifyPassword('correct horse', phc, fakeHasher, Buffer.alloc(0)), /needs the pepper/);
  // The same password and salt without a secret gives another hash.
  const plain = await fakeHasher({ password: Buffer.from('correct horse'), salt: phc.salt, memory: phc.memory, passes: phc.passes, parallelism: phc.parallelism, length: phc.hash.length });
  assert.notDeepEqual(plain, phc.hash);
});

test('an unpeppered hash still verifies, whatever secret is given', async () => {
  // Made before peppering: the fake hasher gives what it gave then.
  const old = parsePhc('$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$qAntQTKppM3LVWVSTnuQICpWy26p4UkQwNwNytXijkc');
  assert.equal(old.keyid, null);
  assert.equal(await verifyPassword('correct horse', old, fakeHasher), true);
  assert.equal(await verifyPassword('correct horse', old, fakeHasher, PEPPER), true);
  assert.equal(await verifyPassword('wrong horse', old, fakeHasher, PEPPER), false);
});

test('hashPassword refuses a pepper without a key version or a secret', async () => {
  for (const pepper of [{}, { keyid: 0, secret: PEPPER }, { keyid: 65536, secret: PEPPER }, { keyid: 1.5, secret: PEPPER }, { keyid: '1', secret: PEPPER }, { keyid: 1 }, { keyid: 1, secret: Buffer.alloc(0) }, { keyid: 1, secret: 'text' }]) {
    await assert.rejects(hashPassword('pw', DEFAULTS, fakeHasher, pepper), /a pepper needs a keyid from 1 to 65535 and a secret/, JSON.stringify(pepper));
  }
});

test('the real Argon2id with a secret matches the RFC 9106 test vector', { skip: REAL }, async () => {
  // RFC 9106 section 5.3 also has associated data, which the login never uses, so crypto.argon2 is called directly.
  const out = await new Promise((resolve, reject) =>
    crypto.argon2('argon2id', { message: Buffer.alloc(32, 1), nonce: Buffer.alloc(16, 2), secret: Buffer.alloc(8, 3), associatedData: Buffer.alloc(12, 4), memory: 32, passes: 3, parallelism: 4, tagLength: 32 }, (e, r) => (e ? reject(e) : resolve(r))),
  );
  assert.equal(out.toString('hex'), '0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659');
  // And through hashPassword: the pepper changes the hash, and the reference vector still verifies with one given.
  const phc = parsePhc(await hashPassword('a fresh one', DEFAULTS, argon2id, { keyid: 2, secret: PEPPER }));
  assert.equal(await verifyPassword('a fresh one', phc, argon2id, PEPPER), true);
  assert.equal(await verifyPassword('a fresh one', phc, argon2id, Buffer.alloc(32, 8)), false);
  assert.equal(await verifyPassword('password', parsePhc(VECTOR), argon2id, PEPPER), true);
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

test('the memory cost is capped at 64 MiB: two checks at once stay within 128 MiB', () => {
  assert.equal(MAX_MEMORY_KIB, 65536);
  assert.doesNotThrow(() => checkCosts({ memory: 65536, passes: 2, parallelism: 1 }));
  assert.throws(() => checkCosts({ memory: 65537, passes: 2, parallelism: 1 }), /memory must be 19456 to 65536 KiB/);
  assert.throws(() => parsePhc(VECTOR.replace('m=65536', 'm=131072')), /too costly/);
});

test('hash-password quotes the name, so the pasted line is read as text whatever the name', async () => {
  const phc = await hashPassword('pw', DEFAULTS, fakeHasher);
  for (const name of ['alice', '123', 'true', 'TRUE', 'null', 'Null', 'false', '0', '1e3', '0x1F', '0o7', '1.5', 'yes', 'no', '1_000']) {
    const c = loadConfig(`users:\n${usersLine(name, phc)}\nnodes:\n  - address: a.test:1\n`);
    assert.equal(c.users[0].name, name);
  }
});

test('the config says to quote a user name that YAML does not read as text', () => {
  for (const v of ['123', 'true', 'null', '1.5', '~']) {
    assert.throws(() => loadConfig(`users:\n  - name: ${v}\n    password_hash: '${VECTOR}'\nnodes:\n  - address: a.test:1\n`), /name is not text: put the name in quotes/, v);
  }
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
