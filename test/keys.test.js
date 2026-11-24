import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { KeyError, Keyring, MAX_BOX_BYTES, MAX_KEYS, MAX_KEY_TEXT_BYTES, MIN_BOX_BYTES, loadKeys, parseKeys } from '../lib/keys.js';

const tmp = () => fs.mkdtemp(path.join(os.tmpdir(), 'keys-'));
const key = (fill) => Buffer.alloc(32, fill);
const text = (k) => k.toString('base64url');
const K1 = text(key(1));
const K2 = text(key(2));
const ring = (...versions) => new Keyring(new Map(versions.map((v) => [v, key(v)])));
const SECRET = Buffer.from('12345678901234567890');
const AAD = 'totp|store|alice';

// The key text must never show up in an error, whole or in part.
const noKey = (err, ...keys) => {
  for (const k of keys) assert.equal(err.message.includes(k.slice(0, 8)), false, err.message);
  return true;
};

test('parseKeys reads versions and keys, with comments, commas and blank lines', () => {
  const keys = parseKeys(`# the users key\n1:${K1}  # old\n\n  2 : ${K2}\r\n`);
  assert.deepEqual([...keys.keys()], [1, 2]);
  assert.deepEqual(keys.get(1), key(1));
  assert.deepEqual(keys.get(2), key(2));
  assert.deepEqual([...parseKeys(`7:${K1},65535:${K2},`).keys()], [7, 65535]);
  assert.deepEqual([...parseKeys(`1:${K1}\r2:${K2}`).keys()], [1, 2]);
});

test('parseKeys refuses bad entries, naming the entry but never the key', () => {
  const bad = (t, pattern) => assert.throws(() => parseKeys(t), (e) => e instanceof KeyError && pattern.test(e.message) && noKey(e, K1, K2), t);
  bad('', /no keys/);
  bad('# nothing\n , \n', /no keys/);
  bad(K1, /entry 1 is not in the form VERSION:KEY/);
  bad(`1:${K1}\n${K2}`, /entry 2 is not in the form VERSION:KEY/);
  for (const v of ['0', '65536', '01', '-1', '1.0', 'one', '', '999999']) bad(`${v}:${K1}`, /entry 1 has a version that is not a whole number from 1 to 65535/);
  bad(`1:${K1.slice(0, -1)}`, /entry 1 \(version 1\) is not 32 bytes of base64url/);
  bad(`1:${K1}A`, /not 32 bytes/);
  bad(`1:${K1}=`, /not 32 bytes/);
  bad(`1:${key(1).toString('base64')}`, /not 32 bytes/); // standard base64 with padding
  bad(`1:${K1.slice(0, -1)}B`, /not 32 bytes/); // does not come back out the same
  bad(`1:${text(Buffer.alloc(16, 1))}`, /not 32 bytes/);
  bad(`1:${text(Buffer.alloc(64, 1))}`, /not 32 bytes/);
  bad('1:', /not 32 bytes/);
  assert.throws(() => parseKeys(undefined), KeyError);
  assert.throws(() => parseKeys(Buffer.from(`1:${K1}`)), KeyError);
});

test('parseKeys refuses a version listed twice', () => {
  assert.throws(() => parseKeys(`1:${K1}\n1:${K2}`), (e) => e instanceof KeyError && /entry 2: version 1 is listed twice/.test(e.message) && noKey(e, K1, K2));
  assert.throws(() => parseKeys(`3:${K1},3:${K1}`), /version 3 is listed twice/);
});

test('parseKeys caps the number of keys and the length of the text', () => {
  const many = (n) => Array.from({ length: n }, (_, i) => `${i + 1}:${K1}`).join('\n');
  assert.equal(parseKeys(many(MAX_KEYS)).size, 16);
  assert.throws(() => parseKeys(many(MAX_KEYS + 1)), (e) => e instanceof KeyError && /17 keys; at most 16/.test(e.message));
  const padded = `1:${K1}\n#`;
  assert.equal(parseKeys(padded.padEnd(MAX_KEY_TEXT_BYTES, 'x')).size, 1);
  assert.throws(() => parseKeys(padded.padEnd(MAX_KEY_TEXT_BYTES + 1, 'x')), (e) => e instanceof KeyError && /longer than 4096 bytes/.test(e.message));
  // Bytes, not characters.
  assert.throws(() => parseKeys(`1:${K1}\n#${'é'.repeat(2100)}`), /longer than 4096 bytes/);
});

test('a keyring knows its versions, and the highest is current', () => {
  const r = ring(3, 1, 2);
  assert.equal(r.current, 3);
  assert.deepEqual(r.versions, [1, 2, 3]);
  r.versions.push(9);
  assert.deepEqual(r.versions, [1, 2, 3]);
  assert.equal(r.has(2), true);
  assert.equal(r.has(4), false);
  assert.throws(() => r.pepper(4), (e) => e instanceof KeyError && /key version 4 is not among the keys given/.test(e.message));
  assert.throws(() => r.check(4), KeyError);
  assert.throws(() => r.recoveryHash(4, '0'.repeat(64)), KeyError);
});

test('a keyring refuses no keys, bad versions and keys of the wrong size', () => {
  assert.throws(() => new Keyring(new Map()), KeyError);
  assert.throws(() => new Keyring(undefined), KeyError);
  assert.throws(() => new Keyring(new Map([[0, key(1)]])), KeyError);
  assert.throws(() => new Keyring(new Map([[65536, key(1)]])), KeyError);
  assert.throws(() => new Keyring(new Map([['1', key(1)]])), KeyError);
  assert.throws(() => new Keyring(new Map([[1, Buffer.alloc(16)]])), (e) => e instanceof KeyError && /key version 1 is not 32 bytes/.test(e.message));
  assert.throws(() => new Keyring(new Map([[1, K1]])), KeyError);
});

// HKDF (RFC 5869) written out with HMAC, to pin the salt and labels: a change to either would make
// every stored secret unreadable.
const hkdf = (ikm, info, length) => {
  const prk = crypto.createHmac('sha256', 'rettui-website users.db').update(ikm).digest();
  let t = Buffer.alloc(0);
  let out = Buffer.alloc(0);
  for (let i = 1; out.length < length; i++) {
    t = crypto.createHmac('sha256', prk).update(Buffer.concat([t, Buffer.from(info), Buffer.from([i])])).digest();
    out = Buffer.concat([out, t]);
  }
  return out.subarray(0, length);
};

test('the subkeys are distinct HKDF outputs, per use and per version', () => {
  const r = ring(1, 2);
  assert.deepEqual(r.pepper(1), hkdf(key(1), 'rettui-website/password-pepper', 32));
  assert.deepEqual(r.check(1), hkdf(key(1), 'rettui-website/key-check', 16));
  assert.equal(r.recoveryHash(1, 'ab'.repeat(32)), crypto.createHmac('sha256', hkdf(key(1), 'rettui-website/recovery-hmac', 32)).update(Buffer.from('ab'.repeat(32), 'hex')).digest('hex'));
  assert.equal(r.pepper(1).length, 32);
  assert.equal(r.check(1).length, 16);
  const all = [r.pepper(1), r.pepper(2), r.check(1), r.check(2), key(1), key(2)].map((b) => b.toString('hex'));
  assert.equal(new Set(all).size, all.length);
  // No subkey is the master key, or a prefix of another subkey.
  assert.equal(r.check(1).equals(r.pepper(1).subarray(0, 16)), false);
  // Callers get copies.
  r.pepper(1).fill(0);
  assert.deepEqual(r.pepper(1), hkdf(key(1), 'rettui-website/password-pepper', 32));
  // The same master key gives the same subkeys.
  assert.deepEqual(ring(1).pepper(1), r.pepper(1));
});

test('a TOTP secret sealed with the current key opens again', () => {
  const r = ring(1, 2);
  for (const secret of [SECRET.subarray(0, 10), SECRET, crypto.randomBytes(64)]) {
    const box = r.sealTotp(secret, AAD);
    assert.equal(box.length, 1 + 2 + 12 + secret.length + 16);
    assert.ok(box.length >= MIN_BOX_BYTES && box.length <= MAX_BOX_BYTES);
    assert.equal(box[0], 1);
    assert.equal(box.readUInt16BE(1), 2);
    assert.equal(r.boxVersion(box), 2);
    assert.deepEqual(r.openTotp(box, AAD), secret);
    assert.equal(box.includes(secret), false);
  }
  // A fresh IV each time.
  assert.notDeepEqual(r.sealTotp(SECRET, AAD), r.sealTotp(SECRET, AAD));
  assert.equal(MIN_BOX_BYTES, 41);
  assert.equal(MAX_BOX_BYTES, 95);
});

test('a box from an older version opens while that version is kept, and not after', () => {
  const old = ring(1).sealTotp(SECRET, AAD);
  const both = ring(1, 2);
  assert.equal(both.boxVersion(old), 1);
  assert.deepEqual(both.openTotp(old, AAD), SECRET);
  assert.throws(() => ring(2).openTotp(old, AAD), (e) => e instanceof KeyError && /key version 1 is not among/.test(e.message));
  // The same version number with another key: the wrong key.
  const other = new Keyring(new Map([[1, key(9)]]));
  assert.throws(() => other.openTotp(old, AAD), (e) => e instanceof KeyError && /does not decrypt with key version 1: the key is wrong or the data is damaged/.test(e.message));
});

test('a box does not open with other associated data', () => {
  const r = ring(1);
  const box = r.sealTotp(SECRET, AAD);
  for (const aad of ['totp|store|bob', 'totp|config|alice', 'totp|store|alice ', '']) {
    assert.throws(() => r.openTotp(box, aad), (e) => e instanceof KeyError && /does not decrypt/.test(e.message), aad);
  }
});

test('a box with any byte changed does not open', () => {
  const r = ring(1, 2);
  const box = r.sealTotp(SECRET, AAD);
  for (let i = 0; i < box.length; i++) {
    const bad = Buffer.from(box);
    bad[i] ^= 0x01;
    // The format byte and the version give their own errors; every other byte fails authentication.
    assert.throws(() => r.openTotp(bad, AAD), KeyError, `byte ${i}`);
  }
  assert.throws(() => r.openTotp(box.subarray(0, box.length - 1), AAD), KeyError);
  assert.throws(() => r.openTotp(Buffer.concat([box, Buffer.from([0])]), AAD), KeyError);
});

test('what is not a box is refused', () => {
  const r = ring(1);
  const box = r.sealTotp(SECRET, AAD);
  const notBox = (b) => assert.throws(() => r.boxVersion(b), (e) => e instanceof KeyError && /not in a known form/.test(e.message));
  notBox(Buffer.alloc(0));
  notBox(Buffer.alloc(MIN_BOX_BYTES - 1, 1));
  notBox(Buffer.alloc(MAX_BOX_BYTES + 1, 1));
  notBox(Buffer.concat([Buffer.from([2]), box.subarray(1)]));
  notBox(box.toString('base64'));
  notBox(null);
  assert.throws(() => r.openTotp(Buffer.alloc(50), AAD), /not in a known form/);
  assert.throws(() => r.openTotp(box, undefined), TypeError);
});

test('sealTotp takes 10 to 64 bytes of secret and text associated data', () => {
  const r = ring(1);
  assert.throws(() => r.sealTotp(Buffer.alloc(9), AAD), RangeError);
  assert.throws(() => r.sealTotp(Buffer.alloc(65), AAD), RangeError);
  assert.throws(() => r.sealTotp('JBSWY3DPEHPK3PXP', AAD), RangeError);
  assert.throws(() => r.sealTotp(SECRET, Buffer.from(AAD)), TypeError);
});

test('recovery hashes depend on the key version and refuse anything but a SHA-256 in hex', () => {
  const r = ring(1, 2);
  const legacy = crypto.createHash('sha256').update('x').digest('hex');
  const h1 = r.recoveryHash(1, legacy);
  assert.match(h1, /^[0-9a-f]{64}$/);
  assert.equal(r.recoveryHash(1, legacy), h1);
  assert.notEqual(r.recoveryHash(2, legacy), h1);
  assert.notEqual(r.recoveryHash(1, '0'.repeat(64)), h1);
  assert.notEqual(h1, legacy);
  for (const bad of ['', legacy.toUpperCase(), legacy.slice(1), `${legacy}0`, Buffer.from(legacy, 'hex'), null]) {
    assert.throws(() => r.recoveryHash(1, bad), TypeError);
  }
});

test('loadKeys gives null when no key is set, and refuses both at once', async () => {
  assert.equal(await loadKeys({}), null);
  assert.equal(await loadKeys({ USERS_KEY: '', USERS_KEY_FILE: '' }), null);
  await assert.rejects(loadKeys({ USERS_KEY: `1:${K1}`, USERS_KEY_FILE: '/nowhere' }), (e) => e instanceof KeyError && /both set; set only one/.test(e.message) && noKey(e, K1));
});

test('loadKeys reads USERS_KEY, and its errors never show the key', async () => {
  const r = await loadKeys({ USERS_KEY: `1:${K1},2:${K2}` }, { warn: () => assert.fail('warned') });
  assert.equal(r.current, 2);
  assert.deepEqual(r.pepper(1), ring(1).pepper(1));
  await assert.rejects(loadKeys({ USERS_KEY: `1:${K1},1:${K2}` }), (e) => e instanceof KeyError && /^USERS_KEY cannot be used: key entry 2: version 1 is listed twice/.test(e.message) && noKey(e, K1, K2));
  await assert.rejects(loadKeys({ USERS_KEY: `${K1}` }), (e) => e instanceof KeyError && noKey(e, K1));
});

test('loadKeys reads USERS_KEY_FILE, and warns when others can read it or it is in the data directory', async (t) => {
  const dir = await tmp();
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const dataDir = path.join(dir, 'data');
  await fs.mkdir(dataDir);
  const file = path.join(dir, 'users.key');
  await fs.writeFile(file, `1:${K1}\n2:${K2}\n`, { mode: 0o400 });
  const warnings = [];
  const warn = (m) => warnings.push(m);
  const r = await loadKeys({ USERS_KEY_FILE: file, DATA_DIR: dataDir }, { warn });
  assert.deepEqual(r.versions, [1, 2]);
  assert.deepEqual(warnings, []);
  // dataDir given beats DATA_DIR.
  await loadKeys({ USERS_KEY_FILE: file, DATA_DIR: dataDir }, { warn, dataDir: dir });
  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /inside the data directory/);
  const inData = path.join(dataDir, 'users.key');
  await fs.writeFile(inData, `1:${K1}\n`, { mode: 0o600 });
  warnings.length = 0;
  await loadKeys({ USERS_KEY_FILE: inData, DATA_DIR: dataDir }, { warn });
  assert.match(warnings.join('\n'), /inside the data directory/);
  if (process.platform !== 'win32') {
    await fs.chmod(file, 0o640);
    warnings.length = 0;
    await loadKeys({ USERS_KEY_FILE: file }, { warn });
    assert.equal(warnings.length, 1);
    assert.match(warnings[0], /can be read by other users \(mode 640\).*chmod 400/);
    for (const w of warnings) noKey({ message: w }, K1, K2);
  }
});

test('loadKeys refuses a missing, oversized, non-file or bad USERS_KEY_FILE without showing the key', async (t) => {
  const dir = await tmp();
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'users.key');
  const refused = (env, pattern) => assert.rejects(loadKeys(env, { warn: () => {} }), (e) => e instanceof KeyError && pattern.test(e.message) && noKey(e, K1, K2));
  await refused({ USERS_KEY_FILE: file }, /USERS_KEY_FILE .*users\.key cannot be read \(ENOENT\)/);
  await refused({ USERS_KEY_FILE: dir }, /cannot be read \((it is not a regular file|EISDIR)\)/);
  await fs.writeFile(file, `1:${K1}\n#`.padEnd(MAX_KEY_TEXT_BYTES + 1, 'x'), { mode: 0o600 });
  await refused({ USERS_KEY_FILE: file }, /cannot be read \(it is larger than 4096 bytes\)/);
  await fs.writeFile(file, `1:${K1}\n1:${K2}\n`, { mode: 0o600 });
  await refused({ USERS_KEY_FILE: file }, /users\.key cannot be used: key entry 2: version 1 is listed twice/);
  await fs.writeFile(file, '', { mode: 0o600 });
  await refused({ USERS_KEY_FILE: file }, /cannot be used: there are no keys/);
});

test('loadKeys refuses a FIFO as USERS_KEY_FILE at once, instead of waiting for something to write to it', { skip: process.platform === 'win32' }, async () => {
  const dir = await tmp();
  const fifo = path.join(dir, 'users.key');
  const { execFile, execFileSync } = await import('node:child_process');
  execFileSync('mkfifo', [fifo]);
  // In a process of its own: an open that waits would hold this one up for good.
  const keysJs = new URL('../lib/keys.js', import.meta.url).href;
  const code = `const { loadKeys } = await import(${JSON.stringify(keysJs)}); try { await loadKeys({ USERS_KEY_FILE: ${JSON.stringify(fifo)} }, { warn: () => {} }); } catch (e) { console.log(e.message); }`;
  const out = await new Promise((resolve) => {
    execFile(process.execPath, ['--input-type=module', '-e', code], { timeout: 10_000 }, (err, stdout) => resolve({ killed: err?.killed ?? false, stdout }));
  });
  assert.equal(out.killed, false, 'it did not wait');
  assert.match(out.stdout, /USERS_KEY_FILE .* cannot be read \(it is not a regular file\)/);
});

test('loadKeys says why a key file cannot be opened in its error code', { skip: process.platform === 'win32' || process.getuid?.() === 0 }, async () => {
  const dir = await tmp();
  const file = path.join(dir, 'users.key');
  await fs.writeFile(file, `1:${text(key(1))}\n`, { mode: 0 });
  await assert.rejects(loadKeys({ USERS_KEY_FILE: file }, { warn: () => {} }), (e) => e instanceof KeyError && e.code === 'EACCES');
});

test('a keyring subset keeps only the versions asked for, the highest of them current; none is null', () => {
  const ring = new Keyring(new Map([[1, key(1)], [2, key(2)], [5, key(5)]]));
  const sub = ring.subset([1, 2, 9]);
  assert.deepEqual(sub.versions, [1, 2]);
  assert.equal(sub.current, 2);
  assert.deepEqual(sub.pepper(2), ring.pepper(2));
  assert.equal(sub.has(5), false);
  assert.equal(ring.subset([7]), null);
  const box = sub.sealTotp(crypto.randomBytes(20), 'aad');
  assert.equal(sub.boxVersion(box), 2);
});
