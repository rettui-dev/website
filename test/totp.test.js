import test from 'node:test';
import assert from 'node:assert/strict';
import { base32Decode, base32Encode, hotp, newSecret, otpauthUri, stepAt, totp, verifyTotp } from '../lib/totp.js';

// RFC 6238, appendix B: the seeds are ASCII digits, 20, 32 and 64 bytes long for SHA-1, SHA-256 and SHA-512.
const SEEDS = {
  sha1: Buffer.from('12345678901234567890'),
  sha256: Buffer.from('12345678901234567890123456789012'),
  sha512: Buffer.from('1234567890123456789012345678901234567890123456789012345678901234'),
};
const VECTORS = [
  [59, '94287082', '46119246', '90693936'],
  [1111111109, '07081804', '68084774', '25091201'],
  [1111111111, '14050471', '67062674', '99943326'],
  [1234567890, '89005924', '91819424', '93441116'],
  [2000000000, '69279037', '90698825', '38618901'],
  [20000000000, '65353130', '77737706', '47863826'],
];

test('TOTP matches the RFC 6238 test vectors for SHA-1, SHA-256 and SHA-512', () => {
  for (const [seconds, sha1, sha256, sha512] of VECTORS) {
    assert.equal(totp(SEEDS.sha1, seconds * 1000, { digits: 8 }), sha1, `sha1 at ${seconds}`);
    assert.equal(totp(SEEDS.sha256, seconds * 1000, { digits: 8, algorithm: 'sha256' }), sha256, `sha256 at ${seconds}`);
    assert.equal(totp(SEEDS.sha512, seconds * 1000, { digits: 8, algorithm: 'sha512' }), sha512, `sha512 at ${seconds}`);
  }
});

test('HOTP matches the RFC 4226 test values, and refuses bad counters and algorithms', () => {
  const expected = ['755224', '287082', '359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489'];
  expected.forEach((code, i) => assert.equal(hotp(SEEDS.sha1, i), code));
  assert.throws(() => hotp(SEEDS.sha1, -1));
  assert.throws(() => hotp(SEEDS.sha1, 1.5));
  assert.throws(() => hotp(SEEDS.sha1, 1, { algorithm: 'md5' }));
});

test('base32 follows RFC 4648 and refuses what is not base32', () => {
  const pairs = [['', ''], ['f', 'MY'], ['fo', 'MZXQ'], ['foo', 'MZXW6'], ['foob', 'MZXW6YQ'], ['fooba', 'MZXW6YTB'], ['foobar', 'MZXW6YTBOI']];
  for (const [plain, coded] of pairs) {
    assert.equal(base32Encode(Buffer.from(plain)), coded);
    if (coded) assert.equal(base32Decode(coded).toString(), plain);
  }
  assert.equal(base32Decode('mzxw 6ytb oi======').toString(), 'foobar');
  for (const bad of ['', '1', 'MZXW8', 'MZ!X', 'MZXW6YTBOJ', null, 42]) assert.equal(base32Decode(bad), null, String(bad));
  const secret = newSecret();
  assert.match(secret, /^[A-Z2-7]{32}$/);
  assert.equal(base32Decode(secret).length, 20);
  assert.notEqual(newSecret(), secret);
});

test('verifyTotp takes the step before, now and after, nothing further, and no used step', () => {
  const secret = SEEDS.sha1;
  const t = 1_800_000_000_000;
  const now = stepAt(t);
  const at = (s) => hotp(secret, s);
  assert.equal(verifyTotp(secret, at(now), t), now);
  assert.equal(verifyTotp(secret, at(now - 1), t), now - 1);
  assert.equal(verifyTotp(secret, at(now + 1), t), now + 1);
  assert.equal(verifyTotp(secret, at(now - 2), t), null);
  assert.equal(verifyTotp(secret, at(now + 2), t), null);
  // A step at or before the last one used is refused: a code works once.
  assert.equal(verifyTotp(secret, at(now), t, now), null);
  assert.equal(verifyTotp(secret, at(now - 1), t, now - 1), null);
  assert.equal(verifyTotp(secret, at(now + 1), t, now), now + 1);
  for (const bad of ['', '12345', '1234567', 'abcdef', ' 123456', null, 123456]) assert.equal(verifyTotp(secret, bad, t), null, String(bad));
});

test('the otpauth URI names the issuer and account and has the secret and the settings apps need', () => {
  const uri = otpauthUri({ issuer: 'My Site', account: 'alice', secret: 'JBSWY3DPEHPK3PXP' });
  assert.equal(uri, 'otpauth://totp/My%20Site:alice?secret=JBSWY3DPEHPK3PXP&issuer=My%20Site&algorithm=SHA1&digits=6&period=30');
  const u = new URL(uri);
  assert.equal(u.protocol, 'otpauth:');
  assert.equal(u.searchParams.get('issuer'), 'My Site');
});
