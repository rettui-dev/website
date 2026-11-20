// Time-based one-time codes (RFC 6238, on HOTP from RFC 4226), with node:crypto only: what
// authenticator apps show. The defaults are the ones every app understands: HMAC-SHA1, a 30 second
// step and 6 digits. A code is taken for the step before, the current one and the one after, so a
// phone clock that is a little off still works, and each step is taken at most once (lastUsedStep).
import crypto from 'node:crypto';

export const STEP_SECONDS = 30;
export const DIGITS = 6;
export const SECRET_BYTES = 20;
// Steps either side of now that a code may be from.
export const SKEW_STEPS = 1;
const ALGORITHMS = new Set(['sha1', 'sha256', 'sha512']);
const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

// Base32 (RFC 4648) without padding, as otpauth:// URIs and the apps want it.
export function base32Encode(buf) {
  let out = '';
  let bits = 0;
  let value = 0;
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
    value &= (1 << bits) - 1;
  }
  if (bits > 0) out += BASE32[(value << (5 - bits)) & 31];
  return out;
}

// The bytes of a base32 text, or null when it is not base32. Spaces and case do not matter, padding
// is allowed; leftover bits must be zero, so that one secret has one spelling.
export function base32Decode(text) {
  if (typeof text !== 'string') return null;
  const clean = text.replace(/\s+/g, '').replace(/=+$/, '').toUpperCase();
  if (clean.length === 0 || !/^[A-Z2-7]+$/.test(clean)) return null;
  const out = [];
  let bits = 0;
  let value = 0;
  for (const ch of clean) {
    value = (value << 5) | BASE32.indexOf(ch);
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
    value &= (1 << bits) - 1;
  }
  if (bits >= 5 || value !== 0) return null;
  return Buffer.from(out);
}

// A new random secret, in base32.
export const newSecret = () => base32Encode(crypto.randomBytes(SECRET_BYTES));

// The HOTP code of a counter, as a string of `digits` digits.
export function hotp(secret, counter, { digits = DIGITS, algorithm = 'sha1' } = {}) {
  if (!ALGORITHMS.has(algorithm)) throw new Error('algorithm must be sha1, sha256 or sha512');
  if (!Number.isSafeInteger(counter) || counter < 0) throw new Error('counter must be a whole number of at least 0');
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const mac = crypto.createHmac(algorithm, secret).update(msg).digest();
  const offset = mac[mac.length - 1] & 0x0f;
  const bin = ((mac[offset] & 0x7f) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
  return String(bin % 10 ** digits).padStart(digits, '0');
}

export const stepAt = (ms, step = STEP_SECONDS) => Math.floor(ms / 1000 / step);

// The TOTP code at a time (milliseconds).
export function totp(secret, ms, { step = STEP_SECONDS, digits = DIGITS, algorithm = 'sha1' } = {}) {
  return hotp(secret, stepAt(ms, step), { digits, algorithm });
}

// The step a code is from, or null when it is from none of the steps around now, or from a step at or
// before lastUsedStep (already used). Every step is compared, in constant time, whatever matches.
export function verifyTotp(secret, code, ms, lastUsedStep = null) {
  if (typeof code !== 'string' || !/^\d{6}$/.test(code)) return null;
  const now = stepAt(ms);
  const given = Buffer.from(code);
  let found = null;
  for (let s = now - SKEW_STEPS; s <= now + SKEW_STEPS; s++) {
    if (s < 0) continue;
    const same = crypto.timingSafeEqual(Buffer.from(hotp(secret, s)), given);
    if (same && found === null && (lastUsedStep === null || s > lastUsedStep)) found = s;
  }
  return found;
}

// The otpauth:// URI an app reads from the QR code. The label is "issuer:account", and the issuer is
// given again as a parameter, as Google Authenticator and the others expect.
export function otpauthUri({ issuer, account, secret }) {
  const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(account)}`;
  const q = new URLSearchParams({ secret, issuer, algorithm: 'SHA1', digits: String(DIGITS), period: String(STEP_SECONDS) });
  return `otpauth://totp/${label}?${q.toString().replace(/\+/g, '%20')}`;
}
