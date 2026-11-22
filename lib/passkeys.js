// Passkeys (WebAuthn) as a second factor. This is the only module that uses @simplewebauthn/server:
// everything the browser sends is checked here for shape and size before the library reads it, the
// library then checks the signatures, origin, rpId, user verification and challenge, and a throw
// from it is only ever "that did not work". Attestation is not trusted for anything: only 'none',
// or 'packed' signed by the new key itself (no certificate), is taken, so the library's certificate
// and revocation code never runs and it never fetches anything. Challenges are single use and short
// lived; those of registration and of step-up are kept here, by session, those of the second sign-in
// step by the caller (in its pending entry).
//
// The store (users.js) keeps the credentials; this module only uses it through:
// passkeys(name), passkeyByRef(name, ref), passkeyById(name, id), passkeyOwner(id),
// passkeyUserId(name), ensurePasskeyUserId(name, {guard}), addPasskey(name, record, {guard}) and
// usePasskey(name, ref, {counter, backedUp}).
import crypto from 'node:crypto';
import net from 'node:net';
import { generateRegistrationOptions, verifyAuthenticationResponse, verifyRegistrationResponse } from '@simplewebauthn/server';
import { decodeAttestationObject, decodeCredentialPublicKey } from '@simplewebauthn/server/helpers';
import { PASSKEY_TRANSPORTS, passkeyLabel, passkeyRef } from './users.js';

// The ref the store names a passkey by (the start of the SHA-256 of the id's bytes), from users.js.
export { passkeyRef };

export const MAX_PASSKEYS = 10;
export const CHALLENGE_MS = 5 * 60_000;
export const MAX_CHALLENGES = 2000;
// EdDSA, ES256 and RS256: what passkeys and security keys use.
export const ALGS = [-8, -7, -257];
// How long the browser lets the person take, in milliseconds.
export const TIMEOUT_MS = 120_000;
// Sizes, in base64url characters, above which a field is refused before anything parses it.
export const LIMITS = { id: 700, clientDataJSON: 1024, authenticatorData: 1024, signature: 1024, userHandle: 128, attestationObject: 4096 };
// A credential given as JSON text is at most this long (the sign-in form takes 8192 bytes).
export const MAX_CREDENTIAL_TEXT = 8192;
// What the store keeps of a credential, at most (bytes).
export const MAX_ID_BYTES = 512;
export const MAX_KEY_BYTES = 600;
export const MAX_NAME = 64;
export const TRANSPORTS = PASSKEY_TRANSPORTS;
const MAX_TRANSPORTS = 8;
const MAX_RP_ID = 253;
const MAX_RP_NAME = 64;
const B64URL = /^[A-Za-z0-9_-]+$/;
const PURPOSES = new Set(['register', 'stepup']);

// A passkey operation that did not work. code: 'unavailable' (no usable site address), 'full'
// (MAX_PASSKEYS already), 'expired' (no challenge for this session, too old, used, or from another
// sign-in), 'invalid' (the browser's answer did not check out), 'attestation' (the authenticator sent
// a certificate), 'duplicate' (the passkey is there already), 'name' (the label is not 1 to 64
// characters without control characters). The message never holds anything the browser sent.
export class PasskeyError extends Error {
  constructor(code, message = MESSAGES[code] ?? 'the passkey could not be checked') {
    super(message);
    this.code = code;
  }
}

const MESSAGES = {
  unavailable: 'passkeys need the https address of the site (site.url)',
  full: `at most ${MAX_PASSKEYS} passkeys per user`,
  expired: 'no passkey challenge for this session, or it is too old',
  invalid: 'the passkey could not be checked',
  attestation: 'the authenticator sent an attestation certificate, which is not accepted',
  duplicate: 'this passkey is added already',
  name: `a passkey name is 1 to ${MAX_NAME} characters, without control characters`,
};

const lower = (name) => (typeof name === 'string' ? name.trim().toLowerCase() : '');

// The bytes of a base64url text, or null when it is not one, or not in its one canonical spelling
// (no padding, no leftover bits), so that one credential id has one spelling.
export function fromB64url(text) {
  if (typeof text !== 'string' || !B64URL.test(text) || text.length % 4 === 1) return null;
  const bytes = Buffer.from(text, 'base64url');
  return bytes.toString('base64url') === text ? bytes : null;
}

// A passkey label as typed, trimmed, or null when the store would not keep it: the one rule of
// users.js (passkeyLabel), so that what is taken here is what the database holds.
export const passkeyName = passkeyLabel;

// Where passkeys work, from the site address as parseSiteUrl gives it (an origin, or null): an https
// origin, or http://localhost for testing. The rpId is the host name; an IP address cannot be one.
export function passkeyOrigin(siteUrl) {
  const none = { available: false, reason: 'no-address', origin: null, rpId: null };
  if (typeof siteUrl !== 'string' || siteUrl === '' || siteUrl.length > 300) return none;
  let u;
  try {
    u = new URL(siteUrl);
  } catch {
    return none;
  }
  const host = u.hostname;
  const local = u.protocol === 'http:' && host === 'localhost';
  if ((u.protocol !== 'https:' && !local) || host === '' || u.username || u.password || u.pathname !== '/' || u.search || u.hash) return none;
  if (net.isIP(host.replace(/^\[|\]$/g, '')) !== 0 || host.endsWith('.') || host.length > MAX_RP_ID) return none;
  return { available: true, reason: null, origin: u.origin, rpId: host };
}

// Why passkeys cannot work at a site address, in words for the operator (the address itself is never
// repeated), or null when they can.
export function passkeyOriginProblem(siteUrl) {
  if (passkeyOrigin(siteUrl).available) return null;
  if (typeof siteUrl !== 'string' || siteUrl === '') return "this site's https address is not set (site.url, or SITE_URL)";
  let u;
  try {
    u = new URL(siteUrl);
  } catch {
    return 'the site address (site.url, or SITE_URL) is not a URL';
  }
  const host = u.hostname;
  if (u.protocol !== 'https:' && !(u.protocol === 'http:' && host === 'localhost')) return 'the site address (site.url, or SITE_URL) is not https; passkeys need https, or http://localhost for testing';
  if (net.isIP(host.replace(/^\[|\]$/g, '')) !== 0) return 'the site address (site.url, or SITE_URL) is an IP address; passkeys need a host name';
  if (host.endsWith('.')) return 'the host name of the site address (site.url, or SITE_URL) ends with a dot; passkeys need it without one';
  if (host.length > MAX_RP_ID) return `the host name of the site address (site.url, or SITE_URL) is longer than ${MAX_RP_ID} characters`;
  return 'the site address (site.url, or SITE_URL) is not only an https origin (no user name, path, query or fragment)';
}

// Challenges of registration and step-up: one per session and purpose, taken once, at most
// CHALLENGE_MS old. At MAX_CHALLENGES the oldest goes.
class Challenges {
  constructor(now) {
    this.now = now;
    this.map = new Map();
  }

  put(sessionId, purpose, entry) {
    const t = this.now();
    for (const [k, e] of this.map) if (t - e.created >= CHALLENGE_MS || t < e.created) this.map.delete(k);
    const k = `${sessionId}|${purpose}`;
    // Set again, it goes to the end: the oldest is always first.
    this.map.delete(k);
    while (this.map.size >= MAX_CHALLENGES) this.map.delete(this.map.keys().next().value);
    this.map.set(k, { ...entry, created: t });
  }

  take(sessionId, purpose) {
    const k = `${sessionId}|${purpose}`;
    const e = this.map.get(k);
    if (!e) return null;
    this.map.delete(k);
    const age = this.now() - e.created;
    return age >= 0 && age < CHALLENGE_MS ? e : null;
  }

  dropSession(sessionId) {
    for (const p of PURPOSES) this.map.delete(`${sessionId}|${p}`);
  }

  dropUser(name) {
    const k = lower(name);
    for (const [key, e] of this.map) if (lower(e.name) === k) this.map.delete(key);
  }
}

const isMap = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

// The credential the browser sent: an object, or its JSON text. Gives a clean copy with only the
// fields the library reads, each a base64url text within LIMITS, or null. kind is 'create' or 'get'.
export function readCredential(input, kind) {
  let c = input;
  if (typeof c === 'string') {
    if (c.length > MAX_CREDENTIAL_TEXT) return null;
    try {
      c = JSON.parse(c);
    } catch {
      return null;
    }
  }
  if (!isMap(c) || !isMap(c.response) || c.type !== 'public-key') return null;
  if (typeof c.id !== 'string' || c.id.length > LIMITS.id || c.rawId !== c.id || fromB64url(c.id) === null) return null;
  const r = c.response;
  const fields = kind === 'create' ? ['clientDataJSON', 'attestationObject'] : ['clientDataJSON', 'authenticatorData', 'signature'];
  const response = {};
  for (const f of fields) {
    if (typeof r[f] !== 'string' || r[f].length > LIMITS[f] || fromB64url(r[f]) === null) return null;
    response[f] = r[f];
  }
  if (kind === 'get' && r.userHandle !== undefined && r.userHandle !== null && r.userHandle !== '') {
    if (typeof r.userHandle !== 'string' || r.userHandle.length > LIMITS.userHandle || fromB64url(r.userHandle) === null) return null;
    response.userHandle = r.userHandle;
  }
  if (kind === 'create') {
    // Only a hint for later sign-ins: unknown ones are left out rather than refused.
    const given = Array.isArray(r.transports) ? r.transports.slice(0, 32) : [];
    response.transports = TRANSPORTS.filter((t) => given.includes(t)).slice(0, MAX_TRANSPORTS);
  }
  return { id: c.id, rawId: c.id, type: 'public-key', response, clientExtensionResults: {} };
}

// The client data, read here only to refuse what the library lets through: a credential made or
// used inside a frame of another site. Gives false when it cannot be read.
function sameOriginClientData(b64) {
  try {
    const data = JSON.parse(Buffer.from(b64, 'base64url').toString('utf8'));
    return isMap(data) && (data.crossOrigin === undefined || data.crossOrigin === false) && data.topOrigin === undefined;
  } catch {
    return false;
  }
}

// The attestation statement, read here to refuse, before the library sees it, anything but 'none'
// or 'packed' signed by the credential key itself: a certificate (x5c), an ECDAA key or another
// format is refused ('attestation'). Gives {fmt, alg} (alg: what a packed statement names).
function checkAttestation(b64) {
  let fmt;
  let stmt;
  try {
    const obj = decodeAttestationObject(Buffer.from(b64, 'base64url'));
    fmt = obj.get('fmt');
    stmt = obj.get('attStmt');
  } catch {
    throw new PasskeyError('invalid');
  }
  if (!(stmt instanceof Map)) throw new PasskeyError('invalid');
  if (fmt === 'none') return { fmt, alg: null };
  if (fmt === 'packed' && !stmt.has('x5c') && !stmt.has('ecdaaKeyId')) return { fmt, alg: stmt.get('alg') };
  throw new PasskeyError('attestation');
}

// The smallest RSA modulus taken, in bits.
export const MIN_RSA_BITS = 2048;

const bytesOf = (v) => (v instanceof Uint8Array ? Buffer.from(v) : null);

// The only RSA public exponent taken: 65537, the one every authenticator uses.
const RSA_EXPONENT = Buffer.from([1, 0, 1]);

// Ed25519 (RFC 8032): the field prime, the curve constant d, and a square root of -1.
const ED_P = 2n ** 255n - 19n;
const ED_D = mod(-121665n * inverse(121666n));
const ED_SQRT_M1 = power(2n, (ED_P - 1n) / 4n);

function mod(a) {
  const r = a % ED_P;
  return r < 0n ? r + ED_P : r;
}

function power(base, exp) {
  let out = 1n;
  let b = mod(base);
  for (let e = exp; e > 0n; e >>= 1n) {
    if (e & 1n) out = (out * b) % ED_P;
    b = (b * b) % ED_P;
  }
  return out;
}

function inverse(a) {
  return power(a, ED_P - 2n);
}

// Whether 32 bytes are an Ed25519 public key that can stand for a signer: the canonical encoding
// of a point on the curve that is not one of the 8 points of small order. A key of small order
// lets one signature pass for many messages, so no passkey has one.
export function goodEd25519(bytes) {
  if (bytes.length !== 32) return false;
  const le = Buffer.from(bytes).reverse();
  const sign = le[0] >> 7;
  le[0] &= 0x7f;
  const y = BigInt(`0x${le.toString('hex')}`);
  if (y >= ED_P) return false;
  // x^2 = (y^2 - 1) / (d y^2 + 1)
  const u = mod(y * y - 1n);
  const v = mod(ED_D * y * y + 1n);
  const xx = (u * inverse(v)) % ED_P;
  let x = power(xx, (ED_P + 3n) / 8n);
  if (mod(x * x - xx) !== 0n) x = (x * ED_SQRT_M1) % ED_P;
  if (mod(x * x - xx) !== 0n) return false;
  if (x === 0n && sign === 1) return false;
  if (Number(x & 1n) !== sign) x = ED_P - x;
  // Small order: doubling it three times (times 8, the cofactor) gives the neutral point (0, 1).
  let [px, py] = [x, y];
  for (let i = 0; i < 3; i++) {
    const t = (ED_D * px * px * py * py) % ED_P;
    [px, py] = [(2n * px * py * inverse(1n + t)) % ED_P, mod((py * py + px * px) * inverse(mod(1n - t)))];
  }
  return !(px === 0n && py === 1n);
}

// The COSE algorithm of a public key, when the key is one that algorithm signs with and node:crypto
// can use, else null: ES256 needs an EC2 key on P-256 (a point on the curve), EdDSA an OKP key on
// Ed25519 (not of small order, see goodEd25519), RS256 an RSA key of at least MIN_RSA_BITS with
// the exponent 65537. The library only reads the label.
export function keyAlg(publicKey) {
  let cose;
  try {
    cose = decodeCredentialPublicKey(publicKey);
  } catch {
    return null;
  }
  if (!(cose instanceof Map)) return null;
  const alg = cose.get(3);
  const kty = cose.get(1);
  let jwk;
  if (alg === -7) {
    const [x, y] = [bytesOf(cose.get(-2)), bytesOf(cose.get(-3))];
    if (kty !== 2 || cose.get(-1) !== 1 || x?.length !== 32 || y?.length !== 32) return null;
    jwk = { kty: 'EC', crv: 'P-256', x: x.toString('base64url'), y: y.toString('base64url') };
  } else if (alg === -8) {
    const x = bytesOf(cose.get(-2));
    if (kty !== 1 || cose.get(-1) !== 6 || x?.length !== 32 || !goodEd25519(x)) return null;
    jwk = { kty: 'OKP', crv: 'Ed25519', x: x.toString('base64url') };
  } else if (alg === -257) {
    const [n, e] = [bytesOf(cose.get(-1)), bytesOf(cose.get(-2))];
    if (kty !== 3 || n === null || e === null || n.length === 0 || !e.equals(RSA_EXPONENT)) return null;
    jwk = { kty: 'RSA', n: n.toString('base64url'), e: e.toString('base64url') };
  } else {
    return null;
  }
  try {
    const key = crypto.createPublicKey({ key: jwk, format: 'jwk' });
    if (alg === -257 && !(key.asymmetricKeyDetails?.modulusLength >= MIN_RSA_BITS)) return null;
  } catch {
    return null;
  }
  return alg;
}

const allowed = (records) => records.map((r) => ({ id: r.id, type: 'public-key', ...(r.transports?.length ? { transports: [...r.transports] } : {}) }));
const unnamed = (label) => label === null || label === undefined || (typeof label === 'string' && label.trim() === '');

// What createLogin and the account API use. siteUrl: the origin from parseSiteUrl, or null. store:
// the UserStore. now and newChallenge are for tests.
export function createPasskeys({ siteUrl, rpName = null, store, now = Date.now, newChallenge = () => crypto.randomBytes(32).toString('base64url') }) {
  const { available, reason, origin, rpId } = passkeyOrigin(siteUrl);
  const shownName = typeof rpName === 'string' && rpName.trim() !== '' ? rpName.trim().slice(0, MAX_RP_NAME) : rpId;
  const challenges = new Challenges(now);

  // The user's full passkey records; with here, only those made at this rpId.
  const records = (name, here = false) => {
    const list = (store?.passkeys(name) ?? []).map((p) => store.passkeyByRef(name, p.ref)).filter((r) => r !== null && r !== undefined);
    return here ? list.filter((r) => r.rpId === rpId) : list;
  };

  const requestOptions = (challenge, creds) => ({ challenge, rpId, allowCredentials: allowed(creds), timeout: TIMEOUT_MS, userVerification: 'required' });

  // Options for navigator.credentials.create, and a challenge for this session and epoch. Throws
  // PasskeyError 'unavailable' or 'full'; errors of the store (UserError, StoreBusyError) as they are.
  async function registrationOptions(name, { sessionId, epoch, guard = null } = {}) {
    if (!available) throw new PasskeyError('unavailable');
    if (typeof sessionId !== 'string' || sessionId === '') throw new Error('registrationOptions needs the session id');
    const have = records(name);
    if (have.length >= MAX_PASSKEYS) throw new PasskeyError('full');
    const userId = fromB64url(await store.ensurePasskeyUserId(name, { guard }));
    if (userId === null) throw new Error('the store gave a passkey user id that is not base64url');
    const options = await generateRegistrationOptions({
      rpName: shownName,
      rpID: rpId,
      userName: name,
      userDisplayName: name,
      userID: new Uint8Array(userId),
      challenge: new Uint8Array(Buffer.from(newChallenge(), 'base64url')),
      timeout: TIMEOUT_MS,
      attestationType: 'none',
      excludeCredentials: allowed(have),
      authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
      supportedAlgorithmIDs: ALGS,
    });
    challenges.put(sessionId, 'register', { challenge: options.challenge, name, epoch });
    return options;
  }

  // Checks what navigator.credentials.create gave and adds the passkey. label: the name the user
  // gave, or empty for "Passkey N". Gives {record, ref, first, recoveryCodes} (recoveryCodes only
  // when it is the user's first second factor). Throws PasskeyError; errors of the store as they are.
  async function finishRegistration(name, response, { sessionId, epoch, label = '', guard = null } = {}) {
    if (!available) throw new PasskeyError('unavailable');
    // Checked first, so that a wrong name does not use up the challenge.
    const given = unnamed(label) ? null : passkeyName(label);
    if (!unnamed(label) && given === null) throw new PasskeyError('name');
    const c = typeof sessionId === 'string' ? challenges.take(sessionId, 'register') : null;
    if (c === null || lower(c.name) !== lower(name) || c.epoch !== epoch) throw new PasskeyError('expired');
    const cred = readCredential(response, 'create');
    if (cred === null || !sameOriginClientData(cred.response.clientDataJSON)) throw new PasskeyError('invalid');
    const statement = checkAttestation(cred.response.attestationObject);
    let info;
    try {
      const v = await verifyRegistrationResponse({
        response: cred,
        expectedChallenge: c.challenge,
        expectedOrigin: origin,
        expectedRPID: rpId,
        expectedType: 'webauthn.create',
        requireUserPresence: true,
        requireUserVerification: true,
        supportedAlgorithmIDs: ALGS,
      });
      if (!v.verified) throw new PasskeyError('invalid');
      info = v.registrationInfo;
    } catch {
      throw new PasskeyError('invalid');
    }
    const { credential } = info;
    const publicKey = Buffer.from(credential.publicKey);
    const alg = keyAlg(publicKey);
    // The id the browser named must be the one the authenticator made, and a self-signed 'packed'
    // statement must use the key's own algorithm.
    if (info.fmt !== statement.fmt || !info.userVerified || credential.id !== cred.id || alg === null || !ALGS.includes(alg)) throw new PasskeyError('invalid');
    if (statement.fmt === 'packed' && statement.alg !== alg) throw new PasskeyError('invalid');
    const idBytes = fromB64url(credential.id);
    if (idBytes === null || idBytes.length > MAX_ID_BYTES || publicKey.length > MAX_KEY_BYTES) throw new PasskeyError('invalid');
    if (!Number.isInteger(credential.counter) || credential.counter < 0 || credential.counter > 0xffffffff) throw new PasskeyError('invalid');
    const have = records(name);
    const own = () => records(name).some((r) => r.id === credential.id);
    if (have.some((r) => r.id === credential.id)) throw new PasskeyError('duplicate');
    if (have.length >= MAX_PASSKEYS) throw new PasskeyError('full');
    const record = {
      type: 'passkey',
      id: credential.id,
      publicKey: publicKey.toString('base64url'),
      counter: credential.counter,
      transports: cred.response.transports,
      name: given ?? `Passkey ${have.length + 1}`,
      created: new Date(now()).toISOString(),
      lastUsed: null,
      backupEligible: info.credentialDeviceType === 'multiDevice',
      backedUp: info.credentialBackedUp === true,
      rpId,
    };
    let added;
    try {
      added = await store.addPasskey(name, record, { guard });
    } catch (err) {
      if (err?.code === 'full') throw new PasskeyError('full');
      // Only a passkey of the user's own is "added already": an id another user has is answered as
      // one that could not be checked, so that nobody can find out which ids others have.
      // taken tells the caller, for its failures log (never with the id).
      if (err?.code === 'exists' && own()) throw new PasskeyError('duplicate');
      if (err?.code === 'exists') throw Object.assign(new PasskeyError('invalid'), { taken: true });
      if (err?.code === 'bad-label') throw new PasskeyError('name');
      throw err;
    }
    return { record, ref: added?.ref ?? passkeyRef(record.id), first: added?.first === true, recoveryCodes: added?.recoveryCodes ?? null };
  }

  // Options for navigator.credentials.get in the second sign-in step, and their challenge, which the
  // caller keeps (single use). null when the user has no passkey usable at this address.
  function loginOptions(name) {
    if (!available) return null;
    const creds = records(name, true);
    if (creds.length === 0) return null;
    const challenge = newChallenge();
    return { options: requestOptions(challenge, creds), challenge };
  }

  // Options for navigator.credentials.get with no allowCredentials, so that the browser offers any
  // discoverable passkey it has for this rpId, and their challenge, which the caller keeps (single
  // use). No user is named: who it is, is found from the answer (ownerOf). null when passkeys are off.
  function signInOptions() {
    if (!available) return null;
    const challenge = newChallenge();
    return { options: { challenge, rpId, timeout: TIMEOUT_MS, userVerification: 'required' }, challenge };
  }

  // The name of the user a get() answer is for, by its credential id, or null for anything that
  // cannot be read or is not known. Only a lookup: nothing in the answer is trusted yet, verify
  // checks it all against the owner's own record. The caller still checks that the user exists.
  function ownerOf(response) {
    if (!available || !store) return null;
    const cred = readCredential(response, 'get');
    return cred === null ? null : store.passkeyOwner(cred.id);
  }

  // The same for confirming a change on the account pages; the challenge is kept for the session.
  // null when the user has no passkey usable here.
  function stepUpOptions(name, sessionId) {
    if (!available || typeof sessionId !== 'string' || sessionId === '') return null;
    const creds = records(name, true);
    if (creds.length === 0) return null;
    const challenge = newChallenge();
    challenges.put(sessionId, 'stepup', { challenge, name, epoch: null });
    return requestOptions(challenge, creds);
  }

  // Checks what navigator.credentials.get gave against a challenge. Gives {ok: true, saved, ref}
  // (saved: the store's write of the new counter), or {ok: false}, with counterError: true and the
  // ref when the signature was right but the counter did not go up (a cloned authenticator, maybe).
  // requireUserHandle (signing in with no name): the answer must carry the user handle, and it must
  // be the user's own; without it, a handle is only checked when the answer has one.
  async function verify(name, response, challenge, { requireUserHandle = false } = {}) {
    const no = { ok: false };
    if (!available || typeof challenge !== 'string' || challenge === '') return no;
    const cred = readCredential(response, 'get');
    if (cred === null || !sameOriginClientData(cred.response.clientDataJSON)) return no;
    const rec = store.passkeyById(name, cred.id);
    if (!rec || rec.rpId !== rpId) return no;
    const ref = rec.ref ?? passkeyRef(rec.id);
    // Only read: nothing is written before the signature is known to be right. A user without a
    // handle yet has none a passkey could send.
    if (cred.response.userHandle === undefined) {
      if (requireUserHandle) return no;
    } else {
      const kept = store.passkeyUserId(name);
      const mine = typeof kept === 'string' ? fromB64url(kept) : null;
      if (mine === null || !mine.equals(fromB64url(cred.response.userHandle))) return no;
    }
    let info;
    try {
      // The counter is compared below, once the signature is known to be right, so that only a
      // real authenticator's counter is reported as gone back. Given 0, the library's own counter
      // check lets every counter through.
      const v = await verifyAuthenticationResponse({
        response: cred,
        expectedChallenge: challenge,
        expectedOrigin: origin,
        expectedRPID: rpId,
        expectedType: 'webauthn.get',
        credential: { id: rec.id, publicKey: new Uint8Array(Buffer.from(rec.publicKey, 'base64url')), counter: 0, transports: rec.transports },
        requireUserVerification: true,
      });
      if (!v.verified || !v.authenticationInfo.userVerified) return no;
      info = v.authenticationInfo;
    } catch {
      return no;
    }
    // Read again: another sign-in may have moved the counter, or the passkey been removed, meanwhile.
    const cur = store.passkeyById(name, cred.id);
    if (!cur || cur.rpId !== rpId) return no;
    const counter = info.newCounter;
    if (!Number.isInteger(counter) || counter < 0 || counter > 0xffffffff) return no;
    // The library's rule: when either counter is above 0 the new one must be higher. Synced
    // passkeys always send 0.
    if ((counter > 0 || cur.counter > 0) && counter <= cur.counter) return { ok: false, counterError: true, ref };
    const { saved } = store.usePasskey(name, ref, { counter, backedUp: info.credentialBackedUp === true });
    return { ok: true, saved, ref };
  }

  // verify with the step-up challenge of the session, which is used up whatever the result. Gives
  // {ok: false, expired: true} when there is none (too old, used, or for another user).
  async function verifyStepUp(name, sessionId, response) {
    const c = typeof sessionId === 'string' ? challenges.take(sessionId, 'stepup') : null;
    if (c === null || lower(c.name) !== lower(name)) return { ok: false, expired: true };
    return verify(name, response, c.challenge);
  }

  return {
    available,
    reason,
    origin,
    rpId,
    registrationOptions,
    finishRegistration,
    loginOptions,
    stepUpOptions,
    signInOptions,
    ownerOf,
    verify,
    verifyStepUp,
    dropSession: (sessionId) => challenges.dropSession(sessionId),
    dropUser: (name) => challenges.dropUser(name),
    // How many registration and step-up challenges are kept (for tests).
    get challengeCount() {
      return challenges.map.size;
    },
  };
}

// Passkeys turned off: no site address. What createLogin uses when it is given none.
export const NO_PASSKEYS = Object.freeze(createPasskeys({ siteUrl: null, store: null }));
