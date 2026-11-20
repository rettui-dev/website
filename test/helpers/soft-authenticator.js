// A software authenticator for the tests, on node:crypto only: it makes credentials and signs
// assertions the way a passkey or security key does, so that lib/passkeys.js and the library under
// it see real WebAuthn data. Every part can be bent to make the bad answers the tests need: the
// flags, the counter, the rpId hash, the client data, the attestation format.
import crypto from 'node:crypto';

// A tiny CBOR encoder (RFC 8949): unsigned and negative integers, byte and text strings, arrays,
// maps (a Map keeps integer keys, as COSE needs), booleans and null. Nothing else is needed here.
function head(major, n) {
  if (n < 24) return Buffer.from([(major << 5) | n]);
  if (n < 0x100) return Buffer.from([(major << 5) | 24, n]);
  if (n < 0x10000) {
    const b = Buffer.alloc(3);
    b[0] = (major << 5) | 25;
    b.writeUInt16BE(n, 1);
    return b;
  }
  const b = Buffer.alloc(5);
  b[0] = (major << 5) | 26;
  b.writeUInt32BE(n, 1);
  return b;
}

export function cbor(value) {
  if (value === null) return Buffer.from([0xf6]);
  if (value === true) return Buffer.from([0xf5]);
  if (value === false) return Buffer.from([0xf4]);
  if (Number.isInteger(value)) return value >= 0 ? head(0, value) : head(1, -1 - value);
  if (typeof value === 'string') {
    const b = Buffer.from(value, 'utf8');
    return Buffer.concat([head(3, b.length), b]);
  }
  if (value instanceof Uint8Array) return Buffer.concat([head(2, value.length), value]);
  if (Array.isArray(value)) return Buffer.concat([head(4, value.length), ...value.map(cbor)]);
  const entries = value instanceof Map ? [...value] : Object.entries(value);
  return Buffer.concat([head(5, entries.length), ...entries.flatMap(([k, v]) => [cbor(k), cbor(v)])]);
}

const b64url = (buf) => Buffer.from(buf).toString('base64url');
const sha256 = (data) => crypto.createHash('sha256').update(data).digest();

export const FLAGS = { UP: 0x01, UV: 0x04, BE: 0x08, BS: 0x10, AT: 0x40, ED: 0x80 };

// The kinds of key, by COSE algorithm: how node:crypto makes them, and how they are signed with.
const KINDS = {
  [-7]: { type: 'ec', opts: { namedCurve: 'P-256' }, hash: 'sha256', crv: 1 },
  [-35]: { type: 'ec', opts: { namedCurve: 'P-384' }, hash: 'sha384', crv: 2 },
  [-8]: { type: 'ed25519', opts: {}, hash: null },
  [-257]: { type: 'rsa', opts: { modulusLength: 2048 }, hash: 'sha256' },
};

// The COSE form of a public key (RFC 9053), as the authenticator puts it in authenticatorData.
export function coseKey(publicKey, alg) {
  const jwk = publicKey.export({ format: 'jwk' });
  const b = (s) => Buffer.from(s, 'base64url');
  if (alg === -7 || alg === -35) return cbor(new Map([[1, 2], [3, alg], [-1, KINDS[alg].crv], [-2, b(jwk.x)], [-3, b(jwk.y)]]));
  if (alg === -8) return cbor(new Map([[1, 1], [3, -8], [-1, 6], [-2, b(jwk.x)]]));
  if (alg === -257) return cbor(new Map([[1, 3], [3, -257], [-1, b(jwk.n)], [-2, b(jwk.e)]]));
  throw new Error(`no COSE form for algorithm ${alg}`);
}

export class SoftAuthenticator {
  // alg: a COSE algorithm of KINDS. privateKey: a JWK, to make the same key every time (fixtures);
  // otherwise a new one. id: the credential id (bytes), random by default. counter: the signature
  // counter; 0 stays 0 (as synced passkeys do), anything else goes up by one on each use.
  constructor({ alg = -7, privateKey = null, id = null, counter = 0, aaguid = Buffer.alloc(16), backupEligible = false, backedUp = false } = {}) {
    const kind = KINDS[alg];
    if (!kind) throw new Error(`unsupported algorithm ${alg}`);
    this.alg = alg;
    this.kind = kind;
    if (privateKey) this.key = crypto.createPrivateKey({ key: privateKey, format: 'jwk' });
    else this.key = crypto.generateKeyPairSync(kind.type, kind.opts).privateKey;
    this.publicKey = crypto.createPublicKey(this.key);
    this.rawId = id ? Buffer.from(id) : crypto.randomBytes(32);
    this.counter = counter;
    this.aaguid = Buffer.from(aaguid);
    this.backupEligible = backupEligible;
    this.backedUp = backedUp;
  }

  get id() {
    return b64url(this.rawId);
  }

  get cose() {
    return coseKey(this.publicKey, this.alg);
  }

  // The private key as a JWK, for fixtures.
  jwk() {
    return this.key.export({ format: 'jwk' });
  }

  sign(data) {
    return crypto.sign(this.kind.hash, data, this.key);
  }

  flags({ up = true, uv = true, be = this.backupEligible, bs = this.backedUp, at = false }) {
    return (up ? FLAGS.UP : 0) | (uv ? FLAGS.UV : 0) | (be ? FLAGS.BE : 0) | (bs ? FLAGS.BS : 0) | (at ? FLAGS.AT : 0);
  }

  // authenticatorData: the SHA-256 of the rpId, the flags, the counter and, when making a
  // credential, the attested credential data.
  authData({ rpId, rpIdHash = null, attested = false, counter = this.counter, idBytes = this.rawId, cose = null, ...flags }) {
    const c = Buffer.alloc(4);
    c.writeUInt32BE(counter >>> 0);
    const parts = [rpIdHash ?? sha256(rpId), Buffer.from([this.flags({ ...flags, at: attested })]), c];
    if (attested) {
      const len = Buffer.alloc(2);
      len.writeUInt16BE(idBytes.length);
      parts.push(this.aaguid, len, idBytes, cose ?? this.cose);
    }
    return Buffer.concat(parts);
  }

  static clientData({ type, challenge, origin, crossOrigin = false, extra = {} }) {
    return Buffer.from(JSON.stringify({ type, challenge, origin, crossOrigin, ...extra }));
  }

  // What navigator.credentials.create gives, as JSON (RegistrationResponseJSON). fmt: 'none',
  // 'packed' (self attestation), 'packed-x5c' (with a certificate chain), or any other format name
  // with an empty statement. Options bend the result: up, uv, be, bs, rpIdHash, crossOrigin, type,
  // extra (more client data fields), statementAlg (the alg a packed statement names), cose (another
  // public key).
  create({ challenge, origin, rpId, fmt = 'none', type = 'webauthn.create', crossOrigin = false, extra = {}, transports = ['internal', 'hybrid'], statementAlg = this.alg, ...rest }) {
    const clientDataJSON = SoftAuthenticator.clientData({ type, challenge, origin, crossOrigin, extra });
    const authData = this.authData({ rpId, attested: true, ...rest });
    let attStmt = new Map();
    let format = fmt;
    if (fmt === 'packed' || fmt === 'packed-x5c') {
      const sig = this.sign(Buffer.concat([authData, sha256(clientDataJSON)]));
      attStmt = new Map([['alg', statementAlg], ['sig', sig]]);
      if (fmt === 'packed-x5c') attStmt.set('x5c', [crypto.randomBytes(64)]);
      format = 'packed';
    } else if (fmt === 'packed-ecdaa') {
      attStmt = new Map([['alg', statementAlg], ['sig', crypto.randomBytes(64)], ['ecdaaKeyId', crypto.randomBytes(32)]]);
      format = 'packed';
    }
    const attestationObject = cbor(new Map([['fmt', format], ['attStmt', attStmt], ['authData', authData]]));
    return {
      id: this.id,
      rawId: this.id,
      type: 'public-key',
      response: { clientDataJSON: b64url(clientDataJSON), attestationObject: b64url(attestationObject), transports },
      clientExtensionResults: {},
      authenticatorAttachment: 'platform',
    };
  }

  // What navigator.credentials.get gives, as JSON (AuthenticationResponseJSON). userHandle: the
  // user id (base64url) a discoverable credential sends, or null. Takes the next counter value,
  // unless counter is given.
  get({ challenge, origin, rpId, userHandle = null, type = 'webauthn.get', crossOrigin = false, extra = {}, counter = null, ...rest }) {
    if (counter !== null) this.counter = counter;
    else if (this.counter > 0) this.counter += 1;
    const clientDataJSON = SoftAuthenticator.clientData({ type, challenge, origin, crossOrigin, extra });
    const authData = this.authData({ rpId, ...rest });
    const signature = this.sign(Buffer.concat([authData, sha256(clientDataJSON)]));
    return {
      id: this.id,
      rawId: this.id,
      type: 'public-key',
      response: { clientDataJSON: b64url(clientDataJSON), authenticatorData: b64url(authData), signature: b64url(signature), userHandle },
      clientExtensionResults: {},
      authenticatorAttachment: 'platform',
    };
  }
}
