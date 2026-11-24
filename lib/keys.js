// The keys that protect the user store. The operator gives one master key per key version, in
// USERS_KEY_FILE (a path) or USERS_KEY (the keys themselves), as "VERSION:KEY" entries where KEY is
// base64url of 32 random bytes. The highest version is the current one: new secrets use it, and
// older versions stay so that what they protect can still be read until it is replaced.
//
// Each master key is never used directly. Three keys are derived from it with HKDF, one per use,
// so that no use can leak anything about another: the argon2 pepper for passwords, an AES-256-GCM
// key for TOTP secrets, and an HMAC key for recovery codes. A fourth derived value is stored next
// to the data so that a wrong key is noticed at start instead of locking everyone out later, and a
// fifth, never stored, picks the stand-in costs for unknown names at sign in.
//
// Errors here are read by the operator and may end up in logs: they name versions, entries and
// files, never key bytes.
import crypto from 'node:crypto';
import { constants as fsc } from 'node:fs';
import fs from 'node:fs/promises';
import path from 'node:path';

// Errors with a message for the operator. They never contain key bytes.
export class KeyError extends Error {}

export const MIN_VERSION = 1;
export const MAX_VERSION = 65535;
export const MAX_KEYS = 16;
export const MAX_KEY_TEXT_BYTES = 4096;
export const KEY_BYTES = 32;

const SALT = 'rettui-website users.db';
const LABELS = {
  pepper: 'rettui-website/password-pepper',
  totp: 'rettui-website/totp-key',
  recovery: 'rettui-website/recovery-hmac',
  check: 'rettui-website/key-check',
  standIn: 'rettui-website/stand-in',
};
const CHECK_BYTES = 16;

// TOTP box: format byte, key version (u16, big-endian), IV, ciphertext, GCM tag.
const BOX_FORMAT = 0x01;
const IV_BYTES = 12;
const TAG_BYTES = 16;
const HEADER_BYTES = 1 + 2 + IV_BYTES;
export const MIN_TOTP_SECRET_BYTES = 10;
export const MAX_TOTP_SECRET_BYTES = 64;
export const MIN_BOX_BYTES = HEADER_BYTES + MIN_TOTP_SECRET_BYTES + TAG_BYTES;
export const MAX_BOX_BYTES = HEADER_BYTES + MAX_TOTP_SECRET_BYTES + TAG_BYTES;

const derive = (master, label, length) => Buffer.from(crypto.hkdfSync('sha256', master, SALT, label, length));

// Reads key entries: "VERSION:KEY", separated by newlines or commas, with "#" starting a comment
// that runs to the end of the line. Gives a Map from version to the 32-byte master key, or throws a
// KeyError that names the entry by its number, never by its text (it may be a key).
export function parseKeys(text) {
  if (typeof text !== 'string') throw new KeyError('the keys must be text');
  if (Buffer.byteLength(text, 'utf8') > MAX_KEY_TEXT_BYTES) throw new KeyError(`the keys are longer than ${MAX_KEY_TEXT_BYTES} bytes`);
  const entries = text
    .split(/\r?\n|\r/)
    .flatMap((line) => line.replace(/#.*/, '').split(','))
    .map((e) => e.trim())
    .filter((e) => e !== '');
  if (entries.length === 0) throw new KeyError('there are no keys: each entry is VERSION:KEY (node scripts/users.js gen-key makes one)');
  if (entries.length > MAX_KEYS) throw new KeyError(`there are ${entries.length} keys; at most ${MAX_KEYS} are allowed`);
  const keys = new Map();
  entries.forEach((entry, i) => {
    const where = `key entry ${i + 1}`;
    const colon = entry.indexOf(':');
    if (colon < 0) throw new KeyError(`${where} is not in the form VERSION:KEY`);
    const v = entry.slice(0, colon).trim();
    const k = entry.slice(colon + 1).trim();
    if (!/^[1-9]\d{0,4}$/.test(v) || Number(v) > MAX_VERSION) throw new KeyError(`${where} has a version that is not a whole number from ${MIN_VERSION} to ${MAX_VERSION}`);
    const version = Number(v);
    // Buffer.from would decode nearly anything, so the text must come back out the same.
    const key = /^[A-Za-z0-9_-]+$/.test(k) ? Buffer.from(k, 'base64url') : null;
    if (!key || key.length !== KEY_BYTES || key.toString('base64url') !== k) {
      throw new KeyError(`${where} (version ${version}) is not ${KEY_BYTES} bytes of base64url (node scripts/users.js gen-key makes one)`);
    }
    if (keys.has(version)) throw new KeyError(`${where}: version ${version} is listed twice`);
    keys.set(version, key);
  });
  return keys;
}

// Whether file lies inside dir, after following links where the paths exist.
async function inside(file, dir) {
  const real = async (p) => fs.realpath(p).catch(() => path.resolve(p));
  const rel = path.relative(await real(dir), await real(file));
  return rel !== '' && !rel.startsWith('..') && !path.isAbsolute(rel);
}

// Reads at most max + 1 bytes of a regular file, so that a huge or growing file is never read whole.
// Opened without blocking, so that a FIFO or a device put in place of the key is refused by the
// check below instead of hanging the start until something writes to it.
async function readCapped(file, max) {
  const handle = await fs.open(file, fsc.O_RDONLY | (fsc.O_NONBLOCK ?? 0));
  try {
    const st = await handle.stat();
    if (!st.isFile()) throw new KeyError('it is not a regular file');
    if (st.size > max) throw new KeyError(`it is larger than ${max} bytes`);
    const buf = Buffer.alloc(max + 1);
    let n = 0;
    let got;
    do {
      ({ bytesRead: got } = await handle.read(buf, n, buf.length - n, n));
      n += got;
    } while (got > 0 && n < buf.length);
    // The file grew after the size was checked.
    if (n > max) throw new KeyError(`it is larger than ${max} bytes`);
    return { text: buf.subarray(0, n).toString('utf8'), mode: st.mode };
  } finally {
    await handle.close();
  }
}

// The keyring from USERS_KEY_FILE or USERS_KEY in env, or null when neither is set. Throws a
// KeyError when both are set or the keys cannot be used. Warns when the file can be read by other
// users, or lies in the data directory: a copy of the data directory (a backup, a shared volume)
// would then carry the key that unlocks it. dataDir defaults to env.DATA_DIR.
export async function loadKeys(env, { warn = console.warn, dataDir = env.DATA_DIR } = {}) {
  const file = env.USERS_KEY_FILE || null;
  const inline = env.USERS_KEY || null;
  if (file && inline) throw new KeyError('USERS_KEY_FILE and USERS_KEY are both set; set only one (USERS_KEY_FILE is safer)');
  if (inline) {
    try {
      return new Keyring(parseKeys(inline));
    } catch (err) {
      throw new KeyError(`USERS_KEY cannot be used: ${err.message}`);
    }
  }
  if (!file) return null;
  let read;
  try {
    read = await readCapped(file, MAX_KEY_TEXT_BYTES);
  } catch (err) {
    const e = new KeyError(`USERS_KEY_FILE ${file} cannot be read (${err instanceof KeyError ? err.message : (err.code ?? 'error')})`);
    // EACCES and the like, for a caller that can say what the file needs.
    if (!(err instanceof KeyError) && typeof err.code === 'string') e.code = err.code;
    throw e;
  }
  if (process.platform !== 'win32' && (read.mode & 0o077) !== 0) {
    warn(`warning: USERS_KEY_FILE ${file} can be read by other users (mode ${(read.mode & 0o777).toString(8)}); make it readable by the server only (chmod 400)`);
  }
  if (dataDir && (await inside(file, dataDir))) {
    warn(`warning: USERS_KEY_FILE ${file} is inside the data directory, so anyone with a copy of the data also has the key; keep it elsewhere`);
  }
  try {
    return new Keyring(parseKeys(read.text));
  } catch (err) {
    throw new KeyError(`USERS_KEY_FILE ${file} cannot be used: ${err.message}`);
  }
}

// The master keys by version and what is derived from them.
export class Keyring {
  #keys = new Map();
  #masters = new Map();
  #current;
  #versions;

  constructor(masters) {
    if (!(masters instanceof Map) || masters.size === 0) throw new KeyError('a keyring needs at least one key');
    for (const [v, master] of masters) {
      if (!Number.isInteger(v) || v < MIN_VERSION || v > MAX_VERSION) throw new KeyError(`key versions are ${MIN_VERSION} to ${MAX_VERSION}`);
      if (!Buffer.isBuffer(master) || master.length !== KEY_BYTES) throw new KeyError(`key version ${v} is not ${KEY_BYTES} bytes`);
      this.#masters.set(v, Buffer.from(master));
      this.#keys.set(v, {
        pepper: derive(master, LABELS.pepper, KEY_BYTES),
        totp: derive(master, LABELS.totp, KEY_BYTES),
        recovery: derive(master, LABELS.recovery, KEY_BYTES),
        check: derive(master, LABELS.check, CHECK_BYTES),
        standIn: derive(master, LABELS.standIn, KEY_BYTES),
      });
    }
    this.#versions = [...this.#keys.keys()].sort((a, b) => a - b);
    this.#current = this.#versions[this.#versions.length - 1];
  }

  get current() {
    return this.#current;
  }

  get versions() {
    return [...this.#versions];
  }

  has(v) {
    return this.#keys.has(v);
  }

  // A keyring with only these of its versions (the highest of them is its current one), or null
  // when none of them is here.
  subset(versions) {
    const keep = new Map([...this.#masters].filter(([v]) => versions.includes(v)));
    return keep.size === 0 ? null : new Keyring(keep);
  }

  #get(v) {
    const k = this.#keys.get(v);
    if (!k) throw new KeyError(`key version ${v} is not among the keys given (USERS_KEY_FILE or USERS_KEY)`);
    return k;
  }

  // Copies, so that a caller cannot change the keys held here.
  pepper(v) {
    return Buffer.from(this.#get(v).pepper);
  }

  // A value stored with the data for each version, to notice a wrong key at start.
  check(v) {
    return Buffer.from(this.#get(v).check);
  }

  // The key that picks which user an unknown name is made to look like at sign in (standIn in
  // users.js). From the lowest version, so that it stays the same across restarts and while a new
  // version is added.
  standInKey() {
    return Buffer.from(this.#get(this.#versions[0]).standIn);
  }

  // Encrypts a raw TOTP secret with the current key. aad ties the box to its row
  // ("totp|<kind>|<name_key>"), so a box copied to another user does not open.
  sealTotp(secret, aad) {
    if (!Buffer.isBuffer(secret) || secret.length < MIN_TOTP_SECRET_BYTES || secret.length > MAX_TOTP_SECRET_BYTES) {
      throw new RangeError(`a TOTP secret must be ${MIN_TOTP_SECRET_BYTES} to ${MAX_TOTP_SECRET_BYTES} bytes`);
    }
    if (typeof aad !== 'string') throw new TypeError('the associated data must be text');
    const header = Buffer.alloc(HEADER_BYTES);
    header[0] = BOX_FORMAT;
    header.writeUInt16BE(this.#current, 1);
    crypto.randomFillSync(header, 3, IV_BYTES);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.#get(this.#current).totp, header.subarray(3), { authTagLength: TAG_BYTES });
    cipher.setAAD(Buffer.from(aad, 'utf8'));
    const body = Buffer.concat([cipher.update(secret), cipher.final()]);
    return Buffer.concat([header, body, cipher.getAuthTag()]);
  }

  // The key version a box was sealed with. Throws a KeyError when it is not a box.
  boxVersion(box) {
    if (!Buffer.isBuffer(box) || box.length < MIN_BOX_BYTES || box.length > MAX_BOX_BYTES || box[0] !== BOX_FORMAT) {
      throw new KeyError('a stored TOTP secret is not in a known form; the data is damaged');
    }
    return box.readUInt16BE(1);
  }

  // The raw TOTP secret in a box. Throws a KeyError when its key version is not here, or when the
  // box does not open: a wrong key, other associated data, or a changed byte.
  openTotp(box, aad) {
    const v = this.boxVersion(box);
    if (typeof aad !== 'string') throw new TypeError('the associated data must be text');
    const k = this.#get(v);
    try {
      const decipher = crypto.createDecipheriv('aes-256-gcm', k.totp, box.subarray(3, HEADER_BYTES), { authTagLength: TAG_BYTES });
      decipher.setAAD(Buffer.from(aad, 'utf8'));
      decipher.setAuthTag(box.subarray(box.length - TAG_BYTES));
      return Buffer.concat([decipher.update(box.subarray(HEADER_BYTES, box.length - TAG_BYTES)), decipher.final()]);
    } catch {
      throw new KeyError(`a stored TOTP secret does not decrypt with key version ${v}: the key is wrong or the data is damaged`);
    }
  }

  // The stored form of a recovery code: an HMAC of its old SHA-256 (hashRecoveryCode in users.js),
  // so that codes saved before there was a key can be wrapped without knowing the codes.
  recoveryHash(v, legacyHex) {
    if (typeof legacyHex !== 'string' || !/^[0-9a-f]{64}$/.test(legacyHex)) throw new TypeError('a recovery code hash must be 64 lower-case hex digits');
    return crypto.createHmac('sha256', this.#get(v).recovery).update(Buffer.from(legacyHex, 'hex')).digest('hex');
  }
}
