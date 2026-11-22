// The user store. It holds the users made on the website (name, role, password hash) and the
// second factor of every user, including those in the config file, whose name, password and role
// stay in the config file. On disk it is users.db in the data directory (see userdb.js); here every
// record is kept in memory, in the shape users.json had, and every read is served from memory.
//
// A store that cannot be read stops the server with a message, and is left as it is: a broken file
// must never become an empty store, which would drop everyone's second factor.
//
// A change is written first, in one short transaction, and only then made in memory, so a failed
// write leaves the store as it is on disk. The exceptions are changed in memory first and then
// written (see save): a used code, which counts as used at once (checkTotp, useRecoveryCode), the
// time of a sign in, and devices.
//
// Another program (scripts/users.js) may change the store while the server runs. Before every
// write, and once a second (watch), the store notices that and reads every record again (reload).
// Changes that matter for sessions (a user made, removed, given another password or role, or a
// second factor taken away) are given to onExternalChange, which ends that user's sessions. A
// write that finds such a change inside its transaction gives it up, has the change acted on, and
// runs again (see write), so that a check of the session (guard) sees the session that ended.
//
// When the store cannot be read again (a row that does not decrypt with the keys this server has,
// a schema that was changed), what is in memory may be stale: a user deleted elsewhere would still
// be there. The store then counts as unreadable until a later read works: onUnreadable and
// onReadable are told, and login.js turns signing in off and ends every session meanwhile.
//
// Whoever calls createUser, setPassword, deleteUser, setRole or resetSecondFactor (and turns a
// second factor on or off) must call auth.endUser(name) from login.js once it worked: that ends the user's
// sessions and open second steps and forgets their devices, so nobody stays signed in on what was
// just taken away.
//
// Limits: at most MAX_STORE_USERS users, MAX_RECOVERY_CODES recovery codes, MAX_DEVICES devices
// and MAX_PASSKEYS passkeys per user. A write past them is refused with StoreFullError and changes
// nothing.
//
// Second factors: TOTP and passkeys (WebAuthn credentials, in credentials[], each named by its ref:
// the start of the SHA-256 of its id). A user has a second factor when either is on. Recovery
// codes belong to the second factor as a whole: they are made when the first one is turned on and
// cleared when the last one goes. Passkeys are checked by passkeys.js; here they are only kept.
// Their ids and public keys are not secret, but are never logged or shown: the API and the audit
// log name a passkey by its ref and name only.
//
// Keys (keys.js): passwords set on the website are peppered with the current key (currentPepper),
// TOTP secrets are encrypted and recovery codes kept as an HMAC under it. A store without a
// database (tests, or a login without a data directory) keeps recovery codes as plain SHA-256.
//
// Known devices: each browser a user signed in from gets a random device id in a cookie; only its
// SHA-256 is kept here, in the user's record (devices, at most MAX_DEVICES, the least recently used
// one goes first). Unlike other changes, devices are changed in memory first and then written: a
// device that is forgotten must stop working at once, even when the write fails. Devices made by a
// passkey sign in alone are at most MAX_PASSKEY_DEVICES and only push out each other, so that nobody
// who holds a passkey can push a device made with the password out. Which devices those are is kept
// in memory only (the device record has no field for it); after a restart they count as the others,
// and are still never known for passwords (login.js reads that from the id).
import crypto from 'node:crypto';
import { KeyError } from './keys.js';
import { dummyPhc, parsePhc } from './password.js';
import { base32Decode, newSecret, verifyTotp } from './totp.js';
import { MAX_PASSKEYS, StoreBusyError, openUserDb } from './userdb.js';

export const STORE_FILE = 'users.json';
export const STORE_VERSION = 1;
export const ROLES = ['admin', 'manage', 'viewer'];
export const DEFAULT_ROLE = 'viewer';
// A user name: letters, digits, dot, dash and underscore, starting with a letter or digit.
export const USER_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$/;
// Names no user may have: the website signs its own background reads of the nodes with them (see
// lib/links.js), so a person with the same name would be taken for that job in a node's log.
export const RESERVED_NAMES = ['status-links'];
export const reservedName = (name) => typeof name === 'string' && RESERVED_NAMES.includes(name.toLowerCase());
export const RESERVED_NAME_TEXT = 'that name is reserved for the website itself: choose another';
export const RECOVERY_CODES = 10;
export const MAX_STORE_USERS = 500;
export const MAX_RECOVERY_CODES = 20;
const MAX_CREDENTIALS = 50;
export const MAX_DEVICES = 10;
// Of those, the devices made by a passkey sign in alone (see rememberDevice) are at most this many per user.
export const MAX_PASSKEY_DEVICES = 3;
// The time of a sign in (and of a known device's use) is written at most this often per user.
export const LOGIN_WRITE_MS = 60_000;
// How often a running server looks for changes made by another program (see watch).
export const WATCH_MS = 1000;
// A store that cannot be read again is logged at most this often.
const FAILED_LOG_MS = 60_000;
// What was deleted or replaced is cleared from users.db-wal (scrub) at most this often.
const SCRUB_MS = 1000;
// How often a write runs again when the store keeps changing elsewhere under it; the last time it
// goes ahead on what it read.
const WRITE_TRIES = 5;
// Thrown inside a write's transaction to give it up and run it again (see write).
const AGAIN = Symbol('again');
const HEX64 = /^[0-9a-f]{64}$/;
// A recovery code as kept with a database: the key version, and the HMAC of its SHA-256 under it.
const WRAPPED = /^k([1-9]\d{0,4}):([0-9a-f]{64})$/;
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?Z$/;
// Recovery codes: 16 base32 letters and digits (80 bits), shown in groups of four.
const RECOVERY_ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567';
// What a passkey may hold: the ways an authenticator can be reached, and the bounds of its fields.
export const PASSKEY_TRANSPORTS = ['ble', 'cable', 'hybrid', 'internal', 'nfc', 'smart-card', 'usb'];
export const MAX_PASSKEY_NAME = 64;
const MAX_PASSKEY_ID_BYTES = 512;
const MAX_PASSKEY_KEY_BYTES = 600;
const MAX_TRANSPORTS = 8;
const MAX_RP_ID = 253;
const MAX_COUNTER = 2 ** 32 - 1;
const RP_ID = /^[A-Za-z0-9.-]+$/;
// Control characters, line and paragraph separators, the marks that turn text around (bidi
// controls, U+061C, U+200E and U+200F among them) and characters that take no room (zero width
// space, joiners, word joiner, byte order mark): a name with them could hide what it is, or break
// the page or the log it is shown in. More than MAX_MARK_RUN combining marks in a row pile up over
// the text around them.
const BAD_NAME_CHARS = /[\p{Cc}\p{Zl}\p{Zp}\p{Bidi_Control}\u200b-\u200d\u2060\ufeff]/u;
const MAX_MARK_RUN = 3;
const MARK_RUN = new RegExp(`\\p{M}{${MAX_MARK_RUN + 1}}`, 'u');
// How often the time of a passkey's use is written when nothing else about it changed.
const PASSKEY_WRITE_MS = LOGIN_WRITE_MS;

// The store cannot be read or makes no sense; the server must not start.
export class StoreError extends Error {}

// A write refused because the store would have more users, codes or devices than it reads.
export class StoreFullError extends Error {
  constructor(message = 'the user store is full') {
    super(message);
    this.code = 'full';
  }
}

export { MAX_PASSKEYS, StoreBusyError };

// What the website says when a change could not be written for one of the reasons above, or null.
export function writeRefusal(err) {
  if (err instanceof StoreFullError) return 'The user store is full, so nothing was changed. Delete users that are not needed any more.';
  if (err instanceof StoreBusyError) return 'Another program is changing the user store; nothing was changed. Try again.';
  return null;
}

// A change the store refuses. code is one of: 'bad-name', 'reserved-name', 'bad-role', 'exists', 'unknown',
// 'config' (the user is in the config file), 'last-admin', 'full' (MAX_STORE_USERS users, or
// MAX_PASSKEYS passkeys), 'bad-label' (a passkey name that cannot be kept).
export class UserError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

const isMap = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const key = (name) => (typeof name === 'string' ? name.trim().toLowerCase() : '');

// A recovery code as typed: case, spaces and dashes do not matter.
export const normalRecoveryCode = (text) => (typeof text === 'string' ? text.toLowerCase().replace(/[\s-]+/g, '') : '');
export const hashRecoveryCode = (text) => crypto.createHash('sha256').update(`rettui-recovery:${normalRecoveryCode(text)}`).digest('hex');

export function newRecoveryCode() {
  const bytes = crypto.randomBytes(16);
  let out = '';
  for (let i = 0; i < 16; i++) out += RECOVERY_ALPHABET[bytes[i] & 31];
  return out.match(/.{4}/g).join('-');
}

const newRecoveryCodes = () => Array.from({ length: RECOVERY_CODES }, newRecoveryCode);

const wrappedCode = (h) => {
  const m = WRAPPED.exec(h);
  return m !== null && Number(m[1]) <= 65535;
};

// Whether s is base64url without padding, in the one way those bytes are written, of min to max
// bytes.
function isB64url(s, min, max) {
  if (typeof s !== 'string' || s.length > Math.ceil((max * 4) / 3) || !/^[A-Za-z0-9_-]*$/.test(s)) return false;
  const b = Buffer.from(s, 'base64url');
  return b.length >= min && b.length <= max && b.toString('base64url') === s;
}

// The ref of a passkey: the first 16 hex digits of the SHA-256 of its id (the bytes, not their
// base64url). It is what the API and the audit log name a passkey by.
export const passkeyRef = (id) => crypto.createHash('sha256').update(Buffer.from(id, 'base64url')).digest('hex').slice(0, 16);

// Whether a passkey name can be kept: 1 to MAX_PASSKEY_NAME characters, none of them BAD_NAME_CHARS,
// no half of a UTF-16 surrogate pair alone (it would be written to the database as something
// else), and no more than MAX_MARK_RUN combining marks in a row. The one rule for names, when one is
// added, renamed and read from the database (passkeys.js uses it too). (A character takes at most
// two UTF-16 units, so a longer text is not spread out first.) Tightening this rule later is safe
// for the database: a stored name it refuses is read as "Passkey N" (userdb.js, record), not
// refused with the store. It still renames those passkeys for their users, so loosen it freely,
// but tighten it only with a note in the changelog.
export const goodPasskeyName = (s) =>
  typeof s === 'string' && s.length > 0 && s.length <= 2 * MAX_PASSKEY_NAME && s.isWellFormed() && [...s].length <= MAX_PASSKEY_NAME && !BAD_NAME_CHARS.test(s) && !MARK_RUN.test(s);

// A passkey name as typed, trimmed, or null when it cannot be kept (goodPasskeyName).
export function passkeyLabel(text) {
  if (typeof text !== 'string' || text.length > 4 * MAX_PASSKEY_NAME) return null;
  const name = text.trim();
  return goodPasskeyName(name) ? name : null;
}

// What is wrong with a stored passkey, as the field's name, or null when nothing is.
function passkeyFault(c) {
  if (!isMap(c) || c.type !== 'passkey') return 'type';
  if (!isB64url(c.id, 1, MAX_PASSKEY_ID_BYTES)) return 'id';
  if (!isB64url(c.publicKey, 1, MAX_PASSKEY_KEY_BYTES)) return 'publicKey';
  if (!Number.isSafeInteger(c.counter) || c.counter < 0 || c.counter > MAX_COUNTER) return 'counter';
  if (!Array.isArray(c.transports) || c.transports.length > MAX_TRANSPORTS || !c.transports.every((t) => PASSKEY_TRANSPORTS.includes(t))) return 'transports';
  if (!goodPasskeyName(c.name)) return 'name';
  if (typeof c.created !== 'string' || !ISO.test(c.created)) return 'created';
  if (c.lastUsed !== null && (typeof c.lastUsed !== 'string' || !ISO.test(c.lastUsed))) return 'lastUsed';
  if (typeof c.backupEligible !== 'boolean') return 'backupEligible';
  if (typeof c.backedUp !== 'boolean') return 'backedUp';
  if (typeof c.rpId !== 'string' || c.rpId.length > MAX_RP_ID || !RP_ID.test(c.rpId)) return 'rpId';
  return null;
}

// Checks one record; throws a StoreError that says where, never the value. wrapped: the record is
// in the database's form: recovery codes may also be kept as an HMAC with a key version, and
// credentials are passkeys, checked strictly. users.json has SHA-256 codes only, and its
// credentials are only looked at in passing (the import drops them).
export function checkRecord(r, where, local, wrapped = false) {
  if (!isMap(r)) throw new StoreError(`${where} is not an object`);
  if (typeof r.name !== 'string' || !USER_NAME_RE.test(r.name)) throw new StoreError(`${where}.name is not a valid user name`);
  if (local) {
    if (!ROLES.includes(r.role)) throw new StoreError(`${where}.role must be one of ${ROLES.join(', ')}`);
    try {
      parsePhc(r.passwordHash);
    } catch (err) {
      throw new StoreError(`${where}.passwordHash ${err.message}`);
    }
  }
  for (const k of ['created', 'lastLogin']) {
    if (r[k] !== undefined && r[k] !== null && (typeof r[k] !== 'string' || !ISO.test(r[k]))) throw new StoreError(`${where}.${k} is not a time`);
  }
  if (r.mustChangePassword !== undefined && typeof r.mustChangePassword !== 'boolean') throw new StoreError(`${where}.mustChangePassword must be true or false`);
  if (r.totp !== undefined && r.totp !== null) {
    const t = r.totp;
    if (!isMap(t)) throw new StoreError(`${where}.totp is not an object`);
    const secret = base32Decode(t.secret);
    if (!secret || secret.length < 10 || secret.length > 64) throw new StoreError(`${where}.totp.secret is not a base32 secret of 10 to 64 bytes`);
    if (typeof t.enabled !== 'boolean') throw new StoreError(`${where}.totp.enabled must be true or false`);
    if (t.lastUsedStep !== null && t.lastUsedStep !== undefined && (!Number.isSafeInteger(t.lastUsedStep) || t.lastUsedStep < 0)) throw new StoreError(`${where}.totp.lastUsedStep must be a whole number or null`);
  }
  if (r.recoveryCodes !== undefined) {
    const ok = (h) => typeof h === 'string' && (HEX64.test(h) || (wrapped && wrappedCode(h)));
    if (!Array.isArray(r.recoveryCodes) || r.recoveryCodes.length > MAX_RECOVERY_CODES || !r.recoveryCodes.every(ok)) {
      throw new StoreError(`${where}.recoveryCodes must be a list of at most ${MAX_RECOVERY_CODES} SHA-256 hashes`);
    }
  }
  if (r.devices !== undefined) {
    const ok = (d) => isMap(d) && typeof d.hash === 'string' && HEX64.test(d.hash) && typeof d.created === 'string' && ISO.test(d.created) && typeof d.lastUsed === 'string' && ISO.test(d.lastUsed);
    if (!Array.isArray(r.devices) || r.devices.length > MAX_DEVICES || !r.devices.every(ok)) {
      throw new StoreError(`${where}.devices must be a list of at most ${MAX_DEVICES} devices, each with a SHA-256 hash and two times`);
    }
  }
  if (r.credentials !== undefined && wrapped) {
    if (!Array.isArray(r.credentials) || r.credentials.length > MAX_PASSKEYS) throw new StoreError(`${where}.credentials must be a list of at most ${MAX_PASSKEYS} passkeys`);
    const ids = new Set();
    r.credentials.forEach((c, i) => {
      const fault = passkeyFault(c);
      if (fault !== null) throw new StoreError(`${where}.credentials[${i + 1}].${fault} is not valid`);
      if (ids.has(c.id)) throw new StoreError(`${where}.credentials[${i + 1}] is listed twice`);
      ids.add(c.id);
    });
  } else if (r.credentials !== undefined) {
    if (!Array.isArray(r.credentials) || r.credentials.length > MAX_CREDENTIALS || !r.credentials.every((c) => isMap(c) && typeof c.type === 'string' && c.type.length > 0 && c.type.length <= 32)) {
      throw new StoreError(`${where}.credentials must be a list of at most ${MAX_CREDENTIALS} objects with a type`);
    }
  }
  if (r.lxmf !== undefined) {
    const l = r.lxmf;
    if (!isMap(l) || typeof l.address !== 'string' || !/^[0-9a-f]{32}$/.test(l.address) || typeof l.confirmed !== 'boolean' || typeof l.nodeAlerts !== 'boolean') {
      throw new StoreError(`${where}.lxmf must be a 32 digit lower-case hex address with confirmed and nodeAlerts as true or false`);
    }
  }
  if (wrapped && r.passkeyUserId !== undefined && r.passkeyUserId !== null && !isB64url(r.passkeyUserId, 32, 32)) {
    throw new StoreError(`${where}.passkeyUserId is not 32 bytes in base64url`);
  }
}

// The records of the text of a users.json, checked; the import (userdb.js) reads it with this.
// maxBytes and maxUsers bound it.
export function parseStore(text, { maxBytes = 8 * 1024 * 1024, maxUsers = MAX_STORE_USERS } = {}) {
  if (Buffer.byteLength(text) > maxBytes) throw new StoreError(`it is larger than ${maxBytes / 1024} KiB`);
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    throw new StoreError('it is not valid JSON');
  }
  if (!isMap(data)) throw new StoreError('it is not a JSON object');
  if (data.version !== STORE_VERSION) {
    throw new StoreError(Number.isInteger(data.version) && data.version > STORE_VERSION ? `it was written by a newer version (store version ${data.version})` : 'it has no known version');
  }
  const lists = {};
  for (const [field, local] of [['users', true], ['configUsers', false]]) {
    const list = data[field] ?? [];
    if (!Array.isArray(list) || list.length > maxUsers) throw new StoreError(`${field} must be a list of at most ${maxUsers} users`);
    const seen = new Set();
    list.forEach((r, i) => {
      checkRecord(r, `${field}[${i + 1}]`, local);
      if (seen.has(key(r.name))) throw new StoreError(`${field}[${i + 1}].name is listed twice`);
      seen.add(key(r.name));
    });
    lists[field] = list;
  }
  return { extra: data, users: lists.users, configUsers: lists.configUsers };
}

// Whether the store's records ({users, configUsers}, as openUserDb gives them) have users who sign
// in with a password of their own. The config file's checks need this before the store is made.
export const storeHasUsers = (data) => (data?.users.length ?? 0) > 0;

const samePhc = (a, b) => Boolean(a && b) && a.salt.equals(b.salt) && a.hash.equals(b.hash) && a.memory === b.memory && a.passes === b.passes && a.parallelism === b.parallelism && (a.keyid ?? null) === (b.keyid ?? null);

// Whether the record b no longer has a secret a had: another password hash, TOTP secret, recovery
// codes or passkeys. What it had is then cleared from users.db-wal (scrubSoon).
const replacesSecrets = (a, b) =>
  a.passwordHash !== b.passwordHash ||
  (a.totp?.secret ?? null) !== (b.totp?.secret ?? null) ||
  (a.recoveryCodes ?? []).some((c) => !(b.recoveryCodes ?? []).includes(c)) ||
  (a.credentials ?? []).some((c) => !(b.credentials ?? []).some((d) => d.id === c.id));

// What about a record matters for the sessions of its user, to tell a change made elsewhere.
const secondFactorOf = (r) => `${r?.totp?.enabled === true}|${r?.totp?.enabled === true ? r.totp.secret : ''}|${(r?.credentials ?? []).map((c) => c.id ?? '').join(',')}`;

// Whether a record has a second factor on: TOTP, or a passkey.
const factorOn = (r) => r?.totp?.enabled === true || (r?.credentials ?? []).length > 0;

// A record without its passkeys but keepRef (all of them when it is null): {next, removed, ids,
// secondFactorOff}. next is the record itself when there was nothing to remove. Without any
// passkey left the recovery codes go too, as when the last one is removed.
function withoutOtherPasskeys(cur, keepRef) {
  const list = cur?.credentials ?? [];
  const keep = list.filter((c) => keepRef !== null && passkeyRef(c.id) === keepRef);
  const gone = list.filter((c) => !keep.includes(c));
  if (gone.length === 0) return { next: cur, removed: 0, ids: [], secondFactorOff: false };
  const next = { ...cur, credentials: keep };
  const secondFactorOff = !factorOn(next);
  if (secondFactorOff) next.recoveryCodes = [];
  return { next, removed: gone.length, ids: gone.map((c) => c.id), secondFactorOff };
}

// What the account and users pages may see of a passkey: no id, no key.
const passkeyView = (c) => ({ ref: passkeyRef(c.id), name: c.name, created: c.created, lastUsed: c.lastUsed, backedUp: c.backedUp, backupEligible: c.backupEligible, rpId: c.rpId });

// A copy of a stored passkey, with its ref, for passkeys.js.
const passkeyCopy = (c) => ({ ...c, transports: [...c.transports], ref: passkeyRef(c.id) });

export class UserStore {
  // db: the UserDb the records are kept in, or null for a store in memory only (tests, or a login
  // without a data directory). data: its records, {users, configUsers} (read from db when not
  // given). configUsers: [{name, phc, role}] from the config file. keys: the Keyring, or null.
  // maxUsers is lower only in tests. log: where a store that cannot be read again is said.
  constructor({ db = null, data = null, configUsers = [], keys = null, warn = console.warn, now = Date.now, log = console.error, maxUsers = MAX_STORE_USERS, dropOrphans = false }) {
    Object.assign(this, { db, keys, now, warn, log, maxUsers });
    // Called with (name, what) after another program changed a user; what lists 'created',
    // 'deleted', 'password', 'role' or 'second-factor'. login.js ends that user's sessions.
    this.onExternalChange = null;
    // Called with (err) when the store cannot be read again, and with () once it can (see the top).
    // They run where the read failed, maybe inside a transaction: they must not write to the store.
    this.onUnreadable = null;
    this.onReadable = null;
    // The error of the last read that failed, while the store cannot be read; else null.
    this.unreadable = null;
    // Picks the costs an unknown name is checked with (standIn) when there are no keys: new for
    // each process then. With keys, a key derived from them is used instead.
    this.standInKey = crypto.randomBytes(32);
    // Changes found by a reload, given to onExternalChange once the transaction is over.
    this.changes = [];
    this.timer = null;
    this.failedLoggedAt = null;
    // See scrubSoon.
    this.scrubPending = false;
    this.scrubTimer = null;
    this.scrubbedAt = null;
    this.config = new Map(configUsers.map((u) => [key(u.name), { name: u.name, phc: u.phc, role: u.role ?? DEFAULT_ROLE }]));
    this.local = new Map();
    this.factors = new Map();
    const records = data ?? db?.load() ?? null;
    for (const r of records?.users ?? []) this.local.set(key(r.name), r);
    // The second factors of a user who is not in the config file (any more) are not used: the name
    // could be given to someone else, who must not inherit them. They are forgotten (see open).
    this.orphans = [];
    this.dropOrphans = dropOrphans;
    for (const r of records?.configUsers ?? []) {
      if (this.config.has(key(r.name)) || !dropOrphans) this.factors.set(key(r.name), r);
      else this.orphans.push(key(r.name));
    }
    for (const k of this.orphans) warn(`the user store: "${k}" has a second factor (passkeys, an app code) kept for a user who is not in the config file. It is not used, and it is removed now; the user starts without one if they are put back.`);
    // A user named like the website's own background reads cannot be a person: no sign in, no role change.
    for (const r of this.local.values()) if (reservedName(r.name)) warn(`the user store: the user "${r.name}" has a name that is reserved for the website itself. It cannot sign in or be changed; delete it.`);
    // When the time of a sign in was last written, by user.
    this.touched = new Map();
    // The hashes of devices made by a passkey sign in alone, oldest first (see rememberDevice).
    this.passkeyDevices = new Set();
    // When the time of a passkey's use was last written, by `${user key}|${passkey id}`.
    this.passkeyTouched = new Map();
    for (const k of this.local.keys()) {
      if (this.config.has(k)) {
        warn(`the user store: the user "${this.local.get(k).name}" is also in the config file; the one in the config file is used, and the one in the user store cannot sign in`);
      }
    }
  }

  // Opens users.db in dataDir (made, and users.json imported, when there is none). Throws
  // StoreError (with a message for the operator) when it is there but cannot be used.
  // keys: the keyring given; the store keeps only the versions users.db has recorded (openUserDb),
  // and unrecordedKeys lists the others. recordKeys: see openUserDb.
  static async open({ dataDir, configUsers = [], keys = null, warn = console.warn, now = Date.now, log = console.error, maxUsers = MAX_STORE_USERS, timeoutMs = 1000, recordKeys = true, dropOrphans = false }) {
    const opened = await openUserDb({ dataDir, keys, timeoutMs, warn, maxUsers, now, recordKeys });
    const store = new UserStore({ db: opened.db, data: opened.data, configUsers, keys: opened.keys, warn, now, log, maxUsers, dropOrphans });
    store.unrecordedKeys = opened.unrecorded;
    return store;
  }

  // The website (not the command line, which does not know the config file) asks for this: it removes
  // the records of config users who are gone (the constructor listed them), and says how many.
  forgetOrphans() {
    const n = this.orphans.length;
    if (n === 0 || this.db === null) return 0;
    this.write(() => {
      for (const k of this.orphans) this.db.remove('config', k);
    });
    this.orphans = [];
    this.scrubSoon();
    return n;
  }

  iso() {
    return new Date(this.now()).toISOString();
  }

  // Reads every record again, in place, and notes what changed for whom (see onExternalChange). A
  // read that fails for what is in the store (not for a store busy elsewhere) makes the store
  // unreadable until one works again (see the top).
  reload() {
    let data;
    try {
      data = this.db.load();
    } catch (err) {
      if ((err instanceof StoreError || err instanceof KeyError) && this.unreadable === null) {
        this.unreadable = err;
        this.tell(this.onUnreadable, err);
      }
      throw err;
    }
    if (this.unreadable !== null) {
      this.unreadable = null;
      this.tell(this.onReadable);
    }
    const changed = new Map();
    const note = (k, name, what) => {
      // A website user hidden by a config user of the same name cannot sign in: its changes do not
      // touch the config user's sessions.
      if (!changed.has(k)) changed.set(k, { name, what: new Set() });
      changed.get(k).what.add(what);
    };
    const swap = (map, list, local) => {
      const before = new Map(map);
      map.clear();
      for (const r of list) map.set(key(r.name), r);
      for (const k of new Set([...before.keys(), ...map.keys()])) {
        if (local && this.config.has(k)) continue;
        const b = before.get(k);
        const a = map.get(k);
        const name = a?.name ?? b.name;
        if (local && !b) note(k, name, 'created');
        else if (local && !a) note(k, name, 'deleted');
        else {
          if (local && (a.passwordHash !== b.passwordHash || (a.mustChangePassword === true) !== (b.mustChangePassword === true))) note(k, name, 'password');
          if (local && a.role !== b.role) note(k, name, 'role');
          if (secondFactorOf(a) !== secondFactorOf(b)) note(k, name, 'second-factor');
        }
      }
    };
    swap(this.local, data.users, true);
    swap(this.factors, this.dropOrphans ? data.configUsers.filter((r) => this.config.has(key(r.name))) : data.configUsers, false);
    for (const k of this.touched.keys()) if (!this.local.has(k) && !this.factors.has(k)) this.touched.delete(k);
    this.forgetPasskeyTimes();
    const order = ['created', 'deleted', 'password', 'role', 'second-factor'];
    for (const { name, what } of changed.values()) this.changes.push([name, order.filter((w) => what.has(w))]);
  }

  tell(callback, ...args) {
    try {
      callback?.(...args);
    } catch (err) {
      this.log(`error: a change in whether the user store can be read could not be acted on: ${err.message}`);
    }
  }

  // Runs fn in a write transaction and gives what it gave. When another program changed the store,
  // the change is read first; then the transaction is given up and the changes are acted on
  // (onExternalChange ends sessions), and it runs again, so that fn (and a guard in it) sees the
  // sessions as they are after the change. The last of WRITE_TRIES goes ahead on what it read. The
  // caller calls notify once the result is in memory.
  write(fn) {
    for (let tries = 1; ; tries++) {
      try {
        return this.db.tx(() => {
          if (this.db.changedElsewhere()) {
            this.reload();
            if (tries < WRITE_TRIES) throw AGAIN;
          }
          return fn();
        });
      } catch (err) {
        if (err !== AGAIN) throw err;
        this.notify();
      }
    }
  }

  // Gives the changes a reload found to onExternalChange. Runs after the transaction, since the
  // callback may write (endUser forgets devices).
  notify() {
    const changes = this.changes;
    this.changes = [];
    for (const [name, what] of changes) {
      try {
        this.onExternalChange?.(name, what);
      } catch (err) {
        this.log(`error: a change to ${name} made elsewhere could not be acted on: ${err.message}`);
      }
    }
  }

  // Reads the store again when another program changed it. Gives whether it did.
  refresh() {
    if (this.db === null || !this.db.changedElsewhere()) return false;
    try {
      this.reload();
    } finally {
      this.notify();
    }
    return true;
  }

  // Looks for changes made by another program every intervalMs, until close(). The timer does not
  // keep the process alive. A store that cannot be read again is logged at most once a minute,
  // and what is in memory stays.
  watch(intervalMs = WATCH_MS) {
    if (this.db === null || this.timer !== null) return;
    this.timer = setInterval(() => {
      // A scrub that found the store busy is tried again.
      if (this.scrubPending && this.scrubTimer === null) this.scrubSoon();
      try {
        this.refresh();
      } catch (err) {
        const t = this.now();
        if (this.failedLoggedAt === null || t - this.failedLoggedAt >= FAILED_LOG_MS || t < this.failedLoggedAt) {
          this.failedLoggedAt = t;
          this.log(`error: the user store could not be read again: ${err.message}`);
        }
      }
    }, intervalMs);
    this.timer.unref();
  }

  close() {
    if (this.timer !== null) clearInterval(this.timer);
    this.timer = null;
    if (this.scrubTimer !== null) clearTimeout(this.scrubTimer);
    this.scrubTimer = null;
    if (this.scrubPending && this.db?.sql.isOpen) this.db.scrub();
    this.scrubPending = false;
    this.db?.close();
  }

  // Clears what was just deleted or replaced (a user, a password hash, a second factor, a used
  // recovery code) from users.db-wal too, where SQLite keeps the last changes until a checkpoint
  // (see UserDb.scrub). Runs after the write, never inside it; at most once every SCRUB_MS, so
  // that changes close together are cleared together. One that finds the store busy is tried again
  // by watch, and by close.
  scrubSoon() {
    if (this.db === null) return;
    this.scrubPending = true;
    if (this.scrubTimer !== null) return;
    const wait = this.scrubbedAt === null ? 0 : Math.max(0, this.scrubbedAt + SCRUB_MS - performance.now());
    if (wait === 0) {
      this.scrubNow();
      return;
    }
    this.scrubTimer = setTimeout(() => {
      this.scrubTimer = null;
      this.scrubNow();
    }, wait);
    this.scrubTimer.unref();
  }

  scrubNow() {
    if (!this.scrubPending || !this.db.sql.isOpen) return;
    this.scrubbedAt = performance.now();
    if (this.db.scrub()) this.scrubPending = false;
  }

  // Every write is synchronous and done when the call that asked for it returns; there is nothing
  // to wait for. Kept so that a server stopping can wait the same way as before.
  async flush() {}

  // Writes a user's record after a change made in memory first. apply makes the same change to a
  // record: when another program changed the store meanwhile, the record is read again, and the
  // change made on the fresh one too, so neither change is lost. create: make a record for a
  // config user who has none (devices). Gives the write as a promise; when it fails, the change
  // stays in memory.
  save(name, apply, { create = false, scrub = false } = {}) {
    if (this.db === null) return Promise.resolve();
    const h0 = this.home(name);
    const mine = h0 ? h0.map.get(h0.k) : undefined;
    try {
      this.write(() => {
        const h = this.home(name);
        if (!h) return;
        let r = h.map.get(h.k);
        if (!r && create) {
          r = h.fresh();
          if (r) h.map.set(h.k, r);
        }
        if (!r) return;
        if (r !== mine) apply(r);
        this.db.put(h.map === this.local ? 'store' : 'config', r);
      });
      if (scrub) this.scrubSoon();
      return Promise.resolve();
    } catch (err) {
      return Promise.reject(err);
    } finally {
      this.notify();
    }
  }

  // Changes one record: change(current) gives the new record, or null to remove it, and may throw
  // UserError. It runs in a transaction, on the record as it is in the store then; the new record
  // is written, and only once that worked is it put in memory. Gives the record. guard, when
  // given, is asked right before: false refuses the change with UserError 'gone' (the session that
  // asked for it ended meanwhile). The devices in memory are kept (see addDevice).
  commit(map, k, change, guard = null) {
    const run = () => {
      if (guard !== null && !guard()) throw new UserError('gone', 'the session that asked for this has ended');
      return change(map.get(k) ?? null);
    };
    // Changes found meanwhile are given on only once the new record is in memory: their callback
    // may write this record too (endUser forgets devices), and must not write the old one.
    let gone = false;
    try {
      const next = this.db === null
        ? run()
        : this.write(() => {
          const cur = map.get(k) ?? null;
          const n = run();
          const kind = map === this.local ? 'store' : 'config';
          if (n === null) this.db.remove(kind, k);
          else this.db.put(kind, n);
          gone = cur !== null && (n === null || replacesSecrets(cur, n));
          return n;
        });
      if (gone) this.scrubSoon();
      const live = map.get(k);
      if (next !== null && live?.devices) next.devices = live.devices;
      if (next === null) map.delete(k);
      else map.set(k, next);
      return next;
    } finally {
      this.notify();
    }
  }

  // Where a user's second factor is kept: {map, k, fresh} (fresh makes a record for a config user
  // who has none yet), or null for an unknown name.
  home(name) {
    const k = key(name);
    const c = this.config.get(k);
    if (c) return { map: this.factors, k, fresh: () => ({ name: c.name, created: this.iso(), lastLogin: null, totp: null, recoveryCodes: [], credentials: [], devices: [] }) };
    if (this.local.has(k)) return { map: this.local, k, fresh: () => null };
    return null;
  }

  // Whether there are users made on the website (besides those in the config file).
  hasLocalUsers() {
    for (const k of this.local.keys()) if (!this.config.has(k)) return true;
    return false;
  }

  // The user who signs in with a name: {name, role, source: 'config' | 'store', phc, secret}, or
  // null. secret is the pepper for phc.keyid, or null (config users are never peppered).
  find(name) {
    const k = key(name);
    const c = this.config.get(k);
    if (c) return { name: c.name, role: c.role, source: 'config', phc: c.phc, secret: null };
    const r = this.local.get(k);
    if (!r || reservedName(r.name)) return null;
    const phc = parsePhc(r.passwordHash);
    const keyid = phc.keyid ?? null;
    return { name: r.name, role: r.role, source: 'store', phc, secret: keyid !== null && this.keys?.has(keyid) ? this.keys.pepper(keyid) : null };
  }

  // The pepper new password hashes get: {keyid, secret} of the current key, or null without keys.
  currentPepper() {
    return this.keys === null ? null : { keyid: this.keys.current, secret: this.keys.pepper(this.keys.current) };
  }

  // Whether a parsed hash should be made again at the next sign in: it has no pepper, or not the
  // current one.
  needsRepepper(phc) {
    return this.keys !== null && (phc?.keyid ?? null) !== this.keys.current;
  }

  // Puts a new hash of the same password in place of oldPhc (parsed, or its text), only when the
  // stored hash is still that one. Nothing else changes (not mustChangePassword either), and it is
  // not a change that ends sessions. Gives whether it was written. Throws when the write fails.
  upgradePassword(name, oldPhc, newPhcText) {
    parsePhc(newPhcText);
    const old = typeof oldPhc === 'string' ? parsePhc(oldPhc) : oldPhc;
    const k = key(name);
    const upgrade = () => {
      const cur = this.local.get(k);
      if (this.config.has(k) || !cur) return null;
      let same = false;
      try {
        same = samePhc(parsePhc(cur.passwordHash), old);
      } catch {
        same = false;
      }
      return same ? { ...cur, passwordHash: newPhcText } : null;
    };
    // As in commit, changes found meanwhile are given on once the new hash is in memory.
    try {
      const next = this.db === null
        ? upgrade()
        : this.write(() => {
          const n = upgrade();
          if (n !== null) this.db.put('store', n);
          return n;
        });
      if (next === null) return false;
      this.scrubSoon();
      const live = this.local.get(k);
      if (live?.devices) next.devices = live.devices;
      this.local.set(k, next);
      return true;
    } finally {
      this.notify();
    }
  }

  // The user with a name, without the password hash: {name, role, source, mustChangePassword}, or
  // null. mustChangePassword: the password was set by an admin, and the user has to choose their
  // own before they can do anything else.
  lookup(name) {
    const k = key(name);
    const c = this.config.get(k);
    if (c) return { name: c.name, role: c.role, source: 'config', mustChangePassword: false };
    const r = this.local.get(k);
    return r && !reservedName(r.name) ? { name: r.name, role: r.role, source: 'store', mustChangePassword: r.mustChangePassword === true } : null;
  }

  // [[lower-case name, parsed hash]] of every user who can sign in, by name.
  namedPhcs() {
    const out = [...this.config].map(([k, c]) => [k, c.phc]);
    for (const [k, r] of this.local) if (!this.config.has(k)) out.push([k, parsePhc(r.passwordHash)]);
    return out.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  }

  // What an unknown name is checked against: a hash that matches no password, with the costs of one
  // of the users. The costs are picked among the distinct costs the users have, by rendezvous
  // hashing: each set of costs gets an HMAC of the name and the costs, and the highest wins. So
  // each unknown name takes as long as one real user does, every time, and the pick only moves
  // when a set of costs comes or goes, not when users do. The HMAC key comes from the store key,
  // so the pick also stays the same across restarts.
  standIn(name) {
    const tuples = new Map();
    for (const [, phc] of this.namedPhcs()) {
      const t = `${phc.memory},${phc.passes},${phc.parallelism},${phc.hash.length}`;
      if (!tuples.has(t)) tuples.set(t, phc);
    }
    if (tuples.size === 0) return dummyPhc();
    const k = this.keys?.standInKey() ?? this.standInKey;
    let best = null;
    let bestScore = null;
    for (const t of [...tuples.keys()].sort()) {
      const score = crypto.createHmac('sha256', k).update(`${key(name)}\0${t}`).digest();
      if (bestScore === null || Buffer.compare(score, bestScore) > 0) [best, bestScore] = [t, score];
    }
    return dummyPhc(tuples.get(best));
  }

  // Every user who can sign in: [{name, role, source}].
  list() {
    const out = [...this.config.values()].map((c) => ({ name: c.name, role: c.role, source: 'config' }));
    for (const [k, r] of this.local) if (!this.config.has(k)) out.push({ name: r.name, role: r.role, source: 'store' });
    return out;
  }

  // The record that holds a user's second factor: the user's own for a website user, a record
  // of its own for a user in the config file (null until it has one). null for an unknown name.
  factorRecord(name) {
    const h = this.home(name);
    return h ? (h.map.get(h.k) ?? null) : null;
  }

  // Whether a TOTP secret is set up and waiting for its first code.
  totpPending(name) {
    const t = this.factorRecord(name)?.totp;
    return Boolean(t) && t.enabled === false;
  }

  // What the account page shows about a user, or null. No secret, passkey id or key is in it.
  // totp.recoveryCodesLeft counts the codes only while TOTP is on, as it always did;
  // recoveryCodesLeft counts them while any second factor is.
  account(name) {
    const user = this.find(name);
    if (!user) return null;
    const r = this.factorRecord(name);
    const left = factorOn(r) ? (r.recoveryCodes?.length ?? 0) : 0;
    return {
      name: user.name,
      role: user.role,
      source: user.source,
      created: r?.created ?? null,
      lastLogin: r?.lastLogin ?? null,
      totp: { enabled: r?.totp?.enabled === true, recoveryCodesLeft: r?.totp?.enabled ? left : 0 },
      credentials: (r?.credentials ?? []).length,
      passkeys: this.passkeys(name),
      recoveryCodesLeft: left,
    };
  }

  // Whether a user has a second factor on: TOTP, or at least one passkey. A passkey made for
  // another address (rpId) counts too, so that changing the address never turns the second step
  // off: such a user signs in with TOTP or a recovery code, or an admin resets them.
  secondFactorEnabled(name) {
    return factorOn(this.factorRecord(name));
  }

  // {totp, passkeys, recoveryCodesLeft}: whether TOTP is on, how many passkeys, how many recovery
  // codes are left (0 without a second factor).
  secondFactors(name) {
    const r = this.factorRecord(name);
    return { totp: r?.totp?.enabled === true, passkeys: (r?.credentials ?? []).length, recoveryCodesLeft: factorOn(r) ? (r.recoveryCodes?.length ?? 0) : 0 };
  }

  // ---- LXMF alert address ----
  // A user's own address for alerts about their account (lxmf-alerts.js), kept in the user's record (a config
  // user's in the record of their second factor, which is made when it is first needed). It counts only once
  // confirmed, and it stays when the password or a passkey changes, so that the alert about it still arrives;
  // it goes with the user.

  // {address, confirmed, nodeAlerts} (a copy), or null when the user has none.
  lxmfOf(name) {
    const l = this.factorRecord(name)?.lxmf;
    return l ? { address: l.address, confirmed: l.confirmed, nodeAlerts: l.nodeAlerts } : null;
  }

  // Sets the address, not confirmed yet (a new address starts without node alerts). Throws UserError 'unknown'.
  async setLxmf(name, address, { guard = null } = {}) {
    const h = this.home(name);
    if (!h) throw new UserError('unknown', 'no such user');
    this.commit(h.map, h.k, (cur) => {
      const r = cur ?? h.fresh();
      if (!r) throw new UserError('unknown', 'no such user');
      return { ...r, lxmf: { address, confirmed: false, nodeAlerts: false } };
    }, guard);
  }

  // Marks the address confirmed, only while it is still the one the code was sent to. Throws UserError 'unknown'.
  async confirmLxmf(name, address, { guard = null } = {}) {
    const h = this.home(name);
    if (!h) throw new UserError('unknown', 'no such user');
    this.commit(h.map, h.k, (cur) => {
      if (!cur?.lxmf || cur.lxmf.address !== address) throw new UserError('unknown', 'that address is not the one being confirmed');
      return { ...cur, lxmf: { ...cur.lxmf, confirmed: true } };
    }, guard);
  }

  // Takes the address away, whether confirmed or not. Throws UserError 'unknown' when there is none.
  async clearLxmf(name, { guard = null } = {}) {
    const h = this.home(name);
    if (!h || !this.factorRecord(name)?.lxmf) throw new UserError('unknown', 'no LXMF address is set');
    this.commit(h.map, h.k, (cur) => {
      if (!cur?.lxmf) throw new UserError('unknown', 'no LXMF address is set');
      const next = { ...cur };
      delete next.lxmf;
      return next;
    }, guard);
  }

  // Whether the user gets the node alerts too. Needs a confirmed address; whether the role may have them is
  // asked where the alerts are sent (lxmfNodeRecipients). Throws UserError 'unknown'.
  async setLxmfNodeAlerts(name, on, { guard = null } = {}) {
    const h = this.home(name);
    if (!h) throw new UserError('unknown', 'no such user');
    this.commit(h.map, h.k, (cur) => {
      if (!cur?.lxmf?.confirmed) throw new UserError('unknown', 'no confirmed LXMF address');
      return { ...cur, lxmf: { ...cur.lxmf, nodeAlerts: on === true } };
    }, guard);
  }

  // Who gets the node alerts at their own address: [{name, role, address}] of the users who can sign in, have
  // a confirmed address, asked for them, and are an admin or a manager now (a user whose role was lowered
  // since gets none, whatever they ticked).
  lxmfNodeRecipients() {
    const out = [];
    for (const u of this.list()) {
      const l = this.factorRecord(u.name)?.lxmf;
      if (l?.confirmed === true && l.nodeAlerts === true && (u.role === 'admin' || u.role === 'manage') && !reservedName(u.name)) out.push({ name: u.name, role: u.role, address: l.address });
    }
    return out;
  }

  // Whether a user other than `name` has confirmed this address (lxmf-alerts.js does not send a code to it).
  lxmfConfirmedElsewhere(address, name) {
    const me = key(name);
    return this.list().some((u) => key(u.name) !== me && this.factorRecord(u.name)?.lxmf?.confirmed === true && this.factorRecord(u.name).lxmf.address === address);
  }

  // ---- passkeys ----

  // A user's passkeys as the pages show them, oldest first: [{ref, name, created, lastUsed,
  // backedUp, backupEligible, rpId}].
  passkeys(name) {
    return (this.factorRecord(name)?.credentials ?? []).map(passkeyView);
  }

  // The stored passkey of a user with this ref, or with this id (base64url), as a copy with its
  // ref; null when there is none.
  passkeyByRef(name, ref) {
    const c = typeof ref === 'string' ? (this.factorRecord(name)?.credentials ?? []).find((x) => passkeyRef(x.id) === ref) : undefined;
    return c ? passkeyCopy(c) : null;
  }

  passkeyById(name, id) {
    const c = typeof id === 'string' ? (this.factorRecord(name)?.credentials ?? []).find((x) => x.id === id) : undefined;
    return c ? passkeyCopy(c) : null;
  }

  // Whether any user other than at (a record) has a passkey with this id. Credential ids are
  // unique in the store: one id can never sign in as two users.
  passkeyTaken(id, at = null) {
    for (const map of [this.local, this.factors]) {
      for (const r of map.values()) if (r !== at && (r.credentials ?? []).some((c) => c.id === id)) return true;
    }
    return false;
  }

  // The name of the user who has a passkey with this credential id (base64url), or null. Looks in
  // website users and in the factor records of config users. Only reads. A config user removed from
  // the config file can keep a factor record, so the caller still checks lookup(name) !== null.
  passkeyOwner(id) {
    if (typeof id !== 'string' || id === '') return null;
    for (const map of [this.local, this.factors]) {
      for (const [k, r] of map) {
        // A website user hidden by a config user of the same name, or with a reserved name, cannot sign in.
        if (map === this.local && (this.config.has(k) || reservedName(r.name))) continue;
        if (map === this.factors && !this.config.has(k)) continue;
        if ((r.credentials ?? []).some((c) => c.id === id)) return r.name;
      }
    }
    return null;
  }

  // The user handle of a user's passkeys, or null when none was made yet. Only reads.
  passkeyUserId(name) {
    return this.factorRecord(name)?.passkeyUserId ?? null;
  }

  // The user handle passkeys of a user are made with (base64url of 32 random bytes), made and
  // kept on first use. It stays when the second factor is reset, so a passkey can later sign in
  // without a name. Makes a record for a config user who has none. Throws UserError 'unknown'.
  async ensurePasskeyUserId(name, { guard = null } = {}) {
    const h = this.home(name);
    if (!h) throw new UserError('unknown', 'no such user');
    const have = this.factorRecord(name)?.passkeyUserId;
    if (have) return have;
    const id = crypto.randomBytes(32).toString('base64url');
    const next = this.commit(h.map, h.k, (cur) => {
      const r = cur ?? h.fresh();
      if (!r) throw new UserError('unknown', 'no such user');
      return r.passkeyUserId ? r : { ...r, passkeyUserId: id };
    }, guard);
    return next.passkeyUserId;
  }

  // Adds a passkey passkeys.js checked: rec has id and publicKey (base64url), counter, transports,
  // name, backupEligible, backedUp and rpId; created and lastUsed are set here when left out. The
  // name is trimmed. Gives {first, recoveryCodes, ref}: first when it is the user's first second
  // factor, and then the new recovery codes (the only time they are seen), else null. Throws
  // UserError 'unknown', 'exists' (this id is kept already, for anyone), 'full' (MAX_PASSKEYS) or
  // 'bad-label', and TypeError for a record that cannot be kept.
  async addPasskey(name, rec, { guard = null } = {}) {
    const h = this.home(name);
    if (!h) throw new UserError('unknown', 'no such user');
    if (!isMap(rec)) throw new TypeError('a passkey must be an object');
    const label = typeof rec.name === 'string' ? rec.name.trim() : rec.name;
    if (!goodPasskeyName(label)) throw new UserError('bad-label', `a passkey name is 1 to ${MAX_PASSKEY_NAME} characters`);
    const p = {
      type: 'passkey',
      id: rec.id,
      publicKey: rec.publicKey,
      counter: rec.counter ?? 0,
      transports: Array.isArray(rec.transports) ? [...rec.transports] : rec.transports ?? [],
      name: label,
      created: rec.created ?? this.iso(),
      lastUsed: rec.lastUsed ?? null,
      backupEligible: rec.backupEligible,
      backedUp: rec.backedUp,
      rpId: rec.rpId,
    };
    const fault = passkeyFault(p);
    if (fault !== null) throw new TypeError(`the passkey's ${fault} is not valid`);
    const ref = passkeyRef(p.id);
    const exists = () => new UserError('exists', 'this passkey is added already');
    if (this.passkeyTaken(p.id)) throw exists();
    const codes = newRecoveryCodes();
    const stored = this.storedCodes(codes);
    const userId = crypto.randomBytes(32).toString('base64url');
    let first = false;
    this.commit(h.map, h.k, (cur) => {
      const r = cur ?? h.fresh();
      if (!r) throw new UserError('unknown', 'no such user');
      const list = r.credentials ?? [];
      if (list.some((c) => passkeyRef(c.id) === ref) || this.passkeyTaken(p.id, cur)) throw exists();
      if (list.length >= MAX_PASSKEYS) throw new UserError('full', `at most ${MAX_PASSKEYS} passkeys`);
      first = !factorOn(r);
      const next = { ...r, credentials: [...list, p] };
      if (!next.passkeyUserId) next.passkeyUserId = userId;
      if (first) next.recoveryCodes = stored;
      return next;
    }, guard);
    return { first, recoveryCodes: first ? codes : null, ref };
  }

  // Gives a passkey another name (trimmed). Gives {from, to}. Throws UserError 'unknown' or 'bad-label'.
  async renamePasskey(name, ref, label, { guard = null } = {}) {
    const h = this.home(name);
    if (!h || !this.passkeyByRef(name, ref)) throw new UserError('unknown', 'no such passkey');
    const to = typeof label === 'string' ? label.trim() : label;
    if (!goodPasskeyName(to)) throw new UserError('bad-label', `a passkey name is 1 to ${MAX_PASSKEY_NAME} characters`);
    let from = null;
    this.commit(h.map, h.k, (cur) => {
      const list = cur?.credentials ?? [];
      const i = list.findIndex((c) => passkeyRef(c.id) === ref);
      if (i < 0) throw new UserError('unknown', 'no such passkey');
      from = list[i].name;
      return { ...cur, credentials: list.map((c, j) => (j === i ? { ...c, name: to } : c)) };
    }, guard);
    return { from, to };
  }

  // Removes a passkey. Gives {label, secondFactorOff}: its name, and whether it was the last
  // second factor, in which case the recovery codes went with it. Throws UserError 'unknown'.
  // Callers end the user's other sessions afterwards.
  async removePasskey(name, ref, { guard = null } = {}) {
    const h = this.home(name);
    if (!h || !this.passkeyByRef(name, ref)) throw new UserError('unknown', 'no such passkey');
    let label = null;
    let secondFactorOff = false;
    let id = null;
    this.commit(h.map, h.k, (cur) => {
      const list = cur?.credentials ?? [];
      const gone = list.find((c) => passkeyRef(c.id) === ref);
      if (!gone) throw new UserError('unknown', 'no such passkey');
      ({ name: label, id } = gone);
      const next = { ...cur, credentials: list.filter((c) => c !== gone) };
      secondFactorOff = !factorOn(next);
      if (secondFactorOff) next.recoveryCodes = [];
      return next;
    }, guard);
    this.passkeyTouched.delete(`${h.k}|${id}`);
    return { label, secondFactorOff };
  }

  // Removes every passkey of a user but keepRef (all of them when it is null), for a password change
  // that is asked to. Gives {removed, secondFactorOff} (see removePasskey). Callers end the user's
  // sessions afterwards (auth.endUser).
  async removeOtherPasskeys(name, keepRef = null, { guard = null } = {}) {
    const h = this.home(name);
    if (!h) throw new UserError('unknown', 'no such user');
    let result = { removed: 0, secondFactorOff: false, ids: [] };
    this.commit(h.map, h.k, (cur) => {
      const r = withoutOtherPasskeys(cur, keepRef);
      result = r;
      return r.next;
    }, guard);
    for (const id of result.ids) this.passkeyTouched.delete(`${h.k}|${id}`);
    return { removed: result.removed, secondFactorOff: result.secondFactorOff };
  }

  // Notes a passkey's use, after passkeys.js checked it: its counter (only ever raised), whether
  // it is backed up, and the time. In memory at once, like a used TOTP code, so that the next
  // check sees the new counter even before the store is written. A new counter or backup state is
  // always written; when only the time changed, it is written at most once each PASSKEY_WRITE_MS
  // (as touchLogin). Gives {ok, saved}: ok is false for an unknown passkey; saved is the write.
  usePasskey(name, ref, { counter, backedUp } = {}) {
    if (counter !== undefined && (!Number.isSafeInteger(counter) || counter < 0 || counter > MAX_COUNTER)) throw new TypeError('a passkey counter is a whole number from 0 to 2^32 - 1');
    if (backedUp !== undefined && typeof backedUp !== 'boolean') throw new TypeError('backedUp must be true or false');
    const c = typeof ref === 'string' ? (this.factorRecord(name)?.credentials ?? []).find((x) => passkeyRef(x.id) === ref) : undefined;
    if (!c) return { ok: false, saved: Promise.resolve() };
    const { id } = c;
    const iso = this.iso();
    const changes = (counter !== undefined && counter > c.counter) || (backedUp !== undefined && backedUp !== c.backedUp);
    const use = (x) => {
      const p = (x.credentials ?? []).find((y) => y.id === id);
      if (!p) return;
      if (counter !== undefined && counter > p.counter) p.counter = counter;
      if (backedUp !== undefined) p.backedUp = backedUp;
      if (p.lastUsed === null || p.lastUsed < iso) p.lastUsed = iso;
    };
    use({ credentials: [c] });
    const at = `${key(name)}|${id}`;
    const t = this.now();
    const last = this.passkeyTouched.get(at);
    if (!changes && last !== undefined && t - last < PASSKEY_WRITE_MS && t >= last) return { ok: true, saved: Promise.resolve() };
    this.passkeyTouched.set(at, t);
    return { ok: true, saved: this.save(name, use) };
  }

  // Forgets when passkeys that are gone were last written.
  forgetPasskeyTimes() {
    for (const at of this.passkeyTouched.keys()) {
      const bar = at.indexOf('|');
      const k = at.slice(0, bar);
      const r = this.local.get(k) ?? this.factors.get(k);
      if (!(r?.credentials ?? []).some((c) => c.id === at.slice(bar + 1))) this.passkeyTouched.delete(at);
    }
  }

  // Starts setting up TOTP: a new secret, not yet in use until enableTotp. Returns it (base32).
  async beginTotp(name, { guard = null } = {}) {
    const h = this.home(name);
    if (!h) throw new UserError('unknown', 'no such user');
    const secret = newSecret();
    this.commit(h.map, h.k, (cur) => {
      const r = cur ?? h.fresh();
      if (!r) throw new UserError('unknown', 'no such user');
      if (r.totp?.enabled) throw new UserError('exists', 'two-step sign-in is already on');
      return { ...r, totp: { secret, enabled: false, lastUsedStep: null } };
    }, guard);
    return secret;
  }

  // The stored form of new recovery codes: an HMAC under the current key, or the plain SHA-256
  // without keys.
  storedCodes(codes) {
    const keys = this.keys;
    if (keys === null) return codes.map(hashRecoveryCode);
    return codes.map((c) => `k${keys.current}:${keys.recoveryHash(keys.current, hashRecoveryCode(c))}`);
  }

  // Turns TOTP on once the first code from the new secret is right. Returns the new recovery
  // codes (the only time they are seen), or null for a wrong code. They replace any the user had
  // (from a passkey), so what is shown now is always the set that works.
  async enableTotp(name, code, { guard = null } = {}) {
    const h = this.home(name);
    const r = this.factorRecord(name);
    if (!h || !r?.totp || r.totp.enabled) throw new UserError('unknown', 'no two-step sign-in is being set up');
    const { secret } = r.totp;
    const step = verifyTotp(base32Decode(secret), code, this.now(), r.totp.lastUsedStep ?? null);
    if (step === null) return null;
    const codes = newRecoveryCodes();
    const stored = this.storedCodes(codes);
    this.commit(h.map, h.k, (cur) => {
      // Another request turned it on, or set up a new secret, in the meantime.
      if (!cur?.totp || cur.totp.enabled || cur.totp.secret !== secret) throw new UserError('unknown', 'no two-step sign-in is being set up');
      return { ...cur, totp: { ...cur.totp, enabled: true, lastUsedStep: step }, recoveryCodes: stored };
    }, guard);
    return codes;
  }

  // Turns TOTP off. The recovery codes stay while the user still has a passkey.
  async disableTotp(name, { guard = null } = {}) {
    const h = this.home(name);
    if (!h || !this.factorRecord(name)) throw new UserError('unknown', 'no such user');
    this.commit(h.map, h.k, (cur) => {
      if (!cur) throw new UserError('unknown', 'no such user');
      const next = { ...cur, totp: null };
      if (!factorOn(next)) next.recoveryCodes = [];
      return next;
    }, guard);
  }

  // Checks a code and, when it is right, marks its step used, at once, so a second request with the
  // same code is refused even before the store is written. Returns {ok, saved}: saved is the write.
  checkTotp(name, code) {
    const r = this.factorRecord(name);
    if (!r?.totp?.enabled) return { ok: false, saved: Promise.resolve() };
    const step = verifyTotp(base32Decode(r.totp.secret), code, this.now(), r.totp.lastUsedStep ?? null);
    if (step === null) return { ok: false, saved: Promise.resolve() };
    r.totp.lastUsedStep = step;
    const { secret } = r.totp;
    const saved = this.save(name, (x) => {
      if (x.totp?.enabled && x.totp.secret === secret && (x.totp.lastUsedStep ?? -1) < step) x.totp = { ...x.totp, lastUsedStep: step };
    });
    return { ok: true, saved };
  }

  // Uses up a recovery code, while any second factor is on. Returns {ok, left, saved}.
  useRecoveryCode(name, code) {
    const r = this.factorRecord(name);
    const codes = factorOn(r) ? (r.recoveryCodes ?? []) : [];
    const sha = hashRecoveryCode(code);
    // What each stored form of this code is, by key version (0: the plain SHA-256).
    const given = new Map([[0, Buffer.from(sha, 'hex')]]);
    const formOf = (v) => {
      if (!given.has(v)) given.set(v, this.keys?.has(v) ? Buffer.from(this.keys.recoveryHash(v, sha), 'hex') : null);
      return given.get(v);
    };
    // Every stored hash is compared, whatever matches.
    let at = -1;
    codes.forEach((h, i) => {
      const m = WRAPPED.exec(h);
      const want = formOf(m ? Number(m[1]) : 0);
      const have = Buffer.from(m ? m[2] : h, 'hex');
      if (want !== null && have.length === want.length && crypto.timingSafeEqual(have, want) && at < 0) at = i;
    });
    if (at < 0 || normalRecoveryCode(code).length !== 16) return { ok: false, left: codes.length, saved: Promise.resolve() };
    const [used] = codes.splice(at, 1);
    const saved = this.save(name, (x) => {
      const i = (x.recoveryCodes ?? []).indexOf(used);
      if (i >= 0) x.recoveryCodes = x.recoveryCodes.filter((_, j) => j !== i);
    }, { scrub: true });
    return { ok: true, left: codes.length, saved };
  }

  // New recovery codes in place of the old ones, while any second factor is on; returns them (the
  // only time they are seen).
  async newRecoveryCodes(name, { guard = null } = {}) {
    const h = this.home(name);
    if (!h || !factorOn(this.factorRecord(name))) throw new UserError('unknown', 'two-step sign-in is not on');
    const codes = newRecoveryCodes();
    const stored = this.storedCodes(codes);
    this.commit(h.map, h.k, (cur) => {
      if (!factorOn(cur)) throw new UserError('unknown', 'two-step sign-in is not on');
      return { ...cur, recoveryCodes: stored };
    }, guard);
    return codes;
  }

  // Notes the time of a sign in, for users who have a record; nothing is made for the others.
  async recordLogin(name) {
    const r = this.factorRecord(name);
    if (!r) return;
    const iso = this.iso();
    r.lastLogin = iso;
    await this.save(name, (x) => {
      x.lastLogin = iso;
    });
  }

  // Notes a sign in: its time, and that the device with this hash was used now. In memory at once;
  // written at most once each LOGIN_WRITE_MS per user, so that signing in over and over cannot keep
  // the disk busy (a crash loses at most that much). Gives the write, when there is one.
  touchLogin(name, hash = null) {
    const r = this.factorRecord(name);
    if (!r) return Promise.resolve();
    const iso = this.iso();
    const touch = (x) => {
      x.lastLogin = iso;
      const d = hash === null ? undefined : (x.devices ?? []).find((y) => y.hash === hash);
      if (d) d.lastUsed = iso;
    };
    touch(r);
    const k = key(name);
    const t = this.now();
    const last = this.touched.get(k);
    if (last !== undefined && t - last < LOGIN_WRITE_MS && t >= last) return Promise.resolve();
    this.touched.set(k, t);
    return this.save(name, touch);
  }

  // ---- known devices ----

  // The devices of a user: [{hash, created, lastUsed}], oldest first.
  devices(name) {
    return (this.factorRecord(name)?.devices ?? []).map((d) => ({ ...d }));
  }

  hasDevice(name, hash) {
    return typeof hash === 'string' && (this.factorRecord(name)?.devices ?? []).some((d) => d.hash === hash);
  }

  // The record that keeps a user's devices, made for a config user who has none yet. null for an
  // unknown name.
  deviceRecord(name) {
    const h = this.home(name);
    if (!h) return null;
    let r = h.map.get(h.k);
    if (!r) {
      r = h.fresh();
      if (!r) return null;
      h.map.set(h.k, r);
    }
    if (!Array.isArray(r.devices)) r.devices = [];
    return r;
  }

  // Remembers a device (by the SHA-256 of its id) for a user, or notes that it was used now. Past
  // MAX_DEVICES the least recently used one is forgotten, one made by a passkey alone first. Gives
  // the write.
  addDevice(name, hash) {
    return this.rememberDevice(name, hash).saved;
  }

  // addDevice, giving {evicted, saved, stored}: evicted are the devices it pushed out ({hash, created,
  // lastUsed}), saved the write. via 'passkey': the device was made by a passkey sign in alone; it
  // pushes out only the oldest such devices (past MAX_PASSKEY_DEVICES, or when the list is full), and
  // is not kept (stored false) when only devices made with the password are there.
  rememberDevice(name, hash, { via = null } = {}) {
    const r = this.deviceRecord(name);
    if (!r || typeof hash !== 'string' || !HEX64.test(hash)) return { evicted: [], saved: Promise.resolve(), stored: false };
    const t = this.iso();
    const passkey = via === 'passkey';
    // As they are now: the change below is made on a second record too (see save).
    const made = new Set(this.passkeyDevices);
    const mine = (x) => x.devices.filter((d) => made.has(d.hash));
    const oldest = (list) => list.reduce((a, d) => (d.lastUsed < a.lastUsed ? d : a));
    const remember = (x) => {
      if (!Array.isArray(x.devices)) x.devices = [];
      const out = [];
      const known = x.devices.find((d) => d.hash === hash);
      if (known) known.lastUsed = t;
      else {
        // In place: a record copied by a change meanwhile shares this list.
        const drop = (d) => out.push(...x.devices.splice(x.devices.indexOf(d), 1));
        if (passkey) {
          while (mine(x).length >= MAX_PASSKEY_DEVICES) drop(oldest(mine(x)));
          // No room left that a device made with the password does not hold: this one is not kept.
          while (x.devices.length >= MAX_DEVICES) {
            if (mine(x).length === 0) return out;
            drop(oldest(mine(x)));
          }
        } else {
          while (x.devices.length >= MAX_DEVICES) drop(oldest(mine(x).length > 0 ? mine(x) : x.devices));
        }
        x.devices.push({ hash, created: t, lastUsed: t });
      }
      return out;
    };
    const evicted = remember(r);
    const stored = r.devices.some((d) => d.hash === hash);
    for (const d of evicted) this.passkeyDevices.delete(d.hash);
    if (stored && passkey) {
      this.passkeyDevices.add(hash);
      // Bounded: users that were deleted or changed elsewhere leave hashes behind.
      while (this.passkeyDevices.size > MAX_STORE_USERS * MAX_PASSKEY_DEVICES) this.passkeyDevices.delete(this.passkeyDevices.values().next().value);
    }
    return { evicted, saved: stored ? this.save(name, remember, { create: true }) : Promise.resolve(), stored };
  }

  // Notes again that a device the user already has was made by a passkey sign in alone: the tags are
  // in memory only (the devices table has no column for them, and a new one would be a schema
  // migration older releases cannot read), so after a restart a browser that signs in with its
  // passkey device cookie gets its tag back here. Past MAX_PASSKEY_DEVICES the oldest other tagged
  // devices are forgotten. Gives {evicted, saved} like rememberDevice.
  tagPasskeyDevice(name, hash) {
    const list = this.factorRecord(name)?.devices;
    if (!Array.isArray(list) || typeof hash !== 'string' || !list.some((d) => d.hash === hash)) return { evicted: [], saved: Promise.resolve() };
    this.passkeyDevices.delete(hash);
    this.passkeyDevices.add(hash);
    while (this.passkeyDevices.size > MAX_STORE_USERS * MAX_PASSKEY_DEVICES) this.passkeyDevices.delete(this.passkeyDevices.values().next().value);
    const evicted = [];
    const saved = [];
    for (;;) {
      const others = list.filter((d) => d.hash !== hash && this.passkeyDevices.has(d.hash));
      if (others.length < MAX_PASSKEY_DEVICES) break;
      const old = others.reduce((a, d) => (d.lastUsed < a.lastUsed ? d : a));
      evicted.push({ ...old });
      saved.push(this.dropDevices(name, { only: old.hash }).saved);
    }
    return { evicted, saved: Promise.all(saved).then(() => {}) };
  }

  // Forgets devices of a user: all of them but keep, or only the one with hash only. Gives
  // {removed, hashes, saved}: they are gone from memory at once, hashes are theirs, saved is the write.
  dropDevices(name, { keep = null, only = null } = {}) {
    const r = this.factorRecord(name);
    const list = r?.devices;
    if (!Array.isArray(list)) return { removed: 0, hashes: [], saved: Promise.resolve() };
    const hashes = [];
    for (let i = list.length - 1; i >= 0; i--) {
      const h = list[i].hash;
      if (only !== null ? h === only : h !== keep) {
        list.splice(i, 1);
        hashes.push(h);
      }
    }
    if (hashes.length === 0) return { removed: 0, hashes, saved: Promise.resolve() };
    for (const h of hashes) this.passkeyDevices.delete(h);
    const gone = new Set(hashes);
    const saved = this.save(name, (x) => {
      if (Array.isArray(x.devices)) x.devices = x.devices.filter((d) => !gone.has(d.hash));
    });
    return { removed: hashes.length, hashes, saved };
  }

  // ---- managing users (the users page uses these) ----

  admins() {
    return this.list().filter((u) => u.role === 'admin').length;
  }

  // Every user as the users page shows them, by name. No secret, hash, device id or passkey id is
  // in it. secondFactor: TOTP or a passkey is on.
  overview() {
    return this.list()
      .map((u) => {
        const r = this.factorRecord(u.name);
        const local = u.source === 'store' ? this.local.get(key(u.name)) : null;
        return {
          name: u.name,
          role: u.role,
          source: u.source,
          secondFactor: factorOn(r),
          totp: r?.totp?.enabled === true,
          passkeys: (r?.credentials ?? []).length,
          devices: (r?.devices ?? []).length,
          lastLogin: r?.lastLogin ?? null,
          created: local?.created ?? null,
          mustChangePassword: local?.mustChangePassword === true,
        };
      })
      .sort((a, b) => (key(a.name) < key(b.name) ? -1 : key(a.name) > key(b.name) ? 1 : 0));
  }

  // Whether removing a user, or giving them another role, would leave no admin.
  wouldLeaveNoAdmin(name, role = null) {
    const u = this.lookup(name);
    return Boolean(u) && u.role === 'admin' && role !== 'admin' && this.admins() <= 1;
  }

  // The website user with a name; refuses users in the config file and unknown names.
  localUser(name) {
    const k = key(name);
    if (this.config.has(k)) throw new UserError('config', 'this user is managed in the config file');
    const r = this.local.get(k);
    if (!r) throw new UserError('unknown', 'no such user');
    return r;
  }

  // passwordHash: a PHC string from hashPassword. mustChangePassword: the user has to choose a
  // password of their own at their first sign in (an admin chose this one).
  async createUser({ name, role = DEFAULT_ROLE, passwordHash, mustChangePassword = false }, { guard = null } = {}) {
    if (typeof name !== 'string' || !USER_NAME_RE.test(name)) throw new UserError('bad-name', 'a name is 1 to 32 letters, digits, dots, dashes or underscores, starting with a letter or digit');
    if (reservedName(name)) throw new UserError('reserved-name', RESERVED_NAME_TEXT);
    if (!ROLES.includes(role)) throw new UserError('bad-role', `the role must be one of ${ROLES.join(', ')}`);
    parsePhc(passwordHash);
    const k = key(name);
    const created = this.iso();
    const check = (cur) => {
      if (this.config.has(k) || cur) throw new UserError('exists', 'a user with this name exists');
      if (this.local.size + this.factors.size >= this.maxUsers) throw new UserError('full', `at most ${this.maxUsers} users`);
    };
    check(this.local.get(k));
    this.commit(this.local, k, (cur) => {
      check(cur);
      const r = { name, role, passwordHash, created, lastLogin: null, totp: null, recoveryCodes: [], credentials: [], devices: [] };
      if (mustChangePassword) r.mustChangePassword = true;
      return r;
    }, guard);
  }

  // Callers end the user's sessions afterwards (auth.endUser). force: the last admin may go too
  // (only the command line offers it, for recovery). noDeleteAdmin: an admin is not deleted
  // (UserError 'admin-delete'), asked again inside the transaction on the record as it is then, so
  // that a user made an admin meanwhile is refused too (the users page; admins are deleted on the
  // command line only, or by themselves).
  async deleteUser(name, { guard = null, force = false, noDeleteAdmin = false } = {}) {
    const k = key(name);
    const check = (r) => {
      if (noDeleteAdmin && r.role === 'admin') throw new UserError('admin-delete', 'an admin can only be deleted from the command line');
      if (!force && r.role === 'admin' && this.admins() <= 1) throw new UserError('last-admin', 'the last admin cannot be removed');
    };
    check(this.localUser(name));
    this.commit(this.local, k, (cur) => {
      if (!cur) throw new UserError('unknown', 'no such user');
      check(cur);
      return null;
    }, guard);
    this.touched.delete(k);
    this.forgetPasskeyTimes();
  }

  // Gives the role the user had right before the change. Callers end the user's sessions
  // afterwards (auth.endUser). noDemote: an admin is not given another role (UserError
  // 'admin-demote'), asked again inside the transaction on the record as it is then, so that a user
  // made an admin meanwhile is refused too (the users page; admins are demoted on the command line
  // only, or by themselves).
  async setRole(name, role, { guard = null, force = false, noDemote = false } = {}) {
    if (!ROLES.includes(role)) throw new UserError('bad-role', `the role must be one of ${ROLES.join(', ')}`);
    if (reservedName(name)) throw new UserError('reserved-name', RESERVED_NAME_TEXT);
    const check = (r) => {
      if (noDemote && r.role === 'admin' && role !== 'admin') throw new UserError('admin-demote', 'an admin can only be demoted from the command line');
      if (!force && r.role === 'admin' && role !== 'admin' && this.admins() <= 1) throw new UserError('last-admin', 'the last admin cannot be removed');
    };
    check(this.localUser(name));
    let from = null;
    this.commit(this.local, key(name), (cur) => {
      if (!cur) throw new UserError('unknown', 'no such user');
      check(cur);
      from = cur.role;
      return { ...cur, role };
    }, guard);
    return from;
  }

  // Callers end the user's other sessions afterwards (auth.endUser). mustChangePassword: set by an
  // admin, who chose it; a user who sets their own clears it. notAdmin: the change is refused for an
  // admin (UserError 'admin-target'), asked again inside the transaction, so that a user made an
  // admin meanwhile is refused too (the users page; admins are reset on the command line only).
  // removeOtherPasskeys: {keep} removes every passkey but the one with the ref keep (all of them when
  // keep is null) in the same write, so that the password and the passkeys change together or not at
  // all. Gives {removedPasskeys}: how many went, or null when that was not asked for.
  async setPassword(name, passwordHash, { guard = null, mustChangePassword = false, notAdmin = false, removeOtherPasskeys = null } = {}) {
    parsePhc(passwordHash);
    if (reservedName(name)) throw new UserError('reserved-name', RESERVED_NAME_TEXT);
    this.localUser(name);
    let others = null;
    this.commit(this.local, key(name), (cur) => {
      if (!cur) throw new UserError('unknown', 'no such user');
      if (notAdmin && cur.role === 'admin') throw new UserError('admin-target', 'an admin can only be reset from the command line');
      let next = { ...cur, passwordHash };
      delete next.mustChangePassword;
      if (mustChangePassword) next.mustChangePassword = true;
      if (removeOtherPasskeys !== null) {
        others = withoutOtherPasskeys(next, removeOtherPasskeys.keep ?? null);
        next = others.next;
      }
      return next;
    }, guard);
    if (others === null) return { removedPasskeys: null };
    for (const id of others.ids) this.passkeyTouched.delete(`${key(name)}|${id}`);
    return { removedPasskeys: others.removed };
  }

  // Takes away a user's second factor (TOTP, recovery codes and passkeys), for someone who lost
  // their phone. Works for users in the config file too. The passkey user handle (passkeyUserId)
  // stays. Callers end the user's sessions afterwards (auth.endUser). notAdmin: as for setPassword
  // (a config user's role is that of the config file).
  async resetSecondFactor(name, { guard = null, notAdmin = false } = {}) {
    const h = this.home(name);
    if (!h) throw new UserError('unknown', 'no such user');
    const refuse = () => new UserError('admin-target', 'an admin can only be reset from the command line');
    if (notAdmin && this.lookup(name)?.role === 'admin') throw refuse();
    if (!this.factorRecord(name)) return;
    this.commit(h.map, h.k, (cur) => {
      // The role right now, in the transaction: a website user's from their record.
      if (notAdmin && (h.map === this.local ? cur?.role : this.lookup(name)?.role) === 'admin') throw refuse();
      return cur ? { ...cur, totp: null, recoveryCodes: [], credentials: [] } : null;
    }, guard);
    this.forgetPasskeyTimes();
  }
}
