// The user store: users.json in the data directory. It holds the users made on the website (name,
// role, password hash) and the second factor of every user, including those in the config file,
// whose name, password and role stay in the config file. It is read once at start and written
// whole on every change, to a temporary file that is then renamed, with mode 0600.
//
// A store that cannot be read stops the server with a message, and is left as it is: a broken file
// must never become an empty store, which would drop everyone's second factor.
//
// TOTP secrets are kept as they are (base32) in this file: the server needs them to check a code.
// Recovery codes are kept only as SHA-256 hashes. The file is as private as the config file.
//
// A change is written first and only then made in memory, so a failed write leaves the store as
// the file is (except a used code, which counts as used at once, see checkTotp).
//
// Whoever calls setPassword, deleteUser, setRole or resetSecondFactor (and turns a second factor
// on or off) must call auth.endUser(name) from login.js once it worked: that ends the user's
// sessions and open second steps and forgets their devices, so nobody stays signed in on what was
// just taken away.
//
// Known devices: each browser a user signed in from gets a random device id in a cookie; only its
// SHA-256 is kept here, in the user's record (devices, at most MAX_DEVICES, the least recently used
// one goes first). Unlike other changes, devices are changed in memory first and then written: a
// device that is forgotten must stop working at once, even when the write fails.
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { parsePhc } from './password.js';
import { base32Decode, newSecret, verifyTotp } from './totp.js';

export const STORE_FILE = 'users.json';
export const STORE_VERSION = 1;
export const ROLES = ['admin', 'manage', 'viewer'];
export const DEFAULT_ROLE = 'viewer';
// A user name: letters, digits, dot, dash and underscore, starting with a letter or digit.
export const USER_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$/;
export const RECOVERY_CODES = 10;
export const MAX_STORE_BYTES = 1024 * 1024;
export const MAX_STORE_USERS = 500;
const MAX_RECOVERY_CODES = 20;
const MAX_CREDENTIALS = 50;
export const MAX_DEVICES = 10;
// The time of a sign in (and of a known device's use) is written at most this often per user.
export const LOGIN_WRITE_MS = 60_000;
const HEX64 = /^[0-9a-f]{64}$/;
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?Z$/;
// Recovery codes: 16 base32 letters and digits (80 bits), shown in groups of four.
const RECOVERY_ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567';

// The store file cannot be read or makes no sense; the server must not start.
export class StoreError extends Error {}

// A change the store refuses. code is one of: 'bad-name', 'bad-role', 'exists', 'unknown',
// 'config' (the user is in the config file), 'last-admin'.
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

// Checks one record of the file; throws a StoreError that says where, never the value.
function checkRecord(r, where, local) {
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
  if (r.totp !== undefined && r.totp !== null) {
    const t = r.totp;
    if (!isMap(t)) throw new StoreError(`${where}.totp is not an object`);
    const secret = base32Decode(t.secret);
    if (!secret || secret.length < 10 || secret.length > 64) throw new StoreError(`${where}.totp.secret is not a base32 secret of 10 to 64 bytes`);
    if (typeof t.enabled !== 'boolean') throw new StoreError(`${where}.totp.enabled must be true or false`);
    if (t.lastUsedStep !== null && t.lastUsedStep !== undefined && (!Number.isSafeInteger(t.lastUsedStep) || t.lastUsedStep < 0)) throw new StoreError(`${where}.totp.lastUsedStep must be a whole number or null`);
  }
  if (r.recoveryCodes !== undefined) {
    if (!Array.isArray(r.recoveryCodes) || r.recoveryCodes.length > MAX_RECOVERY_CODES || !r.recoveryCodes.every((h) => typeof h === 'string' && HEX64.test(h))) {
      throw new StoreError(`${where}.recoveryCodes must be a list of at most ${MAX_RECOVERY_CODES} SHA-256 hashes`);
    }
  }
  if (r.devices !== undefined) {
    const ok = (d) => isMap(d) && typeof d.hash === 'string' && HEX64.test(d.hash) && typeof d.created === 'string' && ISO.test(d.created) && typeof d.lastUsed === 'string' && ISO.test(d.lastUsed);
    if (!Array.isArray(r.devices) || r.devices.length > MAX_DEVICES || !r.devices.every(ok)) {
      throw new StoreError(`${where}.devices must be a list of at most ${MAX_DEVICES} devices, each with a SHA-256 hash and two times`);
    }
  }
  if (r.credentials !== undefined) {
    if (!Array.isArray(r.credentials) || r.credentials.length > MAX_CREDENTIALS || !r.credentials.every((c) => isMap(c) && typeof c.type === 'string' && c.type.length > 0 && c.type.length <= 32)) {
      throw new StoreError(`${where}.credentials must be a list of at most ${MAX_CREDENTIALS} objects with a type`);
    }
  }
}

// The records of the file text, checked. Keys this version does not know are kept as they are.
export function parseStore(text) {
  if (Buffer.byteLength(text) > MAX_STORE_BYTES) throw new StoreError(`it is larger than ${MAX_STORE_BYTES / 1024} KiB`);
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
    if (!Array.isArray(list) || list.length > MAX_STORE_USERS) throw new StoreError(`${field} must be a list of at most ${MAX_STORE_USERS} users`);
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

// Writes a file whole: to a temporary file (mode 0600), synced, then renamed over the old one.
export async function writeAtomic(file, text) {
  const tmp = `${file}.${process.pid}.tmp`;
  try {
    await fs.mkdir(path.dirname(file), { recursive: true });
    // A stale temporary file (or a link planted under that name) is removed first, and 'wx'
    // refuses to open anything that is still there.
    await fs.rm(tmp, { force: true });
    const handle = await fs.open(tmp, 'wx', 0o600);
    try {
      await handle.writeFile(text);
      await handle.sync();
    } finally {
      await handle.close();
    }
    await fs.rename(tmp, file);
  } catch (err) {
    await fs.rm(tmp, { force: true }).catch(() => {});
    throw err;
  }
}

// Reads users.json from dataDir: {file, data}, where data is null for a missing file. Throws
// StoreError (with a message for the operator) when the file is there but cannot be used.
export async function readStore({ dataDir, warn = console.warn }) {
  const file = path.join(dataDir, STORE_FILE);
  let text = null;
  try {
    const st = await fs.stat(file);
    if (!st.isFile()) throw new StoreError('it is not a regular file');
    if (process.platform !== 'win32' && (st.mode & 0o077) !== 0) {
      warn(`warning: ${STORE_FILE} can be read by other users (mode ${(st.mode & 0o777).toString(8)}); it holds second-factor secrets, make it readable by the server only (chmod 600)`);
    }
    text = await fs.readFile(file, 'utf8');
  } catch (err) {
    if (err.code === 'ENOENT') text = null;
    else throw new StoreError(`${STORE_FILE} in the data directory cannot be read (${err instanceof StoreError ? err.message : (err.code ?? 'error')}); fix or move it, it was left as it is`);
  }
  if (text === null) return { file, data: null };
  try {
    return { file, data: parseStore(text) };
  } catch (err) {
    throw new StoreError(`${STORE_FILE} in the data directory cannot be used: ${err.message}. Fix or move it; it was left as it is`);
  }
}

// Whether the store read by readStore has users who sign in with a password of their own. The
// config file's checks need this before the store is opened with the config file's users.
export const storeHasUsers = (data) => (data?.users.length ?? 0) > 0;

export class UserStore {
  // configUsers: [{name, phc, role}] from the config file.
  constructor({ file = null, configUsers = [], data = null, warn = console.warn, now = Date.now }) {
    Object.assign(this, { file, now, warn });
    this.config = new Map(configUsers.map((u) => [key(u.name), { name: u.name, phc: u.phc, role: u.role ?? DEFAULT_ROLE }]));
    this.local = new Map();
    this.factors = new Map();
    this.extra = data?.extra ?? { version: STORE_VERSION };
    for (const r of data?.users ?? []) this.local.set(key(r.name), r);
    for (const r of data?.configUsers ?? []) this.factors.set(key(r.name), r);
    this.saving = Promise.resolve();
    // When the time of a sign in was last written, by user.
    this.touched = new Map();
    for (const k of this.local.keys()) {
      if (this.config.has(k)) {
        warn(`${STORE_FILE}: the user "${this.local.get(k).name}" is also in the config file; the one in the config file is used, and the one in ${STORE_FILE} cannot sign in`);
      }
    }
  }

  // Reads users.json from dataDir; a missing file is an empty store. Throws StoreError (with a
  // message for the operator) when the file is there but cannot be used.
  static async open({ dataDir, configUsers = [], warn = console.warn, now = Date.now }) {
    const { file, data } = await readStore({ dataDir, warn });
    return new UserStore({ file, configUsers, data, warn, now });
  }

  iso() {
    return new Date(this.now()).toISOString();
  }

  text(local, factors) {
    const body = { ...this.extra, version: STORE_VERSION, users: [...local.values()], configUsers: [...factors.values()] };
    return `${JSON.stringify(body, null, 2)}\n`;
  }

  // Writes the store as it is in memory. Writes run one after another.
  save() {
    // A store without a file (tests, or a login without a data directory) lives in memory only.
    if (this.file === null) return Promise.resolve();
    const run = this.saving.then(() => writeAtomic(this.file, this.text(this.local, this.factors)));
    // The chain goes on after a failed write; the caller gets the error.
    this.saving = run.catch(() => {});
    return run;
  }

  // Resolves once every write asked for so far, and any asked for meanwhile, has ended.
  async flush() {
    let p;
    do {
      p = this.saving;
      await p;
    } while (p !== this.saving);
  }

  // Changes one record: change(current) gives the new record, or null to remove it, and may throw
  // UserError. It runs when this write is next in line, on the record as it is then; the file is
  // written with the new record, and only once that worked is it put in memory. Gives the record.
  // guard, when given, is asked right before: false refuses the change with UserError 'gone' (the
  // session that asked for it ended meanwhile). The devices of a record are never changed here:
  // they are changed in memory (see addDevice), and the ones in memory are kept.
  commit(map, k, change, guard = null) {
    const run = this.saving.then(async () => {
      if (guard !== null && !guard()) throw new UserError('gone', 'the session that asked for this has ended');
      const next = change(map.get(k) ?? null);
      if (this.file !== null) {
        const changed = new Map(map);
        if (next === null) changed.delete(k);
        else changed.set(k, next);
        await writeAtomic(this.file, this.text(map === this.local ? changed : this.local, map === this.factors ? changed : this.factors));
      }
      const live = map.get(k);
      if (next !== null && live?.devices) next.devices = live.devices;
      if (next === null) map.delete(k);
      else map.set(k, next);
      return next;
    });
    this.saving = run.catch(() => {});
    return run;
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

  // The user who signs in with a name: {name, role, source: 'config' | 'store', phc}, or null.
  find(name) {
    const k = key(name);
    const c = this.config.get(k);
    if (c) return { name: c.name, role: c.role, source: 'config', phc: c.phc };
    const r = this.local.get(k);
    if (!r) return null;
    return { name: r.name, role: r.role, source: 'store', phc: parsePhc(r.passwordHash) };
  }

  // The user with a name, without the password hash: {name, role, source}, or null.
  lookup(name) {
    const k = key(name);
    const c = this.config.get(k);
    if (c) return { name: c.name, role: c.role, source: 'config' };
    const r = this.local.get(k);
    return r ? { name: r.name, role: r.role, source: 'store' } : null;
  }

  // Every password hash a name could be checked against, for the cost of the stand-in hash.
  phcs() {
    const out = [...this.config.values()].map((c) => c.phc);
    for (const [k, r] of this.local) if (!this.config.has(k)) out.push(parsePhc(r.passwordHash));
    return out;
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

  // What the account page shows about a user, or null. No secret is in it.
  account(name) {
    const user = this.find(name);
    if (!user) return null;
    const r = this.factorRecord(name);
    return {
      name: user.name,
      role: user.role,
      source: user.source,
      created: r?.created ?? null,
      lastLogin: r?.lastLogin ?? null,
      totp: { enabled: r?.totp?.enabled === true, recoveryCodesLeft: r?.totp?.enabled ? (r.recoveryCodes?.length ?? 0) : 0 },
      credentials: (r?.credentials ?? []).length,
    };
  }

  secondFactorEnabled(name) {
    return this.factorRecord(name)?.totp?.enabled === true;
  }

  // Starts setting up TOTP: a new secret, not yet in use until enableTotp. Returns it (base32).
  async beginTotp(name, { guard = null } = {}) {
    const h = this.home(name);
    if (!h) throw new UserError('unknown', 'no such user');
    const secret = newSecret();
    await this.commit(h.map, h.k, (cur) => {
      const r = cur ?? h.fresh();
      if (!r) throw new UserError('unknown', 'no such user');
      if (r.totp?.enabled) throw new UserError('exists', 'two-step sign-in is already on');
      return { ...r, totp: { secret, enabled: false, lastUsedStep: null } };
    }, guard);
    return secret;
  }

  // Turns TOTP on once the first code from the new secret is right. Returns the new recovery
  // codes (the only time they are seen), or null for a wrong code.
  async enableTotp(name, code, { guard = null } = {}) {
    const h = this.home(name);
    const r = this.factorRecord(name);
    if (!h || !r?.totp || r.totp.enabled) throw new UserError('unknown', 'no two-step sign-in is being set up');
    const { secret } = r.totp;
    const step = verifyTotp(base32Decode(secret), code, this.now(), r.totp.lastUsedStep ?? null);
    if (step === null) return null;
    const codes = newRecoveryCodes();
    await this.commit(h.map, h.k, (cur) => {
      // Another request turned it on, or set up a new secret, in the meantime.
      if (!cur?.totp || cur.totp.enabled || cur.totp.secret !== secret) throw new UserError('unknown', 'no two-step sign-in is being set up');
      return { ...cur, totp: { ...cur.totp, enabled: true, lastUsedStep: step }, recoveryCodes: codes.map(hashRecoveryCode) };
    }, guard);
    return codes;
  }

  async disableTotp(name, { guard = null } = {}) {
    const h = this.home(name);
    if (!h || !this.factorRecord(name)) throw new UserError('unknown', 'no such user');
    await this.commit(h.map, h.k, (cur) => {
      if (!cur) throw new UserError('unknown', 'no such user');
      return { ...cur, totp: null, recoveryCodes: [] };
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
    return { ok: true, saved: this.save() };
  }

  // Uses up a recovery code. Returns {ok, left, saved}.
  useRecoveryCode(name, code) {
    const r = this.factorRecord(name);
    const codes = r?.totp?.enabled ? (r.recoveryCodes ?? []) : [];
    const given = Buffer.from(hashRecoveryCode(code), 'hex');
    // Every stored hash is compared, whatever matches.
    let at = -1;
    codes.forEach((h, i) => {
      if (crypto.timingSafeEqual(Buffer.from(h, 'hex'), given) && at < 0) at = i;
    });
    if (at < 0 || normalRecoveryCode(code).length !== 16) return { ok: false, left: codes.length, saved: Promise.resolve() };
    codes.splice(at, 1);
    return { ok: true, left: codes.length, saved: this.save() };
  }

  // New recovery codes in place of the old ones; returns them (the only time they are seen).
  async newRecoveryCodes(name, { guard = null } = {}) {
    const h = this.home(name);
    if (!h || !this.factorRecord(name)?.totp?.enabled) throw new UserError('unknown', 'two-step sign-in is not on');
    const codes = newRecoveryCodes();
    await this.commit(h.map, h.k, (cur) => {
      if (!cur?.totp?.enabled) throw new UserError('unknown', 'two-step sign-in is not on');
      return { ...cur, recoveryCodes: codes.map(hashRecoveryCode) };
    }, guard);
    return codes;
  }

  // Notes the time of a sign in, for users who have a record; nothing is made for the others.
  async recordLogin(name) {
    const r = this.factorRecord(name);
    if (!r) return;
    r.lastLogin = this.iso();
    await this.save();
  }

  // Notes a sign in: its time, and that the device with this hash was used now. In memory at once;
  // written at most once each LOGIN_WRITE_MS per user, so that signing in over and over cannot keep
  // the disk busy (a crash loses at most that much). Gives the write, when there is one.
  touchLogin(name, hash = null) {
    const r = this.factorRecord(name);
    if (!r) return Promise.resolve();
    const iso = this.iso();
    r.lastLogin = iso;
    const d = hash === null ? undefined : (r.devices ?? []).find((x) => x.hash === hash);
    if (d) d.lastUsed = iso;
    const k = key(name);
    const t = this.now();
    const last = this.touched.get(k);
    if (last !== undefined && t - last < LOGIN_WRITE_MS && t >= last) return Promise.resolve();
    this.touched.set(k, t);
    return this.save();
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
  // MAX_DEVICES the least recently used one is forgotten. Gives the write.
  addDevice(name, hash) {
    return this.rememberDevice(name, hash).saved;
  }

  // addDevice, giving {evicted, saved}: evicted are the devices it pushed out ({hash, created,
  // lastUsed}), saved the write.
  rememberDevice(name, hash) {
    const r = this.deviceRecord(name);
    if (!r || typeof hash !== 'string' || !HEX64.test(hash)) return { evicted: [], saved: Promise.resolve() };
    const t = this.iso();
    const evicted = [];
    const known = r.devices.find((d) => d.hash === hash);
    if (known) known.lastUsed = t;
    else {
      // In place: a record copied by a change being written meanwhile shares this list.
      while (r.devices.length >= MAX_DEVICES) {
        let lru = 0;
        r.devices.forEach((d, i) => {
          if (d.lastUsed < r.devices[lru].lastUsed) lru = i;
        });
        evicted.push(...r.devices.splice(lru, 1));
      }
      r.devices.push({ hash, created: t, lastUsed: t });
    }
    return { evicted, saved: this.save() };
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
    return { removed: hashes.length, hashes, saved: hashes.length > 0 ? this.save() : Promise.resolve() };
  }

  // ---- managing users (the users page uses these) ----

  admins() {
    return this.list().filter((u) => u.role === 'admin').length;
  }

  // The website user with a name; refuses users in the config file and unknown names.
  localUser(name) {
    const k = key(name);
    if (this.config.has(k)) throw new UserError('config', 'this user is managed in the config file');
    const r = this.local.get(k);
    if (!r) throw new UserError('unknown', 'no such user');
    return r;
  }

  // passwordHash: a PHC string from hashPassword.
  async createUser({ name, role = DEFAULT_ROLE, passwordHash }) {
    if (typeof name !== 'string' || !USER_NAME_RE.test(name)) throw new UserError('bad-name', 'a name is 1 to 32 letters, digits, dots, dashes or underscores, starting with a letter or digit');
    if (!ROLES.includes(role)) throw new UserError('bad-role', `the role must be one of ${ROLES.join(', ')}`);
    parsePhc(passwordHash);
    const k = key(name);
    const created = this.iso();
    const check = (cur) => {
      if (this.config.has(k) || cur) throw new UserError('exists', 'a user with this name exists');
      if (this.local.size + this.factors.size >= MAX_STORE_USERS) throw new UserError('bad-name', `at most ${MAX_STORE_USERS} users`);
    };
    check(this.local.get(k));
    await this.commit(this.local, k, (cur) => {
      check(cur);
      return { name, role, passwordHash, created, lastLogin: null, totp: null, recoveryCodes: [], credentials: [], devices: [] };
    });
  }

  // Callers end the user's sessions afterwards (auth.endUser).
  async deleteUser(name) {
    const k = key(name);
    const check = (r) => {
      if (r.role === 'admin' && this.admins() <= 1) throw new UserError('last-admin', 'the last admin cannot be removed');
    };
    check(this.localUser(name));
    await this.commit(this.local, k, (cur) => {
      if (!cur) throw new UserError('unknown', 'no such user');
      check(cur);
      return null;
    });
    this.touched.delete(k);
  }

  // Callers end the user's sessions afterwards (auth.endUser).
  async setRole(name, role) {
    if (!ROLES.includes(role)) throw new UserError('bad-role', `the role must be one of ${ROLES.join(', ')}`);
    const check = (r) => {
      if (r.role === 'admin' && role !== 'admin' && this.admins() <= 1) throw new UserError('last-admin', 'the last admin cannot be removed');
    };
    check(this.localUser(name));
    await this.commit(this.local, key(name), (cur) => {
      if (!cur) throw new UserError('unknown', 'no such user');
      check(cur);
      return { ...cur, role };
    });
  }

  // Callers end the user's other sessions afterwards (auth.endUser).
  async setPassword(name, passwordHash, { guard = null } = {}) {
    parsePhc(passwordHash);
    this.localUser(name);
    await this.commit(this.local, key(name), (cur) => {
      if (!cur) throw new UserError('unknown', 'no such user');
      return { ...cur, passwordHash };
    }, guard);
  }

  // Takes away a user's second factor (TOTP and recovery codes; passkeys too, once there are any),
  // for someone who lost their phone. Works for users in the config file too. Callers end the
  // user's sessions afterwards (auth.endUser).
  async resetSecondFactor(name) {
    const h = this.home(name);
    if (!h) throw new UserError('unknown', 'no such user');
    if (!this.factorRecord(name)) return;
    await this.commit(h.map, h.k, (cur) => (cur ? { ...cur, totp: null, recoveryCodes: [], credentials: [] } : null));
  }
}
