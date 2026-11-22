// The user store on disk: users.db in the data directory, a SQLite database opened with node:sqlite.
// UserStore (users.js) keeps every record in memory and serves reads from there; this file maps
// its records to rows and back, and runs each change as one short transaction, so that the server
// and scripts/users.js can both write while the other runs.
//
// What is read from the database is checked as strictly as users.json was (checkRecord), and
// every text and list is bounded before it is used: the file is data, not code. TOTP secrets are
// kept encrypted (keys.js), recovery codes as an HMAC of their old SHA-256, so the database alone
// gives neither. Encryption and decryption happen only here; in memory a TOTP secret is base32.
//
// The first start makes the database and imports users.json into it, once, in one transaction. A
// crash before the end leaves it empty and the next start imports again. users.json is never
// written or removed by the server: it stays as the snapshot an older version of the website can
// still read, until the operator retires it (retireJson renames or deletes it, scripts/users.js
// retire-users-json). While it, or the renamed users.json.imported, is there every start warns: it
// holds second-factor secrets unencrypted.
//
// A user's own LXMF alert address (see lxmf-alerts.js) is kept in the meta table, one row per user, under
// the key "lxmf|<kind>|<name key>", as a short JSON text. That needs no schema change, so older releases
// still read the database: they ignore these rows (they read only the first 32 rows of meta, and these
// come after the ones they look for). A row remembers the created time of the user it belongs to, so that
// one left behind when an older release deleted the user is not given to a new user of the same name.
//
// A database that cannot be read, is newer than this version, has objects (tables, triggers,
// views) this version does not make, or needs a key that was not given stops the start with a
// StoreError for the operator, and is left as it is.
//
// Only the server records a new key version, when it starts. scripts/users.js uses the highest
// version that is both given and recorded, so it never seals or peppers with a key the running
// server does not have.
//
// Note: this imports from users.js, which imports from here. Neither uses the other's exports
// while the modules load, only inside functions, so either can be imported first.
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import fsSync, { constants as fsc } from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { KeyError } from './keys.js';
import { parsePhc } from './password.js';
import { base32Decode, base32Encode } from './totp.js';
import { MAX_DEVICES, MAX_RECOVERY_CODES, MAX_STORE_USERS, STORE_FILE, StoreError, StoreFullError, UserError, checkRecord, parseStore, passkeyLabel } from './users.js';

export const DB_FILE = 'users.db';
// At most this many passkeys per user.
export const MAX_PASSKEYS = 10;
// The longest a passkey's columns are read: its id and public key in bytes, its transports (a JSON
// list of at most eight names), name and rpId in characters. users.js checks them more closely.
const PASSKEY_ID_BYTES = 512;
const PASSKEY_KEY_BYTES = 600;
const TRANSPORTS_CHARS = 128;
const PASSKEY_NAME_CHARS = 64;
const RP_ID_CHARS = 253;
// users.json is read for the import only up to this size: more than MAX_STORE_USERS users with
// every field at its longest ever made.
const MAX_IMPORT_BYTES = 8 * 1024 * 1024;
// The bounds of a TOTP box: format byte, key version, IV and tag around a secret of 10 to 64 bytes.
const MIN_BOX_BYTES = 41;
const MAX_BOX_BYTES = 95;
const ISO_CHARS = 32;
const SQLITE_BUSY = 5;
// The meta rows of users' LXMF addresses: the key prefix, and the longest value read.
const LXMF_PREFIX = 'lxmf|';
const LXMF_VALUE_CHARS = 200;
const LXMF_ADDRESS = /^[0-9a-f]{32}$/;
// Opened without following a link, and without blocking on a FIFO put in place of a file.
const READ_FLAGS = fsc.O_RDONLY | (fsc.O_NOFOLLOW ?? 0) | (fsc.O_NONBLOCK ?? 0);
// Written next to users.db when a store is first made in a data directory, and never removed: an
// import into a new users.db finds it when an older store was moved away (see openUserDb). Its first
// line is when the first store was made; a second line, "users TIME", is added once a store here
// had users, which is what makes an import of users.json a step back. Its name does not start with
// users.db, so that moving users.db* away leaves it.
export const MADE_FILE = 'user-store.created';
// The name users.json gets from retire-users-json. (STORE_FILE cannot be used here while the
// modules load; see the note above.)
export const RETIRED_FILE = 'users.json.imported';
// A dropped field of users.json is named in a warning only when it looks like a field name;
// anything else in the file could be a secret, and is only counted.
const FIELD_NAME = /^[A-Za-z0-9_.]{1,40}$/;

// Schema version 1. The passkey tables are made now, so that going back from the passkey release
// to this one does not find a database "made by a newer version".
const SCHEMA_V1 = `
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT;
CREATE TABLE keys (version INTEGER PRIMARY KEY CHECK (version BETWEEN 1 AND 65535), check_value BLOB NOT NULL, added TEXT NOT NULL) STRICT;
CREATE TABLE users (
  id INTEGER PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('store','config')),
  name TEXT NOT NULL, name_key TEXT NOT NULL,
  role TEXT CHECK (role IN ('admin','manage','viewer')),
  password_hash TEXT CHECK (password_hash IS NULL OR length(password_hash) <= 600),
  must_change_password INTEGER NOT NULL DEFAULT 0 CHECK (must_change_password IN (0,1)),
  created TEXT, last_login TEXT,
  totp_box BLOB CHECK (totp_box IS NULL OR length(totp_box) BETWEEN 41 AND 95),
  totp_enabled INTEGER CHECK (totp_enabled IN (0,1)),
  totp_last_step INTEGER CHECK (totp_last_step >= 0),
  passkey_user_id BLOB UNIQUE,
  UNIQUE (kind, name_key),
  CHECK ((kind = 'store') = (role IS NOT NULL AND password_hash IS NOT NULL)),
  CHECK ((totp_box IS NULL) = (totp_enabled IS NULL))
) STRICT;
CREATE TABLE recovery_codes (user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  key_version INTEGER NOT NULL, hash BLOB NOT NULL CHECK (length(hash) = 32), PRIMARY KEY (user_id, hash)) STRICT;
CREATE TABLE devices (user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  hash TEXT NOT NULL CHECK (length(hash) = 64), created TEXT NOT NULL, last_used TEXT NOT NULL, PRIMARY KEY (user_id, hash)) STRICT;
CREATE TABLE credentials (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  type TEXT NOT NULL CHECK (type = 'passkey'), cred_id BLOB NOT NULL UNIQUE, public_key BLOB NOT NULL,
  counter INTEGER NOT NULL DEFAULT 0, transports TEXT NOT NULL DEFAULT '[]', name TEXT NOT NULL,
  created TEXT NOT NULL, last_used TEXT, backup_eligible INTEGER NOT NULL, backed_up INTEGER NOT NULL, rp_id TEXT NOT NULL) STRICT;
CREATE INDEX credentials_user ON credentials(user_id);
`;

// MIGRATIONS[i] takes the database from schema version i to i + 1, in a transaction of its own.
// checkSchema compares the SQL text sqlite_schema keeps with what these steps make in a new
// database. A step with ALTER TABLE ... RENAME rewrites the stored SQL of other tables, and how it
// does that may differ between SQLite versions: such a step needs its result checked by its own
// rules rather than by comparing text.
//
// Version 2 has the same tables as version 1. It says that passkeys are in use: the release before
// passkeys reads version 1 only, and would let a user whose only second factor is a passkey sign in
// with the password alone. So a database is not moved to it when it opens: the first passkey kept
// raises it (in the same transaction, see syncVersion), and removing the last one lowers it again,
// so that going back stays possible while nobody has a passkey. Such a step is marked onDemand.
const PASSKEYS_IN_USE = Object.assign(() => {}, { onDemand: true });
export const MIGRATIONS = [(sql) => sql.exec(SCHEMA_V1), PASSKEYS_IN_USE];
// The newest schema version this release reads, and the one that says passkeys are in use.
export const SCHEMA_VERSION = MIGRATIONS.length;
export const PASSKEY_VERSION = 2;

// The keys a record of users.json may have; any other is dropped at the import, and named.
const RECORD_KEYS = { store: ['name', 'role', 'passwordHash', 'created', 'lastLogin', 'totp', 'recoveryCodes', 'credentials', 'devices', 'mustChangePassword'], config: ['name', 'created', 'lastLogin', 'totp', 'recoveryCodes', 'credentials', 'devices'] };
const TOTP_KEYS = ['secret', 'enabled', 'lastUsedStep'];
const TOP_KEYS = ['version', 'users', 'configUsers'];

// Another program held the store for longer than the busy timeout; nothing was changed.
export class StoreBusyError extends Error {
  constructor(options) {
    super('another program is changing the user store', options);
    this.code = 'busy';
  }
}

// What the website says when users exist and no key was given.
export const NO_KEY = 'the user store has users, and they need a key: set USERS_KEY_FILE (node scripts/users.js gen-key makes one); nothing was changed';

const nameKey = (name) => name.trim().toLowerCase();
const aadOf = (kind, k) => `totp|${kind}|${k}`;
const isBusy = (err) => err?.code === 'ERR_SQLITE_ERROR' && (err.errcode & 0xff) === SQLITE_BUSY;
const busyOr = (err) => (isBusy(err) ? new StoreBusyError({ cause: err }) : err);
// node:sqlite gives a BLOB as a Uint8Array.
const buf = (v) => (v instanceof Uint8Array ? Buffer.from(v.buffer, v.byteOffset, v.byteLength) : null);
const boxVersion = (box) => box.readUInt16BE(1);
const WRAPPED = /^k([1-9]\d{0,4}):([0-9a-f]{64})$/;

// A column read only when it is at most n long: a longer one comes back as NULL with its length, so
// that a huge value in a damaged or planted file is never read into memory.
const capped = (col, n, as = col) => `CASE WHEN length(${col}) <= ${n} THEN ${col} END AS ${as}, length(${col}) AS ${as}_len`;

export class UserDb {
  // sql: an open DatabaseSync. keys: the Keyring, or null when none was given.
  // migrations: the schema steps, which say what the schema of each version must be (checkSchema).
  // marker: what user-store.created said ({dataDir, made, hadUsers, saved}), or null for none kept.
  constructor(sql, { keys = null, maxUsers = MAX_STORE_USERS, now = Date.now, file = null, migrations = MIGRATIONS, marker = null, warn = console.warn, timeoutMs = 1000 } = {}) {
    Object.assign(this, { sql, keys, maxUsers, now, file, migrations, marker, warn, timeoutMs });
    this.statements = new Map();
    this.seen = this.dataVersion();
    // Whether the open transaction wrote a user (see noteUsers).
    this.wroteUser = false;
  }

  stmt(text) {
    let s = this.statements.get(text);
    if (!s) {
      s = this.sql.prepare(text);
      this.statements.set(text, s);
    }
    return s;
  }

  dataVersion() {
    return this.stmt('PRAGMA data_version').get().data_version;
  }

  userVersion() {
    return this.stmt('PRAGMA user_version').get().user_version;
  }

  // Runs fn in one write transaction: BEGIN IMMEDIATE, COMMIT, or ROLLBACK when fn throws. fn must
  // not wait for anything, so that the store is held for milliseconds only. Throws StoreBusyError
  // when another program held the store for longer than the busy timeout.
  tx(fn) {
    if (this.sql.isTransaction) throw new Error('a user store transaction is already open');
    try {
      this.sql.exec('BEGIN IMMEDIATE');
    } catch (err) {
      throw busyOr(err);
    }
    this.wroteUser = false;
    try {
      const out = fn();
      if (typeof out?.then === 'function') throw new Error('a user store transaction must not wait');
      this.sql.exec('COMMIT');
      if (this.wroteUser) this.noteUsers();
      return out;
    } catch (err) {
      if (this.sql.isTransaction) {
        try {
          this.sql.exec('ROLLBACK');
        } catch {
          // The error that made the transaction fail is the one to report.
        }
      }
      throw busyOr(err);
    }
  }

  // Whether another connection (scripts/users.js, say) changed the store since it was last loaded.
  changedElsewhere() {
    return this.dataVersion() !== this.seen;
  }

  inTx() {
    if (!this.sql.isTransaction) throw new Error('user store writes must run in a transaction');
  }

  // Every record, checked and decrypted: {users, configUsers}. Throws StoreError. The schema is
  // checked each time too: a trigger or view put in while the server runs is refused as at start.
  load() {
    const own = !this.sql.isTransaction;
    if (own) this.sql.exec('BEGIN');
    try {
      checkSchema(this.sql, this.migrations, this.userVersion());
      const lxmf = this.lxmfRows();
      const data = { users: this.records('store', lxmf), configUsers: this.records('config', lxmf) };
      // In the same read transaction as the records, so no change can fall between the two.
      const version = this.dataVersion();
      if (own) this.sql.exec('COMMIT');
      this.seen = version;
      return data;
    } catch (err) {
      if (own && this.sql.isTransaction) this.sql.exec('ROLLBACK');
      if (err instanceof StoreError || err instanceof StoreBusyError) throw err;
      throw new StoreError(`${DB_FILE} in the data directory cannot be read (${err.message}); fix or move it, it was left as it is`);
    }
  }

  // The LXMF address rows of meta: a Map of "<kind>|<name key>" to {address, confirmed, nodeAlerts, created}.
  // A row that is not as this version writes it is left out (the user has no address), never an error: it is
  // a preference, and not worth making the whole store unreadable.
  lxmfRows() {
    const out = new Map();
    const rows = this.stmt(`SELECT key, CASE WHEN length(value) <= ${LXMF_VALUE_CHARS} THEN value END AS value FROM meta WHERE substr(key, 1, ${LXMF_PREFIX.length}) = ? LIMIT ?`).all(LXMF_PREFIX, 2 * this.maxUsers + 1);
    for (const { key: k, value } of rows) {
      if (typeof value !== 'string') continue;
      let v;
      try {
        v = JSON.parse(value);
      } catch {
        continue;
      }
      if (v === null || typeof v !== 'object' || typeof v.address !== 'string' || !LXMF_ADDRESS.test(v.address) || typeof v.confirmed !== 'boolean' || typeof v.nodeAlerts !== 'boolean') continue;
      if (v.created !== null && typeof v.created !== 'string') continue;
      out.set(k.slice(LXMF_PREFIX.length), v);
    }
    return out;
  }

  // At start: deletes the LXMF rows that no user has any more (an older release left them when a user was
  // deleted) or whose `created` is not the user's (a user made again under the same name), so that they cannot
  // push live rows out of lxmfRows' limit. A row that is not JSON goes too. Warns if the limit is still reached.
  // Runs in a write transaction of its own.
  pruneLxmf() {
    const gone = this.tx(() =>
      this.stmt(
        `DELETE FROM meta WHERE substr(key, 1, ${LXMF_PREFIX.length}) = ?1 AND NOT EXISTS (
           SELECT 1 FROM users u WHERE u.kind || '|' || u.name_key = substr(meta.key, ${LXMF_PREFIX.length + 1})
           AND json_valid(meta.value) AND u.created IS (CASE WHEN json_valid(meta.value) THEN json_extract(meta.value, '$.created') END))`,
      ).run(LXMF_PREFIX).changes,
    );
    const left = this.stmt(`SELECT count(*) AS n FROM meta WHERE substr(key, 1, ${LXMF_PREFIX.length}) = ?`).get(LXMF_PREFIX).n;
    if (left > 2 * this.maxUsers) this.warn(`warning: ${DB_FILE} has more LXMF address rows (${left}) than ${2 * this.maxUsers} users can have: only some are read, so some users may have no address`);
    return Number(gone);
  }

  records(kind, lxmf = new Map()) {
    const list = kind === 'store' ? 'users' : 'configUsers';
    const rows = this.stmt(
      `SELECT id, ${capped('name', 64)}, ${capped('name_key', 64)}, ${capped('role', 16)}, ${capped('password_hash', 600)}, must_change_password,
       ${capped('created', ISO_CHARS)}, ${capped('last_login', ISO_CHARS)}, ${capped('totp_box', MAX_BOX_BYTES)}, totp_enabled, totp_last_step,
       ${capped('passkey_user_id', 32)}
       FROM users WHERE kind = ? ORDER BY id LIMIT ?`,
    ).all(kind, this.maxUsers + 1);
    if (rows.length > this.maxUsers) throw this.bad(`${list} has more than ${this.maxUsers} users`);
    return rows.map((row) => this.record(kind, row, `${list} row ${row.id}`, lxmf));
  }

  bad(why) {
    return new StoreError(`${DB_FILE} in the data directory cannot be used: ${why}. Fix or move it; it was left as it is`);
  }

  // One row and its child rows as a record, as users.json had it.
  record(kind, row, where, lxmf = new Map()) {
    for (const col of ['name', 'name_key', 'role', 'password_hash', 'created', 'last_login', 'totp_box', 'passkey_user_id']) {
      if (row[col] === null && row[`${col}_len`] !== null) throw this.bad(`${where}.${col} is too long`);
    }
    if (typeof row.name !== 'string' || typeof row.name_key !== 'string' || row.name_key !== nameKey(row.name)) throw this.bad(`${where}.name does not match its key`);
    const r = { name: row.name };
    if (kind === 'store') Object.assign(r, { role: row.role, passwordHash: row.password_hash });
    else if (row.role !== null || row.password_hash !== null) throw this.bad(`${where} is a config user with a role or password`);
    r.created = row.created;
    r.lastLogin = row.last_login;
    r.totp = null;
    const box = row.totp_box === null ? null : buf(row.totp_box);
    if ((row.totp_box === null) !== (row.totp_enabled === null)) throw this.bad(`${where}.totp is half there`);
    if (box !== null) {
      if (box.length < MIN_BOX_BYTES || row.totp_enabled === null) throw this.bad(`${where}.totp is not a sealed secret`);
      if (this.keys === null) throw new StoreError(NO_KEY);
      let secret;
      try {
        secret = this.keys.openTotp(box, aadOf(kind, row.name_key));
      } catch {
        throw this.bad(`${where}.totp does not decrypt with key version ${boxVersion(box)}: the key is wrong or the row is damaged`);
      }
      if (row.totp_enabled !== 0 && row.totp_enabled !== 1) throw this.bad(`${where}.totp_enabled must be 0 or 1`);
      r.totp = { secret: base32Encode(secret), enabled: row.totp_enabled === 1, lastUsedStep: row.totp_last_step };
    }
    r.recoveryCodes = this.stmt('SELECT key_version, hash FROM recovery_codes WHERE user_id = ? ORDER BY rowid LIMIT ?')
      .all(row.id, MAX_RECOVERY_CODES + 1)
      .map((c) => {
        const h = buf(c.hash);
        if (!Number.isInteger(c.key_version) || c.key_version < 1 || c.key_version > 65535 || h === null || h.length !== 32) throw this.bad(`${where} has a recovery code that is not a key version and a 32-byte hash`);
        return `k${c.key_version}:${h.toString('hex')}`;
      });
    if (row.passkey_user_id !== null) {
      const handle = buf(row.passkey_user_id);
      if (handle === null || handle.length !== 32) throw this.bad(`${where}.passkey_user_id is not 32 bytes`);
      r.passkeyUserId = handle.toString('base64url');
    }
    const creds = this.stmt(
      `SELECT id, ${capped('type', 16)}, ${capped('cred_id', PASSKEY_ID_BYTES)}, ${capped('public_key', PASSKEY_KEY_BYTES)}, counter, ${capped('transports', TRANSPORTS_CHARS)},
       ${capped('name', PASSKEY_NAME_CHARS)}, ${capped('created', ISO_CHARS)}, ${capped('last_used', ISO_CHARS)}, backup_eligible, backed_up, ${capped('rp_id', RP_ID_CHARS)}
       FROM credentials WHERE user_id = ? ORDER BY id LIMIT ?`,
    ).all(row.id, MAX_PASSKEYS + 1);
    if (creds.length > MAX_PASSKEYS) throw this.bad(`${where} has more than ${MAX_PASSKEYS} passkeys`);
    // A name that would not be kept as typed today (refused by a stricter rule than the one it was
    // saved under, blank, or not trimmed: a row changed by hand) is read as "Passkey N", its place
    // in the list, rather than making the whole store unreadable; the next change of the user
    // writes that name back.
    r.credentials = creds.map((c, i) => {
      const p = this.passkey(c, `${where} passkey row ${c.id}`);
      return typeof p.name === 'string' && passkeyLabel(p.name) === p.name ? p : { ...p, name: `Passkey ${i + 1}` };
    });
    r.devices = this.stmt(`SELECT ${capped('hash', 64)}, ${capped('created', ISO_CHARS)}, ${capped('last_used', ISO_CHARS)} FROM devices WHERE user_id = ? ORDER BY rowid LIMIT ?`)
      .all(row.id, MAX_DEVICES + 1)
      .map((d) => ({ hash: d.hash, created: d.created, lastUsed: d.last_used }));
    if (kind === 'store') {
      if (row.must_change_password !== 0 && row.must_change_password !== 1) throw this.bad(`${where}.must_change_password must be 0 or 1`);
      if (row.must_change_password === 1) r.mustChangePassword = true;
    }
    // Only when it belongs to this very user (see the top).
    const mine = lxmf.get(`${kind}|${row.name_key}`);
    if (mine !== undefined && mine.created === (row.created ?? null)) r.lxmf = { address: mine.address, confirmed: mine.confirmed, nodeAlerts: mine.nodeAlerts };
    try {
      checkRecord(r, where, kind === 'store', true);
    } catch (err) {
      throw this.bad(err.message);
    }
    return r;
  }

  // One credentials row as a passkey of a record; checkRecord checks it further. Never says a value.
  passkey(c, where) {
    // A name too long to read is null here, and read as "Passkey N" (see record).
    for (const col of ['type', 'cred_id', 'public_key', 'transports', 'created', 'last_used', 'rp_id']) {
      if (c[col] === null && c[`${col}_len`] !== null) throw this.bad(`${where}.${col} is too long`);
    }
    const id = buf(c.cred_id);
    const publicKey = buf(c.public_key);
    if (id === null || publicKey === null) throw this.bad(`${where} has no id or key`);
    let transports;
    try {
      transports = JSON.parse(c.transports);
    } catch {
      throw this.bad(`${where}.transports is not a list`);
    }
    for (const col of ['backup_eligible', 'backed_up']) if (c[col] !== 0 && c[col] !== 1) throw this.bad(`${where}.${col} must be 0 or 1`);
    return {
      type: c.type,
      id: id.toString('base64url'),
      publicKey: publicKey.toString('base64url'),
      counter: c.counter,
      transports,
      name: c.name,
      created: c.created,
      lastUsed: c.last_used,
      backupEligible: c.backup_eligible === 1,
      backedUp: c.backed_up === 1,
      rpId: c.rp_id,
    };
  }

  // Writes one record: its row is made or replaced, and its recovery codes, devices and passkeys
  // replaced. A passkey keeps its row (matched by its id), so that only what changes about it is
  // written; one whose id belongs to another user is refused with UserError 'exists'. Runs inside
  // tx. Throws StoreFullError past a limit, StoreError for a record it could not read back.
  put(kind, rec) {
    this.inTx();
    if (this.keys === null) throw new StoreError(NO_KEY);
    const k = nameKey(rec.name);
    if ((rec.recoveryCodes ?? []).length > MAX_RECOVERY_CODES) throw new StoreFullError(`the user store is full: at most ${MAX_RECOVERY_CODES} recovery codes per user`);
    if ((rec.devices ?? []).length > MAX_DEVICES) throw new StoreFullError(`the user store is full: at most ${MAX_DEVICES} devices per user`);
    if ((rec.credentials ?? []).length > MAX_PASSKEYS) throw new StoreFullError(`the user store is full: at most ${MAX_PASSKEYS} passkeys per user`);
    // Never write what would not be read back.
    checkRecord(rec, `the record of ${kind === 'store' ? 'a website user' : 'a config user'}`, kind === 'store', true);
    const known = this.stmt('SELECT id FROM users WHERE kind = ? AND name_key = ?').get(kind, k);
    if (!known && this.stmt('SELECT count(*) AS n FROM users WHERE kind = ?').get(kind).n >= this.maxUsers) {
      throw new StoreFullError(`the user store is full: it would have more than ${this.maxUsers} users`);
    }
    const t = rec.totp ?? null;
    const box = t === null ? null : this.keys.sealTotp(base32Decode(t.secret), aadOf(kind, k));
    const local = kind === 'store';
    const { id } = this.stmt(
      `INSERT INTO users (kind, name, name_key, role, password_hash, must_change_password, created, last_login, totp_box, totp_enabled, totp_last_step, passkey_user_id)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT (kind, name_key) DO UPDATE SET name = excluded.name, role = excluded.role, password_hash = excluded.password_hash,
         must_change_password = excluded.must_change_password, created = excluded.created, last_login = excluded.last_login,
         totp_box = excluded.totp_box, totp_enabled = excluded.totp_enabled, totp_last_step = excluded.totp_last_step,
         passkey_user_id = excluded.passkey_user_id
       RETURNING id`,
    ).get(
      kind, rec.name, k, local ? rec.role : null, local ? rec.passwordHash : null, local && rec.mustChangePassword === true ? 1 : 0,
      rec.created ?? null, rec.lastLogin ?? null, box, t === null ? null : t.enabled ? 1 : 0, t === null ? null : (t.lastUsedStep ?? null),
      rec.passkeyUserId ? Buffer.from(rec.passkeyUserId, 'base64url') : null,
    );
    this.stmt('DELETE FROM recovery_codes WHERE user_id = ?').run(id);
    for (const entry of rec.recoveryCodes ?? []) {
      const [version, hex] = this.wrap(entry);
      this.stmt('INSERT OR IGNORE INTO recovery_codes (user_id, key_version, hash) VALUES (?, ?, ?)').run(id, version, Buffer.from(hex, 'hex'));
    }
    this.stmt('DELETE FROM devices WHERE user_id = ?').run(id);
    for (const d of rec.devices ?? []) this.stmt('INSERT OR IGNORE INTO devices (user_id, hash, created, last_used) VALUES (?, ?, ?, ?)').run(id, d.hash, d.created, d.lastUsed);
    const creds = (rec.credentials ?? []).map((c) => ({ ...c, bytes: Buffer.from(c.id, 'base64url') }));
    // By hex, which SQLite gives in upper case.
    const keep = creds.map((c) => c.bytes.toString('hex').toUpperCase());
    this.stmt('DELETE FROM credentials WHERE user_id = ? AND hex(cred_id) NOT IN (SELECT value FROM json_each(?))').run(id, JSON.stringify(keep));
    for (const c of creds) {
      const owner = this.stmt('SELECT user_id FROM credentials WHERE cred_id = ?').get(c.bytes);
      if (owner && owner.user_id !== id) throw new UserError('exists', 'this passkey is added already');
      const values = [c.counter, JSON.stringify(c.transports), c.name, c.lastUsed ?? null, c.backupEligible ? 1 : 0, c.backedUp ? 1 : 0];
      if (owner) {
        // Only when something changed: every write of a record comes here.
        this.stmt(
          `UPDATE credentials SET counter = ?1, transports = ?2, name = ?3, last_used = ?4, backup_eligible = ?5, backed_up = ?6 WHERE cred_id = ?7
           AND (counter IS NOT ?1 OR transports IS NOT ?2 OR name IS NOT ?3 OR last_used IS NOT ?4 OR backup_eligible IS NOT ?5 OR backed_up IS NOT ?6)`,
        ).run(...values, c.bytes);
      } else {
        this.stmt(
          `INSERT INTO credentials (counter, transports, name, last_used, backup_eligible, backed_up, user_id, type, cred_id, public_key, created, rp_id)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        ).run(...values, id, c.type, c.bytes, Buffer.from(c.publicKey, 'base64url'), c.created, c.rpId);
      }
    }
    // The LXMF address: written only when it changed (every write of a record comes here), and gone with the record's.
    const lxmfKey = `${LXMF_PREFIX}${kind}|${k}`;
    if (rec.lxmf) {
      const value = JSON.stringify({ address: rec.lxmf.address, confirmed: rec.lxmf.confirmed, nodeAlerts: rec.lxmf.nodeAlerts, created: rec.created ?? null });
      this.stmt('INSERT INTO meta (key, value) VALUES (?1, ?2) ON CONFLICT (key) DO UPDATE SET value = excluded.value WHERE value IS NOT excluded.value').run(lxmfKey, value);
    } else {
      this.stmt('DELETE FROM meta WHERE key = ?').run(lxmfKey);
    }
    this.syncVersion();
    this.wroteUser = true;
  }

  // Keeps the schema version at PASSKEY_VERSION while any passkey is kept, and at the one before
  // while none is (see MIGRATIONS). Runs inside the transaction that added or removed one, so that
  // no passkey is ever committed under a version an older release reads. Only with steps that know
  // the version (a test may give fewer), and only between those two versions.
  syncVersion() {
    this.inTx();
    if (this.migrations.length < PASSKEY_VERSION || this.migrations[PASSKEY_VERSION - 1] !== PASSKEYS_IN_USE) return;
    const v = this.userVersion();
    if (v !== PASSKEY_VERSION && v !== PASSKEY_VERSION - 1) return;
    const any = this.stmt('SELECT EXISTS (SELECT 1 FROM credentials) AS any').get().any === 1;
    if (any && v === PASSKEY_VERSION - 1) this.sql.exec(`PRAGMA user_version = ${PASSKEY_VERSION}`);
    else if (!any && v === PASSKEY_VERSION) this.sql.exec(`PRAGMA user_version = ${PASSKEY_VERSION - 1}`);
  }

  // Notes in user-store.created that a store here has had users, once: from then on, an import of
  // users.json into a new store here is a step back, and is warned about.
  noteUsers() {
    if (this.marker === null || this.marker.hadUsers) return;
    this.marker.hadUsers = true;
    saveMarker(this.marker, this.warn);
  }

  // [key version, hex] of a stored recovery code. A bare SHA-256 (from users.json, or a store
  // without a database) is wrapped with the current key now.
  wrap(entry) {
    const m = WRAPPED.exec(entry);
    if (m) return [Number(m[1]), m[2]];
    return [this.keys.current, this.keys.recoveryHash(this.keys.current, entry)];
  }

  remove(kind, k) {
    this.inTx();
    this.stmt('DELETE FROM users WHERE kind = ? AND name_key = ?').run(kind, k);
    this.stmt('DELETE FROM meta WHERE key = ?').run(`${LXMF_PREFIX}${kind}|${k}`);
    this.syncVersion();
  }

  // How much each key version still protects: {passwords, recoveryCodes, totp} by version, for
  // every version given, recorded or used. Hashes without a pepper count for none.
  keyUsage() {
    const out = new Map();
    const at = (v) => {
      if (!out.has(v)) out.set(v, { passwords: 0, recoveryCodes: 0, totp: 0 });
      return out.get(v);
    };
    for (const v of this.keys?.versions ?? []) at(v);
    for (const { version } of this.stmt('SELECT version FROM keys').all()) at(version);
    for (const { password_hash: h } of this.stmt(`SELECT password_hash FROM users WHERE kind = 'store' AND length(password_hash) <= 600`).all()) {
      let keyid = null;
      try {
        keyid = parsePhc(h).keyid ?? null;
      } catch {
        // A hash that does not parse was refused at load already.
      }
      if (keyid !== null) at(keyid).passwords++;
    }
    for (const { key_version: v, n } of this.stmt('SELECT key_version, count(*) AS n FROM recovery_codes GROUP BY key_version').all()) at(v).recoveryCodes += n;
    for (const { box } of this.stmt('SELECT substr(totp_box, 1, 3) AS box FROM users WHERE totp_box IS NOT NULL').all()) {
      const b = buf(box);
      if (b?.length === 3) at(boxVersion(b)).totp++;
    }
    return new Map([...out].sort((a, b) => a[0] - b[0]));
  }

  // Seals every TOTP secret again with the current key, in one transaction. Gives how many moved.
  rekey() {
    if (this.keys === null) throw new StoreError(NO_KEY);
    return this.tx(() => {
      let totp = 0;
      for (const row of this.stmt('SELECT id, kind, name_key, totp_box FROM users WHERE totp_box IS NOT NULL').all()) {
        const box = buf(row.totp_box);
        if (box.length >= 3 && boxVersion(box) === this.keys.current) continue;
        const aad = aadOf(row.kind, row.name_key);
        this.stmt('UPDATE users SET totp_box = ? WHERE id = ?').run(this.keys.sealTotp(this.keys.openTotp(box, aad), aad), row.id);
        totp++;
      }
      return { totp };
    });
  }

  // Copies the store to file, which must not exist (a link there counts too). The copy is made in
  // a new folder next to it that only this user can enter (mkdtemp makes it 0700), so nobody can
  // put a link or a file of their own in its way; it is synced there, checked to be the very file
  // made for it (same device and inode, this user's, mode 0600), then linked into place, which
  // refuses a file that appeared meanwhile where a rename would replace it. The folder goes in every
  // case, so a failure leaves nothing behind. A folder others can write to (without the sticky bit,
  // which keeps them from moving what is not theirs) is refused: they could swap the private folder
  // for one of theirs. beforeLink is for tests only.
  backup(file, { beforeLink = null } = {}) {
    const target = path.resolve(file);
    const parent = path.dirname(target);
    const taken = () => new Error(`${file} already exists; choose a new file`);
    const refuse = (why) => Object.assign(new Error(why), { code: 'EUNSAFE' });
    if (fsSync.lstatSync(target, { throwIfNoEntry: false })) throw taken();
    const p = fsSync.statSync(parent);
    if (process.platform !== 'win32' && (p.mode & 0o022) !== 0 && (p.mode & 0o1000) === 0) {
      throw refuse(`${parent} can be written to by other users; write the backup into a folder only you can write to`);
    }
    const dir = fsSync.mkdtempSync(path.join(parent, '.users-backup-'));
    try {
      const uid = process.getuid?.() ?? null;
      if (process.platform !== 'win32') {
        // The folder just made, opened without following a link: still ours, and closed to others.
        const dfd = fsSync.openSync(dir, fsc.O_RDONLY | fsc.O_DIRECTORY | fsc.O_NOFOLLOW);
        try {
          const d = fsSync.fstatSync(dfd);
          if (!d.isDirectory() || d.uid !== uid || (d.mode & 0o077) !== 0) throw refuse(`the folder for the backup in ${parent} was changed while it was made`);
        } finally {
          fsSync.closeSync(dfd);
        }
      }
      const tmp = path.join(dir, DB_FILE);
      // Made here first, empty, so that SQLite writes into a file only the owner can read; kept open
      // to sync it, and to know it again.
      const fd = fsSync.openSync(tmp, fsc.O_RDWR | fsc.O_CREAT | fsc.O_EXCL | (fsc.O_NOFOLLOW ?? 0), 0o600);
      try {
        const made = fsSync.fstatSync(fd);
        this.stmt('VACUUM INTO ?').run(tmp);
        fsSync.fsyncSync(fd);
        beforeLink?.(tmp);
        const now = fsSync.lstatSync(tmp, { throwIfNoEntry: false });
        const ours = now?.isFile() && now.dev === made.dev && now.ino === made.ino && (process.platform === 'win32' || (now.uid === uid && (now.mode & 0o777) === 0o600));
        if (!ours) throw refuse('the backup copy was changed or replaced before it was put in place; nothing was written');
      } finally {
        fsSync.closeSync(fd);
      }
      try {
        fsSync.linkSync(tmp, target);
      } catch (err) {
        if (err.code === 'EEXIST') throw taken();
        throw err;
      }
    } finally {
      fsSync.rmSync(dir, { recursive: true, force: true });
    }
    syncDir(parent);
  }

  // Copies users.db-wal into users.db and empties it (wal_checkpoint TRUNCATE). secure_delete
  // clears what was deleted in users.db, but the WAL still holds the pages as they were before,
  // until a checkpoint; this is that checkpoint. It never waits for another program: when one
  // reads or writes the store just then, it gives false, and is tried again later. Not inside a
  // transaction.
  scrub() {
    if (!this.sql.isOpen || this.sql.isTransaction) return false;
    try {
      this.sql.exec('PRAGMA busy_timeout = 0');
      const r = this.stmt('PRAGMA wal_checkpoint(TRUNCATE)').get();
      return r?.busy === 0;
    } catch {
      return false;
    } finally {
      try {
        this.sql.exec(`PRAGMA busy_timeout = ${Math.max(0, Math.floor(this.timeoutMs))}`);
      } catch {
        // The connection is gone; nothing to set back.
      }
    }
  }

  // The meta rows: imported_from, imported_at, imported_sha256, created (not the LXMF addresses, see the top).
  meta() {
    return Object.fromEntries(this.stmt(`SELECT key, CASE WHEN length(value) <= 200 THEN value END AS value FROM meta WHERE substr(key, 1, ${LXMF_PREFIX.length}) <> ? LIMIT 32`).all(LXMF_PREFIX).map((m) => [m.key, m.value]));
  }

  close() {
    if (this.sql.isOpen) this.sql.close();
  }
}

// Syncs a folder, so that a file just linked into it is still there after a crash. Some systems
// cannot open a folder (Windows); the file itself is synced already, so this is only tried.
function syncDir(dir) {
  let fd;
  try {
    fd = fsSync.openSync(dir, 'r');
    fsSync.fsyncSync(fd);
  } catch {
    // Best effort, see above.
  } finally {
    if (fd !== undefined) fsSync.closeSync(fd);
  }
}

// ---- the schema ----

// What sqlite_schema holds, one line per table, index, trigger or view. A name or SQL text longer
// than anything this version makes is not read, and never matches. The sqlite_stat tables that
// ANALYZE makes are left out: they only guide the query planner, and an ANALYZE run by hand must
// not make the store unusable.
function schemaOf(sql) {
  return sql
    .prepare(`SELECT ${capped('type', 16)}, ${capped('name', 128)}, ${capped('tbl_name', 128)}, ${capped('sql', 8192)} FROM sqlite_schema
      WHERE NOT (type = 'table' AND name LIKE 'sqlite\\_stat%' ESCAPE '\\') ORDER BY name, type LIMIT 100`)
    .all()
    .map((r) => ({ type: r.type, name: r.name, line: JSON.stringify([r.type, r.name, r.tbl_name, r.sql, r.sql === null && r.sql_len !== null]) }));
}

// The schema each version of the steps makes, worked out once in a database in memory.
const expectedSchemas = new WeakMap();
function expectedSchema(migrations, version) {
  let byVersion = expectedSchemas.get(migrations);
  if (!byVersion) expectedSchemas.set(migrations, (byVersion = new Map()));
  if (!byVersion.has(version)) {
    const mem = new DatabaseSync(':memory:');
    try {
      for (let i = 0; i < version; i++) migrations[i](mem);
      byVersion.set(version, schemaOf(mem));
    } finally {
      mem.close();
    }
  }
  return byVersion.get(version);
}

// A name from the file, shown only in letters, digits and underscores.
const shown = (name) => (typeof name === 'string' ? name.replace(/[^A-Za-z0-9_]/g, '?').slice(0, 40) : '(a long name)');

// Checks that the database has exactly the tables and indexes this version makes for its schema
// version, with the same SQL, and nothing else: no trigger, no view, no other table or column. A
// trigger or view put into the file would otherwise run, or be read, as part of the store. Throws
// a StoreError that names the first object that differs.
export function checkSchema(sql, migrations, version) {
  const bad = (why) => new StoreError(`${DB_FILE} in the data directory cannot be used: ${why}, so something other than the website changed it. Fix or move it; it was left as it is`);
  if (!Number.isInteger(version) || version < 0 || version > migrations.length) throw bad(`it has schema version ${Number.isInteger(version) ? version : '?'}, which this version does not know`);
  const want = expectedSchema(migrations, version);
  const have = schemaOf(sql);
  const wanted = new Set(want.map((o) => o.line));
  const extra = have.find((o) => !wanted.has(o.line));
  if (extra) {
    const known = want.some((o) => o.name === extra.name && o.type === extra.type);
    const kind = shown(extra.type);
    throw bad(known ? `its ${kind} ${shown(extra.name)} is not as this version makes it` : `it has ${/^[aeiou]/.test(kind) ? 'an' : 'a'} ${kind} named ${shown(extra.name)} that this version does not make`);
  }
  const had = new Set(have.map((o) => o.line));
  const missing = want.find((o) => !had.has(o.line));
  if (missing) throw bad(`its ${missing.type} ${shown(missing.name)} is missing`);
}

// ---- users.json ----

// Reads a regular file of at most max bytes, without following a link and without waiting on a
// FIFO. Gives {text, st} (st: what fstat said of it), {error} (why it cannot be used, for the
// operator), or null when it is not there.
async function readPlain(file, max) {
  let handle;
  try {
    handle = await fs.open(file, READ_FLAGS);
  } catch (err) {
    if (err.code === 'ENOENT') return null;
    // O_NOFOLLOW refuses a link with ELOOP (EMLINK on some systems).
    if (err.code === 'ELOOP' || err.code === 'EMLINK') return { error: 'it is a link, not a regular file' };
    return { error: `it cannot be read (${err.code ?? 'error'})` };
  }
  try {
    const st = await handle.stat();
    if (!st.isFile()) return { error: 'it is not a regular file' };
    const tooLarge = { error: `it is larger than ${Math.floor(max / 1024)} KiB` };
    if (st.size > max) return tooLarge;
    // One byte more than it said it has, to notice a file that grows while it is read.
    const buf = Buffer.alloc(st.size + 1);
    let n = 0;
    let got;
    do {
      ({ bytesRead: got } = await handle.read(buf, n, buf.length - n, n));
      n += got;
    } while (got > 0 && n < buf.length);
    if (n > st.size) return { error: 'it changed while it was read' };
    return { text: buf.subarray(0, n).toString('utf8'), st };
  } catch (err) {
    return { error: `it cannot be read (${err.code ?? 'error'})` };
  } finally {
    await handle.close();
  }
}

// users.json checked for the import, as records of this version: {users, configUsers, dropped,
// droppedOther}, where dropped names the keys that cannot be kept, and droppedOther counts those
// whose names are not shown (they do not look like field names, and could be anything).
function importable(json, maxUsers) {
  const fail = (why) => new StoreError(`${STORE_FILE} in the data directory cannot be used: ${why}. Fix or move it; it was left as it is`);
  if (json.error) throw fail(json.error);
  let parsed;
  try {
    parsed = parseStore(json.text, { maxBytes: MAX_IMPORT_BYTES, maxUsers });
  } catch (err) {
    throw fail(err.message);
  }
  const dropped = new Set(Object.keys(parsed.extra).filter((k) => !TOP_KEYS.includes(k)));
  const convert = (kind) => (r) => {
    for (const k of Object.keys(r)) if (!RECORD_KEYS[kind].includes(k)) dropped.add(k);
    for (const k of Object.keys(r.totp ?? {})) if (!TOTP_KEYS.includes(k)) dropped.add(`totp.${k}`);
    // Passkeys of users.json cannot be told apart from what a newer version means by them.
    if ((r.credentials ?? []).length > 0) dropped.add('credentials');
    const rec = { name: r.name };
    if (kind === 'store') Object.assign(rec, { role: r.role, passwordHash: r.passwordHash });
    Object.assign(rec, {
      created: r.created ?? null,
      lastLogin: r.lastLogin ?? null,
      totp: r.totp ? { secret: r.totp.secret, enabled: r.totp.enabled, lastUsedStep: r.totp.lastUsedStep ?? null } : null,
      recoveryCodes: [...(r.recoveryCodes ?? [])],
      credentials: [],
      devices: (r.devices ?? []).map((d) => ({ hash: d.hash, created: d.created, lastUsed: d.lastUsed })),
    });
    if (kind === 'store' && r.mustChangePassword === true) rec.mustChangePassword = true;
    return rec;
  };
  const users = parsed.users.map(convert('store'));
  const configUsers = parsed.configUsers.map(convert('config'));
  const named = [...dropped].filter((k) => FIELD_NAME.test(k)).sort();
  return { users, configUsers, dropped: named, droppedOther: dropped.size - named.length };
}

// The SHA-256 of users.json as it was imported, so that a later change to it can be noticed.
const sha256 = (text) => crypto.createHash('sha256').update(text).digest('hex');

// What the website says while users.json is still in the data directory after its import.
export const JSON_STILL_THERE = `warning: users.json is still in the data directory. It holds the second-factor secrets unencrypted and password hashes without a pepper, as they were at the import: move it to offline storage, or retire it with node scripts/users.js retire-users-json (it becomes ${RETIRED_FILE}). Backups made before that hold it too`;

// What the website says while users.json.imported (see retireJson) is still in the data directory.
export const RETIRED_STILL_THERE = `warning: ${RETIRED_FILE} is in the data directory. It is the retired users.json, and still holds the second-factor secrets unencrypted and password hashes without a pepper: move it to offline storage, or delete it (node scripts/users.js retire-users-json --delete does that after checking it is the imported file)`;

// Opens users.db in dataDir, making it (and importing users.json) when there is none. Gives {db,
// data, imported, addedKeys, keys, unrecorded, jsonNotImported, reimported}: data are the records,
// checked and decrypted; imported is null or how many users were imported; addedKeys the key
// versions recorded for the first time; keys the keyring to use (only the versions the store has
// recorded, so never one a running server may lack), unrecorded the given versions it has not;
// jsonNotImported whether a users.json that has users (or cannot be read) is there but was never
// imported; reimported whether users.json was imported into a store made after another one had
// been made here. Throws StoreError (for the operator; nothing was changed on disk),
// StoreBusyError, or KeyError.
//
// recordKeys: whether new key versions are recorded (the server, at start). scripts/users.js gives
// false: it records keys only into a store that has no users and no key recorded (a new store),
// and otherwise uses only versions the server recorded. migrations is only given by tests.
//
// A users.db made here is never removed again, even when the open fails: another process (a
// server starting) may have opened it meanwhile. What can be told before it is made (a users.json
// that cannot be imported, users without a key) stops the open before it is made.
export async function openUserDb({ dataDir, keys = null, timeoutMs = 1000, warn = console.warn, maxUsers = MAX_STORE_USERS, now = Date.now, migrations = MIGRATIONS, recordKeys = true }) {
  const file = path.join(dataDir, DB_FILE);
  const fail = (why) => new StoreError(`${DB_FILE} in the data directory cannot be used (${why}); fix or move it, it was left as it is`);
  const iso = () => new Date(now()).toISOString();
  await fs.mkdir(dataDir, { recursive: true });
  const json = await readPlain(path.join(dataDir, STORE_FILE), MAX_IMPORT_BYTES);
  const marker = readMarker(dataDir, await readPlain(path.join(dataDir, MADE_FILE), 256), now);
  // Read before the import below, which may add users.
  const hadUsersBefore = marker.hadUsers;
  let pending = null;
  const toImport = () => (pending ??= importable(json, maxUsers));
  const hasRecords = (p) => p.users.length + p.configUsers.length > 0;

  // SQLite opens users.db-wal and users.db-shm by their names, following links, and makes them when
  // they are missing. A link, or anything but a file, there is refused before anything is opened.
  for (const f of [`${DB_FILE}-wal`, `${DB_FILE}-shm`]) {
    const st = await fs.lstat(path.join(dataDir, f)).catch((err) => (err.code === 'ENOENT' ? null : Promise.reject(fail(`${f}: ${err.code ?? 'error'}`))));
    if (st !== null && !st.isFile()) throw fail(`${f} next to it is ${st.isSymbolicLink() ? 'a link' : 'not a regular file'}`);
  }

  let st = await fs.lstat(file).catch((err) => (err.code === 'ENOENT' ? null : Promise.reject(fail(err.code ?? 'error'))));
  if (st === null) {
    // A users.json that cannot be imported, or users without a key, stop the start before anything is made.
    if (json !== null && hasRecords(toImport()) && keys === null) throw new StoreError(NO_KEY);
    try {
      await (await fs.open(file, 'wx', 0o600)).close();
    } catch (err) {
      // Another process made it meanwhile.
      if (err.code !== 'EEXIST') throw fail(err.code ?? 'error');
    }
    st = await fs.lstat(file);
  }
  if (!st.isFile()) throw fail(st.isSymbolicLink() ? 'it is a link, not a regular file' : 'it is not a regular file');
  if (process.platform !== 'win32' && (st.mode & 0o077) !== 0) {
    warn(`warning: ${DB_FILE} can be read by other users (mode ${(st.mode & 0o777).toString(8)}); it holds password hashes and second-factor secrets, make it readable by the server only (chmod 600)`);
  }

  let sql = null;
  let db = null;
  try {
    try {
      sql = new DatabaseSync(file, { timeout: timeoutMs, enableForeignKeyConstraints: true, enableDoubleQuotedStringLiterals: false, defensive: true });
    } catch (err) {
      throw fail(err.message);
    }
    sql.enableDefensive?.(true);
    // Nothing in the schema (a trigger, a view) may call functions with side effects.
    sql.exec('PRAGMA trusted_schema = OFF');
    // Read-only checks first, so that a damaged, newer or changed file is not written to at all.
    let check;
    try {
      check = sql.prepare('PRAGMA quick_check(5)').all();
    } catch (err) {
      throw fail(isBusy(err) ? 'another program holds it' : err.message);
    }
    if (check.length !== 1 || check[0].quick_check !== 'ok') throw fail('it is damaged');
    const found = sql.prepare('PRAGMA user_version').get().user_version;
    if (!Number.isInteger(found) || found < 0) throw fail('it has no known schema version');
    if (found > migrations.length) throw new StoreError(`${DB_FILE} in the data directory was made by a newer version (schema version ${found}); use that version, or move it away. It was left as it is`);
    checkSchema(sql, migrations, found);
    // What to import is checked before anything is written, too.
    const p = found !== 0 || json === null ? { users: [], configUsers: [], dropped: [], droppedOther: 0 } : toImport();
    if (hasRecords(p) && keys === null) throw new StoreError(NO_KEY);
    const mode = sql.prepare('PRAGMA journal_mode = WAL').get().journal_mode;
    if (mode !== 'wal') throw fail('it cannot be put in WAL mode');
    // secure_delete: what is deleted (an old TOTP secret, a removed user) is overwritten, not left in free pages.
    sql.exec('PRAGMA synchronous = FULL; PRAGMA foreign_keys = ON; PRAGMA secure_delete = ON;');
    db = new UserDb(sql, { keys, maxUsers, now, file, migrations, marker, warn, timeoutMs });

    // The import: only into a database at version 0, and only once, also when two start at once.
    // A new store records the keys it is made with, before anything is sealed with them.
    let imported = null;
    let importedKeys = [];
    if (found === 0) {
      const done = db.tx(() => {
        if (db.userVersion() !== 0) return null;
        migrations[0](sql);
        for (const v of keys?.versions ?? []) db.stmt('INSERT INTO keys (version, check_value, added) VALUES (?, ?, ?)').run(v, keys.check(v), iso());
        for (const r of p.users) db.put('store', r);
        for (const r of p.configUsers) db.put('config', r);
        const meta = db.stmt('INSERT INTO meta (key, value) VALUES (?, ?)');
        meta.run('created', iso());
        if (json !== null) {
          meta.run('imported_from', STORE_FILE);
          meta.run('imported_at', iso());
          meta.run('imported_sha256', sha256(json.text));
        }
        sql.exec('PRAGMA user_version = 1');
        return { imported: json === null ? null : { users: p.users.length, configUsers: p.configUsers.length }, keys: keys?.versions ?? [] };
      });
      if (done !== null) ({ imported, keys: importedKeys } = done);
    }
    // A step marked onDemand is not taken here (see MIGRATIONS): a database stays below it until
    // what it marks happens. (A later step would then wait for it too.)
    for (let v = 1; v < migrations.length; v++) {
      if (migrations[v].onDemand && db.userVersion() <= v) break;
      db.tx(() => {
        if (db.userVersion() !== v) return;
        migrations[v](sql);
        sql.exec(`PRAGMA user_version = ${v + 1}`);
      });
    }

    db.pruneLxmf();
    const { added, recorded } = checkKeys(db, keys, iso, recordKeys);
    db.keys = keys === null ? null : keys.subset([...recorded]);
    const data = db.load();

    if (imported !== null && (p.dropped.length > 0 || p.droppedOther > 0)) {
      const named = p.dropped.length > 0 ? `: ${p.dropped.join(', ')}` : '';
      const others = p.droppedOther > 0 ? `${named ? ', and' : ':'} ${p.droppedOther} more whose names are not shown` : '';
      warn(`${STORE_FILE}: these fields are not kept in ${DB_FILE} and were dropped${named}${others}`);
    }
    const meta = db.meta();
    let jsonNotImported = false;
    if (json !== null && imported === null) {
      if (meta.imported_sha256 === undefined) {
        warn(`warning: ${STORE_FILE} is in the data directory but is not read: the user store is ${DB_FILE}, made without it. To import it, stop the server, move ${DB_FILE}* away and start`);
        let users = 1;
        try {
          users = toImport().users.length;
        } catch {
          // A users.json that cannot be read counts as one with users: it may well have some.
        }
        jsonNotImported = users > 0;
      } else if (json.text === undefined || meta.imported_sha256 !== sha256(json.text)) {
        warn(`warning: ${STORE_FILE} changed after it was imported on ${meta.imported_at} and is not read. To import it again, stop the server, move ${DB_FILE}* away and start`);
      }
    }
    // Only a store that had users makes an import a step back: a first start without users, then
    // users.json put in place and the store moved away, is a first import.
    const reimported = imported !== null && hadUsersBefore;
    if (reimported) {
      const when = marker.made !== null ? ` on ${marker.made}` : '';
      warn(`WARNING: ${STORE_FILE} was imported into a new ${DB_FILE}, but a user store with users was made in this data directory before${when}. ${STORE_FILE} is the snapshot of an older import: it may bring back users that were deleted since, and old passwords and second factors. Check the users now (node scripts/users.js list), delete those that should not be there, and reset everyone's password (reset-password --generate) and two-step sign-in (reset-2fa)`);
    }
    if (json !== null && meta.imported_sha256 !== undefined) warn(JSON_STILL_THERE);
    if (fsSync.lstatSync(path.join(dataDir, RETIRED_FILE), { throwIfNoEntry: false })) warn(RETIRED_STILL_THERE);
    if (data.users.length + data.configUsers.length > 0) marker.hadUsers = true;
    if (!marker.saved || marker.hadUsers !== marker.savedHadUsers) saveMarker(marker, warn);
    return { db, data, imported, addedKeys: [...importedKeys, ...added], keys: db.keys, unrecorded: keys === null ? [] : keys.versions.filter((v) => !recorded.has(v)), jsonNotImported, reimported };
  } catch (err) {
    if (db) db.close();
    else sql?.close();
    if (err instanceof StoreError || err instanceof StoreBusyError || err instanceof KeyError) throw err;
    if (isBusy(err)) throw new StoreBusyError({ cause: err });
    throw fail(err.message);
  }
}

const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?Z$/;

// What user-store.created says (see MADE_FILE): {dataDir, made, hadUsers, saved, savedHadUsers}.
// read is what readPlain gave. One that cannot be read counts as one of a store that had users:
// a warning too many is better than none.
function readMarker(dataDir, read, now) {
  const m = { dataDir, now, made: null, hadUsers: false, saved: read !== null, savedHadUsers: false };
  if (read === null) return m;
  const lines = typeof read.text === 'string' ? read.text.split('\n').filter((l) => l !== '') : [];
  if (ISO.test(lines[0] ?? '')) {
    m.made = lines[0];
    m.hadUsers = lines.slice(1).some((l) => l.startsWith('users '));
  } else {
    m.hadUsers = true;
  }
  m.savedHadUsers = m.hadUsers;
  return m;
}

// Writes user-store.created from m: to a new file next to it, synced, then renamed over it (which
// replaces a link put there, and never writes through one). A failure is only warned about.
function saveMarker(m, warn) {
  const iso = new Date(m.now()).toISOString();
  m.made ??= iso;
  const text = `${m.made}\n${m.hadUsers ? `users ${iso}\n` : ''}`;
  const tmp = path.join(m.dataDir, `.${MADE_FILE}.${crypto.randomBytes(6).toString('hex')}`);
  try {
    const fd = fsSync.openSync(tmp, fsc.O_WRONLY | fsc.O_CREAT | fsc.O_EXCL | (fsc.O_NOFOLLOW ?? 0), 0o600);
    try {
      fsSync.writeSync(fd, text);
      fsSync.fsyncSync(fd);
    } finally {
      fsSync.closeSync(fd);
    }
    fsSync.renameSync(tmp, path.join(m.dataDir, MADE_FILE));
    Object.assign(m, { saved: true, savedHadUsers: m.hadUsers });
  } catch (err) {
    fsSync.rmSync(tmp, { force: true });
    warn(`warning: ${MADE_FILE} could not be written in the data directory (${err.code ?? 'error'}); a later import of ${STORE_FILE} into a new ${DB_FILE} may not be warned about`);
  }
}

// Checks the keyring against the store, in one transaction that changes nothing unless it passes:
// a version with another check value is the wrong key; a version the data uses must be given,
// and must have a check value, or a wrong key could not be told from the right one (and would
// then be taken as right, locking the right one out). Gives {added, recorded}: the versions
// recorded now, and every version recorded.
//
// record: new versions are recorded (the server at start). Without it (scripts/users.js) they are
// only recorded into a store that has no users and no key recorded yet: one just made.
function checkKeys(db, keys, iso, record) {
  return db.tx(() => {
    const users = db.stmt(`SELECT count(*) AS n FROM users`).get().n;
    const rows = db.stmt('SELECT version, check_value FROM keys LIMIT 1000').all();
    const recorded = new Set(rows.map((r) => r.version));
    if (keys === null) {
      if (users > 0) throw new StoreError(NO_KEY);
      return { added: [], recorded };
    }
    for (const { version, check_value: value } of rows) {
      if (!keys.has(version)) continue;
      const want = keys.check(version);
      const have = buf(value);
      if (have === null || have.length !== want.length || !crypto.timingSafeEqual(have, want)) {
        throw new StoreError(`key version ${version} is not the key the user store was made with; give the right key for version ${version}. Nothing was changed`);
      }
    }
    for (const [v, use] of db.keyUsage()) {
      if (use.passwords + use.recoveryCodes + use.totp === 0) continue;
      if (!keys.has(v)) throw new StoreError(`the user store needs key version ${v}; it is not in USERS_KEY_FILE. Nothing was changed`);
      if (!recorded.has(v)) {
        throw new StoreError(`the user store uses key version ${v} but has no check value for it (its keys table was changed), so a wrong key cannot be told from the right one. Restore ${DB_FILE} from a backup (see "Backups" in wiki/User-Store.md). Nothing was changed`);
      }
    }
    // A store with users always has its key versions recorded: the server records them at every
    // start and the import before the first user. With none, the keys table was emptied, and the
    // key given now (right or wrong) would be taken as right for good.
    if (users > 0 && recorded.size === 0) {
      throw new StoreError(`the user store has users but no check value for any key version (its keys table was emptied), so a wrong key cannot be told from the right one. Restore ${DB_FILE} from a backup (see "Backups" in wiki/User-Store.md). Nothing was changed`);
    }
    const added = record || recorded.size === 0 ? keys.versions.filter((v) => !recorded.has(v)) : [];
    for (const v of added) {
      db.stmt('INSERT INTO keys (version, check_value, added) VALUES (?, ?, ?)').run(v, keys.check(v), iso());
      recorded.add(v);
    }
    return { added, recorded };
  });
}

// Renames users.json, once imported, to users.json.imported with mode 0600, so that it is no
// longer in the way: it still holds the secrets of the import unencrypted. Only when it is the
// very file that was imported (its SHA-256 matches); nothing is ever written over. remove: deletes
// it instead (users.json, or users.json.imported when it was renamed before), after the same check.
// Gives {file, removed}: the path it was renamed to, or the one deleted. Throws StoreError, with
// nothing changed, when it cannot.
export function retireJson(db, dataDir, { remove = false } = {}) {
  const from = path.join(dataDir, STORE_FILE);
  const to = path.join(dataDir, RETIRED_FILE);
  const refuse = (why) => new StoreError(`${why}; nothing was changed`);
  const meta = db.meta();
  if (typeof meta.imported_sha256 !== 'string') throw refuse(`${DB_FILE} was not made from a ${STORE_FILE}, so there is nothing to retire (look at ${STORE_FILE} yourself if there is one)`);
  // With remove, the retired file is deleted when users.json is gone already.
  const there = (p) => fsSync.lstatSync(p, { throwIfNoEntry: false }) !== undefined;
  const file = remove && !there(from) && there(to) ? to : from;
  const name = path.basename(file);
  let fd;
  try {
    fd = fsSync.openSync(file, READ_FLAGS);
  } catch (err) {
    if (err.code === 'ENOENT') throw refuse(`there is no ${STORE_FILE}${remove ? ` or ${RETIRED_FILE}` : ''} in the data directory`);
    if (err.code === 'ELOOP' || err.code === 'EMLINK') throw refuse(`${name} is a link, not the file that was imported`);
    throw refuse(`${name} cannot be read (${err.code ?? 'error'})`);
  }
  try {
    const st = fsSync.fstatSync(fd);
    if (!st.isFile() || st.size > MAX_IMPORT_BYTES) throw refuse(`${name} is not the file that was imported`);
    const bytes = Buffer.alloc(st.size + 1);
    let n = 0;
    let got;
    do {
      got = fsSync.readSync(fd, bytes, n, bytes.length - n, n);
      n += got;
    } while (got > 0 && n < bytes.length);
    if (n !== st.size || sha256(bytes.subarray(0, n).toString('utf8')) !== meta.imported_sha256) {
      throw refuse(`${name} is not the file that was imported on ${meta.imported_at ?? 'the first start'} (it changed since); look at it, and move it to offline storage yourself`);
    }
    // A name is taken off only while it is still this very file.
    const same = (p) => {
      const s = fsSync.lstatSync(p, { throwIfNoEntry: false });
      return s?.isFile() && s.ino === st.ino && s.dev === st.dev;
    };
    if (remove) {
      if (!same(file)) throw refuse(`${name} was replaced while it was read`);
      fsSync.unlinkSync(file);
      syncDir(dataDir);
      return { file, removed: true };
    }
    if (process.platform !== 'win32') fsSync.fchmodSync(fd, 0o600);
    try {
      fsSync.linkSync(from, to);
    } catch (err) {
      if (err.code === 'EEXIST') throw refuse(`${RETIRED_FILE} is there already; move it away first, or delete users.json with --delete`);
      throw refuse(`${STORE_FILE} could not be renamed (${err.code ?? 'error'})`);
    }
    if (!same(to) || !same(from)) {
      if (same(to)) fsSync.unlinkSync(to);
      throw refuse(`${STORE_FILE} was replaced while it was read`);
    }
    fsSync.unlinkSync(from);
    syncDir(dataDir);
    return { file: to, removed: false };
  } finally {
    fsSync.closeSync(fd);
  }
}
