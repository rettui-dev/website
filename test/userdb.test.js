import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { Keyring } from '../lib/keys.js';
import { hashPassword } from '../lib/password.js';
import { base32Decode } from '../lib/totp.js';
import { DB_FILE, JSON_STILL_THERE, MADE_FILE, MIGRATIONS, NO_KEY, SCHEMA_VERSION, StoreBusyError, openUserDb } from '../lib/userdb.js';
import { MAX_DEVICES, STORE_FILE, StoreError, StoreFullError, UserStore, hashRecoveryCode } from '../lib/users.js';
import { fakeHasher } from './helpers/fake-hasher.js';

const NOW = 1_800_000_000_000;
const tmp = () => fs.mkdtemp(path.join(os.tmpdir(), 'userdb-'));
const hash = (pw = 'a good password') => hashPassword(pw, undefined, fakeHasher);
const master = () => crypto.randomBytes(32);
const keyring = (entries) => new Keyring(new Map(entries));
const quiet = () => {};
const time = new Date(NOW).toISOString();
const SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';

// A users.json as the previous version wrote it, with every kind of field.
async function legacyStore() {
  const code = 'abcd-efgh-ijkl-mnop';
  return {
    code,
    json: {
      version: 1,
      future: { x: 1 },
      users: [
        { name: 'Bob', role: 'admin', passwordHash: await hash(), created: time, lastLogin: time, totp: { secret: SECRET, enabled: true, lastUsedStep: 5 }, recoveryCodes: [hashRecoveryCode(code)], credentials: [], devices: [{ hash: 'a'.repeat(64), created: time, lastUsed: time }], passkeyHint: 'later' },
        { name: 'carol', role: 'viewer', passwordHash: await hash('carols password'), mustChangePassword: true },
      ],
      configUsers: [{ name: 'Alice', created: time, lastLogin: null, totp: { secret: SECRET, enabled: false, lastUsedStep: null }, recoveryCodes: [], credentials: [], devices: [] }],
    },
  };
}

async function withJson(json) {
  const dataDir = await tmp();
  const text = JSON.stringify(json, null, 2);
  await fs.writeFile(path.join(dataDir, STORE_FILE), text, { mode: 0o600 });
  return { dataDir, text };
}

// Opens a store with one user who has every secret, and closes it again.
async function seeded(keys) {
  const dataDir = await tmp();
  const store = await UserStore.open({ dataDir, keys, warn: quiet, now: () => NOW });
  await store.createUser({ name: 'bob', role: 'admin', passwordHash: await hash() });
  await store.beginTotp('bob');
  store.close();
  return dataDir;
}

const bytes = (dataDir) => fs.readFile(path.join(dataDir, DB_FILE));
const raw = (dataDir) => new DatabaseSync(path.join(dataDir, DB_FILE));

test('userdb: a new store is made with mode 0600 in WAL mode, at the current schema, and records the key', async () => {
  const dataDir = await tmp();
  const keys = keyring([[1, master()]]);
  const { db, data, imported, addedKeys } = await openUserDb({ dataDir, keys, warn: quiet });
  assert.deepEqual(data, { users: [], configUsers: [] });
  assert.equal(imported, null);
  assert.deepEqual(addedKeys, [1]);
  assert.equal(db.userVersion(), SCHEMA_VERSION);
  assert.equal(db.sql.prepare('PRAGMA journal_mode').get().journal_mode, 'wal');
  assert.deepEqual(db.sql.prepare('SELECT version, check_value FROM keys').all().map((r) => [r.version, Buffer.from(r.check_value).equals(keys.check(1))]), [[1, true]]);
  if (process.platform !== 'win32') {
    for (const f of await fs.readdir(dataDir)) assert.equal((await fs.stat(path.join(dataDir, f))).mode & 0o777, 0o600, f);
  }
  db.close();
  // A second start adds no key row.
  const again = await openUserDb({ dataDir, keys, warn: quiet });
  assert.deepEqual(again.addedKeys, []);
  again.db.close();
  // Without users, no key is needed.
  (await openUserDb({ dataDir, keys: null, warn: quiet })).db.close();
});

test('userdb: a file others can read is warned about, and left as it is', { skip: process.platform === 'win32' }, async () => {
  const dataDir = await seeded(keyring([[1, master()]]));
  await fs.chmod(path.join(dataDir, DB_FILE), 0o644);
  const warnings = [];
  const err = await openUserDb({ dataDir, keys: null, warn: (w) => warnings.push(w) }).then(() => null, (e) => e);
  // It still needs its key; the warning comes first.
  assert.equal(err.message, NO_KEY);
  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /users\.db can be read by other users \(mode 644\).*chmod 600/);
  assert.equal((await fs.stat(path.join(dataDir, DB_FILE))).mode & 0o777, 0o644);
});

test('userdb: a damaged file (garbage, a cut page, a folder) stops the start, and its bytes stay as they are', async () => {
  const keys = keyring([[1, master()]]);
  const garbage = await tmp();
  await fs.writeFile(path.join(garbage, DB_FILE), crypto.randomBytes(8192), { mode: 0o600 });
  const truncated = await seeded(keys);
  const store = await UserStore.open({ dataDir: truncated, keys, warn: quiet });
  for (let i = 0; i < 40; i++) await store.createUser({ name: `user${i}`, passwordHash: await hash() });
  store.close();
  const full = await bytes(truncated);
  await fs.writeFile(path.join(truncated, DB_FILE), full.subarray(0, full.length - 4096 - 100));
  for (const dataDir of [garbage, truncated]) {
    const before = await bytes(dataDir);
    const err = await openUserDb({ dataDir, keys, warn: quiet }).then(() => null, (e) => e);
    assert.ok(err instanceof StoreError, String(err));
    assert.match(err.message, /^users\.db in the data directory cannot be used \(.+\); fix or move it, it was left as it is$/);
    assert.deepEqual(await bytes(dataDir), before);
  }
  const folder = await tmp();
  await fs.mkdir(path.join(folder, DB_FILE));
  await assert.rejects(openUserDb({ dataDir: folder, keys, warn: quiet }), /not a regular file/);
});

test('userdb: a store made by a newer version is refused and left as it is; migrations run one step at a time', async () => {
  const keys = keyring([[1, master()]]);
  const dataDir = await seeded(keys);
  const newer = [...MIGRATIONS, (sql) => sql.exec('ALTER TABLE users ADD COLUMN nickname TEXT')];
  const { db, data } = await openUserDb({ dataDir, keys, warn: quiet, migrations: newer });
  assert.equal(db.userVersion(), 2);
  assert.ok(db.sql.prepare('PRAGMA table_info(users)').all().some((c) => c.name === 'nickname'));
  assert.equal(data.users[0].name, 'bob');
  db.close();
  const before = await bytes(dataDir);
  await assert.rejects(openUserDb({ dataDir, keys, warn: quiet }), (e) => e instanceof StoreError && /made by a newer version \(schema version 2\).*left as it is/.test(e.message));
  assert.deepEqual(await bytes(dataDir), before);
});

test('userdb: users.json is imported once, with the same records; unknown fields are named; it is never written', async () => {
  const { json, code } = await legacyStore();
  const { dataDir, text } = await withJson(json);
  const keys = keyring([[1, master()]]);
  const warnings = [];
  const { db, data, imported } = await openUserDb({ dataDir, keys, warn: (w) => warnings.push(w), now: () => NOW });
  assert.deepEqual(imported, { users: 2, configUsers: 1 });
  assert.deepEqual(warnings, ['users.json: these fields are not kept in users.db and were dropped: future, passkeyHint', JSON_STILL_THERE]);
  const bob = data.users.find((u) => u.name === 'Bob');
  const src = json.users[0];
  const { passkeyHint, recoveryCodes, ...kept } = src;
  assert.ok(passkeyHint && recoveryCodes);
  assert.deepEqual({ ...bob, recoveryCodes: undefined }, { ...kept, recoveryCodes: undefined });
  // The recovery code is kept as an HMAC under key 1 of its SHA-256.
  assert.deepEqual(bob.recoveryCodes, [`k1:${keys.recoveryHash(1, hashRecoveryCode(code))}`]);
  assert.deepEqual(data.users.find((u) => u.name === 'carol'), { name: 'carol', role: 'viewer', passwordHash: json.users[1].passwordHash, created: null, lastLogin: null, totp: null, recoveryCodes: [], credentials: [], devices: [], mustChangePassword: true });
  assert.deepEqual(data.configUsers, [{ ...json.configUsers[0] }]);
  const meta = Object.fromEntries(db.sql.prepare('SELECT key, value FROM meta').all().map((m) => [m.key, m.value]));
  assert.equal(meta.imported_from, STORE_FILE);
  assert.equal(meta.imported_at, time);
  assert.equal(meta.imported_sha256, crypto.createHash('sha256').update(text).digest('hex'));
  db.close();
  // Neither the TOTP secret nor the code's SHA-256 is in the file as it is.
  const disk = await bytes(dataDir);
  assert.equal(disk.includes(Buffer.from(SECRET)), false);
  assert.equal(disk.includes(base32Decode(SECRET)), false);
  assert.equal(disk.includes(Buffer.from(hashRecoveryCode(code), 'hex')), false);
  // The imported code works, once.
  const store = await UserStore.open({ dataDir, keys, warn: quiet });
  assert.equal(store.useRecoveryCode('bob', code).ok, true);
  assert.equal(store.useRecoveryCode('bob', code).ok, false);
  store.close();
  // A second start does not import again, and only says again that users.json is still there.
  const again = await openUserDb({ dataDir, keys, warn: (w) => warnings.push(w) });
  assert.equal(again.imported, null);
  assert.deepEqual(warnings.slice(2), [JSON_STILL_THERE]);
  assert.deepEqual(again.data.users.find((u) => u.name === 'Bob').recoveryCodes, []);
  again.db.close();
  assert.equal(await fs.readFile(path.join(dataDir, STORE_FILE), 'utf8'), text);
});

test('userdb: two starts at once import once', async () => {
  const { json } = await legacyStore();
  const { dataDir } = await withJson(json);
  const keys = keyring([[1, master()]]);
  const opened = await Promise.all([openUserDb({ dataDir, keys, warn: quiet }), openUserDb({ dataDir, keys, warn: quiet })]);
  assert.deepEqual(opened.map((o) => o.imported).filter(Boolean), [{ users: 2, configUsers: 1 }]);
  for (const o of opened) {
    assert.equal(o.data.users.length, 2);
    assert.equal(o.data.configUsers.length, 1);
    o.db.close();
  }
});

test('userdb: a users.json changed after the import, or put there later, is warned about and not read', async () => {
  const { json } = await legacyStore();
  const { dataDir } = await withJson(json);
  const keys = keyring([[1, master()]]);
  (await openUserDb({ dataDir, keys, warn: quiet, now: () => NOW })).db.close();
  await fs.writeFile(path.join(dataDir, STORE_FILE), JSON.stringify({ ...json, users: [] }));
  const warnings = [];
  const { db, data } = await openUserDb({ dataDir, keys, warn: (w) => warnings.push(w) });
  db.close();
  assert.equal(data.users.length, 2);
  assert.deepEqual(warnings, [`warning: users.json changed after it was imported on ${time} and is not read. To import it again, stop the server, move users.db* away and start`, JSON_STILL_THERE]);

  const later = await tmp();
  (await openUserDb({ dataDir: later, keys, warn: quiet })).db.close();
  await fs.writeFile(path.join(later, STORE_FILE), JSON.stringify(json));
  const said = [];
  (await openUserDb({ dataDir: later, keys, warn: (w) => said.push(w) })).db.close();
  assert.match(said[0], /users\.json is in the data directory but is not read/);
});

test('userdb: an import that fails half way leaves an empty store, and the next start imports it whole', async () => {
  const { json } = await legacyStore();
  const { dataDir } = await withJson(json);
  const masters = new Map([[1, master()]]);
  let seals = 0;
  class Failing extends Keyring {
    sealTotp(secret, aad) {
      if (++seals === 2) throw new Error('the process died here');
      return super.sealTotp(secret, aad);
    }
  }
  await assert.rejects(openUserDb({ dataDir, keys: new Failing(masters), warn: quiet }), /died here/);
  const sql = raw(dataDir);
  assert.equal(sql.prepare('PRAGMA user_version').get().user_version, 0);
  assert.deepEqual(sql.prepare(`SELECT name FROM sqlite_schema`).all(), []);
  sql.close();
  const { db, data, imported } = await openUserDb({ dataDir, keys: new Keyring(masters), warn: quiet });
  assert.deepEqual(imported, { users: 2, configUsers: 1 });
  assert.equal(data.users.length, 2);
  db.close();
});

test('userdb: a users.json that cannot be imported, or users without a key, stop the start before anything is made', async () => {
  const { json } = await legacyStore();
  const bad = await withJson({ ...json, users: [{ ...json.users[0], role: 'root' }] });
  await assert.rejects(openUserDb({ dataDir: bad.dataDir, keys: keyring([[1, master()]]), warn: quiet }), (e) => e instanceof StoreError && /^users\.json in the data directory cannot be used: users\[1\]\.role.*it was left as it is$/.test(e.message));
  const good = await withJson(json);
  await assert.rejects(openUserDb({ dataDir: good.dataDir, keys: null, warn: quiet }), (e) => e instanceof StoreError && e.message === NO_KEY);
  for (const { dataDir, text } of [bad, good]) {
    assert.deepEqual(await fs.readdir(dataDir), [STORE_FILE]);
    assert.equal(await fs.readFile(path.join(dataDir, STORE_FILE), 'utf8'), text);
  }
  assert.match(NO_KEY, /USERS_KEY_FILE.*gen-key/);
});

test('userdb: a wrong key, a missing key version, or no key at all stop the start, say which version, and change nothing', async () => {
  const one = master();
  const keys = keyring([[1, one]]);
  const dataDir = await seeded(keys);
  const before = await bytes(dataDir);
  const wrong = master();
  const cases = [
    [keyring([[1, wrong]]), /^key version 1 is not the key the user store was made with/],
    [keyring([[2, master()]]), /^the user store needs key version 1; it is not in USERS_KEY_FILE/],
    [null, new RegExp(`^${NO_KEY.replace(/[().]/g, '\\$&')}$`)],
  ];
  for (const [k, why] of cases) {
    const err = await openUserDb({ dataDir, keys: k, warn: quiet }).then(() => null, (e) => e);
    assert.ok(err instanceof StoreError, String(err));
    assert.match(err.message, why);
    for (const secret of [one, wrong]) {
      assert.equal(err.message.includes(secret.toString('base64url')), false);
      assert.equal(err.message.includes(secret.toString('hex')), false);
    }
    assert.deepEqual(await bytes(dataDir), before);
  }
  // A new version next to the old one is recorded, and the old one still works.
  const both = await openUserDb({ dataDir, keys: keyring([[1, one], [2, master()]]), warn: quiet });
  assert.deepEqual(both.addedKeys, [2]);
  assert.equal(both.data.users[0].totp.enabled, false);
  both.db.close();
});

test('userdb: a damaged or moved TOTP secret, an over-long text and too many users stop the start, naming the row', async () => {
  const keys = keyring([[1, master()]]);
  const cases = [
    [(sql) => {
      const box = Buffer.from(sql.prepare('SELECT totp_box FROM users').get().totp_box);
      box[box.length - 20] ^= 1;
      sql.prepare('UPDATE users SET totp_box = ?').run(box);
    }, /users row 1\.totp does not decrypt with key version 1/],
    ["UPDATE users SET kind = 'config', role = NULL, password_hash = NULL", /configUsers row 1\.totp does not decrypt/],
    [`UPDATE users SET name = '${'b'.repeat(100)}', name_key = '${'b'.repeat(100)}'`, /users row 1\.name is too long/],
    ["UPDATE users SET name = 'Eve'", /users row 1\.name does not match its key/],
    ["UPDATE users SET created = 'yesterday'", /users row 1\.created is not a time/],
    ["INSERT INTO devices (user_id, hash, created, last_used) VALUES (1, 'not hex at all but sixty four characters long xxxxxxxxxxxxxxxxxx', 'x', 'x')", /users row 1\.devices/],
  ];
  for (const [change, why] of cases) {
    const dataDir = await seeded(keys);
    const sql = raw(dataDir);
    if (typeof change === 'function') change(sql);
    else sql.exec(change);
    sql.close();
    const err = await openUserDb({ dataDir, keys, warn: quiet }).then(() => null, (e) => e);
    assert.ok(err instanceof StoreError, `${change}: ${err}`);
    assert.match(err.message, why);
    assert.match(err.message, /it was left as it is/);
    assert.equal(err.message.includes(SECRET), false);
  }
  const dataDir = await seeded(keys);
  await assert.rejects(openUserDb({ dataDir, keys, warn: quiet, maxUsers: 0 }), /more than 0 users/);
});

test('userdb: tx commits, rolls back on a throw, refuses to wait or nest; another writer past the timeout is StoreBusyError', async () => {
  const keys = keyring([[1, master()]]);
  const dataDir = await tmp();
  const { db } = await openUserDb({ dataDir, keys, warn: quiet, timeoutMs: 20 });
  const rec = (name) => ({ name, role: 'viewer', passwordHash: null, created: null, lastLogin: null, totp: null, recoveryCodes: [], credentials: [], devices: [] });
  const r = rec('bob');
  r.passwordHash = await hash();
  assert.throws(() => db.put('store', r), /in a transaction/);
  assert.throws(() => db.tx(() => {
    db.put('store', r);
    throw new Error('changed my mind');
  }), /changed my mind/);
  assert.deepEqual(db.load().users, []);
  assert.throws(() => db.tx(async () => {}), /must not wait/);
  assert.throws(() => db.tx(() => db.tx(() => {})), /already open/);
  db.tx(() => db.put('store', r));
  assert.equal(db.load().users[0].name, 'bob');

  const other = await openUserDb({ dataDir, keys, warn: quiet, timeoutMs: 20 });
  assert.equal(db.changedElsewhere(), false);
  other.db.tx(() => other.db.remove('store', 'bob'));
  assert.equal(db.changedElsewhere(), true);
  assert.deepEqual(db.load().users, []);
  assert.equal(db.changedElsewhere(), false);

  other.db.sql.exec('BEGIN IMMEDIATE');
  const err = (() => {
    try {
      db.tx(() => db.put('store', r));
    } catch (e) {
      return e;
    }
  })();
  other.db.sql.exec('ROLLBACK');
  assert.ok(err instanceof StoreBusyError);
  assert.equal(err.code, 'busy');
  assert.deepEqual(db.load().users, []);
  db.close();
  other.db.close();
  // close twice is fine.
  db.close();
});

test('userdb: limits are refused with StoreFullError and change nothing', async () => {
  const keys = keyring([[1, master()]]);
  const { db } = await openUserDb({ dataDir: await tmp(), keys, warn: quiet, maxUsers: 1 });
  const rec = { name: 'bob', role: 'viewer', passwordHash: await hash(), created: null, lastLogin: null, totp: null, recoveryCodes: [], credentials: [], devices: [] };
  db.tx(() => db.put('store', rec));
  assert.throws(() => db.tx(() => db.put('store', { ...rec, name: 'carol' })), StoreFullError);
  const devices = Array.from({ length: MAX_DEVICES + 1 }, (_, i) => ({ hash: i.toString(16).padStart(64, '0'), created: time, lastUsed: time }));
  assert.throws(() => db.tx(() => db.put('store', { ...rec, devices })), StoreFullError);
  assert.throws(() => db.tx(() => db.put('store', { ...rec, recoveryCodes: Array.from({ length: 21 }, (_, i) => hashRecoveryCode(String(i))) })), StoreFullError);
  // A record that could not be read back is not written either.
  assert.throws(() => db.tx(() => db.put('store', { ...rec, role: 'root' })), StoreError);
  assert.deepEqual(db.load().users.map((u) => [u.name, u.devices.length, u.role]), [['bob', 0, 'viewer']]);
  db.close();
});

test('userdb: rekey seals every TOTP secret with the current key; keyUsage says what each version still protects', async () => {
  const one = master();
  const dataDir = await tmp();
  const store = await UserStore.open({ dataDir, keys: keyring([[1, one]]), warn: quiet, now: () => NOW });
  await store.createUser({ name: 'bob', role: 'admin', passwordHash: await hashPassword('a good password', undefined, fakeHasher, store.currentPepper()) });
  await store.createUser({ name: 'carol', passwordHash: await hash() });
  const secret = await store.beginTotp('bob');
  store.close();
  const two = master();
  const keys = keyring([[1, one], [2, two]]);
  const { db } = await openUserDb({ dataDir, keys, warn: quiet });
  assert.deepEqual([...db.keyUsage()], [[1, { passwords: 1, recoveryCodes: 0, totp: 1 }], [2, { passwords: 0, recoveryCodes: 0, totp: 0 }]]);
  assert.deepEqual(db.rekey(), { totp: 1 });
  assert.deepEqual(db.rekey(), { totp: 0 });
  assert.deepEqual([...db.keyUsage()], [[1, { passwords: 1, recoveryCodes: 0, totp: 0 }], [2, { passwords: 0, recoveryCodes: 0, totp: 1 }]]);
  assert.equal(db.load().users.find((u) => u.name === 'bob').totp.secret, secret);
  db.close();
  // The password still needs version 1.
  await assert.rejects(openUserDb({ dataDir, keys: keyring([[2, two]]), warn: quiet }), /needs key version 1/);
});

test('userdb: a backup is a new 0600 file with every record; an existing file is refused', async () => {
  const keys = keyring([[1, master()]]);
  const dataDir = await seeded(keys);
  const { db, data } = await openUserDb({ dataDir, keys, warn: quiet });
  const dir = await tmp();
  const file = path.join(dir, 'backup.db');
  db.backup(file);
  assert.deepEqual(await fs.readdir(dir), ['backup.db']);
  if (process.platform !== 'win32') assert.equal((await fs.stat(file)).mode & 0o777, 0o600);
  assert.throws(() => db.backup(file), /already exists/);
  db.close();
  const restored = await tmp();
  await fs.copyFile(file, path.join(restored, DB_FILE));
  const again = await openUserDb({ dataDir: restored, keys, warn: quiet });
  assert.deepEqual(again.data, data);
  again.db.close();
});

test('userdb: passkeys of a newer version are kept by other changes and removed with the second factor', async () => {
  const keys = keyring([[1, master()]]);
  const dataDir = await seeded(keys);
  const sql = raw(dataDir);
  sql.prepare("INSERT INTO credentials (user_id, type, cred_id, public_key, name, created, backup_eligible, backed_up, rp_id) VALUES (1, 'passkey', ?, ?, 'phone', ?, 0, 0, 'example.org')").run(Buffer.from('id'), Buffer.from('key'), time);
  sql.close();
  const store = await UserStore.open({ dataDir, keys, warn: quiet });
  assert.equal(store.account('bob').credentials, 1);
  await store.setRole('bob', 'manage', { force: true });
  store.close();
  const again = await UserStore.open({ dataDir, keys, warn: quiet });
  assert.equal(again.account('bob').credentials, 1);
  await again.resetSecondFactor('bob');
  again.close();
  const last = await UserStore.open({ dataDir, keys, warn: quiet });
  assert.equal(last.account('bob').credentials, 0);
  last.close();
});

test('userdb: a link or anything but a file as users.db, users.db-wal or users.db-shm is refused before anything is opened', async () => {
  const keys = keyring([[1, master()]]);
  const target = path.join(await tmp(), 'elsewhere');
  for (const f of [DB_FILE, `${DB_FILE}-wal`, `${DB_FILE}-shm`]) {
    const dataDir = await tmp();
    await fs.symlink(target, path.join(dataDir, f));
    const err = await openUserDb({ dataDir, keys, warn: quiet }).then(() => null, (e) => e);
    assert.ok(err instanceof StoreError, `${f}: ${err}`);
    assert.match(err.message, f === DB_FILE ? /it is a link, not a regular file/ : new RegExp(`${f.replace('.', '\\.')} next to it is a link`));
    await assert.rejects(fs.access(target), `${f}: nothing made through the link`);
    assert.deepEqual(await fs.readdir(dataDir), [f]);
  }
  const dataDir = await seeded(keys);
  await fs.rm(path.join(dataDir, `${DB_FILE}-shm`), { force: true });
  await fs.mkdir(path.join(dataDir, `${DB_FILE}-shm`));
  await assert.rejects(openUserDb({ dataDir, keys, warn: quiet }), /users\.db-shm next to it is not a regular file/);
});

test('userdb: a trigger, view, table, index or column this version does not make is refused at start and on a later read, and the file is left as it is', async () => {
  const keys = keyring([[1, master()]]);
  const cases = [
    ['CREATE TRIGGER backdoor AFTER UPDATE ON users BEGIN UPDATE users SET role = \'admin\'; END', /it has a trigger named backdoor that this version does not make/],
    ['CREATE VIEW v AS SELECT * FROM users', /it has a view named v/],
    ['CREATE TABLE extra (x)', /it has a table named extra/],
    ['CREATE INDEX users_name ON users(name)', /it has an index named users_name/],
    ['ALTER TABLE users ADD COLUMN note TEXT', /its table users is not as this version makes it/],
    ['DROP INDEX credentials_user', /its index credentials_user is missing/],
  ];
  for (const [change, why] of cases) {
    const dataDir = await seeded(keys);
    const sql = raw(dataDir);
    sql.exec(change);
    sql.close();
    const before = await bytes(dataDir);
    const err = await openUserDb({ dataDir, keys, warn: quiet }).then(() => null, (e) => e);
    assert.ok(err instanceof StoreError, `${change}: ${err}`);
    assert.match(err.message, why, change);
    assert.match(err.message, /something other than the website changed it\. Fix or move it; it was left as it is$/);
    assert.deepEqual(await bytes(dataDir), before, change);
  }
  // Checked before anything is written at start: a trigger on keys would otherwise run when the
  // start records a new key version, before the records are read.
  {
    const one = master();
    const dataDir = await seeded(keyring([[1, one]]));
    const sql = raw(dataDir);
    sql.exec(`CREATE TRIGGER planted AFTER INSERT ON keys BEGIN UPDATE users SET role = 'admin'; END`);
    sql.close();
    const before = await bytes(dataDir);
    const err = await openUserDb({ dataDir, keys: keyring([[1, one], [2, master()]]), warn: quiet }).then(() => null, (e) => e);
    assert.match(String(err?.message), /it has a trigger named planted/);
    assert.deepEqual(await bytes(dataDir), before, 'nothing written, the trigger never ran');
  }
  // ANALYZE adds its sqlite_stat tables: they are not part of the schema, and the store still opens.
  {
    const dataDir = await seeded(keys);
    const sql = raw(dataDir);
    sql.exec('ANALYZE');
    assert.ok(sql.prepare("SELECT count(*) AS n FROM sqlite_schema WHERE name LIKE 'sqlite_stat%'").get().n > 0);
    sql.close();
    const ok = await openUserDb({ dataDir, keys, warn: quiet });
    assert.equal(ok.data.users.length, 1);
    ok.db.close();
  }
  // A store at schema version 0 must be empty: a view put in before the first start is refused too.
  const empty = await tmp();
  const sql = raw(empty);
  sql.exec('CREATE VIEW sneaky AS SELECT 1');
  sql.close();
  await assert.rejects(openUserDb({ dataDir: empty, keys, warn: quiet }), /it has a view named sneaky/);

  // While the server runs: the next read refuses it, and the store counts as unreadable.
  const dataDir = await seeded(keys);
  const store = await UserStore.open({ dataDir, keys, warn: quiet });
  const told = [];
  store.onUnreadable = (e) => told.push(e.message);
  const other = raw(dataDir);
  other.exec('CREATE TRIGGER t AFTER INSERT ON users BEGIN SELECT 1; END');
  other.close();
  assert.throws(() => store.refresh(), /it has a trigger named t/);
  assert.equal(told.length, 1);
  assert.ok(store.unreadable instanceof StoreError);
  store.close();
});

test('userdb: a store whose data needs a key version without a check value is refused, and no check value is recorded for it', async () => {
  const one = master();
  const keys = keyring([[1, one]]);
  const dataDir = await seeded(keys);
  const sql = raw(dataDir);
  sql.exec('DELETE FROM keys');
  sql.close();
  const before = await bytes(dataDir);
  // The right key and a wrong one are both refused: neither can be told from the other now.
  for (const k of [keys, keyring([[1, master()]])]) {
    const err = await openUserDb({ dataDir, keys: k, warn: quiet }).then(() => null, (e) => e);
    assert.ok(err instanceof StoreError, String(err));
    assert.match(err.message, /^the user store uses key version 1 but has no check value for it \(its keys table was changed\), so a wrong key cannot be told from the right one\. Restore users\.db from a backup/);
    assert.equal(err.message.includes(one.toString('base64url')), false);
  }
  assert.deepEqual(await bytes(dataDir), before);
  const check = raw(dataDir);
  assert.deepEqual(check.prepare('SELECT * FROM keys').all(), []);
  check.close();

  // Users with nothing that needs a key (unpeppered, no second factor), and the keys table emptied:
  // a wrong key would be recorded as the right one. Refused at start too.
  const plain = await tmp();
  const store = await UserStore.open({ dataDir: plain, keys, warn: quiet });
  await store.createUser({ name: 'carol', role: 'admin', passwordHash: await hash() });
  store.close();
  const wipe = raw(plain);
  wipe.exec('DELETE FROM keys');
  wipe.close();
  const was = await bytes(plain);
  for (const k of [keys, keyring([[1, master()]])]) {
    await assert.rejects(openUserDb({ dataDir: plain, keys: k, warn: quiet }), (e) => e instanceof StoreError && /^the user store has users but no check value for any key version \(its keys table was emptied\)/.test(e.message));
  }
  assert.deepEqual(await bytes(plain), was);
});

test('userdb: users.json as a link, a FIFO or a folder is refused without waiting; dropped fields are named only when they look like field names', async () => {
  const keys = keyring([[1, master()]]);
  const { json } = await legacyStore();
  const linked = await tmp();
  const real = path.join(await tmp(), 'real.json');
  await fs.writeFile(real, JSON.stringify(json));
  await fs.symlink(real, path.join(linked, STORE_FILE));
  await assert.rejects(openUserDb({ dataDir: linked, keys, warn: quiet }), /users\.json in the data directory cannot be used: it is a link, not a regular file/);
  await assert.rejects(fs.access(path.join(linked, DB_FILE)), 'nothing made');
  if (process.platform !== 'win32') {
    const fifo = await tmp();
    const { execFileSync } = await import('node:child_process');
    execFileSync('mkfifo', [path.join(fifo, STORE_FILE)]);
    await assert.rejects(openUserDb({ dataDir: fifo, keys, warn: quiet }), /users\.json in the data directory cannot be used: it is not a regular file/);
  }
  const folder = await tmp();
  await fs.mkdir(path.join(folder, STORE_FILE));
  await assert.rejects(openUserDb({ dataDir: folder, keys, warn: quiet }), /users\.json in the data directory cannot be used: it is not a regular file/);

  const odd = await withJson({ ...json, 'a secret: hunter2': 1, ['x'.repeat(41)]: 2, 'fine_name.2': 3 });
  const warnings = [];
  const { db } = await openUserDb({ dataDir: odd.dataDir, keys, warn: (w) => warnings.push(w) });
  db.close();
  assert.equal(warnings[0], 'users.json: these fields are not kept in users.db and were dropped: fine_name.2, future, passkeyHint, and 2 more whose names are not shown');
  assert.equal(warnings.join('\n').includes('hunter2'), false);
});

test('userdb: users.json imported again into a new users.db, after one was made here before, is warned about loudly', async () => {
  const keys = keyring([[1, master()]]);
  const { json } = await legacyStore();
  const { dataDir } = await withJson(json);
  const first = await openUserDb({ dataDir, keys, warn: quiet, now: () => NOW });
  assert.equal(first.reimported, false);
  first.db.close();
  assert.equal(await fs.readFile(path.join(dataDir, MADE_FILE), 'utf8'), `${time}\nusers ${time}\n`);
  // users.db* moved away (to restore it, say): the old snapshot comes back, and that is said.
  const away = await tmp();
  for (const f of await fs.readdir(dataDir)) if (f.startsWith(DB_FILE)) await fs.rename(path.join(dataDir, f), path.join(away, f));
  const warnings = [];
  const again = await openUserDb({ dataDir, keys, warn: (w) => warnings.push(w) });
  again.db.close();
  assert.deepEqual(again.imported, { users: 2, configUsers: 1 });
  assert.equal(again.reimported, true);
  assert.ok(warnings.some((w) => w.startsWith(`WARNING: users.json was imported into a new users.db, but a user store with users was made in this data directory before on ${time}.`) && /may bring back users that were deleted since, and old passwords and second factors/.test(w) && /reset-password --generate.*reset-2fa/.test(w)), warnings.join('\n'));
});

test('userdb: a first import after a start without users is not a step back, and is not warned about; a store that got users later is', async () => {
  const keys = keyring([[1, master()]]);
  const { json } = await legacyStore();
  // A first start without users, then users.json put in, and the empty store moved away.
  const dataDir = await tmp();
  (await openUserDb({ dataDir, keys, warn: quiet, now: () => NOW })).db.close();
  assert.equal(await fs.readFile(path.join(dataDir, MADE_FILE), 'utf8'), `${time}\n`);
  await fs.writeFile(path.join(dataDir, STORE_FILE), JSON.stringify(json));
  const moveAway = async () => {
    const away = await tmp();
    for (const f of await fs.readdir(dataDir)) if (f.startsWith(DB_FILE)) await fs.rename(path.join(dataDir, f), path.join(away, f));
  };
  await moveAway();
  const warnings = [];
  const first = await openUserDb({ dataDir, keys, warn: (w) => warnings.push(w) });
  first.db.close();
  assert.deepEqual(first.imported, { users: 2, configUsers: 1 });
  assert.equal(first.reimported, false);
  assert.equal(warnings.some((w) => w.startsWith('WARNING')), false, warnings.join('\n'));

  // A store that starts empty and gets its first user while it runs is noted then, at once.
  const later = await tmp();
  const store = await UserStore.open({ dataDir: later, keys, warn: quiet, now: () => NOW });
  assert.equal(await fs.readFile(path.join(later, MADE_FILE), 'utf8'), `${time}\n`);
  await store.createUser({ name: 'bob', role: 'admin', passwordHash: await hash() });
  assert.equal(await fs.readFile(path.join(later, MADE_FILE), 'utf8'), `${time}\nusers ${time}\n`);
  store.close();
  for (const f of await fs.readdir(later)) if (f.startsWith(DB_FILE)) await fs.rm(path.join(later, f));
  await fs.writeFile(path.join(later, STORE_FILE), JSON.stringify(json));
  const again = await openUserDb({ dataDir: later, keys, warn: quiet });
  again.db.close();
  assert.equal(again.reimported, true);
});

test('userdb: a users.db made by an open that then fails is left (another process may have opened it); what can be told first stops the open before it is made', async () => {
  const { json } = await legacyStore();
  const masters = new Map([[1, master()]]);
  class Failing extends Keyring {
    sealTotp() {
      throw new Error('the import failed here');
    }
  }
  const { dataDir, text } = await withJson(json);
  await assert.rejects(openUserDb({ dataDir, keys: new Failing(masters), warn: quiet }), /failed here/);
  assert.ok((await fs.readdir(dataDir)).includes(DB_FILE), 'never removed');
  assert.equal(await fs.readFile(path.join(dataDir, STORE_FILE), 'utf8'), text);
  // Users to import and no key: refused before users.db is made.
  const nokey = await withJson(json);
  await assert.rejects(openUserDb({ dataDir: nokey.dataDir, warn: quiet }), /they need a key/);
  assert.deepEqual(await fs.readdir(nokey.dataDir), [STORE_FILE]);
});

test('userdb: deleted rows are overwritten (secure_delete); a backup is made in a private folder that goes again, and a link as the target is refused', async () => {
  const keys = keyring([[1, master()]]);
  const dataDir = await seeded(keys);
  const { db } = await openUserDb({ dataDir, keys, warn: quiet });
  assert.equal(db.sql.prepare('PRAGMA secure_delete').get().secure_delete, 1);
  const dir = await tmp();
  const elsewhere = path.join(await tmp(), 'through-the-link.db');
  await fs.symlink(elsewhere, path.join(dir, 'link.db'));
  assert.throws(() => db.backup(path.join(dir, 'link.db')), /already exists/);
  await assert.rejects(fs.access(elsewhere), 'nothing written through the link');
  db.backup(path.join(dir, 'b.db'));
  assert.deepEqual((await fs.readdir(dir)).sort(), ['b.db', 'link.db'], 'no temporary folder left');
  assert.equal((await fs.stat(path.join(dir, 'b.db'))).nlink, 1);

  // A folder others can write to, without the sticky bit, is refused; with it (as /tmp), it works.
  if (process.platform !== 'win32') {
    const shared = await tmp();
    await fs.chmod(shared, 0o777);
    assert.throws(() => db.backup(path.join(shared, 'b.db')), (e) => e.code === 'EUNSAFE' && /can be written to by other users; write the backup into a folder only you can write to/.test(e.message));
    assert.deepEqual(await fs.readdir(shared), []);
    await fs.chmod(shared, 0o1777);
    db.backup(path.join(shared, 'b.db'));
    assert.deepEqual(await fs.readdir(shared), ['b.db']);
  }
  // The copy swapped for another file, or opened to others, before it is put in place: refused,
  // and nothing is put there.
  const swaps = [
    (tmp) => {
      fsSync.rmSync(tmp);
      fsSync.writeFileSync(tmp, 'not the backup', { mode: 0o600 });
    },
  ];
  if (process.platform !== 'win32') swaps.push((tmp) => fsSync.chmodSync(tmp, 0o644));
  for (const swap of swaps) {
    const out = await tmp();
    assert.throws(() => db.backup(path.join(out, 'c.db'), { beforeLink: swap }), /the backup copy was changed or replaced before it was put in place/);
    assert.deepEqual(await fs.readdir(out), [], 'nothing put in place, and no folder left');
  }
  db.close();
});
