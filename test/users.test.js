import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { Keyring } from '../lib/keys.js';
import { hashPassword, parsePhc, verifyPassword } from '../lib/password.js';
import {
  LOGIN_WRITE_MS, MAX_DEVICES, MAX_PASSKEYS, MAX_RECOVERY_CODES, RECOVERY_CODES, STORE_FILE, StoreBusyError, StoreError, StoreFullError, UserError, UserStore, hashRecoveryCode, passkeyRef, writeRefusal,
} from '../lib/users.js';
import { DB_FILE, MADE_FILE } from '../lib/userdb.js';
import { base32Decode, hotp, stepAt } from '../lib/totp.js';
import { FAILURES_FILE, createAudit, createFailureLog } from '../lib/audit.js';
import { COOKIE, NO_PEPPER_LOG_MS, createLogin } from '../lib/login.js';
import { fakeHasher } from './helpers/fake-hasher.js';

const NOW = 1_800_000_000_000;
const tmp = () => fs.mkdtemp(path.join(os.tmpdir(), 'users-'));
const hash = (pw = 'a good password') => hashPassword(pw, undefined, fakeHasher);

async function configUser(name, role) {
  return { name, phc: parsePhc(await hash()), ...(role ? { role } : {}) };
}

// One key for every store of these tests; a test that needs others makes its own.
const KEYS = new Keyring(new Map([[1, crypto.randomBytes(32)]]));

// Opens the store of a data directory as the server does; reopen opens it again, as after a restart.
async function open({ dir, configUsers = [], warn = () => {}, clock = { t: NOW }, keys = KEYS, timeoutMs } = {}) {
  const dataDir = dir ?? (await tmp());
  const store = await UserStore.open({ dataDir, configUsers, keys, warn, now: () => clock.t, ...(timeoutMs ? { timeoutMs } : {}) });
  return { store, dataDir, file: path.join(dataDir, DB_FILE), clock };
}
const reopen = (dataDir, opts = {}) => UserStore.open({ dataDir, keys: KEYS, warn: () => {}, ...opts });

// The bytes of the store on disk, the WAL included (where the last changes are until a checkpoint).
const diskBytes = async (dataDir) => Buffer.concat(await Promise.all([DB_FILE, `${DB_FILE}-wal`].map((f) => fs.readFile(path.join(dataDir, f)).catch(() => Buffer.alloc(0)))));

// Holds the store's write lock from another connection, as scripts/users.js would mid-change,
// until the returned function is called.
function holdLock(dataDir) {
  const other = new DatabaseSync(path.join(dataDir, DB_FILE));
  other.exec('BEGIN IMMEDIATE');
  return () => {
    other.exec('ROLLBACK');
    other.close();
  };
}

// A row of the store as it is on disk.
function row(dataDir, name, kind = 'store') {
  const sql = new DatabaseSync(path.join(dataDir, DB_FILE), { readOnly: true });
  try {
    return sql.prepare('SELECT * FROM users WHERE kind = ? AND name_key = ?').get(kind, name.toLowerCase()) ?? null;
  } finally {
    sql.close();
  }
}

const codeAt = (store, name, t, offset = 0) => hotp(base32Decode(store.factorRecord(name).totp.secret), stepAt(t) + offset);

test('store: a new data directory is an empty store in users.db, and no users.json is written', async () => {
  const { store, dataDir } = await open();
  assert.equal(store.hasLocalUsers(), false);
  assert.equal(store.find('nobody'), null);
  await store.createUser({ name: 'bob', passwordHash: await hash() });
  assert.deepEqual((await fs.readdir(dataDir)).sort(), [MADE_FILE, DB_FILE, `${DB_FILE}-shm`, `${DB_FILE}-wal`]);
  store.close();
});

test('store: create, find, set role, set password and delete website users; the files are 0600', async () => {
  const { store, dataDir } = await open();
  await store.createUser({ name: 'Bob', role: 'admin', passwordHash: await hash() });
  await store.createUser({ name: 'carol', passwordHash: await hash() });
  assert.equal(store.hasLocalUsers(), true);
  assert.deepEqual({ ...store.find('  BOB '), phc: undefined }, { name: 'Bob', role: 'admin', source: 'store', phc: undefined, secret: null });
  assert.equal(store.find('carol').role, 'viewer');
  if (process.platform !== 'win32') {
    for (const f of await fs.readdir(dataDir)) assert.equal((await fs.stat(path.join(dataDir, f))).mode & 0o777, 0o600, f);
  }
  await store.setRole('carol', 'manage');
  const newHash = await hash('another password');
  await store.setPassword('carol', newHash);
  const again = await reopen(dataDir);
  assert.equal(again.find('carol').role, 'manage');
  assert.deepEqual(again.find('carol').phc.hash, parsePhc(newHash).hash);
  await again.deleteUser('carol');
  assert.equal(again.find('carol'), null);
  assert.equal((await reopen(dataDir)).find('carol'), null);
  assert.equal(row(dataDir, 'carol'), null);
});

test('store: bad names, bad roles, duplicates in any case and unknown users are refused', async () => {
  const { store } = await open({ configUsers: [await configUser('Alice', 'admin')] });
  const h = await hash();
  const code = async (p) => (await p.then(() => assert.fail('should throw'), (e) => e)).code;
  assert.equal(await code(store.createUser({ name: '-x', passwordHash: h })), 'bad-name');
  assert.equal(await code(store.createUser({ name: 'a'.repeat(33), passwordHash: h })), 'bad-name');
  assert.equal(await code(store.createUser({ name: 'dave', role: 'root', passwordHash: h })), 'bad-role');
  assert.equal(await code(store.createUser({ name: 'ALICE', passwordHash: h })), 'exists');
  await store.createUser({ name: 'dave', passwordHash: h });
  assert.equal(await code(store.createUser({ name: 'Dave', passwordHash: h })), 'exists');
  assert.equal(await code(store.deleteUser('nobody')), 'unknown');
  assert.equal(await code(store.setRole('dave', 'owner')), 'bad-role');
  await assert.rejects(store.createUser({ name: 'erin', passwordHash: 'not a hash' }));
});

test('store: users in the config file cannot be changed or deleted here, but their second factor can be reset', async () => {
  const { store } = await open({ configUsers: [await configUser('Alice', 'admin'), await configUser('Zed')] });
  for (const p of [store.deleteUser('alice'), store.setRole('alice', 'viewer'), store.setPassword('Alice', await hash())]) {
    const err = await p.then(() => null, (e) => e);
    assert.ok(err instanceof UserError);
    assert.equal(err.code, 'config');
  }
  assert.equal(store.find('zed').role, 'viewer');
  assert.equal(store.find('alice').source, 'config');
  await store.beginTotp('Alice');
  await store.enableTotp('Alice', codeAt(store, 'Alice', NOW));
  assert.equal(store.secondFactorEnabled('alice'), true);
  await store.resetSecondFactor('alice');
  assert.equal(store.secondFactorEnabled('alice'), false);
  assert.equal(store.account('alice').totp.recoveryCodesLeft, 0);
});

test('store: the last admin cannot be removed or demoted; config admins count', async () => {
  const { store } = await open();
  await store.createUser({ name: 'root1', role: 'admin', passwordHash: await hash() });
  await store.createUser({ name: 'viewer1', passwordHash: await hash() });
  await assert.rejects(store.deleteUser('root1'), (e) => e.code === 'last-admin');
  await assert.rejects(store.setRole('root1', 'manage'), (e) => e.code === 'last-admin');
  // Non-admins can always go.
  await store.deleteUser('viewer1');
  await store.createUser({ name: 'root2', role: 'admin', passwordHash: await hash() });
  await store.setRole('root1', 'viewer');
  await assert.rejects(store.deleteUser('root2'), (e) => e.code === 'last-admin');
  await store.setRole('root1', 'admin');
  await store.deleteUser('root2');

  // An admin in the config file is an admin too, and cannot be removed here at all.
  const withConfig = (await open({ configUsers: [await configUser('Alice', 'admin')] })).store;
  await withConfig.createUser({ name: 'root', role: 'admin', passwordHash: await hash() });
  await withConfig.deleteUser('root');
  assert.equal(withConfig.admins(), 1);
});

test('store: a name in both the config file and the store is the config one, with a warning', async () => {
  const dataDir = await tmp();
  const first = await reopen(dataDir);
  await first.createUser({ name: 'alice', role: 'admin', passwordHash: await hash('store password') });
  const warnings = [];
  const config = await configUser('Alice', 'viewer');
  const store = await reopen(dataDir, { configUsers: [config], warn: (w) => warnings.push(w) });
  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /"alice" is also in the config file/);
  assert.equal(store.find('alice').source, 'config');
  assert.equal(store.find('alice').role, 'viewer');
  assert.equal(store.hasLocalUsers(), false);
  assert.deepEqual(store.list(), [{ name: 'Alice', role: 'viewer', source: 'config' }]);
});

test('store: a corrupt, unknown or newer users.json stops the import with a message; it is left as it is and no users.db is made', async () => {
  const good = { version: 1, users: [{ name: 'bob', role: 'admin', passwordHash: await hash() }], configUsers: [] };
  const cases = [
    ['{not json', /not valid JSON/],
    ['[]', /not a JSON object/],
    [JSON.stringify({ users: [] }), /no known version/],
    [JSON.stringify({ version: 2, users: [] }), /newer version/],
    [JSON.stringify({ ...good, users: [{ ...good.users[0], role: 'root' }] }), /role/],
    [JSON.stringify({ ...good, users: [{ ...good.users[0], passwordHash: 'x' }] }), /passwordHash/],
    [JSON.stringify({ ...good, users: [good.users[0], { ...good.users[0], name: 'BOB' }] }), /listed twice/],
    [JSON.stringify({ ...good, users: [{ ...good.users[0], totp: { secret: '!!', enabled: true, lastUsedStep: null } }] }), /totp.secret/],
    [JSON.stringify({ ...good, users: [{ ...good.users[0], totp: { secret: 'JBSWY3DPEHPK3PXP', enabled: 'yes', lastUsedStep: null } }] }), /enabled/],
    [JSON.stringify({ ...good, users: [{ ...good.users[0], recoveryCodes: ['abc'] }] }), /recoveryCodes/],
    [JSON.stringify({ ...good, users: [{ ...good.users[0], credentials: [{}] }] }), /credentials/],
    [JSON.stringify({ ...good, users: [{ ...good.users[0], mustChangePassword: 'yes' }] }), /mustChangePassword/],
    [JSON.stringify({ ...good, users: [{ ...good.users[0], devices: [{ hash: 'abc', created: '2027-01-01T00:00:00.000Z', lastUsed: '2027-01-01T00:00:00.000Z' }] }] }), /devices/],
    [JSON.stringify({ ...good, users: [{ ...good.users[0], devices: Array.from({ length: 11 }, () => ({ hash: 'a'.repeat(64), created: '2027-01-01T00:00:00.000Z', lastUsed: '2027-01-01T00:00:00.000Z' })) }] }), /devices/],
    [JSON.stringify({ ...good, configUsers: [{ name: 'alice', devices: [{ hash: 'a'.repeat(64), created: 'yesterday', lastUsed: '2027-01-01T00:00:00.000Z' }] }] }), /devices/],
    [JSON.stringify({ ...good, configUsers: [{ name: '../x' }] }), /name/],
  ];
  for (const [text, why] of cases) {
    const dataDir = await tmp();
    const file = path.join(dataDir, STORE_FILE);
    await fs.writeFile(file, text);
    const err = await reopen(dataDir).then(() => null, (e) => e);
    assert.ok(err instanceof StoreError, text);
    assert.match(err.message, why, text);
    assert.match(err.message, /^users\.json in the data directory cannot be used: .*left as it is$/);
    // The message never repeats a hash or secret.
    assert.equal(err.message.includes(good.users[0].passwordHash), false);
    assert.equal(err.message.includes('JBSWY3DP'), false);
    assert.equal(await fs.readFile(file, 'utf8'), text);
    assert.deepEqual(await fs.readdir(dataDir), [STORE_FILE]);
  }
  // A folder in its place is refused too.
  const dataDir = await tmp();
  await fs.mkdir(path.join(dataDir, STORE_FILE));
  await assert.rejects(reopen(dataDir), StoreError);
});

test('store: a file others can read is warned about', { skip: process.platform === 'win32' }, async () => {
  const { store, dataDir, file } = await open();
  store.close();
  await fs.chmod(file, 0o644);
  const warnings = [];
  await reopen(dataDir, { warn: (w) => warnings.push(w) });
  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /chmod 600/);
});

test('store: TOTP set up, turn on with the first code, codes work once, and secrets stay out of account()', async () => {
  const clock = { t: NOW };
  const { store, dataDir } = await open({ clock });
  await store.createUser({ name: 'bob', passwordHash: await hash() });
  const secret = await store.beginTotp('bob');
  assert.equal(base32Decode(secret).length, 20);
  assert.equal(store.secondFactorEnabled('bob'), false);
  // A second set up before it is on gives a new secret.
  const secret2 = await store.beginTotp('bob');
  assert.notEqual(secret2, secret);
  assert.equal(await store.enableTotp('bob', '000000'), null);
  const codes = await store.enableTotp('bob', codeAt(store, 'bob', NOW));
  assert.equal(codes.length, RECOVERY_CODES);
  assert.equal(new Set(codes).size, RECOVERY_CODES);
  for (const c of codes) assert.match(c, /^[a-z2-7]{4}(-[a-z2-7]{4}){3}$/);
  await assert.rejects(store.beginTotp('bob'), (e) => e.code === 'exists');
  // The code used to turn it on cannot sign in.
  assert.equal(store.checkTotp('bob', codeAt(store, 'bob', NOW)).ok, false);
  clock.t += 30_000;
  const next = codeAt(store, 'bob', clock.t);
  const r = store.checkTotp('bob', next);
  assert.equal(r.ok, true);
  await r.saved;
  assert.equal(store.checkTotp('bob', next).ok, false);
  // The used step survives a restart.
  const again = await reopen(dataDir, { now: () => clock.t });
  assert.equal(again.checkTotp('bob', next).ok, false);
  const text = JSON.stringify(store.account('bob'));
  assert.equal(text.includes(secret2), false);
  for (const c of codes) assert.equal(text.includes(c), false);
  assert.deepEqual(store.account('bob').totp, { enabled: true, recoveryCodesLeft: RECOVERY_CODES });
  // On disk: the secret only encrypted, the recovery codes only as an HMAC, never as their SHA-256.
  const disk = await diskBytes(dataDir);
  for (const s of [Buffer.from(secret2), base32Decode(secret2)]) assert.equal(disk.includes(s), false);
  for (const c of codes) {
    for (const s of [Buffer.from(c), Buffer.from(hashRecoveryCode(c), 'hex'), Buffer.from(hashRecoveryCode(c))]) assert.equal(disk.includes(s), false);
  }
  assert.equal(Buffer.from(row(dataDir, 'bob').totp_box)[0], 1, 'a sealed box');
});

test('store: recovery codes work once each, in any case and with or without dashes; new ones replace the old', async () => {
  const { store } = await open();
  await store.createUser({ name: 'bob', passwordHash: await hash() });
  await store.beginTotp('bob');
  const codes = await store.enableTotp('bob', codeAt(store, 'bob', NOW));
  const r = store.useRecoveryCode('bob', ` ${codes[3].toUpperCase().replace(/-/g, ' ')} `);
  assert.equal(r.ok, true);
  assert.equal(r.left, RECOVERY_CODES - 1);
  await r.saved;
  assert.equal(store.useRecoveryCode('bob', codes[3]).ok, false);
  assert.equal(store.useRecoveryCode('bob', 'aaaa-bbbb-cccc-dddd').ok, false);
  assert.equal(store.useRecoveryCode('bob', '').ok, false);
  assert.equal(store.useRecoveryCode('nobody', codes[0]).ok, false);
  const fresh = await store.newRecoveryCodes('bob');
  assert.equal(store.useRecoveryCode('bob', codes[0]).ok, false);
  assert.equal(store.useRecoveryCode('bob', fresh[0]).ok, true);
  await store.disableTotp('bob');
  assert.equal(store.useRecoveryCode('bob', fresh[1]).ok, false);
  await assert.rejects(store.newRecoveryCodes('bob'), UserError);
});

test('store: a config user gets a second-factor record of its own, and a sign in time only with one', async () => {
  const clock = { t: NOW };
  const { store, dataDir } = await open({ configUsers: [await configUser('Alice', 'admin')], clock });
  await store.recordLogin('alice');
  assert.equal(row(dataDir, 'alice', 'config'), null);
  await store.beginTotp('alice');
  clock.t += 60_000;
  await store.recordLogin('alice');
  assert.equal(row(dataDir, 'alice'), null);
  const r = row(dataDir, 'alice', 'config');
  assert.equal(r.name, 'Alice');
  assert.equal(r.last_login, new Date(NOW + 60_000).toISOString());
  assert.equal(r.role, null);
  assert.equal(r.password_hash, null);
  const again = await reopen(dataDir, { configUsers: [await configUser('Alice', 'admin')] });
  assert.equal(again.totpPending('alice'), true);
  assert.equal(again.find('alice').source, 'config');
});

test('store: a write held up past the timeout is StoreBusyError with a message, and the next write still works', async () => {
  const { store, dataDir } = await open({ timeoutMs: 20 });
  await store.createUser({ name: 'bob', passwordHash: await hash() });
  const release = holdLock(dataDir);
  const err = await store.setRole('bob', 'manage').then(() => null, (e) => e);
  release();
  assert.ok(err instanceof StoreBusyError);
  assert.equal(writeRefusal(err), 'Another program is changing the user store; nothing was changed. Try again.');
  assert.equal(store.find('bob').role, 'viewer');
  await store.setRole('bob', 'admin');
  assert.equal((await reopen(dataDir)).find('bob').role, 'admin');
});

test('audit: one JSON line per event, appended, mode 0600, and a failed write does not throw', async () => {
  const dataDir = await tmp();
  const audit = createAudit({ dataDir, now: () => NOW });
  await audit.write('totp-enabled', { user: 'bob', address: '192.0.2.1' });
  await audit.write('password-changed', { user: 'bob' });
  const lines = (await fs.readFile(audit.file, 'utf8')).trim().split('\n').map((l) => JSON.parse(l));
  assert.deepEqual(lines, [
    { time: new Date(NOW).toISOString(), event: 'totp-enabled', user: 'bob', address: '192.0.2.1' },
    { time: new Date(NOW).toISOString(), event: 'password-changed', user: 'bob' },
  ]);
  if (process.platform !== 'win32') {
    assert.equal((await fs.stat(audit.file)).mode & 0o777, 0o600);
    await fs.chmod(audit.file, 0o644);
    await audit.write('x');
    assert.equal((await fs.stat(audit.file)).mode & 0o777, 0o600);
  }
  const logged = [];
  const broken = createAudit({ dataDir: path.join(audit.file, 'nope'), log: (m) => logged.push(m) });
  await broken.write('x');
  assert.equal(logged.length, 1);
});

test('config: users may have a role (admin, manage or viewer; viewer when left out), nothing else', async () => {
  const { loadConfig } = await import('../lib/config.js');
  const h = await hash();
  const cfg = (extra) => `users:\n  - name: alice\n    password_hash: '${h}'\n${extra}nodes:\n  - address: a.test:1\n`;
  assert.equal(loadConfig(cfg('')).users[0].role, 'viewer');
  for (const role of ['admin', 'manage', 'viewer']) assert.equal(loadConfig(cfg(`    role: ${role}\n`)).users[0].role, role);
  for (const bad of ['root', 'Admin', 'true', '1', '[admin]', '~', "''"]) {
    assert.throws(() => loadConfig(cfg(`    role: ${bad}\n`)), /role must be one of admin, manage, viewer/, bad);
  }
});

test('server: a corrupt users.json stops the start with a clear message and is left as it is', async () => {
  const { spawn } = await import('node:child_process');
  const { fileURLToPath } = await import('node:url');
  const dataDir = await tmp();
  const file = path.join(dataDir, STORE_FILE);
  await fs.writeFile(file, '{"version": 1, "users": [oops');
  const server = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'server.js');
  const child = spawn(process.execPath, [server], { env: { PATH: process.env.PATH, DATA_DIR: dataDir, PORT: '1', HOST: '127.0.0.1' }, stdio: ['ignore', 'pipe', 'pipe'] });
  let err = '';
  child.stderr.on('data', (c) => (err += c));
  const timer = setTimeout(() => child.kill(), 10_000);
  const code = await new Promise((resolve) => child.on('exit', resolve));
  clearTimeout(timer);
  assert.equal(code, 1);
  assert.match(err, /cannot start: users\.json in the data directory cannot be used: it is not valid JSON\. Fix or move it; it was left as it is/);
  assert.doesNotMatch(err, /\n\s+at /, 'no stack trace');
  assert.equal(await fs.readFile(file, 'utf8'), '{"version": 1, "users": [oops');
});

test('store: a change whose write fails (another program holds the store past the timeout) is not made in memory either', async () => {
  const clock = { t: NOW };
  const { store, dataDir } = await open({ clock, configUsers: [await configUser('Alice', 'admin')], timeoutMs: 20 });
  await store.createUser({ name: 'bob', role: 'admin', passwordHash: await hash() });
  await store.createUser({ name: 'carol', passwordHash: await hash() });
  const busy = (e) => e instanceof StoreBusyError;
  let release = holdLock(dataDir);
  // Password, role, delete and create: all refused, nothing changed.
  const oldHash = store.find('bob').phc.hash;
  await assert.rejects(store.setPassword('bob', await hash('a new password')), busy);
  assert.deepEqual(store.find('bob').phc.hash, oldHash);
  await assert.rejects(store.setRole('carol', 'manage'), busy);
  assert.equal(store.find('carol').role, 'viewer');
  await assert.rejects(store.deleteUser('carol'), busy);
  assert.ok(store.find('carol'));
  await assert.rejects(store.createUser({ name: 'dave', passwordHash: await hash() }), busy);
  assert.equal(store.find('dave'), null);
  // Second factor: a set up of a config user leaves no record behind.
  await assert.rejects(store.beginTotp('alice'), busy);
  assert.equal(store.factorRecord('alice'), null);
  release();
  await store.beginTotp('bob');
  const secret = store.factorRecord('bob').totp.secret;
  release = holdLock(dataDir);
  await assert.rejects(store.enableTotp('bob', codeAt(store, 'bob', NOW)), busy);
  assert.equal(store.secondFactorEnabled('bob'), false);
  assert.deepEqual(store.factorRecord('bob').recoveryCodes, []);
  release();
  const codes = await store.enableTotp('bob', codeAt(store, 'bob', NOW));
  assert.equal(store.factorRecord('bob').totp.secret, secret);
  release = holdLock(dataDir);
  const hashes = [...store.factorRecord('bob').recoveryCodes];
  await assert.rejects(store.newRecoveryCodes('bob'), busy);
  assert.deepEqual(store.factorRecord('bob').recoveryCodes, hashes);
  await assert.rejects(store.disableTotp('bob'), busy);
  assert.equal(store.secondFactorEnabled('bob'), true);
  await assert.rejects(store.resetSecondFactor('bob'), busy);
  assert.equal(store.secondFactorEnabled('bob'), true);
  const rehash = await hash();
  assert.throws(() => store.upgradePassword('bob', store.find('bob').phc, rehash), busy);
  assert.deepEqual(store.find('bob').phc.hash, oldHash);
  // A change made in memory first stays made when its write fails: a used code stays used.
  const used = store.useRecoveryCode('bob', codes[1]);
  assert.equal(used.ok, true);
  await assert.rejects(used.saved, busy);
  assert.equal(store.useRecoveryCode('bob', codes[1]).ok, false);
  const dropped = store.dropDevices('bob');
  assert.equal(dropped.removed, 0);
  release();
  // What is in memory is what is on disk, but for the code whose write failed.
  const again = await reopen(dataDir, { configUsers: [await configUser('Alice', 'admin')] });
  assert.equal(again.secondFactorEnabled('bob'), true);
  assert.equal(again.useRecoveryCode('bob', codes[0]).ok, true);
  assert.equal(again.find('carol').role, 'viewer');
  assert.equal(again.find('dave'), null);
});

test('store: two changes at once to different users are both kept on disk', async () => {
  const { store, dataDir } = await open();
  await store.createUser({ name: 'bob', passwordHash: await hash() });
  await store.createUser({ name: 'carol', passwordHash: await hash() });
  await Promise.all([store.setRole('bob', 'manage'), store.setRole('carol', 'admin'), store.beginTotp('bob')]);
  const again = await reopen(dataDir);
  assert.equal(again.find('bob').role, 'manage');
  assert.equal(again.find('carol').role, 'admin');
  assert.equal(again.totpPending('bob'), true);
  assert.equal(again.totpPending('carol'), false);
});

test('store: lookup gives name, role, source and whether the password must change, without the hash', async () => {
  const { store } = await open({ configUsers: [await configUser('Alice', 'admin')] });
  await store.createUser({ name: 'bob', role: 'manage', passwordHash: await hash() });
  assert.deepEqual(store.lookup('ALICE'), { name: 'Alice', role: 'admin', source: 'config', mustChangePassword: false });
  assert.deepEqual(store.lookup('bob'), { name: 'bob', role: 'manage', source: 'store', mustChangePassword: false });
  assert.equal(store.lookup('nobody'), null);
});

test('audit: the log is rotated at its size limit, keeps 3 files in all, each 0600', async () => {
  const dataDir = await tmp();
  const audit = createAudit({ dataDir, now: () => NOW, maxBytes: 300 });
  for (let i = 0; i < 40; i++) await audit.write('sessions-ended', { user: 'bob', n: i, address: '192.0.2.1' });
  const files = (await fs.readdir(dataDir)).sort();
  assert.deepEqual(files, ['audit.log', 'audit.log.1', 'audit.log.2']);
  let total = 0;
  for (const f of files) {
    const st = await fs.stat(path.join(dataDir, f));
    assert.ok(st.size <= 300, `${f}: ${st.size}`);
    total += st.size;
    if (process.platform !== 'win32') assert.equal(st.mode & 0o777, 0o600, f);
  }
  assert.ok(total <= 900);
  // The newest line is in audit.log, the ones before it in audit.log.1, whole lines only.
  const last = (await fs.readFile(audit.file, 'utf8')).trim().split('\n').map((l) => JSON.parse(l));
  assert.equal(last.at(-1).n, 39);
  const prev = (await fs.readFile(`${audit.file}.1`, 'utf8')).trim().split('\n').map((l) => JSON.parse(l));
  assert.equal(prev.at(-1).n, last[0].n - 1);
});

test('config: users only in users.json allow login settings and require_login, and lock every section by default', async () => {
  const { loadConfig, loadNodes } = await import('../lib/config.js');
  const { ALL_SECTIONS: SECTIONS } = await import('../lib/access.js');
  const text = "login:\n  trusted_proxies: ['127.0.0.1']\n  max_sessions: 50\nnodes:\n  - address: a.test:1\n";
  assert.throws(() => loadConfig(text), /"login" needs "users"/);
  const c = loadConfig(text, { storeUsers: true });
  assert.deepEqual(c.login.trustedProxies, ['127.0.0.1']);
  assert.equal(c.login.maxSessions, 50);
  assert.deepEqual(c.users, []);
  assert.deepEqual(c.defaults.requireLogin, [...SECTIONS]);
  assert.deepEqual(c.nodes.get('a.test:1').requireLogin, [...SECTIONS]);
  // An explicit rule, at the top and on a node, works too.
  const rule = loadConfig('require_login: [disk]\nnodes:\n  - address: a.test:1\n    require_login: [peers]\n', { storeUsers: true });
  assert.deepEqual(rule.defaults.requireLogin, ['disk']);
  assert.deepEqual(rule.nodes.get('a.test:1').requireLogin, ['peers']);
  assert.throws(() => loadConfig('require_login: [disk]\nnodes:\n  - address: a.test:1\n'), /require_login needs "users"/);
  // Without a config file, store users lock every section too.
  assert.deepEqual((await loadNodes({}, { storeUsers: true })).defaults.requireLogin, [...SECTIONS]);
  assert.deepEqual((await loadNodes({})).defaults.requireLogin, []);
});

test('server: with users only in the user store, a config with login settings starts and every section is locked', async () => {
  const { spawn } = await import('node:child_process');
  const { fileURLToPath } = await import('node:url');
  const net = await import('node:net');
  const { ALL_SECTIONS: SECTIONS } = await import('../lib/access.js');
  const dataDir = await tmp();
  const key = crypto.randomBytes(32).toString('base64url');
  const seed = await UserStore.open({ dataDir, keys: new Keyring(new Map([[1, Buffer.from(key, 'base64url')]])), warn: () => {} });
  await seed.createUser({ name: 'bob', role: 'admin', passwordHash: await hashPassword('a good password', undefined, undefined, seed.currentPepper()) });
  seed.close();
  const config = path.join(dataDir, 'config.yaml');
  await fs.writeFile(config, "login:\n  trusted_proxies: ['127.0.0.1']\nnodes:\n  - address: 127.0.0.1:9\n");
  const port = await new Promise((resolve) => {
    const probe = net.createServer().listen(0, '127.0.0.1', () => {
      const p = probe.address().port;
      probe.close(() => resolve(p));
    });
  });
  const server = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'server.js');
  const child = spawn(process.execPath, [server], { env: { PATH: process.env.PATH, DATA_DIR: dataDir, CONFIG_FILE: config, PORT: String(port), HOST: '127.0.0.1', USERS_KEY: `1:${key}` }, stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '';
  let err = '';
  child.stdout.on('data', (c) => (out += c));
  child.stderr.on('data', (c) => (err += c));
  try {
    for (let i = 0; i < 100 && !/listening on/.test(out); i++) {
      if (child.exitCode !== null) break;
      await new Promise((r) => setTimeout(r, 50));
    }
    assert.match(out, /listening on/, err);
    const status = await (await fetch(`http://127.0.0.1:${port}/api/status`)).json();
    assert.deepEqual(status.hosts[0].locked.sort(), [...SECTIONS].sort());
    assert.deepEqual(await (await fetch(`http://127.0.0.1:${port}/api/session`)).json(), { enabled: true, name: null });
  } finally {
    child.kill();
    await new Promise((resolve) => (child.exitCode !== null ? resolve() : child.on('exit', resolve)));
  }
});

test('store: devices are kept by hash, in memory at once, at most ten, and survive a change written meanwhile', async () => {
  const { store, dataDir, clock } = await open({ configUsers: [await configUser('alice')] });
  await store.createUser({ name: 'bob', passwordHash: await hash() });
  const h = (c) => c.repeat(64);
  assert.equal(store.hasDevice('bob', h('a')), false);
  // Not a hash, or an unknown user: nothing.
  await store.addDevice('bob', 'nope');
  await store.addDevice('nobody', h('a'));
  assert.deepEqual(store.devices('bob'), []);
  for (let i = 0; i < MAX_DEVICES + 1; i++) {
    clock.t += 1000;
    await store.addDevice('bob', i.toString(16).repeat(64));
  }
  assert.equal(store.devices('bob').length, MAX_DEVICES);
  assert.equal(store.hasDevice('bob', h('0')), false, 'the least recently used went');
  // A config user gets a record of its own for them.
  await store.addDevice('alice', h('f'));
  assert.equal(store.hasDevice('ALICE', h('f')), true);
  // A device dropped while another change is being written stays dropped.
  const change = store.setRole('bob', 'manage');
  const { removed } = store.dropDevices('bob', { keep: h('a') });
  assert.equal(removed, MAX_DEVICES - 1);
  await change;
  assert.deepEqual(store.devices('bob').map((d) => d.hash), [h('a')]);
  const again = await reopen(dataDir, { configUsers: [await configUser('alice')] });
  assert.deepEqual(again.devices('bob').map((d) => d.hash), [h('a')]);
  assert.equal(again.hasDevice('alice', h('f')), true);
  assert.deepEqual(store.dropDevices('bob', { only: h('a') }).removed, 1);
  assert.deepEqual(store.dropDevices('nobody').removed, 0);
});

test('store: a guard that says no refuses the change with UserError gone, and nothing is written', async () => {
  const { store, dataDir } = await open();
  await store.createUser({ name: 'bob', passwordHash: await hash() });
  const before = row(dataDir, 'bob');
  await assert.rejects(store.setPassword('bob', await hash('another one'), { guard: () => false }), (e) => e instanceof UserError && e.code === 'gone');
  await assert.rejects(store.beginTotp('bob', { guard: () => false }), (e) => e.code === 'gone');
  assert.deepEqual(row(dataDir, 'bob'), before);
  assert.equal(store.factorRecord('bob').totp, null);
});

test('failures log: one line per key and period, with the count and the addresses; security events stay in audit.log', async () => {
  const dataDir = await tmp();
  let t = NOW;
  const f = createFailureLog({ dataDir, now: () => t, periodMs: 60_000 });
  const audit = createAudit({ dataDir, now: () => t });
  await audit.write('password-changed', { user: 'bob' });
  for (let i = 0; i < 500; i++) f.note('password-failures', 'user:bob', { user: 'bob', address: `192.0.2.${i % 3}` });
  f.note('second-factor-failures', 'user:bob', { user: 'bob', address: '192.0.2.9' });
  assert.equal(f.size, 2);
  // Nothing is written until the period is over.
  await f.flushDue();
  assert.equal(await fs.readFile(f.file, 'utf8').catch(() => ''), '');
  t += 60_000;
  // The next note writes the summaries that are due, and starts a new one.
  f.note('password-failures', 'user:bob', { user: 'bob', address: '198.51.100.1' });
  await f.flushDue();
  let lines = (await fs.readFile(f.file, 'utf8')).trim().split('\n').map((l) => JSON.parse(l));
  assert.deepEqual(lines.map((l) => [l.event, l.user, l.failures, l.addresses, l.lastAddress]), [['password-failures', 'bob', 500, 3, '192.0.2.1'], ['second-factor-failures', 'bob', 1, 1, '192.0.2.9']]);
  assert.equal(lines[0].from, new Date(NOW).toISOString());
  await f.flush();
  lines = (await fs.readFile(f.file, 'utf8')).trim().split('\n');
  assert.equal(lines.length, 3);
  assert.equal(f.size, 0);
  // audit.log has the security event only.
  assert.deepEqual((await fs.readFile(audit.file, 'utf8')).trim().split('\n').map((l) => JSON.parse(l).event), ['password-changed']);
  assert.equal(path.basename(f.file), FAILURES_FILE);
  if (process.platform !== 'win32') assert.equal((await fs.stat(f.file)).mode & 0o777, 0o600);
});

test('failures log: bounded in keys (the oldest summary is written early) and rotated like audit.log', async () => {
  const dataDir = await tmp();
  const f = createFailureLog({ dataDir, now: () => NOW, maxKeys: 3, maxBytes: 600 });
  for (let i = 0; i < 40; i++) f.note('password-failures', `user:u${i}`, { user: `u${i}`, address: '192.0.2.1' });
  assert.equal(f.size, 3);
  await f.flush();
  const files = (await fs.readdir(dataDir)).sort();
  assert.deepEqual(files, ['failures.log', 'failures.log.1', 'failures.log.2']);
  const last = (await fs.readFile(f.file, 'utf8')).trim().split('\n').map((l) => JSON.parse(l));
  assert.equal(last.at(-1).user, 'u39');
  // start() and stop() run the timer without keeping the process alive.
  f.start();
  f.start();
  f.stop();
  f.stop();
});

test('store: every write is done when its call returns, so flush has nothing to wait for; touchLogin writes at most once a minute', async () => {
  const { store, dataDir, clock } = await open();
  await store.createUser({ name: 'alice', passwordHash: await hash() });
  let writes = 0;
  const put = store.db.put.bind(store.db);
  store.db.put = (...args) => (writes++, put(...args));
  store.touchLogin('alice');
  store.touchLogin('alice');
  assert.equal(writes, 1);
  await store.flush();
  assert.equal(row(dataDir, 'alice').last_login, new Date(clock.t).toISOString());
  clock.t += 59_000;
  store.touchLogin('alice');
  assert.equal(writes, 1);
  assert.equal(store.account('alice').lastLogin, new Date(clock.t).toISOString(), 'in memory at once');
  clock.t += 1000;
  store.touchLogin('alice');
  assert.equal(writes, 2);
  store.addDevice('alice', 'a'.repeat(64));
  assert.equal((await reopen(dataDir)).devices('alice').length, 1);
  assert.equal(await store.touchLogin('nobody'), undefined);
});

test('audit: flush resolves once every line asked for is written', async () => {
  const dataDir = await tmp();
  const audit = createAudit({ dataDir, now: () => NOW });
  for (let i = 0; i < 5; i++) audit.write('sessions-ended', { user: 'alice', ended: i });
  await audit.flush();
  const lines = (await fs.readFile(audit.file, 'utf8')).trim().split('\n');
  assert.equal(lines.length, 5);
  assert.equal(JSON.parse(lines[4]).ended, 4);
});

test('store: a password set by an admin must be changed; the flag is kept on disk only while it is set', async () => {
  const { store, dataDir } = await open();
  await store.createUser({ name: 'bob', passwordHash: await hash(), mustChangePassword: true });
  await store.createUser({ name: 'carol', passwordHash: await hash() });
  assert.equal(store.lookup('bob').mustChangePassword, true);
  assert.equal(store.lookup('carol').mustChangePassword, false);
  assert.equal(row(dataDir, 'bob').must_change_password, 1);
  assert.equal(row(dataDir, 'carol').must_change_password, 0);
  // Read back, the record has the flag only while it is set, as users.json had it.
  const again = await reopen(dataDir);
  assert.equal(again.factorRecord('bob').mustChangePassword, true);
  assert.equal(Object.hasOwn(again.factorRecord('carol'), 'mustChangePassword'), false);
  assert.equal(again.lookup('bob').mustChangePassword, true);
  // Their own new password clears it; an admin's reset sets it again.
  await again.setPassword('bob', await hash('bobs own password'));
  assert.equal(again.lookup('bob').mustChangePassword, false);
  assert.equal(row(dataDir, 'bob').must_change_password, 0);
  await again.setPassword('carol', await hash(), { mustChangePassword: true });
  assert.equal(again.lookup('carol').mustChangePassword, true);
});

test('store: the overview lists every user by name with what the users page shows, and no secret', async () => {
  const { store } = await open({ configUsers: [await configUser('Zed', 'admin')] });
  await store.createUser({ name: 'bob', role: 'manage', passwordHash: await hash(), mustChangePassword: true });
  await store.createUser({ name: 'Anna', passwordHash: await hash() });
  await store.addDevice('bob', 'a'.repeat(64));
  const list = store.overview();
  assert.deepEqual(list.map((u) => u.name), ['Anna', 'bob', 'Zed']);
  assert.deepEqual(list[1], { name: 'bob', role: 'manage', source: 'store', secondFactor: false, totp: false, passkeys: 0, devices: 1, lastLogin: null, created: new Date(NOW).toISOString(), mustChangePassword: true });
  assert.deepEqual(list[2], { name: 'Zed', role: 'admin', source: 'config', secondFactor: false, totp: false, passkeys: 0, devices: 0, lastLogin: null, created: null, mustChangePassword: false });
  assert.doesNotMatch(JSON.stringify(list), /argon2|[0-9a-f]{64}/);
  assert.equal(store.wouldLeaveNoAdmin('Zed'), true);
  assert.equal(store.wouldLeaveNoAdmin('Zed', 'admin'), false);
  assert.equal(store.wouldLeaveNoAdmin('bob'), false);
});

test('store: the last admin goes only with force; a guard that says no changes nothing', async () => {
  const { store } = await open();
  await store.createUser({ name: 'root', role: 'admin', passwordHash: await hash() });
  await store.createUser({ name: 'bob', passwordHash: await hash() });
  await assert.rejects(store.setRole('root', 'viewer'), (e) => e.code === 'last-admin');
  for (const p of [store.deleteUser('bob', { guard: () => false }), store.setRole('bob', 'admin', { guard: () => false }), store.resetSecondFactor('bob', { guard: () => false }), store.createUser({ name: 'x', passwordHash: await hash() }, { guard: () => false })]) {
    await assert.rejects(p, (e) => e instanceof UserError && e.code === 'gone');
  }
  assert.equal(store.lookup('bob').role, 'viewer');
  assert.equal(store.lookup('x'), null);
  await store.setRole('root', 'viewer', { force: true });
  assert.equal(store.admins(), 0);
  await store.setRole('root', 'admin');
  await store.deleteUser('root', { force: true });
  assert.equal(store.lookup('root'), null);
});

test('store: filled to the cap with every field at its most, it is written and read back; more is refused and changes nothing', async () => {
  const maxUsers = 4;
  const clock = { t: NOW };
  const dataDir = await tmp();
  const configUsers = [await configUser('Alice', 'admin'), await configUser('Carol', 'viewer')];
  const store = await UserStore.open({ dataDir, configUsers, keys: KEYS, warn: () => {}, now: () => clock.t, maxUsers });
  await store.createUser({ name: 'b'.repeat(32), role: 'manage', passwordHash: await hash(), mustChangePassword: true });
  await store.createUser({ name: 'd'.repeat(32), role: 'manage', passwordHash: await hash(), mustChangePassword: true });
  for (const name of ['b'.repeat(32), 'd'.repeat(32), 'alice', 'carol']) {
    await store.beginTotp(name);
    await store.enableTotp(name, codeAt(store, name, clock.t));
    for (let i = 0; i < MAX_DEVICES + 3; i++) await store.addDevice(name, crypto.createHash('sha256').update(`${name}${i}`).digest('hex'));
    await store.recordLogin(name);
  }
  await assert.rejects(store.createUser({ name: 'eve', passwordHash: await hash() }), (e) => e instanceof UserError && e.code === 'full');
  const again = await UserStore.open({ dataDir, configUsers, keys: KEYS, warn: () => {}, maxUsers });
  assert.equal(again.devices('alice').length, MAX_DEVICES);
  assert.equal(again.secondFactorEnabled('d'.repeat(32)), true);
  assert.equal(again.account('carol').totp.recoveryCodesLeft, RECOVERY_CODES);
  // The store refuses a row past its limit itself (another program may have filled it meanwhile).
  store.db.maxUsers = 1;
  store.maxUsers = 10;
  await assert.rejects(store.createUser({ name: 'eve', passwordHash: await hash() }), (e) => e instanceof StoreFullError && writeRefusal(e).includes('full'));
  assert.equal(store.lookup('eve'), null, 'nothing changed in memory');
  assert.equal(row(dataDir, 'eve'), null);
  // And one with more users than it reads stops the start.
  await assert.rejects(UserStore.open({ dataDir, keys: KEYS, warn: () => {}, maxUsers: 1 }), /more than 1 users/);
  assert.ok(MAX_RECOVERY_CODES >= RECOVERY_CODES);
});

test('store: notAdmin refuses a password or second-factor reset for an admin, also one made an admin meanwhile; without it (the command line) it works', async () => {
  const { store, dataDir } = await open();
  await store.createUser({ name: 'bob', role: 'admin', passwordHash: await hash() });
  await store.createUser({ name: 'carol', role: 'viewer', passwordHash: await hash() });
  await store.beginTotp('bob');
  const before = store.find('bob').phc;
  await assert.rejects(store.setPassword('bob', await hash('another password'), { notAdmin: true }), (e) => e.code === 'admin-target');
  await assert.rejects(store.resetSecondFactor('bob', { notAdmin: true }), (e) => e.code === 'admin-target');
  assert.deepEqual(store.find('bob').phc, before);
  assert.ok(store.factorRecord('bob').totp);
  await store.setPassword('carol', await hash('another password'), { notAdmin: true });
  // Made an admin by another program (the command line), which this store has not read yet: the
  // transaction reads it first, and refuses.
  const cli = await reopen(dataDir);
  await cli.setRole('carol', 'admin');
  await cli.beginTotp('carol');
  cli.close();
  assert.equal(store.lookup('carol').role, 'viewer', 'not read yet');
  await assert.rejects(store.setPassword('carol', await hash('a third password'), { notAdmin: true }), (e) => e.code === 'admin-target');
  await assert.rejects(store.resetSecondFactor('carol', { notAdmin: true }), (e) => e.code === 'admin-target');
  assert.ok(store.factorRecord('carol').totp);
  await store.setRole('carol', 'viewer');
  await store.setPassword('bob', await hash('another password'));
  await store.resetSecondFactor('bob');
  assert.equal(store.factorRecord('bob').totp, null);
  // setRole gives the role right before its change.
  assert.equal(await store.setRole('carol', 'manage'), 'viewer');
});

test('store: noDeleteAdmin refuses deleting an admin, also one made an admin meanwhile; the command line still deletes one', async () => {
  const { store, dataDir } = await open();
  await store.createUser({ name: 'root', role: 'admin', passwordHash: await hash() });
  await store.createUser({ name: 'bob', role: 'admin', passwordHash: await hash() });
  await store.createUser({ name: 'carol', role: 'viewer', passwordHash: await hash() });
  await store.createUser({ name: 'dave', role: 'viewer', passwordHash: await hash() });
  await assert.rejects(store.deleteUser('bob', { noDeleteAdmin: true }), (e) => e.code === 'admin-delete');
  assert.equal(store.lookup('bob').role, 'admin');
  await store.deleteUser('dave', { noDeleteAdmin: true });
  assert.equal(store.lookup('dave'), null);
  // Made an admin by another program (the command line), which this store has not read yet: the
  // transaction reads the record as it is then, and refuses.
  const cli = await reopen(dataDir);
  await cli.setRole('carol', 'admin');
  cli.close();
  assert.equal(store.lookup('carol').role, 'viewer', 'not read yet');
  await assert.rejects(store.deleteUser('carol', { noDeleteAdmin: true }), (e) => e.code === 'admin-delete');
  assert.equal(store.lookup('carol').role, 'admin');
  // Without it (the command line, or an admin deleting themselves) an admin is deleted.
  await store.deleteUser('bob');
  assert.equal(store.lookup('bob'), null);
});

test('store: noDemote refuses another role for an admin, also one made an admin meanwhile; promotions and the command line still work', async () => {
  const { store, dataDir } = await open();
  await store.createUser({ name: 'root', role: 'admin', passwordHash: await hash() });
  await store.createUser({ name: 'bob', role: 'admin', passwordHash: await hash() });
  await store.createUser({ name: 'carol', role: 'viewer', passwordHash: await hash() });
  for (const role of ['manage', 'viewer']) await assert.rejects(store.setRole('bob', role, { noDemote: true }), (e) => e.code === 'admin-demote');
  assert.equal(store.lookup('bob').role, 'admin');
  // Not an admin: other roles, and making them an admin, as before.
  assert.equal(await store.setRole('carol', 'manage', { noDemote: true }), 'viewer');
  // Made an admin by another program (the command line), which this store has not read yet: the
  // transaction reads the record as it is then, and refuses.
  const cli = await reopen(dataDir);
  await cli.setRole('carol', 'admin');
  cli.close();
  assert.equal(store.lookup('carol').role, 'manage', 'not read yet');
  await assert.rejects(store.setRole('carol', 'viewer', { noDemote: true }), (e) => e.code === 'admin-demote');
  assert.equal(store.lookup('carol').role, 'admin');
  // Without it (the command line, or an admin's own role) an admin is given another role.
  assert.equal(await store.setRole('bob', 'viewer'), 'admin');
  assert.equal(await store.setRole('bob', 'admin', { noDemote: true }), 'viewer');
});

test('store: users.db and its -wal and -shm keep the owner of users.db when root changes it', { skip: process.platform === 'win32' || process.getuid?.() !== 0 }, async () => {
  const { store, dataDir, file } = await open();
  await store.createUser({ name: 'bob', passwordHash: await hash() });
  store.close();
  for (const f of await fs.readdir(dataDir)) await fs.chown(path.join(dataDir, f), 4321, 4322);
  const again = await reopen(dataDir);
  await again.setRole('bob', 'manage');
  for (const f of [file, `${file}-wal`, `${file}-shm`]) {
    const st = await fs.stat(f);
    assert.deepEqual([st.uid, st.gid, st.mode & 0o777], [4321, 4322, 0o600], f);
  }
  again.close();
});

test('store: find gives the pepper of a peppered hash; new hashes get the current one; older and plain ones need a new hash', async () => {
  const one = crypto.randomBytes(32);
  const keys = new Keyring(new Map([[1, one]]));
  const { store, dataDir } = await open({ keys, configUsers: [await configUser('Alice', 'admin')] });
  assert.deepEqual(store.currentPepper(), { keyid: 1, secret: keys.pepper(1) });
  await store.createUser({ name: 'bob', passwordHash: await hashPassword('bobs password!', undefined, fakeHasher, store.currentPepper()) });
  await store.createUser({ name: 'carol', passwordHash: await hash() });
  const bob = store.find('bob');
  assert.equal(bob.phc.keyid, 1);
  assert.ok(bob.secret.equals(keys.pepper(1)));
  assert.equal(await verifyPassword('bobs password!', bob.phc, fakeHasher, bob.secret), true);
  assert.equal(store.find('carol').secret, null);
  assert.equal(store.find('alice').secret, null, 'config users are never peppered');
  assert.equal(store.needsRepepper(bob.phc), false);
  assert.equal(store.needsRepepper(store.find('carol').phc), true);
  store.close();
  // With a newer key, bob's hash is from an older one: it still verifies, and needs a new hash.
  const both = await reopen(dataDir, { keys: new Keyring(new Map([[1, one], [2, crypto.randomBytes(32)]])) });
  assert.equal(both.currentPepper().keyid, 2);
  assert.equal(await verifyPassword('bobs password!', both.find('bob').phc, fakeHasher, both.find('bob').secret), true);
  assert.equal(both.needsRepepper(both.find('bob').phc), true);
  both.close();
  // Without keys (a store in memory only), nothing is peppered.
  const plain = new UserStore({ warn: () => {} });
  assert.equal(plain.currentPepper(), null);
  assert.equal(plain.needsRepepper(parsePhc(await hash())), false);
});

test('store: upgradePassword replaces the hash only while it is still the old one, and changes nothing else', async () => {
  const { store, dataDir } = await open({ configUsers: [await configUser('Alice', 'admin')] });
  await store.createUser({ name: 'bob', passwordHash: await hash('bobs password!'), mustChangePassword: true });
  await store.addDevice('bob', 'a'.repeat(64));
  const calls = [];
  store.onExternalChange = (...a) => calls.push(a);
  const old = store.find('bob').phc;
  const peppered = await hashPassword('bobs password!', undefined, fakeHasher, store.currentPepper());
  assert.equal(store.upgradePassword('bob', old, peppered), true);
  assert.equal(store.find('bob').phc.keyid, 1);
  assert.equal(store.lookup('bob').mustChangePassword, true, 'the flag stays');
  assert.equal(store.hasDevice('bob', 'a'.repeat(64)), true, 'devices stay');
  // The old hash is not the stored one any more: nothing is written.
  assert.equal(store.upgradePassword('bob', old, await hash()), false);
  assert.equal(store.find('bob').phc.keyid, 1);
  assert.equal(store.upgradePassword('alice', store.find('alice').phc, peppered), false, 'config users are never upgraded');
  assert.equal(store.upgradePassword('nobody', old, peppered), false);
  assert.throws(() => store.upgradePassword('bob', store.find('bob').phc, 'not a hash'));
  // A password changed elsewhere meanwhile wins.
  const cli = await reopen(dataDir);
  const theirs = await hash('set by the admin');
  await cli.setPassword('bob', theirs, { mustChangePassword: true });
  assert.equal(store.upgradePassword('bob', store.find('bob').phc, await hash()), false);
  assert.equal(store.find('bob').phc.hash.equals(parsePhc(theirs).hash), true);
  assert.deepEqual(calls, [['bob', ['password']]], 'only the change made elsewhere is told, not the upgrade');
  const again = await reopen(dataDir);
  assert.equal(again.find('bob').phc.hash.equals(parsePhc(theirs).hash), true);
  assert.equal(again.lookup('bob').mustChangePassword, true);
});

test('store: changes made by another program are picked up, told to onExternalChange, and seen by the next change', async () => {
  const configUsers = [await configUser('Alice', 'admin')];
  const { store, dataDir, clock } = await open({ configUsers });
  await store.createUser({ name: 'bob', role: 'admin', passwordHash: await hash() });
  await store.createUser({ name: 'carol', passwordHash: await hash() });
  await store.createUser({ name: 'dave', passwordHash: await hash() });
  await store.beginTotp('alice');
  await store.enableTotp('alice', codeAt(store, 'alice', NOW));
  await store.beginTotp('dave');
  await store.enableTotp('dave', codeAt(store, 'dave', NOW));
  await store.addDevice('dave', 'd'.repeat(64));
  const calls = [];
  store.onExternalChange = (name, what) => calls.push([name, what]);
  assert.equal(store.refresh(), false, 'nothing changed yet');

  // scripts/users.js, with a store of its own on the same file.
  const cli = await reopen(dataDir, { configUsers });
  await cli.setRole('carol', 'admin');
  await cli.setPassword('bob', await hash('new password'), { mustChangePassword: true });
  await cli.createUser({ name: 'erin', passwordHash: await hash() });
  await cli.resetSecondFactor('alice');
  await cli.deleteUser('dave');
  // A sign in time is no reason to end sessions.
  await cli.recordLogin('carol');
  assert.equal(store.refresh(), true);
  assert.deepEqual(calls.sort(), [['Alice', ['second-factor']], ['bob', ['password']], ['carol', ['role']], ['dave', ['deleted']], ['erin', ['created']]]);
  assert.equal(store.find('carol').role, 'admin');
  assert.equal(store.find('dave'), null);
  assert.equal(store.find('erin').role, 'viewer');
  assert.equal(store.secondFactorEnabled('alice'), false);
  assert.equal(store.refresh(), false);

  // A change made here sees the fresh record, even before the timer ran.
  await cli.setRole('erin', 'manage');
  calls.length = 0;
  assert.equal(await store.setRole('erin', 'admin'), 'manage');
  assert.deepEqual(calls, [['erin', ['role']]], 'told after the transaction');
  await cli.deleteUser('erin');
  await assert.rejects(store.setRole('erin', 'viewer'), (e) => e.code === 'unknown');
  assert.equal(store.find('erin'), null);
  // A change made in memory first is made on the fresh record too, and undoes nothing done elsewhere.
  await cli.setRole('carol', 'manage');
  clock.t += LOGIN_WRITE_MS;
  await store.touchLogin('carol');
  const disk = await reopen(dataDir);
  assert.equal(disk.find('carol').role, 'manage');
  assert.equal(disk.account('carol').lastLogin, new Date(clock.t).toISOString());
  // A callback that throws is logged, and the change still made.
  const logs = [];
  store.log = (m) => logs.push(m);
  store.onExternalChange = () => {
    throw new Error('boom');
  };
  await cli.setRole('carol', 'viewer');
  store.refresh();
  assert.equal(store.find('carol').role, 'viewer');
  assert.match(logs[0], /carol.*boom/);
});

test('store: a user ended elsewhere can have their devices forgotten from the callback, which writes', async () => {
  const { store, dataDir } = await open();
  await store.createUser({ name: 'bob', passwordHash: await hash() });
  await store.addDevice('bob', 'a'.repeat(64));
  // As login.js does: endUser forgets the devices, which is a write of its own.
  store.onExternalChange = (name) => store.dropDevices(name).saved;
  const cli = await reopen(dataDir);
  await cli.setPassword('bob', await hash('new password'));
  store.refresh();
  assert.equal(store.hasDevice('bob', 'a'.repeat(64)), false);
  assert.deepEqual((await reopen(dataDir)).devices('bob'), []);
});

test('store: watch looks for changes made elsewhere until close, and logs a store it cannot read at most once a minute', async () => {
  const { store, dataDir } = await open();
  await store.createUser({ name: 'bob', passwordHash: await hash() });
  const seen = [];
  store.onExternalChange = (name, what) => seen.push([name, what]);
  store.watch(10);
  store.watch(10);
  const cli = await reopen(dataDir);
  await cli.setRole('bob', 'manage');
  for (let i = 0; i < 200 && seen.length === 0; i++) await new Promise((r) => setTimeout(r, 5));
  assert.deepEqual(seen, [['bob', ['role']]]);
  // A row another program damaged: the store keeps what it has, and says so once.
  const logs = [];
  store.log = (m) => logs.push(m);
  const sql = new DatabaseSync(path.join(dataDir, DB_FILE));
  sql.exec(`UPDATE users SET created = 'yesterday'`);
  sql.close();
  for (let i = 0; i < 200 && logs.length === 0; i++) await new Promise((r) => setTimeout(r, 5));
  await new Promise((r) => setTimeout(r, 50));
  assert.equal(logs.length, 1);
  assert.match(logs[0], /could not be read again: .*created is not a time/);
  assert.equal(store.find('bob').role, 'manage');
  store.close();
  store.close();
  cli.close();
});

test('store: recovery codes made under an older key still work once a newer key is added', async () => {
  const one = crypto.randomBytes(32);
  const { store, dataDir } = await open({ keys: new Keyring(new Map([[1, one]])) });
  await store.createUser({ name: 'bob', passwordHash: await hash() });
  await store.beginTotp('bob');
  const codes = await store.enableTotp('bob', codeAt(store, 'bob', NOW));
  assert.ok(store.factorRecord('bob').recoveryCodes.every((c) => /^k1:[0-9a-f]{64}$/.test(c)));
  store.close();
  const both = await reopen(dataDir, { keys: new Keyring(new Map([[1, one], [2, crypto.randomBytes(32)]])) });
  assert.equal(both.useRecoveryCode('bob', codes[0]).ok, true);
  const fresh = await both.newRecoveryCodes('bob');
  assert.ok(both.factorRecord('bob').recoveryCodes.every((c) => c.startsWith('k2:')));
  assert.equal(both.useRecoveryCode('bob', fresh[0]).ok, true);
  assert.equal(both.useRecoveryCode('bob', codes[1]).ok, false);
});

test('store: without a database, the store lives in memory and keeps recovery codes as SHA-256', async () => {
  const store = new UserStore({ warn: () => {}, now: () => NOW });
  await store.createUser({ name: 'bob', passwordHash: await hash() });
  await store.beginTotp('bob');
  const codes = await store.enableTotp('bob', codeAt(store, 'bob', NOW));
  assert.deepEqual(store.factorRecord('bob').recoveryCodes, codes.map(hashRecoveryCode));
  const r = store.useRecoveryCode('bob', codes[0]);
  assert.equal(r.ok, true);
  await r.saved;
  assert.equal(store.refresh(), false);
  assert.equal(store.upgradePassword('bob', store.find('bob').phc, await hash()), true);
  await store.flush();
  store.watch();
  store.close();
});

test('store: a change made elsewhere found inside a write is acted on first, so the guard sees the session it ended', async () => {
  const { store, dataDir } = await open();
  await store.createUser({ name: 'bob', role: 'admin', passwordHash: await hash() });
  let ended = false;
  store.onExternalChange = (name) => {
    if (name === 'bob') ended = true;
  };
  // scripts/users.js resets bob's password; the server has not looked yet.
  const cli = await reopen(dataDir);
  await cli.setPassword('bob', await hash('another good password'));
  cli.close();
  // A request of bob's session, guarded by that session still being there.
  await assert.rejects(store.beginTotp('bob', { guard: () => !ended }), (e) => e instanceof UserError && e.code === 'gone');
  assert.equal(ended, true);
  assert.equal(row(dataDir, 'bob').totp_box, null, 'nothing written');
  // The next one, without a change meanwhile, goes ahead.
  await store.beginTotp('bob', { guard: () => true });
  assert.notEqual(row(dataDir, 'bob').totp_box, null);
  store.close();
});

test('store: an unknown name is checked with the costs of one of the users, always the same for the same name', async () => {
  const costs = [[19456, 2, 1], [32768, 3, 1], [65536, 2, 2], [20000, 9, 1]];
  const configUsers = await Promise.all(costs.map(async ([memory, passes, parallelism], i) => ({ name: `user${i}`, phc: parsePhc(await hashPassword('x', { memory, passes, parallelism }, fakeHasher)) })));
  const store = new UserStore({ configUsers });
  const of = (p) => `${p.memory},${p.passes},${p.parallelism},${p.hash.length}`;
  const stored = new Set(configUsers.map((u) => of(u.phc)));
  const picked = new Set();
  for (let i = 0; i < 64; i++) {
    const a = store.standIn(`nobody${i}`);
    assert.ok(stored.has(of(a)), `nobody${i}: drawn from the stored costs`);
    assert.equal(of(store.standIn(`NOBODY${i} `)), of(a), 'the same name in any case gives the same costs');
    assert.equal(of(store.standIn(`nobody${i}`)), of(a));
    picked.add(of(a));
  }
  assert.ok(picked.size > 1, 'names are spread over the users');
  // Each stand-in matches no password: its hash is random.
  assert.notDeepEqual(store.standIn('nobody0').hash, store.standIn('nobody0').hash);
  // Without users, the defaults.
  assert.equal(of(new UserStore({}).standIn('x')), '19456,2,1,32');
  // A sign in with an unknown name works out a hash with the costs standIn gives.
  const calls = [];
  const auth = createLogin({ users: configUsers, store, hasher: async (p) => (calls.push(p), fakeHasher(p)), sleep: async () => {} });
  assert.deepEqual(await auth.attempt('nobody7', 'x', '192.0.2.1'), { ok: false, reason: 'invalid' });
  const want = store.standIn('nobody7');
  assert.deepEqual([calls[0].memory, calls[0].passes, calls[0].parallelism, calls[0].length], [want.memory, want.passes, want.parallelism, want.hash.length]);
});

test('store: a deleted user and a replaced password are cleared from users.db and users.db-wal while the server runs', async () => {
  const { store, dataDir } = await open();
  const bobHash = await hash('bobs own long password');
  const carolOld = await hash('carols first long password');
  await store.createUser({ name: 'bob', role: 'admin', passwordHash: bobHash });
  await store.createUser({ name: 'carol', role: 'admin', passwordHash: carolOld });
  const has = async (text) => (await diskBytes(dataDir)).includes(Buffer.from(text));
  assert.equal(await has(bobHash), true, 'written');
  await store.deleteUser('bob');
  assert.equal(await has(bobHash), false, 'the deleted hash is in neither file');
  // The next one within a second is cleared a moment later, together with anything in between.
  await store.setPassword('carol', await hash('carols second long password'));
  for (let i = 0; i < 40 && store.scrubPending; i++) await new Promise((r) => setTimeout(r, 50));
  assert.equal(store.scrubPending, false);
  assert.equal(await has(carolOld), false, 'the old hash is gone');
  // Another program reading the store just then: nothing waits, and it is tried again.
  const reader = new DatabaseSync(path.join(dataDir, DB_FILE), { readOnly: true });
  reader.exec('BEGIN');
  reader.prepare('SELECT count(*) FROM users').get();
  store.scrubbedAt = null;
  await store.setPassword('carol', await hash('carols third long password'));
  assert.equal(store.scrubPending, true, 'busy: left for later');
  reader.exec('COMMIT');
  reader.close();
  store.close();
});

test('store: the stand-in costs of an unknown name stay the same after a restart, and move only when a set of costs comes or goes', async () => {
  const phcWith = async (memory) => hashPassword('a good password', { memory }, fakeHasher, null);
  const { store, dataDir } = await open();
  await store.createUser({ name: 'cheap', passwordHash: await phcWith(19456) });
  await store.createUser({ name: 'costly', passwordHash: await phcWith(65536) });
  const of = (p) => `${p.memory},${p.passes},${p.parallelism},${p.hash.length}`;
  const names = Array.from({ length: 64 }, (_, i) => `nobody${i}`);
  const picks = () => names.map((n) => of(store.standIn(n)));
  const first = picks();
  assert.deepEqual(new Set(first), new Set(['19456,2,1,32', '65536,2,1,32']), 'drawn from the stored costs, both used');
  // After a restart, with the same key: the same picks.
  store.close();
  const again = await reopen(dataDir);
  assert.deepEqual(names.map((n) => of(again.standIn(n))), first);
  // Another user with costs already there moves nothing; one with new costs only draws names to it.
  await again.createUser({ name: 'cheap2', passwordHash: await phcWith(19456) });
  assert.deepEqual(names.map((n) => of(again.standIn(n))), first);
  await again.createUser({ name: 'middle', passwordHash: await phcWith(32768) });
  const moved = names.map((n) => of(again.standIn(n)));
  assert.ok(moved.some((m) => m === '32768,2,1,32'), 'some names go to the new costs');
  for (const [i, m] of moved.entries()) assert.ok(m === first[i] || m === '32768,2,1,32', `${names[i]} stays or goes to the new costs`);
  again.close();
  // The pick comes from the key: two keys spread the same names differently.
  const configUsers = [{ name: 'a', phc: parsePhc(await phcWith(19456)) }, { name: 'b', phc: parsePhc(await phcWith(65536)) }];
  const keyed = () => new UserStore({ configUsers, keys: new Keyring(new Map([[1, crypto.randomBytes(32)]])) });
  const [x, y] = [keyed(), keyed()];
  assert.notDeepEqual(names.map((n) => of(x.standIn(n))), names.map((n) => of(y.standIn(n))));
});

test('login: a hash that needs a key version this server lacks is a wrong password to the visitor, and an error line to the operator', async () => {
  const { store, dataDir, clock } = await open();
  await store.createUser({ name: 'bob', passwordHash: await hash() });
  const logs = [];
  const calls = [];
  const auth = createLogin({ users: [], store, hasher: async (p) => (calls.push(p), fakeHasher(p)), log: (m) => logs.push(m), sleep: async () => {}, now: () => clock.t });
  // Peppered with a version 2 the server was not given (written by something else).
  const other = new Keyring(new Map([[2, crypto.randomBytes(32)]]));
  const peppered = await hashPassword('a good password', { memory: 32768 }, fakeHasher, { keyid: 2, secret: other.pepper(2) });
  const sql = new DatabaseSync(path.join(dataDir, DB_FILE));
  sql.prepare("UPDATE users SET password_hash = ? WHERE name_key = 'bob'").run(peppered);
  sql.close();
  assert.equal(store.refresh(), true);
  const right = await auth.attempt('bob', 'a good password', '192.0.2.1');
  const wrong = await auth.attempt('bob', 'a wrong password', '192.0.2.2');
  assert.deepEqual(right, { ok: false, reason: 'invalid' });
  assert.deepEqual(right, wrong);
  // Both took a hash with bob's costs.
  assert.deepEqual(calls.map((c) => c.memory), [32768, 32768]);
  // The operator is told once a minute, not at every try.
  assert.equal(logs.length, 1);
  assert.match(logs[0], /^error: the password hash of bob needs key version 2, which this server was not given, so they cannot sign in\. Restart the website with that version in USERS_KEY_FILE\.$/);
  clock.t += NO_PEPPER_LOG_MS;
  assert.deepEqual(await auth.attempt('bob', 'a good password', '192.0.2.3'), { ok: false, reason: 'invalid' });
  assert.equal(logs.length, 2);
  store.close();
});

test('login: when the store cannot be read again, signing in is off and every session ends, until a read works again', async () => {
  const one = crypto.randomBytes(32);
  const keys = new Keyring(new Map([[1, one]]));
  const dataDir = await tmp();
  const store = await UserStore.open({ dataDir, keys, warn: () => {} });
  const logs = [];
  const events = [];
  const audit = { write: async (event, data) => events.push([event, data]), flush: async () => {} };
  const auth = createLogin({ users: [], store, hasher: fakeHasher, log: (m) => logs.push(m), audit, sleep: async () => {} });
  await store.createUser({ name: 'bob', role: 'admin', passwordHash: await hashPassword('a good password', undefined, fakeHasher, store.currentPepper()) });
  await store.createUser({ name: 'carol', passwordHash: await hash() });
  const first = await auth.attempt('bob', 'a good password', '192.0.2.1');
  assert.equal(first.ok, true);
  const s = await auth.signIn('bob', { epoch: first.epoch });
  assert.ok(s);
  assert.equal(auth.sessions.size, 1);
  const req = { headers: { cookie: `${COOKIE}=${s.id}` } };
  assert.equal(auth.session(req).user.name, 'bob');
  events.length = 0;

  // Something with a key the server lacks writes carol's second factor.
  const other = await UserStore.open({ dataDir, keys: new Keyring(new Map([[1, one], [2, crypto.randomBytes(32)]])), warn: () => {} });
  await other.beginTotp('carol');
  assert.throws(() => store.refresh(), /does not decrypt with key version 2/);
  assert.equal(auth.sessions.size, 0, 'every session ended');
  assert.equal(auth.session(req), null);
  assert.deepEqual(await auth.attempt('bob', 'a good password', '192.0.2.1'), { ok: false, reason: 'unavailable' });
  // Turned away before any hash: a wrong password or an unknown name gets the same answer.
  assert.deepEqual(await auth.attempt('bob', 'a wrong password', '192.0.2.1'), { ok: false, reason: 'unavailable' });
  assert.deepEqual(await auth.attempt('nobody', 'a good password', '192.0.2.1'), { ok: false, reason: 'unavailable' });
  assert.match(logs.find((l) => /cannot be read/.test(l)), /^error: the user store cannot be read \(.*\)\. Signing in is off and all 1 sessions were ended until it can be read again/);
  assert.deepEqual(events.map(([e]) => e), ['user-store-unreadable']);
  // Failing again says nothing new.
  assert.throws(() => store.refresh());
  assert.equal(events.length, 1);

  // Once it can be read again, signing in is back.
  await other.resetSecondFactor('carol');
  other.close();
  assert.equal(store.refresh(), true);
  assert.equal(store.unreadable, null);
  assert.deepEqual(events.map(([e]) => e), ['user-store-unreadable', 'user-store-readable']);
  assert.match(logs.at(-1), /can be read again; signing in is back on/);
  assert.equal((await auth.attempt('bob', 'a good password', '192.0.2.1')).ok, true);
  store.close();
});

// ---- passkeys ----

// A passkey as passkeys.js hands it over after a registration; over changes fields.
const passkey = (label = 'Phone', over = {}) => ({
  id: crypto.randomBytes(32).toString('base64url'),
  publicKey: crypto.randomBytes(77).toString('base64url'),
  counter: 0,
  transports: ['hybrid', 'internal'],
  name: label,
  backupEligible: true,
  backedUp: true,
  rpId: 'status.example.org',
  ...over,
});
const userError = (code) => (e) => e instanceof UserError && e.code === code;
// The passkey rows of the store on disk.
function credentialRows(dataDir) {
  const sql = new DatabaseSync(path.join(dataDir, DB_FILE), { readOnly: true });
  try {
    return sql.prepare('SELECT c.*, u.kind, u.name AS user FROM credentials c JOIN users u ON u.id = c.user_id ORDER BY c.id').all();
  } finally {
    sql.close();
  }
}

test('passkeys: added to a website user and a config user, kept in their own rows, and read back the same after a restart', async () => {
  const configUsers = [await configUser('Alice', 'admin')];
  const clock = { t: NOW };
  const { store, dataDir } = await open({ configUsers, clock });
  await store.createUser({ name: 'bob', passwordHash: await hash() });
  assert.deepEqual(store.secondFactors('bob'), { totp: false, passkeys: 0, recoveryCodesLeft: 0 });
  assert.equal(store.passkeyByRef('bob', 'x'), null);
  assert.deepEqual(store.passkeys('nobody'), []);

  const handle = await store.ensurePasskeyUserId('bob');
  assert.equal(Buffer.from(handle, 'base64url').length, 32);
  assert.equal(await store.ensurePasskeyUserId('BOB'), handle, 'made once');
  const one = passkey('  My phone  ');
  const added = await store.addPasskey('bob', one);
  assert.equal(added.first, true);
  assert.equal(added.recoveryCodes.length, RECOVERY_CODES);
  assert.equal(added.ref, passkeyRef(one.id));
  assert.equal(added.ref, crypto.createHash('sha256').update(Buffer.from(one.id, 'base64url')).digest('hex').slice(0, 16));
  clock.t += 1000;
  const two = passkey('Key', { transports: [], backupEligible: false, backedUp: false, counter: 7 });
  assert.deepEqual(await store.addPasskey('bob', two), { first: false, recoveryCodes: null, ref: passkeyRef(two.id) });
  assert.equal(store.secondFactorEnabled('bob'), true);
  assert.deepEqual(store.secondFactors('bob'), { totp: false, passkeys: 2, recoveryCodesLeft: RECOVERY_CODES });

  // A config user without a record gets one, with a user handle, in a 'config' row.
  assert.equal(store.factorRecord('alice'), null);
  const three = passkey('Laptop');
  assert.equal((await store.addPasskey('alice', three)).first, true);
  assert.equal(Buffer.from(store.factorRecord('alice').passkeyUserId, 'base64url').length, 32);
  assert.deepEqual(credentialRows(dataDir).map((r) => [r.kind, r.user, r.name]), [['store', 'bob', 'My phone'], ['store', 'bob', 'Key'], ['config', 'Alice', 'Laptop']]);

  const want = [
    { ref: passkeyRef(one.id), name: 'My phone', created: new Date(NOW).toISOString(), lastUsed: null, backedUp: true, backupEligible: true, rpId: 'status.example.org' },
    { ref: passkeyRef(two.id), name: 'Key', created: new Date(NOW + 1000).toISOString(), lastUsed: null, backedUp: false, backupEligible: false, rpId: 'status.example.org' },
  ];
  assert.deepEqual(store.passkeys('bob'), want);
  const full = { type: 'passkey', ...one, name: 'My phone', created: want[0].created, lastUsed: null, ref: want[0].ref };
  assert.deepEqual(store.passkeyByRef('bob', want[0].ref), full);
  assert.deepEqual(store.passkeyById('bob', one.id), full);
  assert.equal(store.passkeyById('alice', one.id), null, 'only the user\'s own');
  // A copy: changing it changes nothing kept.
  store.passkeyByRef('bob', want[0].ref).transports.push('usb');
  assert.deepEqual(store.passkeyByRef('bob', want[0].ref).transports, ['hybrid', 'internal']);

  // What the pages see has no id and no key.
  const account = store.account('bob');
  assert.deepEqual(account.passkeys, want);
  assert.equal(account.recoveryCodesLeft, RECOVERY_CODES);
  assert.deepEqual(account.totp, { enabled: false, recoveryCodesLeft: 0 });
  const overview = store.overview();
  assert.deepEqual(overview.map((u) => [u.name, u.secondFactor, u.totp, u.passkeys]), [['Alice', true, false, 1], ['bob', true, false, 2]]);
  for (const text of [JSON.stringify(account), JSON.stringify(overview)]) {
    for (const p of [one, two, three]) assert.equal(text.includes(p.id) || text.includes(p.publicKey), false);
  }

  const again = await reopen(dataDir, { configUsers });
  for (const name of ['bob', 'alice']) assert.deepEqual(again.factorRecord(name), store.factorRecord(name), name);
  assert.equal(await again.ensurePasskeyUserId('bob'), handle);
  assert.equal(again.useRecoveryCode('bob', added.recoveryCodes[0]).ok, true);
  again.close();
  store.close();
});

test('passkeys: at most ten per user, every field checked, and a bad name is refused; nothing is written then', async () => {
  const { store, dataDir } = await open();
  await store.createUser({ name: 'bob', passwordHash: await hash() });
  await assert.rejects(store.addPasskey('nobody', passkey()), userError('unknown'));
  const bad = {
    id: ['', 'a+b/', 'aGk=', crypto.randomBytes(513).toString('base64url'), 42],
    publicKey: ['', crypto.randomBytes(601).toString('base64url'), null],
    counter: [-1, 2 ** 32, 1.5, '3'],
    transports: [['warp'], Array(9).fill('usb'), 'usb'],
    rpId: ['', 'a'.repeat(254), 'exa mple.org', 'example.org/'],
    backupEligible: [1, undefined],
    backedUp: ['yes'],
    created: ['yesterday'],
    lastUsed: ['soon'],
  };
  for (const [field, values] of Object.entries(bad)) {
    for (const v of values) await assert.rejects(store.addPasskey('bob', passkey('Phone', { [field]: v })), TypeError, `${field}: ${v}`);
  }
  await assert.rejects(store.addPasskey('bob', 'not an object'), TypeError);
  for (const label of ['', '   ', 'x'.repeat(65), 'a\nb', 'tab\there', 'evil‮gnp.exe', 'line break', 42, null]) {
    await assert.rejects(store.addPasskey('bob', passkey(label)), userError('bad-label'), JSON.stringify(label));
  }
  assert.deepEqual(credentialRows(dataDir), [], 'nothing written');
  assert.equal(store.secondFactorEnabled('bob'), false);

  // 64 characters, some outside the basic plane, are fine.
  const refs = [(await store.addPasskey('bob', passkey('\u{1F511}'.repeat(64)))).ref];
  for (let i = 1; i < MAX_PASSKEYS; i++) refs.push((await store.addPasskey('bob', passkey(`Key ${i}`))).ref);
  assert.equal(new Set(refs).size, MAX_PASSKEYS);
  await assert.rejects(store.addPasskey('bob', passkey('One more')), userError('full'));
  assert.equal(store.passkeys('bob').length, MAX_PASSKEYS);
  assert.equal(credentialRows(dataDir).length, MAX_PASSKEYS);
  assert.equal(store.passkeys('bob')[0].name, '\u{1F511}'.repeat(64));
  // Renaming checks the name the same way, and an unknown ref is refused.
  await assert.rejects(store.renamePasskey('bob', refs[1], 'x'.repeat(65)), userError('bad-label'));
  await assert.rejects(store.renamePasskey('bob', 'ffffffffffffffff', 'New'), userError('unknown'));
  await assert.rejects(store.renamePasskey('nobody', refs[1], 'New'), userError('unknown'));
  assert.deepEqual(await store.renamePasskey('bob', refs[1], ' Work key '), { from: 'Key 1', to: 'Work key' });
  assert.equal((await reopen(dataDir)).passkeyByRef('bob', refs[1]).name, 'Work key');
  // The store itself refuses an eleventh passkey written by any other way.
  const r = store.factorRecord('bob');
  assert.throws(() => store.db.tx(() => store.db.put('store', { ...r, credentials: [...r.credentials, { type: 'passkey', ...passkey(), created: new Date(NOW).toISOString(), lastUsed: null }] })), StoreFullError);
  store.close();
});

test('passkeys: one id belongs to one passkey of one user only', async () => {
  const configUsers = [await configUser('Alice')];
  const { store, dataDir } = await open({ configUsers });
  await store.createUser({ name: 'bob', passwordHash: await hash() });
  await store.createUser({ name: 'carol', passwordHash: await hash() });
  const p = passkey();
  await store.addPasskey('bob', p);
  await assert.rejects(store.addPasskey('bob', passkey('Again', { id: p.id })), userError('exists'));
  for (const name of ['carol', 'alice']) await assert.rejects(store.addPasskey(name, passkey('Mine', { id: p.id })), userError('exists'), name);
  // Added by another program meanwhile: refused all the same.
  const q = passkey();
  const cli = await reopen(dataDir, { configUsers });
  await cli.addPasskey('carol', q);
  await assert.rejects(store.addPasskey('alice', passkey('Mine', { id: q.id })), userError('exists'));
  // And by the database itself, for a record that has it anyway.
  const r = store.factorRecord('bob');
  const copy = { ...store.passkeyById('carol', q.id) };
  delete copy.ref;
  assert.throws(() => store.db.tx(() => store.db.put('store', { ...r, credentials: [...r.credentials, copy] })), userError('exists'));
  assert.deepEqual(credentialRows(dataDir).map((c) => c.user), ['bob', 'carol']);
  cli.close();
  store.close();
});

test('passkeys: passkeyOwner finds the owner of a credential id in website users and in config users\' records, and nobody else', async () => {
  const configUsers = [await configUser('Alice', 'admin')];
  const { store } = await open({ configUsers });
  await store.createUser({ name: 'Bob', passwordHash: await hash() });
  const [mine, hers] = [passkey('Phone'), passkey('Key')];
  await store.addPasskey('Bob', mine);
  await store.addPasskey('alice', hers);
  assert.equal(store.passkeyOwner(mine.id), 'Bob', 'the name as the store keeps it');
  assert.equal(store.passkeyOwner(hers.id), 'Alice');
  // Unknown ids and anything that is not an id.
  for (const id of [crypto.randomBytes(32).toString('base64url'), '', null, undefined, 42, {}, [mine.id], mine.id.toUpperCase()]) assert.equal(store.passkeyOwner(id), null, String(id));
  // It only reads: no record was made for anyone.
  assert.equal(store.factorRecord('nobody'), null);

  // Gone with the passkey, and with the user.
  await store.removePasskey('Bob', passkeyRef(mine.id));
  assert.equal(store.passkeyOwner(mine.id), null);
  const again = passkey('Phone again');
  await store.addPasskey('Bob', again);
  assert.equal(store.passkeyOwner(again.id), 'Bob');
  await store.deleteUser('Bob', { force: true });
  assert.equal(store.passkeyOwner(again.id), null);
  await store.resetSecondFactor('alice');
  assert.equal(store.passkeyOwner(hers.id), null);
  store.close();
});

test('passkeys: the factor record of a config user who is gone never signs anyone in, is warned about at start, and is removed by the website', async () => {
  const configUsers = [await configUser('Alice', 'admin'), await configUser('Zed')];
  const { store, dataDir } = await open({ configUsers });
  const p = passkey('Key');
  await store.addPasskey('Zed', p);
  store.close();
  // The command line does not know the config file: it keeps the record, but it names nobody.
  const cli = await reopen(dataDir, { configUsers: [configUsers[0]] });
  assert.equal(cli.lookup('Zed'), null);
  assert.equal(cli.passkeyOwner(p.id), null);
  cli.close();
  // The website: said at start, then removed.
  const warned = [];
  const web = await reopen(dataDir, { configUsers: [configUsers[0]], dropOrphans: true, warn: (m) => warned.push(m) });
  assert.equal(warned.filter((m) => m.includes('"zed"')).length, 1);
  assert.equal(web.passkeyOwner(p.id), null);
  assert.equal(web.forgetOrphans(), 1);
  assert.equal(row(dataDir, 'Zed', 'config'), null);
  web.close();
  // Put back in the config file (or a website user made with that name): nothing from before.
  const back = await reopen(dataDir, { configUsers, dropOrphans: true });
  assert.equal(back.passkeyOwner(p.id), null);
  assert.equal(back.passkeys('Zed').length, 0);
  assert.equal(back.secondFactorEnabled('Zed'), false);
  back.close();
});

test('passkeys: a website user made over the record of a config user who was removed gets none of its passkeys', async () => {
  const configUsers = [await configUser('Alice', 'admin'), await configUser('Zed')];
  const { store, dataDir } = await open({ configUsers });
  const p = passkey('Key');
  await store.addPasskey('Zed', p);
  store.close();
  const web = await reopen(dataDir, { configUsers: [configUsers[0]], dropOrphans: true });
  web.forgetOrphans();
  await web.createUser({ name: 'zed', passwordHash: await hash() });
  assert.equal(web.passkeyOwner(p.id), null);
  assert.equal(web.secondFactorEnabled('zed'), false);
  web.close();
});

test('passkeys: a website user shadowed by a config user of the same name cannot be named by a passkey', async () => {
  const { store, dataDir } = await open();
  await store.createUser({ name: 'zed', passwordHash: await hash() });
  const p = passkey('Key');
  await store.addPasskey('zed', p);
  assert.equal(store.passkeyOwner(p.id), 'zed');
  store.close();
  const warned = [];
  const shadowed = await reopen(dataDir, { configUsers: [await configUser('Zed')], warn: (m) => warned.push(m) });
  assert.equal(warned.some((m) => m.includes('also in the config file')), true);
  assert.equal(shadowed.passkeyOwner(p.id), null);
  shadowed.close();
});

test('users: a stored user named status-links is warned about at start and cannot sign in or have the role or password changed', async () => {
  const { store, dataDir } = await open();
  await store.createUser({ name: 'Other', passwordHash: await hash() });
  store.close();
  // Put there behind the store's back (an older version, or an edit of users.db).
  const sql = new DatabaseSync(path.join(dataDir, DB_FILE));
  sql.prepare("UPDATE users SET name = 'Status-Links', name_key = 'status-links' WHERE name_key = 'other'").run();
  sql.close();
  const warned = [];
  const again = await reopen(dataDir, { warn: (m) => warned.push(m) });
  assert.equal(warned.some((m) => /reserved/.test(m) && m.includes('Status-Links')), true, warned.join('|'));
  for (const name of ['status-links', 'STATUS-LINKS']) {
    assert.equal(again.find(name), null);
    assert.equal(again.lookup(name), null);
    await assert.rejects(again.setRole(name, 'admin'), { code: 'reserved-name' });
    await assert.rejects(again.setPassword(name, await hash()), { code: 'reserved-name' });
  }
  again.close();
});

test('passkeys: removing the last second factor clears the recovery codes; TOTP off keeps them while a passkey is left', async () => {
  const { store, dataDir } = await open();
  await store.createUser({ name: 'bob', passwordHash: await hash() });
  const { ref, recoveryCodes } = await store.addPasskey('bob', passkey('Phone'));
  // TOTP turned on next makes new codes, and the old ones stop working.
  await store.beginTotp('bob');
  const totpCodes = await store.enableTotp('bob', codeAt(store, 'bob', NOW));
  assert.equal(store.useRecoveryCode('bob', recoveryCodes[0]).ok, false);
  const second = await store.addPasskey('bob', passkey('Key'));
  assert.deepEqual([second.first, second.recoveryCodes], [false, null]);
  assert.deepEqual(store.secondFactors('bob'), { totp: true, passkeys: 2, recoveryCodesLeft: RECOVERY_CODES });

  assert.deepEqual(await store.removePasskey('bob', ref), { label: 'Phone', secondFactorOff: false });
  await store.disableTotp('bob');
  assert.equal(store.secondFactorEnabled('bob'), true);
  assert.deepEqual(store.secondFactors('bob'), { totp: false, passkeys: 1, recoveryCodesLeft: RECOVERY_CODES });
  assert.equal(store.useRecoveryCode('bob', totpCodes[0]).ok, true, 'the codes stay with the passkey');
  await assert.rejects(store.removePasskey('bob', ref), userError('unknown'), 'gone already');
  await assert.rejects(store.removePasskey('nobody', second.ref), userError('unknown'));
  await assert.rejects(store.removePasskey('bob', second.ref, { guard: () => false }), userError('gone'));
  assert.equal(store.passkeys('bob').length, 1, 'a guard that says no changes nothing');

  assert.deepEqual(await store.removePasskey('bob', second.ref), { label: 'Key', secondFactorOff: true });
  assert.deepEqual(store.secondFactors('bob'), { totp: false, passkeys: 0, recoveryCodesLeft: 0 });
  assert.deepEqual(store.factorRecord('bob').recoveryCodes, []);
  assert.equal(store.useRecoveryCode('bob', totpCodes[1]).ok, false);
  assert.equal(store.secondFactorEnabled('bob'), false);
  const again = await reopen(dataDir);
  assert.deepEqual(again.factorRecord('bob').credentials, []);
  assert.equal(row(dataDir, 'bob').totp_box, null);
  store.close();
});

test('passkeys: recovery codes work, and can be made again, with passkeys only; the first passkey after TOTP keeps them', async () => {
  const { store } = await open();
  await store.createUser({ name: 'bob', passwordHash: await hash() });
  await assert.rejects(store.newRecoveryCodes('bob'), userError('unknown'));
  const { recoveryCodes } = await store.addPasskey('bob', passkey());
  const r = store.useRecoveryCode('bob', recoveryCodes[0]);
  assert.deepEqual([r.ok, r.left], [true, RECOVERY_CODES - 1]);
  await r.saved;
  const fresh = await store.newRecoveryCodes('bob');
  assert.equal(store.useRecoveryCode('bob', recoveryCodes[1]).ok, false);
  assert.equal(store.useRecoveryCode('bob', fresh[0]).ok, true);
  assert.equal(store.account('bob').recoveryCodesLeft, RECOVERY_CODES - 1);

  // TOTP first: a passkey added later is not the first factor, and the codes stay.
  await store.createUser({ name: 'carol', passwordHash: await hash() });
  await store.beginTotp('carol');
  const codes = await store.enableTotp('carol', codeAt(store, 'carol', NOW));
  const added = await store.addPasskey('carol', passkey());
  assert.deepEqual([added.first, added.recoveryCodes], [false, null]);
  assert.equal(store.useRecoveryCode('carol', codes[0]).ok, true);
  assert.equal(store.account('carol').totp.recoveryCodesLeft, RECOVERY_CODES - 1);
  // A TOTP set up but not turned on is no second factor: the first passkey is.
  await store.createUser({ name: 'dave', passwordHash: await hash() });
  await store.beginTotp('dave');
  assert.equal((await store.addPasskey('dave', passkey())).first, true);
  assert.equal(store.totpPending('dave'), true);
  store.close();
});

test('passkeys: a reset takes them away with the TOTP and the codes, keeps the user handle, and clears them from users.db-wal', async () => {
  const configUsers = [await configUser('Alice')];
  const { store, dataDir } = await open({ configUsers });
  await store.createUser({ name: 'bob', passwordHash: await hash() });
  const has = async (b64) => (await diskBytes(dataDir)).includes(Buffer.from(b64, 'base64url'));
  const p = passkey();
  const q = passkey();
  const handle = await store.ensurePasskeyUserId('bob');
  await store.addPasskey('bob', p);
  await store.addPasskey('alice', q);
  await store.beginTotp('bob');
  await store.enableTotp('bob', codeAt(store, 'bob', NOW));
  assert.equal(await has(p.publicKey), true, 'written');
  assert.equal(await has(p.id), true, 'written');

  const waitScrub = async () => {
    for (let i = 0; i < 40 && store.scrubPending; i++) await new Promise((r) => setTimeout(r, 50));
    assert.equal(store.scrubPending, false);
  };
  await store.resetSecondFactor('bob');
  await waitScrub();
  assert.deepEqual(store.secondFactors('bob'), { totp: false, passkeys: 0, recoveryCodesLeft: 0 });
  assert.equal(store.factorRecord('bob').passkeyUserId, handle);
  assert.equal(await has(p.publicKey), false, 'the key is in neither file');
  assert.equal(await has(p.id), false, 'nor the id');
  // Removing one does the same.
  await store.removePasskey('alice', passkeyRef(q.id));
  await waitScrub();
  assert.equal(await has(q.publicKey), false);
  const again = await reopen(dataDir, { configUsers });
  assert.equal(again.factorRecord('bob').passkeyUserId, handle);
  assert.equal(await again.ensurePasskeyUserId('bob'), handle);
  assert.equal(again.secondFactorEnabled('bob'), false);
  assert.equal(again.secondFactorEnabled('alice'), false);
  again.close();
  store.close();
});

test('passkeys: a use raises the counter in memory at once and always writes it; only the time is written at most once a minute', async () => {
  const clock = { t: NOW };
  const { store, dataDir } = await open({ clock });
  await store.createUser({ name: 'bob', passwordHash: await hash() });
  const p = passkey('Key', { counter: 5, backedUp: false });
  const { ref } = await store.addPasskey('bob', p);
  const onDisk = () => credentialRows(dataDir).map((c) => [c.counter, c.backed_up, c.last_used])[0];
  assert.equal(store.usePasskey('bob', 'ffffffffffffffff', { counter: 9 }).ok, false);
  assert.equal(store.usePasskey('nobody', ref, { counter: 9 }).ok, false);
  for (const counter of [-1, 2 ** 32, 1.5, '6']) assert.throws(() => store.usePasskey('bob', ref, { counter }), TypeError);
  assert.throws(() => store.usePasskey('bob', ref, { counter: 6, backedUp: 'yes' }), TypeError);

  const first = store.usePasskey('bob', ref, { counter: 6, backedUp: false });
  assert.equal(first.ok, true);
  assert.equal(store.passkeyByRef('bob', ref).counter, 6, 'in memory at once');
  await first.saved;
  assert.deepEqual(onDisk(), [6, 0, new Date(NOW).toISOString()]);
  // Within the minute, a new counter is written all the same.
  clock.t += 1000;
  await store.usePasskey('bob', ref, { counter: 7, backedUp: false }).saved;
  assert.deepEqual(onDisk(), [7, 0, new Date(NOW + 1000).toISOString()]);
  // A lower counter never lowers it (passkeys.js refuses that use; this is a second guard).
  clock.t += 1000;
  await store.usePasskey('bob', ref, { counter: 3, backedUp: false }).saved;
  assert.equal(store.passkeyByRef('bob', ref).counter, 7);
  assert.equal(store.passkeyByRef('bob', ref).lastUsed, new Date(NOW + 2000).toISOString(), 'the time in memory');
  assert.deepEqual(onDisk(), [7, 0, new Date(NOW + 1000).toISOString()], 'only the time changed: not written yet');
  // A change of backup state is written at once.
  await store.usePasskey('bob', ref, { counter: 7, backedUp: true }).saved;
  assert.deepEqual(onDisk(), [7, 1, new Date(NOW + 2000).toISOString()]);
  clock.t += LOGIN_WRITE_MS;
  await store.usePasskey('bob', ref, { counter: 7, backedUp: true }).saved;
  assert.deepEqual(onDisk(), [7, 1, new Date(clock.t).toISOString()], 'a minute later the time is written');
  // A use found to have a change made elsewhere meanwhile is made on the fresh record too.
  const cli = await reopen(dataDir);
  await cli.renamePasskey('bob', ref, 'Renamed');
  await store.usePasskey('bob', ref, { counter: 8 }).saved;
  const back = await reopen(dataDir);
  assert.deepEqual([back.passkeyByRef('bob', ref).name, back.passkeyByRef('bob', ref).counter], ['Renamed', 8]);
  cli.close();
  back.close();
  store.close();
});

test('passkeys: added, removed or renamed by another program, picked up; adding or removing one ends sessions, a new name does not', async () => {
  const { store, dataDir } = await open();
  await store.createUser({ name: 'bob', passwordHash: await hash() });
  const calls = [];
  store.onExternalChange = (name, what) => calls.push([name, what]);
  const cli = await reopen(dataDir);
  const { ref } = await cli.addPasskey('bob', passkey('Phone'));
  assert.equal(store.refresh(), true);
  assert.deepEqual(calls, [['bob', ['second-factor']]]);
  assert.equal(store.secondFactorEnabled('bob'), true);
  calls.length = 0;
  await cli.renamePasskey('bob', ref, 'Old phone');
  await cli.usePasskey('bob', ref, { counter: 3 }).saved;
  assert.equal(store.refresh(), true);
  assert.deepEqual(calls, []);
  assert.deepEqual([store.passkeyByRef('bob', ref).name, store.passkeyByRef('bob', ref).counter], ['Old phone', 3]);
  await cli.removePasskey('bob', ref);
  store.refresh();
  assert.deepEqual(calls, [['bob', ['second-factor']]]);
  assert.equal(store.secondFactorEnabled('bob'), false);
  cli.close();
  store.close();
});

test('passkeys: a store without a database keeps them in memory', async () => {
  const store = new UserStore({ warn: () => {}, now: () => NOW });
  await store.createUser({ name: 'bob', passwordHash: await hash() });
  const { ref, recoveryCodes } = await store.addPasskey('bob', passkey());
  assert.equal(store.useRecoveryCode('bob', recoveryCodes[0]).ok, true);
  await store.usePasskey('bob', ref, { counter: 2 }).saved;
  assert.equal(store.passkeyByRef('bob', ref).counter, 2);
  assert.deepEqual(await store.removePasskey('bob', ref), { label: 'Phone', secondFactorOff: true });
});

test('store: setPassword with removeOtherPasskeys changes the password and the passkeys in one write, or neither', async () => {
  const { store } = await open();
  await store.createUser({ name: 'Bob', passwordHash: await hash() });
  const keep = passkey('Keep');
  const gone = passkey('Gone');
  await store.addPasskey('Bob', keep);
  await store.addPasskey('Bob', gone);
  const before = store.factorRecord('Bob').passwordHash;
  const next = await hash();
  // A write that fails: not the password, not the passkeys.
  const put = store.db.put.bind(store.db);
  store.db.put = () => {
    throw new Error('disk full');
  };
  await assert.rejects(store.setPassword('bob', next, { removeOtherPasskeys: { keep: passkeyRef(keep.id) } }), /disk full/);
  store.db.put = put;
  assert.equal(store.factorRecord('Bob').passwordHash, before);
  assert.equal(store.passkeys('Bob').length, 2);
  // Not asked for: the passkeys stay and nothing is counted.
  assert.deepEqual(await store.setPassword('bob', next), { removedPasskeys: null });
  assert.equal(store.passkeys('Bob').length, 2);
  // Asked for, keeping one; then all of them (null).
  assert.deepEqual(await store.setPassword('bob', await hash(), { removeOtherPasskeys: { keep: passkeyRef(keep.id) } }), { removedPasskeys: 1 });
  assert.deepEqual(store.passkeys('Bob').map((p) => p.ref), [passkeyRef(keep.id)]);
  assert.deepEqual(await store.setPassword('bob', await hash(), { removeOtherPasskeys: { keep: null } }), { removedPasskeys: 1 });
  assert.equal(store.passkeys('Bob').length, 0);
  assert.equal(store.secondFactorEnabled('Bob'), false);
  assert.deepEqual(await store.setPassword('bob', await hash(), { removeOtherPasskeys: { keep: null } }), { removedPasskeys: 0 });
  store.close();
});
