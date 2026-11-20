import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { hashPassword, parsePhc } from '../lib/password.js';
import {
  CHANGED_ON_DISK, LOCK_FILE, LOCK_FRESH_MS, MAX_DEVICES, MAX_STORE_BYTES, MAX_STORE_USERS, RECOVERY_CODES, STORE_FILE, StoreChangedError, StoreError, StoreFullError, UserError, UserStore,
  hashRecoveryCode, serverHeartbeat, startHeartbeat, worstCaseStoreBytes, writeAtomic, writeRefusal,
} from '../lib/users.js';
import { base32Decode, hotp, stepAt } from '../lib/totp.js';
import { FAILURES_FILE, createAudit, createFailureLog } from '../lib/audit.js';
import { fakeHasher } from './helpers/fake-hasher.js';

const NOW = 1_800_000_000_000;
const tmp = () => fs.mkdtemp(path.join(os.tmpdir(), 'users-'));
const hash = (pw = 'a good password') => hashPassword(pw, undefined, fakeHasher);

async function configUser(name, role) {
  return { name, phc: parsePhc(await hash()), ...(role ? { role } : {}) };
}

async function open({ dir, configUsers = [], warn = () => {}, clock = { t: NOW } } = {}) {
  const dataDir = dir ?? (await tmp());
  const store = await UserStore.open({ dataDir, configUsers, warn, now: () => clock.t });
  return { store, dataDir, file: path.join(dataDir, STORE_FILE), clock };
}

const codeAt = (store, name, t, offset = 0) => hotp(base32Decode(store.factorRecord(name).totp.secret), stepAt(t) + offset);

test('store: a missing file is an empty store, and nothing is written until something changes', async () => {
  const { store, dataDir } = await open();
  assert.equal(store.hasLocalUsers(), false);
  assert.equal(store.find('nobody'), null);
  assert.deepEqual(await fs.readdir(dataDir), []);
});

test('store: create, find, set role, set password and delete website users; the file is 0600 and written whole', async () => {
  const { store, file, dataDir } = await open();
  await store.createUser({ name: 'Bob', role: 'admin', passwordHash: await hash() });
  await store.createUser({ name: 'carol', passwordHash: await hash() });
  assert.equal(store.hasLocalUsers(), true);
  assert.deepEqual({ ...store.find('  BOB '), phc: undefined }, { name: 'Bob', role: 'admin', source: 'store', phc: undefined });
  assert.equal(store.find('carol').role, 'viewer');
  if (process.platform !== 'win32') assert.equal((await fs.stat(file)).mode & 0o777, 0o600);
  // Only the file itself: no temporary file is left behind.
  assert.deepEqual(await fs.readdir(dataDir), [STORE_FILE]);
  await store.setRole('carol', 'manage');
  const newHash = await hash('another password');
  await store.setPassword('carol', newHash);
  const again = await UserStore.open({ dataDir, warn: () => {} });
  assert.equal(again.find('carol').role, 'manage');
  assert.deepEqual(again.find('carol').phc.hash, parsePhc(newHash).hash);
  await again.deleteUser('carol');
  assert.equal(again.find('carol'), null);
  assert.equal((await UserStore.open({ dataDir, warn: () => {} })).find('carol'), null);
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
  const first = await UserStore.open({ dataDir, warn: () => {} });
  await first.createUser({ name: 'alice', role: 'admin', passwordHash: await hash('store password') });
  const warnings = [];
  const config = await configUser('Alice', 'viewer');
  const store = await UserStore.open({ dataDir, configUsers: [config], warn: (w) => warnings.push(w) });
  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /"alice" is also in the config file/);
  assert.equal(store.find('alice').source, 'config');
  assert.equal(store.find('alice').role, 'viewer');
  assert.equal(store.hasLocalUsers(), false);
  assert.deepEqual(store.list(), [{ name: 'Alice', role: 'viewer', source: 'config' }]);
});

test('store: a corrupt, unknown or newer file stops the start with a message, and is left as it is', async () => {
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
    const err = await UserStore.open({ dataDir, warn: () => {} }).then(() => null, (e) => e);
    assert.ok(err instanceof StoreError, text);
    assert.match(err.message, why, text);
    assert.match(err.message, /left as it is/);
    // The message never repeats a hash or secret.
    assert.equal(err.message.includes(good.users[0].passwordHash), false);
    assert.equal(err.message.includes('JBSWY3DP'), false);
    assert.equal(await fs.readFile(file, 'utf8'), text);
  }
  // A folder in its place is refused too.
  const dataDir = await tmp();
  await fs.mkdir(path.join(dataDir, STORE_FILE));
  await assert.rejects(UserStore.open({ dataDir, warn: () => {} }), StoreError);
});

test('store: keys this version does not know are kept when the file is written again', async () => {
  const { dataDir, file } = await open();
  await fs.writeFile(file, JSON.stringify({ version: 1, future: { x: 1 }, users: [{ name: 'bob', role: 'viewer', passwordHash: await hash(), passkeyHint: 'later' }] }), { mode: 0o600 });
  const store = await UserStore.open({ dataDir, warn: () => {} });
  await store.setRole('bob', 'manage');
  const data = JSON.parse(await fs.readFile(file, 'utf8'));
  assert.deepEqual(data.future, { x: 1 });
  assert.equal(data.users[0].passkeyHint, 'later');
  assert.equal(data.users[0].role, 'manage');
});

test('store: a file others can read is warned about', { skip: process.platform === 'win32' }, async () => {
  const { dataDir, file } = await open();
  await fs.writeFile(file, JSON.stringify({ version: 1, users: [] }), { mode: 0o644 });
  await fs.chmod(file, 0o644);
  const warnings = [];
  await UserStore.open({ dataDir, warn: (w) => warnings.push(w) });
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
  const again = await UserStore.open({ dataDir, warn: () => {}, now: () => clock.t });
  assert.equal(again.checkTotp('bob', next).ok, false);
  const text = JSON.stringify(store.account('bob'));
  assert.equal(text.includes(secret2), false);
  for (const c of codes) assert.equal(text.includes(c), false);
  assert.deepEqual(store.account('bob').totp, { enabled: true, recoveryCodesLeft: RECOVERY_CODES });
  // On disk: the secret as it is, the recovery codes only hashed.
  const disk = await fs.readFile(path.join(dataDir, STORE_FILE), 'utf8');
  assert.ok(disk.includes(secret2));
  for (const c of codes) {
    assert.equal(disk.includes(c), false);
    assert.ok(disk.includes(hashRecoveryCode(c)));
  }
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
  const { store, file } = await open({ configUsers: [await configUser('Alice', 'admin')], clock });
  await store.recordLogin('alice');
  await assert.rejects(fs.access(file));
  await store.beginTotp('alice');
  clock.t += 60_000;
  await store.recordLogin('alice');
  const data = JSON.parse(await fs.readFile(file, 'utf8'));
  assert.deepEqual(data.users, []);
  assert.equal(data.configUsers.length, 1);
  assert.equal(data.configUsers[0].name, 'Alice');
  assert.equal(data.configUsers[0].lastLogin, new Date(NOW + 60_000).toISOString());
  assert.equal('role' in data.configUsers[0], false);
  assert.equal('passwordHash' in data.configUsers[0], false);
  assert.deepEqual(data.configUsers[0].credentials, []);
});

test('store: a failed write is reported to the caller and the next write still works', async () => {
  const { store, dataDir, file } = await open();
  await store.createUser({ name: 'bob', passwordHash: await hash() });
  // A folder where the temporary file goes makes the write fail.
  await fs.mkdir(`${file}.${process.pid}.tmp`);
  await fs.writeFile(path.join(`${file}.${process.pid}.tmp`, 'x'), 'x');
  await assert.rejects(store.setRole('bob', 'manage'));
  await fs.rm(`${file}.${process.pid}.tmp`, { recursive: true });
  await store.setRole('bob', 'admin');
  assert.equal((await UserStore.open({ dataDir, warn: () => {} })).find('bob').role, 'admin');
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

// Makes the next writes of the store fail, until the returned function is called.
async function breakWrites(file) {
  const tmpPath = `${file}.${process.pid}.tmp`;
  await fs.mkdir(tmpPath);
  await fs.writeFile(path.join(tmpPath, 'x'), 'x');
  return () => fs.rm(tmpPath, { recursive: true });
}

test('store: a change whose write fails is not made in memory either', async () => {
  const clock = { t: NOW };
  const { store, file, dataDir } = await open({ clock, configUsers: [await configUser('Alice', 'admin')] });
  await store.createUser({ name: 'bob', role: 'admin', passwordHash: await hash() });
  await store.createUser({ name: 'carol', passwordHash: await hash() });
  const before = await fs.readFile(file, 'utf8');
  let fix = await breakWrites(file);
  // Password, role, delete and create: all refused, nothing changed.
  const oldHash = store.find('bob').phc.hash;
  await assert.rejects(store.setPassword('bob', await hash('a new password')));
  assert.deepEqual(store.find('bob').phc.hash, oldHash);
  await assert.rejects(store.setRole('carol', 'manage'));
  assert.equal(store.find('carol').role, 'viewer');
  await assert.rejects(store.deleteUser('carol'));
  assert.ok(store.find('carol'));
  await assert.rejects(store.createUser({ name: 'dave', passwordHash: await hash() }));
  assert.equal(store.find('dave'), null);
  // Second factor: a set up of a config user leaves no record behind.
  await assert.rejects(store.beginTotp('alice'));
  assert.equal(store.factorRecord('alice'), null);
  await fix();
  await store.beginTotp('bob');
  const secret = store.factorRecord('bob').totp.secret;
  fix = await breakWrites(file);
  await assert.rejects(store.enableTotp('bob', codeAt(store, 'bob', NOW)));
  assert.equal(store.secondFactorEnabled('bob'), false);
  assert.deepEqual(store.factorRecord('bob').recoveryCodes, []);
  await fix();
  const codes = await store.enableTotp('bob', codeAt(store, 'bob', NOW));
  assert.equal(store.factorRecord('bob').totp.secret, secret);
  fix = await breakWrites(file);
  const hashes = [...store.factorRecord('bob').recoveryCodes];
  await assert.rejects(store.newRecoveryCodes('bob'));
  assert.deepEqual(store.factorRecord('bob').recoveryCodes, hashes);
  await assert.rejects(store.disableTotp('bob'));
  assert.equal(store.secondFactorEnabled('bob'), true);
  await assert.rejects(store.resetSecondFactor('bob'));
  assert.equal(store.secondFactorEnabled('bob'), true);
  await fix();
  // What is in memory is what is on disk.
  const again = await UserStore.open({ dataDir, configUsers: [await configUser('Alice', 'admin')], warn: () => {} });
  assert.equal(again.secondFactorEnabled('bob'), true);
  assert.equal(again.useRecoveryCode('bob', codes[0]).ok, true);
  assert.notEqual(before, await fs.readFile(file, 'utf8'));
});

test('store: two changes at once to different users are both kept on disk', async () => {
  const { store, dataDir } = await open();
  await store.createUser({ name: 'bob', passwordHash: await hash() });
  await store.createUser({ name: 'carol', passwordHash: await hash() });
  await Promise.all([store.setRole('bob', 'manage'), store.setRole('carol', 'admin'), store.beginTotp('bob')]);
  const again = await UserStore.open({ dataDir, warn: () => {} });
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
  const { SECTIONS } = await import('../lib/access.js');
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

test('server: with users only in users.json, a config with login settings starts and every section is locked', async () => {
  const { spawn } = await import('node:child_process');
  const { fileURLToPath } = await import('node:url');
  const net = await import('node:net');
  const { SECTIONS } = await import('../lib/access.js');
  const dataDir = await tmp();
  const seed = await UserStore.open({ dataDir, warn: () => {} });
  await seed.createUser({ name: 'bob', role: 'admin', passwordHash: await hashPassword('a good password') });
  const config = path.join(dataDir, 'config.yaml');
  await fs.writeFile(config, "login:\n  trusted_proxies: ['127.0.0.1']\nnodes:\n  - address: 127.0.0.1:9\n");
  const port = await new Promise((resolve) => {
    const probe = net.createServer().listen(0, '127.0.0.1', () => {
      const p = probe.address().port;
      probe.close(() => resolve(p));
    });
  });
  const server = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'server.js');
  const child = spawn(process.execPath, [server], { env: { PATH: process.env.PATH, DATA_DIR: dataDir, CONFIG_FILE: config, PORT: String(port), HOST: '127.0.0.1' }, stdio: ['ignore', 'pipe', 'pipe'] });
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
  await store.saving;
  const again = await UserStore.open({ dataDir, configUsers: [await configUser('alice')], warn: () => {} });
  assert.deepEqual(again.devices('bob').map((d) => d.hash), [h('a')]);
  assert.equal(again.hasDevice('alice', h('f')), true);
  assert.deepEqual(store.dropDevices('bob', { only: h('a') }).removed, 1);
  assert.deepEqual(store.dropDevices('nobody').removed, 0);
});

test('store: a guard that says no refuses the change with UserError gone, and nothing is written', async () => {
  const { store, dataDir } = await open();
  await store.createUser({ name: 'bob', passwordHash: await hash() });
  const before = await fs.readFile(path.join(dataDir, STORE_FILE), 'utf8');
  await assert.rejects(store.setPassword('bob', await hash('another one'), { guard: () => false }), (e) => e instanceof UserError && e.code === 'gone');
  await assert.rejects(store.beginTotp('bob', { guard: () => false }), (e) => e.code === 'gone');
  assert.equal(await fs.readFile(path.join(dataDir, STORE_FILE), 'utf8'), before);
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

test('store: flush waits for every write, also those asked for meanwhile; touchLogin writes at most once a minute', async () => {
  const { store, file, clock } = await open();
  await store.createUser({ name: 'alice', passwordHash: await hash() });
  let writes = 0;
  const save = store.save.bind(store);
  store.save = () => (writes++, save());
  store.touchLogin('alice');
  store.touchLogin('alice');
  assert.equal(writes, 1);
  await store.flush();
  assert.equal(JSON.parse(await fs.readFile(file, 'utf8')).users[0].lastLogin, new Date(clock.t).toISOString());
  clock.t += 59_000;
  store.touchLogin('alice');
  assert.equal(writes, 1);
  assert.equal(store.account('alice').lastLogin, new Date(clock.t).toISOString(), 'in memory at once');
  clock.t += 1000;
  store.touchLogin('alice');
  assert.equal(writes, 2);
  // A write asked for while flush waits is waited for too.
  const flushed = store.flush();
  store.addDevice('alice', 'a'.repeat(64));
  await flushed;
  assert.equal(JSON.parse(await fs.readFile(file, 'utf8')).users[0].devices.length, 1);
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
  const { store, dataDir, file } = await open();
  await store.createUser({ name: 'bob', passwordHash: await hash(), mustChangePassword: true });
  await store.createUser({ name: 'carol', passwordHash: await hash() });
  assert.equal(store.lookup('bob').mustChangePassword, true);
  assert.equal(store.lookup('carol').mustChangePassword, false);
  const disk = JSON.parse(await fs.readFile(file, 'utf8'));
  assert.equal(disk.users.find((u) => u.name === 'bob').mustChangePassword, true);
  assert.equal(Object.hasOwn(disk.users.find((u) => u.name === 'carol'), 'mustChangePassword'), false, 'older versions read the same file');
  const again = await UserStore.open({ dataDir, warn: () => {} });
  assert.equal(again.lookup('bob').mustChangePassword, true);
  // Their own new password clears it; an admin's reset sets it again.
  await again.setPassword('bob', await hash('bobs own password'));
  assert.equal(again.lookup('bob').mustChangePassword, false);
  assert.equal(Object.hasOwn(JSON.parse(await fs.readFile(file, 'utf8')).users.find((u) => u.name === 'bob'), 'mustChangePassword'), false);
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
  assert.deepEqual(list[1], { name: 'bob', role: 'manage', source: 'store', secondFactor: false, devices: 1, lastLogin: null, created: new Date(NOW).toISOString(), mustChangePassword: true });
  assert.deepEqual(list[2], { name: 'Zed', role: 'admin', source: 'config', secondFactor: false, devices: 0, lastLogin: null, created: null, mustChangePassword: false });
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

test('store: the largest file MAX_STORE_USERS users make is below the read limit, which the old 1 MiB was not', () => {
  const one = worstCaseStoreBytes(1);
  const two = worstCaseStoreBytes(2);
  // Two lists of that many records each: the size grows by two records per user.
  const perUser = two - one;
  assert.ok(perUser > 2 * 3000 && perUser < 2 * 5000, `${perUser} bytes per user`);
  assert.ok(worstCaseStoreBytes(MAX_STORE_USERS) <= MAX_STORE_BYTES);
  assert.ok(worstCaseStoreBytes(MAX_STORE_USERS) > 1024 * 1024);
  assert.equal(worstCaseStoreBytes(MAX_STORE_USERS), one + (MAX_STORE_USERS - 1) * perUser);
});

test('store: filled to the cap with every field at its most, it is written and read back; more is refused and changes nothing', async () => {
  const maxUsers = 4;
  const maxBytes = worstCaseStoreBytes(maxUsers);
  const clock = { t: NOW };
  const dataDir = await tmp();
  const configUsers = [await configUser('Alice', 'admin'), await configUser('Carol', 'viewer')];
  const store = await UserStore.open({ dataDir, configUsers, warn: () => {}, now: () => clock.t, maxUsers, maxBytes });
  await store.createUser({ name: 'b'.repeat(32), role: 'manage', passwordHash: await hash(), mustChangePassword: true });
  await store.createUser({ name: 'd'.repeat(32), role: 'manage', passwordHash: await hash(), mustChangePassword: true });
  for (const name of ['b'.repeat(32), 'd'.repeat(32), 'alice', 'carol']) {
    await store.beginTotp(name);
    await store.enableTotp(name, codeAt(store, name, clock.t));
    for (let i = 0; i < MAX_DEVICES + 3; i++) await store.addDevice(name, crypto.createHash('sha256').update(`${name}${i}`).digest('hex'));
    await store.recordLogin(name);
  }
  await assert.rejects(store.createUser({ name: 'eve', passwordHash: await hash() }), (e) => e instanceof UserError && e.code === 'full');
  const size = (await fs.stat(path.join(dataDir, STORE_FILE))).size;
  assert.ok(size <= maxBytes, `${size} > ${maxBytes}`);
  const again = await UserStore.open({ dataDir, configUsers, warn: () => {}, maxUsers, maxBytes });
  assert.equal(again.devices('alice').length, MAX_DEVICES);
  assert.equal(again.secondFactorEnabled('d'.repeat(32)), true);
  // A file larger than the limit (unknown keys from a newer version, say) is not written.
  const before = await fs.readFile(path.join(dataDir, STORE_FILE), 'utf8');
  store.extra.padding = 'x'.repeat(maxBytes);
  await assert.rejects(store.setRole('b'.repeat(32), 'viewer'), (e) => e instanceof StoreFullError && writeRefusal(e).includes('full'));
  assert.equal(store.lookup('b'.repeat(32)).role, 'manage', 'nothing changed in memory');
  assert.equal(await fs.readFile(path.join(dataDir, STORE_FILE), 'utf8'), before);
  // And one the server finds larger than it reads stops the start.
  await assert.rejects(UserStore.open({ dataDir, warn: () => {}, maxBytes: size - 1 }), /larger than/);
});

test('store: a users.json changed on disk is never written over; the server says so once a minute until restarted', async () => {
  const clock = { t: NOW };
  const logs = [];
  const dataDir = await tmp();
  const store = await UserStore.open({ dataDir, warn: () => {}, now: () => clock.t, log: (m) => logs.push(m) });
  await store.createUser({ name: 'bob', role: 'admin', passwordHash: await hash() });
  await store.createUser({ name: 'carol', passwordHash: await hash() });
  // Another writer (scripts/users.js) changes the file meanwhile.
  const other = await UserStore.open({ dataDir, warn: () => {} });
  await other.setRole('carol', 'manage');
  const theirs = await fs.readFile(path.join(dataDir, STORE_FILE), 'utf8');
  await assert.rejects(store.setRole('carol', 'admin'), (e) => e instanceof StoreChangedError && /restart the website/i.test(writeRefusal(e)));
  assert.equal(store.lookup('carol').role, 'viewer');
  // Writes made in memory first (a sign in, a device) are not written either.
  await assert.rejects(store.addDevice('bob', 'a'.repeat(64)), StoreChangedError);
  clock.t += 30_000;
  await assert.rejects(store.recordLogin('bob'), StoreChangedError);
  assert.equal(await fs.readFile(path.join(dataDir, STORE_FILE), 'utf8'), theirs);
  assert.deepEqual(logs, [`error: ${CHANGED_ON_DISK}. Nothing is written to it until then, so changes made on the website meanwhile are not saved`]);
  clock.t += 60_000;
  await assert.rejects(store.recordLogin('bob'), StoreChangedError);
  assert.equal(logs.length, 2);
  // A file removed, or put there when there was none, counts as changed too.
  const empty = await UserStore.open({ dataDir: await tmp(), warn: () => {}, log: () => {} });
  await fs.writeFile(path.join(path.dirname(empty.file), STORE_FILE), theirs);
  await assert.rejects(empty.createUser({ name: 'dave', passwordHash: await hash() }), StoreChangedError);
  const removed = await UserStore.open({ dataDir, warn: () => {}, log: () => {} });
  await fs.rm(path.join(dataDir, STORE_FILE));
  await assert.rejects(removed.setRole('carol', 'viewer'), StoreChangedError);
  await assert.rejects(fs.access(path.join(dataDir, STORE_FILE)));
});

test('store: a password typed by an admin is refused for an admin, also when they became one meanwhile', async () => {
  const { store } = await open();
  await store.createUser({ name: 'bob', role: 'admin', passwordHash: await hash() });
  await store.createUser({ name: 'carol', role: 'viewer', passwordHash: await hash() });
  await assert.rejects(store.setPassword('bob', await hash('another password'), { typedForAdmin: true }), (e) => e.code === 'admin-password');
  await store.setPassword('carol', await hash('another password'), { typedForAdmin: true });
  await store.setPassword('bob', await hash('another password'));
  // setRole gives the role right before its change.
  assert.equal(await store.setRole('carol', 'manage'), 'viewer');
});

test('writeAtomic keeps the owner and group of the file it replaces', { skip: process.platform === 'win32' || process.getuid?.() !== 0 }, async () => {
  const dir = await tmp();
  const file = path.join(dir, STORE_FILE);
  await fs.writeFile(file, '{}', { mode: 0o600 });
  await fs.chown(file, 4321, 4322);
  await writeAtomic(file, '{"a":1}');
  const st = await fs.stat(file);
  assert.deepEqual([st.uid, st.gid, st.mode & 0o777], [4321, 4322, 0o600]);
  assert.equal(await fs.readFile(file, 'utf8'), '{"a":1}');
  // A new file is the writer's own.
  const fresh = path.join(dir, 'new.json');
  await writeAtomic(fresh, '{}');
  assert.equal((await fs.stat(fresh)).uid, process.getuid());
});

test('heartbeat: users.lock is written at start, touched while the server runs, and removed when it stops', async () => {
  const dataDir = await tmp();
  const logs = [];
  const beat = await startHeartbeat({ dataDir, intervalMs: 10, log: (m) => logs.push(m) });
  assert.match(await fs.readFile(path.join(dataDir, LOCK_FILE), 'utf8'), /^started \d{4}-\d{2}-\d{2}T/);
  assert.notEqual(await serverHeartbeat(dataDir), null);
  // An old file is touched again.
  const old = new Date(Date.now() - 120_000);
  await fs.utimes(path.join(dataDir, LOCK_FILE), old, old);
  assert.equal(await serverHeartbeat(dataDir), null);
  for (let i = 0; i < 200 && (await serverHeartbeat(dataDir)) === null; i++) await new Promise((r) => setTimeout(r, 5));
  assert.notEqual(await serverHeartbeat(dataDir), null);
  // A file removed meanwhile is written again.
  await fs.rm(path.join(dataDir, LOCK_FILE));
  for (let i = 0; i < 200 && (await serverHeartbeat(dataDir)) === null; i++) await new Promise((r) => setTimeout(r, 5));
  assert.notEqual(await serverHeartbeat(dataDir), null);
  await beat.stop();
  await assert.rejects(fs.access(path.join(dataDir, LOCK_FILE)));
  assert.equal(await serverHeartbeat(dataDir), null);
  assert.deepEqual(logs, []);
  // A file in the future counts as a running server; one older than LOCK_FRESH_MS does not.
  await fs.writeFile(path.join(dataDir, LOCK_FILE), '');
  assert.notEqual(await serverHeartbeat(dataDir, Date.now() - 60_000), null);
  assert.equal(await serverHeartbeat(dataDir, Date.now() + LOCK_FRESH_MS + 1000), null);
});
