import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { Readable } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { parseArgs, run } from '../scripts/users.js';
import { hashPassword, parsePhc, verifyPassword } from '../lib/password.js';
import { LOCK_FILE, STORE_FILE, StoreChangedError, UserStore } from '../lib/users.js';
import { fakeHasher } from './helpers/fake-hasher.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const script = path.join(here, '..', 'scripts', 'users.js');
const NOW = 1_800_000_000_000;

// Runs the command line in-process, with a piped password (or none), in a data folder of its own.
async function cli(dataDir, argv, { input = '', config = null, uid = null } = {}) {
  let out = '';
  let err = '';
  const stdout = { write: (t) => (out += t) };
  const stderr = { write: (t) => (err += t) };
  const env = config ? { CONFIG_FILE: config } : {};
  const code = await run(['--data-dir', dataDir, ...argv], { stdin: Readable.from([Buffer.from(input)]), stdout, stderr, env, hasher: fakeHasher, now: () => NOW, uid });
  return { code, out, err };
}

const tmp = () => fs.mkdtemp(path.join(os.tmpdir(), 'users-cli-'));
const reopen = (dataDir, configUsers = []) => UserStore.open({ dataDir, configUsers, warn: () => {} });

async function configFile(dir, role = 'admin') {
  const file = path.join(dir, 'config.yaml');
  const h = await hashPassword('alices password', undefined, fakeHasher);
  await fs.writeFile(file, `users:\n  - name: alice\n    password_hash: '${h}'\n    role: ${role}\nnodes:\n  - address: a.test:1\n`);
  return file;
}

test('cli: the arguments never take a password, and each command its own options', () => {
  assert.throws(() => parseArgs(['create', 'bob', 'hunter2hunter2', '--role', 'admin']), /never taken as an argument/);
  assert.throws(() => parseArgs(['create', 'bob']), /--role/);
  assert.throws(() => parseArgs(['create', 'b@b', '--role', 'admin']), /letters/);
  assert.throws(() => parseArgs(['set-role', 'bob', 'root']), /role must be/);
  assert.throws(() => parseArgs(['delete', 'bob', '--generate']), /unknown option/);
  assert.throws(() => parseArgs(['reset-2fa', 'bob', '--force']), /unknown option/);
  assert.throws(() => parseArgs(['frobnicate']), /unknown command/);
  assert.throws(() => parseArgs([]), /say what to do/);
  const a = parseArgs(['create', 'bob', '--role', 'viewer', '--generate'], { DATA_DIR: '/d' });
  assert.equal(a.dataDir, '/d');
  assert.equal(a.generate, true);
  assert.equal(parseArgs(['delete', 'bob', '--force']).force, true);
});

test('cli: create a first admin with a piped password, then list; the file is 0600 and the server must restart', async () => {
  const dir = await tmp();
  const r = await cli(dir, ['create', 'root', '--role', 'admin'], { input: 'a fine long password\n' });
  assert.equal(r.code, 0, r.err);
  assert.match(r.out, /Made root \(admin\)/);
  assert.match(r.out, /Start the server again/);
  if (process.platform !== 'win32') assert.equal((await fs.stat(path.join(dir, STORE_FILE))).mode & 0o777, 0o600);
  const store = await reopen(dir);
  assert.equal(store.lookup('root').role, 'admin');
  assert.equal(store.lookup('root').mustChangePassword, false, 'their own password');
  assert.equal(await verifyPassword('a fine long password', store.find('root').phc, fakeHasher), true);
  const list = await cli(dir, ['list']);
  assert.match(list.out, /^root\tadmin\tusers\.json, two-step off, 0 devices\tlast sign in never$/m);
  assert.equal((await cli(dir, ['list'], {})).out.includes('$argon2'), false);
});

test('cli: passwords follow the website rules; a one-time password is shown once and must be changed', async () => {
  const dir = await tmp();
  for (const bad of ['short', 'password1234', 'aaaaaaaaaaaaaaaa', 'bob-bob-bob-1']) {
    const r = await cli(dir, ['create', 'bob', '--role', 'viewer'], { input: bad });
    assert.equal(r.code, 1, bad);
    assert.match(r.err, /password/i);
  }
  assert.equal((await reopen(dir)).lookup('bob'), null);
  const r = await cli(dir, ['create', 'bob', '--role', 'viewer', '--generate']);
  assert.equal(r.code, 0, r.err);
  const otp = /One-time password for bob: (\S+)/.exec(r.out)[1];
  assert.match(r.out, /shown only now/);
  const store = await reopen(dir);
  assert.equal(store.lookup('bob').mustChangePassword, true);
  assert.equal(await verifyPassword(otp, store.find('bob').phc, fakeHasher), true);
  assert.equal((await fs.readFile(path.join(dir, STORE_FILE), 'utf8')).includes(otp), false);
  // Reset: a typed one, to be changed at the next sign in.
  const reset = await cli(dir, ['reset-password', 'bob', '--must-change'], { input: 'a typed new password' });
  assert.equal(reset.code, 0, reset.err);
  const again = await reopen(dir);
  assert.equal(await verifyPassword('a typed new password', again.find('bob').phc, fakeHasher), true);
  assert.equal(again.lookup('bob').mustChangePassword, true);
  assert.equal((await cli(dir, ['create', 'BOB', '--role', 'viewer', '--generate'])).code, 1, 'exists, in any case');
});

test('cli: the last admin is kept unless --force; admins in the config file count', async () => {
  const dir = await tmp();
  await cli(dir, ['create', 'root', '--role', 'admin', '--generate']);
  let r = await cli(dir, ['set-role', 'root', 'viewer']);
  assert.equal(r.code, 1);
  assert.match(r.err, /last admin/);
  r = await cli(dir, ['delete', 'root']);
  assert.equal(r.code, 1);
  assert.equal((await reopen(dir)).lookup('root').role, 'admin');
  // With the config file, alice (admin) counts.
  const config = await configFile(dir);
  r = await cli(dir, ['set-role', 'root', 'viewer'], { config });
  assert.equal(r.code, 0, r.err);
  // A config user cannot be changed here, and their name cannot be taken.
  assert.match((await cli(dir, ['delete', 'alice'], { config })).err, /config file/);
  assert.match((await cli(dir, ['create', 'Alice', '--role', 'viewer', '--generate'], { config })).err, /exists/);
  // --force: recovery.
  await cli(dir, ['set-role', 'root', 'admin'], { config });
  r = await cli(dir, ['delete', 'root', '--force']);
  assert.equal(r.code, 0, r.err);
  assert.match(r.out, /there is no admin now/);
});

test('cli: reset-2fa removes the second factor, recovery codes and devices, of website and config users', async () => {
  const dir = await tmp();
  const config = await configFile(dir);
  await cli(dir, ['create', 'bob', '--role', 'viewer', '--generate']);
  const configUsers = [{ name: 'alice', phc: parsePhc(await hashPassword('alices password', undefined, fakeHasher)), role: 'admin' }];
  const store = await reopen(dir, configUsers);
  for (const name of ['bob', 'alice']) {
    await store.beginTotp(name);
    store.factorRecord(name).totp.enabled = true;
    store.factorRecord(name).recoveryCodes = ['a'.repeat(64)];
    await store.addDevice(name, 'b'.repeat(64));
  }
  await store.flush();
  assert.equal((await cli(dir, ['reset-2fa', 'bob'])).code, 0);
  const noConfig = await cli(dir, ['reset-2fa', 'alice']);
  assert.equal(noConfig.code, 1);
  assert.match(noConfig.err, /needs --config/);
  assert.equal((await cli(dir, ['reset-2fa', 'alice'], { config })).code, 0);
  const after = await reopen(dir, configUsers);
  for (const name of ['bob', 'alice']) {
    assert.equal(after.secondFactorEnabled(name), false, name);
    assert.deepEqual(after.factorRecord(name).recoveryCodes, [], name);
    assert.equal(after.devices(name).length, 0, name);
  }
});

test('cli: a users.json that cannot be read is left as it is, and nothing is done', async () => {
  const dir = await tmp();
  const file = path.join(dir, STORE_FILE);
  await fs.writeFile(file, '{not json', { mode: 0o600 });
  const r = await cli(dir, ['create', 'root', '--role', 'admin', '--generate']);
  assert.equal(r.code, 1);
  assert.match(r.err, /cannot be used: it is not valid JSON/);
  assert.equal(await fs.readFile(file, 'utf8'), '{not json');
});

test('cli: a user moved out of the config file starts without the old second factor, which is said', async () => {
  const dir = await tmp();
  const config = await configFile(dir, 'viewer');
  const configUsers = [{ name: 'alice', phc: parsePhc(await hashPassword('alices password', undefined, fakeHasher)), role: 'viewer' }];
  const store = await reopen(dir, configUsers);
  await store.addDevice('alice', 'c'.repeat(64));
  await store.flush();
  assert.ok(config);
  // alice is taken out of the config file, then made in the store.
  const r = await cli(dir, ['create', 'alice', '--role', 'admin', '--generate']);
  assert.equal(r.code, 0, r.err);
  assert.match(r.out, /still has the two-step sign-in and devices alice had as a config file user/);
  const after = await reopen(dir);
  assert.equal(after.lookup('alice').source, 'store');
  assert.equal(after.devices('alice').length, 0);
});

test('cli: runs as a program', { skip: !process.versions.node || Number(process.versions.node.split('.')[0]) < 24 }, async () => {
  const dir = await tmp();
  const out = await new Promise((resolve) => {
    execFile(process.execPath, [script, '--data-dir', dir, 'list'], (err, stdout, stderr) => resolve({ err, stdout, stderr }));
  });
  assert.equal(out.err, null, out.stderr);
  assert.match(out.stdout, /No users\.\nThere is no admin/);
});

test('cli: an unknown option or command is not repeated, since it may be a password', () => {
  for (const argv of [['delete', 'bob', '--hunter2hunter2'], ['--Sekrit-Pass', 'list'], ['hunter2hunter2']]) {
    assert.throws(() => parseArgs(argv), (e) => /unknown (option|command)/.test(e.message) && !/hunter2|Sekrit/.test(e.message), argv.join(' '));
  }
  assert.throws(() => parseArgs(['list', '--server-stopped']), /unknown option for list/);
  assert.equal(parseArgs(['delete', 'bob', '--server-stopped']).serverStopped, true);
});

test('cli: a change is refused while users.lock is recent, unless --server-stopped; list still works', async () => {
  const dir = await tmp();
  const lock = path.join(dir, LOCK_FILE);
  await fs.writeFile(lock, 'started');
  const recent = new Date(NOW - 5_000);
  await fs.utimes(lock, recent, recent);
  const r = await cli(dir, ['create', 'root', '--role', 'admin', '--generate']);
  assert.equal(r.code, 1);
  assert.match(r.err, /server seems to be running: users\.lock .* 5 seconds ago/);
  assert.match(r.err, /--server-stopped/);
  await assert.rejects(fs.access(path.join(dir, STORE_FILE)), 'nothing written');
  assert.equal((await cli(dir, ['list'])).code, 0);
  const forced = await cli(dir, ['create', 'root', '--role', 'admin', '--generate', '--server-stopped']);
  assert.equal(forced.code, 0, forced.err);
  // A lock from a server that stopped without removing it (killed) is old after 30 seconds.
  const old = new Date(NOW - 31_000);
  await fs.utimes(lock, old, old);
  assert.equal((await cli(dir, ['set-role', 'root', 'viewer', '--force'])).code, 0);
});

test('cli: a server that read users.json before the command line changed it does not write over the change', async () => {
  const dir = await tmp();
  await cli(dir, ['create', 'root', '--role', 'admin', '--generate']);
  const logs = [];
  const server = await UserStore.open({ dataDir: dir, warn: () => {}, log: (m) => logs.push(m) });
  assert.equal((await cli(dir, ['create', 'bob', '--role', 'viewer', '--generate'])).code, 0);
  await assert.rejects(server.addDevice('root', 'a'.repeat(64)), StoreChangedError);
  assert.ok((await reopen(dir)).lookup('bob'), 'the change of the command line is kept');
  assert.match(logs[0], /users\.json changed on disk; restart the website to load it/);
});

test('cli: run as root without a users.json, it warns that the file will be root\'s', async () => {
  const dir = await tmp();
  const r = await cli(dir, ['create', 'root', '--role', 'admin', '--generate'], { uid: 0 });
  assert.equal(r.code, 0, r.err);
  assert.match(r.err, /running as root, so the new users\.json is owned by root/);
  assert.doesNotMatch((await cli(dir, ['create', 'bob', '--role', 'viewer', '--generate'], { uid: 0 })).err, /running as root/, 'the file exists: its owner is kept');
  assert.doesNotMatch((await cli(await tmp(), ['create', 'root', '--role', 'admin', '--generate'], { uid: 1000 })).err, /running as root/);
});

test('cli: run as root, the users.json it writes keeps its owner', { skip: process.platform === 'win32' || process.getuid?.() !== 0 }, async () => {
  const dir = await tmp();
  await cli(dir, ['create', 'root', '--role', 'admin', '--generate']);
  const file = path.join(dir, STORE_FILE);
  await fs.chown(file, 1000, 1000);
  assert.equal((await cli(dir, ['create', 'bob', '--role', 'viewer', '--generate'], { uid: 0 })).code, 0);
  const st = await fs.stat(file);
  assert.deepEqual([st.uid, st.gid, st.mode & 0o777], [1000, 1000, 0o600]);
});
