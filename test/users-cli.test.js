import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { Readable } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import { TIMEOUT_MS, UnsafeError, dropPrivileges, keyUsageLines, newKeyLine, parseArgs, run } from '../scripts/users.js';
import { hashPassword, parsePhc, verifyPassword } from '../lib/password.js';
import { Keyring, parseKeys } from '../lib/keys.js';
import { STORE_FILE, UserStore } from '../lib/users.js';
import { DB_FILE, RETIRED_FILE, openUserDb } from '../lib/userdb.js';
import { createLogin } from '../lib/login.js';
import { createPasskeys } from '../lib/passkeys.js';
import { SoftAuthenticator } from './helpers/soft-authenticator.js';
import { fakeHasher } from './helpers/fake-hasher.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const script = path.join(here, '..', 'scripts', 'users.js');
const NOW = 1_800_000_000_000;
const quiet = () => {};

const master = () => crypto.randomBytes(32);
const line = (v, k) => `${v}:${k.toString('base64url')}`;
// One key for most tests, as the server and the command line would share it.
const KEY1 = master();
const ENV = { USERS_KEY: line(1, KEY1) };
const keyring = (entries = [[1, KEY1]]) => new Keyring(new Map(entries));

// Runs the command line in-process, with a piped password (or none), in a data folder of its own.
// drop stands in for dropping root's privileges, which would change the test process itself: the
// tests that need the real one run the command line as a process of its own (see runAs).
async function cli(dataDir, argv, { input = '', config = null, uid = null, env = ENV, cwd = process.cwd(), timeoutMs, drop = () => null } = {}) {
  let out = '';
  let err = '';
  const stdout = { write: (t) => (out += t) };
  const stderr = { write: (t) => (err += t) };
  const all = { ...env, ...(config ? { CONFIG_FILE: config } : {}) };
  const code = await run(['--data-dir', dataDir, ...argv], { stdin: Readable.from([Buffer.from(input)]), stdout, stderr, env: all, hasher: fakeHasher, now: () => NOW, uid, cwd, timeoutMs, drop });
  return { code, out, err };
}

const tmp = () => fs.mkdtemp(path.join(os.tmpdir(), 'users-cli-'));
const opened = new Set();
// The store as the server sees it; closed when the test ends.
async function reopen(dataDir, configUsers = [], keys = keyring()) {
  const store = await UserStore.open({ dataDir, configUsers, keys, warn: quiet });
  opened.add(store);
  return store;
}
test.afterEach(() => {
  for (const s of opened) s.close();
  opened.clear();
});

async function configFile(dir, role = 'admin') {
  const file = path.join(dir, 'config.yaml');
  const h = await hashPassword('alices password', undefined, fakeHasher);
  await fs.writeFile(file, `users:\n  - name: alice\n    password_hash: '${h}'\n    role: ${role}\nnodes:\n  - address: a.test:1\n`);
  return file;
}

const pepperOf = (store, name) => {
  const u = store.find(name);
  return u.secret;
};

test('cli: the arguments never take a password, and each command its own options', () => {
  assert.throws(() => parseArgs(['create', 'bob', 'hunter2hunter2', '--role', 'admin']), /never taken as an argument/);
  assert.throws(() => parseArgs(['create', 'bob']), /--role/);
  assert.throws(() => parseArgs(['create', 'b@b', '--role', 'admin']), /letters/);
  assert.throws(() => parseArgs(['set-role', 'bob', 'root']), /role must be/);
  assert.throws(() => parseArgs(['delete', 'bob', '--generate']), /unknown option/);
  assert.throws(() => parseArgs(['reset-2fa', 'bob', '--force']), /unknown option/);
  assert.throws(() => parseArgs(['frobnicate']), /unknown command/);
  assert.throws(() => parseArgs([]), /say what to do/);
  assert.throws(() => parseArgs(['backup']), /backup needs a file/);
  assert.throws(() => parseArgs(['backup', 'a', 'b']), /too many/);
  assert.throws(() => parseArgs(['check', 'x']), /too many/);
  assert.throws(() => parseArgs(['rekey', '--force']), /unknown option/);
  assert.throws(() => parseArgs(['list', '--version', '2']), /unknown option/);
  const a = parseArgs(['create', 'bob', '--role', 'viewer', '--generate'], { DATA_DIR: '/d' });
  assert.equal(a.dataDir, '/d');
  assert.equal(a.generate, true);
  assert.equal(parseArgs(['delete', 'bob', '--force']).force, true);
  // A backup file is a path, not a user name.
  assert.deepEqual(parseArgs(['backup', '/backups/users 1.db']).args, ['/backups/users 1.db']);
});

test('cli: gen-key prints one key line that the key parser reads; --version picks the version', async () => {
  const dir = await tmp();
  const r = await cli(dir, ['gen-key'], { env: {} });
  assert.equal(r.code, 0, r.err);
  assert.match(r.out, /^1:[A-Za-z0-9_-]{43}\n$/);
  const keys = parseKeys(r.out);
  assert.deepEqual([...keys.keys()], [1]);
  assert.equal(keys.get(1).length, 32);
  assert.match(r.err, /outside the data directory/);
  const two = await cli(dir, ['gen-key', '--version', '2'], { env: {} });
  assert.match(two.out, /^2:/);
  assert.notEqual(two.out.slice(2), r.out.slice(2), 'a new random key each time');
  assert.deepEqual([...parseKeys(`${r.out}${two.out}`).keys()], [1, 2], 'appended lines make a keyring');
  assert.equal(newKeyLine(65535).startsWith('65535:'), true);
  for (const bad of ['0', '65536', 'x', '-1', '01']) {
    const e = await cli(dir, ['gen-key', '--version', bad], { env: {} });
    assert.equal(e.code, 2, bad);
    assert.match(e.err, /--version must be a whole number from 1 to 65535/);
  }
  await assert.rejects(fs.access(path.join(dir, DB_FILE)), 'gen-key does not touch the store');
});

test('cli: create a first admin with a piped password, then list; the file is 0600 and the password peppered', async () => {
  const dir = await tmp();
  const r = await cli(dir, ['create', 'root', '--role', 'admin'], { input: 'a fine long password\n' });
  assert.equal(r.code, 0, r.err);
  assert.match(r.out, /Made root \(admin\)/);
  // The website turns sign-in on only at start: the first user needs a restart, and that is said
  // (and not that a running server picks it up).
  assert.match(r.out, /^This is the first user: if the website is running without users, restart the website to turn on sign-in\.$/m);
  assert.doesNotMatch(r.out, /A running server picks this up/);
  const second = await cli(dir, ['create', 'bob', '--role', 'viewer', '--generate']);
  assert.equal(second.code, 0, second.err);
  assert.doesNotMatch(second.out + second.err, /restart|Start the server/i);
  assert.match(second.out, /A running server picks this up within a second/);
  if (process.platform !== 'win32') assert.equal((await fs.stat(path.join(dir, DB_FILE))).mode & 0o777, 0o600);
  const store = await reopen(dir);
  assert.equal(store.lookup('root').role, 'admin');
  assert.equal(store.lookup('root').mustChangePassword, false, 'their own password');
  const { phc } = store.find('root');
  assert.equal(phc.keyid, 1, 'peppered with the current key');
  assert.equal(await verifyPassword('a fine long password', phc, fakeHasher, pepperOf(store, 'root')), true);
  assert.equal(await verifyPassword('a fine long password', phc, fakeHasher, keyring([[1, master()]]).pepper(1)), false, 'not with another key');
  const list = await cli(dir, ['list']);
  assert.match(list.out, /^root\tadmin\tuser store, two-step off, 0 devices\tlast sign in never$/m);
  assert.equal(list.out.includes('$argon2'), false);
});

test('cli: a new password uses the current (highest) key version', async () => {
  const dir = await tmp();
  const k2 = master();
  const env = { USERS_KEY: `${line(1, KEY1)},${line(2, k2)}` };
  assert.equal((await cli(dir, ['create', 'root', '--role', 'admin', '--generate'], { env })).code, 0);
  const store = await reopen(dir, [], keyring([[1, KEY1], [2, k2]]));
  assert.equal(store.find('root').phc.keyid, 2);
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
  assert.equal(await verifyPassword(otp, store.find('bob').phc, fakeHasher, pepperOf(store, 'bob')), true);
  assert.equal((await fs.readFile(path.join(dir, DB_FILE))).includes(otp), false);
  // Reset: a typed one, to be changed at the next sign in.
  const reset = await cli(dir, ['reset-password', 'bob', '--must-change'], { input: 'a typed new password' });
  assert.equal(reset.code, 0, reset.err);
  const again = await reopen(dir);
  assert.equal(await verifyPassword('a typed new password', again.find('bob').phc, fakeHasher, pepperOf(again, 'bob')), true);
  assert.equal(again.lookup('bob').mustChangePassword, true);
  assert.equal((await cli(dir, ['create', 'BOB', '--role', 'viewer', '--generate'])).code, 1, 'exists, in any case');
});

test('cli: one admin is demoted here while another admin exists (the users page refuses it)', async () => {
  const dir = await tmp();
  await cli(dir, ['create', 'root', '--role', 'admin', '--generate']);
  await cli(dir, ['create', 'bob', '--role', 'admin', '--generate']);
  const r = await cli(dir, ['set-role', 'bob', 'viewer']);
  assert.equal(r.code, 0, r.err);
  assert.equal((await reopen(dir)).lookup('bob').role, 'viewer');
});

test('cli: one admin is deleted here while another admin exists (the users page refuses it)', async () => {
  const dir = await tmp();
  await cli(dir, ['create', 'root', '--role', 'admin', '--generate']);
  await cli(dir, ['create', 'bob', '--role', 'admin', '--generate']);
  const r = await cli(dir, ['delete', 'bob']);
  assert.equal(r.code, 0, r.err);
  assert.equal((await reopen(dir)).lookup('bob'), null);
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
    const h = store.home(name);
    store.commit(h.map, h.k, (cur) => ({ ...cur, totp: { ...cur.totp, enabled: true }, recoveryCodes: store.storedCodes(['aaaa-bbbb-cccc-dddd']) }));
    await store.addDevice(name, 'b'.repeat(64));
  }
  store.close();
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

test('cli: an admin\'s password and two-step sign-in are reset here (the users page refuses them)', async () => {
  const dir = await tmp();
  await cli(dir, ['create', 'root', '--role', 'admin'], { input: 'a good long password\n' });
  const store = await reopen(dir);
  const origin = 'https://status.example.org';
  const pk = createPasskeys({ siteUrl: origin, store, now: () => NOW });
  const o = await pk.registrationOptions('root', { sessionId: 's', epoch: 0 });
  await pk.finishRegistration('root', new SoftAuthenticator().create({ challenge: o.challenge, origin, rpId: 'status.example.org' }), { sessionId: 's', epoch: 0 });
  const before = store.find('root').phc;
  store.close();
  const r2fa = await cli(dir, ['reset-2fa', 'root']);
  assert.equal(r2fa.code, 0, r2fa.err);
  assert.match(r2fa.out, /Two-step sign-in of root is off: their app code, 1 passkey, recovery codes and known devices are gone\./);
  const rpw = await cli(dir, ['reset-password', 'root', '--generate']);
  assert.equal(rpw.code, 0, rpw.err);
  const after = await reopen(dir);
  assert.equal(after.lookup('root').role, 'admin');
  assert.equal(after.secondFactorEnabled('root'), false);
  assert.notDeepEqual(after.find('root').phc, before);
  assert.equal(after.lookup('root').mustChangePassword, true);
  after.close();
});

test('cli: list names the app code and the passkeys; reset-2fa takes the passkeys away too and keeps the user handle', async () => {
  const dir = await tmp();
  await cli(dir, ['create', 'bob', '--role', 'viewer', '--generate']);
  await cli(dir, ['create', 'carol', '--role', 'viewer', '--generate']);
  const store = await reopen(dir);
  const origin = 'https://status.example.org';
  const pk = createPasskeys({ siteUrl: origin, store, now: () => NOW });
  for (const [name, n] of [['bob', 2], ['carol', 1]]) {
    for (let i = 0; i < n; i++) {
      const o = await pk.registrationOptions(name, { sessionId: `s-${name}`, epoch: 0 });
      await pk.finishRegistration(name, new SoftAuthenticator().create({ challenge: o.challenge, origin, rpId: 'status.example.org' }), { sessionId: `s-${name}`, epoch: 0 });
    }
  }
  await store.beginTotp('carol');
  const h = store.home('carol');
  store.commit(h.map, h.k, (cur) => ({ ...cur, totp: { ...cur.totp, enabled: true } }));
  const handle = store.factorRecord('bob').passkeyUserId;
  store.close();
  const list = await cli(dir, ['list']);
  assert.equal(list.code, 0, list.err);
  assert.match(list.out, /^bob\tviewer\tuser store, two-step on \(2 passkeys\), 0 devices, must change password\t/m);
  assert.match(list.out, /^carol\tviewer\tuser store, two-step on \(app code and 1 passkey\), 0 devices, must change password\t/m);
  const help = await cli(dir, ['--help']);
  assert.match(help.out + help.err, /reset-2fa NAME +turns off two-step sign-in: removes the\n +app code, passkeys, recovery codes and/);
  const r = await cli(dir, ['reset-2fa', 'bob']);
  assert.equal(r.code, 0, r.err);
  assert.match(r.out, /^Two-step sign-in of bob is off: their app code, 2 passkeys, recovery codes and known devices are gone\.$/m);
  const after = await reopen(dir);
  assert.deepEqual(after.passkeys('bob'), []);
  assert.equal(after.secondFactorEnabled('bob'), false);
  assert.equal(after.factorRecord('bob').passkeyUserId, handle);
  assert.equal(after.passkeys('carol').length, 1);
  after.close();
  const none = await cli(dir, ['reset-2fa', 'bob']);
  assert.match(none.out, /^Two-step sign-in of bob is off: their app code, recovery codes and known devices are gone\.$/m);
  assert.match((await cli(dir, ['list'])).out, /^bob\tviewer\tuser store, two-step off, /m);
});

test('cli: a users.json that cannot be imported, or a damaged users.db, is left as it is, and nothing is done', async () => {
  const dir = await tmp();
  const file = path.join(dir, STORE_FILE);
  await fs.writeFile(file, '{not json', { mode: 0o600 });
  const r = await cli(dir, ['create', 'root', '--role', 'admin', '--generate']);
  assert.equal(r.code, 1);
  assert.match(r.err, /users\.json in the data directory cannot be used: it is not valid JSON/);
  assert.equal(await fs.readFile(file, 'utf8'), '{not json');
  await assert.rejects(fs.access(path.join(dir, DB_FILE)), 'no database made');

  const other = await tmp();
  const db = path.join(other, DB_FILE);
  const garbage = crypto.randomBytes(8192);
  await fs.writeFile(db, garbage, { mode: 0o600 });
  for (const argv of [['list'], ['check'], ['create', 'root', '--role', 'admin', '--generate']]) {
    const x = await cli(other, argv);
    assert.equal(x.code, 1, argv[0]);
    assert.match(x.err, /users\.db in the data directory cannot be used/, argv[0]);
  }
  assert.deepEqual(await fs.readFile(db), garbage);
});

test('cli: a users.json is imported once by the first command; it stays as it is', async () => {
  const dir = await tmp();
  const phc = await hashPassword('an old long password', undefined, fakeHasher);
  const json = JSON.stringify({ version: 1, users: [{ name: 'Old', role: 'admin', passwordHash: phc, created: '2026-01-01T00:00:00.000Z' }], configUsers: [] });
  await fs.writeFile(path.join(dir, STORE_FILE), json, { mode: 0o600 });
  const r = await cli(dir, ['list']);
  assert.equal(r.code, 0, r.err);
  assert.match(r.out, /^Old\tadmin\tuser store/m);
  assert.equal(await fs.readFile(path.join(dir, STORE_FILE), 'utf8'), json);
  // Imported hashes are not peppered: check says so.
  const c = await cli(dir, ['check']);
  assert.match(c.out, /1 password hash of website users without a pepper/);
});

test('cli: a user moved out of the config file starts without the old second factor, which is said', async () => {
  const dir = await tmp();
  const configUsers = [{ name: 'alice', phc: parsePhc(await hashPassword('alices password', undefined, fakeHasher)), role: 'viewer' }];
  const store = await reopen(dir, configUsers);
  await store.addDevice('alice', 'c'.repeat(64));
  store.close();
  // alice is taken out of the config file, then made in the store.
  const r = await cli(dir, ['create', 'alice', '--role', 'admin', '--generate']);
  assert.equal(r.code, 0, r.err);
  assert.match(r.out, /the user store still has the two-step sign-in and devices alice had as a config file user/);
  const after = await reopen(dir);
  assert.equal(after.lookup('alice').source, 'store');
  assert.equal(after.devices('alice').length, 0);
});

test('cli: runs as a program', async () => {
  const dir = await tmp();
  const out = await new Promise((resolve) => {
    execFile(process.execPath, [script, '--data-dir', dir, 'list'], { env: { ...process.env, USERS_KEY: '', USERS_KEY_FILE: '' } }, (err, stdout, stderr) => resolve({ err, stdout, stderr }));
  });
  assert.equal(out.err, null, out.stderr);
  assert.match(out.stdout, /^No users: there is no user store \(users\.db\) in .* yet\./);
});

test('cli: without a user store or a users.json, only create makes users.db; anything else says so and makes nothing', async () => {
  const dir = await tmp();
  const list = await cli(dir, ['list']);
  assert.equal(list.code, 0, list.err);
  assert.match(list.out, /^No users: there is no user store \(users\.db\) in .* yet\. node scripts\/users\.js create NAME --role admin makes the first user\.$/m);
  for (const argv of [['check'], ['rekey'], ['delete', 'bob'], ['set-role', 'bob', 'admin'], ['reset-2fa', 'bob'], ['retire-users-json'], ['backup', path.join(dir, 'b.db')]]) {
    const r = await cli(dir, argv);
    assert.equal(r.code, 1, argv[0]);
    assert.match(r.err, /^There is no user store \(users\.db\) in .* yet, so there is nothing to (check|change); nothing was made\. Check --data-dir/m, argv[0]);
  }
  assert.deepEqual(await fs.readdir(dir), [], 'nothing made');
  assert.equal((await cli(dir, ['create', 'root', '--role', 'admin', '--generate'])).code, 0);
  assert.ok((await fs.readdir(dir)).includes(DB_FILE));
});

test('cli: an unknown option or command is not repeated, since it may be a password', () => {
  for (const argv of [['delete', 'bob', '--hunter2hunter2'], ['--Sekrit-Pass', 'list'], ['hunter2hunter2']]) {
    assert.throws(() => parseArgs(argv), (e) => /unknown (option|command)/.test(e.message) && !/hunter2|Sekrit/.test(e.message), argv.join(' '));
  }
  assert.throws(() => parseArgs(['list', '--server-stopped']), /unknown option for list/);
  assert.equal(parseArgs(['delete', 'bob', '--server-stopped']).serverStopped, true);
});

test('cli: --server-stopped is accepted and ignored with a note; a leftover users.lock changes nothing', async () => {
  const dir = await tmp();
  await fs.writeFile(path.join(dir, 'users.lock'), 'started');
  const r = await cli(dir, ['create', 'root', '--role', 'admin', '--generate', '--server-stopped']);
  assert.equal(r.code, 0, r.err);
  assert.match(r.err, /--server-stopped is no longer needed and is ignored/);
  const plain = await cli(dir, ['create', 'bob', '--role', 'viewer', '--generate']);
  assert.equal(plain.code, 0, plain.err);
  assert.doesNotMatch(plain.err, /server-stopped|users\.lock|running/);
});

test('cli: changes work while a server store is open, which picks them up and is told who changed', async () => {
  const dir = await tmp();
  await cli(dir, ['create', 'root', '--role', 'admin', '--generate']);
  const server = await reopen(dir);
  const told = [];
  server.onExternalChange = (name, what) => told.push([name, what]);
  await server.addDevice('root', 'a'.repeat(64));

  const made = await cli(dir, ['create', 'bob', '--role', 'viewer', '--generate']);
  assert.equal(made.code, 0, made.err);
  assert.equal((await cli(dir, ['set-role', 'root', 'manage', '--force'])).code, 0);
  assert.equal(server.refresh(), true);
  assert.equal(server.lookup('bob').role, 'viewer');
  assert.equal(server.lookup('root').role, 'manage');
  assert.deepEqual(told.sort(), [['bob', ['created']], ['root', ['role']]]);
  assert.equal(server.devices('root').length, 1, 'the device the server wrote is kept');

  // The server writes on top of the change without losing it, and the command line sees the server's.
  await server.addDevice('bob', 'b'.repeat(64));
  const list = await cli(dir, ['list']);
  assert.match(list.out, /^bob\tviewer\tuser store, two-step off, 1 devices/m);
  assert.match(list.out, /^root\tmanage\t/m);

  // A password reset and a delete reach the server too.
  told.length = 0;
  assert.equal((await cli(dir, ['reset-password', 'bob', '--generate'])).code, 0);
  assert.equal((await cli(dir, ['delete', 'bob'])).code, 0);
  server.refresh();
  assert.equal(server.lookup('bob'), null);
  assert.deepEqual(told, [['bob', ['deleted']]]);
});

test('cli: a store held by another program for longer than the wait is refused, and nothing changes', async () => {
  const dir = await tmp();
  await cli(dir, ['create', 'root', '--role', 'admin', '--generate']);
  const { db } = await openUserDb({ dataDir: dir, keys: keyring(), warn: quiet });
  db.sql.exec('BEGIN IMMEDIATE');
  try {
    // The command line waits TIMEOUT_MS (10 s) for the server; shorter here.
    const started = Date.now();
    const r = await cli(dir, ['set-role', 'root', 'viewer', '--force'], { timeoutMs: 300 });
    assert.equal(r.code, 1);
    assert.match(r.err, /Another program is changing the user store; nothing was changed\. Try again\./);
    assert.ok(Date.now() - started >= 250, 'it waited first');
  } finally {
    db.sql.exec('ROLLBACK');
    db.close();
  }
  assert.equal((await reopen(dir)).lookup('root').role, 'admin');
  assert.equal(TIMEOUT_MS, 10_000);
});

test('cli: without a key, users cannot be changed; with users, nothing opens; the message names gen-key and USERS_KEY_FILE', async () => {
  const dir = await tmp();
  const r = await cli(dir, ['create', 'root', '--role', 'admin', '--generate'], { env: {} });
  assert.equal(r.code, 1);
  assert.match(r.err, /needs its key: set USERS_KEY_FILE/);
  assert.match(r.err, /gen-key/);
  await assert.rejects(fs.access(path.join(dir, DB_FILE)), 'nothing made');
  // An empty store (a server started without users made it) can be listed and checked without one.
  (await UserStore.open({ dataDir: dir, warn: quiet })).close();
  assert.equal((await cli(dir, ['list'], { env: {} })).code, 0);
  const c = await cli(dir, ['check'], { env: {} });
  assert.equal(c.code, 0, c.err);
  assert.match(c.out, /No key is given/);
  assert.equal((await cli(dir, ['rekey'], { env: {} })).code, 1);

  await cli(dir, ['create', 'root', '--role', 'admin', '--generate']);
  const before = await fs.readFile(path.join(dir, DB_FILE));
  for (const argv of [['list'], ['check'], ['backup', path.join(dir, 'b.db')]]) {
    const x = await cli(dir, argv, { env: {} });
    assert.equal(x.code, 1, argv[0]);
    assert.match(x.err, /set USERS_KEY_FILE \(node scripts\/users\.js gen-key makes one\)/, argv[0]);
  }
  assert.deepEqual(await fs.readFile(path.join(dir, DB_FILE)), before);
});

test('cli: a wrong key, a missing key version or a bad key file is refused, and nothing changes', async () => {
  const dir = await tmp();
  await cli(dir, ['create', 'root', '--role', 'admin', '--generate']);
  const before = await fs.readFile(path.join(dir, DB_FILE));
  const wrong = await cli(dir, ['create', 'bob', '--role', 'viewer', '--generate'], { env: { USERS_KEY: line(1, master()) } });
  assert.equal(wrong.code, 1);
  assert.match(wrong.err, /key version 1 is not the key the user store was made with/);
  const missing = await cli(dir, ['list'], { env: { USERS_KEY: line(2, master()) } });
  assert.equal(missing.code, 1);
  assert.match(missing.err, /the user store needs key version 1; it is not in USERS_KEY_FILE/);
  const garbled = await cli(dir, ['list'], { env: { USERS_KEY: '1:short' } });
  assert.equal(garbled.code, 1);
  assert.match(garbled.err, /USERS_KEY cannot be used/);
  assert.doesNotMatch(garbled.err, /short/, 'key text is never repeated');
  const both = await cli(dir, ['list'], { env: { USERS_KEY: line(1, KEY1), USERS_KEY_FILE: '/nonexistent' } });
  assert.match(both.err, /both set/);
  const gone = await cli(dir, ['list'], { env: { USERS_KEY_FILE: path.join(dir, 'nope.key') } });
  assert.equal(gone.code, 1);
  assert.match(gone.err, /USERS_KEY_FILE .*nope\.key cannot be read \(ENOENT\)/);
  assert.deepEqual(await fs.readFile(path.join(dir, DB_FILE)), before);
  assert.equal((await reopen(dir)).lookup('bob'), null);
});

test('cli: the key is read from USERS_KEY_FILE; a key file in the data directory or readable by others is warned about', async () => {
  const dir = await tmp();
  const secrets = await tmp();
  const file = path.join(secrets, 'users.key');
  await fs.writeFile(file, `# the user store key\n${line(1, KEY1)}\n`, { mode: 0o400 });
  const r = await cli(dir, ['create', 'root', '--role', 'admin', '--generate'], { env: { USERS_KEY_FILE: file } });
  assert.equal(r.code, 0, r.err);
  assert.doesNotMatch(r.err, /warning/);
  assert.ok((await reopen(dir)).lookup('root'), 'the same key as USERS_KEY');
  const inside = path.join(dir, 'users.key');
  await fs.writeFile(inside, line(1, KEY1), { mode: 0o644 });
  const w = await cli(dir, ['list'], { env: { USERS_KEY_FILE: inside } });
  assert.equal(w.code, 0, w.err);
  assert.match(w.err, /inside the data directory/);
  if (process.platform !== 'win32') assert.match(w.err, /can be read by other users/);
});

test('cli: backup writes a new 0600 copy that opens with the same key, and never over a file', async () => {
  const dir = await tmp();
  const out = await tmp();
  await cli(dir, ['create', 'root', '--role', 'admin', '--generate']);
  const server = await reopen(dir);
  await server.beginTotp('root');
  const file = path.join(out, 'users-backup.db');
  const r = await cli(dir, ['backup', 'users-backup.db'], { cwd: out });
  assert.equal(r.code, 0, r.err);
  assert.match(r.out, /Backed up the user store to .*users-backup\.db/);
  assert.match(r.out, /Back up the key file separately/);
  if (process.platform !== 'win32') assert.equal((await fs.stat(file)).mode & 0o777, 0o600);
  // The backup is a store of its own: restored into a data directory, it opens with the key.
  const restored = await tmp();
  await fs.copyFile(file, path.join(restored, DB_FILE));
  const back = await reopen(restored);
  assert.equal(back.lookup('root').role, 'admin');
  assert.equal(back.factorRecord('root').totp.secret, server.factorRecord('root').totp.secret);
  // Without its key it does not open.
  await assert.rejects(UserStore.open({ dataDir: restored, keys: keyring([[1, master()]]), warn: quiet }), /key version 1 is not the key/);
  // A file that is there already is never written over.
  await fs.writeFile(path.join(out, 'taken.db'), 'mine');
  const taken = await cli(dir, ['backup', path.join(out, 'taken.db')]);
  assert.equal(taken.code, 1);
  assert.match(taken.err, /already exists/);
  assert.equal(await fs.readFile(path.join(out, 'taken.db'), 'utf8'), 'mine');
  const noDir = await cli(dir, ['backup', path.join(out, 'missing', 'x.db')]);
  assert.equal(noDir.code, 1);
  assert.match(noDir.err, /the backup could not be written/);
});

test('cli: check and rekey say what each key version protects; rekey moves TOTP secrets to the newest key', async () => {
  const dir = await tmp();
  const k2 = master();
  const one = { USERS_KEY: line(1, KEY1) };
  const both = { USERS_KEY: `${line(1, KEY1)}\n${line(2, k2)}` };
  await cli(dir, ['create', 'root', '--role', 'admin', '--generate'], { env: one });
  const store = await reopen(dir);
  await store.beginTotp('root');
  const h = store.home('root');
  store.commit(h.map, h.k, (cur) => ({ ...cur, totp: { ...cur.totp, enabled: true }, recoveryCodes: store.storedCodes(['aaaa-bbbb-cccc-dddd', 'eeee-ffff-gggg-hhhh']) }));
  const secret = store.factorRecord('root').totp.secret;
  store.close();

  let c = await cli(dir, ['check'], { env: one });
  assert.equal(c.code, 0, c.err);
  assert.match(c.out, /no damage found \(quick_check\)/);
  assert.match(c.out, /1 website user, 0 records of config file users/);
  assert.match(c.out, /^version 1 \(current\): 1 password hash, 2 recovery codes, 1 TOTP secret$/m);

  // A new key line: until the server was restarted with it, the command line does not use it, and
  // rekey says to restart first.
  c = await cli(dir, ['check'], { env: both });
  assert.match(c.out, /^version 1 \(current\): 1 password hash, 2 recovery codes, 1 TOTP secret$/m);
  assert.match(c.out, /^version 2: in the key file, but not in use yet; restart the website so that it records it$/m);
  const early2 = await cli(dir, ['rekey'], { env: both });
  assert.equal(early2.code, 1);
  assert.match(early2.err, /^Key version 2 is in the key file, but the user store does not know it yet\. Restart the website first/m);
  // The restart: the server records version 2. Then rekey.
  (await reopen(dir, [], keyring([[1, KEY1], [2, k2]]))).close();
  c = await cli(dir, ['check'], { env: both });
  assert.match(c.out, /^version 1: 1 password hash \(upgraded at next sign in\), 2 recovery codes \(replaced when used or regenerated\), 1 TOTP secret \(moved by rekey\); still needed, keep it in the key file$/m);
  assert.match(c.out, /^version 2 \(current\): unused$/m);
  const r = await cli(dir, ['rekey'], { env: both });
  assert.equal(r.code, 0, r.err);
  assert.match(r.out, /^1 TOTP secret was encrypted again with key version 2\.$/m);
  assert.match(r.out, /^version 1: 1 password hash \(upgraded at next sign in\), 2 recovery codes \(replaced when used or regenerated\), 0 TOTP secrets; still needed/m);
  assert.match(r.out, /^version 2 \(current\): 0 password hashes, 0 recovery codes, 1 TOTP secret$/m);
  assert.equal((await cli(dir, ['rekey'], { env: both })).out.split('\n')[0], '0 TOTP secrets were encrypted again with key version 2.');

  // The secret is the same, now under version 2.
  const after = await reopen(dir, [], keyring([[1, KEY1], [2, k2]]));
  assert.equal(after.factorRecord('root').totp.secret, secret);
  after.close();
  // Version 1 is still needed for the password and the codes: taking it out fails.
  const early = await cli(dir, ['list'], { env: { USERS_KEY: line(2, k2) } });
  assert.equal(early.code, 1);
  assert.match(early.err, /needs key version 1/);
  // Once the password and codes moved (a reset, new codes), version 1 is unused and can go.
  assert.equal((await cli(dir, ['reset-password', 'root', '--generate'], { env: both })).code, 0);
  const s = await reopen(dir, [], keyring([[1, KEY1], [2, k2]]));
  await s.newRecoveryCodes('root');
  s.close();
  c = await cli(dir, ['check'], { env: both });
  assert.match(c.out, /^version 1: unused; it can be removed from the key file$/m);
  const only2 = await cli(dir, ['list'], { env: { USERS_KEY: line(2, k2) } });
  assert.equal(only2.code, 0, only2.err);
  assert.match(only2.out, /^root\tadmin/m);
  c = await cli(dir, ['check'], { env: { USERS_KEY: line(2, k2) } });
  assert.match(c.out, /^version 1 \(not in the key file\): unused; it can be removed from the key file$/m);
});

test('cli: key usage lines', () => {
  const keys = keyring([[1, KEY1], [3, master()]]);
  const lines = keyUsageLines(new Map([[1, { passwords: 0, recoveryCodes: 0, totp: 0 }], [2, { passwords: 1, recoveryCodes: 0, totp: 0 }], [3, { passwords: 0, recoveryCodes: 0, totp: 0 }]]), keys);
  assert.deepEqual(lines, [
    'version 1: unused; it can be removed from the key file',
    'version 2 (not in the key file): 1 password hash (upgraded at next sign in), 0 recovery codes, 0 TOTP secrets; still needed, keep it in the key file',
    'version 3 (current): unused',
  ]);
});

test('cli: a key version only the command line has is never used, so a running server keeps up and a deleted user cannot sign in', async () => {
  const dir = await tmp();
  const k2 = master();
  // The server runs with key 1 only.
  const server = await reopen(dir, [], keyring([[1, KEY1]]));
  const auth = createLogin({ users: [], store: server, hasher: fakeHasher, sleep: async () => {} });
  const pw = 'a long password for bob';
  await server.createUser({ name: 'alice', role: 'admin', passwordHash: await hashPassword('a long password for alice', undefined, fakeHasher, server.currentPepper()) });
  await server.beginTotp('alice');
  await server.createUser({ name: 'bob', role: 'viewer', passwordHash: await hashPassword(pw, undefined, fakeHasher, server.currentPepper()) });
  assert.equal((await auth.attempt('bob', pw, '192.0.2.1')).ok, true);

  // The command line has key 2 as well (added to the key file, the server not restarted yet).
  const env = { USERS_KEY: `${line(1, KEY1)},${line(2, k2)}` };
  const role = await cli(dir, ['set-role', 'alice', 'viewer', '--force'], { env });
  assert.equal(role.code, 0, role.err);
  assert.match(role.err, /key version 2 in the key file is not in use yet: the website records a new version when it starts\. This change uses version 1/);
  assert.equal((await cli(dir, ['delete', 'bob'], { env })).code, 0);

  // The server reads both changes; bob is gone and cannot sign in.
  assert.equal(server.refresh(), true);
  assert.equal(server.unreadable, null);
  assert.equal(server.lookup('bob'), null);
  assert.equal(server.lookup('alice').role, 'viewer');
  assert.deepEqual(await auth.attempt('bob', pw, '192.0.2.2'), { ok: false, reason: 'invalid' });
  // Nothing on disk uses version 2, and it was not recorded.
  const sql = new DatabaseSync(path.join(dir, DB_FILE), { readOnly: true });
  try {
    assert.deepEqual(sql.prepare('SELECT version FROM keys').all().map((r) => r.version), [1]);
    assert.deepEqual(sql.prepare('SELECT DISTINCT substr(totp_box, 2, 2) AS v FROM users WHERE totp_box IS NOT NULL').all().map((r) => Buffer.from(r.v).readUInt16BE(0)), [1]);
  } finally {
    sql.close();
  }
});

test('cli: a new password made while a newer key is not recorded yet uses the newest recorded one', async () => {
  const dir = await tmp();
  (await reopen(dir, [], keyring([[1, KEY1]]))).close();
  const k2 = master();
  const r = await cli(dir, ['create', 'root', '--role', 'admin', '--generate'], { env: { USERS_KEY: `${line(1, KEY1)},${line(2, k2)}` } });
  assert.equal(r.code, 0, r.err);
  const store = await reopen(dir, [], keyring([[1, KEY1]]));
  assert.equal(store.find('root').phc.keyid, 1);
  // A key file with none of the recorded versions cannot change anything (here a store the
  // server made with key 1, with nothing in it that needs it yet).
  const other = await tmp();
  (await reopen(other, [], keyring([[1, KEY1]]))).close();
  const none = await cli(other, ['create', 'bob', '--role', 'viewer', '--generate'], { env: { USERS_KEY: line(2, k2) } });
  assert.equal(none.code, 1);
  assert.match(none.err, /None of the key versions in USERS_KEY_FILE \(or USERS_KEY\) is known to the user store yet\. Start \(or restart\) the website with this key first/);
  const c = await cli(other, ['check'], { env: { USERS_KEY: line(2, k2) } });
  assert.equal(c.code, 0, c.err);
  assert.match(c.out, /^None of the key versions given is recorded in the store yet/m);
  assert.match(c.out, /^version 2: in the key file, but not in use yet; restart the website so that it records it$/m);
});

test('cli: a store with users whose keys table was emptied is refused, and no key version is recorded into it', async () => {
  const dir = await tmp();
  const server = await reopen(dir);
  // A hash without a pepper, and no second factor: nothing in the store needs a key.
  await server.createUser({ name: 'bob', role: 'admin', passwordHash: await hashPassword('a long password for bob', undefined, fakeHasher) });
  server.close();
  const file = path.join(dir, DB_FILE);
  let sql = new DatabaseSync(file);
  sql.exec('DELETE FROM keys');
  sql.close();
  // The right key and a wrong one alike: neither can be told from the other now.
  for (const env of [ENV, { USERS_KEY: line(1, master()) }, { USERS_KEY: line(2, master()) }]) {
    const r = await cli(dir, ['create', 'carol', '--role', 'viewer', '--generate'], { env });
    assert.equal(r.code, 1);
    assert.match(r.err, /^the user store has users but no check value for any key version \(its keys table was emptied\)/m);
  }
  sql = new DatabaseSync(file, { readOnly: true });
  try {
    assert.deepEqual(sql.prepare('SELECT version FROM keys').all(), []);
    assert.deepEqual(sql.prepare('SELECT name FROM users').all().map((u) => u.name), ['bob']);
  } finally {
    sql.close();
  }
});

test('cli: retire-users-json renames the imported users.json to users.json.imported (mode 600) and refuses anything else', async () => {
  const dir = await tmp();
  const phc = await hashPassword('an old long password', undefined, fakeHasher);
  const json = JSON.stringify({ version: 1, users: [{ name: 'Old', role: 'admin', passwordHash: phc }], configUsers: [] });
  const file = path.join(dir, STORE_FILE);
  await fs.writeFile(file, json, { mode: 0o644 });
  const first = await cli(dir, ['list']);
  assert.equal(first.code, 0, first.err);
  assert.match(first.err, /users\.json is still in the data directory\. It holds the second-factor secrets unencrypted and password hashes without a pepper/);
  // Changed since the import: refused, and left as it is.
  await fs.writeFile(file, `${json}\n`);
  let r = await cli(dir, ['retire-users-json']);
  assert.equal(r.code, 1);
  assert.match(r.err, /users\.json is not the file that was imported on .* \(it changed since\).*; nothing was changed/);
  assert.equal(await fs.readFile(file, 'utf8'), `${json}\n`);
  // A link in its place is refused too.
  await fs.rm(file);
  const elsewhere = path.join(await tmp(), 'users.json');
  await fs.writeFile(elsewhere, json);
  await fs.symlink(elsewhere, file);
  r = await cli(dir, ['retire-users-json']);
  assert.equal(r.code, 1);
  assert.match(r.err, /users\.json is a link/);
  await fs.rm(file);
  // The imported file: renamed, mode 600, the same bytes; never written over.
  await fs.writeFile(file, json, { mode: 0o644 });
  r = await cli(dir, ['retire-users-json']);
  assert.equal(r.code, 0, r.err);
  assert.match(r.out, /Renamed users\.json to users\.json\.imported \(mode 600\)/);
  await assert.rejects(fs.access(file));
  const retired = path.join(dir, RETIRED_FILE);
  assert.equal(await fs.readFile(retired, 'utf8'), json);
  if (process.platform !== 'win32') assert.equal((await fs.stat(retired)).mode & 0o777, 0o600);
  // No more warning about users.json, but one about the retired file while it is there.
  const listed = await cli(dir, ['list']);
  assert.doesNotMatch(listed.err, /users\.json is still in the data directory/);
  assert.match(listed.err, /^warning: users\.json\.imported is in the data directory\. It is the retired users\.json, and still holds the second-factor secrets unencrypted.*move it to offline storage, or delete it \(node scripts\/users\.js retire-users-json --delete/m);
  r = await cli(dir, ['retire-users-json']);
  assert.equal(r.code, 1);
  assert.match(r.err, /there is no users\.json in the data directory; nothing was changed/);
  await fs.writeFile(file, json);
  r = await cli(dir, ['retire-users-json']);
  assert.equal(r.code, 1);
  assert.match(r.err, /users\.json\.imported is there already; move it away first, or delete users\.json with --delete/);
  assert.equal(await fs.readFile(file, 'utf8'), json);
  // --delete: users.json first (after the same check), then the retired file.
  r = await cli(dir, ['retire-users-json', '--delete']);
  assert.equal(r.code, 0, r.err);
  assert.match(r.out, /^Deleted users\.json\./m);
  await assert.rejects(fs.access(file));
  await fs.writeFile(retired, `${json} `);
  r = await cli(dir, ['retire-users-json', '--delete']);
  assert.equal(r.code, 1);
  assert.match(r.err, /users\.json\.imported is not the file that was imported/);
  await fs.writeFile(retired, json);
  r = await cli(dir, ['retire-users-json', '--delete']);
  assert.equal(r.code, 0, r.err);
  assert.match(r.out, /^Deleted users\.json\.imported\./m);
  assert.deepEqual((await fs.readdir(dir)).filter((f) => f.startsWith('users.json')), []);
  assert.doesNotMatch((await cli(dir, ['list'])).err, /users\.json/, 'nothing left to warn about');
  r = await cli(dir, ['retire-users-json', '--delete']);
  assert.match(r.err, /there is no users\.json or users\.json\.imported in the data directory/);
  assert.equal(parseArgs(['retire-users-json', '--delete']).remove, true);
  assert.throws(() => parseArgs(['list', '--delete']), /unknown option/);
  await fs.writeFile(file, json);
  // A store made without users.json has nothing to retire.
  const plain = await tmp();
  await cli(plain, ['create', 'root', '--role', 'admin', '--generate']);
  await fs.writeFile(path.join(plain, STORE_FILE), json);
  r = await cli(plain, ['retire-users-json']);
  assert.equal(r.code, 1);
  assert.match(r.err, /was not made from a users\.json/);
  assert.deepEqual(parseArgs(['retire-users-json']).command, 'retire-users-json');
  assert.throws(() => parseArgs(['retire-users-json', 'x']), /too many/);
});

test('cli: dropPrivileges becomes the owner of the data directory (or the folder it would be made in), its groups first, and only from root', async () => {
  const calls = [];
  const proc = ({ known = true } = {}) => {
    let uid = 0;
    let gid = 0;
    return {
      platform: 'linux',
      initgroups: (u, g) => {
        calls.push(['initgroups', u, g]);
        if (!known) throw Object.assign(new Error('User identifier does not exist'), { code: 'ERR_UNKNOWN_CREDENTIAL' });
      },
      setgroups: (g) => calls.push(['setgroups', g]),
      setgid: (g) => (calls.push(['setgid', g]), (gid = g)),
      setuid: (u) => (calls.push(['setuid', u]), (uid = u)),
      getuid: () => uid,
      geteuid: () => uid,
      getgid: () => gid,
    };
  };
  const dir = await tmp();
  const st = await fs.stat(dir);
  if (st.uid === 0) {
    assert.deepEqual(dropPrivileges(dir, proc()), { dir, became: null }, 'root owns it: stays root');
    assert.deepEqual(calls, []);
  }
  assert.deepEqual(dropPrivileges(dir, { ...proc(), platform: 'win32' }), { dir, became: null });
  if (process.getuid?.() === 0) {
    await fs.chown(dir, 4321, 4322);
    const later = path.join(dir, 'not', 'made', 'yet');
    assert.deepEqual(dropPrivileges(later, proc()), { dir: later, became: { uid: 4321, gid: 4322 } });
    assert.deepEqual(calls.splice(0), [['initgroups', 4321, 4322], ['setgid', 4322], ['setuid', 4321]]);
    // A uid without a user entry gets no other groups.
    dropPrivileges(dir, proc({ known: false }));
    assert.deepEqual(calls.splice(0), [['initgroups', 4321, 4322], ['setgroups', []], ['setgid', 4322], ['setuid', 4321]]);
    // One that does not take is an error, never a silent root.
    assert.throws(() => dropPrivileges(dir, { ...proc(), setuid: () => {} }), /could not become the owner/);
    // The folder given through a link (root's, in a folder of root's) is used by its real path.
    const base = await tmp();
    await fs.symlink(dir, path.join(base, 'via'));
    assert.deepEqual(dropPrivileges(path.join(base, 'via'), proc()).dir, await fs.realpath(dir));
  }
  // run calls it for root only, says so, works in the folder it gives, and refuses when it fails.
  const asked = [];
  const r = await cli(dir, ['list'], { uid: 0, drop: (d) => (asked.push(d), { dir: d, became: { uid: 4321, gid: 4322 } }) });
  assert.equal(r.code, 0, r.err);
  assert.deepEqual(asked, [dir]);
  assert.match(r.err, /working as the owner of the data directory \(uid 4321\)/);
  assert.equal((await cli(dir, ['list'], { uid: 1000, drop: () => assert.fail('not root') })).code, 0);
  const no = await cli(dir, ['list'], { uid: 0, drop: () => { throw Object.assign(new Error('nope'), { code: 'EPERM' }); } });
  assert.equal(no.code, 1);
  assert.match(no.err, /could not become the owner of the data directory \(EPERM\), and does nothing as root there/);
  // From then on it works in the folder it was given back (the real path), not the one typed.
  const real = await tmp();
  assert.equal((await cli(real, ['create', 'rosa', '--role', 'admin', '--generate'])).code, 0);
  const moved = await cli(dir, ['list'], { uid: 0, drop: () => ({ dir: real, became: null }) });
  assert.match(moved.out, /^rosa\tadmin/m);
  const unsafe = await cli(dir, ['list'], { uid: 0, drop: () => { throw new UnsafeError('/x can be changed by a user other than root and the owner of the data directory'); } });
  assert.equal(unsafe.code, 1);
  assert.match(unsafe.err, /^running as root, this does nothing in this data directory: \/x can be changed by a user other than root and the owner of the data directory\. Run it as the server's user instead\. Nothing was changed$/m);
});

// Runs the command line as a process of its own, as whoever runs the tests (root, below).
function runAs(argv, env) {
  return new Promise((resolve) => {
    execFile(process.execPath, [script, ...argv], { env: { PATH: process.env.PATH, ...env } }, (err, stdout, stderr) => resolve({ code: err ? err.code : 0, out: stdout, err: stderr }));
  });
}

// A data directory owned by uid 1000 in a folder others can enter, and a key file, as root.
async function ownedSetup() {
  const base = await tmp();
  await fs.chmod(base, 0o755);
  const data = path.join(base, 'data');
  await fs.mkdir(data);
  await fs.chown(data, 1000, 1000);
  const keyFile = path.join(base, 'users.key');
  await fs.writeFile(keyFile, `${line(1, KEY1)}\n`, { mode: 0o400 });
  return { base, data, keyFile };
}

test('cli: run as root on a data directory another user owns, it works as that user: its files are theirs, and a key file only root can read is said to need that user', { skip: process.platform === 'win32' || process.getuid?.() !== 0 }, async () => {
  const { base, data, keyFile } = await ownedSetup();
  // Only root can read the key: the command has become uid 1000 before it reads it.
  const refused = await runAs(['--data-dir', data, 'create', 'root', '--role', 'admin', '--generate'], { USERS_KEY_FILE: keyFile });
  assert.equal(refused.code, 1, refused.err);
  assert.match(refused.err, /working as the owner of the data directory \(uid 1000\)/);
  assert.match(refused.err, /USERS_KEY_FILE .* cannot be read \(EACCES\)\. This runs as the owner of the data directory \(uid 1000\), like the server, so it must be readable by that user; nothing was changed/);
  assert.deepEqual(await fs.readdir(data), [], 'nothing opened or made');
  // Readable by that user: it works, and every file it made is theirs.
  await fs.chown(keyFile, 1000, 1000);
  const r = await runAs(['--data-dir', data, 'create', 'root', '--role', 'admin', '--generate'], { USERS_KEY_FILE: keyFile });
  assert.equal(r.code, 0, r.err);
  assert.doesNotMatch(r.err, /chown|owned by root/);
  for (const f of await fs.readdir(data)) {
    const st = await fs.lstat(path.join(data, f));
    assert.deepEqual([st.uid, st.gid], [1000, 1000], f);
  }
  // A backup into a folder only root can write is refused, with what it needs.
  const rootOnly = path.join(base, 'root-only');
  await fs.mkdir(rootOnly, { mode: 0o700 });
  const b = await runAs(['--data-dir', data, 'backup', path.join(rootOnly, 'b.db')], { USERS_KEY_FILE: keyFile });
  assert.equal(b.code, 1);
  assert.match(b.err, /The backup is written as the owner of the data directory \(uid 1000\)/);
  assert.deepEqual(await fs.readdir(rootOnly), []);
});

test('cli: run as root, a link planted as users.db-wal or users.db-shm is refused, and the file it points to is left alone', { skip: process.platform === 'win32' || process.getuid?.() !== 0 }, async () => {
  for (const planted of [`${DB_FILE}-wal`, `${DB_FILE}-shm`]) {
    const { base, data, keyFile } = await ownedSetup();
    await fs.chown(keyFile, 1000, 1000);
    const victim = path.join(base, 'root-only-victim');
    await fs.writeFile(victim, 'ROOT ONLY\n', { mode: 0o600 });
    // The owner of the data directory (uid 1000) can put links there.
    await fs.symlink(victim, path.join(data, planted));
    await fs.lchown(path.join(data, planted), 1000, 1000);
    const r = await runAs(['--data-dir', data, 'create', 'root', '--role', 'admin', '--generate'], { USERS_KEY_FILE: keyFile });
    assert.equal(r.code, 1, planted);
    assert.match(r.err, new RegExp(`${planted.replace('.', '\\.')} next to it is a link`), planted);
    const st = await fs.stat(victim);
    assert.deepEqual([st.uid, st.gid, st.mode & 0o777], [0, 0, 0o600], planted);
    assert.equal(await fs.readFile(victim, 'utf8'), 'ROOT ONLY\n', planted);
    assert.deepEqual(await fs.readdir(data), [planted], `${planted}: no users.db left behind`);
  }
});

test('cli: run as root where root owns the data directory, the new users.db is said to be root\'s, and nobody\'s owner is changed', { skip: process.platform === 'win32' || process.getuid?.() !== 0 }, async () => {
  const dir = await tmp();
  const r = await cli(dir, ['create', 'root', '--role', 'admin', '--generate'], { uid: 0 });
  assert.equal(r.code, 0, r.err);
  assert.match(r.err, /running as root, and root owns the data directory, so the new users\.db is root's/);
  assert.doesNotMatch((await cli(dir, ['create', 'bob', '--role', 'viewer', '--generate'], { uid: 0 })).err, /running as root/, 'the file exists: nothing to say');
  // A users.db that is someone else's keeps its owner when root changes it.
  const file = path.join(dir, DB_FILE);
  for (const f of await fs.readdir(dir)) await fs.chown(path.join(dir, f), 4321, 4322);
  assert.equal((await cli(dir, ['create', 'carol', '--role', 'viewer', '--generate'], { uid: 0 })).code, 0);
  const st = await fs.stat(file);
  assert.deepEqual([st.uid, st.gid, st.mode & 0o777], [4321, 4322, 0o600]);
});

// A group the user with uid 1000 is in besides their own, from /etc/group, or null.
async function extraGroupOf1000() {
  const passwd = await fs.readFile('/etc/passwd', 'utf8').catch(() => '');
  const name = passwd.split('\n').map((l) => l.split(':')).find((f) => f[2] === '1000')?.[0];
  if (!name) return null;
  const groups = (await fs.readFile('/etc/group', 'utf8').catch(() => '')).split('\n').map((l) => l.split(':'));
  const g = groups.find((f) => f.length >= 4 && f[2] !== '1000' && f[2] !== '0' && f[3].split(',').includes(name));
  return g ? Number(g[2]) : null;
}

test('cli: run as root, it takes on the groups of the data directory\'s owner, so a key file they read through a group can be read', { skip: process.platform === 'win32' || process.getuid?.() !== 0 }, async (t) => {
  const gid = await extraGroupOf1000();
  if (gid === null) return t.skip('uid 1000 has no other group here');
  const { data, keyFile } = await ownedSetup();
  await fs.chown(keyFile, 0, gid);
  await fs.chmod(keyFile, 0o440);
  const r = await runAs(['--data-dir', data, 'create', 'root', '--role', 'admin', '--generate'], { USERS_KEY_FILE: keyFile });
  assert.equal(r.code, 0, r.err);
});

test('cli: run as root, a data directory that is root\'s but others can write to, or that is reached through a folder or link another user controls, is refused', { skip: process.platform === 'win32' || process.getuid?.() !== 0 }, async () => {
  const keyFile = path.join(await tmp(), 'users.key');
  await fs.writeFile(keyFile, `${line(1, KEY1)}\n`, { mode: 0o400 });
  const env = { USERS_KEY_FILE: keyFile };
  const create = (data) => runAs(['--data-dir', data, 'create', 'root', '--role', 'admin', '--generate'], env);

  // Root's, writable by others.
  const open = path.join(await tmp(), 'data');
  await fs.mkdir(open);
  await fs.chmod(open, 0o777);
  let r = await create(open);
  assert.equal(r.code, 1);
  assert.match(r.err, /the data directory is root's, but other users can write to it \(mode 777\); make it writable by its owner only/);
  assert.deepEqual(await fs.readdir(open), []);
  // With the sticky bit, as /tmp has, others cannot replace what root puts there: it works.
  await fs.chmod(open, 0o1777);
  r = await create(open);
  assert.equal(r.code, 0, r.err);

  // A link another user can change, pointing at a folder of root's: the command stays away.
  const base = await tmp();
  await fs.chmod(base, 0o755);
  const theirs = path.join(base, 'theirs');
  await fs.mkdir(theirs);
  await fs.chown(theirs, 2000, 2000);
  const rootDir = path.join(await tmp(), 'root-data');
  await fs.mkdir(rootDir, { mode: 0o700 });
  await fs.symlink(rootDir, path.join(theirs, 'data'));
  await fs.lchown(path.join(theirs, 'data'), 2000, 2000);
  r = await create(path.join(theirs, 'data'));
  assert.equal(r.code, 1);
  assert.match(r.err, /^running as root, this does nothing in this data directory: .*theirs\/data is a link that a user other than root can change/m);
  assert.deepEqual(await fs.readdir(rootDir), [], 'nothing made in root\'s folder');

  // A data directory of uid 1000 inside a folder of uid 2000: 2000 could swap it.
  const inner = path.join(theirs, 'real');
  await fs.mkdir(inner);
  await fs.chown(inner, 1000, 1000);
  r = await create(inner);
  assert.equal(r.code, 1);
  assert.match(r.err, /theirs can be changed by a user other than root and the owner of the data directory/);
  assert.deepEqual(await fs.readdir(inner), []);

  // Not made yet, in a folder anyone can write to: someone else could make it first.
  r = await create(path.join(open, 'later'));
  assert.equal(r.code, 1);
  assert.match(r.err, /the data directory does not exist yet, and other users can make it first/);
});

test('cli: the repository and the image leave database files and backups out', async () => {
  for (const f of ['.gitignore', '.dockerignore']) {
    const lines = (await fs.readFile(path.join(here, '..', f), 'utf8')).split('\n').map((l) => l.trim());
    for (const want of ['*.db', '*.db-wal', '*.db-shm', 'backups/']) assert.ok(lines.includes(want), `${f}: ${want}`);
  }
});

// ---- reset-password and passkeys ----

const passkeyRecord = (label) => ({
  id: crypto.randomBytes(32).toString('base64url'),
  publicKey: crypto.randomBytes(77).toString('base64url'),
  counter: 0,
  transports: ['internal'],
  name: label,
  backupEligible: true,
  backedUp: true,
  rpId: 'status.example.org',
});

// A data folder with bob, who has two passkeys.
async function bobWithPasskeys() {
  const dir = await tmp();
  assert.equal((await cli(dir, ['create', 'bob', '--role', 'viewer', '--generate'])).code, 0);
  const store = await reopen(dir);
  await store.addPasskey('bob', passkeyRecord('Phone'));
  await store.addPasskey('bob', passkeyRecord('Planted'));
  return dir;
}

test('cli: reset-password takes --remove-passkeys, and the help says what it does', () => {
  assert.equal(parseArgs(['reset-password', 'bob', '--remove-passkeys']).removePasskeys, true);
  assert.equal(parseArgs(['reset-password', 'bob']).removePasskeys, false);
  // Only for reset-password.
  for (const command of ['reset-2fa', 'create', 'delete', 'set-role']) {
    const argv = command === 'create' ? ['create', 'bob', '--role', 'viewer', '--remove-passkeys'] : command === 'set-role' ? ['set-role', 'bob', 'viewer', '--remove-passkeys'] : [command, 'bob', '--remove-passkeys'];
    assert.throws(() => parseArgs(argv), /unknown option/, command);
  }
});

test('cli: reset-password says the passkeys still work when the flag is not given, and leaves them', async () => {
  const dir = await bobWithPasskeys();
  const r = await cli(dir, ['reset-password', 'bob', '--generate']);
  assert.equal(r.code, 0, r.err);
  assert.match(r.out, /The password of bob is reset\./);
  assert.match(r.out, /note: bob still has 2 passkeys, which still sign in without the new password\. Give --remove-passkeys to remove them/);
  assert.equal((await reopen(dir)).passkeys('bob').length, 2);
  // One passkey is said in the singular; a user without any gets no such line.
  const one = await bobWithPasskeys();
  const store = await reopen(one);
  await store.removePasskey('bob', store.passkeys('bob')[0].ref);
  assert.match((await cli(one, ['reset-password', 'bob', '--generate'])).out, /bob still has 1 passkey, which/);
  const none = await tmp();
  await cli(none, ['create', 'carol', '--role', 'viewer', '--generate']);
  const plain = await cli(none, ['reset-password', 'carol', '--generate']);
  assert.equal(plain.code, 0, plain.err);
  assert.doesNotMatch(plain.out, /passkey/);
});

test('cli: reset-password --remove-passkeys removes every passkey with the password, and says how many', async () => {
  const dir = await bobWithPasskeys();
  const r = await cli(dir, ['reset-password', 'bob', '--generate', '--remove-passkeys']);
  assert.equal(r.code, 0, r.err);
  assert.match(r.out, /The password of bob is reset\.\n2 passkeys of bob removed\./);
  assert.doesNotMatch(r.out, /still has/);
  const store = await reopen(dir);
  assert.equal(store.passkeys('bob').length, 0);
  assert.equal(store.secondFactorEnabled('bob'), false);
  const otp = /One-time password for bob: (\S+)/.exec(r.out)[1];
  assert.equal(await verifyPassword(otp, store.find('bob').phc, fakeHasher, pepperOf(store, 'bob')), true);
  // Again, with none left.
  assert.match((await cli(dir, ['reset-password', 'bob', '--generate', '--remove-passkeys'])).out, /bob had no passkeys to remove\./);
});

test('cli: reset-password --remove-passkeys changes nothing when the password is refused', async () => {
  const dir = await bobWithPasskeys();
  const r = await cli(dir, ['reset-password', 'bob', '--remove-passkeys'], { input: 'short' });
  assert.equal(r.code, 1);
  assert.equal((await reopen(dir)).passkeys('bob').length, 2);
  // A user from the config file has no password here, so nothing is removed either.
  const cfg = await configFile(dir);
  const config = await cli(dir, ['reset-password', 'alice', '--generate', '--remove-passkeys'], { config: cfg });
  assert.equal(config.code, 1);
  assert.match(config.err, /config file/);
});
