// How server.js starts with the user store: the key it needs, the import of users.json, and the
// starts it refuses. Each test runs server.js as a process of its own, in its own data directory.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { hashPassword } from '../lib/password.js';
import { STORE_FILE, hashRecoveryCode } from '../lib/users.js';
import { base32Encode } from '../lib/totp.js';
import { DB_FILE, NO_KEY } from '../lib/userdb.js';
import { AUDIT_FILE } from '../lib/audit.js';
import { fakeHasher } from './helpers/fake-hasher.js';

const SERVER = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'server.js');
const tmp = () => fs.mkdtemp(path.join(os.tmpdir(), 'server-start-'));
const newKey = () => `1:${crypto.randomBytes(32).toString('base64url')}`;

const freePort = () =>
  new Promise((resolve) => {
    const probe = net.createServer().listen(0, '127.0.0.1', () => {
      const p = probe.address().port;
      probe.close(() => resolve(p));
    });
  });

// Runs server.js with env added to a bare environment. Gives {child, out(), err(), exited}.
function run(env) {
  const child = spawn(process.execPath, [SERVER], { env: { PATH: process.env.PATH, HOST: '127.0.0.1', ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '';
  let err = '';
  child.stdout.on('data', (c) => (out += c));
  child.stderr.on('data', (c) => (err += c));
  const timer = setTimeout(() => child.kill('SIGKILL'), 15_000);
  const exited = new Promise((resolve) => child.on('exit', (code) => (clearTimeout(timer), resolve(code))));
  return { child, out: () => out, err: () => err, exited };
}

// Runs server.js until it listens, then stops it as an operator would (SIGTERM). Gives its output.
async function startAndStop(env) {
  const p = run({ PORT: String(await freePort()), ...env });
  for (let i = 0; i < 200 && !/listening on/.test(p.out()) && p.child.exitCode === null; i++) await new Promise((r) => setTimeout(r, 50));
  assert.match(p.out(), /listening on/, p.err());
  p.child.kill('SIGTERM');
  assert.equal(await p.exited, 0, p.err());
  return { out: p.out(), err: p.err() };
}

// Runs server.js where it must refuse to start. Gives what it said.
async function refused(env) {
  const p = run({ PORT: '1', ...env });
  assert.equal(await p.exited, 1, p.out());
  assert.doesNotMatch(p.err(), /\n\s+at /, 'no stack trace');
  return p.err();
}

const auditLines = async (dataDir) => (await fs.readFile(path.join(dataDir, AUDIT_FILE), 'utf8').catch(() => '')).trim().split('\n').filter(Boolean).map((l) => JSON.parse(l));

// A users.json as an older version wrote it: bob, with two-step sign-in on and a recovery code,
// which the import encrypts and wraps with the current key.
async function usersJson(dataDir) {
  const bob = {
    name: 'bob', role: 'admin', passwordHash: await hashPassword('a good password', undefined, fakeHasher), created: '2026-01-01T00:00:00.000Z',
    totp: { secret: base32Encode(crypto.randomBytes(20)), enabled: true, lastUsedStep: null }, recoveryCodes: [hashRecoveryCode('abcd-efgh-ijkl-mnop')],
  };
  const text = JSON.stringify({ version: 1, users: [bob], configUsers: [] }, null, 2);
  await fs.writeFile(path.join(dataDir, STORE_FILE), text);
  return text;
}

test('server: users in the config file and no key: it refuses to start, says how to make one, and makes nothing', async () => {
  const dataDir = await tmp();
  const config = path.join(dataDir, 'config.yaml');
  await fs.writeFile(config, `users:\n  - name: alice\n    password_hash: '${await hashPassword('a good password', undefined, fakeHasher)}'\nnodes:\n  - address: 127.0.0.1:9\n`);
  const err = await refused({ DATA_DIR: dataDir, CONFIG_FILE: config });
  assert.equal(err.trim().split('\n').at(-1), `cannot start: ${NO_KEY}`);
  assert.match(err, /USERS_KEY_FILE/);
  assert.match(err, /gen-key/);
  assert.deepEqual(await auditLines(dataDir), []);
});

test('server: users.json with users and no key: it refuses to start, and leaves users.json as it is without making users.db', async () => {
  const dataDir = await tmp();
  const text = await usersJson(dataDir);
  const err = await refused({ DATA_DIR: dataDir });
  assert.match(err, new RegExp(`cannot start: ${NO_KEY.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`));
  assert.equal(await fs.readFile(path.join(dataDir, STORE_FILE), 'utf8'), text);
  assert.deepEqual(await fs.readdir(dataDir), [STORE_FILE]);
});

test('server: without users it needs no key, and starts', async () => {
  const dataDir = await tmp();
  await startAndStop({ DATA_DIR: dataDir });
  assert.deepEqual(await auditLines(dataDir), []);
});

test('server: users.json is imported at the first start only; the import and the new key are audited once', async () => {
  const dataDir = await tmp();
  const text = await usersJson(dataDir);
  const key = newKey();
  await startAndStop({ DATA_DIR: dataDir, USERS_KEY: key });
  const first = await auditLines(dataDir);
  assert.deepEqual(first.map((l) => [l.event, l.users, l.configUsers, l.version]), [['user-store-imported', 1, 0, undefined], ['key-added', undefined, undefined, 1]]);
  assert.equal(JSON.stringify(first).includes(key.slice(2)), false, 'the key is never in the audit log');
  assert.ok((await fs.readdir(dataDir)).includes(DB_FILE));
  // users.json is left as it was.
  assert.equal(await fs.readFile(path.join(dataDir, STORE_FILE), 'utf8'), text);
  // The second start reads users.db: no import, no new key.
  const second = await startAndStop({ DATA_DIR: dataDir, USERS_KEY: key });
  assert.deepEqual(await auditLines(dataDir), first);
  assert.doesNotMatch(second.err, /changed after it was imported/);
  // users.json changed since: it is not imported again, and the operator is told.
  await fs.writeFile(path.join(dataDir, STORE_FILE), text.replace('"bob"', '"carol"'));
  const third = await startAndStop({ DATA_DIR: dataDir, USERS_KEY: key });
  assert.match(third.err, /users\.json changed after it was imported on .* and is not read/);
  assert.deepEqual(await auditLines(dataDir), first);
});

test('server: a wrong key, or one missing the version the store needs, is refused and changes nothing; the key never shows', async () => {
  const dataDir = await tmp();
  await usersJson(dataDir);
  await startAndStop({ DATA_DIR: dataDir, USERS_KEY: newKey() });
  const files = async () => Promise.all([DB_FILE, `${DB_FILE}-wal`].map((f) => fs.readFile(path.join(dataDir, f)).catch(() => null)));
  const before = await files();
  const wrong = newKey();
  const err = await refused({ DATA_DIR: dataDir, USERS_KEY: wrong });
  assert.match(err, /cannot start: key version 1 is not the key the user store was made with/);
  assert.equal(err.includes(wrong.slice(2)), false);
  // Version 1 left out: the store's secrets need it.
  const other = `2:${crypto.randomBytes(32).toString('base64url')}`;
  assert.match(await refused({ DATA_DIR: dataDir, USERS_KEY: other }), /cannot start: the user store needs key version 1; it is not in USERS_KEY_FILE/);
  assert.deepEqual(await files(), before);
  // A key that cannot be read at all.
  assert.match(await refused({ DATA_DIR: dataDir, USERS_KEY: '1:short' }), /cannot start: USERS_KEY cannot be used: key entry 1 \(version 1\) is not 32 bytes of base64url/);
  assert.match(await refused({ DATA_DIR: dataDir, USERS_KEY_FILE: path.join(dataDir, 'nope') }), /cannot start: USERS_KEY_FILE .* cannot be read/);
  assert.deepEqual(await files(), before);
});

test('server: a password hash with a keyid in the config file is a plain config error, without a stack trace', async () => {
  const dataDir = await tmp();
  const config = path.join(dataDir, 'config.yaml');
  const peppered = await hashPassword('a good password', undefined, fakeHasher, { keyid: 1, secret: crypto.randomBytes(32) });
  await fs.writeFile(config, `users:\n  - name: alice\n    password_hash: '${peppered}'\nnodes:\n  - address: 127.0.0.1:9\n`);
  const err = await refused({ DATA_DIR: dataDir, CONFIG_FILE: config, USERS_KEY: newKey() });
  assert.match(err.trim().split('\n').at(-1), /^cannot start: CONFIG_FILE: .*password_hash has a keyid: hashes in the config file cannot be peppered/);
});

test('server: a users.json with users that was never imported, next to a store and a config file without users, stops the start', async () => {
  const dataDir = await tmp();
  const key = newKey();
  // The store was made first, without users; users.json was put there later.
  await startAndStop({ DATA_DIR: dataDir, USERS_KEY: key });
  await usersJson(dataDir);
  const err = await refused({ DATA_DIR: dataDir, USERS_KEY: key });
  assert.match(err, /cannot start: users\.json in the data directory has users, but was never imported: users\.db was made without it and has no users, so the site would run without sign-in\. To import it, stop the server, move users\.db\* away and start/);
  // With users in the config file the site has sign-in: it starts, and warns.
  const config = path.join(dataDir, 'config.yaml');
  await fs.writeFile(config, `users:\n  - name: alice\n    password_hash: '${await hashPassword('a good password', undefined, fakeHasher)}'\nnodes:\n  - address: 127.0.0.1:9\n`);
  const ok = await startAndStop({ DATA_DIR: dataDir, USERS_KEY: key, CONFIG_FILE: config });
  assert.match(ok.err, /users\.json is in the data directory but is not read/);
});

test('server: users.json left after its import is warned about at every start; an import into a new users.db after an older one is audited as such', async () => {
  const dataDir = await tmp();
  await usersJson(dataDir);
  const key = newKey();
  const first = await startAndStop({ DATA_DIR: dataDir, USERS_KEY: key });
  assert.match(first.err, /users\.json is still in the data directory\. It holds the second-factor secrets unencrypted/);
  const second = await startAndStop({ DATA_DIR: dataDir, USERS_KEY: key });
  assert.match(second.err, /users\.json is still in the data directory/);
  // users.db* moved away: users.json is imported again, loudly.
  for (const f of await fs.readdir(dataDir)) if (f.startsWith(DB_FILE)) await fs.rm(path.join(dataDir, f));
  const third = await startAndStop({ DATA_DIR: dataDir, USERS_KEY: key });
  assert.match(third.err, /WARNING: users\.json was imported into a new users\.db, but a user store with users was made in this data directory before/);
  const imports = (await auditLines(dataDir)).filter((l) => l.event === 'user-store-imported');
  assert.deepEqual(imports.map((l) => l.again ?? false), [false, true]);
});
