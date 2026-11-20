#!/usr/bin/env node
// Manages the users in users.json, offline: the way to make the first admin of the user store, and
// to get back in after losing the last admin or a phone. It uses the same store and checks as the
// website (lib/users.js): the same names and roles, the same password rules, and the last admin is
// kept unless --force is given. The file is written whole, to a temporary file with mode 0600 that
// is then renamed. A users.json that cannot be read is left as it is, and nothing is done.
//
// The server reads users.json only when it starts, and writes it whole from what it has in memory:
// stop the server first, and start it again afterwards. A running server touches users.lock in the
// data directory every 10 seconds; a change is refused while that file is younger than 30 seconds,
// unless --server-stopped says the server is not running (it crashed, or runs elsewhere). A server
// that finds users.json changed under it refuses to write it until it is restarted.
//
// The new file keeps the owner of the old one; run as root without one, it is root's, which is
// warned about (the server, as another user, could not read it).
//
//   node scripts/users.js list
//   node scripts/users.js create alice --role admin
//   node scripts/users.js create bob --role viewer --generate
//   node scripts/users.js set-role bob manage
//   node scripts/users.js reset-password bob --generate
//   node scripts/users.js reset-2fa alice
//   node scripts/users.js delete bob
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { MAX_PASSWORD_BYTES, argon2Available, argon2id, hashPassword, weakPassword } from '../lib/password.js';
import { LOCK_FILE, ROLES, STORE_FILE, StoreChangedError, StoreError, StoreFullError, USER_NAME_RE, UserError, UserStore, serverHeartbeat } from '../lib/users.js';
import { loadConfigFile } from '../lib/config.js';
import { newOneTimePassword } from '../lib/admin.js';
import { UsageError, ask, readPipe } from './hash-password.js';

export const USAGE = `Usage: node scripts/users.js [--data-dir DIR] [--config FILE] COMMAND [ARGS]

Manages the users in users.json in the data directory (DATA_DIR, or ./data),
offline. Stop the server first and start it again afterwards: it reads
users.json only when it starts. While the server runs it touches users.lock
in the data directory every 10 seconds, and changes are refused while that
file is younger than 30 seconds. A server that finds users.json changed under
it saves nothing more to it until it is restarted.

Commands:
  list                                 every user, with role and second factor
  create NAME --role ROLE [--generate] [--must-change]
                                       a new website user; ROLE is ${ROLES.join(', ')}
  set-role NAME ROLE [--force]         another role for a website user
  reset-password NAME [--generate] [--must-change]
                                       a new password for a website user
  reset-2fa NAME                       turns off two-step sign-in, removes the
                                       recovery codes and known devices
  delete NAME [--force]                deletes a website user

The password is asked for twice on the terminal (not shown) or read from
stdin; it is never taken as an argument. --generate makes a one-time password
instead and shows it once; the user must change it at their next sign in, as
with --must-change. --force lets the last admin go (only for recovery).

  --server-stopped  change users.json although users.lock is recent: only when
                    you know the server is not running (it was killed, or
                    runs on another copy of the data directory)
  --data-dir DIR    the data directory (default: DATA_DIR, or ./data)
  --config FILE     the config file (default: CONFIG_FILE); its users count as
                    admins for the last-admin rule, and their names cannot be
                    used for a website user. Needed to reset the second factor
                    of a user from the config file.
`;

const COMMANDS = { list: 0, create: 1, 'set-role': 2, 'reset-password': 1, 'reset-2fa': 1, delete: 1 };
const FLAGS = { create: ['--generate', '--must-change'], 'reset-password': ['--generate', '--must-change'], 'set-role': ['--force'], delete: ['--force'] };
// Taken by every command that changes users.json.
const WRITE_FLAGS = ['--server-stopped'];

// Parses the arguments into {command, args, role, generate, mustChange, force, dataDir, config}.
// Throws UsageError on anything else, and in particular on an extra word, which could be a password.
export function parseArgs(argv, env = {}) {
  const out = { command: null, args: [], role: null, generate: false, mustChange: false, force: false, serverStopped: false, dataDir: env.DATA_DIR || null, config: env.CONFIG_FILE || null, help: false };
  const flags = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--help' || a === '-h') out.help = true;
    else if (a === '--data-dir' || a === '--config' || a === '--role') {
      const v = argv[++i];
      if (v === undefined || v === '') throw new UsageError(`${a} needs a value`);
      if (a === '--data-dir') out.dataDir = v;
      else if (a === '--config') out.config = v;
      else out.role = v;
      if (a === '--role') flags.push(a);
    } else if (a.startsWith('-')) flags.push(a);
    else if (out.command === null) out.command = a;
    else out.args.push(a);
  }
  if (out.help) return out;
  if (out.command === null) throw new UsageError('say what to do: list, create, set-role, reset-password, reset-2fa or delete');
  // What was typed is not repeated: a mistyped line may hold a password.
  if (!Object.hasOwn(COMMANDS, out.command)) throw new UsageError('unknown command');
  if (out.args.length !== COMMANDS[out.command]) throw new UsageError(out.args.length > COMMANDS[out.command] ? 'too many arguments (a password is never taken as an argument: type it when asked, or pipe it to stdin)' : `${out.command} needs ${COMMANDS[out.command] === 2 ? 'a name and a role' : 'a name'}`);
  const allowed = [...(FLAGS[out.command] ?? []), ...(out.command === 'create' ? ['--role'] : []), ...(out.command === 'list' ? [] : WRITE_FLAGS)];
  for (const f of flags) {
    if (!allowed.includes(f)) throw new UsageError(`unknown option for ${out.command}`);
    if (f === '--server-stopped') out.serverStopped = true;
    if (f === '--generate') out.generate = true;
    if (f === '--must-change') out.mustChange = true;
    if (f === '--force') out.force = true;
  }
  if (out.args[0] !== undefined && !USER_NAME_RE.test(out.args[0])) throw new UsageError('a name is 1 to 32 letters, digits, dots, dashes or underscores, starting with a letter or digit');
  if (out.command === 'create' && !ROLES.includes(out.role)) throw new UsageError(`create needs --role, one of ${ROLES.join(', ')}`);
  if (out.command === 'set-role' && !ROLES.includes(out.args[1])) throw new UsageError(`the role must be one of ${ROLES.join(', ')}`);
  return out;
}

// What the store refuses, in words.
const REFUSED = {
  'last-admin': 'this is the last admin; make another user an admin first (or give --force to recover)',
  config: 'this user is in the config file; change them there',
  unknown: 'there is no such user',
  exists: 'a user with this name exists already (in users.json or in the config file)',
  'bad-name': 'a name is 1 to 32 letters, digits, dots, dashes or underscores, starting with a letter or digit',
  'bad-role': `the role must be one of ${ROLES.join(', ')}`,
  full: 'the user store is full; delete users that are not needed any more',
};

// Runs one command. io: {stdin, stdout, stderr, env, hasher, now, cwd, uid}. Gives the exit code.
export async function run(argv, { stdin = process.stdin, stdout = process.stdout, stderr = process.stderr, env = process.env, hasher = argon2id, now = Date.now, cwd = process.cwd(), uid = process.getuid?.() ?? null } = {}) {
  let args;
  try {
    args = parseArgs(argv, env);
  } catch (err) {
    if (!(err instanceof UsageError)) throw err;
    stderr.write(`${err.message}\n\n${USAGE}`);
    return 2;
  }
  if (args.help) {
    stdout.write(USAGE);
    return 0;
  }
  const dataDir = path.resolve(cwd, args.dataDir ?? 'data');
  if (args.command !== 'list') {
    // A running server would write over the change, or refuse to save anything until restarted.
    let age = null;
    try {
      age = await serverHeartbeat(dataDir, now());
    } catch (err) {
      stderr.write(`${LOCK_FILE} in the data directory cannot be read (${err.code ?? err.message}); nothing was changed\n`);
      return 1;
    }
    if (age !== null && !args.serverStopped) {
      stderr.write(`The server seems to be running: ${LOCK_FILE} in the data directory was touched ${Math.max(0, Math.round(age / 1000))} seconds ago. Stop it first, then run this again; nothing was changed. If it is not running (it was killed, for one), wait 30 seconds or give --server-stopped.\n`);
      return 1;
    }
    if (uid === 0) {
      const exists = await fs.stat(path.join(dataDir, STORE_FILE)).then(() => true, () => false);
      if (!exists) stderr.write(`warning: running as root, so the new ${STORE_FILE} is owned by root (mode 600) and a server running as another user cannot read it. Give it to the server's user afterwards (chown), or run this as that user (in Docker: --user node).\n`);
    }
  }
  let configUsers = [];
  if (args.config) {
    try {
      // storeUsers: true, so that a config file whose users are all in users.json still reads.
      configUsers = (await loadConfigFile(path.resolve(cwd, args.config), { storeUsers: true })).users;
    } catch (err) {
      stderr.write(`the config file cannot be read: ${err.message}\n`);
      return 1;
    }
  } else if (args.command !== 'list') {
    stderr.write('note: no config file (--config or CONFIG_FILE): its users are not counted, and their names are not checked\n');
  }
  let store;
  try {
    store = await UserStore.open({ dataDir, configUsers, warn: (w) => stderr.write(`${w}\n`), now });
  } catch (err) {
    if (!(err instanceof StoreError)) throw err;
    stderr.write(`${err.message}\n`);
    return 1;
  }
  const name = args.args[0];
  const restart = () => stdout.write('Start the server again (or restart it) for this to apply: it reads users.json only when it starts.\n');

  // The password for a create or reset: a one-time one, or one asked for and checked.
  async function password() {
    if (args.generate) return newOneTimePassword();
    if (!argon2Available() && hasher === argon2id) throw new UsageError(`this needs Node.js 24.7 or later for Argon2id (this is ${process.version})`);
    let pw;
    if (stdin.isTTY) {
      pw = await ask('Password: ', stdin, stderr);
      const again = await ask('Same password again: ', stdin, stderr);
      if (again !== pw) throw new UsageError('the two passwords are not the same');
    } else {
      pw = await readPipe(stdin);
    }
    if (Buffer.byteLength(pw) > MAX_PASSWORD_BYTES) throw new UsageError(`the password is longer than ${MAX_PASSWORD_BYTES} bytes`);
    const weak = weakPassword(pw, name);
    if (weak) throw new UsageError(weak.replace('The new password', 'The password').replace('your name', 'the name'));
    return pw;
  }

  const showOnce = (pw) => {
    stdout.write(`One-time password for ${store.lookup(name)?.name ?? name}: ${pw}\n`);
    stdout.write('It is shown only now. Pass it on in a safe way; they must choose a new password when they sign in with it.\n');
  };

  try {
    switch (args.command) {
      case 'list': {
        const users = store.overview();
        if (users.length === 0) stdout.write('No users.\n');
        for (const u of users) {
          const notes = [u.source === 'config' ? 'config file' : 'users.json', u.secondFactor ? 'two-step on' : 'two-step off', `${u.devices} devices`];
          if (u.mustChangePassword) notes.push('must change password');
          stdout.write(`${u.name}\t${u.role}\t${notes.join(', ')}\tlast sign in ${u.lastLogin ?? 'never'}\n`);
        }
        if (store.admins() === 0) stdout.write('There is no admin: nobody can open the users page. Make one with: create NAME --role admin\n');
        return 0;
      }
      case 'create': {
        if (store.lookup(name)) throw new UserError('exists', 'exists');
        const pw = await password();
        const passwordHash = await hashPassword(pw, undefined, hasher);
        await store.createUser({ name, role: args.role, passwordHash, mustChangePassword: args.generate || args.mustChange });
        stdout.write(`Made ${name} (${args.role}).\n`);
        // A user moved out of the config file: their old second factor stays where it was, unused.
        if (store.factors.has(name.toLowerCase())) {
          stdout.write(`note: users.json still has the two-step sign-in and devices ${name} had as a config file user. The new user does not use them (they start without two-step sign-in); they come back only if ${name} is put in the config file again.\n`);
        }
        if (args.generate) showOnce(pw);
        break;
      }
      case 'set-role':
        await store.setRole(name, args.args[1], { force: args.force });
        stdout.write(`${store.lookup(name).name} is now ${args.args[1]}.\n`);
        break;
      case 'reset-password': {
        store.localUser(name);
        const pw = await password();
        const passwordHash = await hashPassword(pw, undefined, hasher);
        await store.setPassword(name, passwordHash, { mustChangePassword: args.generate || args.mustChange });
        stdout.write(`The password of ${store.lookup(name).name} is reset.\n`);
        if (args.generate) showOnce(pw);
        break;
      }
      case 'reset-2fa': {
        if (!store.lookup(name)) throw new UserError('unknown', 'unknown');
        await store.resetSecondFactor(name);
        // The server forgets known devices when an admin resets this on the website; here too.
        const { saved } = store.dropDevices(name);
        await saved;
        stdout.write(`Two-step sign-in of ${store.lookup(name).name} is off, and their recovery codes and known devices are gone.\n`);
        break;
      }
      case 'delete': {
        const shown = store.localUser(name).name;
        await store.deleteUser(name, { force: args.force });
        stdout.write(`Deleted ${shown}.\n`);
        break;
      }
    }
  } catch (err) {
    if (err instanceof UsageError) {
      stderr.write(`${err.message}\n`);
      return 1;
    }
    if (err instanceof UserError) {
      const extra = err.code === 'unknown' && !args.config ? ' (a user from the config file needs --config or CONFIG_FILE)' : '';
      stderr.write(`${REFUSED[err.code] ?? err.message}${extra}; nothing was changed\n`);
      return 1;
    }
    if (err instanceof StoreFullError || err instanceof StoreChangedError) {
      stderr.write(`${err.message}; nothing was changed\n`);
      return 1;
    }
    stderr.write(`users.json could not be written (${err.code ?? err.message}); nothing was changed\n`);
    return 1;
  }
  if (store.admins() === 0) stdout.write('warning: there is no admin now; nobody can open the users page.\n');
  restart();
  return 0;
}

// Run as a program, not when the tests import it.
if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) process.exitCode = await run(process.argv.slice(2));
