#!/usr/bin/env node
// Manages the users in the user store, users.db in the data directory: the way to make the first
// admin, and to get back in after losing the last admin or a phone. It uses the same store and
// checks as the website (lib/users.js): the same names and roles, the same password rules, and the
// last admin is kept unless --force is given. It also backs up the store, checks it, moves TOTP
// secrets to the newest key (rekey), and makes new keys (gen-key).
//
// It may run while the server runs. Each change is one short transaction (the password is hashed
// before it starts), and a running server picks the change up within a second and signs the user
// out. A store that cannot be read is left as it is, and nothing is done.
//
// It needs the same key as the server (USERS_KEY_FILE or USERS_KEY): TOTP secrets are encrypted
// with it, and new passwords are peppered with it. It only uses key versions the user store has
// recorded, which the server does when it starts: a version added to the key file is used once the
// server was restarted with it, so a running server can always read what this writes.
//
// Run as root on a data directory that another user owns (the server's), it becomes that user
// before it opens anything, the key file included: what it makes is then that user's, and nothing
// that user put in the data directory (a link in place of users.db-wal, say) can make root write
// or change the owner of a file elsewhere. The key file must then be readable by that user (or one
// of their groups), as it is for the server. A data directory whose path another user could change
// meanwhile is refused (see dropPrivileges).
//
//   node scripts/users.js list
//   node scripts/users.js create alice --role admin
//   node scripts/users.js create bob --role viewer --generate
//   node scripts/users.js set-role bob manage
//   node scripts/users.js reset-password bob --generate
//   node scripts/users.js reset-2fa alice
//   node scripts/users.js delete bob
//   node scripts/users.js backup /backups/users-2026-01-01.db
//   node scripts/users.js check
//   node scripts/users.js rekey
//   node scripts/users.js retire-users-json [--delete]
//   umask 077; node scripts/users.js gen-key --version 2 >> secrets/users.key
import crypto from 'node:crypto';
import fsSync from 'node:fs';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { MAX_PASSWORD_BYTES, argon2Available, argon2id, hashPassword, parsePhc, weakPassword } from '../lib/password.js';
import { ROLES, STORE_FILE, StoreBusyError, StoreError, USER_NAME_RE, UserError, UserStore, writeRefusal } from '../lib/users.js';
import { DB_FILE, RETIRED_FILE, checkSchema, retireJson } from '../lib/userdb.js';
import { KEY_BYTES, KeyError, MAX_VERSION, MIN_VERSION, loadKeys } from '../lib/keys.js';
import { loadConfigFile } from '../lib/config.js';
import { newOneTimePassword } from '../lib/admin.js';
import { UsageError, ask, readPipe } from './hash-password.js';

// How long a command waits for the server to finish a write of its own before giving up.
export const TIMEOUT_MS = 10_000;

export const USAGE = `Usage: node scripts/users.js [--data-dir DIR] [--config FILE] COMMAND [ARGS]

Manages the users in the user store, ${DB_FILE} in the data directory (DATA_DIR,
or ./data). It works while the server runs: a running server picks up a change
within a second and signs that user out.

It needs the same key as the server, in USERS_KEY_FILE (or USERS_KEY). In
Docker, docker compose exec website node scripts/users.js ... has it already.

Commands:
  list                                 every user, with role and second factor
                                       (app code, passkeys)
  create NAME --role ROLE [--generate] [--must-change]
                                       a new website user; ROLE is ${ROLES.join(', ')}
  set-role NAME ROLE [--force]         another role for a website user
  reset-password NAME [--generate] [--must-change]
                                       a new password for a website user
  reset-2fa NAME                       turns off two-step sign-in: removes the
                                       app code, passkeys, recovery codes and
                                       known devices
  delete NAME [--force]                deletes a website user
  backup FILE                          copies the store to FILE, a new file
                                       (mode 600); back the key up separately
  check                                checks the store and the keys, and says
                                       what each key version still protects
  rekey                                encrypts every TOTP secret with the
                                       newest key, and says what each key
                                       version still protects; restart the
                                       website after adding a key first
  retire-users-json [--delete]         renames users.json, once imported, to
                                       ${RETIRED_FILE} (mode 600); it holds
                                       second-factor secrets unencrypted.
                                       --delete deletes it instead (or
                                       ${RETIRED_FILE}, once renamed)
  gen-key [--version N]                prints a new key line, N:KEY (N is 1 by
                                       default), for the key file:
                                       umask 077; node scripts/users.js gen-key >> secrets/users.key

Run as root on a data directory another user owns, it runs as that user, so the
key file must be readable by them (as it is for the server).

The password is asked for twice on the terminal (not shown) or read from
stdin; it is never taken as an argument. --generate makes a one-time password
instead and shows it once; the user must change it at their next sign in, as
with --must-change. --force lets the last admin go (only for recovery).

  --data-dir DIR    the data directory (default: DATA_DIR, or ./data)
  --config FILE     the config file (default: CONFIG_FILE); its users count as
                    admins for the last-admin rule, and their names cannot be
                    used for a website user. Needed to reset the second factor
                    of a user from the config file.
  --server-stopped  no longer needed, and ignored
`;

const COMMANDS = { list: 0, create: 1, 'set-role': 2, 'reset-password': 1, 'reset-2fa': 1, delete: 1, backup: 1, check: 0, rekey: 0, 'retire-users-json': 0, 'gen-key': 0 };
const FLAGS = { create: ['--generate', '--must-change', '--role'], 'reset-password': ['--generate', '--must-change'], 'set-role': ['--force'], delete: ['--force'], 'gen-key': ['--version'], 'retire-users-json': ['--delete'] };
// The commands that change users. They took --server-stopped once, and still take it, ignored.
const USER_CHANGES = ['create', 'set-role', 'reset-password', 'reset-2fa', 'delete'];
// The commands that write to the store, and so need the key.
const NEEDS_KEY = [...USER_CHANGES, 'rekey'];

// Parses the arguments into {command, args, role, generate, mustChange, force, remove, serverStopped,
// version, dataDir, config}. Throws UsageError on anything else, and in particular on an extra
// word, which could be a password.
export function parseArgs(argv, env = {}) {
  const out = { command: null, args: [], role: null, generate: false, mustChange: false, force: false, remove: false, serverStopped: false, version: null, dataDir: env.DATA_DIR || null, config: env.CONFIG_FILE || null, help: false };
  const flags = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--help' || a === '-h') out.help = true;
    else if (a === '--data-dir' || a === '--config' || a === '--role' || a === '--version') {
      const v = argv[++i];
      if (v === undefined || v === '') throw new UsageError(`${a} needs a value`);
      if (a === '--data-dir') out.dataDir = v;
      else if (a === '--config') out.config = v;
      else if (a === '--role') out.role = v;
      else out.version = v;
      if (a === '--role' || a === '--version') flags.push(a);
    } else if (a.startsWith('-')) flags.push(a);
    else if (out.command === null) out.command = a;
    else out.args.push(a);
  }
  if (out.help) return out;
  if (out.command === null) throw new UsageError(`say what to do: ${Object.keys(COMMANDS).join(', ')}`);
  // What was typed is not repeated: a mistyped line may hold a password.
  if (!Object.hasOwn(COMMANDS, out.command)) throw new UsageError('unknown command');
  const want = COMMANDS[out.command];
  if (out.args.length !== want) {
    const needs = out.command === 'backup' ? 'a file to write' : want === 2 ? 'a name and a role' : 'a name';
    throw new UsageError(out.args.length > want ? 'too many arguments (a password is never taken as an argument: type it when asked, or pipe it to stdin)' : `${out.command} needs ${needs}`);
  }
  const allowed = [...(FLAGS[out.command] ?? []), ...(USER_CHANGES.includes(out.command) ? ['--server-stopped'] : [])];
  for (const f of flags) {
    if (!allowed.includes(f)) throw new UsageError(`unknown option for ${out.command}`);
    if (f === '--server-stopped') out.serverStopped = true;
    if (f === '--generate') out.generate = true;
    if (f === '--must-change') out.mustChange = true;
    if (f === '--force') out.force = true;
    if (f === '--delete') out.remove = true;
  }
  if (USER_CHANGES.includes(out.command) && !USER_NAME_RE.test(out.args[0])) throw new UsageError('a name is 1 to 32 letters, digits, dots, dashes or underscores, starting with a letter or digit');
  if (out.command === 'create' && !ROLES.includes(out.role)) throw new UsageError(`create needs --role, one of ${ROLES.join(', ')}`);
  if (out.command === 'set-role' && !ROLES.includes(out.args[1])) throw new UsageError(`the role must be one of ${ROLES.join(', ')}`);
  if (out.command === 'gen-key') {
    const v = out.version ?? '1';
    if (!/^[1-9]\d{0,4}$/.test(v) || Number(v) > MAX_VERSION) throw new UsageError(`--version must be a whole number from ${MIN_VERSION} to ${MAX_VERSION}`);
    out.version = Number(v);
  }
  return out;
}

// A new key line for the key file: "VERSION:KEY", KEY being base64url of 32 random bytes.
export const newKeyLine = (version) => `${version}:${crypto.randomBytes(KEY_BYTES).toString('base64url')}`;

// What the store refuses, in words.
const REFUSED = {
  'last-admin': 'this is the last admin; make another user an admin first (or give --force to recover)',
  config: 'this user is in the config file; change them there',
  unknown: 'there is no such user',
  exists: 'a user with this name exists already (in the user store or in the config file)',
  'bad-name': 'a name is 1 to 32 letters, digits, dots, dashes or underscores, starting with a letter or digit',
  'bad-role': `the role must be one of ${ROLES.join(', ')}`,
  full: 'the user store is full; delete users that are not needed any more',
};

const NO_KEY_TO_CHANGE = 'Changing the user store needs its key: set USERS_KEY_FILE (or USERS_KEY) to the key the server uses. For a first key, node scripts/users.js gen-key makes one (see "The user store key" in wiki/User-Store.md). Nothing was changed.';

const plural = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

// A user's two-step sign-in for list: off, or on with what it is made of.
function twoStep(u) {
  if (!u.secondFactor) return 'two-step off';
  const parts = [];
  if (u.totp) parts.push('app code');
  if (u.passkeys > 0) parts.push(plural(u.passkeys, 'passkey'));
  return `two-step on (${parts.join(' and ')})`;
}

// One line per key version: what it still protects, and whether it can go from the key file.
export function keyUsageLines(usage, keys) {
  const lines = [];
  for (const [v, u] of usage) {
    const given = keys?.has(v) === true;
    const current = keys?.current === v;
    const used = u.passwords + u.recoveryCodes + u.totp;
    const tag = current ? ' (current)' : given ? '' : ' (not in the key file)';
    if (used === 0) {
      lines.push(`version ${v}${tag}: unused${current ? '' : '; it can be removed from the key file'}`);
      continue;
    }
    const later = !current;
    const parts = [
      `${plural(u.passwords, 'password hash', 'password hashes')}${later && u.passwords > 0 ? ' (upgraded at next sign in)' : ''}`,
      `${plural(u.recoveryCodes, 'recovery code')}${later && u.recoveryCodes > 0 ? ' (replaced when used or regenerated)' : ''}`,
      `${plural(u.totp, 'TOTP secret')}${later && u.totp > 0 ? ' (moved by rekey)' : ''}`,
    ];
    lines.push(`version ${v}${tag}: ${parts.join(', ')}${current ? '' : '; still needed, keep it in the key file'}`);
  }
  return lines;
}

// Website users whose password hash has no pepper yet (made before there was a key, or imported).
function unpeppered(store) {
  let n = 0;
  for (const r of store.local.values()) {
    try {
      if ((parsePhc(r.passwordHash).keyid ?? null) === null) n++;
    } catch {
      // A hash that does not parse was refused when the store was read.
    }
  }
  return n;
}

function writeKeyUsage(store, stdout) {
  for (const line of keyUsageLines(store.db.keyUsage(), store.keys)) stdout.write(`${line}\n`);
  for (const v of store.unrecordedKeys ?? []) stdout.write(`version ${v}: in the key file, but not in use yet; restart the website so that it records it\n`);
  const plain = unpeppered(store);
  if (plain > 0) stdout.write(`${plural(plain, 'password hash', 'password hashes')} of website users without a pepper (made before there was a key; upgraded at next sign in)\n`);
}

// Why running as root on a data directory is not safe: thrown by dropPrivileges, with a message
// for the operator.
export class UnsafeError extends Error {}

const STICKY = 0o1000;

// Whether a folder can be changed (an entry in it renamed or replaced) by a user other than root
// and owner: it belongs to someone else, or others (or a group other than root's) may write to it
// without the sticky bit of a folder that root owns.
function othersCanChange(st, owner) {
  if (st.uid !== 0 && st.uid !== owner) return true;
  const guarded = (st.mode & STICKY) !== 0 && st.uid === 0;
  if ((st.mode & 0o002) !== 0 && !guarded) return true;
  if ((st.mode & 0o020) !== 0 && st.gid !== 0 && !guarded) return true;
  return false;
}

// Run as root, works out the data directory and who it should run as, and becomes that user
// before anything in it is opened. Gives {dir, became}: dir, the data directory with every link
// resolved, to be used from then on; became, the {uid, gid} it became, or null when it stayed root
// (root owns the data directory). Throws UnsafeError when the way to the data directory can be
// changed by someone other than root and its owner: they could then point it elsewhere between
// the check and its use, and have root work in a folder of theirs. Throws other errors when the
// user cannot be changed, so that nothing is done as root then.
//
// The owner is read from the folder itself, opened without following a link (fstat), not from its
// name. Becoming them: their groups (initgroups, so that a key file they read through a group can
// be read here too; none for a uid without a user entry), then their group, then their user, in
// that order, since root is needed for each.
export function dropPrivileges(dataDir, proc = process) {
  const given = path.resolve(dataDir);
  if (proc.platform === 'win32' || typeof proc.setuid !== 'function') return { dir: given, became: null };
  // The deepest folder on the way that exists; the rest is made later, as the owner.
  let base = given;
  const rest = [];
  while (!fsSync.lstatSync(base, { throwIfNoEntry: false })) {
    if (path.dirname(base) === base) throw new UnsafeError(`nothing of ${given} exists`);
    rest.unshift(path.basename(base));
    base = path.dirname(base);
  }
  // A link on the way given is only followed when root owns it and the folder it is in.
  for (let p = base; ; p = path.dirname(p)) {
    const l = fsSync.lstatSync(p);
    if (l.isSymbolicLink()) {
      const parent = fsSync.statSync(path.dirname(p));
      if (l.uid !== 0 || othersCanChange(parent, 0) || parent.uid !== 0) throw new UnsafeError(`${p} is a link that a user other than root can change`);
    }
    if (path.dirname(p) === p) break;
  }
  const realBase = fsSync.realpathSync(base);
  let fd;
  try {
    fd = fsSync.openSync(realBase, fsSync.constants.O_RDONLY | fsSync.constants.O_DIRECTORY | fsSync.constants.O_NOFOLLOW);
  } catch (err) {
    throw new UnsafeError(`${realBase} cannot be opened as a folder (${err.code ?? 'error'})`);
  }
  let st;
  try {
    st = fsSync.fstatSync(fd);
  } finally {
    fsSync.closeSync(fd);
  }
  const owner = { uid: st.uid, gid: st.gid };
  // Every folder above it must be root's or the owner's, and closed to others.
  for (let p = path.dirname(realBase); ; p = path.dirname(p)) {
    const a = fsSync.lstatSync(p);
    if (!a.isDirectory() || othersCanChange(a, owner.uid)) throw new UnsafeError(`${p} can be changed by a user other than root and the owner of the data directory`);
    if (path.dirname(p) === p) break;
  }
  // The sticky bit keeps others from replacing what is there, not from making it first.
  if (rest.length > 0 && (othersCanChange(st, owner.uid) || (st.mode & 0o002) !== 0 || ((st.mode & 0o020) !== 0 && st.gid !== 0))) {
    throw new UnsafeError(`the data directory does not exist yet, and other users can make it first in ${realBase}; make it, owned by the server's user, and run this again`);
  }
  if (owner.uid === 0 && rest.length === 0 && (st.mode & 0o022) !== 0 && !((st.mode & STICKY) !== 0)) {
    throw new UnsafeError(`the data directory is root's, but other users can write to it (mode ${(st.mode & 0o7777).toString(8)}); make it writable by its owner only (chmod go-w)`);
  }
  const dir = path.join(realBase, ...rest);
  if (owner.uid === 0) return { dir, became: null };
  try {
    proc.initgroups(owner.uid, owner.gid);
  } catch (err) {
    // A uid without a user entry here (a container's user, say) has no other groups.
    if (err.code !== 'ERR_UNKNOWN_CREDENTIAL') throw err;
    proc.setgroups([]);
  }
  proc.setgid(owner.gid);
  proc.setuid(owner.uid);
  if (proc.getuid() !== owner.uid || proc.geteuid() !== owner.uid || proc.getgid() !== owner.gid) throw new Error('could not become the owner of the data directory');
  return { dir, became: owner };
}

// Runs one command. io: {stdin, stdout, stderr, env, hasher, now, cwd, uid, timeoutMs, drop}. uid:
// who runs it (root is 0); drop: dropPrivileges, called when that is root. Gives the exit code.
export async function run(argv, { stdin = process.stdin, stdout = process.stdout, stderr = process.stderr, env = process.env, hasher = argon2id, now = Date.now, cwd = process.cwd(), uid = process.getuid?.() ?? null, timeoutMs = TIMEOUT_MS, drop = dropPrivileges } = {}) {
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
  if (args.command === 'gen-key') {
    stdout.write(`${newKeyLine(args.version)}\n`);
    stderr.write('Add this line to the key file (USERS_KEY_FILE), outside the data directory, readable by the server only (chmod 400). Keep a copy of it apart from the backups of the data: without it, two-step sign-in and peppered passwords cannot be used.\n');
    return 0;
  }
  if (args.serverStopped) stderr.write('note: --server-stopped is no longer needed and is ignored: changes work while the server runs\n');
  let dataDir = path.resolve(cwd, args.dataDir ?? 'data');
  const warn = (w) => stderr.write(`${w}\n`);

  let became = null;
  if (uid === 0 && process.platform !== 'win32') {
    try {
      const plan = drop(dataDir);
      if (plan !== null) ({ dir: dataDir, became } = plan);
    } catch (err) {
      if (err instanceof UnsafeError) stderr.write(`running as root, this does nothing in this data directory: ${err.message}. Run it as the server's user instead. Nothing was changed\n`);
      else stderr.write(`running as root, this could not become the owner of the data directory (${err.code ?? err.message}), and does nothing as root there; run it as the server's user. Nothing was changed\n`);
      return 1;
    }
    if (became !== null) stderr.write(`note: running as root; working as the owner of the data directory (uid ${became.uid}), as the server does\n`);
  }
  // What a file this cannot read after becoming that user needs.
  const asOwner = (err) => (became !== null && (err.code === 'EACCES' || err.code === 'EPERM') ? `. This runs as the owner of the data directory (uid ${became.uid}), like the server, so it must be readable by that user` : '');

  let keys;
  try {
    keys = await loadKeys(env, { warn, dataDir });
  } catch (err) {
    if (!(err instanceof KeyError)) throw err;
    stderr.write(`${err.message}${asOwner(err)}; nothing was changed\n`);
    return 1;
  }
  if (keys === null && NEEDS_KEY.includes(args.command)) {
    stderr.write(`${NO_KEY_TO_CHANGE}\n`);
    return 1;
  }

  let configUsers = [];
  if (args.config) {
    try {
      // storeUsers: true, so that a config file whose users are all in the user store still reads.
      configUsers = (await loadConfigFile(path.resolve(cwd, args.config), { storeUsers: true })).users;
    } catch (err) {
      stderr.write(`the config file cannot be read: ${err.message}${asOwner(err)}\n`);
      return 1;
    }
  } else if (USER_CHANGES.includes(args.command)) {
    stderr.write('note: no config file (--config or CONFIG_FILE): its users are not counted, and their names are not checked\n');
  }

  const there = (f) => fs.lstat(path.join(dataDir, f)).then(() => true, () => false);
  const existed = await there(DB_FILE);
  // users.db is made only for a command that can work in a new store: create, or any command when
  // there is a users.json to import. Anything else would only leave an empty store behind (in the
  // wrong folder, perhaps).
  if (!existed && args.command !== 'create' && !(await there(STORE_FILE))) {
    if (args.command === 'list') {
      stdout.write(`No users: there is no user store (${DB_FILE}) in ${dataDir} yet. node scripts/users.js create NAME --role admin makes the first user.\n`);
      return 0;
    }
    stderr.write(`There is no user store (${DB_FILE}) in ${dataDir} yet, so there is nothing to ${args.command === 'check' ? 'check' : 'change'}; nothing was made. Check --data-dir (or DATA_DIR); node scripts/users.js create NAME --role admin makes the first user.\n`);
    return 1;
  }
  let store;
  try {
    // recordKeys: false, so that this never brings in a key version the running server lacks.
    store = await UserStore.open({ dataDir, configUsers, keys, warn, now, timeoutMs, recordKeys: false });
  } catch (err) {
    if (err instanceof StoreBusyError) stderr.write(`${writeRefusal(err)}\n`);
    else if (err instanceof StoreError || err instanceof KeyError) stderr.write(`${err.message}\n`);
    else throw err;
    return 1;
  }
  try {
    if (uid === 0 && became === null && !existed && process.platform !== 'win32') {
      stderr.write(`warning: running as root, and root owns the data directory, so the new ${DB_FILE} is root's (mode 600) and a server running as another user cannot open it. Run this as the server's user instead (in Docker: docker compose exec website, which runs as node), or give the data directory and everything in it to that user.\n`);
    }
    if (keys !== null && NEEDS_KEY.includes(args.command)) {
      if (store.keys === null) {
        stderr.write('None of the key versions in USERS_KEY_FILE (or USERS_KEY) is known to the user store yet. Start (or restart) the website with this key first: it records new key versions when it starts. Nothing was changed.\n');
        return 1;
      }
      const waiting = (store.unrecordedKeys ?? []).filter((v) => v > store.keys.current);
      if (waiting.length > 0 && args.command === 'rekey') {
        stderr.write(`Key version ${waiting.at(-1)} is in the key file, but the user store does not know it yet. Restart the website first, so that it records the new version (it does that when it starts), then run rekey again. Nothing was changed.\n`);
        return 1;
      }
      if (waiting.length > 0) stderr.write(`note: key version ${waiting.at(-1)} in the key file is not in use yet: the website records a new version when it starts. This change uses version ${store.keys.current}; restart the website, then run rekey.\n`);
    }
    const code = await command(args, store, { stdin, stdout, stderr, hasher, cwd, dataDir, given: keys !== null });
    if (code === 1 && became !== null && args.command === 'backup') stderr.write(`The backup is written as the owner of the data directory (uid ${became.uid}): choose a folder that user can write to.\n`);
    return code;
  } finally {
    store.close();
  }
}

// One command on the open store.
async function command(args, store, { stdin, stdout, stderr, hasher, cwd, dataDir, given }) {
  const name = args.args[0];

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

  // Hashed before the store is written, with the pepper of the current key: no transaction is
  // ever open while the hash runs.
  const hash = (pw) => hashPassword(pw, undefined, hasher, store.currentPepper());

  // Set for the first user: the server then needs a restart, rather than picking the change up.
  let restart = false;
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
          const notes = [u.source === 'config' ? 'config file' : 'user store', twoStep(u), `${u.devices} devices`];
          if (u.mustChangePassword) notes.push('must change password');
          stdout.write(`${u.name}\t${u.role}\t${notes.join(', ')}\tlast sign in ${u.lastLogin ?? 'never'}\n`);
        }
        if (store.admins() === 0) stdout.write('There is no admin: nobody can open the users page. Make one with: create NAME --role admin\n');
        return 0;
      }
      case 'check': {
        const rows = store.db.sql.prepare('PRAGMA quick_check(20)').all();
        const ok = rows.length === 1 && rows[0].quick_check === 'ok';
        stdout.write(`${DB_FILE}: ${ok ? 'no damage found (quick_check)' : 'damaged (quick_check):'}\n`);
        if (!ok) {
          for (const r of rows) stdout.write(`  ${String(r.quick_check).slice(0, 200)}\n`);
          stdout.write(`Restore it from a backup (see "Backups" in wiki/User-Store.md).\n`);
          return 1;
        }
        // Checked when the store was opened as well; a store with another schema does not open.
        checkSchema(store.db.sql, store.db.migrations, store.db.userVersion());
        stdout.write('The schema is the one this version makes: no other tables, columns, triggers or views.\n');
        stdout.write(`${plural(store.local.size, 'website user')}, ${plural(store.factors.size, 'record')} of config file users\n`);
        if (store.keys === null && given) {
          stdout.write('None of the key versions given is recorded in the store yet, and nothing in it needs one. Start (or restart) the website with this key: it records new versions when it starts.\n');
          writeKeyUsage(store, stdout);
          return 0;
        }
        if (store.keys === null) {
          stdout.write('No key is given (USERS_KEY_FILE or USERS_KEY). The store has no users, so none is needed yet; one is needed before the first user is made.\n');
          return 0;
        }
        stdout.write(`Every key version the store needs is given, and each matches the key the store knows. Current key version: ${store.keys.current}.\n`);
        writeKeyUsage(store, stdout);
        return 0;
      }
      case 'retire-users-json': {
        const { file, removed } = retireJson(store.db, dataDir, { remove: args.remove });
        if (removed) stdout.write(`Deleted ${path.basename(file)}. Backups made before now still hold it, and the disk may too until the space is used again.\n`);
        else stdout.write(`Renamed users.json to ${path.basename(file)} (mode 600). It still holds the second-factor secrets and password hashes of the import: move it to offline storage, or delete it (retire-users-json --delete) once you have a backup of the store. Backups made before now hold it too.\n`);
        return 0;
      }
      case 'rekey': {
        const { totp } = store.db.rekey();
        stdout.write(`${totp === 1 ? '1 TOTP secret was' : `${totp} TOTP secrets were`} encrypted again with key version ${store.keys.current}.\n`);
        writeKeyUsage(store, stdout);
        return 0;
      }
      case 'backup': {
        const file = path.resolve(cwd, name);
        store.db.backup(file);
        stdout.write(`Backed up the user store to ${file} (mode 600). Back up the key file separately: without its key the backup has no usable two-step sign-in or peppered passwords.\n`);
        return 0;
      }
      case 'create': {
        if (store.lookup(name)) throw new UserError('exists', 'exists');
        const pw = await password();
        const passwordHash = await hash(pw);
        // The website turns sign-in on only when it starts with users.
        const first = !store.hasLocalUsers() && store.config.size === 0;
        await store.createUser({ name, role: args.role, passwordHash, mustChangePassword: args.generate || args.mustChange });
        stdout.write(`Made ${name} (${args.role}).\n`);
        if (first) {
          stdout.write('This is the first user: if the website is running without users, restart the website to turn on sign-in.\n');
          restart = true;
        }
        // A user moved out of the config file: their old second factor stays where it was, unused.
        if (store.factors.has(name.toLowerCase())) {
          stdout.write(`note: the user store still has the two-step sign-in and devices ${name} had as a config file user. The new user does not use them (they start without two-step sign-in); they come back only if ${name} is put in the config file again.\n`);
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
        const passwordHash = await hash(pw);
        await store.setPassword(name, passwordHash, { mustChangePassword: args.generate || args.mustChange });
        stdout.write(`The password of ${store.lookup(name).name} is reset.\n`);
        if (args.generate) showOnce(pw);
        break;
      }
      case 'reset-2fa': {
        if (!store.lookup(name)) throw new UserError('unknown', 'unknown');
        const { passkeys } = store.secondFactors(name);
        await store.resetSecondFactor(name);
        // The server forgets known devices when an admin resets this on the website; here too.
        const { saved } = store.dropDevices(name);
        await saved;
        const gone = passkeys > 0 ? `their app code, ${plural(passkeys, 'passkey')}, recovery codes and known devices are gone` : 'their app code, recovery codes and known devices are gone';
        stdout.write(`Two-step sign-in of ${store.lookup(name).name} is off: ${gone}.\n`);
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
    const refusal = writeRefusal(err);
    if (refusal !== null) {
      stderr.write(`${refusal}\n`);
      return 1;
    }
    if (err instanceof StoreError || err instanceof KeyError) {
      stderr.write(`${err.message}\n`);
      return 1;
    }
    if (args.command === 'backup') {
      stderr.write(`the backup could not be written: ${err.code === 'EUNSAFE' ? err.message : (err.code ?? err.message)}\n`);
      return 1;
    }
    stderr.write(`the user store could not be written (${err.code ?? err.message}); nothing was changed\n`);
    return 1;
  }
  if (store.admins() === 0) stdout.write('warning: there is no admin now; nobody can open the users page.\n');
  if (!restart) stdout.write('A running server picks this up within a second.\n');
  return 0;
}

// Run as a program, not when the tests import it.
if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) process.exitCode = await run(process.argv.slice(2));
