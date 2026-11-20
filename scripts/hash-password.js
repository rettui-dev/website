#!/usr/bin/env node
// Makes the password_hash of a status page user. The password is read from the
// terminal (not shown, asked twice) or from piped stdin, never from the command
// line, where it would end up in the shell history and the process list.
//
//   npm run hash-password -- --name alice
//   printf '%s' "$PASSWORD" | node scripts/hash-password.js --name alice
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DEFAULTS, MAX_PASSWORD_BYTES, argon2Available, checkCosts, hashPassword } from '../lib/password.js';

const USAGE = `Usage: node scripts/hash-password.js [--name NAME] [--memory KIB] [--passes N] [--parallelism N]

Reads a password from the terminal (asked twice, not shown) or from stdin, and
prints its Argon2id hash and a line to paste under "users:" in the config file.
The password cannot be given as an argument.

  --name NAME        the user name for the pasted line (default: name)
  --memory KIB       memory cost in KiB (default ${DEFAULTS.memory})
  --passes N         time cost (default ${DEFAULTS.passes})
  --parallelism N    lanes (default ${DEFAULTS.parallelism})
`;

export class UsageError extends Error {}

// Parses the arguments into {name, costs}. Throws UsageError on anything else,
// and in particular on a bare word, which could be a password.
export function parseArgs(argv) {
  const out = { name: 'name', costs: { ...DEFAULTS }, help: false };
  const numbers = { '--memory': 'memory', '--passes': 'passes', '--parallelism': 'parallelism' };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--help' || a === '-h') out.help = true;
    else if (a === '--name' || Object.hasOwn(numbers, a)) {
      const v = argv[++i];
      if (v === undefined) throw new UsageError(`${a} needs a value`);
      if (a === '--name') {
        if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$/.test(v)) throw new UsageError('--name must be 1 to 32 letters, digits, dots, dashes or underscores, starting with a letter or digit');
        out.name = v;
      } else {
        if (!/^\d{1,10}$/.test(v)) throw new UsageError(`${a} must be a whole number`);
        out.costs[numbers[a]] = Number(v);
      }
    } else if (a.startsWith('-')) throw new UsageError(`unknown option ${a}`);
    else throw new UsageError('the password cannot be given as an argument: type it when asked, or pipe it to stdin');
  }
  try {
    checkCosts(out.costs);
  } catch (err) {
    throw new UsageError(err.message);
  }
  return out;
}

// The line for the config file. The name is quoted: YAML would read a bare
// 123, true or null as a number, a boolean or nothing, and the config needs text.
// The name and the hash have no quotes of their own (see parseArgs and formatPhc).
export function usersLine(name, phc) {
  return `  - { name: '${name}', password_hash: '${phc}' }`;
}

// The password of piped input: everything, less one final line break.
export function fromPipe(text) {
  return text.replace(/\r?\n$/, '');
}

export async function readPipe(stream) {
  const chunks = [];
  let size = 0;
  for await (const c of stream) {
    size += c.length;
    if (size > MAX_PASSWORD_BYTES + 2) throw new UsageError(`the password is longer than ${MAX_PASSWORD_BYTES} bytes`);
    chunks.push(c);
  }
  return fromPipe(Buffer.concat(chunks).toString('utf8'));
}

// Asks for a line on the terminal without showing it.
export function ask(prompt, input, output) {
  return new Promise((resolve, reject) => {
    output.write(prompt);
    let text = '';
    input.setRawMode(true);
    input.resume();
    input.setEncoding('utf8');
    const done = (err, value) => {
      input.setRawMode(false);
      input.pause();
      input.off('data', onData);
      output.write('\n');
      if (err) reject(err);
      else resolve(value);
    };
    const onData = (chunk) => {
      for (const ch of chunk) {
        if (ch === '\r' || ch === '\n') return done(null, text);
        if (ch === '\u0003') return done(new UsageError('cancelled'));
        if (ch === '\u0004') return text ? done(null, text) : done(new UsageError('cancelled'));
        if (ch === '\u007f' || ch === '\b') text = [...text].slice(0, -1).join('');
        else if (ch >= ' ') text += ch;
      }
    };
    input.on('data', onData);
  });
}

async function main() {
  let args;
  try {
    args = parseArgs(process.argv.slice(2));
  } catch (err) {
    process.stderr.write(`${err.message}\n\n${USAGE}`);
    return 2;
  }
  if (args.help) {
    process.stdout.write(USAGE);
    return 0;
  }
  if (!argon2Available()) {
    process.stderr.write(`This needs Node.js 24.7 or later for Argon2id (this is ${process.version}).\n`);
    return 1;
  }
  let password;
  try {
    if (process.stdin.isTTY) {
      password = await ask('Password: ', process.stdin, process.stderr);
      const again = await ask('Same password again: ', process.stdin, process.stderr);
      if (again !== password) throw new UsageError('the two passwords are not the same');
    } else {
      password = await readPipe(process.stdin);
    }
    if (password.length === 0) throw new UsageError('the password is empty');
    if (Buffer.byteLength(password) > MAX_PASSWORD_BYTES) throw new UsageError(`the password is longer than ${MAX_PASSWORD_BYTES} bytes`);
  } catch (err) {
    if (!(err instanceof UsageError)) throw err;
    process.stderr.write(`${err.message}\n`);
    return 1;
  }
  const phc = await hashPassword(password, args.costs);
  process.stdout.write(`${phc}\n\nPaste under "users:" in the config file:\n${usersLine(args.name, phc)}\n`);
  return 0;
}

// Run as a program, not when the tests import it.
if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) process.exitCode = await main();
