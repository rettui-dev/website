// Password hashes for the status page login: Argon2id in the PHC string form
// "$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>", worked out with Node's own
// crypto.argon2 (Node.js 24.7 or later). The string is parsed here, strictly:
// other variants and versions are refused, and so are costs below the OWASP
// minimum or so high that a few logins at once would exhaust the memory.
import crypto from 'node:crypto';

// The OWASP minimum for Argon2id: 19 MiB of memory, 2 passes, 1 lane.
export const MIN_MEMORY_KIB = 19456;
export const MIN_PASSES = 2;
export const MIN_PARALLELISM = 1;
// Every login works out one hash of this size, and at most three run at once (MAX_CONCURRENT_HASHES
// and RESERVED_HASHES in login.js): 64 MiB each keeps that at 192 MiB.
export const MAX_MEMORY_KIB = 64 * 1024;
export const MAX_PASSES = 16;
export const MAX_PARALLELISM = 16;
export const SALT_BYTES = 16;
export const HASH_BYTES = 32;
const MIN_SALT_BYTES = 8;
const MAX_SALT_BYTES = 64;
const MIN_HASH_BYTES = 16;
const MAX_HASH_BYTES = 64;
// Longer passwords are refused before hashing, so the work per try stays bounded.
export const MAX_PASSWORD_BYTES = 1024;
export const DEFAULTS = { memory: MIN_MEMORY_KIB, passes: MIN_PASSES, parallelism: MIN_PARALLELISM };

// Whether this Node.js has crypto.argon2 (24.7 and later).
export const argon2Available = () => typeof crypto.argon2 === 'function';

// The hasher used unless another is given: Argon2id with the given costs. Tests
// pass their own so that the parsing and checking also run on older Node.js.
export function argon2id({ password, salt, memory, passes, parallelism, length }) {
  return new Promise((resolve, reject) => {
    if (!argon2Available()) {
      reject(new Error('password login needs Node.js 24.7 or later (crypto.argon2)'));
      return;
    }
    crypto.argon2('argon2id', { message: password, nonce: salt, memory, passes, parallelism, tagLength: length }, (err, out) => (err ? reject(err) : resolve(out)));
  });
}

// PHC strings use standard base64 without padding. Buffer.from would accept
// nearly anything, so the text is checked and must come back out the same.
function b64(text) {
  if (!/^[A-Za-z0-9+/]+$/.test(text) || text.length % 4 === 1) return null;
  const buf = Buffer.from(text, 'base64');
  return buf.toString('base64').replace(/=+$/, '') === text ? buf : null;
}

const unb64 = (buf) => buf.toString('base64').replace(/=+$/, '');

function int(text, min, max) {
  if (!/^[1-9]\d{0,9}$/.test(text)) return null;
  const n = Number(text);
  return n >= min && n <= max ? n : null;
}

// Parses a PHC string into {memory, passes, parallelism, salt, hash}, or throws
// an Error that says what is wrong without repeating the string.
export function parsePhc(text) {
  if (typeof text !== 'string' || text.length > 512) throw new Error('is not an Argon2id hash');
  const parts = text.split('$');
  // ['', 'argon2id', 'v=19', 'm=..,t=..,p=..', salt, hash]
  if (parts.length !== 6 || parts[0] !== '') throw new Error('is not an Argon2id hash in the form $argon2id$v=19$m=...,t=...,p=...$salt$hash');
  if (parts[1] !== 'argon2id') throw new Error('must be argon2id (argon2i and argon2d are not accepted)');
  if (parts[2] !== 'v=19') throw new Error('must be Argon2 version 19 (v=19)');
  const params = /^m=(\d+),t=(\d+),p=(\d+)$/.exec(parts[3]);
  if (!params) throw new Error('must have its costs as m=...,t=...,p=... and nothing else');
  const memory = int(params[1], 1, 2 ** 32 - 1);
  const passes = int(params[2], 1, 2 ** 32 - 1);
  const parallelism = int(params[3], 1, 2 ** 24 - 1);
  if (memory === null || passes === null || parallelism === null) throw new Error('has a cost that is not a whole number');
  if (memory < MIN_MEMORY_KIB || passes < MIN_PASSES || parallelism < MIN_PARALLELISM) {
    throw new Error(`is too cheap: it needs at least m=${MIN_MEMORY_KIB}, t=${MIN_PASSES}, p=${MIN_PARALLELISM}`);
  }
  if (memory > MAX_MEMORY_KIB || passes > MAX_PASSES || parallelism > MAX_PARALLELISM) {
    throw new Error(`is too costly for a login: at most m=${MAX_MEMORY_KIB}, t=${MAX_PASSES}, p=${MAX_PARALLELISM}`);
  }
  // Argon2 needs at least 8 KiB of memory per lane.
  if (memory < 8 * parallelism) throw new Error('has less memory than its lanes need');
  const salt = b64(parts[4]);
  const hash = b64(parts[5]);
  if (!salt || salt.length < MIN_SALT_BYTES || salt.length > MAX_SALT_BYTES) throw new Error(`has a salt that is not ${MIN_SALT_BYTES} to ${MAX_SALT_BYTES} bytes of base64`);
  if (!hash || hash.length < MIN_HASH_BYTES || hash.length > MAX_HASH_BYTES) throw new Error(`has a hash that is not ${MIN_HASH_BYTES} to ${MAX_HASH_BYTES} bytes of base64`);
  return { memory, passes, parallelism, salt, hash };
}

export function formatPhc({ memory, passes, parallelism, salt, hash }) {
  return `$argon2id$v=19$m=${memory},t=${passes},p=${parallelism}$${unb64(salt)}$${unb64(hash)}`;
}

// Checks the costs a person asked for, the same way parsePhc checks a stored hash.
export function checkCosts({ memory, passes, parallelism }) {
  const ok = (v, min, max) => Number.isInteger(v) && v >= min && v <= max;
  if (!ok(memory, MIN_MEMORY_KIB, MAX_MEMORY_KIB)) throw new Error(`memory must be ${MIN_MEMORY_KIB} to ${MAX_MEMORY_KIB} KiB`);
  if (!ok(passes, MIN_PASSES, MAX_PASSES)) throw new Error(`passes must be ${MIN_PASSES} to ${MAX_PASSES}`);
  if (!ok(parallelism, MIN_PARALLELISM, MAX_PARALLELISM)) throw new Error(`parallelism must be ${MIN_PARALLELISM} to ${MAX_PARALLELISM}`);
  if (memory < 8 * parallelism) throw new Error('memory must be at least 8 KiB per lane');
}

// A new PHC string for a password, with a random salt.
export async function hashPassword(password, costs = DEFAULTS, hasher = argon2id) {
  const c = { ...DEFAULTS, ...costs };
  checkCosts(c);
  const message = Buffer.from(password, 'utf8');
  if (message.length === 0 || message.length > MAX_PASSWORD_BYTES) throw new Error(`the password must be 1 to ${MAX_PASSWORD_BYTES} bytes`);
  const salt = crypto.randomBytes(SALT_BYTES);
  const hash = await hasher({ password: message, salt, memory: c.memory, passes: c.passes, parallelism: c.parallelism, length: HASH_BYTES });
  return formatPhc({ ...c, salt, hash });
}

// Whether the password matches a parsed PHC (see parsePhc). The comparison
// takes the same time wherever the first difference is.
export async function verifyPassword(password, phc, hasher = argon2id) {
  const message = Buffer.from(typeof password === 'string' ? password : '', 'utf8');
  const out = await hasher({ password: message, salt: phc.salt, memory: phc.memory, passes: phc.passes, parallelism: phc.parallelism, length: phc.hash.length });
  return Buffer.isBuffer(out) && out.length === phc.hash.length && crypto.timingSafeEqual(out, phc.hash);
}

// The highest memory, passes, lanes and hash length among some parsed PHCs (or
// the defaults when there are none): a stand-in with these costs takes at least
// as long as any of them.
export function costliest(phcs) {
  const out = { ...DEFAULTS, length: HASH_BYTES };
  for (const p of phcs) {
    out.memory = Math.max(out.memory, p.memory);
    out.passes = Math.max(out.passes, p.passes);
    out.parallelism = Math.max(out.parallelism, p.parallelism);
    out.length = Math.max(out.length, p.hash.length);
  }
  return { memory: out.memory, passes: out.passes, parallelism: out.parallelism, hash: Buffer.alloc(out.length) };
}

// A stand-in for a user that does not exist, with the costs of a real one (see
// costliest), so that a wrong name takes as long as a wrong password. It matches no password.
export function dummyPhc(like = DEFAULTS) {
  return { memory: like.memory, passes: like.passes, parallelism: like.parallelism, salt: crypto.randomBytes(SALT_BYTES), hash: crypto.randomBytes(like.hash?.length ?? HASH_BYTES) };
}

// New passwords set on the website need at least this many characters, and must not be one of the
// most common passwords (below) or the user's name. Passwords already in the config file are not
// checked: the server only has their hash.
export const MIN_PASSWORD_CHARS = 12;
// The most common passwords of 12 characters or more, from public breach lists, lower case. A
// password that is one of these, ignoring case, is refused.
const COMMON_PASSWORDS = new Set([
  '123456789012', '1234567890123', '12345678901234', '123456789123', '123123123123', '111111111111', '000000000000',
  '123456123456', '121212121212', '987654321098', '098765432109', '112233445566', '147258369147', '123456654321',
  'password1234', 'password12345', 'password123456', 'passwordpassword', 'password1password', 'mypassword123',
  'qwertyuiop12', 'qwerty123456', 'qwertyuiopasdfgh', 'qwertyuiopasdfghjkl', 'qwertyqwerty', 'qwerty12345678',
  '1q2w3e4r5t6y', '1qaz2wsx3edc', 'qazwsxedcrfv', 'zaq12wsxcde3', 'asdfghjkl123', 'zxcvbnm12345', 'abcdefghijkl',
  'abcd12345678', 'abc123456789', 'aaaaaaaaaaaa', 'iloveyou1234', 'iloveyouiloveyou', 'letmein12345', 'welcome12345',
  'welcome123456', 'administrator', 'changeme1234', 'trustno11234', 'sunshine1234', 'princess1234', 'football1234',
  'baseball1234', 'superman1234', 'starwars1234', 'monkey123456', 'dragon123456', 'master123456', 'whatever1234',
  'correcthorsebatterystaple', 'correct horse battery staple', 'thequickbrownfox', 'passw0rd1234', 'p@ssw0rd1234',
]);

// Why a new password is too weak, in words, or null when it is fine.
export function weakPassword(password, name = '') {
  if (typeof password !== 'string' || [...password].length < MIN_PASSWORD_CHARS) return `The new password must be at least ${MIN_PASSWORD_CHARS} characters.`;
  const plain = password.toLowerCase();
  if (COMMON_PASSWORDS.has(plain)) return 'This password is one of the most common ones. Choose another.';
  if (new Set(plain).size === 1) return 'The new password is one character over and over. Choose another.';
  // With the name taken out, too little is left.
  if (typeof name === 'string' && name !== '' && [...plain.split(name.toLowerCase()).join('')].length < 8) return 'The new password is too close to your name. Choose another.';
  return null;
}
