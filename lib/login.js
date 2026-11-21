// The status page login: sessions, failed-attempt backoff, the second step for users with a
// second factor, and the checks around a login request. Sessions, waits and second steps are in
// memory, in one process: they are lost on a restart and are not shared between processes. The
// users, their second factors and their known devices are in the user store (users.js).
import crypto from 'node:crypto';
import net from 'node:net';
import { MAX_PASSWORD_BYTES, argon2id, dummyPhc, hashPassword, parsePhc, verifyPassword } from './password.js';
import { UserStore } from './users.js';
import { NO_AUDIT, NO_FAILURES } from './audit.js';
import { NO_PASSKEYS } from './passkeys.js';

export const COOKIE = '__Host-rettui_session';
// The known-device cookie: a random 128-bit id, set after every sign in that worked. Only its
// SHA-256 is kept, with the user (users.js). It never signs anyone in: it only takes a sign in out
// of the waits that others' failures cause (see createLogin).
export const DEVICE_COOKIE = '__Host-rettui_device';
export const DEVICE_MAX_AGE_S = 180 * 24 * 60 * 60;
const DEVICE_ID_RE = /^[A-Za-z0-9_-]{22}$/;
export const MAX_FORM_BYTES = 4096;
// The passkey answer of the second sign-in step is larger than the other forms: a credential as JSON.
export const MAX_PASSKEY_FORM_BYTES = 8192;
export const MAX_NAME_INPUT = 64;
// Each hash takes the memory its costs say (19 MiB by default): only this many run at once for
// sign ins from outside, and only this many more wait. Past that a login is turned away. One
// address gets at most MAX_HASHES_PER_ADDRESS of them (running or waiting).
export const MAX_CONCURRENT_HASHES = 2;
export const MAX_QUEUED_HASHES = 8;
export const MAX_HASHES_PER_ADDRESS = 2;
// One more hash may run for the reserved lanes only: passwords asked while signed in (and new
// password hashes), and sign ins from known devices. Each of those lanes has its own queue, and one
// session or device at most MAX_HASHES_PER_LANE_KEY places in it. So a flood from outside, from
// however many addresses, never holds those back. They take a place of the sign ins from outside
// only while none of those waits, so they never hold those back either.
export const RESERVED_HASHES = 1;
export const MAX_QUEUED_LANE = 4;
export const MAX_HASHES_PER_LANE_KEY = 2;
export const BUSY_RETRY_MS = 2000;
export const LOGIN_DEFAULTS = { idleTimeoutMinutes: 60, maxAgeHours: 12, maxSessions: 1000, trustedProxies: [] };
// One user has at most this many sessions; a new sign in past it ends that user's own least used one.
export const MAX_SESSIONS_PER_USER = 20;
// Tries for one name, from every address together, are a token bucket: NAME_BURST at once, then one
// each NAME_INTERVAL_MS. A try past that waits for its turn, at most NAME_BACKLOG turns; past that
// it is refused (429). Known devices are never held back by it.
export const NAME_INTERVAL_MS = 1000;
export const NAME_BURST = 5;
export const NAME_BACKLOG = 4;
// Sign ins that work from one known device: DEVICE_BURST at once, then one each DEVICE_INTERVAL_MS;
// a right password past that is refused (429) before its hash.
export const DEVICE_INTERVAL_MS = 3000;
export const DEVICE_BURST = 3;
// Failures from an IPv6 /64 count for its /56 and /48 too, with larger free tries, so that a whole
// network does not get the free tries of every /64 in it.
export const NET56_FREE = 60;
export const NET48_FREE = 200;
// Wrong second-factor codes: per user and address (or known device), remembered for a day, with a
// wait of up to an hour, so a known password gives few guesses at the code from one address. Per
// user, from everywhere together, CODE_USER_FREE are free before the same wait; a known device is
// only held back by that once the user has CODE_DEVICE_CEILING wrong codes.
export const CODE_MAX_WAIT_MS = 60 * 60_000;
export const CODE_FORGET_MS = 24 * 60 * 60_000;
export const CODE_USER_FREE = 30;
export const CODE_DEVICE_CEILING = 200;
// A new device is an audit line when the user had none added in this long (see signIn).
export const DEVICE_AUDIT_MS = 24 * 60 * 60_000;
// The error line for a user who cannot sign in for lack of a key version is written at most this often.
export const NO_PEPPER_LOG_MS = 60_000;

// A wait in words, for messages: seconds, minutes or hours.
export function waitText(ms) {
  const s = Math.max(1, Math.ceil(ms / 1000));
  if (s < 90) return `${s} ${s === 1 ? 'second' : 'seconds'}`;
  const m = Math.ceil(s / 60);
  if (m < 90) return `${m} minutes`;
  const h = Math.ceil(m / 60);
  return `${h} ${h === 1 ? 'hour' : 'hours'}`;
}

const lower = (name) => (typeof name === 'string' ? name.toLowerCase() : '');

const ID_RE = /^[A-Za-z0-9_-]{43}$/;
// The second step of a sign in: how long it may take, how many codes one may try, and how many
// may be open at once (in all, and for one user).
export const PENDING_MS = 5 * 60_000;
export const PENDING_TRIES = 5;
export const MAX_PENDING = 1000;
export const MAX_PENDING_PER_USER = 5;
export const MAX_CODE_INPUT = 64;

// Sessions by a random 256-bit id. A session ends after idleMs without a request
// or maxAgeMs after the login, whichever comes first. One user has at most
// maxPerUser; past that a new login of theirs pushes out their own least used one.
// With max sessions open in all, a new login pushes out the least used session of
// whoever has the most, so one user signing in over and over cannot end anyone else's.
export class Sessions {
  constructor({ idleMs, maxAgeMs, max, maxPerUser = MAX_SESSIONS_PER_USER, now = Date.now }) {
    Object.assign(this, { idleMs, maxAgeMs, max, maxPerUser, now });
    // Kept in order of last use: the first entry is the one to push out.
    this.map = new Map();
  }

  // device: the SHA-256 of the known-device id of the browser, or null.
  create(name, { device = null } = {}) {
    this.sweep();
    const k = lower(name);
    const mine = [];
    for (const [id, s] of this.map) if (lower(s.name) === k) mine.push(id);
    for (const id of mine.slice(0, Math.max(0, mine.length - this.maxPerUser + 1))) this.map.delete(id);
    while (this.map.size > 0 && this.map.size >= this.max) this.evict(k);
    const id = crypto.randomBytes(32).toString('base64url');
    const t = this.now();
    // authAt: when the password was last given, for actions that need a recent sign in.
    this.map.set(id, { name, created: t, seen: t, authAt: t, device });
    return id;
  }

  // Ends the least used session of the user with the most; the user signing in (k) on a tie.
  evict(k) {
    const counts = new Map();
    for (const s of this.map.values()) counts.set(lower(s.name), (counts.get(lower(s.name)) ?? 0) + 1);
    let top = k;
    let most = counts.get(k) ?? 0;
    for (const [name, n] of counts) {
      if (n > most) [top, most] = [name, n];
    }
    for (const [id, s] of this.map) {
      if (lower(s.name) === top) {
        this.map.delete(id);
        return;
      }
    }
  }

  // The live sessions of a user, as [{id, created, seen}], most recently used last.
  list(name) {
    this.sweep();
    const k = lower(name);
    const out = [];
    for (const [id, s] of this.map) if (lower(s.name) === k) out.push({ id, created: s.created, seen: s.seen });
    return out;
  }

  // Ends every session of a user but keep (none kept when keep is null). Gives how many ended.
  destroyOthers(name, keep = null) {
    const k = lower(name);
    let n = 0;
    for (const [id, s] of this.map) {
      if (lower(s.name) === k && id !== keep) {
        this.map.delete(id);
        n++;
      }
    }
    return n;
  }

  // Ends every session of a user that was made on one of these devices (hashes). Gives how many ended.
  destroyDevices(name, hashes) {
    const k = lower(name);
    const set = new Set(hashes);
    let n = 0;
    for (const [id, s] of this.map) {
      if (lower(s.name) === k && s.device !== null && set.has(s.device)) {
        this.map.delete(id);
        n++;
      }
    }
    return n;
  }

  // The session of an id, or null. A valid one counts as used now.
  get(id) {
    if (typeof id !== 'string' || !ID_RE.test(id)) return null;
    const s = this.map.get(id);
    if (!s) return null;
    const t = this.now();
    if (t - s.seen >= this.idleMs || t - s.created >= this.maxAgeMs || t < s.created) {
      this.map.delete(id);
      return null;
    }
    s.seen = t;
    this.map.delete(id);
    this.map.set(id, s);
    return s;
  }

  destroy(id) {
    this.map.delete(id);
  }

  // Whether the session of an id is still there, without counting as a use (for a job that runs
  // on behalf of it, such as the confirm of a Reticulum change).
  live(id) {
    const s = typeof id === 'string' ? this.map.get(id) : undefined;
    if (!s) return false;
    const t = this.now();
    return t - s.seen < this.idleMs && t - s.created < this.maxAgeMs && t >= s.created;
  }

  sweep() {
    const t = this.now();
    for (const [id, s] of this.map) if (t - s.seen >= this.idleMs || t - s.created >= this.maxAgeMs) this.map.delete(id);
  }

  get size() {
    return this.map.size;
  }
}

// Backoff after failed logins, per key (an account name or an address). The
// first `free` failures cost nothing; after that each one doubles the wait, up to
// maxMs. An entry is forgotten forgetMs after its last failure, and at most
// maxEntries are kept, so the memory stays bounded. A full map never refuses a new
// key: it forgets the entry with the fewest failures (the oldest of those) to make
// room. Each failure takes a whole hash, so pushing out a key with many failures
// takes at least as many failures for every other key in the map.
export class Throttle {
  constructor({ free = 5, baseMs = 1000, maxMs = 15 * 60_000, forgetMs = 60 * 60_000, maxEntries = 10_000, now = Date.now } = {}) {
    Object.assign(this, { free, baseMs, maxMs, forgetMs, maxEntries, now });
    this.map = new Map();
  }

  // Milliseconds to wait before the next try; 0 when one is allowed now.
  wait(key) {
    const t = this.now();
    const e = this.map.get(key);
    if (!e) return 0;
    if (t - e.last >= this.forgetMs && t >= e.until) {
      this.map.delete(key);
      return 0;
    }
    return Math.max(0, e.until - t);
  }

  // Failures counted for a key and not yet forgotten.
  count(key) {
    const e = this.map.get(key);
    return e && this.now() - e.last < this.forgetMs ? e.count : 0;
  }

  fail(key) {
    const t = this.now();
    const old = this.map.get(key);
    if (!old) this.room(t);
    const count = old && t - old.last < this.forgetMs ? old.count + 1 : 1;
    const over = count - this.free;
    const until = over > 0 ? t + Math.min(this.baseMs * 2 ** Math.min(over - 1, 30), this.maxMs) : 0;
    this.map.delete(key);
    this.map.set(key, { count, last: t, until });
  }

  clear(key) {
    this.map.delete(key);
  }

  // Halves the count of a key, for a success that must not wipe it: an address that spends its
  // tries on many names keeps most of its count even after a login of its own works.
  decay(key) {
    const e = this.map.get(key);
    if (!e) return;
    const count = Math.floor(e.count / 2);
    if (count === 0) this.map.delete(key);
    else e.count = count;
  }

  // Makes room for one more key: a forgotten entry goes first, else the one with the fewest
  // failures, the oldest of those (the map is in order of last failure).
  room(t) {
    while (this.map.size >= this.maxEntries && this.map.size > 0) {
      let victim = null;
      let fewest = Infinity;
      for (const [k, e] of this.map) {
        const score = t - e.last >= this.forgetMs && t >= e.until ? -1 : e.count;
        if (score < fewest) {
          [victim, fewest] = [k, score];
          if (score < 0) break;
        }
      }
      this.map.delete(victim);
    }
  }

  get size() {
    return this.map.size;
  }
}

// The pace of tries at one name: a token bucket per key. burst tries go at once, then one each
// intervalMs. take() gives {ok: true, delayMs}, the wait for the try's turn, or, with more than
// backlog turns already taken, {ok: false, retryAfterMs} and takes nothing. count() takes a turn
// without waiting (a known device): the bucket is drained, but never past the backlog. refund()
// gives back a turn a try took and never used (it was turned away before its hash).
export class NameBucket {
  constructor({ intervalMs = NAME_INTERVAL_MS, burst = NAME_BURST, backlog = NAME_BACKLOG, maxEntries = 10_000, now = Date.now } = {}) {
    Object.assign(this, { intervalMs, burst, backlog, maxEntries, now });
    // The time the next try would be due at if the bucket were empty, by key.
    this.map = new Map();
  }

  due(key, t = this.now()) {
    return Math.max(this.map.get(key) ?? t, t);
  }

  // Milliseconds until a turn is free without waiting; 0 when one is.
  wait(key) {
    const t = this.now();
    return Math.max(0, this.due(key, t) - (this.burst - 1) * this.intervalMs - t);
  }

  take(key) {
    const t = this.now();
    const due = this.due(key, t);
    const delayMs = Math.max(0, due - (this.burst - 1) * this.intervalMs - t);
    if (delayMs > this.backlog * this.intervalMs) return { ok: false, retryAfterMs: delayMs - this.backlog * this.intervalMs };
    this.set(key, due + this.intervalMs, t);
    return { ok: true, delayMs };
  }

  count(key) {
    const t = this.now();
    this.set(key, Math.min(this.due(key, t) + this.intervalMs, t + (this.burst + this.backlog) * this.intervalMs), t);
  }

  refund(key) {
    const d = this.map.get(key);
    if (d === undefined) return;
    const back = d - this.intervalMs;
    // Back to full: the same as no key.
    if (back <= this.now()) this.map.delete(key);
    else this.map.set(key, back);
  }

  set(key, due, t) {
    this.map.delete(key);
    if (this.map.size >= this.maxEntries) this.prune(t);
    this.map.set(key, due);
  }

  // Makes room for a tenth of maxEntries at once, so that a full map costs one pass per many new
  // keys, not two passes for each. A key whose bucket is full again is the same as no key, so those
  // go first; then the ones closest to full.
  prune(t) {
    const target = this.maxEntries - Math.max(1, Math.floor(this.maxEntries / 10));
    for (const [k, d] of this.map) if (d <= t) this.map.delete(k);
    if (this.map.size <= target) return;
    const soonest = [...this.map].sort((a, b) => a[1] - b[1]);
    for (const [k] of soonest.slice(0, this.map.size - target)) this.map.delete(k);
  }

  get size() {
    return this.map.size;
  }
}

export class Busy extends Error {}

const LANES = ['public', 'session', 'device'];

// Runs async jobs at most `limit` at a time from the public lane, with at most `queue` waiting; one
// more is rejected with Busy at once instead of piling up. A job may name a key (the client's
// address): one key has at most `perKey` jobs running or waiting, so one client cannot take every
// place. The lanes 'session' and 'device' have `reserved` more places to run that the public lane
// never takes, each lane its own queue of laneQueue, and per key lanePerKey. Together they run in
// the reserved places, and in a public place only while no public job waits for one: so neither
// side can starve the other. gate(job, key, lane); gate.wouldAccept(key, lane) says whether such a
// job would be taken now, without taking it.
export function hashGate(limit = MAX_CONCURRENT_HASHES, queue = MAX_QUEUED_HASHES, perKey = MAX_HASHES_PER_ADDRESS, { reserved = RESERVED_HASHES, laneQueue = MAX_QUEUED_LANE, lanePerKey = MAX_HASHES_PER_LANE_KEY } = {}) {
  let running = 0;
  let publicRunning = 0;
  let laneRunning = 0;
  let seq = 0;
  const waiting = { public: [], session: [], device: [] };
  const byKey = new Map();
  const release = (k) => {
    if (k === null) return;
    const n = (byKey.get(k) ?? 1) - 1;
    if (n <= 0) byKey.delete(k);
    else byKey.set(k, n);
  };
  const run = (lane) => {
    const { job, k, resolve, reject } = waiting[lane].shift();
    running++;
    if (lane === 'public') publicRunning++;
    else laneRunning++;
    Promise.resolve()
      .then(job)
      .then(resolve, reject)
      .finally(() => {
        running--;
        if (lane === 'public') publicRunning--;
        else laneRunning--;
        release(k);
        next();
      });
  };
  const canRunPublic = () => publicRunning < limit && running < limit + reserved;
  const canRunLane = () => running < limit + reserved && (laneRunning < reserved || waiting.public.length === 0);
  const next = () => {
    for (;;) {
      const s = waiting.session[0];
      const d = waiting.device[0];
      if ((s || d) && canRunLane()) run(!d || (s && s.seq < d.seq) ? 'session' : 'device');
      else if (waiting.public.length > 0 && canRunPublic()) run('public');
      else return;
    }
  };
  const place = (key, lane) => {
    const l = LANES.includes(lane) ? lane : 'public';
    return { l, k: key === null ? null : `${l}|${key}` };
  };
  const accepts = (l, k) => {
    const full = l === 'public' ? waiting.public.length >= queue && !canRunPublic() : waiting[l].length >= laneQueue && !canRunLane();
    return !full && (k === null || (byKey.get(k) ?? 0) < (l === 'public' ? perKey : lanePerKey));
  };
  const gate = (job, key = null, lane = 'public') =>
    new Promise((resolve, reject) => {
      const { l, k } = place(key, lane);
      if (!accepts(l, k)) {
        reject(new Busy('too many logins at once'));
        return;
      }
      if (k !== null) byKey.set(k, (byKey.get(k) ?? 0) + 1);
      waiting[l].push({ job, k, resolve, reject, seq: seq++ });
      next();
    });
  gate.wouldAccept = (key = null, lane = 'public') => {
    const { l, k } = place(key, lane);
    return accepts(l, k);
  };
  gate.load = () => ({ running, waiting: waiting.public.length + waiting.session.length + waiting.device.length, keys: byKey.size });
  return gate;
}

// An address in one form, so that two spellings of it compare equal: IPv6
// expanded and compressed again (RFC 5952: lower case, no leading zeros, the
// longest run of zero groups as "::"), and IPv4 mapped into IPv6 as plain IPv4.
// A zone (%eth0) is kept. Anything that is not an address is only lower-cased.
export function normalIp(ip) {
  if (typeof ip !== 'string') return '';
  const text = ip.toLowerCase();
  if (!net.isIPv6(text)) return text;
  const i = text.indexOf('%');
  const zone = i < 0 ? '' : text.slice(i);
  const g = v6Groups(i < 0 ? text : text.slice(0, i));
  if (!g) return text;
  if (g.slice(0, 5).every((x) => x === 0) && g[5] === 0xffff) return `${g[6] >> 8}.${g[6] & 255}.${g[7] >> 8}.${g[7] & 255}${zone}`;
  // The longest run of two or more zero groups, the first one on a tie.
  let best = -1;
  let bestLen = 1;
  for (let a = 0; a < 8; a++) {
    let b = a;
    while (b < 8 && g[b] === 0) b++;
    if (b - a > bestLen) [best, bestLen] = [a, b - a];
    a = b;
  }
  const hex = (list) => list.map((x) => x.toString(16)).join(':');
  if (best < 0) return hex(g) + zone;
  return `${hex(g.slice(0, best))}::${hex(g.slice(best + bestLen))}${zone}`;
}

// The eight 16-bit groups of an IPv6 address (without a zone), or null.
function v6Groups(ip) {
  let text = ip;
  // A dotted IPv4 tail is two groups.
  const dotted = /^(.*:)(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(text);
  if (dotted) {
    const [a, b, c, d] = dotted.slice(2).map(Number);
    text = `${dotted[1]}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }
  const halves = text.split('::');
  if (halves.length > 2) return null;
  const part = (h) => (h === '' ? [] : h.split(':').map((x) => parseInt(x, 16)));
  const head = part(halves[0]);
  const tail = halves.length === 2 ? part(halves[1]) : [];
  const fill = halves.length === 2 ? 8 - head.length - tail.length : 0;
  if (fill < 0 || head.length + fill + tail.length !== 8) return null;
  const out = [...head, ...new Array(fill).fill(0), ...tail];
  return out.every((x) => Number.isInteger(x) && x >= 0 && x <= 0xffff) ? out : null;
}

// Writes the eight 16-bit groups of an address into out, IPv4 as IPv4-mapped
// IPv6 (::ffff:a.b.c.d) so that both spellings fall in the same networks. A zone
// (%eth0) is left out. Returns 4 or 6, or 0 (out untouched) when ip is not an
// address. Reads character codes only, so a lookup allocates nothing.
function fillAddress(ip, out) {
  const family = typeof ip === 'string' ? net.isIP(ip) : 0;
  if (family === 4) {
    out.fill(0, 0, 5);
    out[5] = 0xffff;
    fillV4(ip, 0, ip.length, out, 6);
    return 4;
  }
  if (family !== 6) return 0;
  const zone = ip.indexOf('%');
  const end = zone < 0 ? ip.length : zone;
  let n = 0;
  let gap = -1;
  let cur = 0;
  let digits = 0;
  for (let i = 0; i < end; i++) {
    const c = ip.charCodeAt(i);
    if (c === 58) {
      if (digits > 0) out[n++] = cur;
      cur = 0;
      digits = 0;
      if (i + 1 < end && ip.charCodeAt(i + 1) === 58) {
        gap = n;
        i++;
      }
    } else if (c === 46) {
      // A dotted IPv4 tail: it started where the current group did.
      fillV4(ip, i - digits, end, out, n);
      n += 2;
      digits = 0;
      break;
    } else {
      cur = cur * 16 + (c <= 57 ? c - 48 : (c | 32) - 87);
      digits++;
    }
  }
  if (digits > 0) out[n++] = cur;
  if (gap >= 0) {
    // Move the groups after "::" to the end, from the last one, and zero the gap.
    const moved = n - gap;
    for (let k = 1; k <= moved; k++) out[8 - k] = out[n - k];
    out.fill(0, gap, 8 - moved);
  }
  return 6;
}

// The dotted IPv4 address in ip[from, to) as two groups, at out[at] and out[at + 1].
function fillV4(ip, from, to, out, at) {
  let hi = 0;
  let octet = 0;
  let dots = 0;
  for (let i = from; i < to; i++) {
    const c = ip.charCodeAt(i);
    if (c === 46) {
      if (dots === 0) hi = octet << 8;
      else if (dots === 1) out[at] = hi | octet;
      else hi = octet << 8;
      octet = 0;
      dots++;
    } else {
      octet = octet * 10 + (c - 48);
    }
  }
  out[at + 1] = hi | octet;
}

// Whether the groups of an address are in a network: its first bits equal the
// network's, which has every bit beyond the prefix cleared.
function inNetwork(addr, network, bits) {
  let left = bits;
  for (let k = 0; k < 8 && left > 0; k++) {
    const mask = left >= 16 ? 0xffff : (0xffff << (16 - left)) & 0xffff;
    if ((addr[k] & mask) !== network[k]) return false;
    left -= 16;
  }
  return true;
}

// The first address of ::ffff:0:0/96, where every IPv4 address is mapped.
const MAPPED_V4 = Uint16Array.of(0, 0, 0, 0, 0, 0xffff, 0, 0);

// The longest trusted_proxies entry: a full IPv6 address with an IPv4 tail and /128.
const MAX_PROXY_ENTRY = 64;

// One trusted_proxies entry, a single address or a network in CIDR notation
// (172.22.0.0/16, fd00::/8), in one spelling: the network with every bit
// beyond the prefix cleared, IPv4-mapped IPv6 as IPv4, and a /32 or /128 as the
// plain address. Null when it is neither. text is the spelling; prefix is the
// written one (0 to 32 for IPv4, 0 to 128 for IPv6), single is true for one
// address. A network may not carry a zone; a single address keeps it.
export function proxyEntry(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_PROXY_ENTRY) return null;
  const slash = value.indexOf('/');
  if (slash < 0) {
    if (net.isIP(value) === 0) return null;
    const text = normalIp(value);
    const family = text.includes(':') ? 6 : 4;
    return { text, family, prefix: family === 4 ? 32 : 128, single: true, groups: null, bits: 128 };
  }
  const addr = value.slice(0, slash);
  const written = value.slice(slash + 1);
  if (!/^(0|[1-9][0-9]{0,2})$/.test(written) || addr.includes('%')) return null;
  const groups = new Uint16Array(8);
  let family = fillAddress(addr, groups);
  if (family === 0) return null;
  let bits = Number(written);
  if (family === 4) {
    if (bits > 32) return null;
    bits += 96;
  } else if (bits > 128) {
    return null;
  } else if (bits >= 96 && groups.subarray(0, 5).every((x) => x === 0) && groups[5] === 0xffff) {
    family = 4;
  }
  for (let k = 0; k < 8; k++) {
    const left = bits - k * 16;
    groups[k] &= left >= 16 ? 0xffff : left <= 0 ? 0 : (0xffff << (16 - left)) & 0xffff;
  }
  const text = normalIp(Array.from(groups, (x) => x.toString(16)).join(':'));
  const prefix = family === 4 ? bits - 96 : bits;
  if (bits === 128) return { text, family, prefix, single: true, groups: null, bits };
  // Every IPv4 address is checked as ::ffff:a.b.c.d, so an IPv6 network holding
  // all of ::ffff:0:0/96 (::/64, ::/80) trusts every IPv4 client, like a /0.
  const coversIpv4 = family === 6 && bits <= 96 && inNetwork(MAPPED_V4, groups, bits);
  return { text: `${text}/${prefix}`, family, prefix, single: false, groups, bits, coversIpv4 };
}

// The trusted proxies as one lookup: has(ip) with an address in normalIp's
// spelling. Single addresses are a set; networks are checked one by one, at
// most as many as trusted_proxies may hold, against a buffer reused each time.
export function proxyMatcher(entries) {
  const singles = new Set();
  const networks = [];
  for (const e of entries) {
    const p = proxyEntry(e);
    if (p === null) throw new Error('a trusted proxy is not an IP address or network');
    if (p.single) singles.add(p.text);
    else networks.push(p);
  }
  const scratch = new Uint16Array(8);
  return {
    has(ip) {
      if (singles.has(ip)) return true;
      if (networks.length === 0 || fillAddress(ip, scratch) === 0) return false;
      for (let i = 0; i < networks.length; i++) if (inNetwork(scratch, networks[i].groups, networks[i].bits)) return true;
      return false;
    },
  };
}

// One X-Forwarded-For hop as an address in normalIp's spelling. Some proxies add
// the client's port: [2001:db8::1]:443 and 192.0.2.1:5678 are read as the
// address alone. Nothing else is changed, so other text stays not an address.
const BRACKETED = /^\[([^\]]*)\](?::[0-9]{1,5})?$/;
const V4_PORT = /^([0-9]{1,3}(?:\.[0-9]{1,3}){3}):[0-9]{1,5}$/;
export function hopAddress(text) {
  const hop = text.trim();
  const m = BRACKETED.exec(hop) ?? V4_PORT.exec(hop);
  return normalIp(m && net.isIP(m[1]) === (m[0].startsWith('[') ? 6 : 4) ? m[1] : hop);
}

// X-Forwarded-For read from the right, from a trusted peer: the first hop that
// is not a trusted proxy, or null when every hop is one. bad is true when a
// hop on the way is not an address, so the peer has to stand in for the client.
function forwarded(header, trusted) {
  const list = typeof header === 'string' ? header.split(',') : [];
  for (let i = list.length - 1; i >= 0; i--) {
    const ip = hopAddress(list[i]);
    if (!net.isIP(ip)) return { ip: null, bad: true };
    if (!trusted.has(ip)) return { ip, bad: false };
  }
  return { ip: null, bad: false };
}

// The address a request comes from. Only when it comes from a trusted proxy is
// X-Forwarded-For read, from the right, skipping the trusted proxies.
export function clientIp(req, trusted) {
  const peer = normalIp(req.socket?.remoteAddress);
  if (!trusted.has(peer)) return peer;
  return forwarded(req.headers['x-forwarded-for'], trusted).ip ?? peer;
}

// Whether a request came over https: on a TLS connection of this server, or from a trusted proxy
// whose X-Forwarded-Proto says https. With several values (proxies that add one each) the last is
// read, the one of the proxy nearest to this server. Anyone else's X-Forwarded-Proto is ignored.
export function viaHttps(req, trusted) {
  if (req.socket?.encrypted === true) return true;
  const header = req.headers['x-forwarded-proto'];
  if (typeof header !== 'string' || !trusted.has(normalIp(req.socket?.remoteAddress))) return false;
  return header.split(',').pop().trim().toLowerCase() === 'https';
}

// The peer, when a trusted proxy sends an X-Forwarded-For hop that is not an
// address (even without a port): then its clients all share the proxy's address.
export function unreadableHop(req, trusted) {
  const header = req.headers['x-forwarded-for'];
  if (header === undefined) return null;
  const peer = normalIp(req.socket?.remoteAddress);
  if (!trusted.has(peer)) return null;
  return forwarded(header, trusted).bad ? peer : null;
}

// Loopback and private networks: where a reverse proxy on the same machine or
// network connects from.
const LOCAL = new net.BlockList();
for (const [net4, prefix] of [['127.0.0.0', 8], ['10.0.0.0', 8], ['172.16.0.0', 12], ['192.168.0.0', 16], ['169.254.0.0', 16], ['100.64.0.0', 10]]) {
  LOCAL.addSubnet(net4, prefix, 'ipv4');
}
for (const [net6, prefix] of [['::1', 128], ['fc00::', 7], ['fe80::', 10]]) LOCAL.addSubnet(net6, prefix, 'ipv6');

// Whether a request looks like it came through a reverse proxy that is not in
// trusted_proxies: X-Forwarded-For from a loopback or private address that is
// not trusted. Then every visitor shares the proxy's address for the wait.
export function untrustedProxy(req, trusted) {
  if (req.headers['x-forwarded-for'] === undefined) return null;
  const peer = normalIp(req.socket?.remoteAddress);
  if (trusted.has(peer)) return null;
  const plain = peer.split('%')[0];
  const family = net.isIP(plain);
  if (family === 0) return null;
  return LOCAL.check(plain, family === 4 ? 'ipv4' : 'ipv6') ? peer : null;
}

// The throttle key of an address: IPv6 by its /64, since one machine usually has a whole one.
export function ipKey(ip) {
  if (net.isIPv6(ip)) {
    const g = v6Groups(ip.split('%')[0]);
    return g ? `ip:${g.slice(0, 4).map((x) => x.toString(16).padStart(4, '0')).join(':')}::/64` : `ip:${ip}`;
  }
  return `ip:${ip}`;
}

// The keys of the larger networks an IPv6 address is in: its /56 and its /48. None for IPv4.
export function netKeys(ip) {
  if (typeof ip !== 'string' || !net.isIPv6(ip)) return null;
  const g = v6Groups(ip.split('%')[0]);
  if (!g) return null;
  const hex = (x) => x.toString(16).padStart(4, '0');
  return { net56: `net:${hex(g[0])}:${hex(g[1])}:${hex(g[2])}:${hex(g[3] & 0xff00)}::/56`, net48: `net:${hex(g[0])}:${hex(g[1])}:${hex(g[2])}::/48` };
}

// The SHA-256 (hex) of a known-device id from a cookie, or null when it is not one.
export function deviceHash(id) {
  return typeof id === 'string' && DEVICE_ID_RE.test(id) ? crypto.createHash('sha256').update(id).digest('hex') : null;
}

export const newDeviceId = () => crypto.randomBytes(16).toString('base64url');

// Whether two parsed password hashes are the same one.
const samePhc = (a, b) => Boolean(a && b) && a.salt.equals(b.salt) && a.hash.equals(b.hash) && a.memory === b.memory && a.passes === b.passes && a.parallelism === b.parallelism && (a.keyid ?? null) === (b.keyid ?? null);

// Whether a POST comes from the page itself and not from another site. Browsers
// send Sec-Fetch-Site; older ones only Origin, which must then name this host.
export function sameOrigin(headers) {
  const site = headers['sec-fetch-site'];
  if (site !== undefined) return site === 'same-origin';
  const origin = headers.origin;
  const host = headers.host;
  if (typeof origin !== 'string' || typeof host !== 'string' || origin === 'null') return false;
  try {
    // An Origin is only a scheme, a host and a port. One with anything else (a user part, which
    // the URL parser would drop, a path) is not one a browser sends.
    const u = new URL(origin);
    return u.origin === origin && u.username === '' && u.password === '' && u.host === host.toLowerCase();
  } catch {
    return false;
  }
}

export function isFormType(value) {
  return typeof value === 'string' && /^application\/x-www-form-urlencoded\s*(;|$)/i.test(value);
}

// The value of one cookie, or null.
export function cookieValue(header, name) {
  if (typeof header !== 'string') return null;
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return null;
}

export class TooLarge extends Error {}

// Reads a request body of at most max bytes.
export function readBody(req, max = MAX_FORM_BYTES) {
  return new Promise((resolve, reject) => {
    const declared = Number(req.headers['content-length']);
    if (Number.isFinite(declared) && declared > max) {
      reject(new TooLarge('body too large'));
      return;
    }
    const chunks = [];
    let size = 0;
    const onData = (c) => {
      size += c.length;
      if (size > max) {
        req.off('data', onData);
        req.resume();
        reject(new TooLarge('body too large'));
        return;
      }
      chunks.push(c);
    };
    req.on('data', onData);
    req.once('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.once('error', reject);
  });
}

// The login itself. users: [{name, phc}] where phc is what parsePhc gives. The result is
// {ok: true, name, epoch, device} or {ok: false, reason, retryAfterMs?}, where reason is 'invalid'
// (one answer for an unknown name and a wrong password), 'throttled', 'paced' or 'busy'. epoch is
// the user's epoch when the password was checked: the sign in may only be finished (signIn,
// startSecondFactor) while it is still the same. device is the SHA-256 of the known-device id the
// request came with, when it is one of this user's, else null.
//
// With a second factor on, a right password gives {ok: true, name, epoch, device, secondFactor: true,
// codeWaitMs?}, which is not yet a sign in: startSecondFactor then gives a short-lived token for the
// code step (finishSecondFactor). codeWaitMs is there when wrong codes hold the code step back.
// store: the user store (users.js); without one, the users of the config file, in memory.
//
// A password or name too long to be right is refused at once and counts nowhere: it is not a guess.
//
// The waits, so that nobody can lock someone else out by knowing their name:
// - accounts: failures per name and address. It refuses (429), and only holds back that address
//   for that name.
// - addresses: failures per address over every name, and for IPv6 per /56 and /48 too (nets56,
//   nets48, with more free tries). They refuse too. A login that works only halves them.
// - names: a token bucket per name, from every address together (NameBucket): tries are paced to
//   about one a second, and refused (429) past a short backlog.
// - devices: a request with a known-device cookie for the name skips all of the above. It counts
//   in a wait of its own (per device), and its failures still count for the address and the name.
// - deviceTurns: the sign ins that work from one known device are paced too (DEVICE_BURST at once,
//   then one each DEVICE_INTERVAL_MS), so that a device with the password cannot keep a hash place busy.
// - reauths: a password asked again while signed in counts per session (attempt with session).
// - codes, codeUsers: wrong second-factor codes per user and address (or device), and per user.
//   They may hold the code step back (up to an hour, remembered for a day), never the password step.
//   A passkey that does not work counts here exactly as a wrong code.
//
// passkeys: what createPasskeys (passkeys.js) gives for the site's address, or NO_PASSKEYS. A user
// whose passkeys cannot be used here (no address, or another one) still has the second step: they
// use the app code or a recovery code.
export function createLogin({ users, store = null, settings = LOGIN_DEFAULTS, hasher = argon2id, now = Date.now, gate = hashGate(), throttle, audit = NO_AUDIT, failures = NO_FAILURES, log = console.error, sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)), passkeys = NO_PASSKEYS }) {
  const db = store ?? new UserStore({ configUsers: users, now });
  const accounts = throttle?.accounts ?? new Throttle({ now });
  const addresses = throttle?.addresses ?? new Throttle({ free: 20, now });
  const nets56 = throttle?.nets56 ?? new Throttle({ free: NET56_FREE, now });
  const nets48 = throttle?.nets48 ?? new Throttle({ free: NET48_FREE, now });
  const devices = throttle?.devices ?? new Throttle({ now });
  const reauths = throttle?.reauths ?? new Throttle({ now });
  const names = throttle?.names ?? new NameBucket({ now });
  const deviceTurns = throttle?.deviceTurns ?? new NameBucket({ intervalMs: DEVICE_INTERVAL_MS, burst: DEVICE_BURST, backlog: 0, now });
  const codes = throttle?.codes ?? new Throttle({ maxMs: CODE_MAX_WAIT_MS, forgetMs: CODE_FORGET_MS, now });
  const codeUsers = throttle?.codeUsers ?? new Throttle({ free: CODE_USER_FREE, maxMs: CODE_MAX_WAIT_MS, forgetMs: CODE_FORGET_MS, now });
  // Second steps by token: {name, addressKey, created, tries, epoch, device, challenge}, oldest
  // first. challenge: that of the passkey prompt, used once, or null.
  const pending = new Map();
  // Raised by endUser: a second step or check that started before it is no longer good.
  const epochs = new Map();
  const epochOf = (name) => epochs.get(lower(name)) ?? 0;
  const sessions = new Sessions({ idleMs: settings.idleTimeoutMinutes * 60_000, maxAgeMs: settings.maxAgeHours * 3_600_000, max: settings.maxSessions, now });
  // Checks running per throttle key, and the logins waiting for them to end.
  const running = new Map();
  // The last hash each user's password was moved from and to by a pepper upgrade (upgrade), by
  // lower-case name: a sign in checked against the old hash while the new one was written is
  // still the same password.
  const upgraded = new Map();
  // When the error line for a user whose hash needs a key version this server lacks was last
  // written, by lower-case name: once a minute each is enough. Only stored users get one, so it
  // stays small.
  const noPepperLogged = new Map();

  // Another program (scripts/users.js) made, removed or changed a user: whatever they were signed
  // in with may be gone, so their sessions end.
  db.onExternalChange = (name, what) => {
    endUser(name);
    audit.write('user-changed-elsewhere', { user: name, what }).catch((err) => log(`could not write the audit log: ${err.message}`));
  };

  // The store cannot be read again (see users.js): what is in memory may be stale, a user deleted
  // elsewhere may still be there. Until it can be read, nobody signs in and every session ends.
  // Nothing here writes to the store: this may run inside its transaction.
  db.onUnreadable = (err) => {
    const ended = sessions.size;
    sessions.map.clear();
    pending.clear();
    upgraded.clear();
    log(`error: the user store cannot be read (${err.message}). Signing in is off and all ${ended} sessions were ended until it can be read again; it is tried every second.`);
    audit.write('user-store-unreadable', { sessionsEnded: ended }).catch((e) => log(`could not write the audit log: ${e.message}`));
  };
  db.onReadable = () => {
    log('the user store can be read again; signing in is back on.');
    audit.write('user-store-readable').catch((e) => log(`could not write the audit log: ${e.message}`));
  };
  const unavailable = () => db.unreadable !== null && db.unreadable !== undefined;

  // The address keys of an address: [[throttle, key]], its /64 (or IPv4 address), /56 and /48.
  const addressKeys = (ip) => {
    const n = netKeys(ip);
    const out = [[addresses, ipKey(ip)]];
    if (n) out.push([nets56, n.net56], [nets48, n.net48]);
    return out;
  };

  // The device of a request, when its id is one of this user's: its hash, else null.
  const knownDevice = (name, id) => {
    const h = deviceHash(id);
    return h !== null && db.hasDevice(name, h) ? h : null;
  };

  // Whether a login for this key has to wait for the checks running for it.
  // Once the free tries are used up, counting the running ones, the next check
  // waits for their outcome: otherwise a burst sent at once would all be
  // checked before the first failure counts.
  const mustWait = (th, key) => {
    const r = running.get(key);
    return r !== undefined && r.n > 0 && th.count(key) + r.n >= th.free;
  };
  const start = (key) => {
    const r = running.get(key) ?? { n: 0, waiting: [] };
    r.n++;
    running.set(key, r);
  };
  const end = (key) => {
    const r = running.get(key);
    if (!r) return;
    r.n--;
    const wake = r.waiting.splice(0);
    if (r.n === 0) running.delete(key);
    for (const resolve of wake) resolve();
  };

  async function attempt(nameInput, password, ip, { session = null, device = null } = {}) {
    const name = typeof nameInput === 'string' ? nameInput.trim().toLowerCase() : '';
    // Too long to be right: not a guess, so it is answered at once and counts nowhere.
    if (typeof password !== 'string' || name.length > MAX_NAME_INPUT || Buffer.byteLength(password) > MAX_PASSWORD_BYTES) return { ok: false, reason: 'invalid' };
    const nameKey = `user:${name}`;
    const addressKey = ipKey(ip);
    const pairKey = `${nameKey}|${addressKey}`;
    const inSession = typeof session === 'string';
    const known = inSession ? null : knownDevice(name, device);
    // keys: the waits that may hold this try back; failKeys: where a failure counts.
    let keys;
    let failKeys;
    let lane;
    let laneKey;
    if (inSession) {
      keys = [[reauths, `session:${session}`]];
      failKeys = keys;
      [lane, laneKey] = ['session', `session:${session}`];
    } else if (known) {
      keys = [[devices, `device:${known}`]];
      failKeys = [...keys, ...addressKeys(ip)];
      [lane, laneKey] = ['device', `device:${known}`];
    } else {
      keys = [[accounts, pairKey], ...addressKeys(ip)];
      failKeys = keys;
      [lane, laneKey] = ['public', addressKey];
    }
    const waitNow = () => Math.max(...keys.map(([th, k]) => th.wait(k)));
    const busy = { ok: false, reason: 'busy', retryAfterMs: BUSY_RETRY_MS };
    if (unavailable()) return { ok: false, reason: 'unavailable' };
    let wait = waitNow();
    if (wait > 0) return { ok: false, reason: 'throttled', retryAfterMs: wait };
    // Asked before a turn of the name is taken: a request the gate would turn away costs nothing.
    if (!gate.wouldAccept(laneKey, lane)) return busy;
    const deviceKey = known ? `device:${known}` : null;
    if (known) {
      const w = deviceTurns.wait(deviceKey);
      if (w > 0) return { ok: false, reason: 'paced', retryAfterMs: w, scope: 'device' };
    }
    // A signed-in user asking again is not paced, and a known device is counted but not held back.
    let turn = false;
    if (known) names.count(nameKey);
    else if (!inSession) {
      const t = names.take(nameKey);
      if (!t.ok) return { ok: false, reason: 'paced', retryAfterMs: t.retryAfterMs };
      turn = true;
      if (t.delayMs > 0) await sleep(t.delayMs);
    }
    // Turned away before its hash: the turn of the name is given back, so that requests that cost
    // the sender nothing cannot keep the name paced for everyone.
    const away = (r) => {
      if (turn) names.refund(nameKey);
      return r;
    };
    for (;;) {
      wait = waitNow();
      if (wait > 0) return away({ ok: false, reason: 'throttled', retryAfterMs: wait });
      const hit = keys.find(([th, k]) => mustWait(th, k));
      if (!hit) break;
      const r = running.get(hit[1]);
      // Only so many wait for one key; the rest are turned away, as when the gate is full.
      if (r.waiting.length >= MAX_QUEUED_HASHES) return away(busy);
      await new Promise((resolve) => r.waiting.push(resolve));
    }
    // Taken before the user is looked up: a password change or the like from here on ends this try.
    const epoch = epochOf(name);
    const user = db.find(name);
    // A website user whose hash needs a key version this server does not have (made elsewhere
    // with a key it was not given) cannot be checked. It is answered as a wrong password, after a
    // hash of the same costs, so that it cannot be told apart, and the operator is told.
    const noPepper = user !== null && user.source === 'store' && (user.phc.keyid ?? null) !== null && user.secret === null;
    const t = now();
    const last = noPepper ? noPepperLogged.get(lower(user.name)) : undefined;
    if (noPepper && (last === undefined || t - last >= NO_PEPPER_LOG_MS || t < last)) {
      noPepperLogged.set(lower(user.name), t);
      log(`error: the password hash of ${user.name} needs key version ${user.phc.keyid}, which this server was not given, so they cannot sign in. Restart the website with that version in USERS_KEY_FILE.`);
    }
    // An unknown name is checked against a hash with the costs of one of the users, always the
    // same one for the same name (see standIn in users.js). It matches no password.
    const standIn = user === null ? db.standIn(name) : noPepper ? dummyPhc(user.phc) : null;
    for (const [, k] of keys) start(k);
    try {
      let good;
      try {
        good = await gate(() => verifyPassword(password, standIn ?? user.phc, hasher, standIn ? null : user.secret), laneKey, lane);
      } catch (err) {
        // Turned away before the check: not a failed try.
        if (err instanceof Busy) return away(busy);
        throw err;
      }
      if (!good || standIn !== null) {
        for (const [th, k] of failKeys) th.fail(k);
        // A signed-in user's own wrong passwords count for the session only, not for the name.
        if (!inSession) failures.note('password-failures', nameKey, { user: name, address: ip });
        return { ok: false, reason: 'invalid' };
      }
      // The password was changed, or the user ended, removed or changed, while it was checked: the
      // password that was right is not the one that counts now.
      if (epochOf(name) !== epoch || !samePassword(name, db.find(name)?.phc, user.phc)) return { ok: false, reason: 'invalid' };
      // The store could not be read again while the password was checked.
      if (unavailable()) return { ok: false, reason: 'unavailable' };
      upgrade(user, password);
      if (known) deviceTurns.count(deviceKey);
      if (inSession) {
        reauths.clear(`session:${session}`);
        return { ok: true, name: user.name, epoch, device: null };
      }
      // With a second factor the waits are only eased once the code is right too, so that a
      // known password cannot be used to start the count of wrong codes again.
      const secondFactor = db.secondFactorEnabled(user.name);
      if (!secondFactor) {
        passed(user.name, ip, known);
        return { ok: true, name: user.name, epoch, device: known };
      }
      const codeWaitMs = codeWait(user.name, ip, known);
      return codeWaitMs > 0 ? { ok: true, name: user.name, epoch, device: known, secondFactor, codeWaitMs } : { ok: true, name: user.name, epoch, device: known, secondFactor };
    } finally {
      for (const [, k] of keys) end(k);
    }
  }

  // Whether the hash a password was checked against (was) is still the one that counts (now): the
  // same hash, or the one a pepper upgrade put in its place.
  function samePassword(name, now, was) {
    if (samePhc(now, was)) return true;
    const u = upgraded.get(lower(name));
    return u !== undefined && samePhc(u.from, was) && samePhc(u.to, now);
  }

  // After a right password: a website user's hash made without the current pepper is made again
  // with it, in the background, with the same costs. Only when a hash place is free (a sign in
  // never waits for it, and it never takes a place from one), and only while the stored hash is
  // still the one that was checked. It is the same password, so no session ends. A failure is only
  // logged: the old hash keeps working. Users in the config file are never upgraded, as the
  // server cannot write that file.
  function upgrade(user, password) {
    if (user.source !== 'store' || !db.needsRepepper(user.phc)) return;
    const laneKey = `upgrade:${lower(user.name)}`;
    if (!gate.wouldAccept(laneKey, 'session')) return;
    const pepper = db.currentPepper();
    const { memory, passes, parallelism } = user.phc;
    gate(() => hashPassword(password, { memory, passes, parallelism }, hasher, pepper), laneKey, 'session')
      .then((text) => {
        if (db.upgradePassword(user.name, user.phc, text)) upgraded.set(lower(user.name), { from: user.phc, to: parsePhc(text) });
      })
      .catch((err) => {
        if (!(err instanceof Busy)) log(`could not move ${user.name}'s password hash to the current key: ${err.message}`);
      });
  }

  // A sign in that is complete eases the waits of the name and the address.
  function passed(name, ip, known) {
    const nameKey = `user:${lower(name)}`;
    accounts.clear(`${nameKey}|${ipKey(ip)}`);
    if (known) devices.clear(`device:${known}`);
    for (const [th, k] of addressKeys(ip)) th.decay(k);
  }

  // How long wrong codes hold back the code step of a user, from this address or device.
  function codeWait(name, ip, known) {
    const userKey = `user:${lower(name)}`;
    if (known) {
      const ceiling = codeUsers.count(userKey) >= CODE_DEVICE_CEILING ? codeUsers.wait(userKey) : 0;
      return Math.max(ceiling, codes.wait(`${userKey}|device:${known}`));
    }
    return Math.max(codeUsers.wait(userKey), codes.wait(`${userKey}|${ipKey(ip)}`), ...addressKeys(ip).map(([th, k]) => th.wait(k)));
  }

  // Checks a second-factor code (or a recovery code) of a user, with the waits: wrong codes count
  // for the user and address (or device), for the user, and for the address. The code is checked
  // and used up before anything is awaited, so two requests with one code cannot both pass. Gives
  // {ok: true, recoveryLeft?} or {ok: false, reason: 'invalid' | 'throttled', retryAfterMs?}.
  // raw: input goes to check as it is, untrimmed and of any size or type (a passkey answer, which
  // check reads itself).
  async function checkCode(name, input, ip, { recovery = false, check = null, device = null, raw = false } = {}) {
    const userKey = `user:${lower(name)}`;
    const pairKey = device ? `${userKey}|device:${device}` : `${userKey}|${ipKey(ip)}`;
    const wait = codeWait(name, ip, device);
    if (wait > 0) return { ok: false, reason: 'throttled', retryAfterMs: wait };
    let text;
    if (raw && check) text = input;
    else text = typeof input === 'string' && input.length <= MAX_CODE_INPUT ? input.trim() : '';
    let r;
    if (check) r = await check(text);
    else if (recovery) r = db.useRecoveryCode(name, text);
    else r = db.checkTotp(name, text);
    if (!r.ok) {
      codes.fail(pairKey);
      codeUsers.fail(userKey);
      for (const [th, k] of addressKeys(ip)) th.fail(k);
      failures.note('second-factor-failures', userKey, { user: name, address: ip });
      return { ok: false, reason: 'invalid' };
    }
    codes.clear(pairKey);
    codeUsers.clear(userKey);
    // The code is used up in memory already; a failed write is only logged, so a full disk does
    // not lock everyone out.
    await Promise.resolve(r.saved).catch((err) => log(`could not save ${name}'s used code: ${err.message}`));
    if (recovery) await audit.write('recovery-code-used', { user: name, left: r.left, address: ip });
    return recovery ? { ok: true, recoveryLeft: r.left } : { ok: true };
  }

  // Checks a passkey answer (what navigator.credentials.get gave) as checkCode checks a code: the
  // same waits, and a passkey that does not work counts as a wrong code. verify(response) is the
  // check of passkeys.js against the right challenge (passkeys.verify or verifyStepUp). A right
  // signature with a counter that went back (a copied authenticator, maybe) is refused and is an
  // audit line, naming the passkey by its label only.
  async function checkPasskey(name, response, ip, { device = null, verify }) {
    let counterRef = null;
    const r = await checkCode(name, response, ip, {
      device,
      raw: true,
      check: async (input) => {
        const v = await verify(input);
        if (v.counterError) counterRef = v.ref ?? null;
        return v.ok ? { ok: true, saved: v.saved } : { ok: false };
      },
    });
    if (counterRef !== null) await audit.write('passkey-counter-error', { user: name, passkey: db.passkeyByRef(name, counterRef)?.name ?? null, address: ip });
    return r;
  }

  // Whether a user has a passkey that works at this site's address.
  const passkeyHere = (name) => passkeys.available && db.passkeys(name).some((p) => p.rpId === passkeys.rpId);

  // The ways a user can give the second step, in the order they are offered: a passkey usable
  // here, the app code, a recovery code. A recovery code is offered while any are left, and also
  // when nothing else is (there is always a field to fill in, so the step never looks open).
  function methodsFor(name) {
    const f = db.secondFactors(name);
    if (!f.totp && f.passkeys === 0) return [];
    const out = [];
    if (passkeyHere(name)) out.push('passkey');
    if (f.totp) out.push('totp');
    if (f.recoveryCodesLeft > 0 || out.length === 0) out.push('recovery');
    return out;
  }

  // A new passkey prompt for a second step: its challenge goes into p, its options to the browser.
  // null (and no challenge) when the user has no passkey usable here.
  function promptFor(p) {
    const o = passkeyHere(p.name) ? passkeys.loginOptions(p.name) : null;
    p.challenge = o?.challenge ?? null;
    return o?.options ?? null;
  }

  function sweepPending() {
    const t = now();
    for (const [token, p] of pending) if (t - p.created >= PENDING_MS || t < p.created) pending.delete(token);
  }

  // The second step after a right password: {token, methods, passkey?, passkeyUnavailable?}. The
  // token is only good from the same address, and while the user's epoch is still the one attempt
  // gave. methods: the ways the user can give it (methodsFor). passkey: the options of the passkey
  // prompt, when 'passkey' is one of them; its challenge is kept with the token. passkeyUnavailable:
  // the user has passkeys, but none that works at this address.
  function startSecondFactor(name, ip, { epoch, device = null }) {
    if (!Number.isInteger(epoch)) throw new Error('startSecondFactor needs the epoch that attempt gave');
    sweepPending();
    const mine = [...pending].filter(([, p]) => lower(p.name) === lower(name));
    for (const [token] of mine.slice(0, Math.max(0, mine.length - MAX_PENDING_PER_USER + 1))) pending.delete(token);
    while (pending.size >= MAX_PENDING) pending.delete(pending.keys().next().value);
    const token = crypto.randomBytes(32).toString('base64url');
    const p = { name, addressKey: ipKey(ip), created: now(), tries: 0, epoch, device, challenge: null };
    let methods = methodsFor(name);
    const options = methods.includes('passkey') ? promptFor(p) : null;
    // Removed meanwhile: it is not offered.
    if (options === null) methods = methods.filter((m) => m !== 'passkey');
    pending.set(token, p);
    const out = { token, methods };
    if (options !== null) out.passkey = options;
    if (db.secondFactors(name).passkeys > 0 && !passkeyHere(name)) out.passkeyUnavailable = true;
    return out;
  }

  // The second step. Gives {ok: true, name, epoch, device} (the token is then used up), or {ok:
  // false, reason}: 'expired' (no such token, too old, from another address, too many wrong codes,
  // or the user's sign in changed meanwhile: start again), 'invalid' or 'throttled' (with restart:
  // true when the wait outlasts the token). passkey: a passkey answer (the parsed JSON of
  // navigator.credentials.get), checked against the challenge of this step, which is used up
  // whatever the result; when the step goes on, a failure carries the options of a new prompt
  // (passkey).
  async function finishSecondFactor(token, { code, recovery, passkey }, ip) {
    sweepPending();
    const p = typeof token === 'string' && ID_RE.test(token) ? pending.get(token) : undefined;
    if (!p || p.addressKey !== ipKey(ip) || unavailable()) return { ok: false, reason: 'expired' };
    // Taken out while the code is checked: the same token cannot be used twice at once.
    pending.delete(token);
    if (!db.lookup(p.name) || p.epoch !== epochOf(p.name)) return { ok: false, reason: 'expired' };
    // A device forgotten since the password step is a device no longer.
    const device = p.device !== null && db.hasDevice(p.name, p.device) ? p.device : null;
    const usePasskey = passkey !== undefined && passkey !== null;
    const useRecovery = !usePasskey && typeof recovery === 'string' && recovery !== '';
    let r;
    if (usePasskey) {
      const challenge = p.challenge;
      p.challenge = null;
      r = await checkPasskey(p.name, passkey, ip, { device, verify: (input) => (challenge === null ? { ok: false } : passkeys.verify(p.name, input, challenge)) });
    } else {
      r = await checkCode(p.name, useRecovery ? recovery : code, ip, { recovery: useRecovery, device });
    }
    // A password change or the like while the code was checked ends this sign in.
    if (p.epoch !== epochOf(p.name)) return { ok: false, reason: 'expired' };
    if (!r.ok) {
      if (r.reason === 'invalid') p.tries++;
      const left = PENDING_MS - (now() - p.created);
      if (r.reason === 'throttled' && r.retryAfterMs >= left) return { ...r, restart: true };
      if (p.tries < PENDING_TRIES && left > 0) pending.set(token, p);
      else return { ok: false, reason: 'expired' };
      // The step goes on: a used passkey challenge is replaced, so the next prompt can work.
      if (usePasskey) {
        const options = promptFor(p);
        if (options !== null) return { ...r, passkey: options };
      }
      return r;
    }
    passed(p.name, ip, device);
    return { ok: true, name: p.name, epoch: p.epoch, device, recoveryLeft: r.recoveryLeft };
  }

  // Ends a user's sessions (all of them, or all but keep), drops their open second steps, also any
  // being checked right now, and forgets their known devices (but the one of the session kept).
  // Gives how many sessions ended. Every change to how a user signs in, or to whether they exist,
  // must call it: a password change (keeping the session that made it), turning a second factor on
  // or off, and making or deleting a user, changing their role, or resetting their password or
  // second factor (see users.js and admin.js).
  function endUser(name, keep = null) {
    const k = lower(name);
    epochs.set(k, epochOf(k) + 1);
    upgraded.delete(k);
    for (const [token, p] of pending) if (lower(p.name) === k) pending.delete(token);
    // The passkey challenges of their account pages (adding a passkey, confirming a change) go too.
    passkeys.dropUser(name);
    const kept = keep === null ? null : (sessions.map.get(keep)?.device ?? null);
    db.dropDevices(name, { keep: kept }).saved.catch((err) => log(`could not save that ${name}'s devices were forgotten: ${err.message}`));
    return sessions.destroyOthers(name, keep);
  }

  // Finishes a sign in: a new session, and the browser remembered as a known device. Gives null when
  // the user's epoch is no longer the one the password was checked in (start again), else {id,
  // deviceId}: deviceId is the device id for the cookie (a new one, or the one the browser has).
  // old: a session id the request came with, which is ended (a planted id never becomes a session).
  // A device is only kept when deviceId is the id of it; else the browser is a new one.
  //
  // A new device goes to audit.log only when it is the user's first in a day, or when it pushes out
  // a device older than a day; the others are summed up in failures.log, so that signing in from
  // new browsers over and over cannot push the security events out of audit.log.
  async function signIn(name, { epoch, device = null, deviceId = null, old = null, ip = null }) {
    if (epochOf(name) !== epoch || !db.lookup(name) || unavailable()) return null;
    if (old) sessions.destroy(old);
    const fresh = device === null || deviceHash(deviceId) !== device;
    const id = fresh ? newDeviceId() : deviceId;
    const hash = fresh ? deviceHash(id) : device;
    const sessionId = sessions.create(name, { device: hash });
    const t = now();
    const age = (d) => t - Date.parse(d.created);
    const firstToday = fresh && !db.devices(name).some((d) => age(d) < DEVICE_AUDIT_MS && age(d) >= 0);
    // In memory at once; written in the background. A known device is only noted as used (it is
    // added again when it was removed meanwhile).
    let evicted = [];
    let saved = Promise.resolve();
    if (fresh || !db.hasDevice(name, hash)) ({ evicted, saved } = db.rememberDevice(name, hash));
    saved = saved.catch((err) => log(`could not save ${name}'s device: ${err.message}`));
    const login = db.touchLogin(name, hash).catch((err) => log(`could not save the sign in time: ${err.message}`));
    if (fresh) {
      const pushedOut = evicted.filter((d) => age(d) >= DEVICE_AUDIT_MS).length;
      if (firstToday || pushedOut > 0) await audit.write('device-added', pushedOut > 0 ? { user: name, pushedOut, address: ip } : { user: name, address: ip });
      else failures.note('device-added', `user:${lower(name)}`, { user: name, address: ip });
    }
    await Promise.all([saved, login]);
    // Ended meanwhile (endUser ended the session and forgot the device too).
    if (epochOf(name) !== epoch || !sessions.map.has(sessionId) || unavailable()) {
      sessions.destroy(sessionId);
      return null;
    }
    return { id: sessionId, deviceId: id };
  }

  // The session of this request, as {id, session, user: {name, role, source, mustChangePassword}},
  // or null. A session of a user who no longer exists is ended; the role is always the one the user
  // has now. A user who must change their password has a session, but only for the password change
  // and signing out (see viewer, and the account and users APIs).
  function session(req) {
    if (unavailable()) return null;
    const id = cookieValue(req.headers.cookie, COOKIE);
    const s = sessions.get(id);
    if (!s) return null;
    const user = db.lookup(s.name);
    if (!user) {
      sessions.destroy(id);
      return null;
    }
    return { id, session: s, user };
  }

  return {
    // Whether anyone can sign in. Read once, when the app is made.
    enabled: users.length > 0 || db.hasLocalUsers(),
    store: db,
    sessions,
    accounts,
    addresses,
    nets56,
    nets48,
    devices,
    deviceTurns,
    reauths,
    names,
    codes,
    codeUsers,
    pending,
    audit,
    failures,
    trusted: proxyMatcher(settings.trustedProxies),
    // The passkeys of this site (passkeys.js), for the account and users APIs.
    passkeys,
    attempt,
    checkCode,
    checkPasskey,
    methodsFor,
    startSecondFactor,
    finishSecondFactor,
    endUser,
    epochOf,
    signIn,
    // The device hash of the cookie of this request, whether or not it is known.
    deviceOf: (req) => deviceHash(cookieValue(req.headers.cookie, DEVICE_COOKIE)),
    // A new password hash, through the reserved lane of the session that asks.
    hash: (password, { session: sid = null } = {}) => gate(() => hashPassword(password, undefined, hasher, db.currentPepper()), sid === null ? null : `session:${sid}`, 'session'),
    maxAgeSeconds: Math.floor(sessions.maxAgeMs / 1000),
    session,
    // The name of whoever is logged in on this request, or null. A user who must change their
    // password first counts as nobody: they see what a visitor sees.
    viewer: (req) => {
      const cur = session(req);
      return cur && !cur.user.mustChangePassword ? cur.user.name : null;
    },
  };
}
