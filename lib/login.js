// The status page login: sessions, failed-attempt backoff and the checks around
// a login request. Everything is in memory, in one process: sessions are lost
// on a restart and are not shared between processes.
import crypto from 'node:crypto';
import net from 'node:net';
import { MAX_PASSWORD_BYTES, argon2id, costliest, dummyPhc, verifyPassword } from './password.js';

export const COOKIE = '__Host-rettui_session';
export const MAX_FORM_BYTES = 4096;
export const MAX_NAME_INPUT = 64;
// Each hash takes the memory its costs say (19 MiB by default): only this many
// run at once, and only this many more wait. Past that a login is turned away.
export const MAX_CONCURRENT_HASHES = 2;
export const MAX_QUEUED_HASHES = 8;
export const LOGIN_DEFAULTS = { idleTimeoutMinutes: 60, maxAgeHours: 12, maxSessions: 1000, trustedProxies: [] };

const ID_RE = /^[A-Za-z0-9_-]{43}$/;

// Sessions by a random 256-bit id. A session ends after idleMs without a request
// or maxAgeMs after the login, whichever comes first. With max sessions open,
// a new login pushes out the one used least recently.
export class Sessions {
  constructor({ idleMs, maxAgeMs, max, now = Date.now }) {
    Object.assign(this, { idleMs, maxAgeMs, max, now });
    // Kept in order of last use: the first entry is the one to push out.
    this.map = new Map();
  }

  create(name) {
    this.sweep();
    while (this.map.size >= this.max) this.map.delete(this.map.keys().next().value);
    const id = crypto.randomBytes(32).toString('base64url');
    const t = this.now();
    this.map.set(id, { name, created: t, seen: t });
    return id;
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
// maxEntries are kept, so the memory stays bounded. When the map is full only an
// entry whose wait is over makes room for a new key: flooding it with new keys
// must not free a key that is still waiting. With every entry still waiting, a
// new key is told to wait too.
export class Throttle {
  constructor({ free = 5, baseMs = 1000, maxMs = 15 * 60_000, forgetMs = 60 * 60_000, maxEntries = 10_000, now = Date.now } = {}) {
    Object.assign(this, { free, baseMs, maxMs, forgetMs, maxEntries, now });
    this.map = new Map();
  }

  // Milliseconds to wait before the next try; 0 when one is allowed now.
  wait(key) {
    const t = this.now();
    const e = this.map.get(key);
    if (!e) return this.map.size < this.maxEntries ? 0 : this.full(t);
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
    if (!old && !this.room(t)) return;
    const count = old && t - old.last < this.forgetMs ? old.count + 1 : 1;
    const over = count - this.free;
    const until = over > 0 ? t + Math.min(this.baseMs * 2 ** Math.min(over - 1, 30), this.maxMs) : 0;
    this.map.delete(key);
    this.map.set(key, { count, last: t, until });
  }

  clear(key) {
    this.map.delete(key);
  }

  // Makes room for one more key by dropping the oldest entry whose wait is over.
  // False when every entry is still waiting.
  room(t) {
    if (this.map.size < this.maxEntries) return true;
    for (const [k, e] of this.map) {
      if (t >= e.until) {
        this.map.delete(k);
        if (this.map.size < this.maxEntries) return true;
      }
    }
    return this.map.size < this.maxEntries;
  }

  // The wait of a new key on a full map: 0 when an entry could make room,
  // else until the first entry's wait is over.
  full(t) {
    let soonest = Infinity;
    for (const e of this.map.values()) {
      if (t >= e.until) return 0;
      soonest = Math.min(soonest, e.until - t);
    }
    return Number.isFinite(soonest) ? soonest : 0;
  }

  get size() {
    return this.map.size;
  }
}

export class Busy extends Error {}

// Runs async jobs at most `limit` at a time, with at most `queue` waiting; one
// more is rejected with Busy at once instead of piling up.
export function hashGate(limit = MAX_CONCURRENT_HASHES, queue = MAX_QUEUED_HASHES) {
  let running = 0;
  const waiting = [];
  const next = () => {
    if (running >= limit || waiting.length === 0) return;
    running++;
    const { job, resolve, reject } = waiting.shift();
    Promise.resolve()
      .then(job)
      .then(resolve, reject)
      .finally(() => {
        running--;
        next();
      });
  };
  const gate = (job) =>
    new Promise((resolve, reject) => {
      if (running >= limit && waiting.length >= queue) {
        reject(new Busy('too many logins at once'));
        return;
      }
      waiting.push({ job, resolve, reject });
      next();
    });
  gate.load = () => ({ running, waiting: waiting.length });
  return gate;
}

// An address in one form: IPv4 mapped into IPv6 as plain IPv4.
export function normalIp(ip) {
  if (typeof ip !== 'string') return '';
  const m = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
  return (m ? m[1] : ip).toLowerCase();
}

// The address a request comes from. Only when it comes from a trusted proxy is
// X-Forwarded-For read, from the right, skipping the trusted proxies.
export function clientIp(req, trusted) {
  const peer = normalIp(req.socket?.remoteAddress);
  if (!trusted.has(peer)) return peer;
  const header = req.headers['x-forwarded-for'];
  const list = typeof header === 'string' ? header.split(',').map((s) => normalIp(s.trim())) : [];
  for (let i = list.length - 1; i >= 0; i--) {
    if (!net.isIP(list[i])) return peer;
    if (!trusted.has(list[i])) return list[i];
  }
  return peer;
}

// The throttle key of an address: IPv6 by its /64, since one machine usually has a whole one.
export function ipKey(ip) {
  if (net.isIPv6(ip)) {
    const full = expandV6(ip);
    return full ? `ip:${full.slice(0, 4).join(':')}::/64` : `ip:${ip}`;
  }
  return `ip:${ip}`;
}

function expandV6(ip) {
  const [head, tail] = ip.split('::');
  const a = head ? head.split(':') : [];
  const b = tail !== undefined && tail !== '' ? tail.split(':') : [];
  if (tail === undefined && a.length !== 8) return null;
  if (b.some((x) => x.includes('.')) || a.some((x) => x.includes('.'))) return null;
  const fill = tail === undefined ? [] : new Array(8 - a.length - b.length).fill('0');
  return [...a, ...fill, ...b].map((x) => x.padStart(4, '0'));
}

// Whether a POST comes from the page itself and not from another site. Browsers
// send Sec-Fetch-Site; older ones only Origin, which must then name this host.
export function sameOrigin(headers) {
  const site = headers['sec-fetch-site'];
  if (site !== undefined) return site === 'same-origin';
  const origin = headers.origin;
  const host = headers.host;
  if (typeof origin !== 'string' || typeof host !== 'string' || origin === 'null') return false;
  try {
    return new URL(origin).host === host.toLowerCase();
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

// The login itself. users: [{name, phc}] where phc is what parsePhc gives. The
// result is {ok: true, name} or {ok: false, reason, retryAfterMs?}, where reason
// is 'invalid' (one answer for an unknown name and a wrong password),
// 'throttled' or 'busy'.
export function createLogin({ users, settings = LOGIN_DEFAULTS, hasher = argon2id, now = Date.now, gate = hashGate(), throttle }) {
  const byName = new Map(users.map((u) => [u.name.toLowerCase(), u]));
  // An unknown name is checked against this. It has the highest costs of any
  // user, so it takes at least as long as a wrong password for any real name.
  const dummy = dummyPhc(costliest(users.map((u) => u.phc)));
  const accounts = throttle?.accounts ?? new Throttle({ now });
  const addresses = throttle?.addresses ?? new Throttle({ free: 20, now });
  const sessions = new Sessions({ idleMs: settings.idleTimeoutMinutes * 60_000, maxAgeMs: settings.maxAgeHours * 3_600_000, max: settings.maxSessions, now });
  // Checks running per throttle key, and the logins waiting for them to end.
  const running = new Map();

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

  async function attempt(nameInput, password, ip) {
    const name = typeof nameInput === 'string' ? nameInput.trim().toLowerCase() : '';
    const accountKey = `user:${name.slice(0, MAX_NAME_INPUT)}`;
    const addressKey = ipKey(ip);
    for (;;) {
      const wait = Math.max(accounts.wait(accountKey), addresses.wait(addressKey));
      if (wait > 0) return { ok: false, reason: 'throttled', retryAfterMs: wait };
      const key = mustWait(accounts, accountKey) ? accountKey : mustWait(addresses, addressKey) ? addressKey : null;
      if (key === null) break;
      const r = running.get(key);
      // Only so many wait for one name or address; the rest are turned away, as when the gate is full.
      if (r.waiting.length >= MAX_QUEUED_HASHES) return { ok: false, reason: 'busy', retryAfterMs: 2000 };
      await new Promise((resolve) => r.waiting.push(resolve));
    }
    const user = byName.get(name);
    const tooLong = typeof password !== 'string' || Buffer.byteLength(password) > MAX_PASSWORD_BYTES || name.length > MAX_NAME_INPUT;
    start(accountKey);
    start(addressKey);
    try {
      let good = false;
      try {
        // Too long a password cannot be right; it is refused without the cost of a hash.
        if (!tooLong) good = await gate(() => verifyPassword(password, user ? user.phc : dummy, hasher));
      } catch (err) {
        // Turned away before the check: not a failed try.
        if (err instanceof Busy) return { ok: false, reason: 'busy', retryAfterMs: 2000 };
        throw err;
      }
      if (!good || !user) {
        accounts.fail(accountKey);
        addresses.fail(addressKey);
        return { ok: false, reason: 'invalid' };
      }
      accounts.clear(accountKey);
      addresses.clear(addressKey);
      return { ok: true, name: user.name };
    } finally {
      end(accountKey);
      end(addressKey);
    }
  }

  return {
    enabled: users.length > 0,
    sessions,
    accounts,
    addresses,
    trusted: new Set(settings.trustedProxies.map(normalIp)),
    attempt,
    maxAgeSeconds: Math.floor(sessions.maxAgeMs / 1000),
    // The name of whoever is logged in on this request, or null.
    viewer(req) {
      if (users.length === 0) return null;
      return sessions.get(cookieValue(req.headers.cookie, COOKIE))?.name ?? null;
    },
  };
}
