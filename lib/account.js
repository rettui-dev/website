// The account API behind the /account page: who is signed in, password change (website users only),
// the TOTP second factor (set up, turn on, turn off, new recovery codes), and signing out everywhere
// else.
//
// Every change is a POST of JSON from the page itself: Sec-Fetch-Site (or Origin) must say same
// origin, the body must be application/json, and the request must carry the X-Rettui-Request
// header, which a form on another site cannot send. Every change also needs a sign in (password)
// from the last 15 minutes; after that the page asks for the password again (POST
// /api/account/reauth, at most REAUTHS_PER_SESSION and REAUTHS_PER_USER an hour). Setting up TOTP and making new recovery codes need the password (or a
// current code) in the request as well. A secret is only ever sent once, to its owner, in the
// answer to set up.
//
// A password asked for here is checked with the waits of the session, not of the name, so nobody
// outside can make a signed-in user wait by sending wrong passwords for the name.
//
// A session can end while its request is under way (a password change or sign out elsewhere, the
// user removed). After every await a change checks that its session is still there; if not, it
// answers 401 and changes nothing, and it never hands out a secret.
import { MAX_PASSWORD_BYTES, MIN_PASSWORD_CHARS, weakPassword } from './password.js';
import { Busy, TooLarge, clientIp, readBody, sameOrigin, waitText } from './login.js';
import { UserError } from './users.js';
import { otpauthUri } from './totp.js';
import { encode } from './qr.js';

export const RECENT_AUTH_MS = 15 * 60_000;
export { MIN_PASSWORD_CHARS };
export const REQUEST_HEADER = 'x-rettui-request';
export const ACCOUNT_PATHS = [
  '/api/account/reauth',
  '/api/account/password',
  '/api/account/totp/setup',
  '/api/account/totp/enable',
  '/api/account/totp/disable',
  '/api/account/recovery-codes',
  '/api/account/sign-out-others',
  '/api/account/devices/remove',
  '/api/account/devices/remove-others',
];
// How often each of these may be asked for in an hour, per session and per user, wrong passwords
// and codes included.
export const ACTION_WINDOW_MS = 60 * 60_000;
export const ACTIONS_PER_SESSION = 5;
export const ACTIONS_PER_USER = 10;
// Passwords asked again (reauth), right and wrong: per session and per user in an hour. Each is a
// hash in the place kept for signed-in users, so they are counted even when the password is right.
export const REAUTHS_PER_SESSION = 10;
export const REAUTHS_PER_USER = 20;
const LIMITED = new Set(['/api/account/totp/setup', '/api/account/totp/enable', '/api/account/totp/disable', '/api/account/recovery-codes', '/api/account/sign-out-others']);

const isJsonType = (value) => typeof value === 'string' && /^application\/json\s*(;|$)/i.test(value);
const isMap = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const iso = (ms) => new Date(ms).toISOString();
// How a device is named to its owner: the start of its hash, enough to tell ten apart.
const deviceRef = (hash) => hash.slice(0, 16);
const DEVICE_REF_RE = /^[0-9a-f]{16}$/;
const GONE = { error: 'Your session has ended. Sign in again.', signIn: true };

// A text field of the body, or '' when it is missing, not text or longer than max.
const field = (body, name, max = 256) => (typeof body[name] === 'string' && body[name].length <= max ? body[name] : '');

// At most `limit` uses per key in any windowMs. At most maxKeys keys are kept; past that the one
// used least recently is forgotten.
export class Budget {
  constructor({ limit, windowMs = ACTION_WINDOW_MS, maxKeys = 10_000, now = Date.now }) {
    Object.assign(this, { limit, windowMs, maxKeys, now });
    this.map = new Map();
  }

  recent(key) {
    const t = this.now();
    return (this.map.get(key) ?? []).filter((at) => t - at < this.windowMs && at <= t);
  }

  // Milliseconds until the key may be used again; 0 when it may now.
  wait(key) {
    const list = this.recent(key);
    return list.length < this.limit ? 0 : list[0] + this.windowMs - this.now();
  }

  take(key) {
    const list = this.recent(key);
    list.push(this.now());
    this.map.delete(key);
    while (this.map.size >= this.maxKeys) this.map.delete(this.map.keys().next().value);
    this.map.set(key, list);
  }
}

// The QR code of the setup URI as rows of 0 and 1; the page draws it. null if it does not fit.
function qrRows(text) {
  for (const level of ['M', 'L']) {
    try {
      const { size, grid } = encode(text, { level });
      return { size, rows: grid.map((row) => row.map((dark) => (dark ? '1' : '0')).join('')) };
    } catch (err) {
      if (!(err instanceof RangeError)) throw err;
    }
  }
  return null;
}

// auth: what createLogin gives. issuer: the name authenticator apps show for the site.
export function createAccountApi({ auth, issuer = 'rettui status', now = Date.now, log = console.error }) {
  const store = auth.store;
  const audit = auth.audit;
  const perSession = new Budget({ limit: ACTIONS_PER_SESSION, now });
  const perUser = new Budget({ limit: ACTIONS_PER_USER, now });
  const reauthPerSession = new Budget({ limit: REAUTHS_PER_SESSION, now });
  const reauthPerUser = new Budget({ limit: REAUTHS_PER_USER, now });
  // The budgets of a path, per session and per user, or null.
  const budgets = (pathname) => {
    if (pathname === '/api/account/reauth') return [reauthPerSession, reauthPerUser];
    return LIMITED.has(pathname) ? [perSession, perUser] : null;
  };
  const recent = (s) => now() - s.authAt < RECENT_AUTH_MS && now() >= s.authAt;
  const retry = (json, r) => {
    const s = Math.ceil(r.retryAfterMs / 1000);
    return json(429, { error: `Too many wrong tries. Try again in ${waitText(r.retryAfterMs)}.`, retryAfter: s }, { 'Retry-After': String(s) });
  };

  // The password of the signed-in user, through the waits of this session. true when it is
  // right; else the answer is sent and it gives false.
  async function checkPassword(json, name, password, ip, wrong, sessionId) {
    const refuse = (...args) => {
      json(...args);
      return false;
    };
    if (!password) return refuse(400, { error: 'Enter your password.', field: 'password' });
    const r = await auth.attempt(name, password, ip, { session: sessionId });
    // Ended while the password was checked: whatever the answer, there is nothing to go on with.
    if (!auth.sessions.map.has(sessionId)) return refuse(401, GONE);
    if (r.reason === 'throttled') {
      retry(json, r);
      return false;
    }
    if (r.reason === 'busy') return refuse(503, { error: 'Too many sign ins at once. Try again in a moment.' }, { 'Retry-After': '2' });
    if (!r.ok) return refuse(400, { error: wrong, field: 'password' });
    return true;
  }

  // The password, or with allowCode a current code from the app, in the body. Gives 'code' or
  // 'password' when one is right; else the answer is sent and it gives null.
  async function confirm(json, body, name, ip, cur, allowCode) {
    const code = allowCode ? field(body, 'code', 64).trim() : '';
    if (code) {
      const device = cur.session.device && store.hasDevice(name, cur.session.device) ? cur.session.device : null;
      const r = await auth.checkCode(name, code, ip, { device });
      if (!auth.sessions.map.has(cur.id)) {
        json(401, GONE);
        return null;
      }
      if (r.reason === 'throttled') {
        retry(json, r);
        return null;
      }
      if (!r.ok) {
        json(400, { error: 'That code is not right.', field: 'code' });
        return null;
      }
      return 'code';
    }
    return (await checkPassword(json, name, field(body, 'password', 4096), ip, 'Wrong password.', cur.id)) ? 'password' : null;
  }

  // GET /api/account
  function get(req, json) {
    const cur = auth.session(req);
    const account = cur ? store.account(cur.user.name) : null;
    if (!account) return json(401, { error: 'Sign in first.', signIn: true });
    const s = cur.session;
    const here = auth.deviceOf(req);
    return json(200, {
      name: account.name,
      role: account.role,
      managedByConfig: account.source === 'config',
      canChangePassword: account.source === 'store',
      lastLogin: account.lastLogin,
      recentSignIn: recent(s),
      recentUntil: recent(s) ? iso(s.authAt + RECENT_AUTH_MS) : null,
      totp: account.totp,
      sessions: auth.sessions.list(account.name).sort((a, b) => a.created - b.created).map((x) => ({ created: iso(x.created), lastSeen: iso(x.seen), current: x.id === cur.id })),
      // Known devices: no name is known for them, only when they were first and last used.
      devices: store.devices(account.name).sort((a, b) => (a.created < b.created ? -1 : 1)).map((d) => ({ id: deviceRef(d.hash), created: d.created, lastUsed: d.lastUsed, current: d.hash === here })),
    });
  }

  const gone = (json) => json(401, GONE);

  // Each action gets alive(): whether its session is still there. It is asked after every await,
  // and by the store right before a change is written (guard).
  const actions = {
    async '/api/account/reauth'({ json, body, name, ip, cur, s, alive }) {
      if (!(await checkPassword(json, name, field(body, 'password', 4096), ip, 'Wrong password.', cur.id))) return;
      if (!alive()) return gone(json);
      s.authAt = now();
      return json(200, { ok: true, recentUntil: iso(s.authAt + RECENT_AUTH_MS) });
    },

    async '/api/account/password'({ json, body, name, ip, cur, user, alive }) {
      if (user.source === 'config') return json(409, { error: 'This password is set in the config file. Change it there.' });
      const current = field(body, 'current', 4096);
      const next = field(body, 'next', 4096);
      if (Buffer.byteLength(next) > MAX_PASSWORD_BYTES) return json(400, { error: `The new password must be at most ${MAX_PASSWORD_BYTES} bytes.`, field: 'next' });
      const weak = weakPassword(next, name);
      if (weak) return json(400, { error: weak, field: 'next' });
      if (next === current) return json(400, { error: 'The new password is the same as the current one.', field: 'next' });
      if (!(await checkPassword(json, name, current, ip, 'The current password is wrong.', cur.id))) return;
      if (!alive()) return gone(json);
      let phc;
      try {
        phc = await auth.hash(next, { session: cur.id });
      } catch (err) {
        if (err instanceof Busy) return json(503, { error: 'Too many sign ins at once. Try again in a moment.' }, { 'Retry-After': '2' });
        throw err;
      }
      if (!alive()) return gone(json);
      // Written first; only then is anyone signed out. A failed write changes nothing.
      await store.setPassword(name, phc, { guard: alive });
      // Whoever had the old password is signed out everywhere else, loses any sign in half done, and
      // every other known device is forgotten. Should this session have ended while the new password
      // was written, it is changed all the same, and every session ends.
      const still = alive();
      auth.endUser(name, still ? cur.id : null);
      await audit.write('password-changed', { user: name, address: ip });
      return still ? json(200, { ok: true }) : gone(json);
    },

    async '/api/account/totp/setup'({ json, body, name, ip, cur, alive }) {
      if (store.secondFactorEnabled(name)) return json(409, { error: 'Two-step sign-in is already on. Turn it off first to set it up again.' });
      if (!(await confirm(json, body, name, ip, cur, false))) return;
      if (!alive()) return gone(json);
      const secret = await store.beginTotp(name, { guard: alive });
      // The secret is only ever given to a session that is still there.
      if (!alive()) return gone(json);
      const uri = otpauthUri({ issuer, account: name, secret });
      return json(200, { secret, uri, qr: qrRows(uri) });
    },

    async '/api/account/totp/enable'({ json, body, name, ip, cur, alive }) {
      if (store.secondFactorEnabled(name)) return json(409, { error: 'Two-step sign-in is already on.' });
      // Checked before any code, so that this answer never touches the count of wrong codes.
      if (!store.totpPending(name)) return json(409, { error: 'Set up two-step sign-in first.' });
      let codes = null;
      const r = await auth.checkCode(name, field(body, 'code', 64), ip, {
        check: async (text) => {
          try {
            codes = await store.enableTotp(name, text, { guard: alive });
          } catch (err) {
            // Set up again or turned on by another request meanwhile: this code is not good now.
            // A session that ended is not a wrong code: that goes up as it is.
            if (!(err instanceof UserError) || err.code === 'gone') throw err;
            return { ok: false };
          }
          return { ok: codes !== null };
        },
      });
      if (r.reason === 'throttled') return retry(json, r);
      if (!r.ok) return json(400, { error: 'That code is not right. Enter the code your app shows now.', field: 'code' });
      // From now on a sign in needs the code: every other session ends.
      const still = alive();
      auth.endUser(name, still ? cur.id : null);
      await audit.write('totp-enabled', { user: name, address: ip });
      // The recovery codes are only ever given to a session that is still there.
      return still && alive() ? json(200, { ok: true, recoveryCodes: codes }) : gone(json);
    },

    async '/api/account/totp/disable'({ json, body, name, ip, cur, alive }) {
      if (!store.secondFactorEnabled(name)) return json(409, { error: 'Two-step sign-in is not on.' });
      const how = await confirm(json, body, name, ip, cur, true);
      if (!how) return;
      if (!alive()) return gone(json);
      await store.disableTotp(name, { guard: alive });
      const still = alive();
      auth.endUser(name, still ? cur.id : null);
      await audit.write('totp-disabled', { user: name, with: how, address: ip });
      return still ? json(200, { ok: true }) : gone(json);
    },

    async '/api/account/recovery-codes'({ json, body, name, ip, cur, alive }) {
      if (!store.secondFactorEnabled(name)) return json(409, { error: 'Two-step sign-in is not on.' });
      const how = await confirm(json, body, name, ip, cur, true);
      if (!how) return;
      if (!alive()) return gone(json);
      const codes = await store.newRecoveryCodes(name, { guard: alive });
      await audit.write('recovery-codes-regenerated', { user: name, with: how, address: ip });
      return alive() ? json(200, { ok: true, recoveryCodes: codes }) : gone(json);
    },

    async '/api/account/sign-out-others'({ json, name, ip, cur, alive }) {
      if (!alive()) return gone(json);
      const ended = auth.endUser(name, cur.id);
      await audit.write('sessions-ended', { user: name, ended, address: ip });
      return json(200, { ok: true, ended });
    },

    // Forgets one known device (body: {device: its id from GET /api/account}), and signs it out:
    // every session made on it ends. When that is this browser, the answer is 401.
    async '/api/account/devices/remove'({ json, body, name, ip, alive }) {
      const ref = field(body, 'device', 16);
      if (!DEVICE_REF_RE.test(ref)) return json(400, { error: 'Say which device to remove.' });
      const hit = store.devices(name).find((d) => deviceRef(d.hash) === ref);
      if (!hit) return json(404, { error: 'That device is not known. Reload the page.' });
      if (!alive()) return gone(json);
      const { removed, hashes, saved } = store.dropDevices(name, { only: hit.hash });
      const ended = auth.sessions.destroyDevices(name, hashes);
      await saved;
      await audit.write('device-removed', { user: name, ended, address: ip });
      return alive() ? json(200, { ok: true, removed, ended }) : gone(json);
    },

    // Forgets every known device but this browser, and signs them out.
    async '/api/account/devices/remove-others'({ json, name, ip, here, alive }) {
      if (!alive()) return gone(json);
      const { removed, hashes, saved } = store.dropDevices(name, { keep: here });
      const ended = auth.sessions.destroyDevices(name, hashes);
      await saved;
      await audit.write('devices-removed', { user: name, removed, ended, address: ip });
      return alive() ? json(200, { ok: true, removed, ended }) : gone(json);
    },
  };

  // POST /api/account/...
  async function post(req, pathname, json) {
    if (!Object.hasOwn(actions, pathname)) return json(404, { error: 'Not found' });
    if (!sameOrigin(req.headers) || req.headers[REQUEST_HEADER] !== '1') return json(403, { error: 'Send this from the account page.' });
    if (!isJsonType(req.headers['content-type'])) return json(415, { error: 'Send JSON (application/json).' });
    let text;
    try {
      text = await readBody(req);
    } catch (err) {
      if (err instanceof TooLarge) return json(413, { error: 'The request is too large.' }, { Connection: 'close' });
      throw err;
    }
    let body;
    try {
      body = JSON.parse(text);
    } catch {
      return json(400, { error: 'The request is not JSON.' });
    }
    if (!isMap(body)) return json(400, { error: 'The request is not a JSON object.' });
    const cur = auth.session(req);
    if (!cur) return json(401, { error: 'Sign in first.', signIn: true });
    const s = cur.session;
    const name = cur.user.name;
    // Asking for the password again is the one thing that needs no recent sign in.
    if (pathname !== '/api/account/reauth' && !recent(s)) return json(403, { error: 'Enter your password again to do this.', reauth: true });
    const limits = budgets(pathname);
    if (limits) {
      const keys = [[limits[0], `${pathname}|session:${cur.id}`], [limits[1], `${pathname}|user:${name.toLowerCase()}`]];
      const wait = Math.max(...keys.map(([b, k]) => b.wait(k)));
      if (wait > 0) {
        const sec = Math.ceil(wait / 1000);
        return json(429, { error: `You did this too often. Try again in ${waitText(wait)}.`, retryAfter: sec }, { 'Retry-After': String(sec) });
      }
      for (const [b, k] of keys) b.take(k);
    }
    const ip = clientIp(req, auth.trusted);
    const alive = () => auth.sessions.map.has(cur.id) && store.lookup(name) !== null;
    try {
      return await actions[pathname]({ json, body, name, ip, cur, s, user: cur.user, alive, here: auth.deviceOf(req) });
    } catch (err) {
      // Every change is written before it is made: when the write fails, nothing changed.
      if (err instanceof UserError && err.code === 'gone') return gone(json);
      if (err instanceof UserError) return json(409, { error: 'That cannot be done right now. Reload the page and try again.' });
      log(`account change failed: ${err?.message ?? err}`);
      return json(500, { error: 'The change could not be saved, so nothing was changed. Try again later.' });
    }
  }

  return { get, post };
}
