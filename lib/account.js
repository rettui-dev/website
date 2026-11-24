// The account API behind the /account page: who is signed in, password change (website users only),
// the second factors (the TOTP app code: set up, turn on, turn off; passkeys: add, rename, remove;
// new recovery codes), and signing out everywhere else.
//
// Every change is a POST of JSON from the page itself: Sec-Fetch-Site (or Origin) must say same
// origin, the body must be application/json, and the request must carry the X-Rettui-Request
// header, which a form on another site cannot send. Every change also needs a sign in (password)
// from the last 15 minutes; after that the page asks for the password again (POST
// /api/account/reauth, at most REAUTHS_PER_SESSION and REAUTHS_PER_USER an hour). Changing the
// password, new recovery codes, setting up or turning off TOTP, and adding or removing a passkey
// need the password in the request AND, with any second factor on, a passkey, a current code or a
// recovery code (confirmBoth): the page asks for them in its step-up dialog. A secret is only ever
// sent once, to its owner, in the answer to set up.
//
// A passkey is added in two requests: passkeys/begin (after the step-up) gives the options for the
// browser and keeps their challenge for this session and the user's epoch; passkeys/finish checks
// what the browser made against it (passkeys.js). A passkey that confirms a change answers the
// challenge of passkeys/challenge, which is kept for the session and used once.
//
// A password asked for here is checked with the waits of the session, not of the name, so nobody
// outside can make a signed-in user wait by sending wrong passwords for the name.
//
// A session can end while its request is under way (a password change or sign out elsewhere, the
// user removed). After every await a change checks that its session is still there; if not, it
// answers 401 and changes nothing, and it never hands out a secret.
import { MAX_PASSWORD_BYTES, MIN_PASSWORD_CHARS, weakPassword } from './password.js';
import { Busy, TooLarge, clientIp, readBody, sameOrigin, waitText } from './login.js';
import { MAX_LXMF_ADDRESSES, UserError, writeRefusal } from './users.js';
import { MAX_NAME as MAX_PASSKEY_NAME, MAX_PASSKEYS, PasskeyError, passkeyName } from './passkeys.js';
import { otpauthUri } from './totp.js';
import { encode } from './qr.js';
import { createFactorHolds } from './factor-hold.js';
import { lxmfPrefix } from './lxmf-alerts.js';

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
  '/api/account/passkeys/challenge',
  '/api/account/passkeys/begin',
  '/api/account/passkeys/finish',
  '/api/account/passkeys/rename',
  '/api/account/passkeys/remove',
  '/api/account/lxmf/set',
  '/api/account/lxmf/resend',
  '/api/account/lxmf/confirm',
  '/api/account/lxmf/remove',
  '/api/account/lxmf/node-alerts',
  '/api/account/lxmf/test',
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
// From a session made with a passkey alone, the password is asked again this many times a day for
// the user, wrong or right: a stolen passkey gives few guesses at the password.
export const REAUTHS_PER_PASSKEY_USER = 20;
export const REAUTH_PASSKEY_WINDOW_MS = 24 * 60 * 60_000;
// Passkey challenges for confirming a change (passkeys/challenge): per session and per user in an
// hour. Each is only a little memory, but one is asked for before every confirmation.
export const CHALLENGES_PER_SESSION = 30;
export const CHALLENGES_PER_USER = 60;
// The largest JSON body of a change: a new passkey's answer is several kilobytes.
export const MAX_JSON_BYTES = 16384;
const LIMITED = new Set([
  '/api/account/totp/setup',
  '/api/account/totp/enable',
  '/api/account/totp/disable',
  '/api/account/recovery-codes',
  '/api/account/sign-out-others',
  '/api/account/passkeys/begin',
  '/api/account/passkeys/finish',
  '/api/account/passkeys/remove',
  // An LXMF address is a place where account alerts go, so it is changed like a second step: the password and
  // the second factor (confirmBoth), a few times an hour. Resending a code is not here (the recent password).
  '/api/account/lxmf/set',
  '/api/account/lxmf/confirm',
  '/api/account/lxmf/remove',
]);

export const isJsonType = (value) => typeof value === 'string' && /^application\/json\s*(;|$)/i.test(value);
export const isMap = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const iso = (ms) => new Date(ms).toISOString();
// How a device is named to its owner: the start of its hash, enough to tell ten apart.
const deviceRef = (hash) => hash.slice(0, 16);
const DEVICE_REF_RE = /^[0-9a-f]{16}$/;
// A passkey is named by its ref (users.js): the start of the SHA-256 of its id, never the id.
const PASSKEY_REF_RE = /^[0-9a-f]{16}$/;
const LXMF_FULL = `You have ${MAX_LXMF_ADDRESSES} LXMF addresses, the most allowed. Remove one first.`;
export const GONE = { error: 'Your session has ended. Sign in again.', signIn: true };
// What a user who has to change the password set for them may still do here.
const BEFORE_NEW_PASSWORD = new Set(['/api/account/reauth', '/api/account/password']);
export const CHANGE_PASSWORD_FIRST = { error: 'Choose a new password first, on your account page.', mustChangePassword: true };

// A text field of the body, or '' when it is missing, not text or longer than max.
export const field = (body, name, max = 256) => (typeof body[name] === 'string' && body[name].length <= max ? body[name] : '');

// Whether the password was given in this session in the last RECENT_AUTH_MS. A session made with a
// passkey alone has not had it (authAt is -Infinity) until the user enters the password.
//
// Routes, all of which need this (account.js post) before they run:
//   step-up too (password and second factor): password, totp/setup, totp/enable (code), totp/disable,
//     recovery-codes, passkeys/begin, passkeys/remove;
//   the recent password alone: sign-out-others, devices/remove, devices/remove-others, passkeys/rename,
//     passkeys/challenge, passkeys/finish (which also needs the challenge of begin);
//   neither: reauth (it is the way to get it, with the password and its own waits).
export const recentSignIn = (s, t) => t - s.authAt < RECENT_AUTH_MS && t >= s.authAt;

// Whether a session made with a passkey alone still has to give its password before it may read the
// manage and users pages and node logs. Unlike recentSignIn this is not a 15 minute window: once the
// password was given in this session (reauth), reads stay open for the life of the session. Changes
// keep the 15 minute rule. A passkey someone planted would otherwise read what only managers and
// admins should see, without ever knowing the password.
export const needsPassword = (s) => s.via === 'passkey' && s.passwordGiven !== true;
// The answer for such a read: the same shape the change routes give, so the pages open the password
// dialog and then load.
export const REAUTH_FIRST = { error: 'Enter your password to see this. You signed in with a passkey, which is not enough here.', reauth: true };

// Reads the JSON object a change is sent as: the checks against other sites first (the request
// header and same origin), then the type and size (at most max bytes). Gives the object, or null
// once it has answered.
export async function readJsonChange(req, json, refused, max = MAX_JSON_BYTES) {
  if (!sameOrigin(req.headers) || req.headers[REQUEST_HEADER] !== '1') {
    json(403, { error: refused });
    return null;
  }
  if (!isJsonType(req.headers['content-type'])) {
    json(415, { error: 'Send JSON (application/json).' });
    return null;
  }
  let text;
  try {
    text = await readBody(req, max);
  } catch (err) {
    if (err instanceof TooLarge) {
      json(413, { error: 'The request is too large.' }, { Connection: 'close' });
      return null;
    }
    throw err;
  }
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    json(400, { error: 'The request is not JSON.' });
    return null;
  }
  if (!isMap(body)) {
    json(400, { error: 'The request is not a JSON object.' });
    return null;
  }
  return body;
}

// Asking a signed-in user to prove it is them again: their password, and with a second factor on,
// a passkey, a current code from their app or a recovery code as well. The password goes through
// the waits of the session, never those of the name, so nobody outside can make a signed-in user
// wait by sending wrong passwords for the name.
export function createStepUp(auth) {
  const store = auth.store;
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
    if (!r.ok) {
      // A wrong password asked again from a session made with a passkey alone is a guess by whoever
      // holds the passkey; nowhere else is it noted (a signed-in user's own slips count for the session).
      if (r.reason === 'invalid' && auth.sessions.map.get(sessionId)?.via === 'passkey') auth.failures.note('reauth-failures', `user:${name.toLowerCase()}`, { user: name, address: ip });
      return refuse(400, { error: wrong, field: 'password' });
    }
    return true;
  }

  // The step-up before a sensitive change: the password, always, and when a second factor is on,
  // one of: a current code from the app (code), an unused recovery code (recovery), or a passkey
  // (passkey: what navigator.credentials.get gave for the challenge of passkeys/challenge). The
  // password alone is not enough then. The second factor is only checked once the password is
  // right, so a wrong password never uses up a code or a challenge; it is checked like one at sign
  // in (its waits, a step used once, a passkey that does not work counts as a wrong code).
  // Gives 'password', 'password+code', 'password+recovery' or 'password+passkey'; else the answer
  // is sent and it gives null. passwordField: the body field the password is in.
  async function confirmBoth(json, body, name, ip, cur, { passwordField = 'password', wrong = 'Wrong password.' } = {}) {
    const second = store.secondFactorEnabled(name);
    const code = second ? field(body, 'code', 64).trim() : '';
    const recovery = second && !code ? field(body, 'recovery', 64).trim() : '';
    const passkey = second && !code && !recovery && isMap(body.passkey) ? body.passkey : null;
    // Asked before the password is checked, so a missing second factor costs no hash and no try.
    if (second && !code && !recovery && !passkey) {
      const methods = auth.methodsFor(name);
      const error = methods.includes('passkey') ? 'Confirm with your passkey, or enter the code from your app or a recovery code.' : 'Enter the code from your app as well, or a recovery code.';
      json(400, { error, field: 'code', secondFactor: true, methods });
      return null;
    }
    if (!(await checkPassword(json, name, field(body, passwordField, 4096), ip, wrong, cur.id))) return null;
    if (!second) return 'password';
    const device = cur.session.device && store.hasDevice(name, cur.session.device) ? cur.session.device : null;
    let r;
    if (passkey) r = await auth.checkPasskey(name, passkey, ip, { device, verify: (input) => auth.passkeys.verifyStepUp(name, cur.id, input) });
    else r = await auth.checkCode(name, code || recovery, ip, { device, recovery: !code });
    if (!auth.sessions.map.has(cur.id)) {
      json(401, GONE);
      return null;
    }
    if (r.reason === 'throttled') {
      retry(json, r);
      return null;
    }
    if (!r.ok) {
      if (passkey) json(400, { error: 'That passkey did not work. Try again.', field: 'passkey' });
      else json(400, code ? { error: 'That code is not right. Enter the code your app shows now.', field: 'code' } : { error: 'That recovery code is not right, or was used already.', field: 'recovery' });
      return null;
    }
    // The passkey that confirmed this (null for a code or recovery code), for a change that keeps it.
    cur.stepUpRef = passkey ? (r.ref ?? null) : null;
    return passkey ? 'password+passkey' : code ? 'password+code' : 'password+recovery';
  }

  return { checkPassword, confirmBoth, retry };
}

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

  // Gives back the latest use of a key (a try that turned out not to count).
  giveBack(key) {
    const list = this.map.get(key);
    if (list && list.length > 0) list.pop();
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

// What the passkey steps answer for each PasskeyError code (passkeys.js): [status, body].
const PASSKEY_REFUSED = {
  unavailable: [409, { error: "Passkeys need this site's https address in the config file (site.url, or SITE_URL)." }],
  full: [409, { error: `You have ${MAX_PASSKEYS} passkeys, the most allowed. Remove one first.` }],
  expired: [409, { error: 'Adding the passkey took too long, or something changed meanwhile. Start again.' }],
  invalid: [400, { error: 'The passkey could not be checked, so it was not added. Try again.' }],
  attestation: [400, { error: 'This security key sent a certificate, which this site does not accept. Try another passkey.' }],
  duplicate: [409, { error: 'This passkey is added already.' }],
  name: [400, { error: `Give the passkey a name of up to ${MAX_PASSKEY_NAME} characters.`, field: 'name' }],
};

// auth: what createLogin gives. issuer: the name authenticator apps show for the site. holds: the
// waits after a first second factor (factor-hold.js), shared with the manage API. alerts: the alerter
// (alerts.js) or null; it is told when a passkey is added, and its lxmf (lxmf-alerts.js) holds the users' own
// LXMF addresses. siteUrl: the site's address (site.url) or null, named in a test alert.
export function createAccountApi({ auth, issuer = 'rettui status', now = Date.now, log = console.error, holds = createFactorHolds({ now }), alerts = null, siteUrl = null }) {
  const store = auth.store;
  const audit = auth.audit;
  // A first second factor, confirmed by the password alone, starts the wait before node changes
  // (factor-hold.js); it is an audit line of its own, so an operator sees it among the rest.
  async function firstFactor(name, method, ip, held) {
    const until = await held;
    await audit.write('second-factor-first', { user: name, role: store.lookup(name)?.role ?? null, method, nodeChangesFrom: iso(until), address: ip });
  }
  const perSession = new Budget({ limit: ACTIONS_PER_SESSION, now });
  const perUser = new Budget({ limit: ACTIONS_PER_USER, now });
  const reauthPerSession = new Budget({ limit: REAUTHS_PER_SESSION, now });
  const reauthPerUser = new Budget({ limit: REAUTHS_PER_USER, now });
  const reauthPerPasskeyUser = new Budget({ limit: REAUTHS_PER_PASSKEY_USER, windowMs: REAUTH_PASSKEY_WINDOW_MS, now });
  const challengePerSession = new Budget({ limit: CHALLENGES_PER_SESSION, now });
  const challengePerUser = new Budget({ limit: CHALLENGES_PER_USER, now });
  const passkeys = auth.passkeys;
  const lxmf = alerts?.lxmf ?? null;
  // A message to the user's own LXMF address about what just happened to their account. It only queues the
  // message: it never waits, and never fails what was done.
  const tell = (name, kind, details) => {
    try {
      lxmf?.notifyUser(name, kind, { ...details, at: now() });
    } catch (err) {
      log(`account: the LXMF message could not be queued (${err?.name ?? 'error'})`);
    }
  };
  // The budgets of a path, per session and per user, or null.
  const budgets = (pathname, via) => {
    if (pathname === '/api/account/reauth') return [reauthPerSession, via === 'passkey' ? reauthPerPasskeyUser : reauthPerUser];
    if (pathname === '/api/account/passkeys/challenge') return [challengePerSession, challengePerUser];
    return LIMITED.has(pathname) ? [perSession, perUser] : null;
  };
  const recent = (s) => recentSignIn(s, now());
  const { checkPassword, confirmBoth, retry } = createStepUp(auth);

  // A passkey as the account page shows it: named by its ref, never its id or key. here: it works
  // at this site's address (one made for another address is listed, so it can be removed).
  const passkeyView = (p) => ({ id: p.ref, name: p.name, created: p.created, lastUsed: p.lastUsed, synced: p.backedUp === true, here: passkeys.available && p.rpId === passkeys.rpId });

  // What the page shows of the LXMF alert addresses: {available: false} without a bridge that takes users' own
  // addresses. A session made with a passkey alone has not given the password: it is told how many addresses
  // there are but not which (an address is personal), until the password is given.
  function lxmfView(name, role, s) {
    if (!lxmf) return { available: false };
    const mine = store.lxmfOf(name);
    const list = mine?.addresses ?? [];
    const hidden = list.length > 0 && needsPassword(s);
    const confirmed = list.some((e) => e.confirmed);
    return {
      available: true,
      set: list.length > 0,
      hidden,
      count: list.length,
      max: MAX_LXMF_ADDRESSES,
      addresses: hidden
        ? []
        : list.map((e) => {
            const pending = e.confirmed ? null : lxmf.pendingFor(name, e.address);
            return { address: e.address, confirmed: e.confirmed, codeExpiresAt: pending ? iso(pending.expiresAt) : null };
          }),
      confirmed,
      // The page may show the node alerts box: admins and managers only (checked again where it is saved).
      canNodeAlerts: role === 'admin' || role === 'manage',
      nodeAlerts: confirmed && mine.nodeAlerts === true,
    };
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
      // How this session was made: 'password' or 'passkey' (a passkey alone, no password given yet).
      signedInWith: s.via === 'passkey' ? 'passkey' : 'password',
      mustChangePassword: cur.user.mustChangePassword,
      // Only admins are shown the way to the users page; the users API checks it again.
      canManageUsers: account.role === 'admin' && !cur.user.mustChangePassword,
      totp: account.totp,
      // Any second factor (the app code or a passkey), the recovery codes that go with it, and the
      // ways a change can be confirmed besides the password.
      secondFactor: store.secondFactorEnabled(account.name),
      recoveryCodesLeft: account.recoveryCodesLeft,
      stepUpMethods: auth.methodsFor(account.name),
      lxmf: lxmfView(account.name, account.role, s),
      passkeys: { available: passkeys.available, reason: passkeys.reason, origin: passkeys.origin, rpId: passkeys.rpId, max: MAX_PASSKEYS, signIn: auth.passkeySignIn === true, list: account.passkeys.map(passkeyView) },
      sessions: auth.sessions.list(account.name).sort((a, b) => a.created - b.created).map((x) => ({ created: iso(x.created), lastSeen: iso(x.seen), current: x.id === cur.id })),
      // Known devices: no name is known for them, only when they were first and last used.
      devices: store.devices(account.name).sort((a, b) => (a.created < b.created ? -1 : 1)).map((d) => ({ id: deviceRef(d.hash), created: d.created, lastUsed: d.lastUsed, current: d.hash === here })),
    });
  }

  // Sends the confirm code to address and, once the bridge took it, keeps the address (not confirmed) when the user
  // has not got it yet. A new address is told to the user's other confirmed addresses, once it is kept.
  // Only a new address (adding: true, after the step-up of /lxmf/set) may be put in the list here: a resend, or a set
  // of an address that waits, whose post was still on its way when the address was removed does not bring it back.
  async function startConfirm({ json, name, alive, address, action, how = null, adding = false }) {
    const r = await lxmf.sendCode(name, address);
    if (!alive()) return gone(json);
    if (!r.ok) {
      const { status, ...answer } = r;
      return json(status, answer, answer.retryAfter > 0 ? { 'Retry-After': String(answer.retryAfter) } : {});
    }
    const had = store.lxmfOf(name)?.addresses.some((e) => e.address === address) === true;
    if (!had && !adding) {
      lxmf.forget(name, address);
      return json(409, { error: 'Your LXMF addresses changed meanwhile. Reload the page.' });
    }
    if (!had) {
      try {
        await store.setLxmf(name, address, { guard: alive });
      } catch (err) {
        // Not kept, so the code that was sent is no good.
        lxmf.forget(name, address);
        if (err instanceof UserError && err.code === 'limit') return json(409, { error: LXMF_FULL, field: 'address' });
        throw err;
      }
      lxmf.notifyAddressChange(name, address, 'added');
    }
    await audit.write(action, { user: name, lxmf: lxmfPrefix(address), ...(how ? { with: how } : {}) });
    return json(200, { ok: true, address, codeSent: true, expiresAt: iso(r.expiresAt) });
  }

  // The addresses a user is adding right now (by name key), which count toward the most allowed from the moment the
  // step-up is done until the address is saved or the add fails, so that adds in parallel cannot go over it.
  const adding = new Map();
  const reserve = (name, address) => {
    const k = name.toLowerCase();
    const set = adding.get(k) ?? new Set();
    set.add(address);
    adding.set(k, set);
    return () => {
      set.delete(address);
      if (set.size === 0 && adding.get(k) === set) adding.delete(k);
    };
  };
  const addingCount = (name, except) => [...(adding.get(name.toLowerCase()) ?? [])].filter((a) => a !== except).length;

  // The address a request names, as lower-case hex, or null.
  const namedAddress = (body) => lxmf.normalise(body.address);
  const BAD_ADDRESS = { error: 'An LXMF address is 32 hex digits, such as 0123456789abcdef0123456789abcdef. Angle brackets around it are fine.', field: 'address' };

  const gone = (json) => json(401, GONE);

  // Each action gets alive(): whether its session is still there. It is asked after every await,
  // and by the store right before a change is written (guard).
  const actions = {
    async '/api/account/reauth'({ json, body, name, ip, cur, s, alive }) {
      if (!(await checkPassword(json, name, field(body, 'password', 4096), ip, 'Wrong password.', cur.id))) return;
      if (!alive()) return gone(json);
      s.authAt = now();
      // Opens the reads that a passkey-only session is held back from, for the rest of the session.
      s.passwordGiven = true;
      return json(200, { ok: true, recentUntil: iso(s.authAt + RECENT_AUTH_MS) });
    },

    async '/api/account/password'({ json, body, name, ip, cur, user, alive }) {
      if (user.source === 'config') return json(409, { error: 'This password is set in the config file. Change it there.' });
      // The current password comes from the step-up dialog (password); current is the older name.
      const passwordField = typeof body.password === 'string' ? 'password' : 'current';
      const current = field(body, passwordField, 4096);
      const next = field(body, 'next', 4096);
      if (Buffer.byteLength(next) > MAX_PASSWORD_BYTES) return json(400, { error: `The new password must be at most ${MAX_PASSWORD_BYTES} bytes.`, field: 'next' });
      const weak = weakPassword(next, name);
      if (weak) return json(400, { error: weak, field: 'next' });
      if (next === current) return json(400, { error: 'The new password is the same as the current one.', field: 'next' });
      const how = await confirmBoth(json, body, name, ip, cur, { passwordField, wrong: 'The current password is wrong.' });
      if (!how) return;
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
      // Asked for with the change (it was confirmed by the same step-up): every passkey but the one
      // that confirmed it goes, and all of them when it was confirmed with a code or recovery code.
      // Only a body that says true does it; the step-up above is what makes it allowed. It is one
      // write with the password: both change, or neither, so a failed write never leaves the new
      // password with the old passkeys and everyone still signed in.
      const keep = how === 'password+passkey' ? (cur.stepUpRef ?? null) : null;
      const { removedPasskeys } = await store.setPassword(name, phc, { guard: alive, removeOtherPasskeys: body.removeOtherPasskeys === true ? { keep } : null });
      // Whoever had the old password is signed out everywhere else, loses any sign in half done, and
      // every other known device is forgotten. Should this session have ended while the new password
      // was written, it is changed all the same, and every session ends.
      const still = alive();
      auth.endUser(name, still ? cur.id : null);
      tell(name, 'password_changed', { removedPasskeys });
      await audit.write('password-changed', { user: name, with: how, address: ip });
      if (removedPasskeys !== null) await audit.write('passkeys-removed-with-password', { user: name, count: removedPasskeys, with: how, address: ip });
      const answer = removedPasskeys === null ? { ok: true } : { ok: true, removedPasskeys };
      return still ? json(200, answer) : gone(json);
    },

    // With a passkey on already, adding the app code needs that second factor too (confirmBoth);
    // without one, the password alone.
    async '/api/account/totp/setup'({ json, body, name, ip, cur, alive }) {
      if (store.secondFactors(name).totp) return json(409, { error: 'The app code is already on. Turn it off first to set it up again.' });
      if (!(await confirmBoth(json, body, name, ip, cur))) return;
      if (!alive()) return gone(json);
      const secret = await store.beginTotp(name, { guard: alive });
      // The secret is only ever given to a session that is still there.
      if (!alive()) return gone(json);
      const uri = otpauthUri({ issuer, account: name, secret });
      return json(200, { secret, uri, qr: qrRows(uri) });
    },

    // Turning the app code on always makes new recovery codes, in place of any the user had (from a
    // passkey), and always ends the other sessions: the answer shows the codes that work now.
    async '/api/account/totp/enable'({ json, body, name, ip, cur, alive }) {
      if (store.secondFactors(name).totp) return json(409, { error: 'The app code is already on.' });
      // Checked before any code, so that this answer never touches the count of wrong codes.
      if (!store.totpPending(name)) return json(409, { error: 'Set up two-step sign-in first.' });
      // Without a passkey on, this is the first second factor: its setup was confirmed by the
      // password alone.
      const first = !store.secondFactorEnabled(name);
      let codes = null;
      let held = null;
      const r = await auth.checkCode(name, field(body, 'code', 64), ip, {
        check: async (text) => {
          try {
            codes = await store.enableTotp(name, text, { guard: alive });
            // The wait counts from the moment the factor is on (in memory at once).
            if (codes !== null && first) held = holds.start(name);
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
      if (held !== null) await firstFactor(name, 'totp', ip, held);
      // The recovery codes are only ever given to a session that is still there.
      return still && alive() ? json(200, { ok: true, recoveryCodes: codes }) : gone(json);
    },

    // The recovery codes stay while a passkey does (secondFactorOff says whether any is left).
    async '/api/account/totp/disable'({ json, body, name, ip, cur, alive }) {
      if (!store.secondFactors(name).totp) return json(409, { error: 'The app code is not on.' });
      const how = await confirmBoth(json, body, name, ip, cur);
      if (!how) return;
      if (!alive()) return gone(json);
      await store.disableTotp(name, { guard: alive });
      const still = alive();
      auth.endUser(name, still ? cur.id : null);
      tell(name, 'second_factor_off', { secondFactorOff: !store.secondFactorEnabled(name) });
      await audit.write('totp-disabled', { user: name, with: how, address: ip });
      return still ? json(200, { ok: true, secondFactorOff: !store.secondFactorEnabled(name) }) : gone(json);
    },

    // While any second factor is on (the app code or a passkey).
    async '/api/account/recovery-codes'({ json, body, name, ip, cur, alive }) {
      if (!store.secondFactorEnabled(name)) return json(409, { error: 'Two-step sign-in is not on.' });
      const how = await confirmBoth(json, body, name, ip, cur);
      if (!how) return;
      if (!alive()) return gone(json);
      const codes = await store.newRecoveryCodes(name, { guard: alive });
      tell(name, 'recovery_codes_new', {});
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

    // A challenge for confirming a change with a passkey (step-up): the options for
    // navigator.credentials.get. The answer goes with the change, which checks it (confirmBoth).
    async '/api/account/passkeys/challenge'({ json, name, cur, alive }) {
      if (!alive()) return gone(json);
      const options = passkeys.stepUpOptions(name, cur.id);
      if (options === null) return json(409, { error: 'You have no passkey to confirm with.' });
      return json(200, { options });
    },

    // Adding a passkey, step one, after the step-up: the options for navigator.credentials.create.
    // Their challenge is kept for this session and the user's epoch: a change to how they sign in
    // meanwhile (endUser) makes the finish fail.
    async '/api/account/passkeys/begin'({ json, body, name, ip, cur, alive }) {
      if (!passkeys.available) return json(409, PASSKEY_REFUSED.unavailable[1]);
      if (store.passkeys(name).length >= MAX_PASSKEYS) return json(409, PASSKEY_REFUSED.full[1]);
      const how = await confirmBoth(json, body, name, ip, cur);
      if (!how) return;
      if (!alive()) return gone(json);
      let options;
      try {
        options = await passkeys.registrationOptions(name, { sessionId: cur.id, epoch: auth.epochOf(name), guard: alive });
      } catch (err) {
        // Full by now: another passkey was added meanwhile.
        if (!(err instanceof PasskeyError)) throw err;
        const [status, answer] = PASSKEY_REFUSED[err.code] ?? PASSKEY_REFUSED.invalid;
        return json(status, answer);
      }
      return alive() ? json(200, { options }) : gone(json);
    },

    // Adding a passkey, step two: what the browser made ({credential, name?}). The first second
    // factor brings recovery codes (shown only now) and ends every other session, as turning the
    // app code on does; a further one changes neither.
    async '/api/account/passkeys/finish'({ json, body, name, ip, cur, alive }) {
      if (!alive()) return gone(json);
      let done;
      try {
        done = await passkeys.finishRegistration(name, body.credential, { sessionId: cur.id, epoch: auth.epochOf(name), label: body.name, guard: alive });
      } catch (err) {
        if (!(err instanceof PasskeyError)) throw err;
        // A passkey id another user has: answered like any passkey that could not be checked, and
        // noted (without the id) for the operator, as it means someone sent another user's id.
        if (err.taken) auth.failures.note('passkey-id-taken', `user:${name.toLowerCase()}`, { user: name, address: ip });
        const [status, answer] = PASSKEY_REFUSED[err.code] ?? PASSKEY_REFUSED.invalid;
        return json(status, answer);
      }
      const held = done.first ? holds.start(name) : null;
      const still = alive();
      if (done.first) auth.endUser(name, still ? cur.id : null);
      // The operator's alert (alerts.events: passkey_added), before the audit write so that a failing audit
      // cannot silence it. It only queues the message and never waits;
      // it is not awaited, and should it ever throw, the passkey is added all the same.
      try {
        alerts?.notifyPasskey({ user: name, role: store.lookup(name)?.role ?? null, passkey: done.record.name, at: now() });
      } catch (err) {
        log(`account: the passkey alert could not be queued (${err?.name ?? 'error'})`);
      }
      tell(name, 'passkey_added', { passkey: done.record.name });
      await audit.write('passkey-added', { user: name, passkey: done.record.name, first: done.first, address: ip });
      if (held !== null) await firstFactor(name, 'passkey', ip, held);
      if (!still || !alive()) return gone(json);
      const view = store.passkeys(name).find((p) => p.ref === done.ref);
      const answer = { ok: true, passkey: view ? passkeyView(view) : { id: done.ref, name: done.record.name } };
      if (done.first) answer.recoveryCodes = done.recoveryCodes;
      return json(200, answer);
    },

    // Another name for a passkey ({id: its ref, name}). It changes nothing about signing in.
    async '/api/account/passkeys/rename'({ json, body, name, alive }) {
      const ref = field(body, 'id', 16);
      if (!PASSKEY_REF_RE.test(ref)) return json(400, { error: 'Say which passkey to rename.' });
      if (!store.passkeyByRef(name, ref)) return json(404, { error: 'That passkey is not known. Reload the page.' });
      const label = passkeyName(body.name);
      if (label === null) return json(400, PASSKEY_REFUSED.name[1]);
      if (!alive()) return gone(json);
      const { from, to } = await store.renamePasskey(name, ref, label, { guard: alive });
      if (from !== to) await audit.write('passkey-renamed', { user: name, from, to });
      return alive() ? json(200, { ok: true }) : gone(json);
    },

    // Removes a passkey ({id, ...step-up}) and ends every other session. When it was the last
    // second factor, two-step sign-in is off and the recovery codes go with it (secondFactorOff).
    async '/api/account/passkeys/remove'({ json, body, name, ip, cur, alive }) {
      const ref = field(body, 'id', 16);
      if (!PASSKEY_REF_RE.test(ref)) return json(400, { error: 'Say which passkey to remove.' });
      if (!store.passkeyByRef(name, ref)) return json(404, { error: 'That passkey is not known. Reload the page.' });
      const how = await confirmBoth(json, body, name, ip, cur);
      if (!how) return;
      if (!alive()) return gone(json);
      const { label, secondFactorOff } = await store.removePasskey(name, ref, { guard: alive });
      const still = alive();
      const ended = auth.endUser(name, still ? cur.id : null);
      tell(name, 'passkey_removed', { passkey: label, secondFactorOff });
      await audit.write('passkey-removed', { user: name, passkey: label, with: how, ended, secondFactorOff, address: ip });
      return still ? json(200, { ok: true, secondFactorOff }) : gone(json);
    },

    // Adds an LXMF alert address. Body {address}, with the step-up of a new second step (confirmBoth: the password,
    // and the second factor when one is on): it is sent a code, and kept (not confirmed) only once the bridge took
    // the message; a refusal changes nothing and is told plainly. A user has up to MAX_LXMF_ADDRESSES. The user's
    // other confirmed addresses are told that it was added. An address that is waiting for its code gets a new one,
    // as a resend does (the recent password).
    async '/api/account/lxmf/set'({ json, body, name, ip, cur, alive }) {
      const address = namedAddress(body);
      if (address === null) return json(400, BAD_ADDRESS);
      const mine = store.lxmfOf(name)?.addresses.find((e) => e.address === address);
      if (mine?.confirmed) return json(409, { error: 'That address is set and confirmed already.', field: 'address' });
      if (!mine && (store.lxmfOf(name)?.addresses.length ?? 0) >= MAX_LXMF_ADDRESSES) return json(409, { error: LXMF_FULL, field: 'address' });
      let how = null;
      if (!mine) {
        if (addingCount(name, address) + (store.lxmfOf(name)?.addresses.length ?? 0) >= MAX_LXMF_ADDRESSES) return json(409, { error: LXMF_FULL, field: 'address' });
        how = await confirmBoth(json, body, name, ip, cur);
        if (!how) return;
      }
      if (!alive()) return gone(json);
      // The step-up took time: look again, and hold a place until the address is saved.
      const now = store.lxmfOf(name)?.addresses.find((e) => e.address === address);
      if (now?.confirmed) return json(409, { error: 'That address is set and confirmed already.', field: 'address' });
      if (!mine && !now) {
        if (addingCount(name, address) + (store.lxmfOf(name)?.addresses.length ?? 0) >= MAX_LXMF_ADDRESSES) return json(409, { error: LXMF_FULL, field: 'address' });
        if ((adding.get(name.toLowerCase()) ?? new Set()).has(address)) return json(409, { error: 'That address is being added already.', field: 'address' });
        const release = reserve(name, address);
        try {
          return await startConfirm({ json, name, alive, address, action: 'lxmf-address-set', how, adding: true });
        } finally {
          release();
        }
      }
      return startConfirm({ json, name, alive, address, action: now ? 'lxmf-code-sent' : 'lxmf-address-set', how, adding: false });
    },

    // Body {address}: sends the code again to an address that is not confirmed yet.
    async '/api/account/lxmf/resend'({ json, body, name, alive }) {
      const address = namedAddress(body);
      if (address === null) return json(400, BAD_ADDRESS);
      const mine = store.lxmfOf(name)?.addresses.find((e) => e.address === address);
      if (!mine) return json(409, { error: 'You do not have that LXMF address. Add it first.', field: 'address' });
      if (mine.confirmed) return json(409, { error: 'That address is confirmed already.', field: 'address' });
      if (!alive()) return gone(json);
      return startConfirm({ json, name, alive, address, action: 'lxmf-code-sent' });
    },

    // Body {address, lxmfCode} with the step-up (confirmBoth): the 6 digits that were sent to that address. (The
    // field is not "code": that one is the second factor's.)
    async '/api/account/lxmf/confirm'({ json, body, name, ip, cur, alive }) {
      const address = namedAddress(body);
      if (address === null) return json(400, BAD_ADDRESS);
      const mine = store.lxmfOf(name)?.addresses.find((e) => e.address === address);
      if (!mine) return json(409, { error: 'You do not have that LXMF address. Add it first.', field: 'address' });
      if (mine.confirmed) return json(409, { error: 'That address is confirmed already.', field: 'address' });
      const code = field(body, 'lxmfCode', 32).replace(/\s+/g, '');
      if (!/^[0-9]{6}$/.test(code)) return json(400, { error: 'Enter the 6 digits that were sent to your LXMF address.', field: 'lxmfCode' });
      // A mistyped code is refused before the second step is spent on it (a peek uses no try); the code is used up
      // only after the step-up.
      const peek = lxmf.peekCode(name, address, code);
      const why = {
        none: 'No code is waiting. Send a new code.',
        expired: 'That code has run out. Send a new code.',
        ended: 'That code has ended. Send a new code.',
        wrong: () => 'That code is not right. Check the digits, or send a new code.',
      };
      const refuse = (r) => json(400, { error: r.reason === 'wrong' ? why.wrong() : (why[r.reason] ?? 'That code is not right.'), field: 'lxmfCode', reason: r.reason });
      if (!peek.ok) return refuse(peek);
      const how = await confirmBoth(json, body, name, ip, cur);
      if (!how) return;
      if (!alive()) return gone(json);
      const r = lxmf.checkCode(name, address, code);
      if (r.ok) {
        try {
          await store.confirmLxmf(name, r.address, { guard: alive });
        } catch (err) {
          // The address was removed meanwhile.
          if (err instanceof UserError && err.code === 'unknown') return json(409, { error: 'Your LXMF addresses changed meanwhile. Reload the page.' });
          throw err;
        }
        await audit.write('lxmf-address-confirmed', { user: name, lxmf: lxmfPrefix(r.address), with: how, address: ip });
        return alive() ? json(200, { ok: true }) : gone(json);
      }
      return refuse(r);
    },

    // Body {address} with the step-up (confirmBoth): takes that address away, confirmed or not. A confirmed one is
    // told to the others and to itself.
    async '/api/account/lxmf/remove'({ json, body, name, ip, cur, alive }) {
      const address = namedAddress(body);
      if (address === null) return json(400, BAD_ADDRESS);
      if (!store.lxmfOf(name)?.addresses.some((e) => e.address === address)) return json(409, { error: 'You do not have that LXMF address.', field: 'address' });
      const how = await confirmBoth(json, body, name, ip, cur);
      if (!how) return;
      const old = store.lxmfOf(name)?.addresses.find((e) => e.address === address);
      if (!old) return json(409, { error: 'You do not have that LXMF address.', field: 'address' });
      if (!alive()) return gone(json);
      await store.clearLxmf(name, address, { guard: alive });
      lxmf.forget(name, address);
      if (old.confirmed) lxmf.notifyAddressChange(name, address, 'removed');
      await audit.write('lxmf-address-removed', { user: name, lxmf: lxmfPrefix(address), with: how, address: ip });
      return alive() ? json(200, { ok: true }) : gone(json);
    },

    // Body {enabled: true or false}: the node alerts at the user's confirmed addresses too. Admins and managers
    // only, with a confirmed address.
    async '/api/account/lxmf/node-alerts'({ json, body, name, user, alive }) {
      if (typeof body.enabled !== 'boolean') return json(400, { error: 'Say whether to turn it on or off.' });
      if (user.role !== 'admin' && user.role !== 'manage') return json(403, { error: 'Only admins and managers can get node alerts.' });
      const confirmed = (store.lxmfOf(name)?.addresses ?? []).filter((e) => e.confirmed);
      if (confirmed.length === 0) return json(409, { error: 'Confirm an LXMF address first.' });
      if (!alive()) return gone(json);
      await store.setLxmfNodeAlerts(name, body.enabled, { guard: alive });
      await audit.write('lxmf-node-alerts', { user: name, enabled: body.enabled, lxmf: confirmed.map((e) => lxmfPrefix(e.address)).join(',') });
      return alive() ? json(200, { ok: true }) : gone(json);
    },

    // A test alert to every confirmed address of the user. Needs only the recent password (no step-up): it changes
    // nothing. It has its own small limits (lxmf-alerts.js sendTest), not those of the changes. The answer says, for
    // each address, whether the message was handed to the bridge's sending (not that it arrived) or held back.
    async '/api/account/lxmf/test'({ json, name, ip, alive }) {
      if (!alive()) return gone(json);
      const r = lxmf.sendTest(name, { siteUrl });
      if (!r.ok) {
        const { status, ...answer } = r;
        return json(status, answer, answer.retryAfter > 0 ? { 'Retry-After': String(answer.retryAfter) } : {});
      }
      const queued = r.results.filter((x) => x.queued).length;
      await audit.write('lxmf-test-sent', { user: name, count: queued, address: ip });
      return alive() ? json(200, { ok: true, queued, held: r.results.length - queued, results: r.results }) : gone(json);
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
    // Without a bridge that takes users' own addresses the feature does not exist.
    if (pathname.startsWith('/api/account/lxmf/') && !lxmf) return json(404, { error: 'Not found' });
    const body = await readJsonChange(req, json, 'Send this from the account page.');
    if (body === null) return;
    const cur = auth.session(req);
    if (!cur) return json(401, { error: 'Sign in first.', signIn: true });
    if (cur.user.mustChangePassword && !BEFORE_NEW_PASSWORD.has(pathname)) return json(403, CHANGE_PASSWORD_FIRST);
    const s = cur.session;
    const name = cur.user.name;
    // Asking for the password again is the one thing that needs no recent sign in.
    if (pathname !== '/api/account/reauth' && !recent(s)) return json(403, { error: 'Enter your password again to do this.', reauth: true });
    const limits = budgets(pathname, s.via);
    if (limits) {
      // A session made with a passkey alone has its own budget per user: whoever holds a stolen
      // passkey cannot use up the tries of the owner's password sessions.
      const who = s.via === 'passkey' ? 'passkey-user' : 'user';
      const keys = [[limits[0], `${pathname}|session:${cur.id}`], [limits[1], `${pathname}|${who}:${name.toLowerCase()}`]];
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
      const refusal = writeRefusal(err);
      if (refusal) return json(500, { error: refusal });
      log(`account change failed: ${err?.message ?? err}`);
      return json(500, { error: 'The change could not be saved, so nothing was changed. Try again later.' });
    }
  }

  return { get, post };
}
