// The users API behind the /users page, for admins only: list every user, make a website user,
// change a role, reset a password or a second factor, and delete a user.
//
// The server is the only authority: the page is served to admins only, and every request here
// checks again that its session is an admin's. When there is no admin at all (neither in the
// config file nor in users.json) the page and this API do not exist (404); an admin is made in the
// config file (role: admin), never here.
//
// Every change is a POST of JSON from the page itself (the request header, same origin, JSON, as
// for the account API), needs a sign in from the last 15 minutes, AND the admin's password in the
// request itself, with a current code from their app (or a recovery code) as well when their
// two-step sign-in is on (step-up, see confirmBoth in account.js). Changes are limited per admin per
// hour, wrong passwords and codes included. After every await the admin's session must still be
// there and still an admin's, and the store asks the same right before it writes (guard); when it
// is gone, nothing is changed and the answer is 401.
//
// Users in the config file are read-only here: only their second factor can be reset. The last
// admin can never be deleted or given another role, also not by themselves.
//
// A password an admin sets (typed, or made here and shown once) must be changed by the user at
// their next sign in: until then their session only reaches the password change and sign out.
// Every change ends the user's sessions, open second steps and known devices (auth.endUser), and
// is an audit line with the admin (actor) and the user, never a password or code.
//
// One admin must not be able to take over another: the password of an admin is only ever reset to
// a one-time password made here (never one the acting admin typed), and resetting the password or
// the second factor of an admin is the audit event admin-reset-admin (actor, target, what), so it
// stands out from the changes made to other users.
import crypto from 'node:crypto';
import { MAX_PASSWORD_BYTES, weakPassword } from './password.js';
import { Busy, clientIp, waitText } from './login.js';
import { ROLES, USER_NAME_RE, UserError, writeRefusal } from './users.js';
import { Budget, CHANGE_PASSWORD_FIRST, GONE, RECENT_AUTH_MS, createStepUp, field, readJsonChange, recentSignIn } from './account.js';

export const USERS_PATHS = ['/api/users/create', '/api/users/role', '/api/users/delete', '/api/users/reset-password', '/api/users/reset-second-factor'];
// Changes one admin may make in an hour, wrong passwords and codes included.
export const USER_CHANGES_PER_ADMIN = 30;
// A one-time password: 20 letters and digits without look-alikes (about 100 bits), in groups of four.
const OTP_ALPHABET = 'abcdefghjkmnpqrstuvwxyz23456789';
const OTP_CHARS = 20;

export function newOneTimePassword() {
  for (;;) {
    let out = '';
    // Rejection sampling, so every character is as likely as any other.
    while (out.length < OTP_CHARS) {
      for (const b of crypto.randomBytes(32)) {
        if (b < 248 && out.length < OTP_CHARS) out += OTP_ALPHABET[b % OTP_ALPHABET.length];
      }
    }
    const text = out.match(/.{4}/g).join('-');
    if (weakPassword(text) === null) return text;
  }
}

// The messages for what the store refuses.
const REFUSED = {
  'last-admin': [409, 'This is the last admin. Make another user an admin first.'],
  config: [409, 'This user is managed in the config file. Change them there.'],
  unknown: [404, 'There is no such user. Reload the page.'],
  exists: [409, 'A user with this name exists already.'],
  'bad-name': [400, 'A name is 1 to 32 letters, digits, dots, dashes or underscores, starting with a letter or digit.'],
  'bad-role': [400, `The role must be one of ${ROLES.join(', ')}.`],
  full: [409, 'The user store is full. Delete users that are not needed any more.'],
  'admin-password': [400, 'The password of an admin can only be reset to a one-time password made here.'],
};

// auth: what createLogin gives.
export function createUsersApi({ auth, now = Date.now, log = console.error }) {
  const store = auth.store;
  const audit = auth.audit;
  const perAdmin = new Budget({ limit: USER_CHANGES_PER_ADMIN, now });
  const { confirmBoth } = createStepUp(auth);
  const gone = (json) => json(401, GONE);
  const refuse = (json, code) => {
    const [status, error] = REFUSED[code] ?? [409, 'That cannot be done right now. Reload the page and try again.'];
    return json(status, { error, code });
  };

  // Whether the users page exists at all: only while someone is an admin.
  const exists = () => store.admins() > 0;

  // The admin session of a request: {cur} for an admin; {status, body} otherwise.
  function admin(req) {
    if (!exists()) return { status: 404, body: { error: 'Not found' } };
    const cur = auth.session(req);
    if (!cur) return { status: 401, body: { error: 'Sign in first.', signIn: true } };
    if (cur.user.role !== 'admin') return { status: 403, body: { error: 'Only admins can manage users.' } };
    if (cur.user.mustChangePassword) return { status: 403, body: CHANGE_PASSWORD_FIRST };
    return { cur };
  }

  // Whether the page may be served to this request: to an admin only.
  const pageAllowed = (req) => Boolean(admin(req).cur);

  // GET /api/users
  function get(req, json) {
    const a = admin(req);
    if (!a.cur) return json(a.status, a.body);
    const s = a.cur.session;
    const recent = recentSignIn(s, now());
    return json(200, {
      me: a.cur.user.name,
      // Whether the step-up dialog asks this admin for a code too.
      secondFactor: store.secondFactorEnabled(a.cur.user.name),
      roles: ROLES,
      recentSignIn: recent,
      recentUntil: recent ? new Date(s.authAt + RECENT_AUTH_MS).toISOString() : null,
      users: store.overview(),
    });
  }

  // The new password of a body: the one typed (newPassword), or a new one-time password (generate:
  // true). Gives {password, generated} or {error}.
  function newPassword(body, name) {
    if (body.generate === true) return { password: newOneTimePassword(), generated: true };
    const typed = field(body, 'newPassword', 4096);
    if (Buffer.byteLength(typed) > MAX_PASSWORD_BYTES) return { error: `The password must be at most ${MAX_PASSWORD_BYTES} bytes.` };
    const weak = weakPassword(typed, name);
    if (weak) return { error: weak.replace('your name', 'the name') };
    return { password: typed, generated: false };
  }

  // A user that is in the list, by the name the page sent; the answer is sent when there is none.
  function target(json, body) {
    const name = field(body, 'name', 64);
    const user = name ? store.lookup(name) : null;
    if (!user) {
      refuse(json, 'unknown');
      return null;
    }
    return user;
  }

  // Each change has two parts: check(), which only reads (the body, the store) and answers what is
  // wrong before any password is asked for, and run(), after the step-up. Both get ctx.
  const actions = {
    '/api/users/create': {
      check({ json, body }) {
        const name = field(body, 'name', 64).trim();
        if (!USER_NAME_RE.test(name)) return refuse(json, 'bad-name');
        const role = field(body, 'role', 16);
        if (!ROLES.includes(role)) return refuse(json, 'bad-role');
        if (store.lookup(name)) return refuse(json, 'exists');
        const pw = newPassword(body, name);
        if (pw.error) return json(400, { error: pw.error, field: 'newPassword' });
        return { name, role, pw };
      },
      async run({ json, cur, alive, actor, ip, how }, { name, role, pw }) {
        const phc = await hash(json, pw.password, cur);
        if (!phc) return;
        if (!alive()) return gone(json);
        await store.createUser({ name, role, passwordHash: phc, mustChangePassword: true }, { guard: alive });
        // Nothing should be there for a new name; this also ends anything a removed user of the same
        // name might still have had under way.
        auth.endUser(name);
        await audit.write('user-created', { actor, user: name, role, password: pw.generated ? 'generated' : 'typed', with: how, address: ip });
        if (!alive()) return gone(json);
        return json(200, pw.generated ? { ok: true, name, oneTimePassword: pw.password } : { ok: true, name });
      },
    },

    '/api/users/role': {
      check({ json, body }) {
        const user = target(json, body);
        if (!user) return;
        if (user.source === 'config') return refuse(json, 'config');
        const role = field(body, 'role', 16);
        if (!ROLES.includes(role)) return refuse(json, 'bad-role');
        if (role === user.role) return json(409, { error: `${user.name} is ${role} already.` });
        if (store.wouldLeaveNoAdmin(user.name, role)) return refuse(json, 'last-admin');
        return { user, role };
      },
      async run({ json, alive, actor, ip, how }, { user, role }) {
        // The role right before the change: another change may have been made since check().
        const from = await store.setRole(user.name, role, { guard: alive });
        const self = user.name.toLowerCase() === actor.toLowerCase();
        // The user signs in again with the new role; an admin who gave themselves another role too.
        const ended = auth.endUser(user.name);
        await audit.write('user-role-changed', { actor, user: user.name, from, to: role, ended, with: how, address: ip });
        if (self) return json(200, { ok: true, signedOut: true });
        return alive() ? json(200, { ok: true }) : gone(json);
      },
    },

    '/api/users/delete': {
      check({ json, body }) {
        const user = target(json, body);
        if (!user) return;
        if (user.source === 'config') return refuse(json, 'config');
        if (store.wouldLeaveNoAdmin(user.name)) return refuse(json, 'last-admin');
        return { user };
      },
      async run({ json, alive, actor, ip, how }, { user }) {
        await store.deleteUser(user.name, { guard: alive });
        const self = user.name.toLowerCase() === actor.toLowerCase();
        const ended = auth.endUser(user.name);
        await audit.write('user-deleted', { actor, user: user.name, role: user.role, ended, with: how, address: ip });
        if (self) return json(200, { ok: true, signedOut: true });
        return alive() ? json(200, { ok: true }) : gone(json);
      },
    },

    '/api/users/reset-password': {
      check({ json, body, actor }) {
        const user = target(json, body);
        if (!user) return;
        if (user.source === 'config') return refuse(json, 'config');
        if (user.name.toLowerCase() === actor.toLowerCase()) return json(409, { error: 'Change your own password on your account page.' });
        // A password the acting admin knows would let them sign in as the other admin.
        if (user.role === 'admin' && body.generate !== true) return json(400, { error: REFUSED['admin-password'][1], field: 'newPassword' });
        const pw = newPassword(body, user.name);
        if (pw.error) return json(400, { error: pw.error, field: 'newPassword' });
        return { user, pw };
      },
      async run({ json, cur, alive, actor, ip, how }, { user, pw }) {
        const phc = await hash(json, pw.password, cur);
        if (!phc) return;
        if (!alive()) return gone(json);
        // The user may have been made an admin since check(): the store asks again.
        await store.setPassword(user.name, phc, { guard: alive, mustChangePassword: true, typedForAdmin: !pw.generated });
        const ended = auth.endUser(user.name);
        if (store.lookup(user.name)?.role === 'admin') await audit.write('admin-reset-admin', { actor, target: user.name, what: 'password', ended, with: how, address: ip });
        else await audit.write('user-password-reset', { actor, user: user.name, password: pw.generated ? 'generated' : 'typed', ended, with: how, address: ip });
        if (!alive()) return gone(json);
        return json(200, pw.generated ? { ok: true, oneTimePassword: pw.password } : { ok: true });
      },
    },

    '/api/users/reset-second-factor': {
      check({ json, body, actor }) {
        const user = target(json, body);
        if (!user) return;
        if (user.name.toLowerCase() === actor.toLowerCase()) return json(409, { error: 'Turn your own two-step sign-in off on your account page.' });
        return { user };
      },
      async run({ json, alive, actor, ip, how }, { user }) {
        await store.resetSecondFactor(user.name, { guard: alive });
        // Ends their sessions and second steps, and forgets every known device of theirs.
        const ended = auth.endUser(user.name);
        if (store.lookup(user.name)?.role === 'admin') await audit.write('admin-reset-admin', { actor, target: user.name, what: 'second-factor', ended, with: how, address: ip });
        else await audit.write('user-second-factor-reset', { actor, user: user.name, ended, with: how, address: ip });
        return alive() ? json(200, { ok: true }) : gone(json);
      },
    },
  };

  // A new password hash, in the lane of the admin's session. null once it has answered.
  async function hash(json, password, cur) {
    try {
      return await auth.hash(password, { session: cur.id });
    } catch (err) {
      if (err instanceof Busy) {
        json(503, { error: 'Too many sign ins at once. Try again in a moment.' }, { 'Retry-After': '2' });
        return null;
      }
      throw err;
    }
  }

  // POST /api/users/...
  async function post(req, pathname, json) {
    if (!Object.hasOwn(actions, pathname)) return json(404, { error: 'Not found' });
    const body = await readJsonChange(req, json, 'Send this from the users page.');
    if (body === null) return;
    const a = admin(req);
    if (!a.cur) return json(a.status, a.body);
    const cur = a.cur;
    const actor = cur.user.name;
    if (!recentSignIn(cur.session, now())) return json(403, { error: 'Enter your password again to do this.', reauth: true });
    const ip = clientIp(req, auth.trusted);
    // The admin's session is still there, and still an admin's (a removed or demoted admin's
    // sessions end, but the role is asked again all the same).
    const alive = () => auth.sessions.map.has(cur.id) && store.lookup(actor)?.role === 'admin';
    const ctx = { json, body, cur, actor, ip, alive };
    const action = actions[pathname];
    let answered = false;
    const checked = action.check({
      ...ctx,
      json: (...args) => {
        answered = true;
        return json(...args);
      },
    });
    // check() has answered: something is wrong, and nothing was asked for or counted.
    if (answered) return;
    const key = `user:${actor.toLowerCase()}`;
    const wait = perAdmin.wait(key);
    if (wait > 0) {
      const sec = Math.ceil(wait / 1000);
      return json(429, { error: `You did this too often. Try again in ${waitText(wait)}.`, retryAfter: sec }, { 'Retry-After': String(sec) });
    }
    perAdmin.take(key);
    // Too many password hashes at once (503, the admin's own requests in parallel, say) checked no
    // password and changed nothing: that try is given back.
    const answer = (status, ...rest) => {
      if (status === 503) perAdmin.giveBack(key);
      return json(status, ...rest);
    };
    try {
      const how = await confirmBoth(answer, body, actor, ip, cur);
      if (!how) return;
      if (!alive()) return gone(json);
      return await action.run({ ...ctx, json: answer, how }, checked);
    } catch (err) {
      // Every change is written before it is made: when the write fails, nothing changed.
      if (err instanceof UserError && err.code === 'gone') return gone(json);
      if (err instanceof UserError) return refuse(json, err.code);
      const refusal = writeRefusal(err);
      if (refusal) return json(500, { error: refusal });
      log(`user change failed: ${err?.message ?? err}`);
      return json(500, { error: 'The change could not be saved, so nothing was changed. Try again later.' });
    }
  }

  return { get, post, exists, pageAllowed };
}
