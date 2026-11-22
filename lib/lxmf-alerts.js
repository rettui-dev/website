// Alerts to a user's own LXMF addresses. A webhook channel with user_addresses: true is an LXMF bridge
// (bridges/lxmf) that takes the address of a message from the website: the signed JSON body has an optional
// "to". A user adds up to three addresses on the account page; each counts only once they have typed back the
// code the website sent to that address. Then three kinds of message go to every confirmed address:
//   - alerts about the user's own account (a passkey added or removed, the password changed or reset, two-step
//     sign-in turned off or reset, new recovery codes, an address added or removed, the password used from a
//     browser that is not a known device). They hold what happened, when and, for an admin's action, which
//     admin: never a credential id, a secret, a device id or an IP address. An
//     address added or removed is told to every other confirmed address (and to the removed one), so that
//     whoever gets into the account cannot add their own or take the owner's away without the owner hearing;
//   - for admins and managers who ticked it, the node alerts the channels get (the Alerter hands them over);
//   - the code that confirms an address (to that address only).
//
// Nothing here fails or delays what the user did: a message is only queued, tried up to MAX_ATTEMPTS times
// in the background, and a failure is logged with the first 8 digits of the address at most. The website
// keeps under the bridge's own limits (per address an hour, and different addresses an hour), so a bug or a
// flood of events here cannot make the bridge refuse, or send a flood to the network: past a limit a message
// is dropped and logged. Each try counts, a retry too. The limits are in memory, so a restart starts them
// over, as the bridge's do; a bridge that answers 429 with Retry-After is left alone until then.
//
// The per-address budget (per_address_per_hour, P, at least 6) is split so that alerts about an account are
// never crowded out, whoever asks for codes to the address or however many node alerts there are: the codes
// get MAX_CODES_PER_ADDRESS (3, and at most P - 4) an hour for the address across all users, codes and node
// alerts together get P - 3, and the account alerts may use all of P, so at least 3 an hour are theirs.
// A code asked for an address that another user has confirmed is answered as if it was sent, and counts against
// the same limits as a real send, but is not posted.
//
// The budget of different addresses an hour (addresses_per_hour, A, at least 10) is split the same way: codes
// may take new addresses only up to half of A (rounded down), codes and node alerts together up to A minus a
// reserve (ADDRESS_RESERVE, 5), and the account alerts may use all of A, so at least 5 new addresses an hour
// are theirs, however many users ask for codes to different addresses.
//
// The confirm code: 6 digits from the system's random source, one for each address a user is confirming, kept
// in memory only as an HMAC under a key made at start, valid CODE_TTL_MS, ended by CODE_TRIES wrong tries (checkCode; the account API looks first with peekCode, which counts none, and bounds guessing with the limits of the confirm route), at
// most CODES_PER_USER an hour for a user (all their addresses together) and CODES_PER_HOUR for everyone. It is compared in constant time and is never logged, audited or sent to the
// page. The page learns only what the bridge answered.
import crypto from 'node:crypto';
import { eventName, signHeaders } from './alerts.js';

export const CODE_TTL_MS = 15 * 60_000;
export const CODE_TRIES = 5;
export const CODES_PER_USER = 3;
export const CODES_PER_HOUR = 30;
// The most codes an address gets an hour, from all users together.
export const CODES_PER_ADDRESS = 3;
// The smallest per-address budget that can be split between codes, node alerts and account alerts.
export const MIN_PER_ADDRESS_PER_HOUR = 6;
// The smallest number of different addresses an hour, and how many of them are kept for account alerts.
export const MIN_ADDRESSES_PER_HOUR = 10;
export const ADDRESS_RESERVE = 5;
export const WINDOW_MS = 60 * 60_000;
// A user gets one alert about a password used from a new browser in this long, however many tries there are.
export const NEW_DEVICE_ALERT_MS = 15 * 60_000;
export const SEND_TIMEOUT_MS = 10_000;
export const MAX_ATTEMPTS = 3;
export const RETRY_DELAYS_MS = [5000, 30_000];
// Messages being sent at once, tries waiting included; past that a message is dropped.
export const MAX_IN_FLIGHT = 200;
// Users with a code waiting; past that the oldest is forgotten.
const MAX_PENDING = 1000;
const MAX_ADDRESSES = 5000;

// An LXMF address as typed: 32 hex digits, in angle brackets or not, in any case. Gives it as lower-case hex,
// or null.
export function normaliseLxmfAddress(text) {
  if (typeof text !== 'string' || text.length > 80) return null;
  let t = text.trim();
  if (t.startsWith('<') && t.endsWith('>')) t = t.slice(1, -1).trim();
  return /^[0-9a-f]{32}$/i.test(t) ? t.toLowerCase() : null;
}

// The first 8 digits of an address: all that logs and the audit log hold of it.
export const lxmfPrefix = (address) => String(address).slice(0, 8);

const key = (name) => String(name).trim().toLowerCase();
const when = (t) => {
  const iso = new Date(t).toISOString();
  return `${iso.slice(0, 10)} ${iso.slice(11, 16)} UTC`;
};
const waitText = (ms) => {
  const s = Math.max(1, Math.ceil(ms / 1000));
  if (s < 90) return `${s} ${s === 1 ? 'second' : 'seconds'}`;
  const m = Math.ceil(s / 60);
  if (m < 90) return `${m} minutes`;
  const h = Math.ceil(m / 60);
  return `${h} ${h === 1 ? 'hour' : 'hours'}`;
};

// At most `limit` uses per key in any windowMs; at most maxKeys keys are kept (the one used least recently goes).
class Window {
  constructor({ limit, now, windowMs = WINDOW_MS, maxKeys = 10_000 }) {
    Object.assign(this, { limit, now, windowMs, maxKeys });
    this.map = new Map();
  }

  recent(k) {
    const t = this.now();
    return (this.map.get(k) ?? []).filter((at) => t - at < this.windowMs && at <= t);
  }

  // Milliseconds until the key may be used again; 0 when it may now.
  wait(k) {
    const list = this.recent(k);
    return list.length < this.limit ? 0 : list[0] + this.windowMs - this.now();
  }

  take(k) {
    const list = this.recent(k);
    list.push(this.now());
    this.map.delete(k);
    while (this.map.size >= this.maxKeys) this.map.delete(this.map.keys().next().value);
    this.map.set(k, list);
  }

  // Gives back the latest use of a key (a message the bridge refused, which it counted for nothing).
  giveBack(k) {
    const list = this.map.get(k);
    if (list && list.length > 0) list.pop();
  }
}

// What the page is told for each way the bridge can refuse a message, by the bridge's status (see "Addresses
// the website names" in bridges/lxmf/README.md). status is what the account API answers with. retry: whether
// sending again later may work; refused: the bridge counted nothing for it, so the website's own count is
// given back.
function refusal(status, retryAfter) {
  const wait = retryAfter > 0 ? ` Try again in ${waitText(retryAfter * 1000)}.` : ' Try again later.';
  if (status === 403) return { code: 'bridge-off', status: 502, retry: false, refused: true, error: 'The alert bridge has addresses named by the website turned off, so it cannot send to your address. Ask whoever runs this site to turn on website_recipients in the bridge.' };
  if (status === 400) return { code: 'bridge-address', status: 400, retry: false, refused: true, field: 'address', error: 'The alert bridge does not accept that address. Check that it is 32 hex digits.' };
  if (status === 422) return { code: 'bridge-own-address', status: 400, retry: false, refused: true, field: 'address', error: "That is the alert bridge's own address, which cannot get alerts. Use the address of your own LXMF app." };
  if (status === 429) return { code: 'bridge-limit', status: 429, retry: false, refused: true, retryAfter, error: `The alert bridge has sent the most messages it allows to this address for now.${wait}` };
  if (status === 503) {
    const after = retryAfter > 0 ? retryAfter : 60;
    return { code: 'bridge-busy', status: 503, retry: true, refused: true, retryAfter: after, error: `The alert bridge is busy with other messages. Try again in ${waitText(after * 1000)}.` };
  }
  if (status === 401) return { code: 'bridge-secret', status: 502, retry: false, refused: false, error: "The alert bridge did not accept the website's signature. Ask whoever runs this site to check that the website and the bridge have the same secret." };
  return { code: 'bridge-refused', status: 502, retry: status >= 500, refused: status >= 400 && status < 500, error: `The alert bridge refused the message (it answered ${status}). Ask whoever runs this site to look at the bridge's log.` };
}

const UNREACHABLE = { code: 'bridge-unreachable', status: 502, retry: true, refused: false, error: 'The alert bridge could not be reached. Try again later, and tell whoever runs this site if it stays so.' };

// The plain words of an alert about a user's own account. d: what the kind needs ({passkey, secondFactorOff,
// removedPasskeys, passkeys, actor, what}).
export function accountMessage(kind, name, d, at, issuer) {
  const t = when(at);
  const head = `[${issuer}]`;
  const label = (l) => JSON.stringify(String(l).slice(0, 64));
  const count = (n) => `${n} ${n === 1 ? 'passkey was' : 'passkeys were'} removed with it.`;
  switch (kind) {
    case 'passkey_added':
      return `${head} A passkey named ${label(d.passkey)} was added to your account ${name} at ${t}. If this was not you, change your password and remove the passkey.`;
    case 'passkey_removed':
      return `${head} A passkey named ${label(d.passkey)} was removed from your account ${name} at ${t}.${d.secondFactorOff ? ' It was your last second step, so two-step sign-in is now off.' : ''} If this was not you, change your password.`;
    case 'password_changed':
      return `${head} The password of your account ${name} was changed at ${t}.${Number.isInteger(d.removedPasskeys) && d.removedPasskeys > 0 ? ` ${count(d.removedPasskeys)}` : ''} If this was not you, tell whoever runs the site at once.`;
    case 'password_reset':
      return `${head} The admin ${d.actor} reset the password of your account ${name} at ${t}.${Number.isInteger(d.removedPasskeys) && d.removedPasskeys > 0 ? ` ${count(d.removedPasskeys)}` : ''} You choose a new one when you next sign in.`;
    case 'second_factor_off':
      return `${head} The app code of your account ${name} was turned off at ${t}. ${d.secondFactorOff ? 'Two-step sign-in is now off.' : 'Your passkeys still work as your second step.'} If this was not you, change your password.`;
    case 'second_factor_reset':
      return `${head} The admin ${d.actor} reset the two-step sign-in of your account ${name} at ${t}. Your app code, passkeys and recovery codes were removed.`;
    case 'recovery_codes_new':
      return `${head} New recovery codes were made for your account ${name} at ${t}. The old ones no longer work. If this was not you, change your password.`;
    case 'sign_in_new_device': {
      const site = typeof d.siteUrl === 'string' && d.siteUrl !== '' ? ` to ${d.siteUrl.slice(0, 200)}` : '';
      return `${head} The password of your account ${name} was just used to sign in${site} from a new browser at ${t}. If this was not you, change your password.`;
    }
    case 'lxmf_address_changed': {
      const which = `The LXMF address starting ${lxmfPrefix(d.address)}`;
      return d.what === 'removed'
        ? `${head} ${which} was removed from the alerts of your account ${name} at ${t}. It gets no more alerts. If this was not you, change your password.`
        : `${head} ${which} was added to the alerts of your account ${name} at ${t}. It gets alerts once the code sent to it is typed in. If this was not you, change your password.`;
    }
    default:
      throw new Error('unknown alert kind');
  }
}

const codeMessage = (code, issuer) => `[${issuer}] Your code to confirm this address is ${code}. It works for ${CODE_TTL_MS / 60_000} minutes. If you did not ask for it, ignore this message.`;

// channel: {url, secret, perAddressPerHour, addressesPerHour} (from the config). store: the user store.
// fetchFn, sleep and randomCode are for tests.
export function createLxmfAlerts(options) {
  return new LxmfAlerts(options);
}

export class LxmfAlerts {
  // The URL and the secret of the channel: private, so no dump or JSON of this object shows them.
  #url;
  #secret;
  // The key the codes are kept under, made at start.
  #codeKey = crypto.randomBytes(32);
  // By user key and address: {address, digest, expires, tries}.
  #pending = new Map();
  #inFlight = 0;
  #stopped = false;
  #idle = [];

  constructor({
    channel,
    store,
    issuer = 'rettui status',
    now = Date.now,
    fetchFn = fetch,
    sleep = (ms) => new Promise((r) => setTimeout(r, ms).unref()),
    log = console.error,
    timeoutMs = SEND_TIMEOUT_MS,
    retryDelays = RETRY_DELAYS_MS,
    randomCode = () => String(crypto.randomInt(0, 1_000_000)).padStart(6, '0'),
  }) {
    this.#url = channel.url;
    this.#secret = channel.secret;
    Object.assign(this, { store, issuer, now, fetchFn, sleep, log, timeoutMs, retryDelays, randomCode });
    const budget = channel.perAddressPerHour ?? 10;
    if (!Number.isInteger(budget) || budget < MIN_PER_ADDRESS_PER_HOUR) throw new Error(`per_address_per_hour must be a whole number of at least ${MIN_PER_ADDRESS_PER_HOUR}`);
    this.perAddress = new Window({ limit: budget, maxKeys: MAX_ADDRESSES, now });
    // Codes alone (3 an hour, 2 at least left to the account alerts), and codes with node alerts (3 left to them).
    this.codesAddress = new Window({ limit: Math.min(CODES_PER_ADDRESS, budget - 4), maxKeys: MAX_ADDRESSES, now });
    this.bulkAddress = new Window({ limit: budget - 3, maxKeys: MAX_ADDRESSES, now });
    // Addresses a bridge told us to leave alone: address to the time (ms) it may be sent to again.
    this.blocked = new Map();
    this.addressesPerHour = channel.addressesPerHour ?? 50;
    if (!Number.isInteger(this.addressesPerHour) || this.addressesPerHour < MIN_ADDRESSES_PER_HOUR) throw new Error(`addresses_per_hour must be a whole number of at least ${MIN_ADDRESSES_PER_HOUR}`);
    this.codesPerUser = new Window({ limit: CODES_PER_USER, now });
    this.codesAll = new Window({ limit: CODES_PER_HOUR, now, maxKeys: 2 });
    // Alerts about a password used from a new browser: one a user in NEW_DEVICE_ALERT_MS.
    this.newDevice = new Window({ limit: 1, now, windowMs: NEW_DEVICE_ALERT_MS });
  }

  normalise(text) {
    return normaliseLxmfAddress(text);
  }

  // ---- the limits ----

  // Milliseconds until a new address may take a place in a window of addresses: 0 when the address is already
  // in it or there is room. limit: the most different addresses the window may hold for this use.
  #roomWait(win, address, limit) {
    if (win.recent(address).length > 0) return 0;
    let distinct = 0;
    let soonest = Infinity;
    for (const k of win.map.keys()) {
      const list = win.recent(k);
      if (list.length === 0) continue;
      distinct++;
      soonest = Math.min(soonest, list[list.length - 1] + win.windowMs - this.now());
    }
    return distinct >= limit ? Math.max(1, soonest) : 0;
  }

  // Milliseconds until this address may be sent to: 0 when it may now. An address that already had a message
  // in the hour only counts against its own limit; a new one also against the number of different addresses,
  // of which codes may take half and codes with node alerts all but the reserve for account alerts.
  #addressWait(address, cls) {
    const own = this.perAddress.wait(address);
    if (own > 0) return own;
    let w = this.#roomWait(this.perAddress, address, this.addressesPerHour);
    if (cls !== 'account') w = Math.max(w, this.#roomWait(this.bulkAddress, address, this.addressesPerHour - ADDRESS_RESERVE));
    if (cls === 'code') w = Math.max(w, this.#roomWait(this.codesAddress, address, Math.floor(this.addressesPerHour / 2)));
    return w;
  }

  // Milliseconds until a message of this class may go to the address: 0 when it may now. cls: 'account' (only
  // the total counts), 'node' (also the share of codes and node alerts) or 'code' (also the codes' own cap).
  #wait(address, cls) {
    let w = this.#addressWait(address, cls);
    const until = this.blocked.get(address);
    if (until !== undefined) {
      if (until > this.now()) w = Math.max(w, until - this.now());
      else this.blocked.delete(address);
    }
    if (cls !== 'account') w = Math.max(w, this.bulkAddress.wait(address));
    if (cls === 'code') w = Math.max(w, this.codesAddress.wait(address));
    return w;
  }

  #windows(address, cls) {
    return [this.perAddress, ...(cls === 'code' ? [this.codesAddress] : []), ...(cls !== 'account' ? [this.bulkAddress] : [])].map((b) => [b, address]);
  }

  #take(address, cls) {
    for (const [b, kk] of this.#windows(address, cls)) b.take(kk);
  }

  #giveBack(address, cls) {
    for (const [b, kk] of this.#windows(address, cls)) b.giveBack(kk);
  }

  // The bridge said 429 with a time to wait: nothing goes to that address until then.
  #block(address, seconds) {
    this.blocked.delete(address);
    while (this.blocked.size >= MAX_ADDRESSES) this.blocked.delete(this.blocked.keys().next().value);
    this.blocked.set(address, this.now() + seconds * 1000);
  }

  // ---- the confirm code ----

  #digest(code) {
    return crypto.createHmac('sha256', this.#codeKey).update(code).digest();
  }

  // The key of the code a user has for an address.
  #pendingKey(name, address) {
    return `${key(name)}|${address}`;
  }

  // The code waiting for a user's address, {address, expiresAt}, or null (none, or it ran out).
  pendingFor(name, address) {
    const k = this.#pendingKey(name, address);
    const p = this.#pending.get(k);
    if (!p) return null;
    if (p.expires <= this.now()) {
      this.#pending.delete(k);
      return null;
    }
    return { address: p.address, expiresAt: p.expires };
  }

  // Drops the code for one address, or for all of a user's when no address is given.
  forget(name, address = null) {
    if (address !== null) {
      this.#pending.delete(this.#pendingKey(name, address));
      return;
    }
    const start = `${key(name)}|`;
    for (const k of [...this.#pending.keys()]) if (k.startsWith(start)) this.#pending.delete(k);
  }

  // Sends a new code to address, which replaces any code the user had for that address. Gives {ok: true, expiresAt}, or
  // {ok: false, status, code, error, retryAfter?, field?} for the account API to answer with; nothing is kept
  // then, and what the bridge counted for nothing is given back.
  async sendCode(name, address) {
    // An address that another user has confirmed: answered as if the code was sent, with the same limits for
    // the asker, but nothing goes out and nothing is kept or logged that tells the asker (a code nobody has
    // cannot be typed back). Otherwise a user could fill the owner's budget, or find who has which address.
    const elsewhere = this.store.lxmfConfirmedElsewhere(address, name);
    const answer = await this.#sendCode(name, address, elsewhere);
    // A short random wait narrows the timing gap to a real send. A bridge that is slow or hangs still shows:
    // a real send waits for it (up to the timeout) and this case does not.
    if (elsewhere) await Promise.resolve(this.sleep(crypto.randomInt(20, 151))).catch(() => {});
    return answer;
  }

  async #sendCode(name, address, elsewhere) {
    const k = key(name);
    const held = (ms, what) => ({ ok: false, status: 429, code: 'limit', retryAfter: Math.ceil(ms / 1000), error: `${what} Try again in ${waitText(ms)}.` });
    let w = this.codesPerUser.wait(k);
    if (w > 0) return held(w, `You asked for ${CODES_PER_USER} codes in the last hour, the most allowed.`);
    w = this.codesAll.wait('all');
    if (w > 0) return held(w, 'Too many codes were sent from this site in the last hour.');
    w = this.#wait(address, 'code');
    if (w > 0) return held(w, 'That address has had the most messages allowed for now.');
    if (this.#inFlight >= MAX_IN_FLIGHT) return held(WINDOW_MS / 4, 'The site is sending too many messages right now.');
    const code = this.randomCode();
    const pk = this.#pendingKey(name, address);
    const previous = this.#pending.get(pk);
    const expires = this.now() + CODE_TTL_MS;
    this.#pending.delete(pk);
    while (this.#pending.size >= MAX_PENDING) this.#pending.delete(this.#pending.keys().next().value);
    const mine = { address, digest: this.#digest(code), expires, tries: 0 };
    this.#pending.set(pk, mine);
    this.codesPerUser.take(k);
    this.codesAll.take('all');
    this.#take(address, 'code');
    if (elsewhere) return { ok: true, expiresAt: expires };
    this.#inFlight++;
    let r;
    try {
      r = await this.#post(address, 'lxmf_check', codeMessage(code, this.issuer));
    } finally {
      this.#inFlight--;
      this.#settle();
    }
    if (r.ok) return { ok: true, expiresAt: expires };
    // Nothing was sent: the old code, if any, still stands, and a message the bridge refused counts for nothing.
    // Only while the entry is still the one this call made: another call for the same address (a resend)
    // may have replaced it since, and its code is the one that counts then.
    if (this.#pending.get(pk) === mine) {
      this.#pending.delete(pk);
      if (previous && previous.expires > this.now()) this.#pending.set(pk, previous);
    }
    if (r.refused) {
      this.codesPerUser.giveBack(k);
      this.codesAll.giveBack('all');
      this.#giveBack(address, 'code');
    }
    this.log(`lxmf: the confirm code for ${lxmfPrefix(address)} was not sent (${r.error})`);
    const { retry, refused, ...answer } = r;
    return { ok: false, ...answer };
  }

  // Looks at a code without using a try or the code up: {ok: true} when it is the right one, else {ok: false, reason,
  // left} as checkCode gives them (a wrong one costs nothing here). It lets the account API refuse a mistyped code
  // before the second step is spent on it; the code itself is only used up by checkCode, after the step-up. A wrong
  // guess made here is bounded by the limits of the confirm route, not by the tries of the code.
  peekCode(name, address, text) {
    const k = this.#pendingKey(name, address);
    const p = this.#pending.get(k);
    if (!p) return { ok: false, reason: 'none' };
    if (p.expires <= this.now()) {
      this.#pending.delete(k);
      return { ok: false, reason: 'expired' };
    }
    if (!crypto.timingSafeEqual(this.#digest(String(text)), p.digest)) return { ok: false, reason: 'wrong', left: CODE_TRIES - p.tries };
    return { ok: true };
  }

  // Checks a code the user typed (6 digits) for one of their addresses. Gives {ok: true, address} (the code is
  // used up), or {ok: false, reason}: 'none' (no code was sent), 'expired', 'wrong' (with left: the tries left) or 'ended'
  // (this wrong try was the last one: the code is gone).
  checkCode(name, address, text) {
    const k = this.#pendingKey(name, address);
    const p = this.#pending.get(k);
    if (!p) return { ok: false, reason: 'none' };
    if (p.expires <= this.now()) {
      this.#pending.delete(k);
      return { ok: false, reason: 'expired' };
    }
    const have = this.#digest(String(text));
    if (!crypto.timingSafeEqual(have, p.digest)) {
      p.tries++;
      if (p.tries >= CODE_TRIES) {
        this.#pending.delete(k);
        return { ok: false, reason: 'ended' };
      }
      return { ok: false, reason: 'wrong', left: CODE_TRIES - p.tries };
    }
    this.#pending.delete(k);
    return { ok: true, address: p.address };
  }

  // ---- messages ----

  // An alert about the user's own account, to each of their confirmed addresses (none is sent without one). Never
  // throws, never waits. kind and d: see accountMessage.
  notifyUser(name, kind, d = {}) {
    try {
      const message = accountMessage(kind, name, d, d.at ?? this.now(), this.issuer);
      const to = (this.store.lxmfOf(name)?.addresses ?? []).filter((e) => e.confirmed);
      if (to.length === 0) return;
      // A sign in from a new browser can happen as often as someone tries: one alert in a while is enough, and
      // the rest are counted but not sent.
      if (kind === 'sign_in_new_device') {
        const k = key(name);
        if (this.newDevice.wait(k) > 0) return;
        this.newDevice.take(k);
      }
      for (const e of to) this.#queue(e.address, 'account', kind, message);
    } catch (err) {
      this.log(`lxmf: could not queue a message (${err?.name ?? 'error'})`);
    }
  }

  // An address was added or removed: every other confirmed address of the user is told, and a removed one
  // (which was confirmed) too, so that someone who got into the account cannot add their own address or take
  // the owner's away without the owner hearing of it. what: 'added' or 'removed'. Call it after the change.
  notifyAddressChange(name, address, what) {
    try {
      const message = accountMessage('lxmf_address_changed', name, { what, address }, this.now(), this.issuer);
      const to = new Set((this.store.lxmfOf(name)?.addresses ?? []).filter((e) => e.confirmed && e.address !== address).map((e) => e.address));
      if (what === 'removed') to.add(address);
      for (const a of to) this.#queue(a, 'account', 'lxmf_address_changed', message);
    } catch (err) {
      this.log(`lxmf: could not queue a message (${err?.name ?? 'error'})`);
    }
  }

  // A node alert the channels get (the text is theirs), to the admins and managers who asked for it. Never
  // throws, never waits.
  notifyNode(event, text) {
    try {
      const name = eventName(event);
      for (const r of this.store.lxmfNodeRecipients()) this.#queue(r.address, 'node', name, text);
    } catch (err) {
      this.log(`lxmf: could not queue a message (${err?.name ?? 'error'})`);
    }
  }

  // Queues one message: dropped (and logged) past a limit, else sent in the background with its retries.
  // cls: 'account' or 'node' (see #wait).
  #queue(address, cls, event, message) {
    if (this.#stopped) return;
    if (this.#inFlight >= MAX_IN_FLIGHT) {
      this.log('lxmf: too many messages are waiting to be sent, one was dropped');
      return;
    }
    const w = this.#wait(address, cls);
    if (w > 0) {
      this.log(`lxmf: a message to ${lxmfPrefix(address)} was dropped to keep under the limit (${waitText(w)} to go)`);
      return;
    }
    this.#take(address, cls);
    this.#inFlight++;
    this.#deliver(address, cls, event, message)
      .catch((err) => this.log(`lxmf: sending failed (${err?.name ?? 'error'})`))
      .finally(() => {
        this.#inFlight--;
        this.#settle();
      });
  }

  async #deliver(address, cls, event, message) {
    for (let attempt = 1; ; attempt++) {
      if (this.#stopped) return;
      if (attempt > 1) {
        // A retry is a message to the bridge like the first: it counts again, and is dropped if that is over a limit.
        const w = this.#wait(address, cls);
        if (w > 0) {
          this.log(`lxmf: a message to ${lxmfPrefix(address)} was dropped to keep under the limit (${waitText(w)} to go)`);
          return;
        }
        this.#take(address, cls);
      }
      const r = await this.#post(address, event, message);
      if (r.ok) return;
      if (r.refused) this.#giveBack(address, cls);
      // An alert about the account is not tried again after the bridge was unreachable or timed out: the first
      // try may have got through, and a second would be a duplicate of a security alert (and the bridge's count,
      // which we cannot see, would be one more than ours).
      const last = attempt >= MAX_ATTEMPTS || !r.retry || (cls === 'account' && r.code === 'bridge-unreachable');
      this.log(`lxmf: a message to ${lxmfPrefix(address)} failed (${r.code})${last ? ', giving up' : `, try ${attempt + 1} of ${MAX_ATTEMPTS} follows`}`);
      if (last) return;
      await Promise.resolve(this.sleep(this.retryDelays[Math.min(attempt - 1, this.retryDelays.length - 1)])).catch(() => {});
    }
  }

  // One POST to the bridge. Gives {ok: true}, or the refusal (see refusal): never the URL, the secret or the
  // answer's text.
  async #post(address, event, message) {
    const body = JSON.stringify({ event, message, to: address, sentAt: new Date(this.now()).toISOString() });
    const headers = { 'User-Agent': 'rettui-status', 'Content-Type': 'application/json' };
    if (this.#secret !== undefined) Object.assign(headers, signHeaders(this.#secret, body, this.now));
    try {
      // A redirect is an error, not followed: it could lead the secret somewhere else.
      const res = await this.fetchFn(this.#url, { method: 'POST', body, headers, redirect: 'error', signal: AbortSignal.timeout(this.timeoutMs) });
      await res.body?.cancel().catch(() => {});
      if (res.ok) return { ok: true };
      const after = Number.parseInt(res.headers?.get?.('retry-after') ?? '', 10);
      const seconds = Number.isInteger(after) && after > 0 ? Math.min(after, 24 * 3600) : 0;
      if (res.status === 429 && seconds > 0) this.#block(address, seconds);
      return { ok: false, ...refusal(res.status, seconds) };
    } catch {
      return { ok: false, ...UNREACHABLE };
    }
  }

  #settle() {
    if (this.#inFlight === 0) for (const r of this.#idle.splice(0)) r();
  }

  // Resolves when nothing is being sent. For tests and a clean stop.
  idle() {
    return this.#inFlight === 0 ? Promise.resolve() : new Promise((r) => this.#idle.push(r));
  }

  stop() {
    this.#stopped = true;
    this.#pending.clear();
  }
}
