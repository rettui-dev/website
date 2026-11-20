// The HTTP side: static files, /api/status, /api/session, /api/stats, /api/logs/<host>, /api/incidents, /api/releases, /feed.xml, /join-qr.svg
// and /healthz, the public JSON API (/api/public/...), and with users, /login, /login/code, /login/passkey, /logout, the
// /account page and its API (/api/account, see account.js), and for admins the /users page and its API
// (/api/users, see admin.js).
// In status mode only the status page and the APIs are served; the project pages answer 404.
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { RANGES } from './history.js';
import { parseLogsQuery } from './logs.js';
import { joinQrSvg } from './join.js';
import { LOGO_URL, NO_SITE, PROJECT_FILES, hasBranding, renderAccountPage, renderProjectPage, renderStatus } from './site.js';
import { FEED_TYPE, buildFeed, feedEtag } from './feed.js';
import { etagMatches, memoJson, publicIncidents, publicStats } from './public-api.js';
import { COOKIE, DEVICE_COOKIE, DEVICE_MAX_AGE_S, MAX_CODE_INPUT, MAX_FORM_BYTES, MAX_PASSKEY_FORM_BYTES, PENDING_MS, TooLarge, clientIp, cookieValue, deviceHash, ipKey, isFormType, readBody, sameOrigin, unreadableHop, untrustedProxy, waitText } from './login.js';
import { ACCOUNT_PATHS, REQUEST_HEADER, createAccountApi } from './account.js';
import { USERS_PATHS, createUsersApi } from './admin.js';

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.woff2': 'font/woff2',
  '.txt': 'text/plain; charset=utf-8',
  '.webmanifest': 'application/manifest+json',
};

const SECURITY_HEADERS = {
  'Content-Security-Policy':
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  // Passkeys may be made and used by this site's own pages only, never in a frame of another.
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), publickey-credentials-get=(self), publickey-credentials-create=(self)',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
};

const LOGS_PATH = '/api/logs/';
const NO_PROXIES = new Set();
export const LOGS_NOT_SERVED = 'this node does not serve logs (needs a newer rettui started with --stats-logs, and a stats token)';

// How many incidents /api/incidents lists at most.
export const INCIDENTS_SHOWN = 100;

// Clean URLs for the pages; everything else is a file under public/.
const PAGES = {
  '/': 'index.html',
  '/status': 'status.html',
  '/status/': 'status.html',
  '/join': 'join.html',
  '/join/': 'join.html',
  '/downloads': 'downloads.html',
  '/downloads/': 'downloads.html',
};

// In status mode the status page is the home page and the project pages do not exist.
const STATUS_PAGES = { '/': 'status.html', '/status': 'status.html', '/status/': 'status.html' };

// How long the public API answers are kept in memory.
export const PUBLIC_TTL_MS = 10_000;

function cacheControl(file) {
  if (/\.(woff2|png)$/.test(file)) return 'public, max-age=604800';
  return 'no-cache';
}

function send(res, status, type, body, extra = {}, head = false) {
  res.writeHead(status, { ...SECURITY_HEADERS, 'Content-Type': type, 'Content-Length': Buffer.byteLength(body), ...extra });
  res.end(head ? undefined : body);
}

// Maps a URL path to a file inside root, or null when it would leave it.
export function resolveStatic(root, urlPath, pages = PAGES) {
  let decoded;
  try {
    decoded = decodeURIComponent(urlPath);
  } catch {
    return null;
  }
  if (decoded.includes('\0') || decoded.includes('\\')) return null;
  const rel = pages[decoded] ?? decoded.slice(1);
  const file = path.resolve(root, rel);
  if (!file.startsWith(root + path.sep)) return null;
  return file;
}

// One answer for a wrong name and a wrong password, so neither gives away which names exist.
export const LOGIN_FAILED = 'Wrong name or password.';
export const CODE_FAILED = 'That code is not right.';
export const CODE_EXPIRED = 'The sign in took too long or had too many wrong codes. Enter your name and password again.';
export const PASSKEY_FAILED = 'That passkey did not work. Try again, or use another way to sign in.';
const LOGIN_PATHS = new Set(['/login', '/logout', '/login/code', '/login/passkey']);

export function createApp({ monitor, publicDir, login = null, releases = null, mode = 'full', site = NO_SITE, publicTtlMs = PUBLIC_TTL_MS, warn = console.warn }) {
  const root = path.resolve(publicDir);
  const statusOnly = mode === 'status';
  const pages = statusOnly ? STATUS_PAGES : PAGES;
  const statusFile = path.join(root, 'status.html');
  // The status page is filled in for a custom site (or one with an address), and served as the file otherwise.
  const customPage = statusOnly || hasBranding(site) || Boolean(site.url);
  // The project pages get their Open Graph address and picture only when the site's address is known;
  // without it they are the files, byte for byte.
  const projectPaths = site.url && !statusOnly ? new Map([[path.join(root, 'index.html'), '/'], [path.join(root, 'join.html'), '/join'], [path.join(root, 'downloads.html'), '/downloads']]) : new Map();
  // Rendered pages by file, kept until the file changes.
  const rendered = new Map();
  // The public API answers: built from the anonymous view, kept in memory, the same for everybody.
  const publicStatsAnswer = memoJson(() => publicStats(monitor.snapshot(1, false), new Date(monitor.now()).toISOString()), publicTtlMs);
  const publicIncidentsAnswer = memoJson(() => publicIncidents(monitor.incidentList(INCIDENTS_SHOWN), new Date(monitor.now()).toISOString()), publicTtlMs);
  const auth = login?.enabled ? login : null;
  const account = auth ? createAccountApi({ auth, issuer: site.name ?? 'rettui status', now: auth.sessions.now }) : null;
  const accountFile = path.join(root, 'account.html');
  const usersApi = auth ? createUsersApi({ auth, now: auth.sessions.now }) : null;
  const usersFile = path.join(root, 'users.html');
  // Said once: a reverse proxy that is not in trusted_proxies makes every
  // visitor share its address for the failed-login wait.
  let warnedProxy = false;
  // Said once too: a trusted proxy whose X-Forwarded-For can't be read as addresses.
  let warnedHop = false;
  const checkProxy = (req) => {
    if (!warnedHop) {
      const from = unreadableHop(req, auth.trusted);
      if (from !== null) {
        warnedHop = true;
        warn(`WARNING: login: the trusted proxy ${from} sent an X-Forwarded-For entry that is not an IP address, so the visitors it forwards share its address for the failed-login waits. Make the proxy send plain client addresses (an address with a port, like 192.0.2.1:5678 or [2001:db8::1]:443, is read) (see "Behind a reverse proxy" in README.md)`);
      }
    }
    if (warnedProxy) return;
    const peer = untrustedProxy(req, auth.trusted);
    if (peer === null) return;
    warnedProxy = true;
    warn(`WARNING: login: requests from ${peer} carry X-Forwarded-For, but ${peer} is not a trusted proxy, so every visitor shares its address for the failed-login waits and one visitor's failures hold back everyone. List it in login.trusted_proxies in the config file, or in LOGIN_TRUSTED_PROXIES without a config file (see "Behind a reverse proxy" in README.md)`);
  };
  // With a login, answers differ by who asks: no shared cache may keep them.
  const apiCache = auth ? { 'Cache-Control': 'private, no-store', Vary: 'Cookie' } : { 'Cache-Control': 'no-store' };

  function serveFile(req, res, file) {
    fs.stat(file, (err, st) => {
      if (err || !st.isFile()) return send(res, 404, 'text/plain; charset=utf-8', 'Not found\n');
      const type = MIME[path.extname(file).toLowerCase()];
      if (!type) return send(res, 404, 'text/plain; charset=utf-8', 'Not found\n');
      res.writeHead(200, { ...SECURITY_HEADERS, 'Content-Type': type, 'Content-Length': st.size, 'Cache-Control': cacheControl(file) });
      if (req.method === 'HEAD') return res.end();
      const stream = fs.createReadStream(file);
      stream.on('error', () => res.destroy());
      stream.pipe(res);
    });
  }

  // A page that is filled in on the server: read and rendered once, again when the file changes.
  function servePage(req, res, file, render, headers = { 'Cache-Control': 'no-cache' }) {
    fs.stat(file, (err, st) => {
      if (err || !st.isFile()) return send(res, 404, 'text/plain; charset=utf-8', 'Not found\n');
      const done = (body) => send(res, 200, MIME['.html'], body, headers, req.method === 'HEAD');
      const hit = rendered.get(file);
      if (hit?.mtimeMs === st.mtimeMs) return done(hit.body);
      fs.readFile(file, 'utf8', (e, html) => {
        if (e) return send(res, 404, 'text/plain; charset=utf-8', 'Not found\n');
        let body;
        try {
          body = render(html);
        } catch (renderErr) {
          console.error(`request failed: ${renderErr.message}`);
          return send(res, 500, 'text/plain; charset=utf-8', 'Server error\n');
        }
        rendered.set(file, { mtimeMs: st.mtimeMs, body });
        done(body);
      });
    });
  }

  // Whether a file is one of the pages served only through serveGated.
  const gated = (file) => {
    const rel = path.relative(root, file).toLowerCase();
    return rel === 'account.html' || rel === 'users.html';
  };

  // The account page, only on a site with users; the users page, for admins only (for everyone
  // else it is not there).
  function serveGated(req, res, file) {
    const head = req.method === 'HEAD';
    if (path.relative(root, file).toLowerCase() === 'account.html') {
      if (!auth) return send(res, 404, 'text/plain; charset=utf-8', 'Not found\n', {}, head);
      return servePage(req, res, accountFile, (html) => renderAccountPage(html, { mode, site }));
    }
    if (!auth || !usersApi.pageAllowed(req)) return send(res, 404, 'text/plain; charset=utf-8', 'Not found\n', apiCache, head);
    return servePage(req, res, usersFile, (html) => renderAccountPage(html, { mode, site, title: 'Users' }), apiCache);
  }

  // A public API answer: any origin may read it, it is cached for a short time, and it never depends on a cookie.
  function servePublic(req, res, answer) {
    const { body, etag } = answer();
    const headers = { 'Cache-Control': 'public, max-age=30', ETag: etag, 'Access-Control-Allow-Origin': '*' };
    if (etagMatches(req.headers['if-none-match'], etag)) {
      res.writeHead(304, { ...SECURITY_HEADERS, ...headers });
      return res.end();
    }
    send(res, 200, MIME['.json'], body, headers, req.method === 'HEAD');
  }

  function cookie(id, maxAge) {
    return `${COOKIE}=${id}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Strict`;
  }

  const deviceCookie = (id) => `${DEVICE_COOKIE}=${id}; Path=/; Max-Age=${DEVICE_MAX_AGE_S}; HttpOnly; Secure; SameSite=Strict`;

  const tooMany = (json, ms, error = `Too many failed attempts. Try again in ${waitText(ms)}.`, extra = {}) => {
    const s = Math.ceil(ms / 1000);
    return json(429, { error, retryAfter: s, ...extra }, { 'Retry-After': String(s) });
  };

  // A new session for a sign in that is complete (r: what attempt or finishSecondFactor gave), and
  // the known-device cookie. A new session id every time: an id someone planted before cannot
  // become a session. When the user's sign in changed since the password was checked, nothing is
  // made and the answer is `failed`. The browser's device id is kept only when it is still the
  // device the password step found; a device cookie changed or dropped since then (between /login
  // and /login/code) makes this a new browser, with a new id.
  async function signIn(req, json, old, r, ip, failed) {
    const cookieId = cookieValue(req.headers.cookie, DEVICE_COOKIE);
    const same = typeof r.device === 'string' && deviceHash(cookieId) === r.device;
    const done = await auth.signIn(r.name, { epoch: r.epoch, device: same ? r.device : null, deviceId: same ? cookieId : null, old, ip });
    if (!done) return json(401, failed);
    // A password an admin set: the page sends the user to the account page to choose their own.
    const must = auth.store.lookup(r.name)?.mustChangePassword === true;
    return json(200, must ? { ok: true, name: r.name, mustChangePassword: true } : { ok: true, name: r.name }, { 'Set-Cookie': [cookie(done.id, auth.maxAgeSeconds), deviceCookie(done.deviceId)] });
  }

  // POST /login, /login/code, /login/passkey and /logout. They only take a form sent by the page
  // itself, with the X-Rettui-Request header, which a form on another site cannot send.
  async function post(req, res, pathname) {
    const json = (status, body, extra = {}) => send(res, status, MIME['.json'], JSON.stringify(body), { 'Cache-Control': 'no-store', ...extra });
    if (!sameOrigin(req.headers) || req.headers[REQUEST_HEADER] !== '1') return json(403, { error: 'Log in from the status page.' });
    if (!isFormType(req.headers['content-type'])) return json(415, { error: 'Send the form as application/x-www-form-urlencoded.' });
    let text;
    try {
      text = await readBody(req, pathname === '/login/passkey' ? MAX_PASSKEY_FORM_BYTES : MAX_FORM_BYTES);
    } catch (err) {
      if (err instanceof TooLarge) return json(413, { error: 'The form is too large.' }, { Connection: 'close' });
      throw err;
    }
    const old = cookieValue(req.headers.cookie, COOKIE);
    if (pathname === '/logout') {
      if (old) {
        auth.sessions.destroy(old);
        auth.passkeys.dropSession(old);
      }
      return json(200, { ok: true }, { 'Set-Cookie': cookie('', 0) });
    }
    const form = new URLSearchParams(text);
    if (pathname === '/login/code') {
      const code = form.get('code') ?? '';
      const recovery = form.get('recovery') ?? '';
      if (!code.trim() && !recovery.trim()) return json(400, { error: 'Enter the code.' });
      if (code.length > MAX_CODE_INPUT || recovery.length > MAX_CODE_INPUT) return json(400, { error: CODE_FAILED });
      const r = await auth.finishSecondFactor(form.get('pending'), { code, recovery }, clientIp(req, auth.trusted));
      if (r.reason === 'throttled' && r.restart) return tooMany(json, r.retryAfterMs, `Too many wrong codes. Wait ${waitText(r.retryAfterMs)}, then sign in again.`, { restart: true });
      if (r.reason === 'throttled') return tooMany(json, r.retryAfterMs, `Too many wrong codes. Try again in ${waitText(r.retryAfterMs)}.`);
      if (r.reason === 'expired') return json(401, { error: CODE_EXPIRED, restart: true });
      if (!r.ok) return json(401, { error: CODE_FAILED });
      return signIn(req, json, old, r, clientIp(req, auth.trusted), { error: CODE_EXPIRED, restart: true });
    }
    // The second step with a passkey: credential is the JSON text of what navigator.credentials.get
    // gave. One that cannot be read is checked all the same, so it counts as a passkey that did not
    // work; passkeys.js reads nothing of it before its shape and sizes are checked.
    if (pathname === '/login/passkey') {
      const text = form.get('credential') ?? '';
      if (!text.trim()) return json(400, { error: 'Use your passkey, or another way to sign in.' });
      let credential;
      try {
        credential = JSON.parse(text);
      } catch {
        credential = {};
      }
      if (credential === null || typeof credential !== 'object' || Array.isArray(credential)) credential = {};
      const ip = clientIp(req, auth.trusted);
      const r = await auth.finishSecondFactor(form.get('pending'), { passkey: credential }, ip);
      if (r.reason === 'throttled' && r.restart) return tooMany(json, r.retryAfterMs, `Too many wrong codes. Wait ${waitText(r.retryAfterMs)}, then sign in again.`, { restart: true });
      if (r.reason === 'throttled') return tooMany(json, r.retryAfterMs, `Too many wrong codes. Try again in ${waitText(r.retryAfterMs)}.`, r.passkey ? { passkey: r.passkey } : {});
      if (r.reason === 'expired') return json(401, { error: CODE_EXPIRED, restart: true });
      if (!r.ok) return json(401, r.passkey ? { error: PASSKEY_FAILED, passkey: r.passkey } : { error: PASSKEY_FAILED });
      return signIn(req, json, old, r, ip, { error: CODE_EXPIRED, restart: true });
    }
    const name = form.get('name');
    const password = form.get('password');
    if (!name || !password) return json(400, { error: 'Enter a name and a password.' });
    const ip = clientIp(req, auth.trusted);
    const r = await auth.attempt(name, password, ip, { device: cookieValue(req.headers.cookie, DEVICE_COOKIE) });
    if (r.reason === 'throttled') return tooMany(json, r.retryAfterMs);
    if (r.reason === 'paced' && r.scope === 'device') return tooMany(json, r.retryAfterMs, `Too many sign ins from this browser right now. Try again in ${waitText(r.retryAfterMs)}.`);
    if (r.reason === 'paced') return tooMany(json, r.retryAfterMs, `Too many sign ins for this name right now. Try again in ${waitText(r.retryAfterMs)}.`);
    if (r.reason === 'busy') return json(503, { error: 'Too many logins at once. Try again in a moment.' }, { 'Retry-After': '2' });
    // The user store cannot be read (see users.js): nobody signs in until it can.
    if (r.reason === 'unavailable') return json(503, { error: 'Signing in is not possible right now. Try again later.' }, { 'Retry-After': '30' });
    if (!r.ok) return json(401, { error: LOGIN_FAILED });
    // With a second factor the password alone is not a sign in: the page asks for the code next,
    // with this token, which is good for one sign in from this address for 5 minutes. When wrong
    // codes hold the code step back for longer than that, there is no token: the answer says how
    // long to wait. A shorter wait comes with the token, and the page says it.
    if (r.secondFactor) {
      if (r.codeWaitMs >= PENDING_MS) return tooMany(json, r.codeWaitMs, `Too many wrong codes were entered for this account. Sign in again in ${waitText(r.codeWaitMs)}.`);
      const extra = r.codeWaitMs > 0 ? { codeWait: Math.ceil(r.codeWaitMs / 1000), notice: `Too many wrong codes were entered for this account. You can enter a code in ${waitText(r.codeWaitMs)}.` } : {};
      // methods: the ways this user can give the second step; passkey: the options of the passkey
      // prompt; passkeyUnavailable: their passkeys do not work at this address. All of it only
      // ever after a right password.
      const step = auth.startSecondFactor(r.name, ip, { epoch: r.epoch, device: r.device });
      const ways = { methods: step.methods };
      if (step.passkey) ways.passkey = step.passkey;
      if (step.passkeyUnavailable) ways.passkeyUnavailable = true;
      return json(200, { ok: false, secondFactor: true, pending: step.token, ...ways, expiresIn: Math.floor(PENDING_MS / 1000), ...extra });
    }
    return signIn(req, json, old, r, ip, { error: LOGIN_FAILED });
  }

  // GET /api/logs/<host:port>?lines&level: the node's recent log lines, fetched on demand with the node's own
  // token. Only for a logged-in viewer (or a node with public_logs) who may see the details, and every error
  // is our own words: nothing the node says is passed on.
  async function serveLogs(req, res, pathname, searchParams, viewer) {
    const json = (status, body, extra = {}) => send(res, status, MIME['.json'], JSON.stringify(body), { ...apiCache, ...extra }, req.method === 'HEAD');
    let host;
    try {
      host = decodeURIComponent(pathname.slice(LOGS_PATH.length)).toLowerCase();
    } catch {
      return json(404, { error: 'unknown host' });
    }
    if (!monitor.history.has(host) || !monitor.nodeInfo(host).publicDetails) return json(404, { error: 'unknown host' });
    // Access first, so a visitor who may not read the logs cannot tell a node without logs from a locked one.
    // Without users nobody can log in: the same answer for every node.
    if (!monitor.logsAllowed(host, viewer !== null)) return auth ? json(401, { error: 'log in to see the logs' }) : json(404, { error: 'unknown host' });
    if (!monitor.logsAvailable(host)) return json(404, { error: LOGS_NOT_SERVED });
    const q = parseLogsQuery(searchParams);
    if (q.error) return json(400, { error: q.error });
    // A HEAD request checks access only; it never costs the node a fetch.
    if (req.method === 'HEAD') return json(200, {});
    // A new question is limited for each viewer: the login name, or the address of someone without one
    // (public_logs); without users the address is the connection's, as there are no trusted proxies.
    const who = viewer !== null ? `user:${viewer}` : ipKey(clientIp(req, auth?.trusted ?? NO_PROXIES));
    const r = await monitor.logsFor(host, q, who);
    if (r.ok) return json(200, { host, requested: q, fetchedAt: new Date(r.fetchedAt).toISOString(), ...r.data });
    if (r.error === 'rate') return json(429, { error: `Too many requests for logs just now. Try again in ${r.retryAfter} ${r.retryAfter === 1 ? 'second' : 'seconds'}.`, retryAfter: r.retryAfter }, { 'Retry-After': String(r.retryAfter) });
    if (r.error === 'not-found') return json(404, { error: LOGS_NOT_SERVED });
    return json(502, { error: 'The node did not answer with logs. Try again later.' });
  }

  function handle(req, res) {
    const head = req.method === 'HEAD';
    if (auth) checkProxy(req);
    if (auth && req.method === 'POST' && LOGIN_PATHS.has(req.url)) {
      post(req, res, req.url).catch((err) => {
        console.error(`login request failed: ${err?.message ?? err}`);
        if (res.headersSent) res.destroy();
        else send(res, 500, 'text/plain; charset=utf-8', 'Server error\n');
      });
      return;
    }
    if (auth && req.method === 'POST' && ACCOUNT_PATHS.includes(req.url)) {
      const json = (status, body, extra = {}) => send(res, status, MIME['.json'], JSON.stringify(body), { 'Cache-Control': 'no-store', ...extra });
      account.post(req, req.url, json).catch((err) => {
        console.error(`account request failed: ${err?.message ?? err}`);
        if (res.headersSent) res.destroy();
        else send(res, 500, 'text/plain; charset=utf-8', 'Server error\n');
      });
      return;
    }
    if (auth && req.method === 'POST' && USERS_PATHS.includes(req.url)) {
      const json = (status, body, extra = {}) => send(res, status, MIME['.json'], JSON.stringify(body), { 'Cache-Control': 'no-store', ...extra });
      usersApi.post(req, req.url, json).catch((err) => {
        console.error(`users request failed: ${err?.message ?? err}`);
        if (res.headersSent) res.destroy();
        else send(res, 500, 'text/plain; charset=utf-8', 'Server error\n');
      });
      return;
    }
    if (req.method !== 'GET' && !head) {
      return send(res, 405, 'text/plain; charset=utf-8', 'Method not allowed\n', { Allow: 'GET, HEAD' });
    }
    // Some request targets (for example "//") are not a valid URL: that is a bad request.
    let parsed;
    try {
      parsed = new URL(req.url ?? '/', 'http://localhost');
    } catch {
      return send(res, 400, 'text/plain; charset=utf-8', 'Bad request\n');
    }
    const { pathname, searchParams } = parsed;
    if (pathname === '/healthz') return send(res, 200, 'text/plain; charset=utf-8', 'ok\n', { 'Cache-Control': 'no-store' }, head);
    if (pathname === '/api/public/stats') return servePublic(req, res, publicStatsAnswer);
    if (pathname === '/api/public/incidents') return servePublic(req, res, publicIncidentsAnswer);
    if (site.logo && pathname === LOGO_URL) {
      // Shown through an <img> only; opened on its own it still gets the strict policy, and a sandbox as well.
      const extra = { 'Cache-Control': 'public, max-age=3600', 'Content-Security-Policy': `${SECURITY_HEADERS['Content-Security-Policy']}; sandbox` };
      return send(res, 200, site.logo.mime, site.logo.bytes, extra, head);
    }
    if (statusOnly && (pathname === '/join-qr.svg' || pathname === '/api/releases' || pathname === '/feed.xml')) return send(res, 404, 'text/plain; charset=utf-8', 'Not found\n');
    if (pathname === '/join-qr.svg') {
      // Made from the text in lib/join.js, so it cannot differ from what the page shows.
      return send(res, 200, MIME['.svg'], joinQrSvg(), { 'Cache-Control': 'no-cache' }, head);
    }
    if (pathname === '/feed.xml') {
      if (!releases) return send(res, 404, 'text/plain; charset=utf-8', 'Not found\n');
      // Built from the cache the background job keeps, so a visitor never makes a request to GitHub.
      const body = buildFeed(releases.feedItems(), { siteUrl: site.url });
      const etag = feedEtag(body);
      const headers = { 'Cache-Control': 'public, max-age=300', ETag: etag };
      if (etagMatches(req.headers['if-none-match'], etag)) {
        res.writeHead(304, { ...SECURITY_HEADERS, ...headers });
        return res.end();
      }
      return send(res, 200, FEED_TYPE, body, headers, head);
    }
    if (pathname === '/api/releases') {
      // The same for every visitor, and only ever read from the cache the background job keeps.
      if (!releases) return send(res, 404, MIME['.json'], JSON.stringify({ error: 'releases are not available' }), { 'Cache-Control': 'no-store' }, head);
      return send(res, 200, MIME['.json'], JSON.stringify(releases.snapshot()), { 'Cache-Control': 'no-store' }, head);
    }
    // For the sign in button on every page: whether the site has users, and who is signed in. It says
    // nothing else, and it is never cached.
    if (pathname === '/api/session') {
      const cur = auth ? auth.session(req) : null;
      const body = { enabled: auth !== null, name: cur?.user.name ?? null };
      // Signed in with a password an admin set: only the account page is open to them.
      if (cur?.user.mustChangePassword) body.mustChangePassword = true;
      return send(res, 200, MIME['.json'], JSON.stringify(body), apiCache, head);
    }
    // The account and users pages by their clean URLs; any other spelling of their files is sent
    // to the same place below, once it is resolved.
    if (pathname === '/account' || pathname === '/account/') return serveGated(req, res, accountFile);
    if (pathname === '/users' || pathname === '/users/') return serveGated(req, res, usersFile);
    if (pathname === '/api/users') {
      if (!auth) return send(res, 404, MIME['.json'], JSON.stringify({ error: 'Not found' }), apiCache, head);
      return usersApi.get(req, (status, body) => send(res, status, MIME['.json'], JSON.stringify(body), apiCache, head));
    }
    if (pathname === '/api/account') {
      if (!auth) return send(res, 404, MIME['.json'], JSON.stringify({ error: 'there are no accounts' }), apiCache, head);
      return account.get(req, (status, body) => send(res, status, MIME['.json'], JSON.stringify(body), apiCache, head));
    }
    // Who is logged in, if anyone; without users nobody ever is.
    const isLogs = pathname.startsWith(LOGS_PATH);
    const viewer = auth && (pathname === '/api/status' || pathname === '/api/stats' || isLogs) ? auth.viewer(req) : null;
    if (isLogs) {
      serveLogs(req, res, pathname, searchParams, viewer).catch((err) => {
        console.error(`logs request failed: ${err?.message ?? err}`);
        if (res.headersSent) res.destroy();
        else send(res, 500, 'text/plain; charset=utf-8', 'Server error\n');
      });
      return;
    }
    if (pathname === '/api/status') {
      const body = monitor.snapshot(90, viewer !== null);
      if (auth) {
        // What the page offers a login for, by host; nothing once logged in.
        for (const h of body.hosts) h.locked = [...monitor.hiddenFor(`${h.host}:${h.port}`, viewer !== null)];
        body.viewer = { name: viewer };
      }
      return send(res, 200, MIME['.json'], JSON.stringify(body), apiCache, head);
    }
    if (pathname === '/api/incidents') {
      // Up and down is public, so the incidents are too; the same for every visitor.
      const body = { generatedAt: new Date(monitor.now()).toISOString(), incidents: monitor.incidentList(INCIDENTS_SHOWN) };
      return send(res, 200, MIME['.json'], JSON.stringify(body), apiCache, head);
    }
    if (pathname === '/api/stats') {
      const json = (status, body) => send(res, status, MIME['.json'], JSON.stringify(body), apiCache, head);
      // Only configured hosts have details; nothing else is looked up.
      const host = (searchParams.get('host') ?? '').toLowerCase();
      const view = searchParams.get('view') ?? 'node';
      if (!monitor.history.has(host) || !monitor.nodeInfo(host).publicDetails || (view === 'node' && !monitor.statsHistory.has(host))) return json(404, { error: 'unknown host' });
      const range = searchParams.get('range') ?? '24h';
      if (!Object.hasOwn(RANGES, range)) return json(400, { error: 'range must be 6h, 24h or 7d' });
      if (view !== 'node' && view !== 'combined') return json(400, { error: 'view must be node or combined' });
      if (view === 'combined' && monitor.nodeInfo(host).proxyFor.length === 0) return json(400, { error: 'not a proxy' });
      if (viewer === null && monitor.hiddenFor(host, false).has('details')) return json(401, { error: 'log in to see the details' });
      return send(res, 200, MIME['.json'], monitor.detailJson(host, range, view, viewer !== null), apiCache, head);
    }
    const file = resolveStatic(root, pathname, pages);
    if (!file) return send(res, 400, 'text/plain; charset=utf-8', 'Bad request\n');
    // Every spelling of a gated page (/users.html, /%75sers.html, /users.html/, /USERS.html on a
    // file system that ignores case) goes through its gate.
    if (gated(file)) return serveGated(req, res, file);
    if (statusOnly && PROJECT_FILES.some((f) => file === path.join(root, f))) return send(res, 404, 'text/plain; charset=utf-8', 'Not found\n');
    if (customPage && file === statusFile) return servePage(req, res, file, (html) => renderStatus(html, { mode, site }));
    if (projectPaths.has(file)) return servePage(req, res, file, (html) => renderProjectPage(html, { origin: site.url, path: projectPaths.get(file) }));
    serveFile(req, res, file);
  }

  const server = http.createServer((req, res) => {
    try {
      handle(req, res);
    } catch (err) {
      // Whatever went wrong stays in the log; the visitor gets no details.
      console.error(`request failed: ${err?.message ?? err}`);
      if (res.headersSent) res.destroy();
      else send(res, 500, 'text/plain; charset=utf-8', 'Server error\n');
    }
  });
  // Malformed HTTP is answered and closed instead of left to the default handler.
  server.on('clientError', (_err, socket) => {
    if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
    else socket.destroy();
  });
  return server;
}
