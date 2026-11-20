// The HTTP side: static files, /api/status, /api/session, /api/stats, /api/logs/<host>, /api/incidents, /api/releases, /feed.xml, /join-qr.svg
// and /healthz, the public JSON API (/api/public/...), and with users in the config, /login and /logout.
// In status mode only the status page and the APIs are served; the project pages answer 404.
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { RANGES } from './history.js';
import { parseLogsQuery } from './logs.js';
import { joinQrSvg } from './join.js';
import { LOGO_URL, NO_SITE, PROJECT_FILES, hasBranding, renderProjectPage, renderStatus } from './site.js';
import { FEED_TYPE, buildFeed, feedEtag } from './feed.js';
import { etagMatches, memoJson, publicIncidents, publicStats } from './public-api.js';
import { COOKIE, TooLarge, clientIp, cookieValue, ipKey, isFormType, readBody, sameOrigin, untrustedProxy } from './login.js';

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
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
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
  // Said once: a reverse proxy that is not in trusted_proxies makes every
  // visitor share its address for the failed-login wait.
  let warnedProxy = false;
  const checkProxy = (req) => {
    if (warnedProxy) return;
    const peer = untrustedProxy(req, auth.trusted);
    if (peer === null) return;
    warnedProxy = true;
    warn(`login: requests from ${peer} carry X-Forwarded-For, but ${peer} is not in login.trusted_proxies, so all visitors share its address for the failed-login wait (see "Behind a reverse proxy" in README.md)`);
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
  function servePage(req, res, file, render) {
    fs.stat(file, (err, st) => {
      if (err || !st.isFile()) return send(res, 404, 'text/plain; charset=utf-8', 'Not found\n');
      const done = (body) => send(res, 200, MIME['.html'], body, { 'Cache-Control': 'no-cache' }, req.method === 'HEAD');
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

  // POST /login and /logout. Both only take a form sent by the page itself.
  async function post(req, res, pathname) {
    const json = (status, body, extra = {}) => send(res, status, MIME['.json'], JSON.stringify(body), { 'Cache-Control': 'no-store', ...extra });
    if (!sameOrigin(req.headers)) return json(403, { error: 'Log in from the status page.' });
    if (!isFormType(req.headers['content-type'])) return json(415, { error: 'Send the form as application/x-www-form-urlencoded.' });
    let text;
    try {
      text = await readBody(req);
    } catch (err) {
      if (err instanceof TooLarge) return json(413, { error: 'The form is too large.' }, { Connection: 'close' });
      throw err;
    }
    const old = cookieValue(req.headers.cookie, COOKIE);
    if (pathname === '/logout') {
      if (old) auth.sessions.destroy(old);
      return json(200, { ok: true }, { 'Set-Cookie': cookie('', 0) });
    }
    const form = new URLSearchParams(text);
    const name = form.get('name');
    const password = form.get('password');
    if (!name || !password) return json(400, { error: 'Enter a name and a password.' });
    const r = await auth.attempt(name, password, clientIp(req, auth.trusted));
    if (r.reason === 'throttled') {
      const s = Math.ceil(r.retryAfterMs / 1000);
      return json(429, { error: `Too many failed attempts. Try again in ${s} ${s === 1 ? 'second' : 'seconds'}.`, retryAfter: s }, { 'Retry-After': String(s) });
    }
    if (r.reason === 'busy') return json(503, { error: 'Too many logins at once. Try again in a moment.' }, { 'Retry-After': '2' });
    if (!r.ok) return json(401, { error: LOGIN_FAILED });
    // A new id on every login: an id someone planted before cannot become a session.
    if (old) auth.sessions.destroy(old);
    const id = auth.sessions.create(r.name);
    return json(200, { ok: true, name: r.name }, { 'Set-Cookie': cookie(id, auth.maxAgeSeconds) });
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
    if (auth && req.method === 'POST' && (req.url === '/login' || req.url === '/logout')) {
      post(req, res, req.url).catch((err) => {
        console.error(`login request failed: ${err?.message ?? err}`);
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
      const name = auth ? auth.viewer(req) : null;
      return send(res, 200, MIME['.json'], JSON.stringify({ enabled: auth !== null, name }), apiCache, head);
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
