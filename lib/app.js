// The HTTP side: static files, /api/status, /api/stats and /healthz.
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { RANGES } from './history.js';

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
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

// Clean URLs for the two pages; everything else is a file under public/.
const PAGES = { '/': 'index.html', '/status': 'status.html', '/status/': 'status.html' };

function cacheControl(file) {
  if (/\.(woff2|png)$/.test(file)) return 'public, max-age=604800';
  return 'no-cache';
}

function send(res, status, type, body, extra = {}, head = false) {
  res.writeHead(status, { ...SECURITY_HEADERS, 'Content-Type': type, 'Content-Length': Buffer.byteLength(body), ...extra });
  res.end(head ? undefined : body);
}

// Maps a URL path to a file inside root, or null when it would leave it.
export function resolveStatic(root, urlPath) {
  let decoded;
  try {
    decoded = decodeURIComponent(urlPath);
  } catch {
    return null;
  }
  if (decoded.includes('\0') || decoded.includes('\\')) return null;
  const rel = PAGES[decoded] ?? decoded.slice(1);
  const file = path.resolve(root, rel);
  if (!file.startsWith(root + path.sep)) return null;
  return file;
}

export function createApp({ monitor, publicDir }) {
  const root = path.resolve(publicDir);

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

  function handle(req, res) {
    const head = req.method === 'HEAD';
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
    if (pathname === '/api/status') {
      return send(res, 200, MIME['.json'], JSON.stringify(monitor.snapshot()), { 'Cache-Control': 'no-store' }, head);
    }
    if (pathname === '/api/stats') {
      const json = (status, body) => send(res, status, MIME['.json'], JSON.stringify(body), { 'Cache-Control': 'no-store' }, head);
      // Only configured hosts have details; nothing else is looked up.
      const host = (searchParams.get('host') ?? '').toLowerCase();
      const view = searchParams.get('view') ?? 'node';
      if (!monitor.history.has(host) || (view === 'node' && !monitor.statsHistory.has(host))) return json(404, { error: 'unknown host' });
      const range = searchParams.get('range') ?? '24h';
      if (!Object.hasOwn(RANGES, range)) return json(400, { error: 'range must be 6h, 24h or 7d' });
      if (view !== 'node' && view !== 'combined') return json(400, { error: 'view must be node or combined' });
      if (view === 'combined' && monitor.nodeInfo(host).proxyFor.length === 0) return json(400, { error: 'not a proxy' });
      return send(res, 200, MIME['.json'], monitor.detailJson(host, range, view), { 'Cache-Control': 'no-store' }, head);
    }
    const file = resolveStatic(root, pathname);
    if (!file) return send(res, 400, 'text/plain; charset=utf-8', 'Bad request\n');
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
