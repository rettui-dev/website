import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Monitor } from '../lib/monitor.js';
import { createApp, resolveStatic } from '../lib/app.js';
import { JOIN_HOST, JOIN_PORT, JOIN_SNIPPET, joinQrSvg } from '../lib/join.js';
import { encode, toSvg } from '../lib/qr.js';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const publicDir = path.join(root, 'public');
const read = (name) => fs.readFile(path.join(publicDir, name), 'utf8');

const SNAPSHOT = {
  generatedAt: '2026-11-19T12:00:00.000Z',
  ttlSeconds: 900,
  projects: [{ repo: 'a/b', url: 'https://github.com/a/b', releasesUrl: 'https://github.com/a/b/releases', status: 'none', stale: false, ageSeconds: 0, fetchedAt: null, error: null, release: null }],
};

async function start({ releases = null } = {}) {
  const dataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'website-pages-'));
  const monitor = new Monitor({ targets: [{ host: 'a.test', port: 4242 }], dataDir, probeFn: async () => ({ up: true, ms: 9 }) });
  await monitor.checkAll();
  const server = createApp({ monitor, publicDir, releases });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  return { base: `http://127.0.0.1:${port}`, port, close: () => new Promise((r) => (server.closeAllConnections(), server.close(r))) };
}

function raw(port, requestPath, method) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path: requestPath, method }, (res) => {
      let body = '';
      res.on('data', (c) => (body += c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
    });
    req.on('error', reject);
    req.end();
  });
}

function assertSecurityHeaders(res, where) {
  assert.equal(res.headers.get('x-content-type-options'), 'nosniff', where);
  assert.equal(res.headers.get('x-frame-options'), 'DENY', where);
  assert.match(res.headers.get('content-security-policy'), /default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'/, where);
  assert.equal(res.headers.get('referrer-policy'), 'no-referrer', where);
}

test('/join and /downloads are pages with clean URLs, with and without a slash', async () => {
  const s = await start();
  try {
    for (const url of ['/join', '/join/', '/downloads', '/downloads/']) {
      const res = await fetch(s.base + url);
      assert.equal(res.status, 200, url);
      assert.equal(res.headers.get('content-type'), 'text/html; charset=utf-8', url);
      assertSecurityHeaders(res, url);
      const html = await res.text();
      assert.match(html, url.startsWith('/join') ? /<h1>Join the network<\/h1>/ : /<h1>Downloads<\/h1>/, url);
    }
    const head = await raw(s.port, '/join', 'HEAD');
    assert.equal(head.status, 200);
    assert.equal(head.body, '');
    const post = await raw(s.port, '/downloads', 'POST');
    assert.equal(post.status, 405);
    assert.equal(post.headers.allow, 'GET, HEAD');
  } finally {
    await s.close();
  }
});

test('the new pages and scripts stay inside the public folder', () => {
  const dir = path.resolve(publicDir);
  assert.equal(resolveStatic(dir, '/join'), path.join(dir, 'join.html'));
  assert.equal(resolveStatic(dir, '/join/'), path.join(dir, 'join.html'));
  assert.equal(resolveStatic(dir, '/downloads'), path.join(dir, 'downloads.html'));
  assert.equal(resolveStatic(dir, '/downloads/'), path.join(dir, 'downloads.html'));
  assert.equal(resolveStatic(dir, '/downloads.js'), path.join(dir, 'downloads.js'));
  assert.equal(resolveStatic(dir, '/join/../../x'), null);
});

test('/join-qr.svg is an SVG, GET and HEAD only, with the security headers', async () => {
  const s = await start();
  try {
    const res = await fetch(`${s.base}/join-qr.svg`);
    assert.equal(res.status, 200);
    assert.equal(res.headers.get('content-type'), 'image/svg+xml');
    assertSecurityHeaders(res, 'svg');
    assert.equal(res.headers.get('cross-origin-resource-policy'), 'same-origin');
    const svg = await res.text();
    assert.match(svg, /^<svg xmlns="http:\/\/www\.w3\.org\/2000\/svg" viewBox="0 0 \d+ \d+"/);
    assert.equal(svg.match(/<[a-z]+/g).join(' '), '<svg <rect <path');
    assert.doesNotMatch(svg, /script|style|href|on[a-z]+=|<!|javascript/i);
    assert.equal(Number(res.headers.get('content-length')), Buffer.byteLength(svg));
    // It is the code of the text the page shows.
    assert.equal(svg, toSvg(encode(JOIN_SNIPPET, { level: 'M' }).grid));
    assert.equal(svg, joinQrSvg());
    const head = await raw(s.port, '/join-qr.svg', 'HEAD');
    assert.equal(head.status, 200);
    assert.equal(head.headers['content-type'], 'image/svg+xml');
    assert.equal(head.headers['content-length'], String(Buffer.byteLength(svg)));
    assert.equal(head.body, '');
    for (const method of ['POST', 'PUT', 'DELETE']) {
      const r = await raw(s.port, '/join-qr.svg', method);
      assert.equal(r.status, 405, method);
      assert.equal(r.headers.allow, 'GET, HEAD');
    }
    // A query string does not change it, and nothing else is read from the request.
    assert.equal(await (await fetch(`${s.base}/join-qr.svg?data=evil`)).text(), svg);
  } finally {
    await s.close();
  }
});

test('the QR code is small enough to scan from a phone', () => {
  const code = encode(JOIN_SNIPPET, { level: 'M' });
  assert.ok(code.version <= 8, `version ${code.version}`);
  assert.equal(code.level, 'M');
});

test('the config the page shows is the text of the QR code, and is Reticulum syntax', async () => {
  const html = await read('join.html');
  const m = /<code id="config-snippet">([^<]*)<\/code>/.exec(html);
  assert.ok(m, 'the snippet is in a <code> with an id');
  assert.equal(m[1], JOIN_SNIPPET);
  assert.doesNotMatch(m[1], /&/);
  const lines = JOIN_SNIPPET.trimEnd().split('\n').map((l) => l.trim());
  assert.deepEqual(lines, ['[[rettui entry point]]', 'type = TCPClientInterface', 'enabled = yes', `target_host = ${JOIN_HOST}`, `target_port = ${JOIN_PORT}`]);
  assert.equal(JOIN_HOST, 'rns.rettui.dev');
  assert.equal(JOIN_PORT, 4242);
  assert.match(html, /<code class="addr" id="hostport">rns\.rettui\.dev:4242<\/code>/);
  for (const host of ['front', 'back', 'side']) assert.match(html, new RegExp(`<code id="ep-${host}">${host}\\.rns\\.rettui\\.dev:4242</code>`));
  assert.match(html, /<img class="qr" src="\/join-qr\.svg"[^>]* alt="[^"]+"/);
});

test('copy buttons are buttons, point at real elements, and have a status region', async () => {
  for (const name of ['join.html', 'downloads.html']) {
    const html = await read(name);
    const ids = new Set([...html.matchAll(/\sid="([^"]+)"/g)].map((m) => m[1]));
    for (const [tag] of html.matchAll(/<[a-z]+[^>]*\sdata-copy(?:-from)?="[^"]*"[^>]*>/g)) {
      assert.match(tag, /^<button type="button"/, `${name}: ${tag}`);
      const from = /data-copy-from="([^"]+)"/.exec(tag);
      if (from) assert.ok(ids.has(from[1]), `${name}: ${from[1]} exists`);
      const status = /data-copy-status="([^"]+)"/.exec(tag);
      if (status) assert.match(html, new RegExp(`id="${status[1]}"[^>]*role="status"|role="status"[^>]*id="${status[1]}"`), `${name}: ${status[1]} is a status region`);
    }
  }
  assert.match(await read('join.html'), /data-copy-from="config-snippet"/);
  // The Downloads buttons are made by the script, each with its own status region beside it (the first .copied).
  assert.match(await read('downloads.js'), /"data-copy": asset\.sha256[\s\S]*?class: "copied", role: "status"/);
  // The script copies on click, so Enter and Space on a button work, and says Copied.
  const js = await read('copy.js');
  assert.match(js, /button\[data-copy-from\]/);
  assert.match(js, /"Copied"/);
  assert.doesNotMatch(await read('downloads.js'), /innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function/);
});

test('no page has inline script or style, and every file it loads exists', async () => {
  const pages = (await fs.readdir(publicDir)).filter((n) => n.endsWith('.html'));
  assert.deepEqual(pages.sort(), ['downloads.html', 'index.html', 'join.html', 'status.html']);
  for (const name of pages) {
    const html = await read(name);
    assert.doesNotMatch(html, /<script(?![^>]*\ssrc=)/i, `${name}: inline script`);
    assert.doesNotMatch(html, /<script[^>]*\ssrc="[^"]*"[^>]*>\s*[^<\s]/i, `${name}: script with a body`);
    assert.doesNotMatch(html, /<style/i, `${name}: style element`);
    assert.doesNotMatch(html, /\sstyle\s*=/i, `${name}: style attribute`);
    assert.doesNotMatch(html, /\son[a-z]+\s*=/i, `${name}: event handler attribute`);
    assert.doesNotMatch(html, /javascript:/i, `${name}: javascript: link`);
    for (const [, url] of html.matchAll(/(?:src|href)="(\/[^"#?]*)"/g)) {
      if (url === '/' || ['/status', '/join', '/downloads', '/join-qr.svg', '/feed.xml'].includes(url)) continue;
      await fs.access(path.join(publicDir, url)).catch(() => assert.fail(`${name} loads ${url}, which does not exist`));
    }
    // Same-origin only: no third party scripts, styles or images.
    for (const [, url] of html.matchAll(/<(?:script|link|img)[^>]*\s(?:src|href)="(https?:[^"]+)"/g)) assert.fail(`${name} loads ${url} from another origin`);
  }
});

test('the nav on every page lists Join and Downloads, and marks only the current page', async () => {
  const expected = { 'index.html': '/', 'status.html': '/status', 'join.html': '/join', 'downloads.html': '/downloads' };
  for (const [name, current] of Object.entries(expected)) {
    const html = await read(name);
    const nav = /<nav class="links"[^>]*>([\s\S]*?)<\/nav>/.exec(html)[1];
    assert.match(nav, /<a href="\/join"/, name);
    assert.match(nav, /<a href="\/downloads"/, name);
    const marked = [...nav.matchAll(/<a href="([^"]+)"[^>]*aria-current="page"/g)].map((m) => m[1]);
    assert.deepEqual(marked, [current], name);
    assert.match(html, /<footer>[\s\S]*href="\/join"[\s\S]*href="\/downloads"/, `${name}: footer`);
  }
  const home = await read('index.html');
  assert.match(home, /class="btn primary" href="\/downloads"/);
  assert.match(home, /class="btn" href="\/join"/);
});

test('/api/releases serves the cache and nothing else, for GET and HEAD', async () => {
  let reads = 0;
  const releases = {
    snapshot() {
      reads++;
      return SNAPSHOT;
    },
  };
  const s = await start({ releases });
  try {
    const res = await fetch(`${s.base}/api/releases`);
    assert.equal(res.status, 200);
    assert.equal(res.headers.get('content-type'), 'application/json; charset=utf-8');
    assert.equal(res.headers.get('cache-control'), 'no-store');
    assertSecurityHeaders(res, 'api');
    assert.deepEqual(await res.json(), SNAPSHOT);
    const head = await raw(s.port, '/api/releases', 'HEAD');
    assert.equal(head.status, 200);
    assert.equal(head.body, '');
    assert.equal(head.headers['cache-control'], 'no-store');
    for (const method of ['POST', 'PUT', 'DELETE', 'PATCH']) {
      const r = await raw(s.port, '/api/releases', method);
      assert.equal(r.status, 405, method);
      assert.equal(r.headers.allow, 'GET, HEAD');
    }
    // Query strings are ignored: a visitor cannot choose a repository or ask for a refresh.
    const q = await fetch(`${s.base}/api/releases?repo=evil/x&refresh=1`);
    assert.deepEqual(await q.json(), SNAPSHOT);
    assert.equal(reads, 3);
  } finally {
    await s.close();
  }
});

test('/api/releases without a release cache is a 404 with a JSON error', async () => {
  const s = await start();
  try {
    const res = await fetch(`${s.base}/api/releases`);
    assert.equal(res.status, 404);
    assert.equal(res.headers.get('cache-control'), 'no-store');
    assert.deepEqual(await res.json(), { error: 'releases are not available' });
  } finally {
    await s.close();
  }
});

test('the Docker image copies every folder the new files are in', async () => {
  const dockerfile = await fs.readFile(path.join(root, 'Dockerfile'), 'utf8');
  for (const line of ['COPY server.js ./', 'COPY lib ./lib', 'COPY public ./public']) assert.ok(dockerfile.includes(line), line);
  for (const file of ['lib/qr.js', 'lib/join.js', 'lib/releases.js', 'public/join.html', 'public/downloads.html', 'public/downloads.js']) await fs.access(path.join(root, file));
  const ignore = await fs.readFile(path.join(root, '.dockerignore'), 'utf8');
  assert.doesNotMatch(ignore, /^(lib|public|server\.js)$/m);
});
