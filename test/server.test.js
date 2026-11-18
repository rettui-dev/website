import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Monitor } from '../lib/monitor.js';
import { createApp, resolveStatic } from '../lib/app.js';

const publicDir = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'public');

async function start() {
  const dataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'website-'));
  const monitor = new Monitor({
    targets: [{ host: 'a.test', port: 4242 }],
    dataDir,
    probeFn: async () => ({ up: true, ms: 9 }),
  });
  await monitor.checkAll();
  const server = createApp({ monitor, publicDir });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}`;
  return { base, port: server.address().port, close: () => new Promise((r) => (server.closeAllConnections(), server.close(r))) };
}

// fetch normalises ../ in URLs, so raw requests are sent with http.
function raw(port, requestPath, method = 'GET') {
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

test('/api/status has the expected shape', async () => {
  const s = await start();
  try {
    const res = await fetch(`${s.base}/api/status`);
    assert.equal(res.status, 200);
    assert.match(res.headers.get('content-type'), /^application\/json/);
    assert.equal(res.headers.get('cache-control'), 'no-store');
    const body = await res.json();
    assert.equal(body.overall, 'up');
    assert.equal(typeof body.checkedAt, 'string');
    assert.equal(body.intervalSeconds, 30);
    const h = body.hosts[0];
    assert.deepEqual(Object.keys(h).sort(), ['checks', 'error', 'history', 'host', 'lastChecked', 'latencyMs', 'port', 'status', 'uptimePercent']);
    assert.equal(h.host, 'a.test');
    assert.equal(h.latencyMs, 9);
    assert.deepEqual(Object.keys(h.history[0]).sort(), ['ms', 't', 'up']);
  } finally {
    await s.close();
  }
});

test('/healthz answers ok', async () => {
  const s = await start();
  try {
    const res = await fetch(`${s.base}/healthz`);
    assert.equal(res.status, 200);
    assert.equal(await res.text(), 'ok\n');
  } finally {
    await s.close();
  }
});

test('pages and assets are served with the right types and headers', async () => {
  const s = await start();
  try {
    const cases = [
      ['/', 'text/html; charset=utf-8'],
      ['/status', 'text/html; charset=utf-8'],
      ['/site.css', 'text/css; charset=utf-8'],
      ['/status.js', 'text/javascript; charset=utf-8'],
      ['/brand/wordmark.png', 'image/png'],
      ['/fonts/FiraCodeNerdFont-Regular-Text.woff2', 'font/woff2'],
    ];
    for (const [url, type] of cases) {
      const res = await fetch(s.base + url);
      assert.equal(res.status, 200, url);
      assert.equal(res.headers.get('content-type'), type, url);
      assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
      assert.match(res.headers.get('content-security-policy'), /default-src 'none'/);
      await res.arrayBuffer();
    }
    const font = await fetch(`${s.base}/fonts/FiraCodeNerdFont-Regular-Text.woff2`);
    assert.match(font.headers.get('cache-control'), /max-age=\d+/);
    await font.arrayBuffer();
  } finally {
    await s.close();
  }
});

test('path traversal is rejected', async () => {
  const s = await start();
  try {
    for (const p of ['/../package.json', '/%2e%2e/package.json', '/..%2fserver.js', '/fonts/../../server.js', '/%00', '/..%5cserver.js', '/%zz']) {
      const r = await raw(s.port, p);
      assert.ok([400, 404].includes(r.status), `${p} gave ${r.status}`);
      assert.doesNotMatch(r.body, /createApp|rettui-website/);
    }
  } finally {
    await s.close();
  }
});

test('missing files, directories and unknown types are 404', async () => {
  const s = await start();
  try {
    for (const p of ['/nope.html', '/fonts', '/fonts/']) {
      const res = await fetch(s.base + p);
      assert.equal(res.status, 404, p);
      await res.arrayBuffer();
    }
  } finally {
    await s.close();
  }
});

test('only GET and HEAD are allowed', async () => {
  const s = await start();
  try {
    const post = await raw(s.port, '/api/status', 'POST');
    assert.equal(post.status, 405);
    assert.equal(post.headers.allow, 'GET, HEAD');
    const head = await raw(s.port, '/', 'HEAD');
    assert.equal(head.status, 200);
    assert.equal(head.body, '');
  } finally {
    await s.close();
  }
});

test('resolveStatic stays inside the root', () => {
  const root = path.resolve('/srv/public');
  assert.equal(resolveStatic(root, '/'), path.join(root, 'index.html'));
  assert.equal(resolveStatic(root, '/status'), path.join(root, 'status.html'));
  assert.equal(resolveStatic(root, '/a/b.css'), path.join(root, 'a', 'b.css'));
  assert.equal(resolveStatic(root, '/../x'), null);
  assert.equal(resolveStatic(root, '/a/../../x'), null);
  assert.equal(resolveStatic(root, '/%2e%2e/x'), null);
  assert.equal(resolveStatic(root, '/a\0b'), null);
});
