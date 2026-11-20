import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import vm from 'node:vm';
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
  assert.deepEqual(pages.sort(), ['account.html', 'downloads.html', 'index.html', 'join.html', 'status.html', 'users.html']);
  for (const name of pages) {
    const html = await read(name);
    assert.doesNotMatch(html, /<script(?![^>]*\ssrc=)/i, `${name}: inline script`);
    assert.doesNotMatch(html, /<script[^>]*\ssrc="[^"]*"[^>]*>\s*[^<\s]/i, `${name}: script with a body`);
    assert.doesNotMatch(html, /<style/i, `${name}: style element`);
    assert.doesNotMatch(html, /\sstyle\s*=/i, `${name}: style attribute`);
    assert.doesNotMatch(html, /\son[a-z]+\s*=/i, `${name}: event handler attribute`);
    assert.doesNotMatch(html, /javascript:/i, `${name}: javascript: link`);
    for (const [, url] of html.matchAll(/(?:src|href)="(\/[^"#?]*)"/g)) {
      if (url === '/' || ['/status', '/join', '/downloads', '/account', '/users', '/join-qr.svg', '/feed.xml'].includes(url)) continue;
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

test('every page has the sign in button in the header, after the theme button, and loads account.js', async () => {
  for (const name of ['index.html', 'status.html', 'join.html', 'downloads.html', 'account.html', 'users.html']) {
    const html = await read(name);
    const header = /<header class="top">([\s\S]*?)<\/header>/.exec(html)[1];
    // Hidden until account.js has heard that the site has users; the words are in the file.
    assert.match(header, /<div class="signin" id="signin" hidden>\s*<span class="signin-name" id="signin-name" hidden><\/span>\s*<button id="signin-btn" type="button">Sign in<\/button>\s*<\/div>/, name);
    assert.ok(header.indexOf('id="theme-toggle"') < header.indexOf('id="signin"'), `${name}: the button comes last, at the right`);
    assert.match(html, /<script src="\/account\.js" defer><\/script>/, name);
  }
  // One dialog, made by the script, so no page carries its own copy.
  assert.doesNotMatch(await read('status.html'), /<dialog id="login"/);
  const js = await read('account.js');
  assert.doesNotMatch(js, /innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function/);
  assert.match(js, /\/api\/session/);
  assert.match(js, /\/login/);
  assert.match(js, /\/logout/);
});

test('account.js is served in a status-only site too (it is not a project file)', async () => {
  const { PROJECT_FILES } = await import('../lib/site.js');
  assert.equal(PROJECT_FILES.includes('account.js'), false);
});

test('the account scripts only set text, send the request header, and the sign in has a code step', async () => {
  const page = await read('account-page.js');
  assert.doesNotMatch(page, /innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function/);
  assert.match(page, /'X-Rettui-Request': '1'/);
  assert.match(page, /'Content-Type': 'application\/json'/);
  assert.match(page, /\/api\/account\/reauth/);
  // The QR code is drawn as SVG elements, never parsed from text.
  assert.match(page, /createElementNS\(SVG, 'svg'\)/);
  const js = await read('account.js');
  assert.match(js, /\/login\/code/);
  assert.match(js, /setAttribute\('inputmode', 'numeric'\)/);
  assert.match(js, /autocomplete = 'one-time-code'/);
  assert.match(js, /'Use a recovery code'/);
  assert.match(js, /link\.href = '\/account'/);
  // Sign in, the code step and sign out all go through post(), which sends the header.
  assert.match(js, /headers: \{ 'X-Rettui-Request': '1' \}/);
  assert.match(js, /post\('\/login', /);
  assert.match(js, /post\('\/login\/code', /);
  assert.match(js, /post\('\/logout', /);
  assert.doesNotMatch(js, /fetch\('\/(login|logout)/);
  // The sensitive changes go through the step-up dialog; set up asks it for the password only.
  assert.match(page, /confirmed\('\/api\/account\/totp\/setup', \{\}, \{[^}]*passwordOnly: true \}\)/);
  for (const p of ['/api/account/password', '/api/account/recovery-codes', '/api/account/totp/disable']) assert.match(page, new RegExp(`confirmed\\('${p.replace(/\//g, '\\/')}'`), p);
  assert.match(page, /\/api\/account\/sign-out-others/);
  const html = await read('account.html');
  // No inline box for the current password or a code: the pop-up asks, and the page says so.
  assert.doesNotMatch(html, /id="(pw-current|totp-setup-password|codes-new-secret|totp-disable-code)"/);
  assert.match(html, /a pop-up asks for your current password, and for a code from your app if two-step sign-in is on/);
  assert.match(html, /<script src="\/step-up\.js" defer><\/script>\s*<script src="\/account-page\.js" defer><\/script>/);
  assert.match(html, /<button id="sessions-end" type="button">Sign out other sessions<\/button>/);
  assert.match(html, /<input id="totp-enable-code" type="text" inputmode="numeric" autocomplete="one-time-code"/);
  assert.match(html, /<input id="pw-next" type="password" autocomplete="new-password"/);
  assert.match(html, /<meta name="robots" content="noindex">/);
});

test('the users page script only sets text, sends the request header, and asks before destructive changes', async () => {
  const js = await read('users-page.js');
  assert.doesNotMatch(js, /innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function/);
  assert.match(js, /'X-Rettui-Request': '1'/);
  assert.match(js, /'Content-Type': 'application\/json'/);
  for (const p of ['/api/users/create', '/api/users/role', '/api/users/delete', '/api/users/reset-password', '/api/users/reset-second-factor']) assert.ok(js.includes(`'${p}'`), p);
  // Every change goes through the step-up dialog, which says what it does; choices come first.
  assert.match(js, /window\.rettuiStepUp\.ask\(/);
  assert.match(js, /\$\('act'\)\.showModal\(\)/);
  assert.match(js, /navigator\.clipboard\.writeText\(\$\('users-otp-value'\)\.textContent\)/);
  const html = await read('users.html');
  assert.match(html, /<meta name="robots" content="noindex">/);
  assert.match(html, /<table class="users-table">/);
  assert.match(html, /<th scope="col">Actions<\/th>/);
  assert.match(html, /shown only now, and never again/);
  // The account page links to it, hidden until the server says this is an admin.
  assert.match(await read('account.html'), /<p id="acct-users" hidden><a href="\/users">Manage users<\/a>/);
  assert.match(await read('account-page.js'), /\$\('acct-users'\)\.hidden = data\.canManageUsers !== true/);
});

test('the step-up dialog asks for the password, and the code only with two-step sign-in on; it is built without markup', async () => {
  const js = await read('step-up.js');
  assert.doesNotMatch(js, /innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function/);
  // A modal dialog with a title, the words of what happens, and an error that is read out.
  assert.match(js, /el\('dialog', 'login'\)/);
  assert.match(js, /dlg\.showModal\(\)/);
  assert.match(js, /setAttribute\('aria-labelledby', 'stepup-title'\)/);
  assert.match(js, /err\.setAttribute\('aria-live', 'assertive'\)/);
  // The password, always.
  assert.match(js, /el\('label', null, 'Your password'\)/);
  assert.match(js, /pw\.type = 'password';\s*pw\.autocomplete = 'current-password';/);
  // The code: a numeric one-time-code field that password managers leave alone, and a recovery code instead.
  assert.match(js, /el\('label', null, 'Code from your app'\)/);
  assert.match(js, /code\.setAttribute\('inputmode', 'numeric'\)/);
  assert.match(js, /code\.pattern = '\[0-9\]\{6\}'/);
  assert.match(js, /i\.autocomplete = id === 'stepup-code' \? 'one-time-code' : 'off'/);
  assert.match(js, /\['data-bwignore', 'data-1p-ignore', 'data-lpignore'\]\.forEach/);
  assert.match(js, /'Use a recovery code instead'/);
  // Shown only with two-step sign-in on.
  assert.match(js, /\$\('stepup-code'\)\.hidden = !second \|\| on/);
  // Confirm and Cancel; Escape (cancel) and the backdrop close it; Tab stays inside; the focus goes back.
  assert.match(js, /el\('button', 'primary', 'Confirm'\)/);
  assert.match(js, /el\('button', null, 'Cancel'\)/);
  assert.match(js, /addEventListener\('cancel'/);
  assert.match(js, /e\.key !== 'Tab'/);
  assert.match(js, /s\.back\.focus\(\)/);
  // Loaded on both pages that use it, never inline.
  for (const name of ['account.html', 'users.html']) assert.match(await read(name), /<script src="\/step-up\.js" defer><\/script>/, name);
  // The users page confirms every change there, and asks for a code when the admin's two-step sign-in is on.
  const users = await read('users-page.js');
  assert.match(users, /secondFactor: Boolean\(data && data\.secondFactor\)/);
  assert.doesNotMatch(await read('users.html'), /id="(new-confirm|act-confirm)"/);
  // The code field of the sign in dialog keeps the password manager hints.
  assert.match(await read('account.js'), /\['data-bwignore', 'data-1p-ignore', 'data-lpignore'\]\.forEach\(function \(a\) \{ code\.setAttribute\(a, 'true'\); \}\)/);
});

// A few elements, enough for users-page.js to run in node:vm.
class FakeElement {
  constructor(id = null) {
    Object.assign(this, { id, hidden: false, value: '', checked: false, disabled: false, children: [], listeners: {}, attrs: {}, isConnected: true, text: '' });
  }
  get textContent() {
    return this.text;
  }
  set textContent(v) {
    this.text = String(v);
    this.children = [];
  }
  get firstChild() {
    return this.children[0] ?? null;
  }
  addEventListener(type, f) {
    (this.listeners[type] ??= []).push(f);
  }
  fire(type, event = {}) {
    for (const f of this.listeners[type] ?? []) f({ preventDefault() {}, ...event });
  }
  appendChild(c) {
    this.children.push(c);
    return c;
  }
  setAttribute(k, v) {
    this.attrs[k] = v;
  }
  focus() {}
  showModal() {}
  close() {
    this.fire('close');
  }
  all() {
    return [this, ...this.children.flatMap((c) => c.all())];
  }
}

test('the users page keeps its success message once the list is loaded again', async () => {
  const js = await read('users-page.js');
  const els = new Map();
  const byId = (id) => {
    if (!els.has(id)) els.set(id, new FakeElement(id));
    return els.get(id);
  };
  const users = { me: 'alice', secondFactor: false, roles: ['admin', 'manage', 'viewer'], users: [{ name: 'alice', role: 'admin', source: 'config', secondFactor: false, devices: 0 }, { name: 'carol', role: 'viewer', source: 'store', secondFactor: false, devices: 0 }] };
  const answer = (status, body) => Promise.resolve({ status, json: () => Promise.resolve(body) });
  const context = {
    document: { getElementById: byId, createElement: () => new FakeElement() },
    window: { rettuiStepUp: { ask: (o) => o.send({ password: 'pw' }) } },
    fetch: (url, opts) => (opts?.method === 'POST' ? answer(200, { ok: true }) : answer(200, users)),
    navigator: {},
    location: { assign() {} },
  };
  vm.runInNewContext(js, context);
  const settle = () => new Promise((r) => setTimeout(r, 10));
  await settle();
  const button = byId('users-rows').all().find((e) => e.attrs['aria-label'] === 'Change the role of carol');
  button.fire('click');
  byId('act-role').value = 'manage';
  byId('act-form').fire('submit');
  await settle();
  assert.equal(byId('users-status').textContent, 'carol now has the role manage.');
  assert.match(await read('users.html'), /<p id="users-status" class="note" role="status">/);
});
