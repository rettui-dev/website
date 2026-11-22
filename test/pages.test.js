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
  assert.deepEqual(pages.sort(), ['account.html', 'downloads.html', 'index.html', 'join.html', 'manage.html', 'status.html', 'users.html']);
  for (const name of pages) {
    const html = await read(name);
    assert.doesNotMatch(html, /<script(?![^>]*\ssrc=)/i, `${name}: inline script`);
    assert.doesNotMatch(html, /<script[^>]*\ssrc="[^"]*"[^>]*>\s*[^<\s]/i, `${name}: script with a body`);
    assert.doesNotMatch(html, /<style/i, `${name}: style element`);
    assert.doesNotMatch(html, /\sstyle\s*=/i, `${name}: style attribute`);
    assert.doesNotMatch(html, /\son[a-z]+\s*=/i, `${name}: event handler attribute`);
    assert.doesNotMatch(html, /javascript:/i, `${name}: javascript: link`);
    for (const [, url] of html.matchAll(/(?:src|href)="(\/[^"#?]*)"/g)) {
      if (url === '/' || ['/status', '/join', '/downloads', '/account', '/users', '/manage', '/join-qr.svg', '/feed.xml'].includes(url)) continue;
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
  for (const name of ['index.html', 'status.html', 'join.html', 'downloads.html', 'account.html', 'users.html', 'manage.html']) {
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
  assert.match(page, /confirmed\('\/api\/account\/totp\/setup', \{\}, \{[^}]*passwordOnly: !secondFactorOn\(\) \}\)/);
  for (const p of ['/api/account/password', '/api/account/recovery-codes', '/api/account/totp/disable']) assert.match(page, new RegExp(`confirmed\\('${p.replace(/\//g, '\\/')}'`), p);
  assert.match(page, /\/api\/account\/sign-out-others/);
  const html = await read('account.html');
  // No inline box for the current password or a code: the pop-up asks, and the page says so.
  assert.doesNotMatch(html, /id="(pw-current|totp-setup-password|codes-new-secret|totp-disable-code)"/);
  assert.match(html, /a pop-up asks for your current password, and for your passkey or a code from your app if two-step sign-in is on/);
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
  assert.match(js, /\$\('stepup-code'\)\.hidden = !second \|\| which !== 'code'/);
  // Confirm and Cancel; Escape (cancel) and the backdrop close it; Tab stays inside; the focus goes back.
  assert.match(js, /el\('button', 'primary', 'Confirm'\)/);
  assert.match(js, /el\('button', null, 'Cancel'\)/);
  assert.match(js, /addEventListener\('cancel'/);
  assert.match(js, /e\.key !== 'Tab'/);
  assert.match(js, /s\.back\.focus\(\)/);
  // Loaded on both pages that use it, never inline.
  for (const name of ['account.html', 'users.html', 'manage.html']) assert.match(await read(name), /<script src="\/step-up\.js" defer><\/script>/, name);
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
  focus() {
    FakeElement.active = this;
  }
  showModal() {
    this.open = true;
  }
  close() {
    this.open = false;
    this.fire('close');
  }
  all() {
    return [this, ...this.children.flatMap((c) => c.all())];
  }
  // For the sign in dialog, which looks at it before it shows anything.
  get offsetParent() {
    return {};
  }
  querySelectorAll() {
    return [];
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

// ---- passkeys in the browser: passkey.js, the step-up dialog, the sign in dialog, the account page ----

const settle = () => new Promise((r) => setTimeout(r, 10));

// A fake document: elements found by id from the body down (as the scripts that build their own
// dialogs need), or made on the first ask (as the pages that have their markup in the file need).
function makeDom({ prebuilt = false } = {}) {
  FakeElement.active = null;
  const body = new FakeElement('body');
  const made = new Map();
  const byId = (id) => {
    if (prebuilt) {
      if (!made.has(id)) made.set(id, new FakeElement(id));
      return made.get(id);
    }
    return body.all().find((e) => e.id === id) ?? null;
  };
  const document = {
    body,
    getElementById: byId,
    createElement: (tag) => Object.assign(new FakeElement(), { tag }),
    querySelectorAll: () => [],
    addEventListener() {},
    dispatchEvent() {},
    get activeElement() {
      return FakeElement.active;
    },
  };
  return { document, byId, body, made };
}

// A fetch that answers from a table of 'METHOD /path' -> [status, body] (or a function giving it).
function router(routes, log = []) {
  const fetch = (url, opts = {}) => {
    const method = opts.method ?? 'GET';
    log.push({ url, method, body: opts.body, headers: opts.headers });
    const route = routes[`${method} ${url}`];
    if (!route) return Promise.reject(new Error(`no route ${method} ${url}`));
    const [status, body] = typeof route === 'function' ? route(opts, log) : route;
    return Promise.resolve({ status, ok: status < 400, json: () => Promise.resolve(body) });
  };
  return { fetch, log };
}

const plain = (v) => JSON.parse(JSON.stringify(v));
const bytes = (...n) => Uint8Array.from(n);
const buf = (...n) => bytes(...n).buffer;
const array = (view) => Array.from(new Uint8Array(view));

function passkeyContext(extra = {}) {
  const calls = { create: [], get: [] };
  const credentials = {
    create: async (o) => (calls.create.push(o), extra.created === undefined ? null : extra.created),
    get: async (o) => (calls.get.push(o), extra.got === undefined ? null : extra.got),
  };
  const window = extra.window ?? { PublicKeyCredential: function PublicKeyCredential() {} };
  const context = { window, navigator: 'navigator' in extra ? extra.navigator : { credentials }, atob, btoa, Uint8Array, JSON, Promise, Error, Array, Object, String };
  return { context, calls, window };
}

async function loadPasskey(extra) {
  const p = passkeyContext(extra);
  vm.runInNewContext(await read('passkey.js'), p.context);
  return { ...p, api: p.window.rettuiPasskey };
}

test('passkey.js: supported() needs PublicKeyCredential and navigator.credentials, and nothing is inline', async () => {
  const js = await read('passkey.js');
  assert.doesNotMatch(js, /innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function/);
  assert.equal((await loadPasskey()).api.supported(), true);
  assert.equal((await loadPasskey({ window: {} })).api.supported(), false);
  assert.equal((await loadPasskey({ navigator: {} })).api.supported(), false);
  assert.equal((await loadPasskey({ navigator: { credentials: { get() {} } } })).api.supported(), false);
  // The page is in a context where navigator is missing altogether: still a plain false.
  assert.equal((await loadPasskey({ navigator: null })).api.supported(), false);
});

test('passkey.js: without the browser helpers, options and answers are converted by hand (base64url)', async () => {
  // Bytes that give '+', '/' and each amount of padding in base64.
  const vectors = [[[0xfb, 0xff, 0xfe], '-__-'], [[0xfb, 0xff], '-_8'], [[0xfb], '-w'], [[], '']];
  for (const [raw, text] of vectors) {
    const created = {
      id: 'abc',
      rawId: bytes(...raw).buffer,
      type: 'public-key',
      authenticatorAttachment: 'platform',
      getClientExtensionResults: () => ({ credProps: { rk: true } }),
      response: { clientDataJSON: bytes(1, 2, 3).buffer, attestationObject: bytes(...raw, 9).buffer, getTransports: () => ['internal', 'hybrid'] },
    };
    const { api, calls } = await loadPasskey({ created });
    const options = {
      rp: { name: 'rettui', id: 'site.test' },
      user: { id: text || 'AQ', name: 'alice', displayName: 'alice' },
      challenge: text || 'AQ',
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      excludeCredentials: [{ id: text || 'AQ', type: 'public-key', transports: ['usb'] }],
      timeout: 120000,
    };
    const answer = await api.create(options);
    const sent = calls.create[0].publicKey;
    const expected = text ? raw : [1];
    assert.deepEqual(array(sent.challenge), expected, text);
    assert.deepEqual(array(sent.user.id), expected, text);
    assert.deepEqual(array(sent.excludeCredentials[0].id), expected, text);
    assert.deepEqual(sent.excludeCredentials[0].transports, ['usb']);
    assert.equal(sent.rp.id, 'site.test');
    assert.equal(sent.timeout, 120000);
    assert.equal(answer.rawId, text);
    assert.equal(answer.id, 'abc');
    assert.equal(answer.type, 'public-key');
    assert.equal(answer.authenticatorAttachment, 'platform');
    assert.deepEqual(plain(answer.clientExtensionResults), { credProps: { rk: true } });
    assert.equal(answer.response.clientDataJSON, 'AQID');
    
    assert.deepEqual(array(Buffer.from(answer.response.attestationObject, 'base64url')), [...raw, 9]);
    for (const v of [answer.rawId, answer.response.clientDataJSON, answer.response.attestationObject]) assert.doesNotMatch(v, /[+/=]/);
    assert.deepEqual(plain(answer.response.transports), ['internal', 'hybrid']);
  }
});

test('passkey.js: a sign in answer by hand has the user handle only when the passkey has one', async () => {
  const make = (userHandle) => ({
    id: 'k1',
    rawId: buf(1, 2),
    type: 'public-key',
    getClientExtensionResults: () => ({}),
    response: { clientDataJSON: buf(0xfb), authenticatorData: buf(0xff, 0xfe), signature: buf(7, 8, 9), userHandle },
  });
  const options = { challenge: '-_8', rpId: 'site.test', allowCredentials: [{ id: '-__-', type: 'public-key' }], userVerification: 'required' };
  const withHandle = await loadPasskey({ got: make(buf(5)) });
  const answer = await withHandle.api.get(options);
  assert.deepEqual(array(withHandle.calls.get[0].publicKey.challenge), [0xfb, 0xff]);
  assert.deepEqual(array(withHandle.calls.get[0].publicKey.allowCredentials[0].id), [0xfb, 0xff, 0xfe]);
  assert.equal(withHandle.calls.get[0].publicKey.userVerification, 'required');
  assert.deepEqual(plain(answer.response), { clientDataJSON: '-w', authenticatorData: '__4', signature: 'BwgJ', userHandle: 'BQ' });
  assert.equal(answer.rawId, 'AQI');
  for (const none of [null, undefined]) {
    const w = await loadPasskey({ got: make(none) });
    assert.equal('userHandle' in (await w.api.get(options)).response, false);
  }
  // No allowCredentials at all is fine too.
  const open = await loadPasskey({ got: make(null) });
  await open.api.get({ challenge: 'AQ' });
  assert.deepEqual(plain(open.calls.get[0].publicKey.allowCredentials), []);
});

test('passkey.js: with PublicKeyCredential.parse*FromJSON and toJSON, the browser does the conversion', async () => {
  const seen = [];
  const PublicKeyCredential = function PublicKeyCredential() {};
  PublicKeyCredential.parseCreationOptionsFromJSON = (j) => (seen.push(['create', j]), { parsed: 'creation' });
  PublicKeyCredential.parseRequestOptionsFromJSON = (j) => (seen.push(['get', j]), { parsed: 'request' });
  const credential = { toJSON: () => ({ id: 'native', response: {} }), rawId: 'not touched', response: null };
  const { api, calls } = await loadPasskey({ window: { PublicKeyCredential }, created: credential, got: credential });
  assert.deepEqual(await api.create({ challenge: 'x' }), { id: 'native', response: {} });
  assert.deepEqual(await api.get({ challenge: 'y' }), { id: 'native', response: {} });
  assert.deepEqual(seen, [['create', { challenge: 'x' }], ['get', { challenge: 'y' }]]);
  assert.deepEqual({ ...calls.create[0].publicKey }, { parsed: 'creation' });
  assert.deepEqual({ ...calls.get[0].publicKey }, { parsed: 'request' });
});

test('passkey.js: a cancelled prompt rejects with NotAllowedError, and every other failure keeps its name', async () => {
  const cancel = Object.assign(new Error('The operation either timed out or was not allowed.'), { name: 'NotAllowedError' });
  const taken = Object.assign(new Error('already'), { name: 'InvalidStateError' });
  const w = await loadPasskey();
  assert.equal(w.api.cancelled(cancel), true);
  assert.equal(w.api.cancelled(taken), false);
  assert.equal(w.api.cancelled(null), false);
  assert.equal(w.api.cancelled(undefined), false);
  assert.equal(w.api.cancelled('NotAllowedError'), false);
  // The browser refuses: the rejection is the browser's own.
  const refuse = (error) => ({ navigator: { credentials: { create: () => Promise.reject(error), get: () => Promise.reject(error) } } });
  for (const [error, name] of [[cancel, 'NotAllowedError'], [taken, 'InvalidStateError']]) {
    const x = await loadPasskey(refuse(error));
    await assert.rejects(x.api.create({ challenge: 'AQ', user: { id: 'AQ' } }), { name });
    await assert.rejects(x.api.get({ challenge: 'AQ' }), { name });
  }
  // A throw instead of a rejection is a rejection too.
  const sync = await loadPasskey({ navigator: { credentials: { create() { throw taken; }, get() { throw taken; } } } });
  await assert.rejects(sync.api.get({ challenge: 'AQ' }), { name: 'InvalidStateError' });
  // No credential back (null) is a cancel.
  await assert.rejects(w.api.get({ challenge: 'AQ' }), { name: 'NotAllowedError' });
  await assert.rejects(w.api.create({ challenge: 'AQ', user: { id: 'AQ' } }), { name: 'NotAllowedError' });
  // No WebAuthn in this browser: a rejection, not a throw.
  const none = await loadPasskey({ window: {} });
  await assert.rejects(none.api.get({ challenge: 'AQ' }), { name: 'NotSupportedError' });
  await assert.rejects(none.api.create({ challenge: 'AQ', user: { id: 'AQ' } }), { name: 'NotSupportedError' });
  // Options that are not base64url do not reach the browser.
  await assert.rejects(w.api.get({ challenge: '***' }));
  assert.equal(w.calls.get.length, 1);
});

// ---- the step-up dialog ----

async function stepUp({ methods, secondFactor, passkey = {}, routes = {}, send } = {}) {
  const dom = makeDom();
  const log = [];
  const net = router(routes, log);
  const got = [];
  const rettuiPasskey = {
    supported: () => passkey.supported !== false,
    get: (o) => (got.push(o), passkey.error ? Promise.reject(passkey.error) : Promise.resolve({ id: 'cred-1', response: { signature: 'sig' } })),
    cancelled: (e) => Boolean(e) && e.name === 'NotAllowedError',
  };
  const window = { rettuiPasskey };
  vm.runInNewContext(await read('step-up.js'), { window, document: dom.document, fetch: net.fetch, JSON, Promise });
  const sent = [];
  const answers = [];
  const asking = window.rettuiStepUp.ask({
    title: 'Remove it',
    why: 'It goes.',
    action: 'Remove',
    methods,
    secondFactor,
    send: (fields) => (sent.push(plain(fields)), Promise.resolve(answers.length ? answers.shift() : send ? send(fields) : { status: 200, body: { ok: true } })),
  });
  let result = 'pending';
  asking.then((r) => (result = plain(r)));
  const $ = (id) => dom.byId(id);
  return { $, sent, log, got, answers, dom, result: () => result, asking };
}

const CHALLENGE = ['POST /api/account/passkeys/challenge', [200, { options: { challenge: 'AQID', rpId: 'site.test' } }]];

test('step-up: a user with a passkey is asked for the password and the passkey first, with the code and recovery links', async () => {
  const s = await stepUp({ methods: ['passkey', 'totp', 'recovery'], routes: Object.fromEntries([CHALLENGE]) });
  const { $ } = s;
  assert.equal($('stepup-code').hidden, true);
  assert.equal($('stepup-recovery').hidden, true);
  assert.equal($('stepup-use-passkey').hidden, true);
  assert.equal($('stepup-use-code').hidden, false);
  assert.equal($('stepup-use-recovery').hidden, false);
  assert.equal($('stepup-use-code').textContent, 'Use the code from your app instead');
  assert.equal($('stepup-use-recovery').textContent, 'Use a recovery code instead');
  assert.match($('stepup-why').textContent, /^It goes\. Enter your password, then confirm with your passkey\.$/);
  assert.equal(FakeElement.active.id, 'stepup-password');
  // Nothing is asked of the browser until the visitor presses Confirm.
  assert.equal(s.got.length, 0);
  assert.equal(s.log.length, 0);
  $('stepup-password').value = 'hunter2';
  $('stepup-form').fire('submit');
  await settle();
  assert.equal(s.log.length, 1);
  assert.equal(s.log[0].url, '/api/account/passkeys/challenge');
  assert.equal(s.log[0].headers['X-Rettui-Request'], '1');
  assert.equal(s.log[0].headers['Content-Type'], 'application/json');
  assert.deepEqual(s.got, [{ challenge: 'AQID', rpId: 'site.test' }]);
  assert.deepEqual(s.sent, [{ password: 'hunter2', passkey: { id: 'cred-1', response: { signature: 'sig' } } }]);
  assert.deepEqual(s.result(), { status: 200, body: { ok: true } });
  assert.equal($('stepup-password').value, '');
});

test('step-up: the links switch between the passkey, the app code and a recovery code, and the fields follow', async () => {
  const s = await stepUp({ methods: ['passkey', 'totp', 'recovery'], routes: Object.fromEntries([CHALLENGE]) });
  const { $ } = s;
  $('stepup-use-code').fire('click');
  assert.equal($('stepup-code').hidden, false);
  assert.equal(FakeElement.active.id, 'stepup-code');
  assert.equal($('stepup-use-passkey').hidden, false);
  assert.equal($('stepup-use-code').hidden, true);
  assert.equal($('stepup-use-recovery').hidden, false);
  $('stepup-use-recovery').fire('click');
  assert.equal($('stepup-recovery').hidden, false);
  assert.equal($('stepup-code').hidden, true);
  assert.equal(FakeElement.active.id, 'stepup-recovery');
  $('stepup-password').value = 'pw';
  $('stepup-recovery').value = ' abcd-efgh ';
  $('stepup-form').fire('submit');
  await settle();
  // A recovery code is sent as before, and the browser was never asked.
  assert.deepEqual(s.sent, [{ password: 'pw', recovery: 'abcd-efgh' }]);
  assert.equal(s.got.length, 0);
  assert.equal(s.log.length, 0);
});

test('step-up: without a passkey in methods it is the old dialog, and a bare secondFactor means the app code and recovery code', async () => {
  for (const opts of [{ methods: ['totp', 'recovery'] }, { secondFactor: true }]) {
    const s = await stepUp(opts);
    assert.equal(s.$('stepup-code').hidden, false);
    assert.equal(s.$('stepup-use-passkey').hidden, true);
    assert.equal(s.$('stepup-use-code').hidden, true);
    assert.equal(s.$('stepup-use-recovery').hidden, false);
    assert.match(s.$('stepup-why').textContent, /Enter your password and the code your app shows now\.$/);
    s.$('stepup-password').value = 'pw';
    s.$('stepup-code').value = '123 456';
    s.$('stepup-form').fire('submit');
    await settle();
    assert.deepEqual(s.sent, [{ password: 'pw', code: '123456' }]);
  }
  // Nothing to confirm with but the password.
  for (const opts of [{}, { methods: [] }, { secondFactor: false }]) {
    const s = await stepUp(opts);
    assert.equal(s.$('stepup-code').hidden, true);
    assert.equal(s.$('stepup-use-recovery').hidden, true);
    assert.match(s.$('stepup-why').textContent, /Enter your password\.$/);
    s.$('stepup-password').value = 'pw';
    s.$('stepup-form').fire('submit');
    await settle();
    assert.deepEqual(s.sent, [{ password: 'pw' }]);
  }
  // A user with only a passkey and recovery codes, and a browser that cannot do passkeys: recovery code, and it says why.
  const s = await stepUp({ methods: ['passkey', 'recovery'], passkey: { supported: false } });
  assert.equal(s.$('stepup-recovery').hidden, false);
  assert.equal(s.$('stepup-use-passkey').hidden, true);
  assert.match(s.$('stepup-why').textContent, /This browser cannot use your passkey\./);
});

test('step-up: a cancelled passkey prompt, or a user with no passkey, is said in the dialog and sends nothing', async () => {
  const cancelled = await stepUp({ methods: ['passkey', 'recovery'], routes: Object.fromEntries([CHALLENGE]), passkey: { error: Object.assign(new Error('x'), { name: 'NotAllowedError' }) } });
  cancelled.$('stepup-password').value = 'pw';
  cancelled.$('stepup-form').fire('submit');
  await settle();
  assert.equal(cancelled.$('stepup-error').textContent, 'The passkey was not used. Try again, or use another way to confirm.');
  assert.equal(cancelled.sent.length, 0);
  assert.equal(cancelled.result(), 'pending');
  // The button is back, with its words, and has the focus.
  assert.equal(cancelled.$('stepup-go').disabled, false);
  assert.equal(cancelled.$('stepup-go').textContent, 'Remove');
  assert.equal(FakeElement.active.id, 'stepup-go');
  assert.equal(cancelled.$('stepup-password').value, 'pw');

  const broken = await stepUp({ methods: ['passkey'], routes: Object.fromEntries([CHALLENGE]), passkey: { error: Object.assign(new Error('x'), { name: 'SecurityError' }) } });
  broken.$('stepup-password').value = 'pw';
  broken.$('stepup-form').fire('submit');
  await settle();
  assert.equal(broken.$('stepup-error').textContent, 'Could not use the passkey. Try again, or use another way to confirm.');

  const none = await stepUp({ methods: ['passkey', 'recovery'], routes: { 'POST /api/account/passkeys/challenge': [409, { error: 'You have no passkey to confirm with.' }] } });
  none.$('stepup-password').value = 'pw';
  none.$('stepup-form').fire('submit');
  await settle();
  assert.equal(none.$('stepup-error').textContent, 'You have no passkey to confirm with.');
  assert.equal(none.got.length, 0);
  assert.equal(none.sent.length, 0);

  const down = await stepUp({ methods: ['passkey'], routes: {} });
  down.$('stepup-password').value = 'pw';
  down.$('stepup-form').fire('submit');
  await settle();
  assert.equal(down.$('stepup-error').textContent, 'Could not reach the server. Try again.');
  assert.equal(down.$('stepup-go').disabled, false);
  // No password, nothing asked.
  const empty = await stepUp({ methods: ['passkey'], routes: Object.fromEntries([CHALLENGE]) });
  empty.$('stepup-form').fire('submit');
  assert.equal(empty.$('stepup-error').textContent, 'Enter your password.');
  assert.equal(empty.log.length, 0);
});

test('step-up: a wrong passkey stays in the dialog, a sign in that is too old asks the server for it with the password, and a second step the dialog did not know of is added', async () => {
  const wrong = await stepUp({ methods: ['passkey', 'recovery'], routes: Object.fromEntries([CHALLENGE]) });
  wrong.answers.push({ status: 400, body: { field: 'passkey', error: 'That passkey did not work. Try again.' } });
  wrong.$('stepup-password').value = 'pw';
  wrong.$('stepup-form').fire('submit');
  await settle();
  assert.equal(wrong.$('stepup-error').textContent, 'That passkey did not work. Try again.');
  assert.equal(wrong.result(), 'pending');
  assert.equal(wrong.$('stepup-password').attrs['aria-invalid'], 'false');
  assert.equal(FakeElement.active.id, 'stepup-go');
  // Try again: a new challenge each time.
  wrong.$('stepup-form').fire('submit');
  await settle();
  assert.equal(wrong.log.length, 2);
  assert.equal(wrong.result().status, 200);

  let tries = 0;
  const old = await stepUp({
    methods: ['passkey'],
    routes: {
      'POST /api/account/passkeys/challenge': () => (++tries === 1 ? [403, { reauth: true }] : [200, { options: { challenge: 'AQID' } }]),
      'POST /api/account/reauth': [200, { ok: true }],
    },
  });
  old.$('stepup-password').value = 'pw';
  old.$('stepup-form').fire('submit');
  await settle();
  assert.deepEqual(old.log.map((l) => l.url), ['/api/account/passkeys/challenge', '/api/account/reauth', '/api/account/passkeys/challenge']);
  assert.deepEqual(JSON.parse(old.log[1].body), { password: 'pw' });
  assert.equal(old.sent.length, 1);

  const badPw = await stepUp({
    methods: ['passkey'],
    routes: { 'POST /api/account/passkeys/challenge': [403, { reauth: true }], 'POST /api/account/reauth': [400, { error: 'That password is not right.' }] },
  });
  badPw.$('stepup-password').value = 'nope';
  badPw.$('stepup-form').fire('submit');
  await settle();
  assert.equal(badPw.$('stepup-error').textContent, 'That password is not right.');
  assert.equal(badPw.sent.length, 0);
  assert.equal(FakeElement.active.id, 'stepup-password');

  // The server wants a second step the page did not know of: the dialog learns the methods and shows the first.
  const late = await stepUp({ methods: [], routes: Object.fromEntries([CHALLENGE]) });
  late.answers.push({ status: 400, body: { field: 'code', secondFactor: true, methods: ['passkey', 'totp', 'recovery'], error: 'Confirm with your passkey, or enter the code from your app or a recovery code.' } });
  late.$('stepup-password').value = 'pw';
  late.$('stepup-form').fire('submit');
  await settle();
  assert.equal(late.$('stepup-error').textContent, 'Confirm with your passkey, or enter the code from your app or a recovery code.');
  assert.equal(late.$('stepup-code').hidden, true);
  assert.equal(late.$('stepup-use-code').hidden, false);
  late.$('stepup-form').fire('submit');
  await settle();
  assert.deepEqual(late.sent[1].passkey, { id: 'cred-1', response: { signature: 'sig' } });

  // A sign in that has ended closes the dialog with the answer, for the page to deal with.
  const out = await stepUp({ methods: ['passkey'], routes: { 'POST /api/account/passkeys/challenge': [401, { signIn: true }] } });
  out.$('stepup-password').value = 'pw';
  out.$('stepup-form').fire('submit');
  await settle();
  assert.deepEqual(out.result(), { status: 401, body: { signIn: true } });
  assert.equal(out.sent.length, 0);
});

test('step-up: Cancel gives null, and the code inputs keep the password manager hints', async () => {
  const s = await stepUp({ methods: ['passkey', 'totp'] });
  s.$('stepup-cancel').fire('click');
  await settle();
  assert.equal(s.result(), null);
  for (const id of ['stepup-code', 'stepup-recovery']) for (const a of ['data-bwignore', 'data-1p-ignore', 'data-lpignore']) assert.equal(s.$(id).attrs[a], 'true', `${id} ${a}`);
});

// ---- the sign in dialog ----

const OPTIONS = { challenge: 'AQID', rpId: 'site.test', allowCredentials: [{ id: 'AQ', type: 'public-key' }], userVerification: 'required' };

async function signIn({ login, passkeyAnswers = [], passkey = {} } = {}) {
  const dom = makeDom();
  for (const id of ['signin', 'signin-btn', 'signin-name']) dom.body.appendChild(Object.assign(new FakeElement(id), { hidden: id !== 'signin-btn' }));
  const log = [];
  const answers = [...passkeyAnswers];
  const net = router(
    {
      'GET /api/session': [200, { enabled: true, name: null }],
      'POST /login': [200, login],
      'POST /login/passkey': () => answers.shift() ?? [200, { ok: true, name: 'alice' }],
      'POST /login/code': [200, { ok: true, name: 'alice' }],
    },
    log
  );
  const got = [];
  const window = {
    rettuiPasskey: {
      supported: () => passkey.supported !== false,
      get: (o) => (got.push(o), passkey.errors?.length ? Promise.reject(passkey.errors.shift()) : Promise.resolve({ id: 'cred-1', response: { signature: 'sig' } })),
      cancelled: (e) => Boolean(e) && e.name === 'NotAllowedError',
    },
  };
  const context = { window, document: dom.document, fetch: net.fetch, location: { pathname: '/', assign() {} }, HTMLDialogElement: function HTMLDialogElement() {}, CustomEvent: class CustomEvent {}, URLSearchParams, JSON, Promise, Array, Object };
  vm.runInNewContext(await read('account.js'), context);
  await settle();
  const $ = dom.byId;
  $('signin-btn').fire('click');
  $('login-name').value = 'alice';
  $('login-password').value = 'pw';
  $('login-form').fire('submit');
  await settle();
  const form = (n) => Object.fromEntries(log[n].body.entries());
  return { $, log, got, window, form };
}

const SECOND = { secondFactor: true, pending: 'tok', methods: ['passkey', 'totp', 'recovery'], passkey: OPTIONS };

test('sign in: a user with a passkey gets a focused "Use your passkey" button, which the visitor presses; the prompt is not automatic', async () => {
  const s = await signIn({ login: SECOND });
  const { $ } = s;
  assert.equal($('login-code-form').hidden, false);
  assert.equal($('login-form').hidden, true);
  assert.equal($('login-passkey').tag, 'button');
  assert.equal($('login-passkey').type, 'button');
  assert.equal($('login-passkey').textContent, 'Use your passkey');
  assert.equal($('login-passkey').hidden, false);
  assert.equal($('login-code-submit').hidden, true);
  assert.equal($('login-code').hidden, true);
  assert.equal(FakeElement.active.id, 'login-passkey');
  assert.equal($('login-use-passkey').hidden, true);
  assert.equal($('login-use-code').hidden, false);
  assert.equal($('login-use-recovery').hidden, false);
  assert.equal($('login-use-code').textContent, 'Use the code from the app');
  assert.equal($('login-use-recovery').textContent, 'Use a recovery code');
  // Nothing was asked of the browser, and nothing sent to /login/passkey, before the click.
  assert.equal(s.got.length, 0);
  assert.equal(s.log.some((l) => l.url === '/login/passkey'), false);
  assert.equal($('login-password').value, '');

  $('login-passkey').fire('click');
  await settle();
  assert.deepEqual(s.got, [OPTIONS]);
  const sent = s.form(s.log.findIndex((l) => l.url === '/login/passkey'));
  assert.equal(sent.pending, 'tok');
  assert.deepEqual(JSON.parse(sent.credential), { id: 'cred-1', response: { signature: 'sig' } });
  const post = s.log.find((l) => l.url === '/login/passkey');
  assert.equal(post.headers['X-Rettui-Request'], '1');
  assert.equal(s.window.rettuiAccount.name(), 'alice');
  assert.equal($('login').open, false);
});

test('sign in: a cancelled prompt is said, costs the server nothing, and the visitor can try again or use the code', async () => {
  const cancel = Object.assign(new Error('x'), { name: 'NotAllowedError' });
  const s = await signIn({ login: SECOND, passkey: { errors: [cancel] } });
  const { $ } = s;
  $('login-passkey').fire('click');
  await settle();
  assert.equal($('login-code-error').textContent, 'The passkey was not used. Try again, or use another way to sign in.');
  assert.equal(s.log.some((l) => l.url === '/login/passkey'), false);
  assert.equal($('login-passkey').disabled, false);
  assert.equal($('login-passkey').textContent, 'Use your passkey');
  assert.equal(FakeElement.active.id, 'login-passkey');
  // The second press works, with the same options and token.
  $('login-passkey').fire('click');
  await settle();
  assert.equal(s.got.length, 2);
  assert.equal(s.window.rettuiAccount.name(), 'alice');

  const other = await signIn({ login: SECOND, passkey: { errors: [Object.assign(new Error('x'), { name: 'SecurityError' })] } });
  other.$('login-passkey').fire('click');
  await settle();
  assert.equal(other.$('login-code-error').textContent, 'Could not use the passkey. Try again, or use another way to sign in.');

  // The fallbacks: the app code, and the recovery code, then the passkey again.
  const t = await signIn({ login: SECOND });
  t.$('login-use-code').fire('click');
  assert.equal(t.$('login-passkey').hidden, true);
  assert.equal(t.$('login-code-submit').hidden, false);
  assert.equal(t.$('login-code').hidden, false);
  assert.equal(t.$('login-use-passkey').hidden, false);
  assert.equal(t.$('login-use-code').hidden, true);
  assert.equal(FakeElement.active.id, 'login-code');
  assert.equal(t.$('login-code').attrs['data-bwignore'], 'true');
  t.$('login-use-recovery').fire('click');
  assert.equal(t.$('login-recovery').hidden, false);
  assert.equal(t.$('login-code').hidden, true);
  assert.equal(t.$('login-recovery').attrs['data-1p-ignore'], 'true');
  assert.equal(FakeElement.active.id, 'login-recovery');
  t.$('login-recovery').value = 'abcd-efgh';
  t.$('login-code-form').fire('submit');
  await settle();
  const recovery = t.log.find((l) => l.url === '/login/code');
  assert.deepEqual(Object.fromEntries(recovery.body.entries()), { pending: 'tok', recovery: 'abcd-efgh' });
  assert.equal(t.got.length, 0);
});

test('sign in: a wrong passkey shows the server\'s words and uses the fresh options; an ended second step goes back to the password', async () => {
  const fresh = { ...OPTIONS, challenge: 'BAUG' };
  const s = await signIn({
    login: SECOND,
    passkeyAnswers: [[401, { error: 'That passkey did not work. Try again, or use another way to sign in.', passkey: fresh }], [401, { error: 'That sign in took too long. Start again.', restart: true }]],
  });
  const { $ } = s;
  $('login-passkey').fire('click');
  await settle();
  assert.equal($('login-code-error').textContent, 'That passkey did not work. Try again, or use another way to sign in.');
  assert.equal($('login-passkey').disabled, false);
  assert.equal($('login-code-form').hidden, false);
  assert.equal(FakeElement.active.id, 'login-passkey');
  $('login-passkey').fire('click');
  await settle();
  assert.deepEqual(s.got, [OPTIONS, fresh]);
  assert.equal($('login-form').hidden, false);
  assert.equal($('login-code-form').hidden, true);
  assert.equal($('login-error').textContent, 'That sign in took too long. Start again.');
  assert.equal(FakeElement.active.id, 'login-password');
  assert.equal(s.window.rettuiAccount.name(), null);
  // The throttle: the server's words, the dialog stays.
  const hot = await signIn({ login: SECOND, passkeyAnswers: [[429, { error: 'Too many tries. Wait a minute.' }]] });
  hot.$('login-passkey').fire('click');
  await settle();
  assert.equal(hot.$('login-code-error').textContent, 'Too many tries. Wait a minute.');
  assert.equal(hot.$('login-code-form').hidden, false);
});

test('sign in: no passkey in the answer, or a browser without passkeys, starts at the code with the old words', async () => {
  // An older server says nothing of methods.
  const old = await signIn({ login: { secondFactor: true, pending: 'tok' } });
  assert.equal(old.$('login-passkey').hidden, true);
  assert.equal(old.$('login-code').hidden, false);
  assert.equal(old.$('login-code-submit').hidden, false);
  assert.equal(old.$('login-use-passkey').hidden, true);
  assert.equal(old.$('login-use-code').hidden, true);
  assert.equal(old.$('login-use-recovery').hidden, false);
  assert.equal(FakeElement.active.id, 'login-code');
  assert.equal(old.$('login-code-why').textContent, 'Enter the 6-digit code from your authenticator app.');
  // A user with the app code only.
  const totp = await signIn({ login: { secondFactor: true, pending: 'tok', methods: ['totp', 'recovery'] } });
  assert.equal(totp.$('login-use-passkey').hidden, true);
  assert.equal(totp.$('login-code').hidden, false);
  // The browser cannot do passkeys.
  const old2 = await signIn({ login: SECOND, passkey: { supported: false } });
  assert.equal(old2.$('login-passkey').hidden, true);
  assert.equal(old2.$('login-use-passkey').hidden, true);
  assert.equal(old2.$('login-code').hidden, false);
  assert.match(old2.$('login-code-why').textContent, /This browser cannot use your passkey\.$/);
  // Passkeys that do not work at this address: the server says so, and sends no options.
  const away = await signIn({ login: { secondFactor: true, pending: 'tok', methods: ['totp', 'recovery'], passkeyUnavailable: true } });
  assert.match(away.$('login-code-why').textContent, /Your passkey does not work at this address\.$/);
  assert.equal(away.$('login-passkey').hidden, true);
  // Passkey and recovery codes only, in a browser without passkeys: straight to the recovery code.
  const only = await signIn({ login: { secondFactor: true, pending: 'tok', methods: ['passkey', 'recovery'], passkey: OPTIONS }, passkey: { supported: false } });
  assert.equal(only.$('login-recovery').hidden, false);
  assert.equal(FakeElement.active.id, 'login-recovery');
  // Cancel and open again: the password step, with the second step forgotten.
  old.$('login').close();
  old.$('signin-btn').fire('click');
  assert.equal(old.$('login-form').hidden, false);
  assert.equal(old.$('login-code-form').hidden, true);
});

// ---- the account page and the users page ----

const ACCOUNT = {
  name: 'alice',
  role: 'viewer',
  lastLogin: null,
  managedByConfig: false,
  canManageUsers: false,
  mustChangePassword: false,
  canChangePassword: true,
  totp: { enabled: false, recoveryCodesLeft: 0 },
  secondFactor: false,
  recoveryCodesLeft: 0,
  stepUpMethods: [],
  sessions: [],
  devices: [],
  passkeys: { available: true, reason: null, origin: 'https://site.test', rpId: 'site.test', max: 10, list: [] },
};
const KEY = { id: 'aaaa1111bbbb2222', name: 'Work laptop', created: '2026-11-01T10:00:00.000Z', lastUsed: null, synced: false, here: true };

async function accountPage({ account = ACCOUNT, routes = {}, ask, passkey = {} } = {}) {
  const dom = makeDom({ prebuilt: true });
  dom.byId('codes-box').hidden = true;
  dom.byId('totp-setup-box').hidden = true;
  dom.byId('passkey-add').textContent = 'Add a passkey';
  dom.byId('passkeys-note').textContent = /<p id="passkeys-note" class="note">([^<]*)<\/p>/.exec(await read('account.html'))[1];
  const state = { account: structuredClone(account) };
  const log = [];
  const net = router({ 'GET /api/account': () => [200, state.account], ...routes }, log);
  const asked = [];
  const created = [];
  const window = {
    rettuiPasskey: {
      supported: () => passkey.supported !== false,
      create: (o) => (created.push(o), passkey.error ? Promise.reject(passkey.error) : Promise.resolve({ id: 'new-cred', response: { attestationObject: 'att' } })),
      cancelled: (e) => Boolean(e) && e.name === 'NotAllowedError',
    },
    rettuiStepUp: {
      ask: (o) => (asked.push(o), ask ? ask(o) : o.send({ password: 'pw' })),
    },
  };
  const context = { window, document: dom.document, fetch: net.fetch, navigator: {}, location: { host: 'site.test' }, JSON, Promise, Array, Object, Date, Blob: function Blob() {}, URL: {}, setTimeout };
  vm.runInNewContext(await read('account-page.js'), context);
  await settle();
  const $ = dom.byId;
  const texts = (id) => $(id).all().map((e) => e.textContent).filter(Boolean);
  return { $, log, asked, created, state, texts, window };
}

const buttonOf = (page, label) => page.$('passkeys-list').all().find((e) => e.attrs['aria-label'] === label);

test('account page: the passkeys are listed with name, dates, synced or device-bound, and what is not usable at this address', async () => {
  const list = [
    KEY,
    { id: 'cccc3333dddd4444', name: 'Phone', created: '2026-11-02T10:00:00.000Z', lastUsed: '2026-11-03T10:00:00.000Z', synced: true, here: true },
    { id: 'eeee5555ffff6666', name: 'Old key', created: '2026-10-01T10:00:00.000Z', lastUsed: null, synced: false, here: false },
  ];
  const p = await accountPage({ account: { ...ACCOUNT, secondFactor: true, recoveryCodesLeft: 8, stepUpMethods: ['passkey', 'recovery'], passkeys: { ...ACCOUNT.passkeys, list } } });
  assert.equal(p.$('acct-passkeys').hidden, false);
  const items = p.$('passkeys-list').children;
  assert.equal(items.length, 3);
  const text = (li) => li.all().map((e) => e.textContent).join('|');
  assert.match(text(items[0]), /Work laptop/);
  assert.match(text(items[0]), /Added .*last used never\. Device-bound/);
  assert.doesNotMatch(text(items[0]), /Not usable/);
  assert.match(text(items[1]), /Phone/);
  assert.match(text(items[1]), /Synced: also on your other devices/);
  assert.doesNotMatch(text(items[1]), /last used never/);
  assert.match(text(items[2]), /Not usable at this address\./);
  // Every button names its passkey, for a screen reader and for voice control.
  for (const k of list) {
    assert.ok(buttonOf(p, `Rename the passkey ${k.name}`), k.name);
    assert.ok(buttonOf(p, `Remove the passkey ${k.name}`), k.name);
  }
  assert.equal(p.$('passkeys-none').hidden, true);
  assert.equal(p.$('passkeys-unavailable').hidden, true);
  assert.equal(p.$('passkey-add-form').hidden, false);
  assert.equal(p.$('passkeys-full').hidden, true);
  // Recovery codes show for any second step; the app code is off.
  assert.equal(p.$('acct-recovery').hidden, false);
  assert.equal(p.$('codes-left').textContent, '8 recovery codes left.');
  assert.equal(p.$('codes-on').hidden, false);
  assert.equal(p.$('totp-on').hidden, true);
  assert.equal(p.$('totp-off').hidden, false);
  assert.match(p.$('totp-state').textContent, /^Off: no app code is set up\. Your passkeys are your second step\.$/);
  // No second step and no passkeys: no recovery codes card, the add form is there.
  const none = await accountPage();
  assert.equal(none.$('acct-recovery').hidden, true);
  assert.equal(none.$('passkeys-none').hidden, false);
  assert.equal(none.$('passkey-add-form').hidden, false);
  assert.equal(none.$('totp-state').textContent, 'Off: your password alone signs you in.');
});

test('account page: no site address gives the reason and no add form; the maximum and a browser without passkeys say so', async () => {
  const away = await accountPage({ account: { ...ACCOUNT, passkeys: { available: false, reason: 'no-address', origin: null, rpId: null, max: 10, list: [{ ...KEY, here: false }] } } });
  assert.equal(away.$('passkeys-unavailable').hidden, false);
  assert.equal(away.$('passkeys-unavailable').textContent, "Passkeys need this site's https address in the config file (site.url, or SITE_URL).");
  assert.equal(away.$('passkey-add-form').hidden, true);
  assert.equal(away.$('passkeys-browser').hidden, true);
  assert.match(away.$('passkeys-list').children[0].all().map((e) => e.textContent).join('|'), /Not usable at this address\./);
  // The one that is listed can still be removed.
  assert.ok(buttonOf(away, 'Remove the passkey Work laptop'));

  const many = Array.from({ length: 10 }, (_, i) => ({ ...KEY, id: `id${i}`, name: `Key ${i}` }));
  const full = await accountPage({ account: { ...ACCOUNT, secondFactor: true, passkeys: { ...ACCOUNT.passkeys, list: many } } });
  assert.equal(full.$('passkey-add-form').hidden, true);
  assert.equal(full.$('passkeys-full').hidden, false);
  assert.equal(full.$('passkeys-full').textContent, 'You have 10 passkeys, the most allowed. Remove one first.');

  const old = await accountPage({ passkey: { supported: false } });
  assert.equal(old.$('passkey-add-form').hidden, true);
  assert.equal(old.$('passkeys-browser').hidden, false);
  // An older server sends no passkeys at all: the card stays away.
  const { passkeys, ...before } = ACCOUNT;
  const older = await accountPage({ account: before });
  assert.equal(older.$('acct-passkeys').hidden, true);
  // A password an admin set: only the password change is there.
  const must = await accountPage({ account: { ...ACCOUNT, mustChangePassword: true } });
  assert.equal(must.$('acct-passkeys').hidden, true);
  assert.equal(must.$('acct-recovery').hidden, true);
});

test('account page: adding a passkey confirms first, makes it in the browser, and shows the recovery codes that come with the first one', async () => {
  const finished = [];
  const p = await accountPage({
    routes: {
      'POST /api/account/passkeys/begin': [200, { options: { challenge: 'AQID', user: { id: 'AQ' } } }],
      'POST /api/account/passkeys/finish': (o) => (finished.push(JSON.parse(o.body)), [200, { ok: true, passkey: KEY, recoveryCodes: ['aaaa-bbbb', 'cccc-dddd'] }]),
    },
  });
  p.$('passkey-name').value = '  Work laptop ';
  p.$('passkey-add-form').fire('submit');
  await settle();
  // The step-up has no second step to ask for (none is on), and says what it is for.
  assert.equal(p.asked.length, 1);
  assert.equal(p.asked[0].title, 'Add a passkey');
  assert.deepEqual(plain(p.asked[0].methods), []);
  assert.equal(p.asked[0].secondFactor, false);
  assert.deepEqual(p.log.filter((l) => l.method === 'POST').map((l) => l.url), ['/api/account/passkeys/begin', '/api/account/passkeys/finish']);
  assert.deepEqual(JSON.parse(p.log.find((l) => l.url.endsWith('/begin')).body), { password: 'pw' });
  assert.deepEqual(plain(p.created), [{ challenge: 'AQID', user: { id: 'AQ' } }]);
  assert.deepEqual(finished, [{ name: 'Work laptop', credential: { id: 'new-cred', response: { attestationObject: 'att' } } }]);
  assert.equal(p.log.find((l) => l.url.endsWith('/finish')).headers['X-Rettui-Request'], '1');
  // The codes are shown, with the focus on the button that says they are saved.
  assert.equal(p.$('codes-box').hidden, false);
  assert.deepEqual(p.$('codes-list').children.map((c) => c.textContent), ['aaaa-bbbb', 'cccc-dddd']);
  assert.equal(p.$('acct-recovery').hidden, false);
  assert.equal(p.$('codes-on').hidden, true);
  assert.equal(FakeElement.active.id, 'codes-done');
  assert.match(p.$('acct-status').textContent, /The passkey is added\. You are signed out everywhere else\./);
  assert.equal(p.$('passkey-name').value, '');
  assert.equal(p.$('passkey-add').disabled, false);
});

const NOTE_ALONE = "A passkey can sign you in on its own: press 'Sign in with a passkey' and confirm on your device. It also works as the second step after your password. Passkeys made on phones, computers and password managers usually work on their own. Some security keys only work as the second step: if yours does not show up, add it again here.";

test('account page: the passkeys note is true with signing in on its own off, and says how to use it when on', async () => {
  const html = await read('account.html');
  const fromFile = /<p id="passkeys-note" class="note">([^<]*)<\/p>/.exec(html)[1];
  // The file's words hold whichever way the site is set: they do not call a passkey only a second step.
  assert.doesNotMatch(fromFile, /is a second step/);
  assert.match(fromFile, /works as the second step after your password/);
  const on = await accountPage({ account: { ...ACCOUNT, passkeys: { ...ACCOUNT.passkeys, signIn: true } } });
  assert.equal(on.$('passkeys-note').textContent, NOTE_ALONE);
  for (const missing of [undefined, false]) {
    const off = await accountPage({ account: { ...ACCOUNT, passkeys: { ...ACCOUNT.passkeys, ...(missing === undefined ? {} : { signIn: false }) } } });
    assert.equal(off.$('passkeys-note').textContent, fromFile);
  }
  // Without the site address nothing can sign in, so the note does not promise it.
  const none = await accountPage({ account: { ...ACCOUNT, passkeys: { available: false, reason: 'no-address', origin: null, rpId: null, max: 10, signIn: true, list: [] } } });
  assert.equal(none.$('passkeys-note').textContent, fromFile);
});

test('account page: after a password change the page says passkeys still sign in, when they can, and not otherwise', async () => {
  const changed = (account) => accountPage({
    account,
    routes: { 'POST /api/account/password': [200, { ok: true }] },
  });
  const submit = async (p) => {
    p.$('pw-next').value = 'a long new password';
    p.$('pw-again').value = 'a long new password';
    p.$('pw-form').fire('submit');
    await settle();
  };
  const withKey = await changed({ ...ACCOUNT, canChangePassword: true, secondFactor: true, stepUpMethods: ['passkey', 'recovery'], passkeys: { ...ACCOUNT.passkeys, signIn: true, list: [KEY] } });
  await submit(withKey);
  assert.equal(withKey.$('acct-status').textContent, 'Your password is changed. You are signed out everywhere else. Your passkeys can still sign you in without the password. Check the list below and remove any you do not know.');
  assert.equal(withKey.$('pw-next').value, '');
  // No passkeys, signing in on its own off, or no site address: the old words only.
  for (const passkeys of [{ ...ACCOUNT.passkeys, signIn: true, list: [] }, { ...ACCOUNT.passkeys, signIn: false, list: [KEY] }, { ...ACCOUNT.passkeys, list: [KEY] }]) {
    const p = await changed({ ...ACCOUNT, canChangePassword: true, passkeys });
    await submit(p);
    assert.equal(p.$('acct-status').textContent, 'Your password is changed. You are signed out everywhere else.');
  }
});

test('account page: the box "also remove my other passkeys" shows only with passkeys, is off by default, and sends the flag only when ticked', async () => {
  const run = async (account, tick, answer) => {
    const p = await accountPage({ account, routes: { 'POST /api/account/password': [200, answer] } });
    if (tick) p.$('pw-remove').checked = true;
    p.$('pw-next').value = 'a long new password';
    p.$('pw-again').value = 'a long new password';
    p.$('pw-form').fire('submit');
    await settle();
    return { p, body: JSON.parse(p.log.find((l) => l.url === '/api/account/password').body) };
  };
  const withKeys = { ...ACCOUNT, canChangePassword: true, passkeys: { ...ACCOUNT.passkeys, signIn: true, list: [KEY, { ...KEY, id: 'other' }] } };
  const html = await read('account.html');
  assert.match(html, /<input id="pw-remove" type="checkbox"/);
  assert.doesNotMatch(/<input id="pw-remove"[^>]*checked/.exec(html)?.[0] ?? '', /checked/);
  const off = await run(withKeys, false, { ok: true });
  assert.equal(off.p.$('pw-remove-box').hidden, false);
  assert.equal(off.p.$('pw-remove').checked, false);
  assert.equal(Object.hasOwn(off.body, 'removeOtherPasskeys'), false);
  const on = await run(withKeys, true, { ok: true, removedPasskeys: 1 });
  assert.equal(on.body.removeOtherPasskeys, true);
  assert.match(on.p.$('acct-status').textContent, /Your password is changed\. You are signed out everywhere else\. 1 passkey was removed\./);
  const many = await run(withKeys, true, { ok: true, removedPasskeys: 3 });
  assert.match(many.p.$('acct-status').textContent, /3 passkeys were removed\./);
  // Without passkeys there is nothing to remove: the box is hidden and never sent.
  const none = await run({ ...ACCOUNT, canChangePassword: true, passkeys: { ...ACCOUNT.passkeys, list: [] } }, true, { ok: true });
  assert.equal(none.p.$('pw-remove-box').hidden, true);
  assert.equal(Object.hasOwn(none.body, 'removeOtherPasskeys'), false);
});

test('account page: a later passkey has no codes and no sign out; a user with a second step confirms with it; no name is sent when none is typed', async () => {
  const finished = [];
  const account = { ...ACCOUNT, secondFactor: true, totp: { enabled: true, recoveryCodesLeft: 3 }, recoveryCodesLeft: 3, stepUpMethods: ['totp', 'recovery'] };
  const p = await accountPage({
    account,
    routes: {
      'POST /api/account/passkeys/begin': [200, { options: { challenge: 'AQID' } }],
      'POST /api/account/passkeys/finish': (o) => (finished.push(JSON.parse(o.body)), [200, { ok: true, passkey: KEY }]),
    },
  });
  p.$('passkey-add-form').fire('submit');
  await settle();
  assert.deepEqual(p.asked[0].methods, ['totp', 'recovery']);
  assert.equal(p.asked[0].secondFactor, true);
  assert.deepEqual(Object.keys(finished[0]), ['credential']);
  assert.equal(p.$('codes-box').hidden, true);
  assert.equal(p.$('acct-status').textContent, 'The passkey is added.');
  assert.equal(FakeElement.active.id, 'acct-passkeys-h');
});

test('account page: adding a passkey that is cancelled, already there, refused or too old says so and leaves the page as it was', async () => {
  const setup = (error, finish) => accountPage({
    passkey: { error },
    routes: {
      'POST /api/account/passkeys/begin': [200, { options: { challenge: 'AQID' } }],
      'POST /api/account/passkeys/finish': finish ?? [200, { ok: true }],
    },
  });
  const fill = async (p) => {
    p.$('passkey-add-form').fire('submit');
    await settle();
    return p.$('passkey-add-error').textContent;
  };
  const cancelled = await setup(Object.assign(new Error('x'), { name: 'NotAllowedError' }));
  assert.equal(await fill(cancelled), 'The passkey was not added. Try again when you are ready.');
  assert.equal(cancelled.log.some((l) => l.url.endsWith('/finish')), false);
  assert.equal(FakeElement.active.id, 'passkey-name');
  assert.equal(cancelled.$('passkey-add').disabled, false);
  assert.equal(cancelled.$('passkey-add').textContent, 'Add a passkey');
  assert.equal(await fill(await setup(Object.assign(new Error('x'), { name: 'InvalidStateError' }))), 'This passkey is added already.');
  assert.equal(await fill(await setup(Object.assign(new Error('x'), { name: 'SecurityError' }))), 'The passkey could not be made on this device. Try another one.');
  for (const [status, text] of [
    [400, 'The passkey could not be checked, so it was not added. Try again.'],
    [400, 'This security key sent a certificate, which this site does not accept. Try another passkey.'],
    [409, 'This passkey is added already.'],
    [409, 'You have 10 passkeys, the most allowed. Remove one first.'],
    [409, 'Adding the passkey took too long, or something changed meanwhile. Start again.'],
  ]) {
    assert.equal(await fill(await setup(undefined, [status, { error: text }])), text);
  }
  // A name the server refuses is marked on the field.
  const named = await setup(undefined, [400, { error: 'Give the passkey a name of up to 64 characters.', field: 'name' }]);
  await fill(named);
  assert.equal(named.$('passkey-name').attrs['aria-invalid'], 'true');
  // Begin refused (site address missing, or full): said, and the browser was never asked.
  const begin = await accountPage({ routes: { 'POST /api/account/passkeys/begin': [409, { error: "Passkeys need this site's https address in the config file (site.url, or SITE_URL)." }] } });
  assert.match(await fill(begin), /^Passkeys need this site's https address/);
  assert.equal(begin.created.length, 0);
  // A name that is too long is caught before anything is asked.
  const long = await setup();
  long.$('passkey-name').value = 'x'.repeat(65);
  long.$('passkey-add-form').fire('submit');
  await settle();
  assert.equal(long.$('passkey-add-error').textContent, 'Give the passkey a name of up to 64 characters.');
  assert.equal(long.asked.length, 0);
  assert.equal(long.log.filter((l) => l.method === 'POST').length, 0);
  // The step-up given up: nothing happens.
  const quit = await accountPage({ ask: () => Promise.resolve(null) });
  quit.$('passkey-add-form').fire('submit');
  await settle();
  assert.equal(quit.created.length, 0);
  assert.equal(quit.$('passkey-add').disabled, false);
});

test('account page: removing a passkey asks for a second step, says when it is the last one, and tells what happened', async () => {
  const account = { ...ACCOUNT, secondFactor: true, recoveryCodesLeft: 8, stepUpMethods: ['passkey', 'recovery'], passkeys: { ...ACCOUNT.passkeys, list: [KEY] } };
  const p = await accountPage({
    account,
    routes: { 'POST /api/account/passkeys/remove': () => ((p.state.account = { ...ACCOUNT }), [200, { ok: true, secondFactorOff: true }]) },
  });
  buttonOf(p, 'Remove the passkey Work laptop').fire('click');
  await settle();
  assert.equal(p.asked[0].title, 'Remove the passkey Work laptop');
  assert.equal(p.asked[0].danger, true);
  assert.deepEqual(p.asked[0].methods, ['passkey', 'recovery']);
  assert.match(p.asked[0].why, /only second step.*turns off.*recovery codes stop working/);
  assert.deepEqual(JSON.parse(p.log.find((l) => l.url.endsWith('/remove')).body), { id: KEY.id, password: 'pw' });
  assert.equal(p.$('acct-status').textContent, 'The passkey is removed. Two-step sign-in is now off. You are signed out everywhere else.');
  assert.equal(p.$('acct-recovery').hidden, true);
  assert.equal(p.$('passkeys-none').hidden, false);
  assert.equal(FakeElement.active.id, 'acct-passkeys-h');

  // Another second step remains: it does not say it is the last.
  const two = await accountPage({ account: { ...account, totp: { enabled: true, recoveryCodesLeft: 8 } }, routes: { 'POST /api/account/passkeys/remove': [200, { ok: true, secondFactorOff: false }] } });
  buttonOf(two, 'Remove the passkey Work laptop').fire('click');
  await settle();
  assert.doesNotMatch(two.asked[0].why, /only second step/);
  assert.equal(two.$('acct-status').textContent, 'The passkey is removed. You are signed out everywhere else.');
  // An error from the server is said; a step-up that is given up does nothing.
  const bad = await accountPage({ account, routes: { 'POST /api/account/passkeys/remove': [409, { error: 'That passkey is not there.' }] } });
  buttonOf(bad, 'Remove the passkey Work laptop').fire('click');
  await settle();
  assert.equal(bad.$('acct-status').textContent, 'That passkey is not there.');
  const quit = await accountPage({ account, ask: () => Promise.resolve(null) });
  buttonOf(quit, 'Remove the passkey Work laptop').fire('click');
  await settle();
  assert.equal(quit.log.filter((l) => l.method === 'POST').length, 0);
});

test('account page: a passkey is renamed in place, with the name checked, and Cancel gives the focus back', async () => {
  const account = { ...ACCOUNT, secondFactor: true, stepUpMethods: ['passkey'], passkeys: { ...ACCOUNT.passkeys, list: [KEY] } };
  const p = await accountPage({ account, routes: { 'POST /api/account/passkeys/rename': [200, { ok: true }] } });
  buttonOf(p, 'Rename the passkey Work laptop').fire('click');
  const li = p.$('passkeys-list').children[0];
  const input = li.all().find((e) => e.tag === 'input');
  const label = li.all().find((e) => e.tag === 'label');
  assert.equal(label.textContent, 'New name for the passkey Work laptop');
  assert.equal(label.htmlFor, input.id);
  assert.equal(input.value, 'Work laptop');
  assert.equal(input.maxLength, 64);
  assert.equal(FakeElement.active, input);
  const form = li.all().find((e) => e.tag === 'form');
  const error = li.all().find((e) => e.attrs.role === 'alert');
  // Empty, too long, and with a control character: said, nothing sent.
  for (const bad of ['  ', 'y'.repeat(65), 'a\u0007b']) {
    input.value = bad;
    form.fire('submit');
    await settle();
    assert.equal(error.textContent, 'Give the passkey a name of up to 64 characters.', JSON.stringify(bad));
    assert.equal(input.attrs['aria-invalid'], 'true');
  }
  assert.equal(p.log.filter((l) => l.method === 'POST').length, 0);
  input.value = ' Desk ';
  form.fire('submit');
  await settle();
  assert.deepEqual(JSON.parse(p.log.find((l) => l.url.endsWith('/rename')).body), { id: KEY.id, name: 'Desk' });
  assert.equal(p.$('acct-status').textContent, 'The passkey is renamed.');
  // Cancel: the list is back, with the focus on the Rename button of that passkey.
  buttonOf(p, 'Rename the passkey Work laptop').fire('click');
  const again = p.$('passkeys-list').children[0];
  again.all().find((e) => e.textContent === 'Cancel').fire('click');
  assert.equal(FakeElement.active.attrs['aria-label'], 'Rename the passkey Work laptop');
  // The same name is not sent again.
  buttonOf(p, 'Rename the passkey Work laptop').fire('click');
  const third = p.$('passkeys-list').children[0];
  third.all().find((e) => e.tag === 'form').fire('submit');
  await settle();
  assert.equal(p.log.filter((l) => l.url.endsWith('/rename')).length, 1);
  // The server's refusal is said in the form.
  const refuse = await accountPage({ account, routes: { 'POST /api/account/passkeys/rename': [409, { error: 'That passkey is not there.' }] } });
  buttonOf(refuse, 'Rename the passkey Work laptop').fire('click');
  const item = refuse.$('passkeys-list').children[0];
  item.all().find((e) => e.tag === 'input').value = 'Other';
  item.all().find((e) => e.tag === 'form').fire('submit');
  await settle();
  assert.equal(item.all().find((e) => e.attrs.role === 'alert').textContent, 'That passkey is not there.');
});

test('account page: changes ask the step-up with the methods the server lists, and the app code setup asks for the password only when nothing else is on', async () => {
  const account = { ...ACCOUNT, secondFactor: true, totp: { enabled: false, recoveryCodesLeft: 0 }, recoveryCodesLeft: 4, stepUpMethods: ['passkey', 'recovery'], passkeys: { ...ACCOUNT.passkeys, list: [KEY] } };
  const p = await accountPage({ account, routes: { 'POST /api/account/recovery-codes': [200, { recoveryCodes: ['x-1', 'x-2'] }], 'POST /api/account/totp/setup': [200, { secret: 'ABCD', qr: null }] } });
  p.$('codes-new-form').fire('submit');
  await settle();
  assert.deepEqual(p.asked[0].methods, ['passkey', 'recovery']);
  assert.equal(p.asked[0].secondFactor, true);
  assert.deepEqual(p.$('codes-list').children.map((c) => c.textContent), ['x-1', 'x-2']);
  p.$('totp-setup-form').fire('submit');
  await settle();
  assert.equal(p.asked[1].title, 'Set up an app code');
  assert.deepEqual(p.asked[1].methods, ['passkey', 'recovery']);
  // Nothing else on: the password alone, as before.
  const plainAccount = await accountPage({ routes: { 'POST /api/account/totp/setup': [200, { secret: 'ABCD', qr: null }] } });
  plainAccount.$('totp-setup-form').fire('submit');
  await settle();
  assert.deepEqual(plain(plainAccount.asked[0].methods), []);
  assert.equal(plainAccount.asked[0].secondFactor, false);
  // An older server that only knows the app code: the dialog gets the code and recovery code.
  const { stepUpMethods, secondFactor, recoveryCodesLeft, passkeys, ...before } = { ...ACCOUNT, totp: { enabled: true, recoveryCodesLeft: 5 } };
  const older = await accountPage({ account: before, routes: { 'POST /api/account/recovery-codes': [200, { recoveryCodes: ['y-1'] }] } });
  assert.equal(older.$('codes-left').textContent, '5 recovery codes left.');
  assert.equal(older.$('acct-recovery').hidden, false);
  older.$('codes-new-form').fire('submit');
  await settle();
  assert.equal(older.asked[0].secondFactor, true);
  assert.equal(older.asked[0].methods.includes('totp'), true);
  // Turning the app code off with a passkey left says the passkey still works.
  const both = await accountPage({ account: { ...account, totp: { enabled: true, recoveryCodesLeft: 4 } }, routes: { 'POST /api/account/totp/disable': [200, { ok: true }] } });
  both.$('totp-disable-form').fire('submit');
  await settle();
  assert.equal(both.asked[0].title, 'Turn off the app code');
  assert.match(both.asked[0].why, /Your passkeys and recovery codes still work/);
});

test('users page: the passkey count and kinds show, and the reset says what it removes', async () => {
  const js = await read('users-page.js');
  const dom = makeDom({ prebuilt: true });
  const users = {
    me: 'alice',
    secondFactor: true,
    stepUpMethods: ['passkey', 'recovery'],
    roles: ['admin', 'manage', 'viewer'],
    users: [
      { name: 'alice', role: 'admin', source: 'config', secondFactor: true, totp: false, passkeys: 1, devices: 0 },
      { name: 'bob', role: 'viewer', source: 'store', secondFactor: true, totp: true, passkeys: 2, devices: 1 },
      { name: 'carol', role: 'viewer', source: 'store', secondFactor: true, totp: false, passkeys: 1, devices: 0 },
      { name: 'dave', role: 'viewer', source: 'store', secondFactor: true, totp: true, passkeys: 0, devices: 0 },
      { name: 'erin', role: 'viewer', source: 'store', secondFactor: false, totp: false, passkeys: 0, devices: 0 },
      { name: 'old', role: 'viewer', source: 'store', secondFactor: true, devices: 0 },
      { name: 'zed', role: 'admin', source: 'store', secondFactor: true, totp: true, passkeys: 1, devices: 2 },
    ],
  };
  const log = [];
  const asked = [];
  const net = router({ 'GET /api/users': [200, users], 'POST /api/users/reset-second-factor': [200, { ok: true }] }, log);
  const context = {
    document: dom.document,
    window: { rettuiStepUp: { ask: (o) => (asked.push(o), o.send({ password: 'pw' })) } },
    fetch: net.fetch,
    navigator: {},
    location: { assign() {} },
    JSON, Promise, Array, Object, Date,
  };
  vm.runInNewContext(js, context);
  await settle();
  const row = (name) => dom.byId('users-rows').children.find((tr) => tr.children[0].textContent.startsWith(name));
  const second = (name) => row(name).children.find((c) => c.attrs['data-label'] === 'Two-step sign-in').textContent;
  assert.equal(second('alice'), 'On: 1 passkey');
  assert.equal(second('bob'), 'On: app code, 2 passkeys');
  assert.equal(second('carol'), 'On: 1 passkey');
  assert.equal(second('dave'), 'On: app code');
  assert.equal(second('erin'), 'Off');
  assert.equal(second('old'), 'On');
  const reset = (name) => row(name).all().find((e) => e.attrs['aria-label'] === `Reset the two-step sign-in of ${name}`);
  assert.equal(reset('alice'), undefined);
  reset('bob').fire('click');
  await settle();
  assert.match(asked[0].why, /removes their app code, 2 passkeys, recovery codes and known devices, and signs them out everywhere\./);
  assert.deepEqual(asked[0].methods, ['passkey', 'recovery']);
  assert.equal(asked[0].secondFactor, true);
  reset('carol').fire('click');
  await settle();
  assert.match(asked[1].why, /removes their passkey, recovery codes and known devices,/);
  reset('old').fire('click');
  await settle();
  assert.match(asked[2].why, /removes their app code, recovery codes and known devices,/);
  // Another admin: no password or two-step reset, no role change and no delete here (the server
  // refuses them), and the page says where they are done.
  const labels = (name) => row(name).all().map((e) => e.attrs['aria-label']).filter(Boolean);
  assert.equal(reset('zed'), undefined);
  assert.equal(labels('zed').includes('Reset the password of zed'), false);
  assert.equal(labels('zed').includes('Change the role of zed'), false);
  assert.equal(labels('zed').includes('Delete zed'), false);
  assert.ok(labels('bob').includes('Delete bob'));
  assert.ok(labels('bob').includes('Reset the password of bob'));
  // The password reset dialog says the passkeys still sign the user in, and where they are removed.
  assert.match(await read('users-page.js'), /Their passkeys still sign them in without a password\. To stop those too, use Reset two-step sign-in, which removes them\./);
  const note = row('zed').all().find((e) => /users-admin-note/.test(e.className ?? ''));
  assert.match(note.textContent, /^Admins are reset, demoted and deleted on the server: scripts\/users\.js reset-password, reset-2fa, set-role or delete\.$/);
  assert.equal(row('bob').all().some((e) => /users-admin-note/.test(e.className ?? '')), false);
  assert.equal(row('alice').all().some((e) => /users-admin-note/.test(e.className ?? '')), false, 'not on their own row');
});

test('every page loads passkey.js, the pages with passkey controls do not use inline script, and the dialogs never start a prompt by themselves', async () => {
  for (const name of ['index.html', 'status.html', 'join.html', 'downloads.html', 'account.html', 'users.html', 'manage.html']) {
    const html = await read(name);
    assert.equal((html.match(/<script src="\/passkey\.js" defer><\/script>/g) ?? []).length, 1, name);
    // The sign in dialog (account.js) uses it on every page, so it comes first.
    assert.ok(html.indexOf('/passkey.js') < html.indexOf('/account.js'), name);
  }
  for (const name of ['passkey.js', 'account.js', 'step-up.js', 'account-page.js', 'users-page.js', 'manage-page.js']) {
    assert.doesNotMatch(await read(name), /innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function/, name);
  }
  // The only callers of get() and create() are click and submit handlers: a prompt needs a click in Safari.
  const sign = await read('account.js');
  assert.equal((sign.match(/rettuiPasskey\.get\(/g) ?? []).length, 2, 'the second step, and the passkey on its own');
  assert.match(sign, /key\.addEventListener\('click', usePasskey\)/);
  assert.match(sign, /alone\.addEventListener\('click', usePasskeyAlone\)/);
  assert.match(sign, /alone\.type = 'button'/);
  assert.match(sign, /post\('\/login\/passkey\/begin', /);
  assert.match(sign, /post\('\/login\/passkey\/finish', /);
  assert.match(sign, /key\.type = 'button'/);
  assert.match(sign, /post\('\/login\/passkey', /);
  assert.match(await read('step-up.js'), /\/api\/account\/passkeys\/challenge/);
  const page = await read('account-page.js');
  for (const p of ['/api/account/passkeys/begin', '/api/account/passkeys/finish', '/api/account/passkeys/rename', '/api/account/passkeys/remove']) assert.ok(page.includes(`'${p}'`), p);
});

// ---- the sign in dialog: "Sign in with a passkey" on its own ----

const ORIGIN_OK = 'https://site.test';

// The sign in dialog opened on a page, with the server saying passkeys alone are offered (session
// gives the fields of GET /api/session). routes answer the two POSTs; get is the fake browser's
// rettuiPasskey.get (a function giving a promise), supported what supported() says.
async function aloneDialog({ session = { passkeySignIn: true, passkeyOrigin: ORIGIN_OK }, origin = ORIGIN_OK, begin, finish, get, supported = true, noPasskeyJs = false } = {}) {
  const dom = makeDom();
  for (const id of ['signin', 'signin-btn', 'signin-name']) dom.body.appendChild(Object.assign(new FakeElement(id), { hidden: id !== 'signin-btn' }));
  const log = [];
  const net = router(
    {
      'GET /api/session': [200, { enabled: true, name: null, ...session }],
      ...(begin ? { 'POST /login/passkey/begin': begin } : {}),
      ...(finish ? { 'POST /login/passkey/finish': finish } : {}),
    },
    log
  );
  const got = [];
  const window = noPasskeyJs ? {} : {
    rettuiPasskey: {
      supported: () => supported,
      get: (o) => (got.push(o), get ? get(o) : Promise.resolve({ id: 'cred-1', response: { signature: 'sig' } })),
      cancelled: (e) => Boolean(e) && e.name === 'NotAllowedError',
    },
  };
  const context = { window, document: dom.document, fetch: net.fetch, location: { pathname: '/', origin, assign() {} }, HTMLDialogElement: function HTMLDialogElement() {}, CustomEvent: class CustomEvent {}, URLSearchParams, JSON, Promise, Array, Object };
  vm.runInNewContext(await read('account.js'), context);
  await settle();
  const $ = dom.byId;
  $('signin-btn').fire('click');
  const posts = () => log.filter((l) => l.method === 'POST');
  const form = (n) => Object.fromEntries(posts()[n].body.entries());
  return { $, log, got, window, posts, form };
}

const BEGUN = [200, { token: 'T'.repeat(43), options: { challenge: 'AQID', rpId: 'site.test', timeout: 120000, userVerification: 'required' }, expiresIn: 300 }];
const NO_PASSKEY_USED = 'No passkey was used. If yours did not show up, sign in with your name and password, then add a passkey on your account page.';
const NotAllowed = () => Object.assign(new Error('x'), { name: 'NotAllowedError' });

test('sign in with a passkey: an "or" and a real button under the form, only when the server, the address and the browser all allow it', async () => {
  const s = await aloneDialog({ begin: BEGUN });
  const b = s.$('login-passkey-only');
  assert.equal(b.tag, 'button');
  assert.equal(b.type, 'button', 'not a submit: Enter in the password field sends the password');
  assert.equal(b.textContent, 'Sign in with a passkey');
  assert.equal(b.hidden, false);
  assert.equal(b.disabled, false);
  assert.equal(s.$('login-or').tag, 'p');
  assert.equal(s.$('login-or').textContent, 'or');
  assert.equal(s.$('login-or').hidden, false);
  // It comes after the name and password actions, inside the same form.
  const kids = s.$('login-form').children.map((c) => c.id ?? c.className);
  assert.ok(kids.indexOf('login-passkey-only') > kids.indexOf('login-or'), kids.join());
  assert.ok(kids.indexOf('login-or') > kids.indexOf('login-error'));
  // Opening the dialog asks nothing of the browser.
  assert.equal(s.got.length, 0);
  assert.equal(s.posts().length, 0);

  const hidden = {
    'the server does not offer it': await aloneDialog({ session: {} }),
    'the server says false': await aloneDialog({ session: { passkeySignIn: false, passkeyOrigin: ORIGIN_OK } }),
    'a truthy word instead of true': await aloneDialog({ session: { passkeySignIn: 'yes', passkeyOrigin: ORIGIN_OK } }),
    'no address named': await aloneDialog({ session: { passkeySignIn: true } }),
    'this is another address': await aloneDialog({ origin: 'https://other.example.net' }),
    'the same host over http': await aloneDialog({ origin: 'http://site.test' }),
    'WebAuthn is missing': await aloneDialog({ supported: false }),
    'passkey.js did not load': await aloneDialog({ noPasskeyJs: true }),
  };
  for (const [why, d] of Object.entries(hidden)) {
    assert.equal(d.$('login-passkey-only').hidden, true, why);
    assert.equal(d.$('login-or').hidden, true, why);
    d.$('login-passkey-only').fire('click');
    await settle();
    assert.equal(d.posts().length, 0, `${why}: a click on it sends nothing`);
    assert.equal(d.got.length, 0, why);
  }
});

test('sign in with a passkey: begin, the browser prompt, finish; no name or password is sent, and the dialog closes signed in', async () => {
  let release;
  const wait = new Promise((r) => (release = r));
  const s = await aloneDialog({ begin: BEGUN, finish: [200, { ok: true, name: 'bob' }], get: () => wait });
  const b = s.$('login-passkey-only');
  s.$('login-name').value = 'typed';
  s.$('login-password').value = 'typed too';
  b.fire('click');
  // While the prompt is open: busy, said so, nothing else can start.
  assert.equal(b.disabled, true);
  assert.equal(b.textContent, 'Waiting for your passkey...');
  assert.equal(s.$('login-submit').disabled, true);
  await settle();
  assert.deepEqual(s.got, [BEGUN[1].options]);
  assert.equal(s.posts().length, 1);
  release({ id: 'cred-1', response: { signature: 'sig' } });
  await settle();
  assert.deepEqual(s.posts().map((p) => p.url), ['/login/passkey/begin', '/login/passkey/finish']);
  assert.equal(s.form(0).name, undefined);
  assert.deepEqual(Object.fromEntries(s.posts()[0].body.entries()), {}, 'begin sends nothing');
  const sent = s.form(1);
  assert.deepEqual(Object.keys(sent).sort(), ['credential', 'token'], 'no name, no password');
  assert.equal(sent.token, 'T'.repeat(43));
  assert.deepEqual(JSON.parse(sent.credential), { id: 'cred-1', response: { signature: 'sig' } });
  for (const p of s.posts()) {
    assert.equal(p.headers['X-Rettui-Request'], '1');
    assert.equal(p.method, 'POST');
  }
  assert.equal(s.window.rettuiAccount.name(), 'bob');
  assert.equal(s.$('login').open, false);
  assert.equal(s.$('login-password').value, '', 'the password field is emptied');
  assert.equal(b.disabled, false);
  assert.equal(b.textContent, 'Sign in with a passkey');
  assert.equal(s.$('login-submit').disabled, false);
});

test('sign in with a passkey: a cancelled prompt, or none on this device, says so in the alert line, marks no field, and sends nothing', async () => {
  const s = await aloneDialog({ begin: BEGUN, get: () => Promise.reject(NotAllowed()) });
  // An earlier wrong password had marked the fields.
  s.$('login-name').setAttribute('aria-invalid', 'true');
  s.$('login-password').setAttribute('aria-invalid', 'true');
  s.$('login-passkey-only').fire('click');
  await settle();
  assert.equal(s.$('login-error').textContent, NO_PASSKEY_USED);
  assert.equal(NO_PASSKEY_USED, 'No passkey was used. If yours did not show up, sign in with your name and password, then add a passkey on your account page.');
  assert.equal(s.$('login-error').attrs.role, 'alert');
  assert.notEqual(s.$('login-name').attrs['aria-invalid'], 'true');
  assert.notEqual(s.$('login-password').attrs['aria-invalid'], 'true');
  assert.equal(s.posts().length, 1, 'only begin: a cancelled prompt costs the server nothing more');
  assert.equal(s.$('login-passkey-only').disabled, false);
  assert.equal(s.$('login-passkey-only').textContent, 'Sign in with a passkey');
  assert.equal(FakeElement.active.id, 'login-passkey-only', 'the focus is back on the button');
  assert.equal(s.$('login').open, true);
  assert.equal(s.window.rettuiAccount.name(), null);
  // Another try starts again, and clears the old words first.
  s.$('login-passkey-only').fire('click');
  assert.equal(s.$('login-error').textContent, '');
  await settle();
  assert.equal(s.got.length, 2);

  const other = await aloneDialog({ begin: BEGUN, get: () => Promise.reject(Object.assign(new Error('x'), { name: 'SecurityError' })) });
  other.$('login-passkey-only').fire('click');
  await settle();
  assert.equal(other.$('login-error').textContent, 'This browser could not use a passkey. Sign in with your name and password.');
  assert.equal(FakeElement.active.id, 'login-passkey-only');
  // A browser that throws at once is the same.
  const thrown = await aloneDialog({ begin: BEGUN, get: () => { throw new Error('boom'); } });
  thrown.$('login-passkey-only').fire('click');
  await settle();
  assert.equal(thrown.$('login-passkey-only').disabled, false, 'no stuck busy state');
});

test('sign in with a passkey: the server\'s words are shown for 401, 429, 503 and 404, and an ended prompt starts cleanly on the next press', async () => {
  const answers = [
    [401, { error: 'That passkey did not work. Try again, or sign in with your name and password.' }],
    [401, { error: 'That took too long, or your connection changed. Try again.', restart: true }],
    [429, { error: 'Too many failed sign ins from here. Try again in 5 minutes.', retryAfter: 300 }],
    [503, { error: 'Signing in is not possible right now. Try again later.' }],
    [200, { ok: true, name: 'bob' }],
  ];
  const s = await aloneDialog({ begin: BEGUN, finish: () => answers.shift() });
  const b = s.$('login-passkey-only');
  const press = async () => {
    b.fire('click');
    await settle();
  };
  await press();
  assert.equal(s.$('login-error').textContent, 'That passkey did not work. Try again, or sign in with your name and password.');
  assert.equal(b.disabled, false);
  assert.equal(FakeElement.active.id, 'login-passkey-only');
  await press();
  assert.equal(s.$('login-error').textContent, 'That took too long, or your connection changed. Try again.');
  assert.equal(s.$('login-form').hidden, false, 'still the same form: nothing to go back to');
  await press();
  assert.equal(s.$('login-error').textContent, 'Too many failed sign ins from here. Try again in 5 minutes.');
  await press();
  assert.equal(s.$('login-error').textContent, 'Signing in is not possible right now. Try again later.');
  assert.equal(s.window.rettuiAccount.name(), null);
  // Every press is a new begin, with a new token: nothing is kept from the one that ended.
  await press();
  assert.equal(s.window.rettuiAccount.name(), 'bob');
  assert.equal(s.posts().filter((p) => p.url === '/login/passkey/begin').length, 5);
  assert.equal(s.got.length, 5);
  for (let n = 0; n < s.posts().length; n++) assert.equal(s.log.filter((l) => l.url === '/login/passkey/finish').length, 5);

  // Off on the server after the page loaded (404), and a begin that is paced (429): the words are shown, no prompt opens.
  const off = await aloneDialog({ begin: [404, { error: 'Signing in with a passkey alone is off on this site.' }] });
  off.$('login-passkey-only').fire('click');
  await settle();
  assert.equal(off.$('login-error').textContent, 'Signing in with a passkey alone is off on this site.');
  assert.equal(off.got.length, 0);
  const paced = await aloneDialog({ begin: [429, { error: 'Too many sign ins from here right now. Try again in 2 seconds.', retryAfter: 2 }] });
  paced.$('login-passkey-only').fire('click');
  await settle();
  assert.equal(paced.$('login-error').textContent, 'Too many sign ins from here right now. Try again in 2 seconds.');
  assert.equal(paced.got.length, 0);
  assert.equal(paced.$('login-passkey-only').disabled, false);
  // A begin answer without a prompt is not trusted.
  const odd = await aloneDialog({ begin: [200, { ok: true }] });
  odd.$('login-passkey-only').fire('click');
  await settle();
  assert.equal(odd.$('login-error').textContent, 'Could not sign in. Try again.');
  assert.equal(odd.got.length, 0);
});

test('sign in with a passkey: no network is said, at begin and at finish, and the button is usable again', async () => {
  // No route for begin: the fake fetch rejects, as a dropped connection does.
  const down = await aloneDialog({});
  down.$('login-passkey-only').fire('click');
  await settle();
  assert.equal(down.$('login-error').textContent, 'Could not reach the server. Try again.');
  assert.equal(down.$('login-passkey-only').disabled, false);
  assert.equal(down.$('login-passkey-only').textContent, 'Sign in with a passkey');
  assert.equal(FakeElement.active.id, 'login-passkey-only');
  // Begin works, finish does not.
  const half = await aloneDialog({ begin: BEGUN });
  half.$('login-passkey-only').fire('click');
  await settle();
  assert.equal(half.got.length, 1);
  assert.equal(half.$('login-error').textContent, 'Could not reach the server. Try again.');
  assert.equal(half.$('login-passkey-only').disabled, false);
  assert.equal(half.$('login-submit').disabled, false);
  assert.equal(half.window.rettuiAccount.name(), null);
});

test('sign in with a passkey: when the dialog is closed while the answer is on its way, a sign in that worked shows in the page, and one that did not shows nothing', async () => {
  const holder = {};
  const s = await aloneDialog({ begin: BEGUN, finish: () => (holder.s.$('login').close(), [200, { ok: true, name: 'bob' }]) });
  holder.s = s;
  s.$('login-passkey-only').fire('click');
  await settle();
  assert.equal(s.$('login').open, false);
  assert.equal(s.window.rettuiAccount.name(), 'bob', 'the server signed the browser in, so the page says so');
  assert.equal(s.$('login-passkey-only').disabled, false);
  // A refused answer after the close: nothing changes, nothing is said.
  const h2 = {};
  const t = await aloneDialog({ begin: BEGUN, finish: () => (h2.t.$('login').close(), [401, { error: 'That did not work.' }]) });
  h2.t = t;
  t.$('login-passkey-only').fire('click');
  await settle();
  assert.equal(t.window.rettuiAccount.name(), null);
  assert.equal(t.$('login-error').textContent, '');
});

test('sign in with a passkey: a double click opens one prompt, and closing the dialog while it is open ends the press, drops a late answer, and leaves nothing stuck', async () => {
  let release;
  const wait = new Promise((r) => (release = r));
  const s = await aloneDialog({ begin: BEGUN, finish: [200, { ok: true, name: 'bob' }], get: () => wait });
  const b = s.$('login-passkey-only');
  b.fire('click');
  b.fire('click');
  b.fire('click');
  await settle();
  assert.equal(s.posts().length, 1, 'one begin');
  assert.equal(s.got.length, 1, 'one prompt');
  // The password form is held off while the prompt is open.
  s.$('login-name').value = 'alice';
  s.$('login-password').value = 'pw';
  s.$('login-form').fire('submit');
  await settle();
  assert.equal(s.posts().length, 1);

  // Closed (Escape, Cancel, a click outside) while the browser still asks.
  s.$('login').close();
  assert.equal(b.disabled, false);
  assert.equal(b.textContent, 'Sign in with a passkey');
  assert.equal(s.$('login-submit').disabled, false);
  // The visitor confirms later: the answer is dropped, nobody is signed in.
  release({ id: 'late', response: { signature: 'sig' } });
  await settle();
  assert.equal(s.posts().length, 1, 'no finish for a dialog that was closed');
  assert.equal(s.window.rettuiAccount.name(), null);
  assert.equal(s.$('login-error').textContent, '');
  // Opened again, the password sign in works, and so does another press.
  s.$('signin-btn').fire('click');
  assert.equal(s.$('login').open, true);
  assert.equal(b.disabled, false);
  b.fire('click');
  await settle();
  assert.equal(s.got.length, 2);

  // Closed before the server answered begin: no prompt at all.
  const t = await aloneDialog({ begin: BEGUN, finish: [200, { ok: true, name: 'bob' }] });
  t.$('login-passkey-only').fire('click');
  t.$('login').close();
  await settle();
  assert.equal(t.got.length, 0, 'no prompt after the dialog was closed');
  assert.equal(t.$('login-passkey-only').disabled, false);
  assert.equal(t.window.rettuiAccount.name(), null);
});

test('sign in with a passkey: the password form still works, and a server error of it does not touch the passkey button', async () => {
  const s = await aloneDialog({ begin: BEGUN });
  const net = s.log;
  s.$('login-name').value = 'alice';
  s.$('login-password').value = 'wrong';
  const before = net.length;
  s.$('login-form').fire('submit');
  await settle();
  // The fake has no /login route: the old words for a dropped connection, and the fields marked, as before.
  assert.equal(s.$('login-error').textContent, 'Could not reach the server. Try again.');
  assert.equal(s.$('login-name').attrs['aria-invalid'], 'true');
  assert.equal(net.length, before + 1);
  assert.equal(s.$('login-passkey-only').hidden, false);
  assert.equal(s.$('login-passkey-only').disabled, false);
});

// ---- the manage page ----

test('the manage page: text only, the request header, the step-up for every change, and its regions', async () => {
  const js = await read('manage-page.js');
  assert.doesNotMatch(js, /innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function/);
  assert.match(js, /'X-Rettui-Request': '1'/);
  assert.match(js, /'Content-Type': 'application\/json'/);
  for (const p of ['/api/manage/settings', '/api/manage/restart', '/api/manage/rollback', '/api/manage/reticulum']) assert.match(js, new RegExp(`confirmed\\('${p.replace(/\//g, '\\/')}'`), p);
  assert.match(js, /window\.rettuiStepUp\.ask\(/);
  assert.match(js, /var POLL_MS = 3000;/);
  assert.match(js, /var POLL_LIMIT_MS = 120000;/);
  const html = await read('manage.html');
  assert.match(html, /<meta name="robots" content="noindex">/);
  assert.match(html, /<p id="manage-status" class="note" role="status">/);
  for (const id of ['manage-error', 'manage-form-error', 'manage-restart-error', 'manage-rollback-error']) assert.match(html, new RegExp(`<p id="${id}" class="login-error" role="alert"></p>`), id);
  assert.match(html, /<label for="manage-node">Node<\/label>\s*<select id="manage-node"/);
  assert.match(html, /<input id="manage-revision" type="hidden"/);
  // The Reticulum panel: a labelled region, a status that is read out, no control in it.
  const panel = /<section id="manage-ret"[\s\S]*?<\/section>/.exec(html)[0];
  assert.match(panel, /aria-labelledby="manage-ret-h"/);
  assert.match(panel, /<h2 id="manage-ret-h">Reticulum configuration<\/h2>/);
  assert.match(panel, /<p id="manage-ret-status" class="note" role="status"><\/p>/);
  assert.doesNotMatch(panel, /<(input|button|select|textarea|form|a)\b/);
  assert.match(html, /<button id="manage-restart" type="button" class="danger">Restart Reticulum<\/button>/);
  assert.match(html, /<button id="manage-older" type="button" hidden>Older entries<\/button>/);
  assert.match(html, /<script src="\/step-up\.js" defer><\/script>\s*<script src="\/manage-page\.js" defer><\/script>/);
  // The account page links to it for the manage and admin roles only; the server checks again.
  assert.match(await read('account.html'), /<p id="acct-manage" hidden><a href="\/manage">Manage nodes<\/a>/);
  assert.match(await read('account-page.js'), /\$\('acct-manage'\)\.hidden = !\(\(data\.role === 'manage' \|\| data\.role === 'admin'\) && data\.mustChangePassword !== true\);/);
  // Long values wrap on a phone.
  assert.match(await read('site.css'), /\.manage-field \{[^}]*overflow-wrap: anywhere/);
});

const MANAGE = { me: 'bob', roleOk: true, secondFactor: true, stepUpMethods: ['totp', 'recovery'], recentSignIn: true, nodes: [{ host: 'a.test:1', name: 'Hilltop' }, { host: 'b.test:2', name: 'b.test:2' }] };
const NODE_URL = '/api/manage/node?host=a.test%3A1';
const AUDIT_URL = '/api/manage/audit?host=a.test%3A1';
const EVIL = '<img src=x onerror=alert(1)>';
function nodeState(extra = {}) {
  return {
    host: 'a.test:1', name: 'Hilltop', version: '2.5.0', settings_revision: 'a'.repeat(32), skewSeconds: 200,
    clock: { skewMinutes: 3, warning: "This node's clock is 3 minutes off from the website's, so signed requests can't be trusted; fix the node's time." },
    settings: [
      { key: 'pn_name', label: EVIL, help: 'Shown in lists.', kind: 'text', access: 'change', value: 'Hilltop' },
      { key: 'pn_autopeer', label: 'Peer by itself', help: '', kind: 'toggle', access: 'change', value: 'true' },
      { key: 'log_level', label: 'Log level', help: '', kind: 'choice', choices: ['info', 'debug'], access: 'change', value: 'info' },
      { key: 'pn_enabled', label: 'Propagation node', help: 'Off only.', kind: 'toggle', access: 'turn_off_only', value: 'false' },
      { key: 'hub_enabled', label: 'Hub', help: '', kind: 'toggle', access: 'turn_off_only', value: 'true' },
    ],
    network: { state: 'running', shared_instance: false, interfaces_total: 2, interfaces_online: 1 },
    restart: null, restart_allowed_at: null,
    ...extra,
  };
}
const ENTRIES = { entries: [{ seq: 9, time: 100, id: '00112233aabbccdd', actor: 'alice', op: 'settings', changes: [{ key: 'pn_name', from: 'Old', to: 'Hilltop' }], result: 'ok', error: null }, { seq: 8, time: 90, id: null, actor: 'bob', op: 'restart', changes: [], result: 'failed', error: 'eth0 down' }], more: true };

// Runs manage-page.js against the fake document. routes as for router(); ask: what the step-up
// dialog does (it sends the password and a code by default). Timers are kept, to be run by hand.
async function managePage({ routes = {}, ask, me = MANAGE, Date: FakeDate } = {}) {
  const dom = makeDom({ prebuilt: true });
  const { fetch, log } = router({ 'GET /api/manage': [200, me], [`GET ${NODE_URL}`]: [200, nodeState()], [`GET ${AUDIT_URL}`]: [200, ENTRIES], ...routes });
  const timers = [];
  const asked = [];
  const window = {
    setTimeout: (f) => (timers.push(f), timers.length),
    clearTimeout: () => {},
    rettuiStepUp: { ask: (o) => (asked.push(o), ask ? ask(o) : o.send({ password: 'pw', code: '123456' })) },
  };
  const context = { document: dom.document, window, fetch, ...(FakeDate ? { Date: FakeDate } : {}) };
  vm.runInNewContext(await read('manage-page.js'), context);
  await settle();
  const fields = () => dom.byId('manage-fields').all();
  const tick = async () => {
    const f = timers.shift();
    f();
    await settle();
  };
  return { ...dom, log, asked, timers, tick, fields, posts: () => log.filter((x) => x.method === 'POST').map((x) => ({ url: x.url, body: JSON.parse(x.body), headers: x.headers })) };
}

test('manage page: the node is shown with its status line, clock warning, settings form and the last change, all as text', async () => {
  const p = await managePage();
  const $ = p.byId;
  assert.equal($('manage').hidden, false);
  assert.equal($('manage-none').hidden, true);
  assert.equal($('manage-view-only').hidden, true);
  assert.deepEqual($('manage-node').children.map((o) => [o.value, o.textContent]), [['a.test:1', 'Hilltop (a.test:1)'], ['b.test:2', 'b.test:2']]);
  assert.equal($('manage-node-h').textContent, 'Hilltop (a.test:1)');
  assert.equal($('manage-line').textContent, 'rettui 2.5.0 · Reticulum running, 1 of 2 interfaces online · clock 3 min off');
  assert.equal($('manage-clock').hidden, false);
  assert.match($('manage-clock').textContent, /^This node's clock is 3 minutes off/);
  assert.equal($('manage-revision').value, 'a'.repeat(32));
  // The node's label is text: it is shown as it came, and is no element.
  const label = p.fields().find((e) => e.tag === 'label' && e.textContent === EVIL);
  assert.ok(label, 'the label is set as text');
  assert.equal(p.fields().some((e) => e.tag === 'img'), false);
  const input = p.fields().find((e) => e.id === label.htmlFor);
  assert.equal(input.value, 'Hilltop');
  assert.match(input.attrs['aria-describedby'], /-help manage-form-error$/);
  // Groups by the key: one fieldset for the propagation node, one for the hub, one for the rest.
  assert.deepEqual(p.fields().filter((e) => e.tag === 'legend').map((e) => e.textContent), ['Propagation node', 'General', 'Hub']);
  // A service that is off: its button is off, and the words say where it is turned on.
  const offs = p.fields().filter((e) => e.tag === 'button');
  assert.deepEqual(offs.map((b) => [b.attrs['aria-label'], b.disabled]), [['Turn off Propagation node', true], ['Turn off Hub', false]]);
  assert.ok(p.fields().some((e) => e.textContent === 'Turn on in the terminal on the node.'));
  // The node's list of changes, and its last settings change with a Roll back button.
  assert.equal($('manage-audit-rows').children.length, 2);
  assert.equal($('manage-older').hidden, false);
  assert.match($('manage-last').textContent, /^A settings change by alice, /);
  assert.equal($('manage-last-list').children[0].textContent, 'pn_name: "Old" to "Hilltop"');
  assert.equal($('manage-rollback').hidden, false);
  assert.equal($('manage-rollback').disabled, false);
  assert.equal($('manage-save').disabled, false);
  assert.equal($('manage-restart').disabled, false);
});

const RET = {
  revision: 'f'.repeat(32),
  shared_instance: true,
  truncated: false,
  sections: [
    { path: ['reticulum'], keys: [{ key: 'enable_transport', value: 'yes', set: true }] },
    { path: ['interfaces', EVIL], keys: [{ key: 'type', value: EVIL, set: true }, { key: 'passphrase', value: null, set: true }, { key: 'network_name', value: null, set: false }, { key: 'note', value: '', set: true }] },
    { path: ['interfaces', 'Empty'], keys: [] },
  ],
};

test('manage page: the Reticulum configuration is a read-only table per section, as text, with hidden keys told as set or not set', async () => {
  const p = await managePage({ routes: { [`GET ${NODE_URL}`]: [200, nodeState({ reticulum: RET })] } });
  const $ = p.byId;
  const all = $('manage-ret-sections').all();
  assert.equal($('manage-ret').hidden, false);
  assert.equal($('manage-ret-status').textContent, '');
  assert.equal($('manage-ret-shared').hidden, false);
  // Its words are in the page (the fake document starts empty).
  assert.match(await read('manage.html'), /<p id="manage-ret-shared" class="note" hidden>This node uses a shared Reticulum instance\. The file shown here is this node's own config; the live settings may be those of another Reticulum process\.<\/p>/);
  assert.deepEqual(all.filter((e) => e.tag === 'h3').map((e) => e.textContent), ['reticulum', `interfaces / ${EVIL}`, 'interfaces / Empty']);
  assert.equal(all.some((e) => e.tag === 'img' || e.tag === 'script'), false, 'the markup of the node is text');
  assert.deepEqual(all.filter((e) => e.tag === 'caption').map((e) => e.textContent), ['Reticulum settings of reticulum', `Reticulum settings of interfaces / ${EVIL}`]);
  const rows = all.filter((e) => e.tag === 'tr' && e.children[0].tag === 'th' && e.children[0].scope === 'row').map((tr) => [tr.children[0].textContent, tr.children[1].textContent]);
  assert.deepEqual(rows, [['enable_transport', 'yes'], ['type', EVIL], ['passphrase', 'set (hidden)'], ['network_name', 'not set'], ['note', '(empty)']]);
  assert.deepEqual(all.filter((e) => e.tag === 'th' && e.scope === 'col').map((e) => e.textContent), ['Setting', 'Value', 'Setting', 'Value']);
  assert.ok(all.some((e) => e.textContent === 'No settings listed.'));
  // Read only: nothing to click, type in or submit in the panel.
  assert.equal(all.some((e) => ['input', 'button', 'select', 'textarea', 'a'].includes(e.tag) || Object.keys(e.listeners).length > 0), false);
  // Not shared: the note is hidden. No section: it says so.
  const other = await managePage({ routes: { [`GET ${NODE_URL}`]: [200, nodeState({ reticulum: { ...RET, shared_instance: false, sections: [] } })] } });
  assert.equal(other.byId('manage-ret-shared').hidden, true);
  assert.equal(other.byId('manage-ret-status').textContent, 'The node lists no Reticulum configuration.');
  assert.equal(other.byId('manage-ret-sections').children.length, 0);
});

test('manage page: a cut config says so, and the sample of the stub node is painted as cleaned', async () => {
  const { cleanReticulum } = await import('../lib/manage-api.js');
  const { sampleReticulum } = await import('./helpers/manage-node.js');
  const cleaned = cleanReticulum(sampleReticulum());
  assert.equal(cleaned.truncated, true);
  const p = await managePage({ routes: { [`GET ${NODE_URL}`]: [200, nodeState({ reticulum: cleaned })] } });
  assert.equal(p.byId('manage-ret-status').textContent, 'Part of the config is not shown.');
  const all = p.byId('manage-ret-sections').all();
  assert.equal(all.filter((e) => e.tag === 'h3').length, 128);
  assert.ok(all.some((e) => e.tag === 'th' && e.textContent === 'passphrase'));
  assert.ok(all.some((e) => e.tag === 'td' && e.textContent === 'set (hidden)'));
  assert.equal(all.some((e) => e.textContent.includes('hunter2')), false);
  assert.equal(all.some((e) => e.tag === 'script' || e.tag === 'img'), false);
  // Not cut: no words. Cut and empty: both are said.
  const whole = await managePage({ routes: { [`GET ${NODE_URL}`]: [200, nodeState({ reticulum: { ...RET, truncated: false } })] } });
  assert.equal(whole.byId('manage-ret-status').textContent, '');
  const none = await managePage({ routes: { [`GET ${NODE_URL}`]: [200, nodeState({ reticulum: { ...RET, truncated: true, sections: [] } })] } });
  assert.equal(none.byId('manage-ret-status').textContent, 'The node lists no Reticulum configuration. Part of the config is not shown.');
  const cut = await managePage({ routes: { [`GET ${NODE_URL}`]: [200, nodeState({ reticulum: { ...RET, truncated: true } })] } });
  assert.equal(cut.byId('manage-ret-status').textContent, 'Part of the config is not shown.');
});

test('manage page: a node without Reticulum config says so, and the panel is gone when the node cannot be read', async () => {
  for (const reticulum of [null, undefined, 'x', { sections: 'x' }]) {
    const p = await managePage({ routes: { [`GET ${NODE_URL}`]: [200, nodeState({ reticulum })] } });
    assert.equal(p.byId('manage-ret').hidden, false);
    assert.equal(p.byId('manage-ret-status').textContent, 'This node does not say what its Reticulum config holds.');
    assert.equal(p.byId('manage-ret-shared').hidden, true);
    assert.equal(p.byId('manage-ret-sections').children.length, 0);
  }
  const down = await managePage({ routes: { [`GET ${NODE_URL}`]: [502, { error: 'The node could not be reached.', code: 'network' }] } });
  assert.equal(down.byId('manage-ret').hidden, true);
  // While a node loads, the status (a role=status element) says so; the page sets it as text.
  assert.match(await read('manage-page.js'), /\$\('manage-ret-status'\)\.textContent = 'Loading the Reticulum configuration\.\.\.';/);
});

test('manage page: Save sends only what changed, with the revision, through the step-up; a stale revision loads the form again', async () => {
  let saves = 0;
  const p = await managePage({
    routes: {
      'POST /api/manage/settings': () => (++saves === 1 ? [200, { ok: true, id: '1'.repeat(16), applied: [{ key: 'pn_name', from: 'Hilltop', to: 'Valley' }], notes: ['Announced again.'] }] : [409, { error: 'The settings were changed elsewhere since the page loaded them.', code: 'stale_revision' }]),
    },
  });
  const $ = p.byId;
  $('manage-form').fire('submit');
  await settle();
  assert.equal($('manage-form-error').textContent, 'Nothing to save: no setting was changed.');
  assert.equal(p.asked.length, 0);
  const name = p.fields().find((e) => e.tag === 'input' && e.value === 'Hilltop');
  name.value = 'Valley';
  p.fields().find((e) => e.tag === 'input' && e.type === 'checkbox').checked = false;
  $('manage-form').fire('submit');
  await settle();
  assert.equal(p.asked.length, 1);
  assert.equal(p.asked[0].title, 'Save settings on Hilltop');
  assert.equal(p.asked[0].secondFactor, true);
  assert.deepEqual(p.posts()[0].body, { host: 'a.test:1', revision: 'a'.repeat(32), changes: { pn_name: 'Valley', pn_autopeer: 'false' }, password: 'pw', code: '123456' });
  assert.equal(p.posts()[0].headers['X-Rettui-Request'], '1');
  assert.equal($('manage-status').textContent, 'Saved: 1 setting changed. Announced again.');
  const reads = p.log.filter((x) => x.url === NODE_URL).length;
  p.fields().find((e) => e.tag === 'input' && e.value === 'Hilltop').value = 'Other';
  $('manage-form').fire('submit');
  await settle();
  assert.equal($('manage-form-error').textContent, 'The settings were changed elsewhere since the page loaded them.');
  assert.equal($('manage-status').textContent, 'The settings were loaded again, because they changed elsewhere.');
  assert.equal(p.log.filter((x) => x.url === NODE_URL).length, reads + 1);
});

test('manage page: Turn off sends false for that key alone; Roll back sends the change id', async () => {
  const p = await managePage({ routes: { 'POST /api/manage/settings': [200, { ok: true, applied: [] }], 'POST /api/manage/rollback': [403, { error: 'Only the terminal turns a service on.', code: 'not_allowed' }] } });
  const $ = p.byId;
  p.fields().find((e) => e.attrs['aria-label'] === 'Turn off Hub').fire('click');
  await settle();
  assert.equal(p.asked[0].danger, true);
  assert.deepEqual(p.posts()[0].body.changes, { hub_enabled: 'false' });
  assert.equal($('manage-status').textContent, 'Hub is turned off.');
  $('manage-rollback').fire('click');
  await settle();
  assert.deepEqual(p.posts()[1].body, { host: 'a.test:1', id: '00112233aabbccdd', password: 'pw', code: '123456' });
  assert.equal($('manage-rollback-error').textContent, 'Only the terminal turns a service on.');
  // Older entries asks from the oldest one shown.
  $('manage-older').fire('click');
  await settle();
  assert.ok(p.log.some((x) => x.url === `${AUDIT_URL}&before=8`));
});

test('manage page: without two-step sign-in it only shows; a gone session says so', async () => {
  const p = await managePage({ me: { ...MANAGE, secondFactor: false } });
  const $ = p.byId;
  assert.equal($('manage-view-only').hidden, false);
  assert.equal($('manage-save').disabled, true);
  assert.equal($('manage-restart').disabled, true);
  assert.equal($('manage-rollback').disabled, true);
  assert.ok(p.fields().filter((e) => e.tag === 'button').every((b) => b.disabled));
  $('manage-form').fire('submit');
  $('manage-restart').fire('click');
  await settle();
  assert.equal(p.asked.length, 0);
  const gone = await managePage({ routes: { 'GET /api/manage': [401, { error: 'Sign in first.', signIn: true }] } });
  assert.equal(gone.byId('manage').hidden, true);
  assert.equal(gone.byId('manage-status').textContent, 'Your session has ended. Sign in again to manage nodes.');
  const none = await managePage({ me: { ...MANAGE, nodes: [] } });
  assert.equal(none.byId('manage-none').hidden, false);
  assert.equal(none.byId('manage').hidden, true);
  // A node that cannot be read: its error, and no form.
  const down = await managePage({ routes: { [`GET ${NODE_URL}`]: [502, { error: 'The node could not be reached.', code: 'network' }] } });
  assert.equal(down.byId('manage-error').textContent, 'The node could not be reached.');
  assert.equal(down.byId('manage-settings').hidden, true);
});

test('manage page: in the 24 hours after a first second factor it only shows, and says until when', async () => {
  const until = new Date(Date.now() + 3600_000).toISOString();
  const p = await managePage({ me: { ...MANAGE, secondFactor: true, nodeChangesFrom: until } });
  const $ = p.byId;
  assert.equal($('manage-wait').hidden, false);
  assert.equal($('manage-view-only').hidden, true);
  assert.equal($('manage-wait-until').textContent, new Date(until).toLocaleString());
  assert.equal($('manage-save').disabled, true);
  assert.equal($('manage-restart').disabled, true);
  $('manage-restart').fire('click');
  await settle();
  assert.equal(p.asked.length, 0);
  // Once it is over (or never was), the page changes as before.
  for (const nodeChangesFrom of [new Date(Date.now() - 1000).toISOString(), null, undefined]) {
    const q = await managePage({ me: { ...MANAGE, secondFactor: true, nodeChangesFrom } });
    assert.equal(q.byId('manage-wait').hidden, true, String(nodeChangesFrom));
    assert.equal(q.byId('manage-restart').disabled, false, String(nodeChangesFrom));
  }
  assert.match(await read('manage.html'), /<p id="manage-wait" class="acct-card users-warning" hidden>Your two-step sign-in was turned on less than 24 hours ago/);
});

test('users page: while nodes are managed, an admin without two-step sign-in is told to turn it on, and no step-up opens', async () => {
  const js = await read('users-page.js');
  const run = async (page) => {
    const els = new Map();
    const byId = (id) => {
      if (!els.has(id)) els.set(id, new FakeElement(id));
      return els.get(id);
    };
    const asked = [];
    const posts = [];
    const answer = (status, body) => Promise.resolve({ status, json: () => Promise.resolve(body) });
    const context = {
      document: { getElementById: byId, createElement: () => new FakeElement() },
      window: { rettuiStepUp: { ask: (o) => (asked.push(o), o.send({ password: 'pw', code: '123456' })) } },
      fetch: (url, opts) => (opts?.method === 'POST' ? (posts.push(url), answer(200, { ok: true })) : answer(200, page)),
      navigator: {},
      location: { assign() {} },
    };
    vm.runInNewContext(js, context);
    await new Promise((r) => setTimeout(r, 10));
    const button = byId('users-rows').all().find((e) => e.attrs['aria-label'] === 'Reset the two-step sign-in of carol');
    button.fire('click');
    await new Promise((r) => setTimeout(r, 10));
    return { byId, asked, posts };
  };
  const users = [{ name: 'alice', role: 'admin', source: 'config', secondFactor: false, devices: 0 }, { name: 'carol', role: 'manage', source: 'store', secondFactor: true, totp: true, devices: 1 }];
  const page = { me: 'alice', roles: ['admin', 'manage', 'viewer'], users };
  const blocked = await run({ ...page, secondFactor: false, secondFactorRequired: true });
  assert.equal(blocked.byId('users-need-2fa').hidden, false);
  assert.equal(blocked.asked.length, 0, 'no step-up dialog');
  assert.deepEqual(blocked.posts, []);
  assert.match(blocked.byId('users-status').textContent, /changing users needs two-step sign-in/);
  // With a second factor on, the step-up asks for it; without managed nodes, nothing changes.
  for (const [secondFactor, secondFactorRequired] of [[true, true], [false, false]]) {
    const r = await run({ ...page, secondFactor, secondFactorRequired });
    assert.equal(r.byId('users-need-2fa').hidden, true);
    assert.equal(r.asked.length, 1);
    assert.equal(r.asked[0].secondFactor, secondFactor);
    assert.deepEqual(r.posts, ['/api/users/reset-second-factor']);
  }
  assert.match(await read('users.html'), /<p id="users-need-2fa" class="acct-card users-warning" tabindex="-1" hidden>Nodes are managed from this website, so changing users needs two-step sign-in\. Until you turn it on on your <a href="\/account">account page<\/a>, you can only look\.<\/p>/);
});

test('manage page: Restart asks the node every 3 seconds until it says how it went, and gives up after 2 minutes', async () => {
  let reads = 0;
  const restarting = nodeState({ restart: { id: 'r'.repeat(16), state: 'restarting', started: 1, problems: [] } });
  const up = nodeState({ restart: { id: 'r'.repeat(16), state: 'up', started: 1, problems: [] } });
  const p = await managePage({ routes: { 'POST /api/manage/restart': [202, { ok: true, id: 'r'.repeat(16), state: 'restarting' }], [`GET ${NODE_URL}`]: () => [200, ++reads <= 1 ? nodeState() : reads === 2 ? restarting : up] } });
  const $ = p.byId;
  $('manage-restart').fire('click');
  await settle();
  assert.equal(p.asked[0].danger, true);
  assert.equal($('manage-status').textContent, 'Reticulum is restarting. This page checks every few seconds until it is back.');
  assert.equal($('manage-restart').disabled, true);
  assert.equal(p.timers.length, 1);
  await p.tick();
  assert.equal(p.timers.length, 1, 'still restarting: asks again');
  await p.tick();
  assert.equal($('manage-status').textContent, 'Reticulum is back: every interface that was online is online again.');
  assert.equal(p.timers.length, 0);
  // A node that never says: after 2 minutes the page stops asking.
  let t = 0;
  class Clock extends Date {
    static now() {
      return t;
    }
  }
  const slow = await managePage({ Date: Clock, routes: { 'POST /api/manage/restart': [202, { ok: true, id: 'r'.repeat(16) }], [`GET ${NODE_URL}`]: () => [200, restarting] } });
  slow.byId('manage-restart').fire('click');
  await settle();
  let polls = 0;
  while (slow.timers.length && polls < 100) {
    t += 3000;
    polls++;
    await slow.tick();
  }
  assert.equal(polls, 40);
  assert.equal(slow.byId('manage-status').textContent, 'The node has not said after 2 minutes that Reticulum is back. Reload the page to check.');
});

// ---- the manage page: Reticulum changes on probation ----

const CONFIRM_URL = '/api/manage/confirm?host=a.test%3A1';
const RET_EDIT = {
  revision: 'e'.repeat(32),
  shared_instance: false,
  truncated: false,
  sections: [
    { path: ['reticulum'], keys: [{ key: 'enable_transport', value: 'False', set: true }] },
    { path: ['interfaces', EVIL], keys: [{ key: 'type', value: 'TCPServerInterface', set: true }, { key: 'interface_enabled', value: 'Yes', set: true }, { key: 'mode', value: 'Full', set: true }, { key: 'bitrate', value: '9600', set: true }, { key: 'passphrase', value: null, set: true }] },
    { path: ['interfaces', 'Not offered'], keys: [{ key: 'enabled', value: 'yes', set: true }] },
  ],
  editable: [['reticulum'], ['interfaces', EVIL], ['interfaces', 'Gone']],
};
const retState = (extra = {}) => nodeState({ reticulum: RET_EDIT, confirmSeconds: 120, pending: null, reticulum_result: null, confirm: null, ...extra });
const retControls = (p) => p.byId('manage-ret-fields').all();

test('manage page: the Reticulum form offers the sections the node allows, as text, with their current values', async () => {
  const p = await managePage({ routes: { [`GET ${NODE_URL}`]: [200, retState()] } });
  const $ = p.byId;
  assert.equal($('manage-ret-edit').hidden, false);
  assert.equal($('manage-ret-form').hidden, false);
  assert.equal($('manage-ret-pending').textContent, '');
  assert.equal($('manage-ret-revision').value, 'e'.repeat(32));
  const all = retControls(p);
  // One fieldset per section offered that is in the view; the node's name is text.
  assert.deepEqual(all.filter((e) => e.tag === 'legend').map((e) => e.textContent), ['reticulum', `interfaces / ${EVIL}`]);
  assert.equal(all.some((e) => e.tag === 'img' || e.tag === 'script'), false);
  const labels = all.filter((e) => e.tag === 'label');
  assert.deepEqual(labels.map((l) => l.textContent), ['Transport (enable_transport)', 'Enabled', 'Mode', 'Announce cap (percent)', 'Bitrate (bits per second)', 'Ingress control']);
  // Every control has its label and help, and points at the error too.
  for (const l of labels) {
    const input = all.find((e) => e.id === l.htmlFor);
    assert.ok(input, l.textContent);
    assert.ok(['select', 'input'].includes(input.tag), l.textContent);
    const [help, err] = input.attrs['aria-describedby'].split(' ');
    assert.equal(err, 'manage-ret-error');
    assert.ok(all.some((e) => e.id === help && e.textContent.length > 10), l.textContent);
  }
  const byLabel = (text, n = 0) => all.find((e) => e.id === labels.filter((l) => l.textContent === text)[n].htmlFor);
  // Current values, read in the file's own spelling and from an alias.
  assert.equal(byLabel('Transport (enable_transport)').value, 'no');
  assert.equal(byLabel('Enabled').value, 'yes');
  assert.equal(byLabel('Mode').value, 'full');
  assert.deepEqual(byLabel('Mode').children.map((o) => o.value), ['full', 'gateway', 'access_point', 'roaming', 'boundary']);
  assert.equal(byLabel('Bitrate (bits per second)').value, '9600');
  assert.equal(byLabel('Bitrate (bits per second)').attrs.inputmode, 'numeric');
  assert.equal(byLabel('Announce cap (percent)').value, '');
  assert.equal(byLabel('Announce cap (percent)').attrs.inputmode, 'decimal');
  // Not set: a choice that keeps it so.
  assert.deepEqual(byLabel('Ingress control').children.map((o) => [o.value, o.textContent]), [['', '(not set, leave as is)'], ['yes', 'yes'], ['no', 'no']]);
  assert.equal(byLabel('Ingress control').value, '');
  // The words say what leaving it does, and a value that is not one of the choices is told as it is.
  const ingress = byLabel('Ingress control');
  assert.match(all.find((e) => e.id === ingress.attrs['aria-describedby'].split(' ')[0]).textContent, /Pick a value to change it\. Leave this to keep it as it is\.$/);
  const odd = await managePage({ routes: { [`GET ${NODE_URL}`]: [200, retState({ reticulum: { ...RET_EDIT, sections: [RET_EDIT.sections[0], { path: ['interfaces', EVIL], keys: [{ key: 'mode', value: 'Weird', set: true }] }] } })] } });
  const oddMode = retControls(odd).find((e) => e.tag === 'select' && e.children[0]?.value === '' && e.children[0].textContent.startsWith('(now: Weird'));
  assert.equal(oddMode.children[0].textContent, '(now: Weird, leave as is)');
  // The danger button says what happens, with this node's window.
  assert.equal($('manage-ret-apply-help').textContent, "Reticulum restarts. The website then checks that it can still reach this node and keeps the change. If it can't within 2 minutes, the node puts the old config back by itself.");
  // A shared instance, a user without two-step sign-in, or no editable section: no form, and one line
  // that says why (the section is not just gone). A node that says nothing of its config has no section.
  const sharedWhy = 'This node uses a shared Reticulum instance, so the website does not change its settings.';
  for (const [what, opts, why] of [
    ['shared', { routes: { [`GET ${NODE_URL}`]: [200, retState({ reticulum: { ...RET_EDIT, shared_instance: true } })] } }, sharedWhy],
    ['shared network', { routes: { [`GET ${NODE_URL}`]: [200, retState({ network: { state: 'running', shared_instance: true } })] } }, sharedWhy],
    ['view only', { me: { ...MANAGE, secondFactor: false }, routes: { [`GET ${NODE_URL}`]: [200, retState()] } }, 'You can look, but not change Reticulum settings yet. See the notice at the top.'],
    ['none editable', { routes: { [`GET ${NODE_URL}`]: [200, retState({ reticulum: { ...RET_EDIT, editable: [] } })] } }, 'This node does not let the website change any Reticulum settings.'],
    ['older node', { routes: { [`GET ${NODE_URL}`]: [200, nodeState({ reticulum: RET })] } }, sharedWhy],
  ]) {
    const q = await managePage(opts);
    assert.equal(q.byId('manage-ret-form').hidden, true, what);
    assert.equal(q.byId('manage-ret-edit').hidden, false, what);
    assert.equal(q.byId('manage-ret-why').hidden, false, what);
    assert.equal(q.byId('manage-ret-why').textContent, why, what);
    assert.equal(q.byId('manage-nav').hidden, false, what);
    assert.equal(retControls(q).filter((e) => e.tag === 'select' || e.tag === 'input').length, 0, what);
  }
  // Nothing to say about Reticulum at all: no section, and no entry for it in the list of links.
  const none = await managePage({ routes: { [`GET ${NODE_URL}`]: [200, nodeState({ reticulum: null })] } });
  assert.equal(none.byId('manage-ret-edit').hidden, true);
  assert.equal(none.byId('nav-manage-ret-edit').hidden, true);
  assert.equal(none.byId('nav-manage-settings').hidden, false);
  // The form itself shows no reason line.
  assert.equal($('manage-ret-why').hidden, true);
});

test('manage page: Apply and test sends only what changed, through a danger step-up, then follows the confirm job and loads the node once', async () => {
  let reads = 0;
  let polls = 0;
  const deadline = Math.floor(Date.now() / 1000) + 120;
  const job = (state, extra = {}) => ({ id: '1'.repeat(16), state, outcome: null, message: `job ${state}`, confirmBy: null, updatedAt: 'x', ...extra });
  const p = await managePage({
    routes: {
      [`GET ${NODE_URL}`]: () => (++reads === 1 ? [200, retState()] : [200, retState({ reticulum_result: { id: '1'.repeat(16), outcome: 'committed', at: 100, message: '' }, confirm: job('done', { outcome: 'committed', message: 'The change passed the test and is kept.' }) })]),
      'POST /api/manage/reticulum': [202, { ok: true, id: '1'.repeat(16), state: 'restarting', applied: [{ path: ['interfaces', EVIL], key: 'enabled', from: 'Yes', to: 'no' }], confirm: job('waiting', { message: 'Reticulum is restarting with the change.' }) }],
      [`GET ${CONFIRM_URL}`]: () => [200, { job: ++polls === 1 ? job('probing', { nodeState: 'probation', confirmBy: deadline, message: 'Checking that the website can still reach the node over Reticulum.' }) : job('done', { outcome: 'committed', message: 'The change passed the test and is kept.' }) }],
    },
  });
  const $ = p.byId;
  // Nothing changed: nothing is asked.
  $('manage-ret-form').fire('submit');
  await settle();
  assert.equal($('manage-ret-error').textContent, 'Nothing to apply: no Reticulum setting was changed.');
  assert.equal(p.asked.length, 0);
  const all = retControls(p);
  const labels = all.filter((e) => e.tag === 'label');
  const byLabel = (text) => all.find((e) => e.id === labels.find((l) => l.textContent === text).htmlFor);
  // A value that is set cannot be removed from here.
  byLabel('Bitrate (bits per second)').value = '';
  $('manage-ret-form').fire('submit');
  await settle();
  assert.match($('manage-ret-error').textContent, /Bitrate \(bits per second\): a value can be changed here, but not removed/);
  // The same value in another spelling is no change; a new one is.
  byLabel('Bitrate (bits per second)').value = '9600.0';
  byLabel('Mode').value = 'full';
  byLabel('Enabled').value = 'no';
  byLabel('Announce cap (percent)').value = ' 5 ';
  $('manage-ret-form').fire('submit');
  await settle();
  assert.equal(p.asked.length, 1);
  const asked = p.asked[0];
  assert.equal(asked.danger, true);
  assert.equal(asked.action, 'Apply and test');
  assert.equal(asked.title, 'Apply and test on Hilltop');
  assert.ok(asked.why.startsWith("Reticulum restarts. The website then checks that it can still reach this node and keeps the change. If it can't within 2 minutes, the node puts the old config back by itself."), asked.why);
  assert.match(asked.why, /Changes interfaces \/ <img src=x onerror=alert\(1\)> \/ Enabled to no, interfaces \/ .* \/ Announce cap \(percent\) to 5\.$/);
  const post = p.posts().find((x) => x.url === '/api/manage/reticulum');
  assert.deepEqual(post.body, { host: 'a.test:1', revision: 'e'.repeat(32), changes: [{ path: ['interfaces', EVIL], key: 'enabled', value: 'no' }, { path: ['interfaces', EVIL], key: 'announce_cap', value: '5' }], password: 'pw', code: '123456' });
  assert.equal(post.headers['X-Rettui-Request'], '1');
  // Restarting: the form is gone, the status says so, and the restart button waits.
  assert.equal($('manage-ret-form').hidden, true);
  assert.equal($('manage-ret-pending').textContent, `Restarting: Reticulum is restarting with the change (interfaces / ${EVIL} / enabled to "no").`);
  assert.equal($('manage-restart').disabled, true);
  assert.equal($('manage-status').textContent, 'Reticulum is restarting with the change. This page shows how the test goes.');
  assert.equal(p.timers.length, 1);
  await p.tick();
  // The job probes: the change is on probation until the node's deadline, and the job says what it does.
  const hhmm = new Date(deadline * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  assert.equal($('manage-ret-pending').textContent, `On probation until ${hhmm} (interfaces / ${EVIL} / enabled to "no"). Checking that the website can still reach the node over Reticulum.`);
  assert.equal(p.log.filter((x) => x.url === NODE_URL).length, 1, 'the node is not read again while the job runs');
  assert.equal(p.timers.length, 1);
  await p.tick();
  // Over: the node is loaded once, and the panel says it is kept.
  assert.equal(p.log.filter((x) => x.url === CONFIRM_URL).length, 2);
  assert.equal(p.log.filter((x) => x.url === NODE_URL).length, 2);
  assert.equal(p.timers.length, 0);
  assert.equal($('manage-status').textContent, 'The change passed the test and is kept.');
  assert.match($('manage-ret-pending').textContent, /^Kept: the last Reticulum change \(.+\) passed the test\.$/);
  assert.equal($('manage-ret-form').hidden, false, 'the next change can be made');
});

test('manage page: each state of a Reticulum change is said in the status region, with what the node said as text', async () => {
  const at = Math.floor(Date.now() / 1000) + 300;
  const pending = (state, extra = {}) => ({ id: '2'.repeat(16), actor: `bob${EVIL}`, state, applied_at: 1, confirm_seconds: 300, healthy_at: null, confirm_by: state === 'probation' ? at : null, changes: [{ path: ['interfaces', EVIL], key: 'enabled', from: 'yes', to: 'no' }], problems: [], ...extra });
  const job = (state, message) => ({ id: '2'.repeat(16), state, outcome: null, message, confirmBy: at, updatedAt: 'x' });
  const hhmm = new Date(at * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  const what = `(interfaces / ${EVIL} / enabled to "no", by bob${EVIL})`;
  const cases = [
    [{ pending: pending('restarting') }, `Restarting: Reticulum is restarting with the change ${what}.`],
    [{ pending: pending('probation'), confirm: job('probing', 'Checking that the website can still reach the node over Reticulum.') }, `On probation until ${hhmm} ${what}. Checking that the website can still reach the node over Reticulum.`],
    [{ pending: pending('probation') }, `On probation until ${hhmm} ${what}. The website is not checking this change, so the node puts the old config back then.`],
    [{ pending: pending('rolling_back', { problems: ['Hilltop TCP is offline', EVIL] }) }, `Rolling back: the node is putting the old config back ${what}, as Hilltop TCP is offline; ${EVIL}.`],
    [{ pending: pending('unknown') }, `A Reticulum change is pending on this node ${what}.`],
    [{ reticulum_result: { id: '2'.repeat(16), outcome: 'rolled_back', at: 1, message: `no confirm by the deadline ${EVIL}` } }, `Rolled back: the node put the old config back: no confirm by the deadline ${EVIL}`],
    [{ reticulum_result: { id: '2'.repeat(16), outcome: 'rollback_failed', at: 1, message: 'no backup found' } }, 'Not rolled back: the node could not put the old config back: no backup found Check the node in the terminal.'],
    [{ reticulum_result: { id: '2'.repeat(16), outcome: 'left', at: 1, message: '' } }, 'Left as it was: the config was changed on the node meanwhile.'],
    [{ confirm: { ...job('gave-up', "The website could not reach this node's Reticulum port in time, so it did not keep the change. The node puts the old config back by itself."), id: '3'.repeat(16) } }, "The website could not reach this node's Reticulum port in time, so it did not keep the change. The node puts the old config back by itself."],
  ];
  for (const [extra, words] of cases) {
    const p = await managePage({ routes: { [`GET ${NODE_URL}`]: [200, retState(extra)], [`GET ${CONFIRM_URL}`]: [200, { job: extra.confirm ?? null }] } });
    const $ = p.byId;
    assert.equal($('manage-ret-edit').hidden, false, words);
    assert.equal($('manage-ret-pending').textContent, words);
    assert.equal($('manage-ret-pending').children.length, 0, 'text, no elements');
    if (extra.pending) {
      assert.equal($('manage-ret-form').hidden, true, `no new change while one is pending: ${words}`);
      assert.equal($('manage-restart').disabled, true, words);
    }
    // A job that still runs is followed when the page loads.
    assert.equal(p.timers.length, extra.confirm && extra.confirm.state === 'probing' ? 1 : 0, words);
  }
  // A user who cannot change anything still sees how a change goes.
  const look = await managePage({ me: { ...MANAGE, secondFactor: false }, routes: { [`GET ${NODE_URL}`]: [200, retState({ pending: pending('restarting') })] } });
  assert.equal(look.byId('manage-ret-edit').hidden, false);
  assert.equal(look.byId('manage-ret-form').hidden, true);
  // The audit list shows the section of a Reticulum change.
  const listed = await managePage({ routes: { [`GET ${NODE_URL}`]: [200, retState()], [`GET ${AUDIT_URL}`]: [200, { entries: [{ seq: 3, time: 1, id: '2'.repeat(16), actor: 'bob', op: 'auto_rollback', changes: [], result: 'rolled_back', error: 'no confirm by the deadline' }, { seq: 2, time: 1, id: '2'.repeat(16), actor: 'bob', op: 'reticulum', changes: [{ path: ['interfaces', EVIL], key: 'enabled', from: 'yes', to: 'no' }], result: 'ok', error: null }], more: false }] } });
  const rows = listed.byId('manage-audit-rows').children.map((tr) => tr.children.map((c) => c.textContent));
  assert.deepEqual(rows.map((r) => r.slice(1)), [['bob', 'Rolled back by itself', '-', 'Rolled back: no confirm by the deadline'], ['bob', 'Reticulum config', `interfaces / ${EVIL} / enabled: "yes" to "no"`, 'Done']]);
});

test('manage page: a refused change says why; a stale revision or a pending change loads the node again', async () => {
  let reads = 0;
  const answers = [[409, { error: 'The Reticulum configuration was changed elsewhere since the page loaded it.', code: 'stale_revision' }], [400, { error: 'enabled of interfaces / x must be yes or no.', key: 'enabled' }], [409, { error: 'Another Reticulum change on this node is still being tested.', code: 'pending' }]];
  const p = await managePage({ routes: { [`GET ${NODE_URL}`]: () => (++reads, [200, retState()]), 'POST /api/manage/reticulum': () => answers.shift() } });
  const $ = p.byId;
  const change = () => {
    const all = retControls(p);
    const label = all.find((e) => e.tag === 'label' && e.textContent === 'Enabled');
    all.find((e) => e.id === label.htmlFor).value = 'no';
    $('manage-ret-form').fire('submit');
    return settle();
  };
  await change();
  assert.equal($('manage-ret-error').textContent, 'The Reticulum configuration was changed elsewhere since the page loaded it.');
  assert.equal($('manage-status').textContent, 'The Reticulum configuration was loaded again.');
  assert.equal(reads, 2);
  await change();
  assert.equal($('manage-ret-error').textContent, 'enabled of interfaces / x must be yes or no.');
  assert.equal(reads, 2, 'a bad value keeps the form as it is');
  await change();
  assert.equal(reads, 3);
  assert.equal(p.timers.length, 0, 'no job to follow');
  // Cancelled in the step-up: nothing is sent.
  const c = await managePage({ ask: () => Promise.resolve(null), routes: { [`GET ${NODE_URL}`]: [200, retState()] } });
  const all = retControls(c);
  all.find((e) => e.id === all.find((x) => x.tag === 'label' && x.textContent === 'Enabled').htmlFor).value = 'no';
  c.byId('manage-ret-form').fire('submit');
  await settle();
  assert.equal(c.posts().length, 0);
  assert.equal(c.byId('manage-ret-error').textContent, '');
});

test('manage page: following a confirm job stops when the server says too often, and the script asks the confirm route only', async () => {
  const p = await managePage({ routes: { [`GET ${NODE_URL}`]: [200, retState({ pending: { id: '2'.repeat(16), state: 'probation', confirm_by: 1, changes: [], problems: [] }, confirm: { id: '2'.repeat(16), state: 'probing', outcome: null, message: 'Checking.', confirmBy: 1 } })], [`GET ${CONFIRM_URL}`]: [429, { error: 'Too often.' }] } });
  assert.equal(p.timers.length, 1);
  await p.tick();
  assert.equal(p.timers.length, 0);
  assert.equal(p.byId('manage-status').textContent, 'The page stopped asking how the change goes, as it asked too often. Reload the page in a while.');
  const js = await read('manage-page.js');
  assert.match(js, /confirmed\('\/api\/manage\/reticulum'/);
  assert.match(js, /getJson\('\/api\/manage\/confirm\?host=' \+ encodeURIComponent\(host\)\)/);
  assert.match(js, /var CONFIRM_POLL_LIMIT_MS = 25 \* 60000;/);
});

test('manage page: while the job is followed, the change shows as on probation as soon as the job probes, confirms or knows the deadline', async () => {
  const deadline = Math.floor(Date.now() / 1000) + 300;
  const hhmm = new Date(deadline * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  const P = { id: '2'.repeat(16), state: 'restarting', confirm_by: null, changes: [], problems: [] };
  const base = { id: '2'.repeat(16), outcome: null, updatedAt: 'x' };
  const steps = [
    [{ ...base, state: 'waiting', nodeState: 'restarting', confirmBy: null, message: 'Reticulum is restarting with the change.' }, 'Restarting: Reticulum is restarting with the change.'],
    // An older server that does not say the node's state: the job's own state is enough.
    [{ ...base, state: 'probing', confirmBy: null, message: 'Checking.' }, 'On probation until unknown. Checking.'],
    [{ ...base, state: 'waiting', confirmBy: deadline, message: 'The node did not take the confirm yet. Trying again.' }, `On probation until ${hhmm}. The node did not take the confirm yet. Trying again.`],
    [{ ...base, state: 'confirming', nodeState: 'probation', confirmBy: deadline, message: 'Keeping the change.' }, `On probation until ${hhmm}. Keeping the change.`],
    [{ ...base, state: 'waiting', nodeState: 'rolling_back', confirmBy: deadline, message: 'The node is putting the old config back.' }, 'Rolling back: the node is putting the old config back.'],
  ];
  let n = 0;
  const p = await managePage({ routes: { [`GET ${NODE_URL}`]: [200, retState({ pending: P, confirm: steps[0][0] })], [`GET ${CONFIRM_URL}`]: () => [200, { job: steps[++n][0] }] } });
  assert.equal(p.byId('manage-ret-pending').textContent, 'Restarting: Reticulum is restarting with the change.');
  for (let i = 1; i < steps.length; i++) {
    await p.tick();
    assert.equal(p.byId('manage-ret-pending').textContent, steps[i][1], `step ${i}`);
  }
});

test('manage page: turning an interface or transport on is only offered when the node allows it, and then the dialog lists what opens and asks for a tick', async () => {
  const offered = (p, label) => {
    const all = retControls(p);
    const l = all.find((e) => e.tag === 'label' && e.textContent === label);
    const input = all.find((e) => e.id === l.htmlFor);
    const help = all.find((e) => e.id === input.attrs['aria-describedby'].split(' ')[0]);
    return { input, values: input.children.map((o) => o.value), help: help.textContent };
  };
  const off = { ...RET_EDIT, sections: [{ path: ['reticulum'], keys: [{ key: 'enable_transport', value: 'no', set: true }] }, { path: ['interfaces', EVIL], keys: [{ key: 'enabled', value: 'no', set: true }] }, { path: ['interfaces', 'On'], keys: [{ key: 'enabled', value: 'yes', set: true }] }], editable: [['reticulum'], ['interfaces', EVIL], ['interfaces', 'On']] };
  for (const allowed of [undefined, false, 'yes']) {
    const p = await managePage({ routes: { [`GET ${NODE_URL}`]: [200, retState({ reticulum: off, reticulum_enable_allowed: allowed })] } });
    const t = offered(p, 'Transport (enable_transport)');
    assert.deepEqual(t.values, ['no'], String(allowed));
    assert.match(t.help, /Turning this on is only possible in the terminal on this node\.$/);
    // Ingress control is no turn-on of that kind: yes stays on offer.
    assert.deepEqual(offered(p, 'Ingress control').values, ['', 'yes', 'no']);
    // One that is on can still be turned off.
    const on = retControls(p).filter((e) => e.tag === 'label' && e.textContent === 'Enabled').map((l) => retControls(p).find((e) => e.id === l.htmlFor));
    assert.deepEqual(on.map((x) => x.children.map((o) => o.value)), [['no'], ['yes', 'no']]);
  }
  // Allowed: yes is offered; turning on lists what opens and needs the box ticked (step-up.js).
  const p = await managePage({ routes: { [`GET ${NODE_URL}`]: [200, retState({ reticulum: off, reticulum_enable_allowed: true })], 'POST /api/manage/reticulum': [202, { ok: true, id: '4'.repeat(16), applied: [], notes: ['Opens TCP port 4242 on 0.0.0.0.'], confirm: null }] } });
  const t = offered(p, 'Transport (enable_transport)');
  assert.deepEqual(t.values, ['yes', 'no']);
  assert.doesNotMatch(t.help, /only possible in the terminal/);
  t.input.value = 'yes';
  const iface = retControls(p).find((e) => e.id === retControls(p).find((l) => l.tag === 'label' && l.textContent === 'Enabled').htmlFor);
  iface.value = 'yes';
  p.byId('manage-ret-form').fire('submit');
  await settle();
  const asked = p.asked[0];
  assert.equal(asked.danger, true);
  assert.deepEqual(plain(asked.opens), [
    'reticulum: Transport: this node passes traffic and announces on for other peers, and is known on the network as a transport node.',
    `interfaces / ${EVIL}: The interface starts: a server interface opens its listening port (on every address when it listens on 0.0.0.0), a client interface connects out, and this node is announced on it.`,
  ]);
  assert.equal(asked.acknowledge, 'I know what this opens on the node, and want it.');
  assert.match(asked.why, /This turns on what is listed below\.$/);
  // The node's notes are said once it took the change.
  assert.equal(p.byId('manage-status').textContent, 'Reticulum is restarting with the change. This page shows how the test goes. The node says: Opens TCP port 4242 on 0.0.0.0.');
  // Turning off asks for no tick.
  const q = await managePage({ routes: { [`GET ${NODE_URL}`]: [200, retState({ reticulum: off, reticulum_enable_allowed: true })], 'POST /api/manage/reticulum': [202, { ok: true, id: '4'.repeat(16), confirm: null }] } });
  const onAgain = retControls(q).filter((e) => e.tag === 'label' && e.textContent === 'Enabled').map((l) => retControls(q).find((e) => e.id === l.htmlFor))[1];
  onAgain.value = 'no';
  q.byId('manage-ret-form').fire('submit');
  await settle();
  assert.equal(q.asked[0].opens, undefined);
  assert.equal(q.asked[0].acknowledge, undefined);
});

test('step-up: with opens and acknowledge it lists what opens and does nothing until the box is ticked', async () => {
  const dom = makeDom();
  const sent = [];
  const window = {};
  vm.runInNewContext(await read('step-up.js'), { document: dom.document, window, fetch: () => Promise.reject(new Error('no fetch')) });
  const done = window.rettuiStepUp.ask({ title: 'Apply', why: 'Why.', action: 'Apply and test', danger: true, opens: ['Opens <b>A</b>', 'Opens B'], acknowledge: 'I know.', send: (f) => (sent.push(f), Promise.resolve({ status: 202, body: {} })) });
  const $ = dom.byId;
  assert.deepEqual($('stepup-opens').children.map((li) => [li.tag, li.textContent]), [['li', 'Opens <b>A</b>'], ['li', 'Opens B']]);
  assert.equal($('stepup-opens').hidden, false);
  assert.equal($('stepup-ack-row').hidden, false);
  assert.equal($('stepup-ack-label').textContent, 'I know.');
  assert.equal($('stepup-ack-label').htmlFor, 'stepup-ack');
  assert.equal($('stepup-ack').type, 'checkbox');
  assert.equal($('stepup-ack').checked, false);
  $('stepup-password').value = 'pw';
  $('stepup-code').value = '123456';
  $('stepup-form').fire('submit');
  await settle();
  assert.equal(sent.length, 0, 'not without the tick');
  assert.equal($('stepup-error').textContent, 'Tick the box first: it says you know what this change opens.');
  assert.equal($('stepup-ack').attrs['aria-invalid'], 'true');
  $('stepup-ack').checked = true;
  $('stepup-form').fire('submit');
  await settle();
  assert.equal(sent.length, 1);
  assert.deepEqual(await done, { status: 202, body: {} });
  // Asked again without them: no list, no box, and the tick of before is gone.
  const again = window.rettuiStepUp.ask({ title: 'Save', send: () => Promise.resolve({ status: 200, body: {} }) });
  assert.equal($('stepup-opens').hidden, true);
  assert.equal($('stepup-opens').children.length, 0);
  assert.equal($('stepup-ack-row').hidden, true);
  assert.equal($('stepup-ack').checked, false);
  $('stepup-password').value = 'pw';
  $('stepup-form').fire('submit');
  await settle();
  assert.deepEqual(await again, { status: 200, body: {} });
});

test("manage page: the node's checks of a pending change are a list in the status region, as text, and follow the job", async () => {
  const P = {
    id: '2'.repeat(16), state: 'probation', confirm_by: null, changes: [], problems: [],
    checks: [
      { interface: 'Hilltop TCP', kind: 'self_test', result: 'passed' },
      { interface: 'Hilltop TCP', kind: 'self_test', result: 'waiting' },
      { interface: EVIL, kind: 'self_test', result: 'failed' },
      { interface: 'Radio', kind: 'online', result: 'traffic' },
      { interface: 'Radio', kind: 'online', result: 'no_traffic' },
      { interface: 'Radio', kind: 'online', result: 'waiting' },
      { interface: 'Odd', kind: 'ping', result: 'passed' },
      { interface: 'Odd', kind: 'self_test', result: 'traffic' },
    ],
  };
  const job = { id: P.id, state: 'probing', nodeState: 'probation', confirmBy: null, outcome: null, message: 'Checking.', updatedAt: 'x', checks: [{ interface: 'Radio', kind: 'online', result: 'traffic' }] };
  const p = await managePage({ routes: { [`GET ${NODE_URL}`]: [200, retState({ pending: P, confirm: { ...job, checks: [] } })], [`GET ${CONFIRM_URL}`]: [200, { job }] } });
  const list = p.byId('manage-ret-checks');
  assert.equal(list.hidden, false);
  assert.deepEqual(list.children.map((li) => [li.tag, li.textContent]), [
    ['li', 'Hilltop TCP: Reticulum answered a test request'],
    ['li', 'Hilltop TCP: waiting for a test answer'],
    ['li', `${EVIL}: Reticulum did not answer a test request`],
    ['li', 'Radio: online, traffic seen'],
    ['li', 'Radio: online, no traffic yet'],
    ['li', 'Radio: waiting to come online'],
  ]);
  assert.ok(list.all().every((e) => e === list || (e.tag === 'li' && e.children.length === 0)), 'text only: the name of the node is no element');
  // The job's next read of the node brings the checks up to date.
  await p.tick();
  assert.deepEqual(list.children.map((li) => li.textContent), ['Radio: online, traffic seen']);
  // No pending change, or no checks: no list.
  for (const extra of [{}, { pending: { ...P, checks: [] } }, { pending: { ...P, checks: undefined } }]) {
    const q = await managePage({ routes: { [`GET ${NODE_URL}`]: [200, retState(extra)] } });
    assert.equal(q.byId('manage-ret-checks').hidden, true);
    assert.equal(q.byId('manage-ret-checks').children.length, 0);
  }
  // The audit table shows the node's notes after the result.
  const a = await managePage({ routes: { [`GET ${NODE_URL}`]: [200, retState()], [`GET ${AUDIT_URL}`]: [200, { entries: [{ seq: 2, time: 1, id: P.id, actor: 'bob', op: 'confirm', changes: [], result: 'ok', error: null, notes: ['Checks: Hilltop TCP self_test passed; Radio online traffic'] }, { seq: 1, time: 1, id: P.id, actor: 'bob', op: 'auto_rollback', changes: [], result: 'rolled_back', error: 'Reticulum on Radio did not answer a test request', notes: [`Checks with the change: ${EVIL} self_test failed`, 'Checks after the rollback: Radio online traffic'] }], more: false }] } });
  const results = a.byId('manage-audit-rows').children.map((tr) => tr.children[4].textContent);
  assert.deepEqual(results, ['Done. Checks: Hilltop TCP self_test passed; Radio online traffic', `Rolled back: Reticulum on Radio did not answer a test request. Checks with the change: ${EVIL} self_test failed Checks after the rollback: Radio online traffic`]);
});

// ---- the manage page: layout, feedback beside the action, kept edits and waits ----

test('manage page: a refusal with retryAfter keeps the pressed button off, counts down beside it, and says when it works again', async () => {
  const stamping = { error: "The node is still making its announce stamp, so it can't test a Reticulum change yet. Nothing was changed. Try again in 3 seconds.", code: 'stamping', retryAfter: 3 };
  const p = await managePage({ routes: { [`GET ${NODE_URL}`]: [200, retState()], 'POST /api/manage/reticulum': [429, stamping] } });
  const $ = p.byId;
  assert.equal(p.timers.length, 0, 'no timer without a wait');
  const all = retControls(p);
  all.find((e) => e.id === all.find((l) => l.tag === 'label' && l.textContent === 'Enabled').htmlFor).value = 'no';
  $('manage-ret-form').fire('submit');
  await settle();
  // The words of the node are read out once, in the alert; the countdown is for the eyes (aria-hidden in the page).
  assert.equal($('manage-ret-error').textContent, stamping.error);
  assert.equal($('manage-ret-apply').disabled, true);
  assert.equal($('manage-ret-apply-retry').textContent, 'You can try again in 3 s.');
  assert.equal(p.timers.length, 1);
  const html = await read('manage.html');
  assert.match(html, /<span id="manage-ret-apply-retry" class="manage-retry" aria-hidden="true"><\/span>/);
  await p.tick();
  assert.equal($('manage-ret-apply-retry').textContent, 'You can try again in 2 s.');
  assert.equal($('manage-ret-apply').disabled, true);
  await p.tick();
  assert.equal($('manage-ret-apply-retry').textContent, 'You can try again in 1 s.');
  await p.tick();
  assert.equal($('manage-ret-apply').disabled, false);
  assert.equal($('manage-ret-apply-retry').textContent, '');
  assert.equal($('manage-ret-error').textContent, '', 'the old refusal is gone');
  assert.equal($('manage-status').textContent, 'You can try again now.');
  assert.equal(p.timers.length, 0);
  // The button works again: the same press is asked again.
  $('manage-ret-form').fire('submit');
  await settle();
  assert.equal(p.posts().filter((x) => x.url === '/api/manage/reticulum').length, 2);
});

test('manage page: a wait on Restart, Save or Roll back switches only that button off; a refusal without a wait, or a 400 that carries one, switches nothing off', async () => {
  const p = await managePage({ routes: { 'POST /api/manage/restart': [503, { error: 'The node restarted moments ago. Try again in 2 seconds.', code: 'before_start', retryAfter: 2 }] } });
  const $ = p.byId;
  $('manage-restart').fire('click');
  await settle();
  assert.equal($('manage-restart-error').textContent, 'The node restarted moments ago. Try again in 2 seconds.');
  assert.equal($('manage-restart').disabled, true);
  assert.equal($('manage-restart-retry').textContent, 'You can try again in 2 s.');
  assert.equal($('manage-save').disabled, false);
  assert.equal($('manage-rollback').disabled, false);
  await p.tick();
  await p.tick();
  assert.equal($('manage-restart').disabled, false);
  // Save: a rate limit; while it runs, a repaint of the form (Turn off, a reload) keeps Save off.
  let posts = 0;
  const q = await managePage({ routes: { 'POST /api/manage/settings': () => (++posts === 1 ? [429, { error: 'The node is limiting changes right now. Try again in 1 minute.', code: 'rate_limited', retryAfter: 60 }] : [200, { ok: true, applied: [] }]) } });
  q.fields().find((e) => e.tag === 'input' && e.value === 'Hilltop').value = 'Valley';
  q.byId('manage-form').fire('submit');
  await settle();
  assert.equal(q.byId('manage-save').disabled, true);
  assert.equal(q.byId('manage-save-retry').textContent, 'You can try again in 60 s.');
  q.fields().find((e) => e.attrs['aria-label'] === 'Turn off Hub').fire('click');
  await settle();
  assert.equal(q.byId('manage-save').disabled, true, 'still waiting after the form was built again');
  // Roll back.
  const r = await managePage({ routes: { 'POST /api/manage/rollback': [429, { error: 'Too often. Try again in 5 seconds.', retryAfter: 5 }] } });
  r.byId('manage-rollback').fire('click');
  await settle();
  assert.equal(r.byId('manage-rollback').disabled, true);
  assert.equal(r.byId('manage-rollback-retry').textContent, 'You can try again in 5 s.');
  // No retryAfter, or a status that is not 429 or 503: the button stays as it was.
  for (const [status, body] of [[409, { error: 'Pending.', code: 'pending' }], [400, { error: 'Bad.', retryAfter: 9 }]]) {
    const s = await managePage({ routes: { 'POST /api/manage/restart': [status, body] } });
    s.byId('manage-restart').fire('click');
    await settle();
    assert.equal(s.byId('manage-restart').disabled, false, String(status));
    assert.equal(s.timers.length, 0, String(status));
  }
});

test('manage page: the form says how many settings changed, and keeps the edits when it is built again for the same node', async () => {
  const p = await managePage();
  const $ = p.byId;
  assert.equal($('manage-form-dirty').textContent, 'No changes.');
  const name = p.fields().find((e) => e.tag === 'input' && e.value === 'Hilltop');
  name.value = 'Valley';
  name.fire('input');
  assert.equal($('manage-form-dirty').textContent, '1 setting changed, not saved yet.');
  const box = p.fields().find((e) => e.tag === 'input' && e.type === 'checkbox');
  box.checked = false;
  box.fire('change');
  assert.equal($('manage-form-dirty').textContent, '2 settings changed, not saved yet.');
  name.value = 'Hilltop';
  name.fire('input');
  box.checked = true;
  box.fire('change');
  assert.equal($('manage-form-dirty').textContent, 'No changes.');
  // Turn off builds the form again: what was typed stays, and the focus goes to the row of the service.
  const off = await managePage({ routes: { 'POST /api/manage/settings': [200, { ok: true, applied: [] }] } });
  off.fields().find((e) => e.tag === 'input' && e.value === 'Hilltop').value = 'Typed';
  off.fields().find((e) => e.attrs['aria-label'] === 'Turn off Hub').fire('click');
  await settle();
  const again = off.fields().find((e) => e.tag === 'input' && e.id === name.id);
  assert.equal(again.value, 'Typed');
  assert.equal(off.byId('manage-form-dirty').textContent, '1 setting changed, not saved yet.');
  assert.ok(FakeElement.active && FakeElement.active.tag === 'p' && FakeElement.active.textContent === 'Hub: on', 'the focus is on the row that was turned off');
  // A save has used the edits: the form starts clean.
  const saved = await managePage({ routes: { 'POST /api/manage/settings': [200, { ok: true, applied: [{ key: 'pn_name' }] }] } });
  saved.fields().find((e) => e.tag === 'input' && e.value === 'Hilltop').value = 'Valley';
  saved.byId('manage-form').fire('submit');
  await settle();
  assert.equal(saved.fields().some((e) => e.tag === 'input' && e.value === 'Valley'), false);
  // The words of the dialog say what each setting becomes.
  assert.equal(saved.asked[0].why, `Changes ${EVIL} to "Valley".`);
});

test('manage page: the Reticulum form marks a changed field with its old value in words, counts the changes, and keeps them across a reload', async () => {
  let reads = 0;
  const p = await managePage({ routes: { [`GET ${NODE_URL}`]: () => (++reads, [200, retState()]), 'POST /api/manage/reticulum': [409, { error: 'The Reticulum configuration was changed elsewhere since the page loaded it.', code: 'stale_revision' }] } });
  const $ = p.byId;
  assert.equal($('manage-ret-dirty').textContent, 'No changes.');
  const all = retControls(p);
  const byLabel = (text) => all.find((e) => e.id === all.filter((l) => l.tag === 'label' && l.textContent === text)[0].htmlFor);
  const rowOf = (input) => all.find((e) => e.children.includes(input));
  const bitrate = byLabel('Bitrate (bits per second)');
  bitrate.value = '19200';
  bitrate.fire('input');
  const row = rowOf(bitrate);
  assert.equal(row.className, 'manage-field changed');
  const was = row.children.find((c) => c.textContent.startsWith('Was:'));
  assert.equal(was.textContent, 'Was: 9600');
  assert.equal(was.hidden, false);
  assert.equal($('manage-ret-dirty').textContent, '1 change not applied yet.');
  const enabled = byLabel('Enabled');
  enabled.value = 'no';
  enabled.fire('change');
  assert.equal($('manage-ret-dirty').textContent, '2 changes not applied yet.');
  // Back to the node's value: no longer marked.
  bitrate.value = '9600.0';
  bitrate.fire('input');
  assert.equal(row.className, 'manage-field');
  assert.equal(row.children.find((c) => c.textContent.startsWith('Was:')).hidden, true, 'the old value is hidden again');
  assert.equal($('manage-ret-dirty').textContent, '1 change not applied yet.');
  // A stale revision loads the node again: the edit of a field whose value did not change stays.
  $('manage-ret-form').fire('submit');
  await settle();
  assert.equal(reads, 2);
  const after = retControls(p);
  const enabledAgain = after.find((e) => e.id === after.filter((l) => l.tag === 'label' && l.textContent === 'Enabled')[0].htmlFor);
  assert.equal(enabledAgain.value, 'no');
  assert.equal($('manage-ret-dirty').textContent, '1 change not applied yet.');
  // After a change that was applied, the form starts clean (the job ends with a load that keeps nothing).
  assert.match(await read('site.css'), /\.manage-field\.changed \{ border-left: 3px solid var\(--accent\)/);
});

test('manage page: the status region is only written when its words change, and the list of checks is not built again for the same checks', async () => {
  const P = { id: '2'.repeat(16), state: 'probation', confirm_by: Math.floor(Date.now() / 1000) + 300, changes: [], problems: [], checks: [{ interface: 'Radio', kind: 'online', result: 'traffic' }] };
  const job = { id: P.id, state: 'probing', nodeState: 'probation', confirmBy: P.confirm_by, outcome: null, message: 'Checking.', updatedAt: 'x', checks: P.checks };
  const p = await managePage({ routes: { [`GET ${NODE_URL}`]: [200, retState({ pending: P, confirm: { ...job } })], [`GET ${CONFIRM_URL}`]: [200, { job }] } });
  const $ = p.byId;
  const writes = [];
  for (const id of ['manage-ret-pending', 'manage-ret-status', 'manage-clock', 'manage-status', 'manage-ret-checks', 'manage-ret-left']) {
    const e = $(id);
    const set = Object.getOwnPropertyDescriptor(FakeElement.prototype, 'textContent').set;
    const get = Object.getOwnPropertyDescriptor(FakeElement.prototype, 'textContent').get;
    Object.defineProperty(e, 'textContent', { get, set(v) { writes.push(id); set.call(this, v); }, configurable: true });
  }
  // The first read of the job starts the countdown (that is a change); after it nothing changes.
  await p.tick();
  const item = $('manage-ret-checks').children[0];
  writes.length = 0;
  await p.tick();
  await p.tick();
  assert.deepEqual(writes, [], 'nothing was written: the words did not change');
  assert.equal($('manage-ret-checks').children[0], item, 'the same list item');
  // The countdown is outside the live region, and the page says nothing to click.
  assert.match($('manage-ret-left').textContent, /^About [45] minutes left\.$/);
  assert.equal($('manage-ret-auto').textContent, 'The website is testing the change. Nothing to click: it is kept if the test passes, and put back by the node if not.');
  assert.equal($('manage-pending-line').hidden, false);
  assert.equal($('manage-pending-text').textContent, $('manage-ret-pending').textContent);
  assert.equal($('manage-ret-edit').className, 'acct-card on-probation');
  const html = await read('manage.html');
  assert.doesNotMatch(/<div id="manage-ret-live"[\s\S]*?<\/div>/.exec(html)[0], /manage-ret-left|manage-ret-auto/);
  // A change of the words is written, once.
  job.checks = [{ interface: 'Radio', kind: 'online', result: 'no_traffic' }];
  await p.tick();
  assert.deepEqual(writes, ['manage-ret-checks']);
  assert.equal($('manage-ret-checks').children[0].textContent, 'Radio: online, no traffic yet');
  // Without a job that is followed there is no countdown, and no timer is made for one.
  const q = await managePage({ routes: { [`GET ${NODE_URL}`]: [200, retState({ pending: P })] } });
  assert.equal(q.byId('manage-ret-left').hidden, true);
  assert.equal(q.timers.length, 0);
  assert.equal(q.byId('manage-ret-auto').textContent, 'Nothing to click here: the node puts the old config back by itself if the change is not kept in time.');
});

test('manage page: a disabled control has its reason beside it, and the list of links hides the sections that are not there', async () => {
  const p = await managePage({ me: { ...MANAGE, secondFactor: false } });
  const $ = p.byId;
  const why = 'You can look but not change anything yet. See the notice at the top of the page.';
  assert.equal($('manage-why').textContent, why);
  assert.equal($('manage-why').hidden, false);
  assert.equal($('manage-restart-why').textContent, why);
  assert.equal($('manage-restart').attrs['aria-describedby'], 'manage-restart-why');
  assert.equal($('manage-last-why').textContent, why);
  assert.equal($('manage-last-why').hidden, false);
  const html = await read('manage.html');
  assert.match(html, /<button id="manage-save"[^>]*aria-describedby="manage-form-dirty manage-why"/);
  assert.match(html, /<button id="manage-rollback"[^>]*aria-describedby="manage-last-why"/);
  assert.ok(p.fields().filter((e) => e.tag === 'button').every((b) => b.attrs['aria-describedby'].endsWith('manage-why')));
  // A user who may change things sees no reason, and every section has its link.
  const ok = await managePage();
  assert.equal(ok.byId('manage-why').hidden, true);
  assert.equal(ok.byId('manage-restart-why').hidden, true);
  assert.equal(ok.byId('manage-restart-why').textContent, '');
  assert.equal(ok.byId('manage-nav').hidden, false);
  for (const id of ['manage-settings', 'manage-ret', 'manage-restart-card', 'manage-last-card', 'manage-audit-card']) assert.equal(ok.byId(`nav-${id}`).hidden, false, id);
  // The Reticulum change section is not there for this node, so its link is not either.
  assert.equal(ok.byId('nav-manage-ret-edit').hidden, true);
  // A node that cannot be read: its sections are gone, and so are their links and the list.
  const down = await managePage({ routes: { [`GET ${NODE_URL}`]: [502, { error: 'The node could not be reached.', code: 'network' }] } });
  assert.equal(down.byId('nav-manage-settings').hidden, true);
  assert.equal(down.byId('nav-manage-restart-card').hidden, true);
  assert.equal(down.byId('nav-manage-ret').hidden, true);
  // A restart that waits says why beside the button: the node's rate limit, or a change on probation.
  const later = await managePage({ routes: { [`GET ${NODE_URL}`]: [200, nodeState({ restart_allowed_at: Math.floor(Date.now() / 1000) + 600 })] } });
  assert.match(later.byId('manage-restart-why').textContent, /^The node allows the next restart at .+\.$/);
  assert.equal(later.byId('manage-restart').disabled, true);
  const busy = await managePage({ routes: { [`GET ${NODE_URL}`]: [200, retState({ pending: { id: '2'.repeat(16), state: 'restarting', changes: [], problems: [] } })] } });
  assert.equal(busy.byId('manage-restart-why').textContent, 'A Reticulum change is being tested. Restart waits until it is kept or put back.');
  // Last change: the wording of the empty case, and of what Roll back does.
  const none = await managePage({ routes: { [`GET ${AUDIT_URL}`]: [200, { entries: [], more: true }] } });
  assert.equal(none.byId('manage-last').textContent, 'Nothing to roll back: there is no settings change in the latest entries. Use Older entries below to look further back.');
  assert.equal(none.byId('manage-last-note').hidden, true);
  assert.equal(ok.byId('manage-last-note').hidden, false);
});

test('manage page: an error is scrolled into view where it can be scrolled, focus goes to the place that changed, and the fake page without scrolling still works', async () => {
  const p = await managePage({ routes: { 'POST /api/manage/restart': [202, { ok: true, id: 'r'.repeat(16) }], 'POST /api/manage/rollback': [200, { ok: true }] } });
  const scrolled = [];
  p.byId('manage-form-error').scrollIntoView = (o) => scrolled.push(o);
  p.byId('manage-form').fire('submit');
  await settle();
  assert.deepEqual(plain(scrolled), [{ block: 'nearest' }]);
  p.byId('manage-restart').fire('click');
  await settle();
  assert.equal(FakeElement.active, p.byId('manage-restart-h'));
  p.byId('manage-rollback').fire('click');
  await settle();
  assert.equal(FakeElement.active, p.byId('manage-last-h'));
  const html = await read('manage.html');
  for (const id of ['manage-restart-h', 'manage-last-h', 'manage-ret-edit-h', 'manage-settings-h']) assert.match(html, new RegExp(`<h2 id="${id}"[^>]*tabindex="-1"`), id);
});

test('the manage and status pages use the width of a large screen, and keep sticky parts from hiding what has the focus', async () => {
  const css = await read('site.css');
  for (const name of ['manage.html', 'status.html', 'join.html', 'downloads.html', 'account.html', 'users.html']) assert.match(await read(name), /<main id="main" tabindex="-1" class="wrap wide/, name);
  assert.match(await read('manage.html'), /<main id="main" tabindex="-1" class="wrap wide acct-page manage-page">/);
  assert.match(css, /body:has\(> main\.wide\) \.wrap \{ max-width: 1400px;/);
  assert.match(css, /html:has\(\.manage-page\) \{ scroll-padding-top: 80px; scroll-padding-bottom: 72px; \}/);
  assert.match(css, /\.manage-live \{ position: sticky; top: 0;/);
  assert.match(css, /\.manage-bar \{ position: sticky; bottom: 0;/);
  assert.match(css, /main\.wide:has\(#hosts\) \{ display: grid; grid-template-columns: minmax\(0, 1fr\) 22rem;/);
  // The strip holds the status and the error, as the pinned markup, and is no landmark.
  const strip = /<div class="manage-live">([\s\S]*?)<\/div>/.exec(await read('manage.html'))[1];
  assert.match(strip, /<p id="manage-status" class="note" role="status">/);
  assert.match(strip, /<p id="manage-error" class="login-error" role="alert"><\/p>/);
  // The form is a settings form with its bar: the error and Save sit together.
  const bar = /<div class="manage-bar">([\s\S]*?)<\/form>/.exec(await read('manage.html'))[1];
  assert.match(bar, /id="manage-form-error"[\s\S]*id="manage-save"[\s\S]*id="manage-form-dirty"/);
  // Nothing is styled or scripted inline (the site's policy is style-src 'self', script-src 'self').
  assert.doesNotMatch(await read('manage.html'), /\sstyle=|<script(?![^>]*\ssrc=)/);
  assert.doesNotMatch(await read('manage-page.js'), /\.style\b|cssText|setAttribute\('style'/);
});

test('manage page: "(may be empty)" is in the label of an optional setting once, also when the node already says it', async () => {
  const settings = [
    { key: 'pn_name', label: 'Propagation node name', help: '', kind: 'optional', access: 'change', value: '' },
    { key: 'hub_greeting', label: 'Hub greeting (may be empty)', help: '', kind: 'optional', access: 'change', value: '' },
    { key: 'pn_storage', label: 'Storage', help: '', kind: 'number', access: 'change', value: '5' },
  ];
  const p = await managePage({ routes: { [`GET ${NODE_URL}`]: [200, nodeState({ settings })] } });
  assert.deepEqual(p.fields().filter((e) => e.tag === 'label').map((e) => e.textContent), ['Propagation node name (may be empty)', 'Storage', 'Hub greeting (may be empty)']);
});

test('every page has the same 1400px header and footer, and the wide pages lay themselves out as designed, in files and in rules', async () => {
  const css = await read('site.css');
  // The frame does not move between pages: header and footer are 1400px wide whatever main is.
  assert.match(css, /header\.top \.wrap, footer \.wrap \{ max-width: 1400px; padding-inline: clamp\(16px, 3vw, 32px\); \}/);
  assert.match(css, /body:has\(> main\.wide\) \.wrap \{ max-width: 1400px;/);
  // The footer block that the server rewrites is as it was.
  for (const name of ['index.html', 'status.html', 'join.html', 'downloads.html', 'account.html', 'users.html', 'manage.html']) assert.match(await read(name), /<footer>\s*<div class="wrap">/, name);
  // Home is not wide.
  assert.doesNotMatch(await read('index.html'), /<main[^>]*\bwide\b/);
  // Join: the QR and the other entry points are one side column, last in the document order, sticky only in a tall window.
  const join = await read('join.html');
  const side = /<div class="join-side">([\s\S]*?)\n  <\/div>\n  <noscript>/.exec(join);
  assert.ok(side, 'the side column wraps the last two sections');
  assert.match(side[1], /<h2>From an Android phone<\/h2>[\s\S]*<img class="qr" src="\/join-qr\.svg"[\s\S]*<h2>Other entry points<\/h2>[\s\S]*id="status-ep" role="status"/);
  assert.doesNotMatch(join.slice(0, join.indexOf('<div class="join-side">')), /class="qr"/);
  assert.match(css, /@media \(min-width: 1100px\) and \(min-height: 700px\) \{\s*\.join-side \{ position: sticky; top: 16px; \}/);
  assert.match(css, /main\.wide:has\(> \.join-side\) \{ display: grid; grid-template-columns: minmax\(0, 46rem\) minmax\(18rem, 26rem\);/);
  // Downloads: the projects side by side from 1000px.
  assert.match(css, /@media \(min-width: 1000px\) \{\s*#projects \{ grid-template-columns: repeat\(auto-fit, minmax\(min\(100%, 34rem\), 1fr\)\);/);
  // Account: two columns from 1000px for the cards in the signed-in part only; the alert spans both.
  assert.match(css, /#acct:not\(\[hidden\]\) \{ display: grid; grid-template-columns: repeat\(2, minmax\(0, 1fr\)\);/);
  assert.match(css, /#acct > #acct-must-change \{ grid-column: 1 \/ -1;/);
  assert.match(css, /#acct-signin \{ max-width: 32rem; \}/);
  // Users: the card stack is on below 1100px for this page only; the global rule (700px, used by the Manage tables too) is as it was.
  assert.match(css, /@media \(max-width: 1099px\) \{\s*\.users-page \.users-table, /);
  assert.match(css, /@media \(max-width: 700px\) \{\s*\.users-table:not\(\.manage-ret-table\), /);
  assert.match(css, /\.users-page td\.users-actions \{ min-width: 20rem; \}/);
  assert.match(css, /\.users-page #users > \.acct-card > \.note \{ max-width: 70ch; \}/);
  // One h1 size on the account pages, as on the others.
  assert.match(css, /\.acct-page h1 \{ margin: 0 0 8px; font-size: 22px; \}/);
  // The cells the phone layout reads still have their labels.
  assert.match(await read('users-page.js'), /cell\(tr, 'Actions', undefined, 'users-actions'\)/);
});
