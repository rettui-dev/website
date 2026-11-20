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
  assert.ok(labels('bob').includes('Change the role of bob'));
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
  assert.equal((sign.match(/rettuiPasskey\.get\(/g) ?? []).length, 1);
  assert.match(sign, /key\.addEventListener\('click', usePasskey\)/);
  assert.match(sign, /key\.type = 'button'/);
  assert.match(sign, /post\('\/login\/passkey', /);
  assert.match(await read('step-up.js'), /\/api\/account\/passkeys\/challenge/);
  const page = await read('account-page.js');
  for (const p of ['/api/account/passkeys/begin', '/api/account/passkeys/finish', '/api/account/passkeys/rename', '/api/account/passkeys/remove']) assert.ok(page.includes(`'${p}'`), p);
});

// ---- the manage page ----

test('the manage page: text only, the request header, the step-up for every change, and its regions', async () => {
  const js = await read('manage-page.js');
  assert.doesNotMatch(js, /innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function/);
  assert.match(js, /'X-Rettui-Request': '1'/);
  assert.match(js, /'Content-Type': 'application\/json'/);
  for (const p of ['/api/manage/settings', '/api/manage/restart', '/api/manage/rollback']) assert.match(js, new RegExp(`confirmed\\('${p.replace(/\//g, '\\/')}'`), p);
  assert.match(js, /window\.rettuiStepUp\.ask\(/);
  assert.match(js, /var POLL_MS = 3000;/);
  assert.match(js, /var POLL_LIMIT_MS = 120000;/);
  const html = await read('manage.html');
  assert.match(html, /<meta name="robots" content="noindex">/);
  assert.match(html, /<p id="manage-status" class="note" role="status">/);
  for (const id of ['manage-error', 'manage-form-error', 'manage-restart-error', 'manage-rollback-error']) assert.match(html, new RegExp(`<p id="${id}" class="login-error" role="alert"></p>`), id);
  assert.match(html, /<label for="manage-node">Node<\/label>\s*<select id="manage-node"/);
  assert.match(html, /<input id="manage-revision" type="hidden"/);
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
