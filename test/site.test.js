import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Monitor } from '../lib/monitor.js';
import { loadConfig, loadConfigFile, loadNodes } from '../lib/config.js';
import { createApp } from '../lib/app.js';
import { MAX_LOGO_BYTES, NO_SITE, renderStatus, sniffLogo } from '../lib/site.js';

const publicDir = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'public');
const NODES = 'nodes:\n  - address: a.test:1\n';
const PNG = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.alloc(40)]);
const SVG = Buffer.from('<?xml version="1.0"?>\n<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"><rect width="10" height="10"/></svg>');
const tmp = () => fs.mkdtemp(path.join(os.tmpdir(), 'website-site-'));

async function configFile(text, files = {}) {
  const dir = await tmp();
  for (const [name, content] of Object.entries(files)) await fs.writeFile(path.join(dir, name), content);
  const file = path.join(dir, 'config.yaml');
  await fs.writeFile(file, text);
  return file;
}

const refuses = (text, re) => assert.throws(() => loadConfig(text), re);

test('site_mode: default full, status accepted, anything else stops the start', () => {
  assert.equal(loadConfig(NODES).siteMode, 'full');
  assert.deepEqual(loadConfig(NODES).site.links, []);
  assert.equal(loadConfig(`site_mode: status\n${NODES}`).siteMode, 'status');
  for (const bad of ['Status', 'both', '""', '1', 'true', '[status]', '~']) refuses(`site_mode: ${bad}\n${NODES}`, /site_mode must be full or status/);
});

test('SITE_MODE: environment value, and not together with CONFIG_FILE', async () => {
  assert.equal((await loadNodes({})).siteMode, 'full');
  assert.equal((await loadNodes({ SITE_MODE: 'status' })).siteMode, 'status');
  assert.equal((await loadNodes({ SITE_MODE: 'full' })).siteMode, 'full');
  await assert.rejects(loadNodes({ SITE_MODE: 'nope' }), /SITE_MODE must be full or status/);
  await assert.rejects(loadNodes({ SITE_MODE: '' }), /SITE_MODE is empty/);
  const file = await configFile(NODES);
  await assert.rejects(loadNodes({ CONFIG_FILE: file, SITE_MODE: 'status' }), /not both/);
  assert.equal((await loadNodes({ CONFIG_FILE: file })).siteMode, 'full');
});

test('site: values are checked, and an error never repeats the value', () => {
  const ok = loadConfig(`site:
  name: " Acme Net "
  description: A backbone.
  footer: Run by Acme
  links:
    - { label: Docs, url: "https://acme.example/docs?a=1&b=2" }
    - { label: Chat, url: "http://chat.example" }
${NODES}`).site;
  assert.equal(ok.name, 'Acme Net');
  assert.deepEqual(ok.links, [{ label: 'Docs', url: 'https://acme.example/docs?a=1&b=2' }, { label: 'Chat', url: 'http://chat.example/' }]);
  const bad = {
    'unknown key': 'site:\n  colour: red\n',
    'not a map': 'site: [a]\n',
    'empty name': 'site:\n  name: ""\n',
    'long name': `site:\n  name: ${'x'.repeat(49)}\n`,
    'name not text': 'site:\n  name: 5\n',
    'control chars': 'site:\n  name: "a\\u0007b"\n',
    'bidi chars': 'site:\n  footer: "a\\u202eb"\n',
    'long description': `site:\n  description: ${'x'.repeat(201)}\n`,
    'long footer': `site:\n  footer: ${'x'.repeat(201)}\n`,
    'seven links': `site:\n  links:\n${Array.from({ length: 7 }, (_, i) => `    - { label: L${i}, url: "https://a.example" }`).join('\n')}\n`,
    'links not a list': 'site:\n  links: https://a.example\n',
    'link not a map': 'site:\n  links: [x]\n',
    'link extra key': 'site:\n  links:\n    - { label: A, url: "https://a.example", target: x }\n',
    'link no label': 'site:\n  links:\n    - { url: "https://a.example" }\n',
    'link long label': `site:\n  links:\n    - { label: ${'x'.repeat(33)}, url: "https://a.example" }\n`,
    'link ftp': 'site:\n  links:\n    - { label: A, url: "ftp://a.example/secret" }\n',
    'link javascript': 'site:\n  links:\n    - { label: A, url: "javascript:alert(1)" }\n',
    'link credentials': 'site:\n  links:\n    - { label: A, url: "https://user:hunter2@a.example" }\n',
    'link user only': 'site:\n  links:\n    - { label: A, url: "https://user@a.example" }\n',
    'link not a url': 'site:\n  links:\n    - { label: A, url: "not a url hunter2" }\n',
    'link relative': 'site:\n  links:\n    - { label: A, url: "/status" }\n',
    'logo not text': 'site:\n  logo: 5\n',
  };
  for (const [what, text] of Object.entries(bad)) {
    assert.throws(() => loadConfig(`${text}${NODES}`), (err) => {
      assert.match(err.message, /^CONFIG_FILE: /, what);
      for (const secret of ['hunter2', 'secret', 'alert(1)', 'red']) assert.equal(err.message.includes(secret), false, `${what}: ${err.message}`);
      return true;
    }, what);
  }
});

test('site.logo: read at start, checked by its first bytes and size, errors say no content', async () => {
  const file = await configFile('site:\n  logo: logo.png\n' + NODES, { 'logo.png': PNG });
  const site = (await loadConfigFile(file)).site;
  assert.equal(site.logo.mime, 'image/png');
  assert.equal(site.logo.bytes.length, PNG.length);
  assert.equal('logoPath' in site, false);
  const dir = path.dirname(file);
  const bad = async (name, content, re) => {
    await fs.writeFile(path.join(dir, name), content);
    await fs.writeFile(file, `site:\n  logo: ${name}\n${NODES}`);
    await assert.rejects(loadConfigFile(file), (err) => (assert.match(err.message, re), !err.message.includes(dir) && !err.message.includes('TOPSECRET')));
  };
  await bad('text.png', 'TOPSECRET not an image', /^CONFIG_FILE: site\.logo is not a PNG, JPEG, WebP or SVG image$/);
  await bad('script.svg', '<svg xmlns="http://www.w3.org/2000/svg"><script>TOPSECRET</script></svg>', /not a PNG/);
  await bad('handler.svg', '<svg xmlns="http://www.w3.org/2000/svg" onload="TOPSECRET"/>', /not a PNG/);
  await bad('html.svg', '<html><svg></svg></html>', /not a PNG/);
  await bad('big.png', Buffer.concat([PNG, Buffer.alloc(MAX_LOGO_BYTES)]), /at most 512 KiB/);
  await bad('empty.png', '', /not a PNG/);
  await fs.writeFile(file, `site:\n  logo: missing.png\n${NODES}`);
  await assert.rejects(loadConfigFile(file), /^Error: CONFIG_FILE: site\.logo cannot be read \(ENOENT\)$/);
  await fs.mkdir(path.join(dir, 'folder.png'));
  await fs.writeFile(file, `site:\n  logo: folder.png\n${NODES}`);
  await assert.rejects(loadConfigFile(file), /at most 512 KiB/);
  // A file of exactly the largest size is fine.
  await fs.writeFile(path.join(dir, 'max.png'), Buffer.concat([PNG, Buffer.alloc(MAX_LOGO_BYTES - PNG.length)]));
  await fs.writeFile(file, `site:\n  logo: max.png\n${NODES}`);
  assert.equal((await loadConfigFile(file)).site.logo.bytes.length, MAX_LOGO_BYTES);
});

test('sniffLogo: the four kinds, and the look-alikes', () => {
  assert.equal(sniffLogo(PNG), 'image/png');
  assert.equal(sniffLogo(Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0])), 'image/jpeg');
  assert.equal(sniffLogo(Buffer.concat([Buffer.from('RIFF'), Buffer.alloc(4), Buffer.from('WEBPVP8 ')])), 'image/webp');
  assert.equal(sniffLogo(Buffer.concat([Buffer.from('RIFF'), Buffer.alloc(4), Buffer.from('WAVEfmt ')])), null);
  assert.equal(sniffLogo(SVG), 'image/svg+xml');
  assert.equal(sniffLogo(Buffer.from('﻿<!-- hi --><svg viewBox="0 0 1 1"></svg>')), 'image/svg+xml');
  assert.equal(sniffLogo(Buffer.from('<svg><SCRIPT>1</SCRIPT></svg>')), null);
  assert.equal(sniffLogo(Buffer.from('<svg><foreignObject/></svg>')), null);
  assert.equal(sniffLogo(Buffer.from('GIF89a')), null);
  assert.equal(sniffLogo(Buffer.alloc(0)), null);
});

// ---- the page and the server

const read = (name) => fs.readFile(path.join(publicDir, name), 'utf8');

async function start({ mode = 'full', site = NO_SITE, releases = null } = {}) {
  const dataDir = await tmp();
  const monitor = new Monitor({ targets: [{ host: 'a.test', port: 4242 }], dataDir, probeFn: async () => ({ up: true, ms: 9 }) });
  await monitor.checkAll();
  const server = createApp({ monitor, publicDir, releases, mode, site });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  const get = (p, method = 'GET') => new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path: p, method }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks), text: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('error', reject);
    req.end();
  });
  return { get, close: () => (server.closeAllConnections(), new Promise((r) => server.close(r))) };
}

const SITE = {
  name: 'Acme <Net> & "Co"',
  logo: { bytes: PNG, mime: 'image/png' },
  links: [{ label: 'Docs & <more>', url: 'https://acme.example/a?x=1&y="2"' }, { label: 'Chat', url: 'http://chat.example/' }],
  description: 'Our <b>backbone</b>',
  footer: 'Run by "us" & <them>',
};

test('full mode with no site serves the existing pages byte for byte', async () => {
  const s = await start();
  try {
    for (const [url, file] of [['/', 'index.html'], ['/status', 'status.html'], ['/status.html', 'status.html'], ['/join', 'join.html'], ['/downloads', 'downloads.html']]) {
      const r = await s.get(url);
      assert.equal(r.status, 200, url);
      assert.equal(r.text, await read(file), url);
    }
    assert.equal((await s.get('/brand/site-logo')).status, 404);
  } finally {
    await s.close();
  }
});

test('renderStatus: full mode with no site changes nothing', async () => {
  const html = await read('status.html');
  assert.equal(renderStatus(html, { mode: 'full', site: NO_SITE }), html);
});

test('renderStatus: every block of status.html is found, or it fails loudly', async () => {
  const html = await read('status.html');
  for (const bad of [html.replace('<title>', '<title >'), html.replace('<nav class="links"', '<nav'), html.replace('<footer>', '<footer class="x">'), html.replace('<a class="brand"', '<a class="b"')]) {
    assert.throws(() => renderStatus(bad, { mode: 'status', site: { ...NO_SITE, name: 'x', logo: { mime: 'image/png' }, description: 'd' } }), /block is missing/);
  }
});

test('status mode: / and /status are the status page, with no link to the project pages', async () => {
  const s = await start({ mode: 'status' });
  try {
    const home = await s.get('/');
    assert.equal(home.status, 200);
    assert.match(home.headers['content-type'], /^text\/html/);
    assert.equal((await s.get('/status')).text, home.text);
    assert.equal((await s.get('/status/')).text, home.text);
    assert.equal((await s.get('/status.html')).text, home.text);
    assert.equal((await s.get('/', 'HEAD')).body.length, 0);
    for (const gone of ['/join', '/join/', '/join.html', '/downloads', '/downloads/', '/downloads.html', '/downloads.js', '/index.html', '/copy.js', '/join-qr.svg', '/api/releases', '/brand/site-logo']) {
      const r = await s.get(gone);
      assert.equal(r.status, 404, gone);
      assert.equal(r.headers['x-content-type-options'], 'nosniff', gone);
    }
    for (const ok of ['/api/status', '/api/incidents', '/api/public/stats', '/healthz', '/status.js', '/site.css', '/theme.js', '/netmap.js', '/brand/icon.png']) assert.equal((await s.get(ok)).status, 200, ok);
    for (const word of ['/join', '/downloads', 'docs.rettui.dev', 'github.com/rettui-dev', 'wordmark', 'rettui']) assert.equal(home.text.includes(word), false, word);
    assert.match(home.text, /<title>Status<\/title>/);
    assert.match(home.text, /<a href="\/" aria-current="page">Status<\/a>/);
    assert.match(home.text, /<script src="\/theme\.js"><\/script>/);
    assert.doesNotMatch(home.text.replace(/<script src="[^"]*"( defer)?><\/script>/g, ''), /<script/);
  } finally {
    await s.close();
  }
});

test('status mode with a custom site: name, logo, links, texts, all escaped', async () => {
  const s = await start({ mode: 'status', site: SITE });
  try {
    const page = (await s.get('/')).text;
    assert.equal((await s.get('/status')).text, page);
    assert.match(page, /<title>Status - Acme &lt;Net&gt; &amp; &quot;Co&quot;<\/title>/);
    assert.match(page, /<meta name="description" content="Our &lt;b&gt;backbone&lt;\/b&gt;">/);
    assert.match(page, /<link rel="icon" type="image\/png" href="\/brand\/site-logo">/);
    assert.match(page, /<img class="site-logo" src="\/brand\/site-logo" alt="" height="28">/);
    assert.match(page, /<span class="brand-name">Acme &lt;Net&gt; &amp; &quot;Co&quot;<\/span>/);
    assert.match(page, /<a href="https:\/\/acme\.example\/a\?x=1&amp;y=&quot;2&quot;" rel="noopener noreferrer">Docs &amp; &lt;more&gt;<\/a>/);
    assert.match(page, /<a href="http:\/\/chat\.example\/" rel="noopener noreferrer">Chat<\/a>/);
    assert.match(page, /<p class="site-description">Our &lt;b&gt;backbone&lt;\/b&gt;<\/p>/);
    assert.match(page, /<span>Run by &quot;us&quot; &amp; &lt;them&gt;<\/span>/);
    // Nothing from the config became markup.
    for (const raw of ['<Net>', '<b>', '<more>', '<them>']) assert.equal(page.includes(raw), false, raw);
    assert.equal(page.includes('docs.rettui.dev'), false);
  } finally {
    await s.close();
  }
});

test('status mode: a name without a logo, and a logo without a name', async () => {
  let s = await start({ mode: 'status', site: { ...NO_SITE, name: 'Only Name' } });
  try {
    const page = (await s.get('/')).text;
    assert.match(page, /<a class="brand" href="\/"><span class="brand-name">Only Name<\/span><\/a>/);
    assert.equal(page.includes('site-logo'), false);
    assert.match(page, /<link rel="icon" type="image\/png" href="\/brand\/icon\.png">/);
  } finally {
    await s.close();
  }
  s = await start({ mode: 'status', site: { ...NO_SITE, logo: { bytes: SVG, mime: 'image/svg+xml' } } });
  try {
    const page = (await s.get('/')).text;
    assert.match(page, /<img class="site-logo" src="\/brand\/site-logo" alt="Status" height="28"><\/a>/);
    assert.match(page, /<link rel="icon" type="image\/svg\+xml" href="\/brand\/site-logo">/);
    assert.equal(page.includes('apple-touch-icon'), false);
  } finally {
    await s.close();
  }
});

test('full mode with a site: the status page is branded, the other pages are the same', async () => {
  const s = await start({ site: { ...SITE, logo: null } });
  try {
    const page = (await s.get('/status')).text;
    assert.match(page, /<title>Status - Acme/);
    assert.match(page, /<a href="\/join">Join<\/a>/);
    assert.match(page, /<a href="http:\/\/chat\.example\/" rel="noopener noreferrer">Chat<\/a>/);
    assert.match(page, /<span>Acme &lt;Net&gt; &amp; &quot;Co&quot;<\/span>/);
    assert.equal(page.includes('<span>rettui</span>'), false);
    for (const [url, file] of [['/', 'index.html'], ['/join', 'join.html'], ['/downloads', 'downloads.html']]) assert.equal((await s.get(url)).text, await read(file), url);
  } finally {
    await s.close();
  }
});

test('the logo is served with its type, the strict policy and a sandbox', async () => {
  for (const [bytes, mime] of [[PNG, 'image/png'], [SVG, 'image/svg+xml']]) {
    const s = await start({ mode: 'status', site: { ...NO_SITE, logo: { bytes, mime } } });
    try {
      const r = await s.get('/brand/site-logo');
      assert.equal(r.status, 200);
      assert.equal(r.headers['content-type'], mime);
      assert.equal(r.headers['content-length'], String(bytes.length));
      assert.equal(r.headers['x-content-type-options'], 'nosniff');
      assert.match(r.headers['content-security-policy'], /^default-src 'none'; script-src 'self'; style-src 'self';.*; sandbox$/);
      assert.deepEqual(r.body, bytes);
      const h = await s.get('/brand/site-logo', 'HEAD');
      assert.equal(h.status, 200);
      assert.equal(h.body.length, 0);
      assert.equal((await s.get('/brand/site-logo', 'POST')).status, 405);
    } finally {
      await s.close();
    }
  }
});

test('status mode makes no release requests and asks nothing of the cache', async () => {
  const releases = { snapshot: () => assert.fail('the release cache must not be read') };
  const s = await start({ mode: 'status', releases });
  try {
    assert.equal((await s.get('/api/releases')).status, 404);
  } finally {
    await s.close();
  }
});
