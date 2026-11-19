import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Monitor } from '../lib/monitor.js';
import { createApp } from '../lib/app.js';
import { NO_SITE, openGraphTail, renderProjectPage, renderStatus } from '../lib/site.js';

const publicDir = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'public');
const ORIGIN = 'https://rettui.example';
const PNG = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.alloc(40)]);
const SVG = Buffer.from('<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"/>');
const PAGES = { '/': 'index.html', '/status': 'status.html', '/join': 'join.html', '/downloads': 'downloads.html' };
const read = (name) => fs.readFile(path.join(publicDir, name), 'utf8');

// The content of every meta tag with that attribute value, as a list.
const metas = (html, attr, name) => [...html.matchAll(new RegExp(`<meta ${attr}="${name}" content="([^"]*)"`, 'g'))].map((m) => m[1]);
const one = (html, attr, name) => {
  const all = metas(html, attr, name);
  assert.equal(all.length, 1, `${attr}=${name} appears ${all.length} times`);
  return all[0];
};

async function start({ mode = 'full', site = NO_SITE } = {}) {
  const monitor = new Monitor({ targets: [{ host: 'a.test', port: 4242 }], dataDir: await fs.mkdtemp(path.join(os.tmpdir(), 'website-og-')), probeFn: async () => ({ up: true, ms: 9 }) });
  await monitor.checkAll();
  const server = createApp({ monitor, publicDir, releases: null, mode, site });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  const get = (p) =>
    new Promise((resolve, reject) => {
      http.get({ host: '127.0.0.1', port, path: p }, (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks), text: Buffer.concat(chunks).toString('utf8') }));
      }).on('error', reject);
    });
  return { get, close: () => (server.closeAllConnections(), new Promise((r) => server.close(r))) };
}

test('every page has its own title and description for sharing, and theme-color and description', async () => {
  const titles = new Set();
  for (const file of Object.values(PAGES)) {
    const html = await read(file);
    const title = /<title>([^<]*)<\/title>/.exec(html)[1];
    assert.equal(one(html, 'property', 'og:title'), file === 'index.html' ? 'rettui - Reticulum client for the terminal, browser and Android' : title, file);
    assert.equal(one(html, 'property', 'og:description'), one(html, 'name', 'description'), file);
    assert.equal(one(html, 'property', 'og:type'), 'website');
    assert.equal(one(html, 'property', 'og:site_name'), 'rettui');
    assert.deepEqual(metas(html, 'name', 'theme-color'), ['#16161e', '#f3f3f6']);
    assert.equal(one(html, 'name', 'color-scheme'), 'dark light');
    assert.ok(one(html, 'name', 'description').length > 20);
    titles.add(one(html, 'property', 'og:title'));
    // Nothing that needs the site's address is in the file.
    assert.doesNotMatch(html, /og:url|og:image|twitter:/, file);
  }
  assert.equal(titles.size, 4);
});

test('without a site address the pages are served as the files, with no url or picture', async () => {
  const s = await start();
  try {
    for (const [url, file] of Object.entries(PAGES)) {
      const r = await s.get(url);
      assert.equal(r.text, await read(file), url);
      assert.deepEqual(metas(r.text, 'property', 'og:image'), [], url);
    }
  } finally {
    await s.close();
  }
});

test('with a site address each page gets og:url, the picture and the card, once', async () => {
  const s = await start({ site: { ...NO_SITE, url: ORIGIN } });
  try {
    for (const [url, file] of Object.entries(PAGES)) {
      const r = await s.get(url);
      assert.equal(r.status, 200, url);
      assert.equal(r.headers['content-type'], 'text/html; charset=utf-8');
      assert.equal(one(r.text, 'property', 'og:url'), `${ORIGIN}${url}`, url);
      assert.equal(one(r.text, 'property', 'og:image'), `${ORIGIN}/brand/og-card.png`);
      assert.equal(one(r.text, 'property', 'og:image:width'), '1200');
      assert.equal(one(r.text, 'property', 'og:image:height'), '630');
      assert.ok(one(r.text, 'property', 'og:image:alt').length > 5);
      assert.equal(one(r.text, 'name', 'twitter:card'), 'summary_large_image');
      assert.equal(one(r.text, 'name', 'twitter:image'), `${ORIGIN}/brand/og-card.png`);
      assert.equal(one(r.text, 'property', 'og:title').length > 0, true);
      // Only the tags are added: removing them gives back the file.
      const added = r.text.slice(r.text.indexOf('<meta property="og:url"'), r.text.indexOf('</head>'));
      assert.equal(r.text.replace(added, ''), await read(file), url);
      assert.equal((await s.get(url)).text, r.text, 'the same the second time');
    }
    // /index.html is the home page, too.
    assert.equal(one((await s.get('/index.html')).text, 'property', 'og:url'), `${ORIGIN}/`);
  } finally {
    await s.close();
  }
});

test('the card is a PNG of 1200 by 630 and at most 150 KB, and is served', async () => {
  const file = await fs.readFile(path.join(publicDir, 'brand', 'og-card.png'));
  assert.deepEqual([...file.subarray(0, 8)], [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  assert.equal(file.readUInt32BE(16), 1200);
  assert.equal(file.readUInt32BE(20), 630);
  assert.ok(file.length <= 150 * 1024, `${file.length} bytes`);
  const s = await start({ site: { ...NO_SITE, url: ORIGIN } });
  try {
    const r = await s.get('/brand/og-card.png');
    assert.equal(r.status, 200);
    assert.equal(r.headers['content-type'], 'image/png');
    assert.equal(r.body.length, file.length);
  } finally {
    await s.close();
  }
});

test('status page: the name and description are in the tags, escaped', async () => {
  {
    const page = await read('status.html');
    const site = { ...NO_SITE, name: 'Acme <Net> & "Co"', description: 'Our <b>"backbone"</b> & more', url: ORIGIN };
    const out = renderStatus(page, { mode: 'full', site });
    assert.equal(one(out, 'property', 'og:title'), 'Status - Acme &lt;Net&gt; &amp; &quot;Co&quot;');
    assert.equal(one(out, 'property', 'og:site_name'), 'Acme &lt;Net&gt; &amp; &quot;Co&quot;');
    assert.equal(one(out, 'property', 'og:description'), 'Our &lt;b&gt;&quot;backbone&quot;&lt;/b&gt; &amp; more');
    assert.equal(one(out, 'property', 'og:url'), `${ORIGIN}/status`);
    // A site with a name of its own does not borrow rettui's card.
    assert.deepEqual(metas(out, 'property', 'og:image'), []);
    assert.equal(one(out, 'name', 'twitter:card'), 'summary');
    assert.doesNotMatch(out, /<b>|<Net>/);
  }
});

test('status-only site: names from the site, its own address, and a picture only when it is a raster logo', async () => {
  let s = await start({ mode: 'status', site: { ...NO_SITE, url: ORIGIN } });
  try {
    const r = await s.get('/');
    assert.equal(one(r.text, 'property', 'og:title'), 'Status');
    assert.equal(one(r.text, 'property', 'og:site_name'), 'Status');
    assert.equal(one(r.text, 'property', 'og:description'), 'Reachability of the Reticulum entry points');
    assert.equal(one(r.text, 'property', 'og:url'), `${ORIGIN}/`);
    assert.deepEqual(metas(r.text, 'property', 'og:image'), []);
    assert.equal(one(r.text, 'name', 'twitter:card'), 'summary');
    // The project pages stay hidden, and so does their picture URL's page.
    for (const p of ['/join', '/downloads', '/index.html']) assert.equal((await s.get(p)).status, 404, p);
  } finally {
    await s.close();
  }
  s = await start({ mode: 'status', site: { ...NO_SITE, name: 'Acme Mesh', description: 'Backbone status', url: ORIGIN, logo: { bytes: PNG, mime: 'image/png' } } });
  try {
    const r = await s.get('/');
    assert.equal(one(r.text, 'property', 'og:title'), 'Status - Acme Mesh');
    assert.equal(one(r.text, 'property', 'og:image'), `${ORIGIN}/brand/site-logo`);
    assert.equal(one(r.text, 'name', 'twitter:card'), 'summary');
    assert.equal(metas(r.text, 'property', 'og:image:width').length, 0);
  } finally {
    await s.close();
  }
  s = await start({ mode: 'status', site: { ...NO_SITE, name: 'Acme Mesh', url: ORIGIN, logo: { bytes: SVG, mime: 'image/svg+xml' } } });
  try {
    assert.deepEqual(metas((await s.get('/')).text, 'property', 'og:image'), []);
  } finally {
    await s.close();
  }
});

test('status-only without a site address leaves no url or picture, and names are still set', async () => {
  const s = await start({ mode: 'status', site: { ...NO_SITE, name: 'Acme' } });
  try {
    const r = await s.get('/');
    assert.equal(one(r.text, 'property', 'og:title'), 'Status - Acme');
    assert.doesNotMatch(r.text, /og:url|og:image|twitter:/);
  } finally {
    await s.close();
  }
});

test('the tags escape every value and a page without a head is an error', () => {
  const tags = openGraphTail({ origin: 'https://a.example', path: '/x', image: { path: '/p.png', alt: '"><script>x</script>' } });
  assert.doesNotMatch(tags, /<script>/);
  assert.match(tags, /content="&quot;&gt;&lt;script&gt;x&lt;\/script&gt;"/);
  assert.throws(() => renderProjectPage('<html><body></body></html>', { origin: ORIGIN, path: '/' }), /no head/);
});
