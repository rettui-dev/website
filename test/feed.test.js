import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Monitor } from '../lib/monitor.js';
import { createApp } from '../lib/app.js';
import { MAX_FEED_CONTENT, buildFeed, truncateText, xmlText } from '../lib/feed.js';
import { MAX_NOTES, ReleaseCache, cleanNotes, fromGitHub } from '../lib/releases.js';
import { NO_SITE } from '../lib/site.js';

const publicDir = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'public');
const tmp = () => fs.mkdtemp(path.join(os.tmpdir(), 'website-feed-'));

// A small XML checker without a dependency: walks the text once and throws on anything that is not
// well formed (tags that do not match, a stray "<" or "&", a bad character, a second root). Returns
// the tree as {name, attrs, children, text}.
function parseXml(xml) {
  const NAME_START = /[A-Za-z_:]/;
  const NAME = /[A-Za-z0-9_:.-]/;
  const ENTITIES = new Set(['amp', 'lt', 'gt', 'quot', 'apos']);
  let i = 0;
  const fail = (m) => {
    throw new Error(`${m} at ${i}`);
  };
  const checkChars = (s) => {
    for (const ch of s) {
      const c = ch.codePointAt(0);
      if (!(c === 9 || c === 10 || c === 13 || (c >= 0x20 && c <= 0xd7ff) || (c >= 0xe000 && c <= 0xfffd) || (c >= 0x10000 && c <= 0x10ffff))) fail(`invalid character U+${c.toString(16)}`);
    }
  };
  checkChars(xml);
  const decode = (raw) => {
    let out = '';
    for (let k = 0; k < raw.length; k++) {
      if (raw[k] === '<') fail('"<" in text');
      if (raw[k] !== '&') {
        out += raw[k];
        continue;
      }
      const end = raw.indexOf(';', k);
      if (end < 0) fail('"&" without ";"');
      const name = raw.slice(k + 1, end);
      if (!ENTITIES.has(name)) fail(`unknown entity ${name}`);
      out += { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" }[name];
      k = end;
    }
    return out;
  };
  const readName = () => {
    const s = i;
    if (!NAME_START.test(xml[i] ?? '')) fail('name expected');
    while (i < xml.length && NAME.test(xml[i])) i++;
    return xml.slice(s, i);
  };
  const skipSpace = () => {
    while (i < xml.length && ' \t\r\n'.includes(xml[i])) i++;
  };
  if (!xml.startsWith('<?xml version="1.0" encoding="utf-8"?>')) fail('no XML declaration');
  i = xml.indexOf('?>') + 2;
  skipSpace();
  const element = () => {
    if (xml[i] !== '<') fail('"<" expected');
    i++;
    const name = readName();
    const attrs = {};
    for (;;) {
      const before = i;
      skipSpace();
      if (xml[i] === '/' && xml[i + 1] === '>') {
        i += 2;
        return { name, attrs, children: [], text: '' };
      }
      if (xml[i] === '>') {
        i++;
        break;
      }
      if (i === before) fail('space expected');
      const key = readName();
      if (xml[i] !== '=') fail('"=" expected');
      i++;
      const q = xml[i];
      if (q !== '"' && q !== "'") fail('quote expected');
      const end = xml.indexOf(q, i + 1);
      if (end < 0) fail('unterminated attribute');
      if (Object.hasOwn(attrs, key)) fail(`duplicate attribute ${key}`);
      attrs[key] = decode(xml.slice(i + 1, end));
      i = end + 1;
    }
    const node = { name, attrs, children: [], text: '' };
    for (;;) {
      const lt = xml.indexOf('<', i);
      if (lt < 0) fail('unclosed element');
      node.text += decode(xml.slice(i, lt));
      i = lt;
      if (xml[i + 1] === '/') {
        i += 2;
        if (readName() !== name) fail('mismatched end tag');
        skipSpace();
        if (xml[i] !== '>') fail('">" expected');
        i++;
        return node;
      }
      node.children.push(element());
    }
  };
  const root = element();
  skipSpace();
  if (i !== xml.length) fail('content after the root element');
  return root;
}

const kids = (node, name) => node.children.filter((c) => c.name === name);
const kid = (node, name) => kids(node, name)[0];

const item = (extra = {}, repo = 'rettui-dev/rettui') => ({
  repo,
  fetchedAt: Date.parse('2026-11-19T12:00:00Z'),
  release: { tag: 'v2.1.0', name: 'rettui v2.1.0', publishedAt: '2026-11-18T10:00:00Z', url: `https://github.com/${repo}/releases/tag/v2.1.0`, notes: 'Added things.', assets: [], ...extra },
});

test('the checker itself refuses what is not well formed', () => {
  for (const bad of ['<a>', '<a></b>', '<a>&bogus;</a>', '<a>1 < 2</a>', '<a/><b/>', '<a b=c/>', '<a>\u0001</a>', '<a>&</a>']) {
    assert.throws(() => parseXml(`<?xml version="1.0" encoding="utf-8"?>${bad}`), undefined, bad);
  }
  assert.equal(parseXml('<?xml version="1.0" encoding="utf-8"?><a x="1 &amp; 2">t &lt; u</a>').text, 't < u');
});

test('a feed with releases is valid Atom with stable ids, links and text content', () => {
  const xml = buildFeed([item(), item({ tag: 'v0.3.0', name: 'rngit-rs v0.3.0', publishedAt: '2026-11-19T08:00:00Z', url: 'https://github.com/rettui-dev/rngit-rs/releases/tag/v0.3.0' }, 'rettui-dev/rngit-rs')]);
  const feed = parseXml(xml);
  assert.equal(feed.name, 'feed');
  assert.equal(feed.attrs.xmlns, 'http://www.w3.org/2005/Atom');
  assert.equal(kid(feed, 'id').text, 'tag:rettui.dev,2026:releases');
  assert.equal(kid(feed, 'title').text, 'rettui releases');
  assert.equal(kid(feed, 'updated').text, '2026-11-19T08:00:00Z');
  assert.ok(kid(feed, 'author'));
  // Without a site address there is no link to the site itself.
  assert.equal(kids(feed, 'link').length, 0);
  const entries = kids(feed, 'entry');
  assert.equal(entries.length, 2);
  // Newest first.
  assert.deepEqual(entries.map((e) => kid(e, 'id').text), ['https://github.com/rettui-dev/rngit-rs/releases/tag/v0.3.0', 'https://github.com/rettui-dev/rettui/releases/tag/v2.1.0']);
  const e = entries[1];
  assert.equal(kid(e, 'title').text, 'rettui rettui v2.1.0');
  assert.equal(kid(e, 'updated').text, '2026-11-18T10:00:00Z');
  assert.deepEqual(kid(e, 'link').attrs, { rel: 'alternate', type: 'text/html', href: 'https://github.com/rettui-dev/rettui/releases/tag/v2.1.0' });
  assert.deepEqual(kid(e, 'content').attrs, { type: 'text' });
  assert.equal(kid(e, 'content').text, 'Added things.');
  // The same input gives the same feed.
  assert.equal(buildFeed([item()]), buildFeed([item()]));
});

test('with a site address the feed links to itself and to the downloads page', () => {
  const feed = parseXml(buildFeed([item()], { siteUrl: 'https://rettui.example' }));
  assert.equal(kid(feed, 'id').text, 'https://rettui.example/feed.xml');
  const links = Object.fromEntries(kids(feed, 'link').map((l) => [l.attrs.rel, l.attrs.href]));
  assert.deepEqual(links, { self: 'https://rettui.example/feed.xml', alternate: 'https://rettui.example/downloads' });
});

test('an empty cache gives an empty but valid feed', () => {
  const feed = parseXml(buildFeed([]));
  assert.equal(kids(feed, 'entry').length, 0);
  assert.equal(kid(feed, 'updated').text, '1970-01-01T00:00:00Z');
  assert.ok(kid(feed, 'id') && kid(feed, 'title') && kid(feed, 'author'));
});

test('text is escaped and characters XML does not allow are removed', () => {
  const nasty = `<script>alert("x")</script> & 'q' ]]> \u0000\u0008\u000b\u001f\u007f\u0085￾ ok \ud800 \udc00 lone, pair \u{1F600}`;
  const xml = buildFeed([item({ notes: nasty, name: 'a<b>&"c"', url: 'https://github.com/o/r/releases/tag/x?a=1&b="2"' })]);
  const entry = kid(parseXml(xml), 'entry');
  assert.equal(kid(entry, 'title').text, 'rettui a<b>&"c"');
  assert.equal(kid(entry, 'link').attrs.href, 'https://github.com/o/r/releases/tag/x?a=1&b="2"');
  assert.equal(kid(entry, 'content').text, `<script>alert("x")</script> & 'q' ]]>  ok   lone, pair \u{1F600}`);
  assert.ok(!xml.includes('<script>'));
  assert.equal(xmlText('a&b<c>"d\'\u0001'), 'a&amp;b&lt;c&gt;&quot;d&apos;');
  assert.equal(xmlText(undefined), '');
});

test('long notes are cut at the cap without splitting a character', () => {
  const emoji = '\u{1F600}'.repeat(MAX_FEED_CONTENT + 50);
  const cut = truncateText(emoji);
  assert.equal([...cut].length, MAX_FEED_CONTENT);
  assert.ok(cut.endsWith('…'));
  assert.equal(truncateText('short'), 'short');
  assert.equal(truncateText('x'.repeat(MAX_FEED_CONTENT)).length, MAX_FEED_CONTENT);
  const entry = kid(parseXml(buildFeed([item({ notes: 'y'.repeat(100_000) })])), 'entry');
  assert.equal([...kid(entry, 'content').text].length, MAX_FEED_CONTENT);
});

test('a release without notes still has content, and a bad date falls back to the fetch time', () => {
  const xml = buildFeed([item({ notes: '', publishedAt: 'not a date' })]);
  const entry = kid(parseXml(xml), 'entry');
  assert.match(kid(entry, 'content').text, /No release notes/);
  assert.equal(kid(entry, 'updated').text, '2026-11-19T12:00:00Z');
});

test('the cache keeps cleaned release notes for the feed, and the downloads API leaves them out', async () => {
  const gh = { tag_name: 'v2.1.0', name: 'rettui v2.1.0', draft: false, published_at: '2026-11-18T10:00:00Z', body: `## Added\r\n- a thing\u0000\u0007\r\n`, assets: [] };
  assert.equal(fromGitHub('rettui-dev/rettui', gh).notes, '## Added\n- a thing');
  assert.equal(fromGitHub('rettui-dev/rettui', { ...gh, body: 42 }).notes, '');
  assert.equal(cleanNotes('x'.repeat(MAX_NOTES + 10)).length, MAX_NOTES);
  const fetchFn = async () => new Response(JSON.stringify(gh), { headers: { 'content-type': 'application/json' } });
  const cache = new ReleaseCache({ repos: ['rettui-dev/rettui'], dataDir: await tmp(), fetchFn, log: () => {} });
  assert.deepEqual(cache.feedItems(), []);
  await cache.refreshDue();
  assert.equal(cache.feedItems()[0].release.notes, '## Added\n- a thing');
  assert.equal(Object.hasOwn(cache.snapshot().projects[0].release, 'notes'), false);
  // Saved notes come back after a restart.
  const again = new ReleaseCache({ repos: ['rettui-dev/rettui'], dataDir: cache.dataDir, fetchFn, log: () => {} });
  await again.load();
  assert.equal(again.feedItems()[0].release.notes, '## Added\n- a thing');
});

async function start({ mode = 'full', site = NO_SITE, releases } = {}) {
  const monitor = new Monitor({ targets: [{ host: 'a.test', port: 4242 }], dataDir: await tmp(), probeFn: async () => ({ up: true, ms: 9 }) });
  await monitor.checkAll();
  const server = createApp({ monitor, publicDir, releases, mode, site });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  const get = (p, method = 'GET', headers = {}) =>
    new Promise((resolve, reject) => {
      const req = http.request({ host: '127.0.0.1', port, path: p, method, headers }, (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text: Buffer.concat(chunks).toString('utf8') }));
      });
      req.on('error', reject);
      req.end();
    });
  return { get, close: () => (server.closeAllConnections(), new Promise((r) => server.close(r))) };
}

const stubCache = (items) => ({ feedItems: () => items, snapshot: () => ({ projects: [] }) });

test('GET /feed.xml: headers, body, ETag and HEAD', async () => {
  const s = await start({ releases: stubCache([item()]), site: { ...NO_SITE, url: 'https://rettui.example' } });
  try {
    const r = await s.get('/feed.xml');
    assert.equal(r.status, 200);
    assert.equal(r.headers['content-type'], 'application/atom+xml; charset=utf-8');
    assert.equal(r.headers['cache-control'], 'public, max-age=300');
    assert.equal(r.headers['x-content-type-options'], 'nosniff');
    assert.match(r.headers['content-security-policy'], /default-src 'none'/);
    assert.match(r.headers.etag, /^"[0-9a-f]{24}"$/);
    assert.equal(Number(r.headers['content-length']), Buffer.byteLength(r.text));
    assert.equal(kids(parseXml(r.text), 'entry').length, 1);
    assert.equal(kid(parseXml(r.text), 'id').text, 'https://rettui.example/feed.xml');
    const head = await s.get('/feed.xml', 'HEAD');
    assert.equal(head.status, 200);
    assert.equal(head.text, '');
    assert.equal(head.headers['content-length'], r.headers['content-length']);
    assert.equal(head.headers['content-type'], r.headers['content-type']);
    const same = await s.get('/feed.xml', 'GET', { 'If-None-Match': r.headers.etag });
    assert.equal(same.status, 304);
    assert.equal(same.text, '');
    // The query string is ignored.
    assert.equal((await s.get('/feed.xml?x=1')).text, r.text);
  } finally {
    await s.close();
  }
});

test('/feed.xml: other methods are 405, an empty cache is an empty feed, no cache is 404', async () => {
  const s = await start({ releases: stubCache([]) });
  try {
    for (const method of ['POST', 'PUT', 'DELETE', 'PATCH']) {
      const r = await s.get('/feed.xml', method);
      assert.equal(r.status, 405, method);
      assert.equal(r.headers.allow, 'GET, HEAD');
    }
    const r = await s.get('/feed.xml');
    assert.equal(r.status, 200);
    assert.equal(kids(parseXml(r.text), 'entry').length, 0);
  } finally {
    await s.close();
  }
  const none = await start({ releases: null });
  try {
    assert.equal((await none.get('/feed.xml')).status, 404);
  } finally {
    await none.close();
  }
});

test('in status-only mode /feed.xml is 404 like the other project pages', async () => {
  const s = await start({ mode: 'status', releases: stubCache([item()]) });
  try {
    assert.equal((await s.get('/feed.xml')).status, 404);
    assert.equal((await s.get('/feed.xml', 'HEAD')).status, 404);
  } finally {
    await s.close();
  }
});

test('the home and downloads pages advertise the feed, the status page does not need to', async () => {
  for (const file of ['index.html', 'downloads.html']) {
    const html = await fs.readFile(path.join(publicDir, file), 'utf8');
    assert.match(html, /<link rel="alternate" type="application\/atom\+xml" title="rettui releases" href="\/feed\.xml">/, file);
  }
});
