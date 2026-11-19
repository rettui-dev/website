import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { MAX_ASSETS, MAX_BYTES, MAX_CHECKSUM_FILES, ReleaseCache, ReleaseError, allowedAssetUrl, classifyAsset, cleanRelease, fetchLatest, fromGitHub, loadReleaseSettings, loadToken, parseChecksums, parseRepos } from '../lib/releases.js';

const REPO = 'rettui-dev/rettui';
const API = `https://api.github.com/repos/${REPO}/releases/latest`;
const HEX = (c) => c.repeat(64);
const download = (name, tag = 'v2.0.0', repo = REPO) => `https://github.com/${repo}/releases/download/${tag}/${name}`;

function asset(name, extra = {}) {
  return { name, size: 1000, state: 'uploaded', browser_download_url: download(name), digest: `sha256:${HEX('a')}`, ...extra };
}

function release(extra = {}, assets = [asset('rettui-v2.0.0-x86_64-unknown-linux-gnu.tar.gz')]) {
  return { tag_name: 'v2.0.0', name: 'rettui v2.0.0', draft: false, prerelease: false, published_at: '2026-11-16T19:48:24Z', html_url: 'https://evil.example/x', body: 'notes', assets, ...extra };
}

const json = (body, status = 200, headers = {}) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });

// A fetch that answers from a table of URL -> response (or function), and records what was asked.
function fakeFetch(routes) {
  const calls = [];
  const fn = async (url, init = {}) => {
    calls.push({ url: String(url), headers: { ...init.headers }, redirect: init.redirect });
    const route = routes[String(url)];
    if (route === undefined) return new Response('not found', { status: 404 });
    return typeof route === 'function' ? route(init) : route.clone();
  };
  fn.calls = calls;
  return fn;
}

async function tmp() {
  return fs.mkdtemp(path.join(os.tmpdir(), 'releases-'));
}

test('RELEASE_REPOS: the default, a list, and every bad entry', () => {
  assert.deepEqual(parseRepos(undefined), ['rettui-dev/rettui', 'rettui-dev/rngit-rs']);
  assert.deepEqual(parseRepos(' a/b , Some-Owner/some.repo_1 '), ['a/b', 'Some-Owner/some.repo_1']);
  for (const bad of ['', 'a', 'a/', '/b', 'a/b/c', 'a b/c', 'a/b c', '../x', 'a/..', 'a/.', '-a/b', 'a-/b', 'a--b/c', 'https://github.com/a/b', 'a/b?x=1', 'a/b#c', 'a/b,', ',a/b', 'a/b,a/b', 'A/B,a/b', 'a\n/b', 'a/b%2f', 'o/é', `${'a'.repeat(40)}/b`, `a/${'b'.repeat(101)}`]) {
    assert.throws(() => parseRepos(bad), /RELEASE_REPOS/, JSON.stringify(bad));
  }
  assert.throws(() => parseRepos(Array.from({ length: 9 }, (_, i) => `a/r${i}`).join(',')), /more than 8/);
});

test('the GitHub token: from the variable, from a file, and never both', async () => {
  const dir = await tmp();
  const file = path.join(dir, 'token');
  await fs.writeFile(file, 'ghp_exampletoken123\n');
  assert.equal(await loadToken({}), null);
  assert.equal(await loadToken({ GITHUB_TOKEN: '' }), null);
  assert.equal(await loadToken({ GITHUB_TOKEN: ' ghp_abc ' }), 'ghp_abc');
  assert.equal(await loadToken({ GITHUB_TOKEN_FILE: file }), 'ghp_exampletoken123');
  assert.equal(await loadToken({ GITHUB_TOKEN: '', GITHUB_TOKEN_FILE: file }), 'ghp_exampletoken123');
  await assert.rejects(loadToken({ GITHUB_TOKEN: 'x', GITHUB_TOKEN_FILE: file }), /either GITHUB_TOKEN or GITHUB_TOKEN_FILE/);
  await assert.rejects(loadToken({ GITHUB_TOKEN_FILE: path.join(dir, 'missing') }), /cannot be read \(ENOENT\)/);
  await fs.writeFile(file, '\n');
  await assert.rejects(loadToken({ GITHUB_TOKEN_FILE: file }), /is empty/);
  await fs.writeFile(file, 'x'.repeat(2000));
  await assert.rejects(loadToken({ GITHUB_TOKEN_FILE: file }), /not a token/);
  await assert.rejects(loadToken({ GITHUB_TOKEN: 'two words' }), /not a token/);
  // The message never repeats the value.
  await assert.rejects(loadToken({ GITHUB_TOKEN: 'secret value' }), (err) => !/secret/.test(err.message));
  assert.deepEqual(await loadReleaseSettings({ RELEASE_REPOS: 'a/b', GITHUB_TOKEN: 't' }), { repos: ['a/b'], token: 't' });
  await assert.rejects(loadReleaseSettings({ RELEASE_REPOS: 'nope' }), /RELEASE_REPOS/);
});

test('files are put on a platform from realistic names', () => {
  const cases = [
    ['rettui-v2.0.0-x86_64-unknown-linux-gnu.tar.gz', 'linux-x86_64'],
    ['rettui-v2.0.0-aarch64-unknown-linux-gnu.tar.gz', 'linux-aarch64'],
    ['rettui_2.0.0_amd64.deb', 'linux-x86_64'],
    ['rettui_2.0.0_arm64.deb', 'linux-aarch64'],
    ['rettui-desktop-v2.0.0-x86_64-unknown-linux-gnu.AppImage', 'linux-x86_64'],
    ['rettui-desktop-v2.0.0-aarch64-unknown-linux-gnu.flatpak', 'linux-aarch64'],
    ['rettui-2.0.0-1.x86_64.rpm', 'linux-x86_64'],
    ['rettui-v2.0.0-armv7-unknown-linux-gnueabihf.tar.gz', 'linux-other'],
    ['rettui-v2.0.0-i686-unknown-linux-musl.tar.gz', 'linux-other'],
    ['rettui-v2.0.0-aarch64-apple-darwin.tar.gz', 'macos-arm64'],
    ['rettui-v2.0.0-x86_64-apple-darwin.tar.gz', 'macos-x86_64'],
    ['rettui-desktop-v2.0.0-aarch64-apple-darwin.dmg', 'macos-arm64'],
    ['rettui-macos-universal.dmg', 'macos'],
    ['rettui-v2.0.0-x86_64-pc-windows-msvc.zip', 'windows'],
    ['rettui-desktop-v2.0.0-x86_64-pc-windows-msvc.exe', 'windows'],
    ['rettui-setup.msi', 'windows'],
    ['rettui-windows-x64.zip', 'windows'],
    ['rettui-v2.0.0-android-arm64-v8a.apk', 'android'],
    ['rettui.apk', 'android'],
    ['rettui-v2.0.0-docker-image.tar', 'docker'],
    ['rettui-2.0.0-src.tar.gz', 'source'],
    ['rngit-rs-source.zip', 'source'],
    ['SHA256SUMS', 'checksums'],
    ['SHA256SUMS.txt', 'checksums'],
    ['checksums.txt', 'checksums'],
    ['rettui-v2.0.0-x86_64-unknown-linux-gnu.tar.gz.sha256', 'checksums'],
    ['PKGBUILD', 'other'],
    ['rettui.rb', 'other'],
    ['notes.txt', 'other'],
  ];
  for (const [name, platform] of cases) assert.equal(classifyAsset(name).platform, platform, name);
  // Darwin must not be taken for Windows ("win" is inside "darwin").
  assert.equal(classifyAsset('tool-darwin-amd64.tar.gz').platform, 'macos-x86_64');
  assert.equal(classifyAsset('rettui-desktop-v2.0.0-x86_64-unknown-linux-gnu.deb').kind, 'Desktop app');
  assert.equal(classifyAsset('rettui_2.0.0_amd64.deb').kind, 'Debian package');
  assert.equal(classifyAsset('rettui-v2.0.0-x86_64-unknown-linux-gnu.tar.gz').kind, null);
  assert.equal(classifyAsset('rettui_2.0.0_amd64.deb').label, 'Linux x86_64');
});

test('checksum files: GNU, BSD and bare hashes', () => {
  const a = HEX('a');
  const b = HEX('B');
  const c = HEX('c');
  const sums = parseChecksums(`${a}  rettui-linux.tar.gz\r\n${b} *dist/rettui-win.zip\nSHA256 (rettui.apk) = ${c}\n# comment\nnot a hash  file\n${'d'.repeat(63)}  short\n\n`);
  assert.deepEqual([...sums], [['rettui-linux.tar.gz', a], ['rettui-win.zip', b.toLowerCase()], ['rettui.apk', c]]);
  assert.deepEqual([...parseChecksums(`${a}\n`)], [['', a]]);
  assert.equal(parseChecksums('').size, 0);
  assert.equal(parseChecksums(null).size, 0);
  // The first sum for a name wins, and a long file is read only so far.
  assert.equal(parseChecksums(`${a}  x\n${b}  x\n`).get('x'), a);
  const many = Array.from({ length: 2000 }, (_, i) => `${a}  f${i}`).join('\n');
  assert.equal(parseChecksums(many).size, 500);
  assert.equal(parseChecksums(`${a}  ${'n'.repeat(700)}`).size, 0);
});

test('only plain https links to this repository\'s release files are kept', () => {
  assert.equal(allowedAssetUrl(REPO, download('a.tar.gz')), download('a.tar.gz'));
  assert.equal(allowedAssetUrl(REPO, download('a.tar.gz', 'v1').replace('rettui-dev', 'Rettui-Dev')), download('a.tar.gz', 'v1').replace('rettui-dev', 'Rettui-Dev'));
  for (const bad of [
    undefined, null, 42, {}, '',
    'http://github.com/rettui-dev/rettui/releases/download/v1/a',
    'https://evil.example/rettui-dev/rettui/releases/download/v1/a',
    'https://github.com.evil.example/rettui-dev/rettui/releases/download/v1/a',
    'https://github.com@evil.example/rettui-dev/rettui/releases/download/v1/a',
    'https://user:pw@github.com/rettui-dev/rettui/releases/download/v1/a',
    'https://github.com:8443/rettui-dev/rettui/releases/download/v1/a',
    'https://api.github.com/repos/rettui-dev/rettui/releases/assets/1',
    'https://github.com/other/repo/releases/download/v1/a',
    'https://github.com/rettui-dev/rettui-evil/releases/download/v1/a',
    'https://github.com/rettui-dev/rettui/releases/latest/download/a',
    'https://github.com/rettui-dev/rettui/archive/refs/tags/v1.tar.gz',
    'https://github.com/rettui-dev/rettui/releases/download/v1/a?x=1',
    'https://github.com/rettui-dev/rettui/releases/download/v1/a#x',
    'https://github.com/rettui-dev/rettui/releases/download/v1/',
    'https://github.com/rettui-dev/rettui/releases/download/v1/a/b',
    'https://github.com/rettui-dev/rettui/releases/download/v1/..',
    'https://github.com/rettui-dev/rettui/releases/download/v1/%2e%2e/%2e%2e/x',
    'https://github.com/rettui-dev/rettui/releases/download/../../../evil/x/y',
    'javascript:alert(1)',
    'data:text/html,x',
    `https://github.com/rettui-dev/rettui/releases/download/v1/${'a'.repeat(500)}`,
  ]) {
    assert.equal(allowedAssetUrl(REPO, bad), null, String(bad));
  }
});

test('a release from GitHub is checked, trimmed and given a platform', () => {
  const r = fromGitHub(REPO, release({}, [asset('rettui_2.0.0_amd64.deb', { size: 123, digest: `sha256:${HEX('A')}` }), asset('PKGBUILD', { digest: null })]));
  assert.equal(r.tag, 'v2.0.0');
  assert.equal(r.name, 'rettui v2.0.0');
  assert.equal(r.publishedAt, '2026-11-16T19:48:24.000Z');
  // The page link is built here, whatever GitHub's answer says.
  assert.equal(r.url, `https://github.com/${REPO}/releases/tag/v2.0.0`);
  assert.deepEqual(r.assets.map((a) => [a.name, a.platform, a.size, a.sha256, a.checksumSource]), [
    ['rettui_2.0.0_amd64.deb', 'linux-x86_64', 123, HEX('a'), 'digest'],
    ['PKGBUILD', 'other', 1000, null, null],
  ]);
  assert.deepEqual(Object.keys(r.assets[0]).sort(), ['checksumSource', 'kind', 'label', 'name', 'platform', 'sha256', 'size', 'url']);
});

test('what GitHub sends is cleaned: bad links, names, sizes, digests, text and counts', () => {
  const evil = [
    asset('ok.tar.gz'),
    asset('http.tar.gz', { browser_download_url: 'http://github.com/rettui-dev/rettui/releases/download/v2.0.0/http.tar.gz' }),
    asset('elsewhere.tar.gz', { browser_download_url: 'https://evil.example/a.tar.gz' }),
    asset('other-repo.tar.gz', { browser_download_url: download('other-repo.tar.gz', 'v2.0.0', 'x/y') }),
    asset('../slash.tar.gz'),
    asset('a b.tar.gz'),
    asset('<img src=x onerror=alert(1)>'),
    asset(''),
    asset(42),
    asset('bad-size.tar.gz', { size: -1 }),
    asset('float-size.tar.gz', { size: 1.5 }),
    asset('huge-size.tar.gz', { size: 2 ** 50 }),
    asset('bad-digest.tar.gz', { digest: 'sha256:xyz' }),
    asset('md5-digest.tar.gz', { digest: `md5:${HEX('a')}` }),
    asset('upload-failed.tar.gz', { state: 'starter' }),
    null,
    'string',
    [],
  ];
  const r = fromGitHub(REPO, release({ name: `  Name\u0000with‮control ${'x'.repeat(300)}` }, evil));
  assert.deepEqual(r.assets.map((a) => a.name), ['bad-digest.tar.gz', 'bad-size.tar.gz', 'float-size.tar.gz', 'huge-size.tar.gz', 'md5-digest.tar.gz', 'ok.tar.gz']);
  const byName = Object.fromEntries(r.assets.map((a) => [a.name, a]));
  assert.equal(byName['bad-size.tar.gz'].size, null);
  assert.equal(byName['float-size.tar.gz'].size, null);
  assert.equal(byName['huge-size.tar.gz'].size, null);
  assert.equal(byName['bad-digest.tar.gz'].sha256, null);
  assert.equal(byName['md5-digest.tar.gz'].sha256, null);
  assert.equal(r.name.length, 100);
  assert.doesNotMatch(r.name, /[\u0000‮]/u);
  for (const a of r.assets) assert.match(a.url, /^https:\/\/github\.com\/rettui-dev\/rettui\/releases\/download\//);
  // Too many files are cut, and a tag is cut and cleaned.
  const many = Array.from({ length: 300 }, (_, i) => asset(`f${i}.tar.gz`));
  assert.equal(fromGitHub(REPO, release({}, many)).assets.length, MAX_ASSETS);
  const odd = fromGitHub(REPO, release({ tag_name: `v1\n${'9'.repeat(300)}` }));
  assert.equal(odd.tag.length, 100);
  assert.doesNotMatch(odd.url, /[\n ]/);
  // A tag that would break out of the link is escaped.
  assert.equal(fromGitHub(REPO, release({ tag_name: 'v1/../x?y#z' })).url, `https://github.com/${REPO}/releases/tag/v1%2F..%2Fx%3Fy%23z`);
  // A bad date is no date.
  assert.equal(fromGitHub(REPO, release({ published_at: 'yesterday' })).publishedAt, null);
  assert.equal(fromGitHub(REPO, release({ published_at: 12 })).publishedAt, null);
});

test('an answer that is not a release is an error, and a draft is none', () => {
  for (const bad of [null, 'x', 42, [], {}, { tag_name: '' }, { tag_name: 7 }]) {
    assert.throws(() => fromGitHub(REPO, bad), (err) => err instanceof ReleaseError && err.code === 'bad response', JSON.stringify(bad));
  }
  assert.equal(fromGitHub(REPO, release({ draft: true })), null);
  assert.deepEqual(fromGitHub(REPO, { tag_name: 'v1' }).assets, []);
  assert.deepEqual(fromGitHub(REPO, { tag_name: 'v1', assets: 'nope' }).assets, []);
  assert.equal(cleanRelease(REPO, 'x'), null);
  assert.equal(cleanRelease(REPO, { tag: '' }), null);
});

test('the request: GitHub headers, no redirect following by fetch, and the token only to the API', async () => {
  const f = fakeFetch({ [API]: json(release()) });
  const result = await fetchLatest(REPO, { fetchFn: f, token: 'tok_secret' });
  assert.equal(result.state, 'ok');
  assert.equal(f.calls.length, 1);
  assert.equal(f.calls[0].headers.Accept, 'application/vnd.github+json');
  assert.match(f.calls[0].headers['User-Agent'], /\S/);
  assert.equal(f.calls[0].headers.Authorization, 'Bearer tok_secret');
  assert.equal(f.calls[0].redirect, 'manual');
  const anon = fakeFetch({ [API]: json(release()) });
  await fetchLatest(REPO, { fetchFn: anon });
  assert.equal('Authorization' in anon.calls[0].headers, false);
});

test('no release yet, a draft, and every failure have their own answer', async () => {
  assert.deepEqual(await fetchLatest(REPO, { fetchFn: fakeFetch({ [API]: json({ message: 'Not Found' }, 404) }) }), { state: 'none', release: null });
  assert.deepEqual(await fetchLatest(REPO, { fetchFn: fakeFetch({ [API]: json(release({ draft: true })) }) }), { state: 'none', release: null });
  const code = async (fetchFn) => {
    try {
      await fetchLatest(REPO, { fetchFn, timeoutMs: 200 });
    } catch (err) {
      assert.ok(err instanceof ReleaseError);
      return err.code;
    }
    return 'no error';
  };
  assert.equal(await code(fakeFetch({ [API]: new Response('x', { status: 500 }) })), 'http 500');
  assert.equal(await code(fakeFetch({ [API]: new Response('x', { status: 401 }) })), 'http 401');
  assert.equal(await code(fakeFetch({ [API]: new Response('x', { status: 403, headers: { 'x-ratelimit-remaining': '0' } }) })), 'rate limited');
  assert.equal(await code(fakeFetch({ [API]: new Response('x', { status: 403 }) })), 'http 403');
  assert.equal(await code(fakeFetch({ [API]: new Response('not json') })), 'bad response');
  assert.equal(await code(fakeFetch({ [API]: json([1, 2]) })), 'bad response');
  assert.equal(await code(fakeFetch({ [API]: json({ tag_name: null }) })), 'bad response');
  assert.equal(await code(async () => { throw new TypeError('fetch failed'); }), 'network error');
  // Never answers: the time limit ends it. (AbortSignal.timeout does not keep a process alive, so the test does.)
  const hang = () => {
    const keep = setTimeout(() => {}, 10_000);
    return () => clearTimeout(keep);
  };
  assert.equal(await code((url, init) => new Promise((_, reject) => {
    const done = hang();
    init.signal.addEventListener('abort', () => (done(), reject(new Error('aborted'))));
  })), 'timeout');
  // Answers, then stops in the middle of the body.
  const stalled = (url, init) => {
    const done = hang();
    init.signal.addEventListener('abort', done);
    return new Response(new ReadableStream({ start(c) { c.enqueue(new TextEncoder().encode('{"tag')); } }));
  };
  assert.equal(await code(stalled), 'timeout');
});

test('an answer over 1 MiB is refused, by its length and while it is read', async () => {
  const big = JSON.stringify(release({ body: 'x'.repeat(MAX_BYTES) }));
  const fetchLength = fakeFetch({ [API]: new Response(big, { headers: { 'content-length': String(big.length) } }) });
  await assert.rejects(fetchLatest(REPO, { fetchFn: fetchLength }), (err) => err.code === 'too large');
  // No length given: it is counted as it arrives, and stops reading at the cap.
  let pulled = 0;
  const chunk = new TextEncoder().encode('x'.repeat(64 * 1024));
  const endless = () => new Response(new ReadableStream({ pull(c) { pulled++; c.enqueue(chunk); } }));
  await assert.rejects(fetchLatest(REPO, { fetchFn: endless }), (err) => err.code === 'too large');
  assert.ok(pulled <= 20, `read ${pulled} chunks`);
  // Just under the cap is read.
  const under = JSON.stringify(release({ body: 'x'.repeat(MAX_BYTES - 2000) }));
  assert.equal((await fetchLatest(REPO, { fetchFn: fakeFetch({ [API]: new Response(under) }) })).state, 'ok');
});

test('redirects are followed only within GitHub, and the token stays with the API', async () => {
  const moved = `https://api.github.com/repositories/1/releases/latest`;
  const f = fakeFetch({ [API]: new Response(null, { status: 301, headers: { location: moved } }), [moved]: json(release()) });
  assert.equal((await fetchLatest(REPO, { fetchFn: f, token: 'tok_secret' })).state, 'ok');
  assert.deepEqual(f.calls.map((c) => c.url), [API, moved]);
  assert.equal(f.calls[1].headers.Authorization, 'Bearer tok_secret');
  const refuse = async (location) => {
    const calls = [];
    const fetchFn = async (url) => {
      calls.push(String(url));
      return new Response(null, { status: 302, headers: { location } });
    };
    await assert.rejects(fetchLatest(REPO, { fetchFn, token: 'tok_secret' }), (err) => err instanceof ReleaseError && /redirect|bad/.test(err.code), location);
    assert.deepEqual(calls, [API], `${location} was not asked`);
  };
  for (const location of ['https://evil.example/x', 'http://api.github.com/x', 'https://github.com.evil.example/x', 'https://evilgithubusercontent.com/x', 'https://user:pw@api.github.com/x', 'https://api.github.com:8443/x', 'ftp://github.com/x', 'file:///etc/passwd']) await refuse(location);
  // A loop ends.
  const loop = fakeFetch({ [API]: new Response(null, { status: 302, headers: { location: API } }) });
  await assert.rejects(fetchLatest(REPO, { fetchFn: loop }), (err) => err.code === 'too many redirects');
  assert.equal(loop.calls.length, 4);
  // A redirect with no place to go.
  await assert.rejects(fetchLatest(REPO, { fetchFn: fakeFetch({ [API]: new Response(null, { status: 302 }) }) }), (err) => err.code === 'bad redirect');
});

test('checksums: the digest first, then a checksums file, then nothing', async () => {
  const sumsUrl = download('SHA256SUMS');
  const files = [
    asset('with-digest.tar.gz'),
    asset('in-file.tar.gz', { digest: null }),
    asset('also-in-file.zip', { digest: null }),
    asset('nowhere.apk', { digest: null }),
    asset('SHA256SUMS', { digest: null }),
  ];
  const body = `${HEX('1')}  in-file.tar.gz\n${HEX('2')} *also-in-file.zip\n${HEX('3')}  with-digest.tar.gz\n`;
  // The file is on another GitHub host after a redirect, as release files are.
  const storage = 'https://release-assets.githubusercontent.com/abc';
  const f = fakeFetch({
    [API]: json(release({}, files)),
    [sumsUrl]: new Response(null, { status: 302, headers: { location: storage } }),
    [storage]: new Response(body),
  });
  const { release: r } = await fetchLatest(REPO, { fetchFn: f, token: 'tok_secret' });
  const by = Object.fromEntries(r.assets.map((a) => [a.name, a]));
  assert.deepEqual([by['with-digest.tar.gz'].sha256, by['with-digest.tar.gz'].checksumSource], [HEX('a'), 'digest']);
  assert.deepEqual([by['in-file.tar.gz'].sha256, by['in-file.tar.gz'].checksumSource], [HEX('1'), 'file']);
  assert.deepEqual([by['also-in-file.zip'].sha256, by['also-in-file.zip'].checksumSource], [HEX('2'), 'file']);
  assert.deepEqual([by['nowhere.apk'].sha256, by['nowhere.apk'].checksumSource], [null, null]);
  // The token went to the API only, not to the file host.
  assert.equal(f.calls.length, 3);
  assert.equal(f.calls[1].headers.Authorization, undefined);
  assert.equal(f.calls[2].headers.Authorization, undefined);
  // With a digest for every file, no checksums file is read.
  const all = fakeFetch({ [API]: json(release({}, [asset('a.tar.gz'), asset('SHA256SUMS')])) });
  await fetchLatest(REPO, { fetchFn: all });
  assert.equal(all.calls.length, 1);
});

test('one checksum file per file, a failing checksum file, and at most 3 files read', async () => {
  const per = [asset('app.tar.gz', { digest: null }), asset('app.tar.gz.sha256', { digest: null }), asset('app.zip', { digest: null }), asset('app.zip.sha256', { digest: null })];
  const f = fakeFetch({
    [API]: json(release({}, per)),
    [download('app.tar.gz.sha256')]: new Response(`${HEX('4')}\n`),
    [download('app.zip.sha256')]: new Response(`${HEX('5')}  app.zip\n`),
  });
  const r = (await fetchLatest(REPO, { fetchFn: f })).release;
  assert.equal(r.assets.find((a) => a.name === 'app.tar.gz').sha256, HEX('4'));
  assert.equal(r.assets.find((a) => a.name === 'app.zip').sha256, HEX('5'));
  // A checksum file that fails is not an error: the files just have no checksum.
  const broken = fakeFetch({ [API]: json(release({}, [asset('a.zip', { digest: null }), asset('SHA256SUMS', { digest: null })])), [download('SHA256SUMS')]: new Response('x', { status: 500 }) });
  const rb = (await fetchLatest(REPO, { fetchFn: broken })).release;
  assert.equal(rb.assets.find((a) => a.name === 'a.zip').sha256, null);
  // Only the first few checksum files are read, and a big one is not.
  const names = Array.from({ length: 6 }, (_, i) => asset(`part${i}.sha256`, { digest: null }));
  const many = fakeFetch({ [API]: json(release({}, [asset('x.zip', { digest: null }), ...names])) });
  await fetchLatest(REPO, { fetchFn: many });
  assert.equal(many.calls.length, 1 + MAX_CHECKSUM_FILES);
  const huge = fakeFetch({ [API]: json(release({}, [asset('x.zip', { digest: null }), asset('SHA256SUMS', { digest: null, size: 5 * MAX_BYTES })])) });
  await fetchLatest(REPO, { fetchFn: huge });
  assert.equal(huge.calls.length, 1);
  // A checksum file over the cap is cut off too.
  const endless = fakeFetch({ [API]: json(release({}, [asset('x.zip', { digest: null }), asset('SHA256SUMS', { digest: null })])), [download('SHA256SUMS')]: () => new Response('a'.repeat(MAX_BYTES + 10)) });
  assert.equal((await fetchLatest(REPO, { fetchFn: endless })).release.assets.find((a) => a.name === 'x.zip').sha256, null);
});

// A cache with a clock the test moves and a fetch it can break.
async function cacheWith(routes, extra = {}) {
  const dir = await tmp();
  const clock = { t: Date.parse('2026-11-19T12:00:00Z') };
  const logs = [];
  const fetchFn = fakeFetch(routes);
  const cache = new ReleaseCache({ repos: [REPO, 'rettui-dev/rngit-rs'], dataDir: dir, fetchFn, now: () => clock.t, log: (m) => logs.push(m), ...extra });
  return { cache, clock, logs, fetchFn, dir };
}

const NONE = { message: 'Not Found' };

test('the cache fetches, shows, and saves releases.json', async () => {
  const { cache, fetchFn, dir } = await cacheWith({ [API]: json(release()), 'https://api.github.com/repos/rettui-dev/rngit-rs/releases/latest': json(NONE, 404) });
  assert.equal(cache.snapshot().projects[0].status, 'loading');
  await cache.refreshDue();
  const snap = cache.snapshot();
  assert.equal(snap.ttlSeconds, 900);
  assert.deepEqual(snap.projects.map((p) => [p.repo, p.status, p.stale, p.ageSeconds, p.error]), [[REPO, 'ok', false, 0, null], ['rettui-dev/rngit-rs', 'none', false, 0, null]]);
  assert.equal(snap.projects[0].release.tag, 'v2.0.0');
  assert.equal(snap.projects[0].releasesUrl, `https://github.com/${REPO}/releases`);
  assert.equal(snap.projects[1].release, null);
  assert.equal(fetchFn.calls.length, 2);
  const saved = JSON.parse(await fs.readFile(path.join(dir, 'releases.json'), 'utf8'));
  assert.equal(saved.version, 1);
  assert.equal(saved.repos[REPO].release.tag, 'v2.0.0');
  assert.equal(saved.repos['rettui-dev/rngit-rs'].state, 'none');
  assert.deepEqual((await fs.readdir(dir)).filter((n) => n.endsWith('.tmp')), []);
});

test('nothing is fetched again within 15 minutes, however often the page asks', async () => {
  const { cache, clock, fetchFn } = await cacheWith({ [API]: json(release()), 'https://api.github.com/repos/rettui-dev/rngit-rs/releases/latest': json(NONE, 404) });
  await cache.refreshDue();
  for (let i = 0; i < 50; i++) {
    cache.snapshot();
    await cache.tick();
  }
  assert.equal(fetchFn.calls.length, 2);
  clock.t += 14 * 60_000;
  await cache.tick();
  assert.equal(fetchFn.calls.length, 2);
  clock.t += 61_000;
  await cache.tick();
  assert.equal(fetchFn.calls.length, 4);
});

test('a refresh that is already running is joined, not repeated', async () => {
  let release_;
  const gate = new Promise((r) => (release_ = r));
  const { cache, fetchFn } = await cacheWith({ [API]: async () => (await gate, json(release())), 'https://api.github.com/repos/rettui-dev/rngit-rs/releases/latest': json(NONE, 404) });
  const a = cache.tick();
  const b = cache.tick();
  assert.equal(a, b);
  release_();
  await a;
  assert.equal(fetchFn.calls.length, 2);
});

test('when GitHub fails the last good copy stays, marked stale with its age', async () => {
  const state = { fail: false };
  const { cache, clock, logs } = await cacheWith({
    [API]: () => (state.fail ? new Response('x', { status: 502 }) : json(release())),
    'https://api.github.com/repos/rettui-dev/rngit-rs/releases/latest': json(NONE, 404),
  });
  await cache.refreshDue();
  state.fail = true;
  clock.t += 16 * 60_000;
  await cache.refreshDue();
  const p = cache.snapshot().projects[0];
  assert.equal(p.status, 'ok');
  assert.equal(p.stale, true);
  assert.equal(p.ageSeconds, 16 * 60);
  assert.equal(p.error, 'http 502');
  assert.equal(p.release.tag, 'v2.0.0');
  assert.equal(cache.snapshot().projects[1].stale, false);
  // The failure is logged once, with the repository and a code.
  clock.t += 60_000;
  await cache.refreshDue();
  clock.t += 120_000;
  await cache.refreshDue();
  assert.deepEqual(logs, [`releases: could not refresh ${REPO} (http 502); keeping the last copy`]);
  // When GitHub is back, the mark goes.
  state.fail = false;
  clock.t += 16 * 60_000;
  await cache.refreshDue();
  const again = cache.snapshot().projects[0];
  assert.deepEqual([again.stale, again.error, again.ageSeconds], [false, null, 0]);
});

test('with no copy at all a failure is "unavailable", and retries back off up to the interval', async () => {
  const { cache, clock, fetchFn, logs } = await cacheWith({ [API]: new Response('x', { status: 500 }), 'https://api.github.com/repos/rettui-dev/rngit-rs/releases/latest': new Response('x', { status: 500 }) });
  await cache.refreshDue();
  const p = cache.snapshot().projects[0];
  assert.deepEqual([p.status, p.stale, p.ageSeconds, p.release, p.error], ['unavailable', false, null, null, 'http 500']);
  assert.match(logs[0], /nothing to show yet/);
  const seen = [];
  for (let i = 0; i < 12; i++) {
    const before = fetchFn.calls.length;
    clock.t += 1000;
    await cache.refreshDue();
    if (fetchFn.calls.length > before) seen.push(clock.t);
    // Jump to the next retry.
    clock.t = Math.min(...[...cache.entries.values()].map((e) => e.nextAt));
  }
  const gaps = seen.slice(1).map((t, i) => t - seen[i]);
  // The wait doubles from 30 seconds and stops at 15 minutes.
  assert.ok(gaps.length >= 6);
  assert.ok(gaps.every((g, i) => i === 0 || g >= gaps[i - 1] - 2000), `gaps grow: ${gaps}`);
  assert.ok(Math.max(...gaps) <= 15 * 60_000 + 2000);
  assert.equal(logs.length, 2);
});

test('the copy on disk is read at start, and fresh data is not asked for again at once', async () => {
  const first = await cacheWith({ [API]: json(release()), 'https://api.github.com/repos/rettui-dev/rngit-rs/releases/latest': json(NONE, 404) });
  await first.cache.refreshDue();
  const down = { [API]: new Response('x', { status: 503 }), 'https://api.github.com/repos/rettui-dev/rngit-rs/releases/latest': new Response('x', { status: 503 }) };
  const second = await cacheWith(down, { dataDir: first.dir });
  second.clock.t = first.clock.t + 5 * 60_000;
  await second.cache.load();
  const snap = second.cache.snapshot();
  assert.deepEqual(snap.projects.map((p) => [p.status, p.ageSeconds, p.stale]), [['ok', 300, false], ['none', 300, false]]);
  await second.cache.refreshDue();
  assert.equal(second.fetchFn.calls.length, 0);
  // Old data is asked for at once, and on failure it is shown stale.
  second.clock.t += 20 * 60_000;
  await second.cache.refreshDue();
  assert.equal(second.fetchFn.calls.length, 2);
  assert.equal(second.cache.snapshot().projects[0].stale, true);
  assert.equal(second.cache.snapshot().projects[0].ageSeconds, 25 * 60);
});

test('a missing, damaged or wrong releases.json is ignored', async () => {
  for (const content of [null, '', 'not json', '[]', '{"version":2,"repos":{}}', '{"version":1}', '{"version":1,"repos":{"rettui-dev/rettui":{"state":"ok","fetchedAt":"x","release":{}}}}', '{"version":1,"repos":{"rettui-dev/rettui":{"state":"ok","fetchedAt":1,"release":{"tag":""}}}}', '{"version":1,"repos":{"rettui-dev/rettui":{"state":"weird","fetchedAt":1}}}', '{"version":1,"repos":{"__proto__":{"state":"none","fetchedAt":1}}}']) {
    const { cache, dir } = await cacheWith({});
    if (content !== null) await fs.writeFile(path.join(dir, 'releases.json'), content);
    await cache.load();
    assert.equal(cache.snapshot().projects[0].status, 'loading', String(content));
  }
  const { cache, dir } = await cacheWith({});
  await fs.writeFile(path.join(dir, 'releases.json'), ' '.repeat(3 * 1024 * 1024));
  await cache.load();
  assert.equal(cache.snapshot().projects[0].status, 'loading');
});

test('a changed releases.json is checked as strictly as an answer from GitHub', async () => {
  const { cache, dir } = await cacheWith({});
  const bad = {
    tag: 'v1',
    name: 'x',
    publishedAt: '2026-01-01T00:00:00Z',
    url: 'https://evil.example/',
    assets: [
      { name: 'ok.zip', size: 1, url: download('ok.zip', 'v1'), sha256: HEX('b'), checksumSource: 'file' },
      { name: 'evil.zip', size: 1, url: 'https://evil.example/evil.zip', sha256: HEX('b') },
      { name: 'script.zip', size: 1, url: 'javascript:alert(1)', sha256: HEX('b') },
      { name: 'other.zip', size: 1, url: download('other.zip', 'v1', 'x/y'), sha256: HEX('b') },
      { name: 'badsum.zip', size: 1, url: download('badsum.zip', 'v1'), sha256: '<script>' },
    ],
  };
  await fs.writeFile(path.join(dir, 'releases.json'), JSON.stringify({ version: 1, repos: { [REPO]: { state: 'ok', fetchedAt: 1, release: bad } } }));
  await cache.load();
  const r = cache.snapshot().projects[0].release;
  assert.deepEqual(r.assets.map((a) => [a.name, a.sha256, a.checksumSource]), [['badsum.zip', null, null], ['ok.zip', HEX('b'), 'file']]);
  assert.equal(r.url, `https://github.com/${REPO}/releases/tag/v1`);
});

test('the token is never in a snapshot, a log line, an error or a saved file', async () => {
  const token = 'ghp_SUPERSECRETTOKEN1234567890';
  const leaky = (url, init) => {
    // A failure whose message holds everything it was given.
    throw new Error(`failed ${url} ${JSON.stringify(init.headers)} ${token}`);
  };
  const { cache, logs, dir } = await cacheWith({ [API]: leaky, 'https://api.github.com/repos/rettui-dev/rngit-rs/releases/latest': json(release()) }, { token });
  await cache.refreshDue();
  // One repository worked, so there is something to save.
  const ok = fakeFetch({ [API]: json(release()), 'https://api.github.com/repos/rettui-dev/rngit-rs/releases/latest': json(release()) });
  cache.fetchFn = ok;
  cache.entries.get(REPO).nextAt = 0;
  await cache.refreshDue();
  assert.equal(ok.calls[0].headers.Authorization, `Bearer ${token}`);
  const everything = JSON.stringify(cache.snapshot()) + logs.join('\n') + (await fs.readFile(path.join(dir, 'releases.json'), 'utf8'));
  assert.doesNotMatch(everything, /SUPERSECRET|Bearer|Authorization/);
  assert.equal(logs.length, 1);
  assert.match(logs[0], /network error/);
  // The error a caller gets has a code only.
  await assert.rejects(fetchLatest(REPO, { fetchFn: leaky, token }), (err) => err instanceof ReleaseError && err.message === 'network error' && !err.message.includes(token));
});

test('start() fetches in the background and stop() ends the timer', async () => {
  const { cache, fetchFn } = await cacheWith({ [API]: json(release()), 'https://api.github.com/repos/rettui-dev/rngit-rs/releases/latest': json(NONE, 404) });
  cache.start();
  assert.ok(cache.timer);
  await cache.tick();
  assert.equal(fetchFn.calls.length, 2);
  cache.stop();
  assert.equal(cache.timer, null);
  cache.stop();
});

test('an unwritable data folder is logged and does not stop the cache', async () => {
  const { cache, logs, dir } = await cacheWith({ [API]: json(release()), 'https://api.github.com/repos/rettui-dev/rngit-rs/releases/latest': json(NONE, 404) });
  // A file where the folder should be.
  const blocked = path.join(dir, 'blocked');
  await fs.writeFile(blocked, 'x');
  cache.dataDir = blocked;
  cache.file = path.join(blocked, 'releases.json');
  await cache.refreshDue();
  assert.equal(cache.snapshot().projects[0].status, 'ok');
  assert.match(logs.join('\n'), /could not save releases/);
});
