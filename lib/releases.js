// The latest releases of the project's repositories, for the Downloads page. A background job asks
// the GitHub API at most every 15 minutes and keeps the answer in memory and in releases.json;
// visitors only ever read that copy, so nothing a visitor sends starts a request.
//
// Everything in GitHub's answer is untrusted: it is size capped, checked field by field, and
// download links that do not point at this repository's release files are dropped.
import fs from 'node:fs/promises';
import path from 'node:path';

export const DEFAULT_REPOS = ['rettui-dev/rettui', 'rettui-dev/rngit-rs'];
export const MAX_REPOS = 8;
export const TTL_MS = 15 * 60_000;
export const TIMEOUT_MS = 10_000;
export const MAX_BYTES = 1024 * 1024;
export const MAX_ASSETS = 100;
export const MAX_REDIRECTS = 3;
// The most checksum files read for one release.
export const MAX_CHECKSUM_FILES = 3;
// The most lines read from one checksum file.
export const MAX_CHECKSUM_LINES = 500;
// How often the job looks at whether anything is due.
export const TICK_MS = 30_000;
// The first retry after a failure; it doubles, up to the normal interval.
export const RETRY_MS = 30_000;

const API_HOST = 'api.github.com';
const USER_AGENT = 'rettui-website';
const MAX_STORED_BYTES = 2 * 1024 * 1024;

// A failure with a short fixed code, which is all that is ever logged or shown about it. It never
// carries a URL, a header or part of an answer, so it cannot carry the token either.
export class ReleaseError extends Error {
  constructor(code) {
    super(code);
    this.name = 'ReleaseError';
    this.code = code;
  }
}

// --- Settings ---

const OWNER = /^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$/;
const REPO_NAME = /^[A-Za-z0-9._-]{1,100}$/;

// RELEASE_REPOS: a comma separated list of owner/name. Anything else is an error.
export function parseRepos(text) {
  if (text === undefined) return [...DEFAULT_REPOS];
  const list = text.split(',').map((s) => s.trim());
  if (list.length > MAX_REPOS) throw new Error(`RELEASE_REPOS lists more than ${MAX_REPOS} repositories`);
  const seen = new Set();
  for (const [n, item] of list.entries()) {
    const [owner, name, ...more] = item.split('/');
    const ok = more.length === 0 && OWNER.test(owner ?? '') && REPO_NAME.test(name ?? '') && name !== '.' && name !== '..';
    if (!ok) throw new Error(`RELEASE_REPOS: entry ${n + 1} is not owner/name`);
    const key = item.toLowerCase();
    if (seen.has(key)) throw new Error(`RELEASE_REPOS: "${item}" is listed twice`);
    seen.add(key);
  }
  return list;
}

// The GitHub token, if any: GITHUB_TOKEN, or the first line of the file GITHUB_TOKEN_FILE. It only
// raises the rate limit; the repositories are public.
export async function loadToken(env) {
  const direct = env.GITHUB_TOKEN ?? '';
  if (direct !== '' && env.GITHUB_TOKEN_FILE) throw new Error('set either GITHUB_TOKEN or GITHUB_TOKEN_FILE, not both');
  let token = direct;
  if (env.GITHUB_TOKEN_FILE) {
    let handle;
    try {
      handle = await fs.open(path.resolve(env.GITHUB_TOKEN_FILE), 'r');
      const buf = Buffer.alloc(1025);
      const { bytesRead } = await handle.read(buf, 0, buf.length, 0);
      token = buf.toString('utf8', 0, bytesRead);
    } catch (err) {
      throw new Error(`GITHUB_TOKEN_FILE cannot be read (${err.code ?? 'error'})`);
    } finally {
      await handle?.close().catch(() => {});
    }
    if (token.trim() === '') throw new Error('GITHUB_TOKEN_FILE is empty');
  }
  token = token.trim();
  // An empty GITHUB_TOKEN is the same as none (compose passes one when the variable is unset).
  if (token === '') return null;
  if (!/^[\x21-\x7e]{1,255}$/.test(token)) throw new Error('the GitHub token is not a token (printable characters, at most 255)');
  return token;
}

export async function loadReleaseSettings(env) {
  return { repos: parseRepos(env.RELEASE_REPOS), token: await loadToken(env) };
}

// --- Checking what GitHub sends ---

const isObject = (v) => typeof v === 'object' && v !== null && !Array.isArray(v);
// Control characters, and the invisible characters that reorder or hide text.
const UNSAFE = [[0, 0x1f], [0x7f, 0x9f], [0x200b, 0x200f], [0x2028, 0x202e], [0x2060, 0x2069], [0xfeff, 0xfeff]];
const isUnsafe = (ch) => UNSAFE.some(([from, to]) => ch.codePointAt(0) >= from && ch.codePointAt(0) <= to);

// Plain text of at most max characters, or null.
function text(value, max) {
  if (typeof value !== 'string') return null;
  const clean = [...value].filter((ch) => !isUnsafe(ch)).join('').trim();
  if (clean === '') return null;
  return [...clean].slice(0, max).join('');
}

function isoDate(value) {
  if (typeof value !== 'string' || value.length > 40) return null;
  const t = Date.parse(value);
  return Number.isFinite(t) ? new Date(t).toISOString() : null;
}

function sha256(value) {
  return typeof value === 'string' && /^[0-9a-f]{64}$/i.test(value) ? value.toLowerCase() : null;
}

// "sha256:<hex>" as GitHub writes the digest of an asset.
function digest(value) {
  return typeof value === 'string' && value.startsWith('sha256:') ? sha256(value.slice(7)) : null;
}

// A download link is kept only when it is a plain https link to a file of this repository's
// releases: https://github.com/<owner>/<repo>/releases/download/<tag>/<file>.
export function allowedAssetUrl(repo, value) {
  if (typeof value !== 'string' || value.length > 500) return null;
  let u;
  try {
    u = new URL(value);
  } catch {
    return null;
  }
  if (u.protocol !== 'https:' || u.hostname !== 'github.com' || u.port || u.username || u.password || u.search || u.hash) return null;
  const prefix = `/${repo}/releases/download/`;
  if (!u.pathname.toLowerCase().startsWith(prefix.toLowerCase())) return null;
  const rest = u.pathname.slice(prefix.length).split('/');
  if (rest.length !== 2 || rest.some((s) => s === '' || s === '.' || s === '..')) return null;
  return u.href;
}

// --- Platforms ---

// In the order the page shows them.
export const PLATFORMS = [
  ['linux-x86_64', 'Linux x86_64'],
  ['linux-aarch64', 'Linux aarch64'],
  ['linux-other', 'Linux (other)'],
  ['macos-arm64', 'macOS (Apple silicon)'],
  ['macos-x86_64', 'macOS (Intel)'],
  ['macos', 'macOS'],
  ['windows', 'Windows'],
  ['android', 'Android'],
  ['docker', 'Docker'],
  ['source', 'Source'],
  ['checksums', 'Checksums'],
  ['other', 'Other'],
];
const LABELS = new Map(PLATFORMS);
const ORDER = new Map(PLATFORMS.map(([id], i) => [id, i]));

// A name is made of words; a word is a run of letters and digits.
const has = (name, ...words) => words.some((w) => new RegExp(`(^|[^a-z0-9])${w}([^a-z0-9]|$)`).test(name));
const ARM64 = ['aarch64', 'arm64', 'armv8', 'arm64-v8a'];
const X86_64 = ['x86_64', 'x86-64', 'amd64', 'x64'];

export function isChecksumFile(name) {
  return /^(?:.*[-_.])?(?:sha256sums?|checksums?)(?:\.txt)?$/i.test(name) || /\.sha256(?:sum)?$/i.test(name);
}

// What an asset is for, from its file name. Returns {platform, label, kind}; kind says how it is
// packaged when the name tells, for example "Desktop app" or "Debian package".
export function classifyAsset(fileName) {
  const name = fileName.toLowerCase();
  let kind = null;
  if (has(name, 'desktop')) kind = 'Desktop app';
  else if (name.endsWith('.deb')) kind = 'Debian package';
  else if (name.endsWith('.rpm')) kind = 'RPM package';
  else if (name.endsWith('.flatpak')) kind = 'Flatpak';
  else if (name.endsWith('.appimage')) kind = 'AppImage';
  else if (name.endsWith('.dmg')) kind = 'Disk image';
  const result = (platform) => ({ platform, label: LABELS.get(platform), kind });
  const arm64 = has(name, ...ARM64);
  const x86 = has(name, ...X86_64);

  if (isChecksumFile(fileName)) return result('checksums');
  if (name.endsWith('.apk') || name.endsWith('.aab') || has(name, 'android')) return result('android');
  if (has(name, 'darwin', 'macos', 'osx') || name.endsWith('.dmg') || name.endsWith('.pkg')) {
    return result(arm64 ? 'macos-arm64' : x86 ? 'macos-x86_64' : 'macos');
  }
  if (has(name, 'windows', 'win32', 'win64', 'win') || /\.(exe|msi)$/.test(name)) return result('windows');
  if (has(name, 'linux') || /\.(deb|rpm|flatpak|appimage|snap)$/.test(name)) {
    return result(arm64 ? 'linux-aarch64' : x86 ? 'linux-x86_64' : 'linux-other');
  }
  if (has(name, 'docker', 'oci', 'container')) return result('docker');
  if (has(name, 'src', 'source', 'sources')) return result('source');
  return result('other');
}

// --- Checksum files ---

// The SHA-256 sums in a checksum file, as a Map of file name to hex. Reads GNU lines ("<hex>  name",
// "<hex> *name"), BSD lines ("SHA256 (name) = <hex>"), and a lone hash, which is stored under "".
export function parseChecksums(content) {
  const sums = new Map();
  const lines = String(content).split(/\r?\n/).slice(0, MAX_CHECKSUM_LINES);
  for (const raw of lines) {
    const line = raw.trim();
    if (line.length > 600) continue;
    let m = /^([0-9a-fA-F]{64})[ \t]+\*?(.+)$/.exec(line);
    let name;
    let hex;
    if (m) [, hex, name] = m;
    else if ((m = /^SHA256 \((.+)\) = ([0-9a-fA-F]{64})$/.exec(line))) [, name, hex] = m;
    else if (/^[0-9a-fA-F]{64}$/.test(line)) [hex, name] = [line, ''];
    else continue;
    const base = name.replace(/\\/g, '/').split('/').pop();
    if (!sums.has(base)) sums.set(base, hex.toLowerCase());
  }
  return sums;
}

// --- Turning GitHub's answer into the release we keep ---

function cleanAsset(repo, a) {
  if (!isObject(a)) return null;
  const name = text(a.name, 200);
  // A file name is plain characters and never has a slash.
  if (name === null || !/^[\w.+~@=,()-]+$/u.test(name)) return null;
  const url = allowedAssetUrl(repo, a.url);
  if (url === null) return null;
  const size = Number.isSafeInteger(a.size) && a.size >= 0 && a.size <= 2 ** 40 ? a.size : null;
  const sum = sha256(a.sha256);
  return { name, size, url, sha256: sum, checksumSource: sum === null ? null : a.checksumSource === 'file' ? 'file' : 'digest' };
}

// Checks a release in the shape we keep (what GitHub sent after fromGitHub, or what releases.json
// holds). Returns it with the platform of each file, or null when it is not a release.
export function cleanRelease(repo, r) {
  if (!isObject(r)) return null;
  const tag = text(r.tag, 100);
  if (tag === null) return null;
  const assets = [];
  for (const a of Array.isArray(r.assets) ? r.assets.slice(0, MAX_ASSETS) : []) {
    const clean = cleanAsset(repo, a);
    if (clean) assets.push({ ...clean, ...classifyAsset(clean.name) });
  }
  assets.sort((a, b) => ORDER.get(a.platform) - ORDER.get(b.platform) || (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  return {
    tag,
    name: text(r.name, 100) ?? tag,
    publishedAt: isoDate(r.publishedAt),
    // Built here, never taken from the answer.
    url: `https://github.com/${repo}/releases/tag/${encodeURIComponent(tag)}`,
    assets,
  };
}

// GitHub's "latest release" object to our shape. Null for a draft.
export function fromGitHub(repo, json) {
  if (!isObject(json)) throw new ReleaseError('bad response');
  if (json.draft === true) return null;
  const assets = (Array.isArray(json.assets) ? json.assets : []).slice(0, MAX_ASSETS).map((a) =>
    isObject(a) && (a.state === undefined || a.state === 'uploaded')
      ? { name: a.name, size: a.size, url: a.browser_download_url, sha256: digest(a.digest), checksumSource: 'digest' }
      : null,
  );
  const release = cleanRelease(repo, { tag: json.tag_name, name: json.name, publishedAt: json.published_at, assets });
  if (release === null) throw new ReleaseError('bad response');
  return release;
}

// --- Asking GitHub ---

// Only GitHub's own hosts, over https, are ever asked, and only they may be followed to.
function allowedHost(u) {
  if (u.protocol !== 'https:' || u.username || u.password || u.port) return false;
  return u.hostname === 'github.com' || u.hostname === API_HOST || u.hostname.endsWith('.githubusercontent.com');
}

// Waits for promise, but gives up when the signal fires, even if the thing waited for ignores it.
function withDeadline(promise, signal) {
  return new Promise((resolve, reject) => {
    const onAbort = () => reject(new ReleaseError('timeout'));
    if (signal.aborted) return onAbort();
    signal.addEventListener('abort', onAbort, { once: true });
    Promise.resolve(promise).then(resolve, reject).finally(() => signal.removeEventListener('abort', onAbort));
  });
}

async function readCapped(res, maxBytes, signal) {
  const length = Number(res.headers.get('content-length'));
  if (Number.isFinite(length) && length > maxBytes) {
    res.body?.cancel().catch(() => {});
    throw new ReleaseError('too large');
  }
  if (!res.body) return '';
  const reader = res.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await withDeadline(reader.read(), signal);
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) throw new ReleaseError('too large');
      chunks.push(value);
    }
  } catch (err) {
    reader.cancel().catch(() => {});
    if (err instanceof ReleaseError) throw err;
    throw new ReleaseError(signal.aborted ? 'timeout' : 'network error');
  }
  return Buffer.concat(chunks).toString('utf8');
}

// One GET with a time limit for the whole thing, a size cap, and redirects followed by hand,
// only to GitHub's hosts. The token goes to the API host only. Resolves {status, body}.
async function get(url, { fetchFn, token, accept, timeoutMs, maxBytes }) {
  const signal = AbortSignal.timeout(timeoutMs);
  let current = new URL(url);
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    if (!allowedHost(current)) throw new ReleaseError('redirect refused');
    const headers = { 'User-Agent': USER_AGENT, Accept: accept };
    if (token && current.hostname === API_HOST) headers.Authorization = `Bearer ${token}`;
    let res;
    try {
      res = await withDeadline(fetchFn(current.href, { headers, redirect: 'manual', signal }), signal);
    } catch {
      throw new ReleaseError(signal.aborted ? 'timeout' : 'network error');
    }
    if (res.status >= 300 && res.status < 400) {
      const location = res.headers.get('location');
      res.body?.cancel().catch(() => {});
      if (!location) throw new ReleaseError('bad redirect');
      try {
        current = new URL(location, current);
      } catch {
        throw new ReleaseError('bad redirect');
      }
      continue;
    }
    if (res.status === 200) return { status: 200, body: await readCapped(res, maxBytes, signal) };
    res.body?.cancel().catch(() => {});
    if ((res.status === 403 || res.status === 429) && res.headers.get('x-ratelimit-remaining') === '0') throw new ReleaseError('rate limited');
    return { status: res.status, body: '' };
  }
  throw new ReleaseError('too many redirects');
}

// Fills in the checksums of files that GitHub gave no digest for, from the release's checksum files.
async function addChecksums(repo, release, opts) {
  if (release.assets.every((a) => a.sha256 !== null)) return release;
  const sources = release.assets.filter((a) => a.platform === 'checksums' && (a.size === null || a.size <= opts.maxBytes)).slice(0, MAX_CHECKSUM_FILES);
  const sums = new Map();
  for (const file of sources) {
    let answer;
    try {
      answer = await get(file.url, { ...opts, accept: 'application/octet-stream' });
    } catch {
      // A checksum file that cannot be read only means those files show "no checksum published".
      continue;
    }
    if (answer.status !== 200) continue;
    for (const [name, hex] of parseChecksums(answer.body)) {
      // A file with one bare hash belongs to the file it is named after: app.tar.gz.sha256.
      const target = name === '' ? file.name.replace(/\.sha256(?:sum)?$/i, '') : name;
      if (!sums.has(target)) sums.set(target, hex);
    }
  }
  const assets = release.assets.map((a) => {
    if (a.sha256 !== null || !sums.has(a.name)) return a;
    return { ...a, sha256: sums.get(a.name), checksumSource: 'file' };
  });
  return { ...release, assets };
}

// The latest release of one repository: {state: 'ok', release} or {state: 'none'} when it has none.
// Throws ReleaseError for anything else.
export async function fetchLatest(repo, { fetchFn = fetch, token = null, timeoutMs = TIMEOUT_MS, maxBytes = MAX_BYTES } = {}) {
  const opts = { fetchFn, token, timeoutMs, maxBytes };
  const answer = await get(`https://${API_HOST}/repos/${repo}/releases/latest`, { ...opts, accept: 'application/vnd.github+json' });
  if (answer.status === 404) return { state: 'none', release: null };
  if (answer.status !== 200) throw new ReleaseError(`http ${answer.status}`);
  let json;
  try {
    json = JSON.parse(answer.body);
  } catch {
    throw new ReleaseError('bad response');
  }
  const release = fromGitHub(repo, json);
  if (release === null) return { state: 'none', release: null };
  return { state: 'ok', release: await addChecksums(repo, release, opts) };
}

// --- The cache ---

export class ReleaseCache {
  constructor({ repos = DEFAULT_REPOS, dataDir, fetchFn = fetch, token = null, now = Date.now, ttlMs = TTL_MS, timeoutMs = TIMEOUT_MS, maxBytes = MAX_BYTES, log = console.error }) {
    this.repos = repos;
    this.file = path.join(dataDir, 'releases.json');
    this.dataDir = dataDir;
    this.fetchFn = fetchFn;
    this.token = token;
    this.now = now;
    this.ttlMs = ttlMs;
    this.timeoutMs = timeoutMs;
    this.maxBytes = maxBytes;
    this.log = log;
    // repo -> {state, release, fetchedAt, error, failures, nextAt}
    this.entries = new Map(repos.map((r) => [r, { state: null, release: null, fetchedAt: null, error: null, failures: 0, nextAt: 0 }]));
    this.timer = null;
    this.running = null;
    this.saving = Promise.resolve();
  }

  // Reads the last good copy from disk. A missing or damaged file is not an error: the first
  // refresh makes a new one.
  async load() {
    let saved;
    try {
      const st = await fs.stat(this.file);
      if (!st.isFile() || st.size > MAX_STORED_BYTES) return;
      saved = JSON.parse(await fs.readFile(this.file, 'utf8'));
    } catch {
      return;
    }
    if (!isObject(saved) || saved.version !== 1 || !isObject(saved.repos)) return;
    const now = this.now();
    for (const [repo, e] of this.entries) {
      const s = Object.hasOwn(saved.repos, repo) ? saved.repos[repo] : null;
      if (!isObject(s) || !Number.isFinite(s.fetchedAt) || s.fetchedAt < 0) continue;
      const fetchedAt = Math.min(s.fetchedAt, now);
      if (s.state === 'none') Object.assign(e, { state: 'none', release: null, fetchedAt });
      else if (s.state === 'ok') {
        const release = cleanRelease(repo, s.release);
        if (release) Object.assign(e, { state: 'ok', release, fetchedAt });
      } else continue;
      // Fresh data from before a restart is not asked for again at once.
      e.nextAt = fetchedAt + this.ttlMs;
    }
  }

  start() {
    this.stop();
    this.timer = setInterval(() => void this.tick(), TICK_MS);
    this.timer.unref();
    void this.tick();
  }

  stop() {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  // One refresh at a time; a call while one runs joins it.
  tick() {
    this.running ??= this.refreshDue().finally(() => {
      this.running = null;
    });
    return this.running;
  }

  async refreshDue() {
    let changed = false;
    for (const repo of this.repos) {
      if (this.now() < this.entries.get(repo).nextAt) continue;
      changed = (await this.refreshOne(repo)) || changed;
    }
    if (changed) await this.save();
  }

  // Asks GitHub about one repository. Returns whether there is something new to save.
  async refreshOne(repo) {
    const e = this.entries.get(repo);
    const at = this.now();
    try {
      const { state, release } = await fetchLatest(repo, { fetchFn: this.fetchFn, token: this.token, timeoutMs: this.timeoutMs, maxBytes: this.maxBytes });
      Object.assign(e, { state, release, fetchedAt: at, error: null, failures: 0, nextAt: at + this.ttlMs });
      return true;
    } catch (err) {
      const code = err instanceof ReleaseError ? err.code : 'error';
      // Said once for each kind of failure, with the repository (public) and the code only.
      if (e.error !== code) this.log(`releases: could not refresh ${repo} (${code}); ${e.release ? 'keeping the last copy' : 'nothing to show yet'}`);
      e.failures++;
      e.error = code;
      e.nextAt = at + Math.min(this.ttlMs, RETRY_MS * 2 ** Math.min(e.failures - 1, 10));
      return false;
    }
  }

  // What /api/releases says. The last good copy of a repository stays, marked stale with its age,
  // while refreshing fails.
  snapshot() {
    const now = this.now();
    const projects = this.repos.map((repo) => {
      const e = this.entries.get(repo);
      const haveData = e.state !== null;
      let status = 'loading';
      if (e.state === 'ok') status = 'ok';
      else if (e.state === 'none') status = 'none';
      else if (e.error !== null) status = 'unavailable';
      return {
        repo,
        url: `https://github.com/${repo}`,
        releasesUrl: `https://github.com/${repo}/releases`,
        status,
        stale: haveData && e.error !== null,
        ageSeconds: haveData ? Math.max(0, Math.floor((now - e.fetchedAt) / 1000)) : null,
        fetchedAt: haveData ? new Date(e.fetchedAt).toISOString() : null,
        error: e.error,
        release: e.state === 'ok' ? e.release : null,
      };
    });
    return { generatedAt: new Date(now).toISOString(), ttlSeconds: Math.round(this.ttlMs / 1000), projects };
  }

  // Writes releases.json to a temporary file and renames it, so a crash never leaves half a file.
  save() {
    const repos = {};
    for (const [repo, e] of this.entries) if (e.state !== null) repos[repo] = { state: e.state, fetchedAt: e.fetchedAt, release: e.release };
    const body = JSON.stringify({ version: 1, repos });
    this.saving = this.saving.then(async () => {
      const tmp = `${this.file}.${process.pid}.tmp`;
      try {
        await fs.mkdir(this.dataDir, { recursive: true });
        await fs.rm(tmp, { force: true });
        const handle = await fs.open(tmp, 'wx', 0o600);
        try {
          await handle.writeFile(body);
          await handle.sync();
        } finally {
          await handle.close();
        }
        await fs.rename(tmp, this.file);
      } catch (err) {
        this.log(`could not save releases: ${err.code ?? 'error'}`);
        await fs.rm(tmp, { force: true }).catch(() => {});
      }
    });
    return this.saving;
  }
}
