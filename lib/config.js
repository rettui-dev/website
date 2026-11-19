// The optional YAML config file: the nodes to watch, their stats URLs, display
// names and which nodes proxy which. Read once at start; every mistake stops
// the server with a message that never repeats a URL (it could carry a token).
import fs from 'node:fs/promises';
import path from 'node:path';
import net from 'node:net';
import { constants as fsConstants } from 'node:fs';
import YAML from 'yaml';
import { DEFAULT_TARGETS, parseTargets } from './monitor.js';
import { isPrivateHost, parseStatsUrls } from './stats.js';
import { validToken } from './peers.js';
import { SECTIONS } from './access.js';
import { parsePhc } from './password.js';
import { LOGIN_DEFAULTS, normalIp } from './login.js';

export const MAX_CONFIG_BYTES = 64 * 1024;
export const MAX_NODES = 64;
export const MAX_NAME = 48;
const NODE_KEYS = ['address', 'name', 'stats_url', 'stats_token', 'stats_token_file', 'proxy_for', 'count_own', 'public_details', 'public_disk_figures', 'require_login'];
const TOP_KEYS = ['nodes', 'stats_token', 'stats_token_file', 'public_details', 'public_disk_figures', 'users', 'login', 'require_login'];
export const MAX_USERS = 64;
// A user name: letters, digits, dot, dash and underscore, starting with a letter or digit.
const USER_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$/;
// The login settings: [YAML key, key in the result, smallest, largest].
const LOGIN_NUMBERS = [
  ['idle_timeout_minutes', 'idleTimeoutMinutes', 1, 7 * 24 * 60],
  ['max_age_hours', 'maxAgeHours', 1, 90 * 24],
  ['max_sessions', 'maxSessions', 1, 100_000],
];
const MAX_TRUSTED_PROXIES = 16;
export const MAX_TOKEN_FILE_BYTES = 1024;

class ConfigError extends Error {}
const fail = (msg) => {
  throw new ConfigError(`CONFIG_FILE: ${msg}`);
};

const isMap = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

// "host:port" in its normal form (host in lower case), or an error naming where it was.
function address(value, where) {
  if (typeof value !== 'string' || value.includes(',')) fail(`${where} must be one host:port`);
  try {
    const [t] = parseTargets(value);
    return { host: t.host, port: t.port, key: `${t.host}:${t.port}` };
  } catch {
    return fail(`${where} is not a host:port`);
  }
}

function statsUrl(value, where) {
  let url = null;
  try {
    url = new URL(typeof value === 'string' ? value.trim() : '');
  } catch {
    // reported below
  }
  if (!url || (url.protocol !== 'http:' && url.protocol !== 'https:') || !url.hostname || url.username || url.password) {
    fail(`${where} is not an http(s) URL without a user name or password`);
  }
  if (url.protocol === 'http:' && !isPrivateHost(url.hostname)) {
    fail(`${where} uses plain http, which is only allowed for loopback and private addresses; use https`);
  }
  return url.href;
}

// Parses plain data out of the YAML text: no aliases, no custom tags, no merge
// keys, no repeated keys, one document.
function parse(text) {
  if (typeof text !== 'string') fail('the file is not text');
  if (Buffer.byteLength(text) > MAX_CONFIG_BYTES) fail(`the file is larger than ${MAX_CONFIG_BYTES / 1024} KiB`);
  let doc;
  try {
    doc = YAML.parseDocument(text, { schema: 'core', version: '1.2', merge: false, maxAliasCount: 0, uniqueKeys: true, prettyErrors: false });
  } catch {
    return fail('the file is not valid YAML');
  }
  // Warnings include tags nobody defined, which would otherwise pass as text.
  const problem = doc.errors[0] ?? doc.warnings[0];
  if (problem) fail(`invalid YAML at line ${problem.linePos?.[0]?.line ?? '?'} (${problem.code})`);
  try {
    return doc.toJS({ maxAliasCount: 0 });
  } catch {
    return fail('invalid YAML (aliases are not allowed)');
  }
}

// true or false, or the fallback when the key is absent.
function flag(value, where, fallback) {
  if (value === undefined) return fallback;
  if (typeof value !== 'boolean') fail(`${where} must be true or false`);
  return value;
}

// A token from the file or the environment. Errors say where, never what.
function tokenValue(value, where) {
  if (!validToken(value)) fail(`${where} must be 16 to 256 printable characters without spaces`);
  return value;
}

// The users who can log in, as [{name, phc}]. Errors never repeat a hash.
function users(value) {
  if (!Array.isArray(value) || value.length === 0 || value.length > MAX_USERS) fail(`"users" must be a list of 1 to ${MAX_USERS} users`);
  const seen = new Set();
  return value.map((u, i) => {
    const where = `users[${i + 1}]`;
    if (!isMap(u)) fail(`${where} must be a map with name and password_hash`);
    for (const k of Object.keys(u)) if (k !== 'name' && k !== 'password_hash') fail(`${where} has an unknown key "${String(k).slice(0, 40)}"`);
    if (typeof u.name !== 'string' || !USER_RE.test(u.name)) fail(`${where}.name must be 1 to 32 letters, digits, dots, dashes or underscores, starting with a letter or digit`);
    // Names are matched without regard to case, so they must differ in more than case.
    if (seen.has(u.name.toLowerCase())) fail(`${where}.name "${u.name}" is listed twice`);
    seen.add(u.name.toLowerCase());
    if (!Object.hasOwn(u, 'password_hash')) fail(`${where} needs a password_hash (make one with npm run hash-password)`);
    let phc;
    try {
      phc = parsePhc(u.password_hash);
    } catch (err) {
      return fail(`${where}.password_hash ${err.message}`);
    }
    return { name: u.name, phc };
  });
}

// The login settings, with the defaults for what is left out.
function loginSettings(value) {
  const out = { ...LOGIN_DEFAULTS, trustedProxies: [] };
  if (value === undefined) return out;
  if (!isMap(value)) fail('"login" must be a map');
  const known = [...LOGIN_NUMBERS.map((n) => n[0]), 'trusted_proxies'];
  for (const k of Object.keys(value)) if (!known.includes(k)) fail(`login has an unknown key "${String(k).slice(0, 40)}"`);
  for (const [key, name, min, max] of LOGIN_NUMBERS) {
    if (!Object.hasOwn(value, key)) continue;
    const v = value[key];
    if (!Number.isInteger(v) || v < min || v > max) fail(`login.${key} must be a whole number from ${min} to ${max}`);
    out[name] = v;
  }
  if (Object.hasOwn(value, 'trusted_proxies')) {
    const list = value.trusted_proxies;
    if (!Array.isArray(list) || list.length > MAX_TRUSTED_PROXIES) fail(`login.trusted_proxies must be a list of at most ${MAX_TRUSTED_PROXIES} IP addresses`);
    list.forEach((ip, i) => {
      if (typeof ip !== 'string' || net.isIP(ip) === 0) fail(`login.trusted_proxies[${i + 1}] is not an IP address`);
    });
    // One spelling per address, the one the peer address is put in before it is compared.
    out.trustedProxies = list.map(normalIp);
  }
  if (out.idleTimeoutMinutes > out.maxAgeHours * 60) fail('login.idle_timeout_minutes cannot be longer than login.max_age_hours');
  return out;
}

// A require_login list: known sections, each once.
function sections(value, where) {
  if (!Array.isArray(value)) fail(`${where} must be a list of sections (${SECTIONS.join(', ')})`);
  const out = [];
  value.forEach((v, i) => {
    if (typeof v !== 'string' || !SECTIONS.includes(v)) fail(`${where}[${i + 1}] must be one of ${SECTIONS.join(', ')}`);
    if (out.includes(v)) fail(`${where} lists ${v} twice`);
    out.push(v);
  });
  return out;
}

function tokenPath(value, where) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 512 || value.includes('\0')) fail(`${where} must be a file path`);
  return value;
}

// Turns the text of a config file into what the monitor needs:
// {targets, statsUrls, nodes, tokens, tokenFiles}. tokens maps "host:port" to a
// token given in the file, tokenFiles to a path still to be read (see
// loadConfigFile). Tokens are kept out of nodes, which is what the monitor
// shows. nodes maps "host:port" to
// {name, proxyFor, proxiedBy, countOwn}. Throws Error on anything unexpected.
export function loadConfig(text) {
  const root = parse(text);
  if (!isMap(root)) fail('the top level must be a map with a "nodes" list');
  for (const k of Object.keys(root)) {
    if (!TOP_KEYS.includes(k)) fail(`unknown key "${String(k).slice(0, 40)}" at the top level`);
  }
  // Without users nothing can be locked, and the page has no login.
  const people = Object.hasOwn(root, 'users') ? users(root.users) : [];
  if (people.length === 0) {
    if (Object.hasOwn(root, 'login')) fail('"login" needs "users": add at least one user, or remove "login"');
    if (Object.hasOwn(root, 'require_login') && sections(root.require_login, 'require_login').length) fail('require_login needs "users": nobody could log in to see those sections');
  }
  const login = loginSettings(root.login);
  if (Object.hasOwn(root, 'stats_token') && Object.hasOwn(root, 'stats_token_file')) fail('use either stats_token or stats_token_file at the top level, not both');
  // What the page may show: whether nodes have a Details view, and whether exact
  // disk figures are published. A node can override both.
  // With users and no rule, the default locks every section.
  const defaults = {
    publicDetails: flag(root.public_details, 'public_details', true),
    publicDiskFigures: flag(root.public_disk_figures, 'public_disk_figures', false),
    requireLogin: Object.hasOwn(root, 'require_login') ? sections(root.require_login, 'require_login') : people.length ? [...SECTIONS] : [],
  };
  const defaultToken = Object.hasOwn(root, 'stats_token') ? tokenValue(root.stats_token, 'stats_token') : null;
  const defaultFile = Object.hasOwn(root, 'stats_token_file') ? tokenPath(root.stats_token_file, 'stats_token_file') : null;
  if (!Array.isArray(root.nodes) || root.nodes.length === 0) fail('"nodes" must be a list with at least one node');
  if (root.nodes.length > MAX_NODES) fail(`"nodes" has more than ${MAX_NODES} entries`);

  const targets = [];
  const statsUrls = new Map();
  const nodes = new Map();
  const tokens = new Map();
  const tokenFiles = new Map();
  const wanted = []; // [key, proxy_for values, where]

  root.nodes.forEach((n, i) => {
    const where = `nodes[${i + 1}]`;
    if (!isMap(n)) fail(`${where} must be a map`);
    for (const k of Object.keys(n)) if (!NODE_KEYS.includes(k)) fail(`${where} has an unknown key "${String(k).slice(0, 40)}"`);
    if (!Object.hasOwn(n, 'address')) fail(`${where} needs an address`);
    const a = address(n.address, `${where}.address`);
    if (nodes.has(a.key)) fail(`${where} lists ${a.key} twice`);

    let name = null;
    if (Object.hasOwn(n, 'name')) {
      if (typeof n.name !== 'string') fail(`${where}.name must be text`);
      name = n.name.trim();
      if (name.length === 0 || name.length > MAX_NAME) fail(`${where}.name must be 1 to ${MAX_NAME} characters`);
      if (/[\u0000-\u001f\u007f-\u009f]/.test(name)) fail(`${where}.name has control characters`);
    }
    if (Object.hasOwn(n, 'stats_url')) statsUrls.set(a.key, statsUrl(n.stats_url, `${where}.stats_url`));
    if (Object.hasOwn(n, 'stats_token') && Object.hasOwn(n, 'stats_token_file')) fail(`${where} has both stats_token and stats_token_file`);
    if (Object.hasOwn(n, 'stats_token') || Object.hasOwn(n, 'stats_token_file')) {
      if (!statsUrls.has(a.key)) fail(`${where} has a token but no stats_url`);
      if (Object.hasOwn(n, 'stats_token')) tokens.set(a.key, tokenValue(n.stats_token, `${where}.stats_token`));
      else tokenFiles.set(a.key, tokenPath(n.stats_token_file, `${where}.stats_token_file`));
    } else if (statsUrls.has(a.key)) {
      // The top level setting is the default for every node that has a stats URL.
      if (defaultToken !== null) tokens.set(a.key, defaultToken);
      else if (defaultFile !== null) tokenFiles.set(a.key, defaultFile);
    }

    let countOwn = false;
    if (Object.hasOwn(n, 'count_own')) {
      if (typeof n.count_own !== 'boolean') fail(`${where}.count_own must be true or false`);
      if (!Object.hasOwn(n, 'proxy_for')) fail(`${where}.count_own only makes sense together with proxy_for`);
      countOwn = n.count_own;
    }
    if (Object.hasOwn(n, 'proxy_for')) {
      if (!Array.isArray(n.proxy_for) || n.proxy_for.length === 0 || n.proxy_for.length > MAX_NODES) {
        fail(`${where}.proxy_for must be a list of 1 to ${MAX_NODES} addresses`);
      }
      wanted.push([a.key, n.proxy_for, where]);
    }
    targets.push({ host: a.host, port: a.port });
    const publicDetails = flag(n.public_details, `${where}.public_details`, defaults.publicDetails);
    const publicDiskFigures = flag(n.public_disk_figures, `${where}.public_disk_figures`, defaults.publicDiskFigures);
    let requireLogin = defaults.requireLogin;
    if (Object.hasOwn(n, 'require_login')) {
      requireLogin = sections(n.require_login, `${where}.require_login`);
      if (requireLogin.length && people.length === 0) fail(`${where}.require_login needs "users": nobody could log in to see those sections`);
    }
    nodes.set(a.key, { name, proxyFor: [], proxiedBy: null, countOwn, publicDetails, publicDiskFigures, requireLogin });
  });

  for (const [key, list, where] of wanted) {
    const mine = nodes.get(key);
    list.forEach((raw, j) => {
      const m = address(raw, `${where}.proxy_for[${j + 1}]`).key;
      if (m === key) fail(`${key} cannot proxy itself`);
      if (!nodes.has(m)) fail(`${where}.proxy_for lists ${m}, which is not one of the nodes`);
      if (mine.proxyFor.includes(m)) fail(`${where}.proxy_for lists ${m} twice`);
      const member = nodes.get(m);
      if (member.proxiedBy) fail(`${m} is proxied by both ${member.proxiedBy} and ${key}; a node can have one proxy`);
      member.proxiedBy = key;
      mine.proxyFor.push(m);
    });
  }
  // A proxy cannot be proxied: groups are one level deep. Two nodes that proxy
  // each other (or a longer loop) are reported as a cycle first.
  for (const [key, n] of nodes) {
    const seen = new Set([key]);
    for (let at = n.proxiedBy; at; at = nodes.get(at).proxiedBy) {
      if (seen.has(at)) fail(`the proxy settings form a cycle through ${at}`);
      seen.add(at);
    }
  }
  for (const [key, n] of nodes) {
    if (n.proxiedBy && n.proxyFor.length) fail(`${key} is proxied by ${n.proxiedBy} and also proxies others; proxies cannot be nested`);
  }
  return { targets, statsUrls, nodes, tokens, tokenFiles, defaults, users: people, login };
}

// Reads one token file: a small file with the token and, usually, a final newline.
// The file is opened first and checked through the open handle (so it cannot be
// swapped in between), must be a regular file, and at most MAX_TOKEN_FILE_BYTES
// are read. O_NONBLOCK keeps an open of a named pipe from hanging the start.
// A file that other users can read gets a warning (never the token) in warnings.
async function readTokenFile(file, where, warnings) {
  let text;
  let handle;
  try {
    handle = await fs.open(file, fsConstants.O_RDONLY | fsConstants.O_NONBLOCK);
    const st = await handle.stat();
    if (!st.isFile() || st.size > MAX_TOKEN_FILE_BYTES) fail(`${where} is not a small file`);
    const buf = Buffer.alloc(MAX_TOKEN_FILE_BYTES + 1);
    const { bytesRead } = await handle.read(buf, 0, buf.length, 0);
    if (bytesRead > MAX_TOKEN_FILE_BYTES) fail(`${where} is not a small file`);
    text = buf.toString('utf8', 0, bytesRead);
    if (process.platform !== 'win32' && (st.mode & 0o044) !== 0) {
      warnings.push(`warning: ${where} (${path.basename(file)}) can be read by other users (mode ${(st.mode & 0o777).toString(8)}); make it readable by the server only, for example chmod 600`);
    }
  } catch (err) {
    if (err instanceof ConfigError) throw err;
    return fail(`${where} cannot be read (${err.code ?? 'error'})`);
  } finally {
    await handle?.close().catch(() => {});
  }
  return tokenValue(text.trim(), `the token in ${where}`);
}

// Startup warnings about how tokens are shared. When one token value goes to
// stats URLs on different hostnames, whoever runs one of those nodes learns a
// secret that is good for the others. The token itself is never named.
export function tokenWarnings(statsUrls, tokens) {
  const hostsByToken = new Map();
  for (const [key, token] of tokens) {
    const url = statsUrls.get(key);
    if (!url) continue;
    const set = hostsByToken.get(token) ?? new Set();
    set.add(new URL(url).hostname);
    hostsByToken.set(token, set);
  }
  const out = [];
  for (const hosts of hostsByToken.values()) {
    if (hosts.size > 1) out.push(`warning: one stats token is sent to stats URLs on ${hosts.size} different hostnames; use a separate token for each node (a stats_token_file per node)`);
  }
  return out;
}

// Reads and checks the file. The size is checked before reading it. Token files
// are read now, relative to the config file's folder, and merged into tokens;
// the result has no tokenFiles left.
export async function loadConfigFile(file) {
  let text;
  try {
    const st = await fs.stat(file);
    if (!st.isFile()) fail('the path is not a file');
    if (st.size > MAX_CONFIG_BYTES) fail(`the file is larger than ${MAX_CONFIG_BYTES / 1024} KiB`);
    text = await fs.readFile(file, 'utf8');
  } catch (err) {
    if (err instanceof ConfigError) throw err;
    return fail(`cannot read the file (${err.code ?? 'error'})`);
  }
  const config = loadConfig(text);
  const cache = new Map();
  config.warnings = [];
  for (const [key, p] of config.tokenFiles) {
    const full = path.resolve(path.dirname(file), p);
    if (!cache.has(full)) cache.set(full, await readTokenFile(full, 'stats_token_file', config.warnings));
    config.tokens.set(key, cache.get(full));
  }
  config.tokenFiles = new Map();
  config.warnings.push(...tokenWarnings(config.statsUrls, config.tokens));
  return config;
}

// PUBLIC_DETAILS and PUBLIC_DISK_FIGURES: true or false, nothing else.
function envFlag(value, name, fallback) {
  if (value === undefined) return fallback;
  // An empty value is a mistake (a blank line in an env file), not a choice: it must not mean public.
  if (value === '') throw new Error(`${name} is empty: set it to true or false, or remove it`);
  if (value === 'true') return true;
  if (value === 'false') return false;
  throw new Error(`${name} must be true or false`);
}

// Turns "host:port=path,..." into a Map of "host:port" to a file path. Strict like
// STATS_URLS: only nodes that have a stats URL, none twice, no empty path. A path
// cannot contain a comma.
export function parseTokenFiles(list, statsUrls) {
  const map = new Map();
  const items = String(list ?? '').split(',').map((x) => x.trim()).filter(Boolean);
  items.forEach((item, n) => {
    const i = item.indexOf('=');
    const key = i > 0 ? item.slice(0, i).trim().toLowerCase() : '';
    const file = i > 0 ? item.slice(i + 1).trim() : '';
    if (!file || file.includes('\0')) throw new Error(`STATS_TOKEN_FILES: entry ${n + 1} is not host:port=path`);
    if (!statsUrls.has(key)) throw new Error(`STATS_TOKEN_FILES: entry ${n + 1} is not a node with a stats URL`);
    if (map.has(key)) throw new Error(`STATS_TOKEN_FILES: "${key}" is listed twice`);
    map.set(key, file);
  });
  return map;
}

// Where the nodes come from: the config file when CONFIG_FILE is set, else the
// STATUS_TARGETS and STATS_URLS variables exactly as before. In that case a token
// can be set for every stats URL (STATS_TOKEN or STATS_TOKEN_FILE) and for single
// nodes (STATS_TOKEN_FILES, which wins). Setting both a file and the variables is
// an error, so it is never unclear which one counts.
export async function loadNodes(env) {
  if (env.CONFIG_FILE) {
    if (env.STATUS_TARGETS || env.STATS_URLS || env.STATS_TOKEN || env.STATS_TOKEN_FILE || env.STATS_TOKEN_FILES || env.PUBLIC_DETAILS || env.PUBLIC_DISK_FIGURES) {
      throw new Error('CONFIG_FILE replaces STATUS_TARGETS, STATS_URLS, STATS_TOKEN, STATS_TOKEN_FILE, STATS_TOKEN_FILES, PUBLIC_DETAILS and PUBLIC_DISK_FIGURES: set either the file or the variables, not both');
    }
    return loadConfigFile(env.CONFIG_FILE);
  }
  const defaults = { publicDetails: envFlag(env.PUBLIC_DETAILS, 'PUBLIC_DETAILS', true), publicDiskFigures: envFlag(env.PUBLIC_DISK_FIGURES, 'PUBLIC_DISK_FIGURES', false) };
  const targets = parseTargets(env.STATUS_TARGETS || DEFAULT_TARGETS.join(','));
  const statsUrls = parseStatsUrls(env.STATS_URLS, targets);
  const perNode = parseTokenFiles(env.STATS_TOKEN_FILES, statsUrls);
  const tokens = new Map();
  const warnings = [];
  if (env.STATS_TOKEN && env.STATS_TOKEN_FILE) throw new Error('set either STATS_TOKEN or STATS_TOKEN_FILE, not both');
  try {
    let token = null;
    if (env.STATS_TOKEN) token = tokenValue(env.STATS_TOKEN, 'STATS_TOKEN');
    else if (env.STATS_TOKEN_FILE) token = await readTokenFile(path.resolve(env.STATS_TOKEN_FILE), 'STATS_TOKEN_FILE', warnings);
    if (token !== null) for (const key of statsUrls.keys()) tokens.set(key, token);
    const cache = new Map();
    for (const [key, file] of perNode) {
      const full = path.resolve(file);
      if (!cache.has(full)) cache.set(full, await readTokenFile(full, 'STATS_TOKEN_FILES', warnings));
      tokens.set(key, cache.get(full));
    }
  } catch (err) {
    // These messages come from the config file checks: say STATS_TOKEN, not CONFIG_FILE.
    throw new Error(err.message.replace(/^CONFIG_FILE: /, ''));
  }
  warnings.push(...tokenWarnings(statsUrls, tokens));
  // Users and their sections need the config file; with the variables there is no login.
  return { targets, statsUrls, nodes: new Map(), tokens, tokenFiles: new Map(), warnings, defaults: { ...defaults, requireLogin: [] }, users: [], login: { ...LOGIN_DEFAULTS } };
}
