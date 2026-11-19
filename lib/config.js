// The optional YAML config file: the nodes to watch, their stats URLs, display
// names and which nodes proxy which. Read once at start; every mistake stops
// the server with a message that never repeats a URL (it could carry a token).
import fs from 'node:fs/promises';
import YAML from 'yaml';
import { DEFAULT_TARGETS, parseTargets } from './monitor.js';
import { isPrivateHost, parseStatsUrls } from './stats.js';

export const MAX_CONFIG_BYTES = 64 * 1024;
export const MAX_NODES = 64;
export const MAX_NAME = 48;
const NODE_KEYS = ['address', 'name', 'stats_url', 'proxy_for', 'count_own'];

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

// Turns the text of a config file into what the monitor needs:
// {targets, statsUrls, nodes}. nodes maps "host:port" to
// {name, proxyFor, proxiedBy, countOwn}. Throws Error on anything unexpected.
export function loadConfig(text) {
  const root = parse(text);
  if (!isMap(root)) fail('the top level must be a map with a "nodes" list');
  for (const k of Object.keys(root)) if (k !== 'nodes') fail(`unknown key "${String(k).slice(0, 40)}" at the top level`);
  if (!Array.isArray(root.nodes) || root.nodes.length === 0) fail('"nodes" must be a list with at least one node');
  if (root.nodes.length > MAX_NODES) fail(`"nodes" has more than ${MAX_NODES} entries`);

  const targets = [];
  const statsUrls = new Map();
  const nodes = new Map();
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
    nodes.set(a.key, { name, proxyFor: [], proxiedBy: null, countOwn });
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
  return { targets, statsUrls, nodes };
}

// Reads and checks the file. The size is checked before reading it.
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
  return loadConfig(text);
}

// Where the nodes come from: the config file when CONFIG_FILE is set, else the
// STATUS_TARGETS and STATS_URLS variables exactly as before. Setting both is an
// error, so it is never unclear which one counts.
export async function loadNodes(env) {
  if (env.CONFIG_FILE) {
    if (env.STATUS_TARGETS || env.STATS_URLS) {
      throw new Error('CONFIG_FILE replaces STATUS_TARGETS and STATS_URLS: set either the file or the variables, not both');
    }
    return loadConfigFile(env.CONFIG_FILE);
  }
  const targets = parseTargets(env.STATUS_TARGETS || DEFAULT_TARGETS.join(','));
  return { targets, statsUrls: parseStatsUrls(env.STATS_URLS, targets), nodes: new Map() };
}
