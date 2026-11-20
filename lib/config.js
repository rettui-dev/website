// The optional YAML config file: the nodes to watch, their stats URLs, display
// names and which nodes proxy which. Read once at start; every mistake stops
// the server with a message that never repeats a URL (it could carry a token).
import fs from 'node:fs/promises';
import path from 'node:path';
import net from 'node:net';
import { constants as fsConstants } from 'node:fs';
import YAML from 'yaml';
import { DEFAULT_TARGETS, HOST_RE, parseTargets } from './monitor.js';
import { isPrivateHost, parseStatsUrls } from './stats.js';
import { validToken } from './peers.js';
import { SECTIONS } from './access.js';
import { parsePhc } from './password.js';
import { DEFAULT_ROLE, ROLES, USER_NAME_RE as USER_RE } from './users.js';
import { LOGIN_DEFAULTS, normalIp } from './login.js';
import { ALL_EVENTS, DEFAULT_QUEUE_SAMPLES, EVENTS, FORMATS } from './alerts.js';
import { ADDRESS_RE } from './smtp.js';
import { MAX_LINK_LABEL, MAX_LINK_URL, MAX_SITE_LINKS, MAX_SITE_NAME, MAX_SITE_TEXT, NO_SITE, SITE_MODES, parseSiteUrl, readLogo, resolveLogoPath } from './site.js';

export const MAX_CONFIG_BYTES = 64 * 1024;
export const MAX_NODES = 64;
export const MAX_NAME = 48;
export const MAX_UPSTREAMS = 8;
const NODE_KEYS = ['address', 'name', 'stats_url', 'stats_token', 'stats_token_file', 'proxy_for', 'count_own', 'public_details', 'public_disk_figures', 'public_logs', 'require_login', 'upstreams'];
const TOP_KEYS = ['nodes', 'stats_token', 'stats_token_file', 'public_details', 'public_disk_figures', 'public_logs', 'users', 'login', 'require_login', 'alerts', 'site_mode', 'site'];
const SITE_KEYS = ['name', 'logo', 'links', 'description', 'footer', 'url'];
export const MAX_USERS = 64;
// The login settings: [YAML key, key in the result, smallest, largest].
const LOGIN_NUMBERS = [
  ['idle_timeout_minutes', 'idleTimeoutMinutes', 1, 7 * 24 * 60],
  ['max_age_hours', 'maxAgeHours', 1, 90 * 24],
  ['max_sessions', 'maxSessions', 1, 100_000],
];
const MAX_TRUSTED_PROXIES = 16;
export const MAX_TOKEN_FILE_BYTES = 1024;
export const MAX_CHANNELS = 4;
export const MAX_RECIPIENTS = 5;
const ALERT_KEYS = ['channels', 'events', 'cooldown_minutes', 'repeat_minutes', 'announce_queue_samples'];
const WEBHOOK_KEYS = ['type', 'url', 'format', 'secret', 'secret_file'];
const EMAIL_KEYS = ['type', 'host', 'port', 'security', 'username', 'password_file', 'auth', 'from', 'to'];
const DEFAULT_PORT = { tls: 465, starttls: 587 };

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

// The external backbone peers a node connects out to, as [{name, address?}]. They are only
// shown on the network map: nothing here is ever resolved, probed or fetched.
function upstreams(value, where) {
  if (!Array.isArray(value) || value.length === 0 || value.length > MAX_UPSTREAMS) fail(`${where} must be a list of 1 to ${MAX_UPSTREAMS} upstreams`);
  const seen = new Set();
  return value.map((u, i) => {
    const at = `${where}[${i + 1}]`;
    if (!isMap(u)) fail(`${at} must be a map with a name and an optional address`);
    for (const k of Object.keys(u)) if (k !== 'name' && k !== 'address') fail(`${at} has an unknown key "${String(k).slice(0, 40)}"`);
    if (typeof u.name !== 'string') fail(`${at}.name must be text`);
    const name = u.name.trim();
    if (name.length === 0 || name.length > MAX_NAME) fail(`${at}.name must be 1 to ${MAX_NAME} characters`);
    if (/[\u0000-\u001f\u007f-\u009f]/.test(name)) fail(`${at}.name has control characters`);
    if (seen.has(name.toLowerCase())) fail(`${where} lists the name "${name}" twice`);
    seen.add(name.toLowerCase());
    return Object.hasOwn(u, 'address') ? { name, address: address(u.address, `${at}.address`).key } : { name };
  });
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

// A mail password: 1 to 256 characters, spaces allowed, no control characters.
function passwordValue(value, where) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 256 || /[\u0000-\u001f\u007f-\u009f]/.test(value)) fail(`${where} must be 1 to 256 characters without control characters`);
  return value;
}

// The users who can log in, as [{name, phc, role}]. Errors never repeat a hash.
function users(value) {
  if (!Array.isArray(value) || value.length === 0 || value.length > MAX_USERS) fail(`"users" must be a list of 1 to ${MAX_USERS} users`);
  const seen = new Set();
  return value.map((u, i) => {
    const where = `users[${i + 1}]`;
    if (!isMap(u)) fail(`${where} must be a map with name and password_hash`);
    for (const k of Object.keys(u)) if (k !== 'name' && k !== 'password_hash' && k !== 'role') fail(`${where} has an unknown key "${String(k).slice(0, 40)}"`);
    // YAML reads an unquoted 123, true or null as a number, a boolean or nothing.
    if (u.name !== undefined && typeof u.name !== 'string' && !isMap(u.name) && !Array.isArray(u.name)) fail(`${where}.name is not text: put the name in quotes, as YAML reads a bare 123, true or null as something else`);
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
    if (Object.hasOwn(u, 'role') && !ROLES.includes(u.role)) fail(`${where}.role must be one of ${ROLES.join(', ')}`);
    return { name: u.name, phc, role: u.role ?? DEFAULT_ROLE };
  });
}

// A list of trusted proxies: at most MAX_TRUSTED_PROXIES IP addresses, in one spelling each, the
// one the peer address is put in before it is compared. at(i) names the i-th entry in a message.
function trustedProxies(list, where, at, failWith) {
  if (!Array.isArray(list) || list.length > MAX_TRUSTED_PROXIES) failWith(`${where} must be a list of at most ${MAX_TRUSTED_PROXIES} IP addresses`);
  list.forEach((ip, i) => {
    if (typeof ip !== 'string' || net.isIP(ip) === 0) failWith(`${at(i + 1)} is not an IP address`);
  });
  return list.map(normalIp);
}

// LOGIN_TRUSTED_PROXIES: the trusted proxies without a config file, as a comma separated list.
export function parseTrustedProxiesEnv(text) {
  const thrower = (m) => {
    throw new Error(m);
  };
  if (text === '') thrower('LOGIN_TRUSTED_PROXIES is empty: set it to the IP addresses of the reverse proxies, separated by commas, or remove it');
  const list = text.split(',').map((x) => x.trim());
  return trustedProxies(list, 'LOGIN_TRUSTED_PROXIES', (i) => `LOGIN_TRUSTED_PROXIES: entry ${i}`, thrower);
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
  if (Object.hasOwn(value, 'trusted_proxies')) out.trustedProxies = trustedProxies(value.trusted_proxies, 'login.trusted_proxies', (i) => `login.trusted_proxies[${i}]`, fail);
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

// An integer in a range, or the fallback when the key is absent.
function whole(map, key, where, min, max, fallback) {
  if (!Object.hasOwn(map, key)) return fallback;
  const v = map[key];
  if (!Number.isInteger(v) || v < min || v > max) fail(`${where}.${key} must be a whole number from ${min} to ${max}`);
  return v;
}

// One alert address: one line, no brackets or quotes. Errors never repeat it.
function mailAddress(value, where) {
  if (typeof value !== 'string' || !ADDRESS_RE.test(value) || value.length > 254) fail(`${where} must be an email address such as name@example.org`);
  return value;
}

function webhookChannel(c, where) {
  for (const k of Object.keys(c)) if (!WEBHOOK_KEYS.includes(k)) fail(`${where} has an unknown key "${String(k).slice(0, 40)}"`);
  if (!Object.hasOwn(c, 'url')) fail(`${where} needs a url`);
  if (typeof c.url === 'string' && c.url.length > 2048) fail(`${where}.url is longer than 2048 characters`);
  // The URL may carry a secret (chat services put one in the path): the messages never repeat it.
  const out = { type: 'webhook', url: statsUrl(c.url, `${where}.url`), format: 'generic' };
  if (Object.hasOwn(c, 'format')) {
    if (typeof c.format !== 'string' || !FORMATS.includes(c.format)) fail(`${where}.format must be one of ${FORMATS.join(', ')}`);
    out.format = c.format;
  }
  if (Object.hasOwn(c, 'secret') && Object.hasOwn(c, 'secret_file')) fail(`${where} has both secret and secret_file`);
  if (Object.hasOwn(c, 'secret')) out.secret = tokenValue(c.secret, `${where}.secret`);
  if (Object.hasOwn(c, 'secret_file')) out.secretFile = tokenPath(c.secret_file, `${where}.secret_file`);
  return out;
}

function emailChannel(c, where) {
  for (const k of Object.keys(c)) if (!EMAIL_KEYS.includes(k)) fail(`${where} has an unknown key "${String(k).slice(0, 40)}"`);
  if (typeof c.host !== 'string' || c.host.length > 253 || !(HOST_RE.test(c.host) || net.isIPv4(c.host))) fail(`${where}.host must be the name of the mail server`);
  let security = 'starttls';
  if (Object.hasOwn(c, 'security')) {
    if (c.security !== 'tls' && c.security !== 'starttls') fail(`${where}.security must be tls (SMTPS, usually port 465) or starttls (usually port 587); mail is never sent unencrypted`);
    security = c.security;
  }
  const out = { type: 'email', host: c.host.toLowerCase(), port: whole(c, 'port', where, 1, 65535, DEFAULT_PORT[security]), security, from: mailAddress(c.from, `${where}.from`) };
  if (!Array.isArray(c.to) || c.to.length === 0 || c.to.length > MAX_RECIPIENTS) fail(`${where}.to must be a list of 1 to ${MAX_RECIPIENTS} email addresses`);
  out.to = c.to.map((a, i) => mailAddress(a, `${where}.to[${i + 1}]`));
  if (Object.hasOwn(c, 'username')) {
    if (typeof c.username !== 'string' || c.username.length === 0 || c.username.length > 256 || /[\u0000-\u001f\u007f-\u009f]/.test(c.username)) fail(`${where}.username must be 1 to 256 characters without control characters`);
    if (!Object.hasOwn(c, 'password_file')) fail(`${where} has a username but no password_file`);
    out.username = c.username;
    out.passwordFile = tokenPath(c.password_file, `${where}.password_file`);
    out.auth = 'plain';
    if (Object.hasOwn(c, 'auth')) {
      if (c.auth !== 'plain' && c.auth !== 'login') fail(`${where}.auth must be plain or login`);
      out.auth = c.auth;
    }
  } else if (Object.hasOwn(c, 'password_file') || Object.hasOwn(c, 'auth')) fail(`${where} has a password_file or auth but no username`);
  return out;
}

// The optional alerts section: where to send a message when a node goes down or comes back.
// Returns null without one, else {channels, events, queueSamples, cooldownMinutes, repeatMinutes}. A channel's
// secret_file or password_file is only a path here (secretFile, passwordFile); loadConfigFile reads it.
function alertSettings(value) {
  if (value === undefined) return null;
  if (!isMap(value)) fail('"alerts" must be a map with a list of channels');
  for (const k of Object.keys(value)) if (!ALERT_KEYS.includes(k)) fail(`alerts has an unknown key "${String(k).slice(0, 40)}"`);
  if (!Array.isArray(value.channels) || value.channels.length === 0 || value.channels.length > MAX_CHANNELS) fail(`alerts.channels must be a list of 1 to ${MAX_CHANNELS} channels`);
  const channels = value.channels.map((c, i) => {
    const where = `alerts.channels[${i + 1}]`;
    if (!isMap(c)) fail(`${where} must be a map with a type (webhook or email)`);
    if (c.type === 'webhook') return webhookChannel(c, where);
    if (c.type === 'email') return emailChannel(c, where);
    return fail(`${where}.type must be webhook or email`);
  });
  let events = [...EVENTS];
  if (Object.hasOwn(value, 'events')) {
    if (!Array.isArray(value.events) || value.events.length === 0 || value.events.length > ALL_EVENTS.length) fail(`alerts.events must be a list of ${ALL_EVENTS.join(', ')}`);
    events = [];
    value.events.forEach((e, i) => {
      if (typeof e !== 'string' || !ALL_EVENTS.includes(e)) fail(`alerts.events[${i + 1}] must be one of ${ALL_EVENTS.join(', ')}`);
      if (events.includes(e)) fail(`alerts.events lists ${e} twice`);
      events.push(e);
    });
  }
  const repeatMinutes = whole(value, 'repeat_minutes', 'alerts', 0, 7 * 24 * 60, 0);
  if (repeatMinutes !== 0 && repeatMinutes < 5) fail('alerts.repeat_minutes must be 0 (no reminders) or at least 5');
  const queueSamples = whole(value, 'announce_queue_samples', 'alerts', 1, 100, DEFAULT_QUEUE_SAMPLES);
  return { channels, events, queueSamples, cooldownMinutes: whole(value, 'cooldown_minutes', 'alerts', 0, 24 * 60, 15), repeatMinutes };
}

function tokenPath(value, where) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 512 || value.includes('\0')) fail(`${where} must be a file path`);
  return value;
}

// site_mode (or SITE_MODE): full or status.
function siteMode(value, where, fail_ = fail) {
  if (typeof value !== 'string' || !SITE_MODES.includes(value)) fail_(`${where} must be ${SITE_MODES.join(' or ')}`);
  return value;
}

// One line of plain text for the site section: no control or direction characters.
function siteText(value, where, max) {
  if (typeof value !== 'string') fail(`${where} must be text`);
  const text = value.trim();
  if (text.length === 0 || text.length > max) fail(`${where} must be 1 to ${max} characters`);
  if (/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/.test(text)) fail(`${where} has control characters`);
  return text;
}

// A link for the nav: http or https, a host, no user name or password.
function siteLink(value, where) {
  if (!isMap(value)) fail(`${where} must be a map with label and url`);
  for (const k of Object.keys(value)) if (k !== 'label' && k !== 'url') fail(`${where} has an unknown key "${String(k).slice(0, 40)}"`);
  const label = siteText(value.label, `${where}.label`, MAX_LINK_LABEL);
  if (typeof value.url !== 'string' || value.url.length === 0 || value.url.length > MAX_LINK_URL) fail(`${where}.url must be an http or https URL of up to ${MAX_LINK_URL} characters`);
  let u;
  try {
    u = new URL(value.url);
  } catch {
    return fail(`${where}.url is not a URL`);
  }
  if ((u.protocol !== 'https:' && u.protocol !== 'http:') || u.hostname === '') fail(`${where}.url must be an http or https URL`);
  if (u.username || u.password) fail(`${where}.url must not contain a user name or password`);
  return { label, url: u.href };
}

// The site: section; the logo is a path here and is read by loadConfigFile.
// site.url (or SITE_URL): the origin the site is served at.
function siteUrl(value, where, fail_ = fail) {
  try {
    return parseSiteUrl(value);
  } catch (err) {
    return fail_(`${where} ${err.message}`);
  }
}

function siteSettings(value) {
  if (value === undefined) return { ...NO_SITE, links: [], logoPath: null };
  if (!isMap(value)) fail('"site" must be a map');
  for (const k of Object.keys(value)) if (!SITE_KEYS.includes(k)) fail(`site has an unknown key "${String(k).slice(0, 40)}"`);
  const out = { name: null, logo: null, logoPath: null, links: [], description: null, footer: null, url: null };
  if (Object.hasOwn(value, 'url')) out.url = siteUrl(value.url, 'site.url');
  if (Object.hasOwn(value, 'name')) out.name = siteText(value.name, 'site.name', MAX_SITE_NAME);
  if (Object.hasOwn(value, 'description')) out.description = siteText(value.description, 'site.description', MAX_SITE_TEXT);
  if (Object.hasOwn(value, 'footer')) out.footer = siteText(value.footer, 'site.footer', MAX_SITE_TEXT);
  if (Object.hasOwn(value, 'logo')) out.logoPath = tokenPath(value.logo, 'site.logo');
  if (Object.hasOwn(value, 'links')) {
    if (!Array.isArray(value.links) || value.links.length > MAX_SITE_LINKS) fail(`site.links must be a list of at most ${MAX_SITE_LINKS} links`);
    out.links = value.links.map((l, i) => siteLink(l, `site.links[${i + 1}]`));
  }
  return out;
}

// Turns the text of a config file into what the monitor needs:
// {targets, statsUrls, nodes, tokens, tokenFiles}. tokens maps "host:port" to a
// token given in the file, tokenFiles to a path still to be read (see
// loadConfigFile). Tokens are kept out of nodes, which is what the monitor
// shows. nodes maps "host:port" to
// {name, proxyFor, proxiedBy, countOwn, ..., upstreams (only when the node has some)}. Throws Error on anything unexpected.
// storeUsers: whether the user store (users.json) has users of its own; they count as users here,
// for login, require_login and the default that locks every section.
export function loadConfig(text, { storeUsers = false } = {}) {
  const root = parse(text);
  if (!isMap(root)) fail('the top level must be a map with a "nodes" list');
  for (const k of Object.keys(root)) {
    if (!TOP_KEYS.includes(k)) fail(`unknown key "${String(k).slice(0, 40)}" at the top level`);
  }
  // Without users (in this file or in users.json) nothing can be locked, and the page has no login.
  const people = Object.hasOwn(root, 'users') ? users(root.users) : [];
  const hasUsers = people.length > 0 || storeUsers;
  if (!hasUsers) {
    if (Object.hasOwn(root, 'login')) fail('"login" needs "users": add at least one user (here or on the website, in users.json), or remove "login"');
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
    // Logs can hold private things: only an explicit true makes them public.
    publicLogs: flag(root.public_logs, 'public_logs', false),
    requireLogin: Object.hasOwn(root, 'require_login') ? sections(root.require_login, 'require_login') : hasUsers ? [...SECTIONS] : [],
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
    const ups = Object.hasOwn(n, 'upstreams') ? upstreams(n.upstreams, `${where}.upstreams`) : [];
    targets.push({ host: a.host, port: a.port });
    const publicDetails = flag(n.public_details, `${where}.public_details`, defaults.publicDetails);
    const publicDiskFigures = flag(n.public_disk_figures, `${where}.public_disk_figures`, defaults.publicDiskFigures);
    const publicLogs = flag(n.public_logs, `${where}.public_logs`, defaults.publicLogs);
    let requireLogin = defaults.requireLogin;
    if (Object.hasOwn(n, 'require_login')) {
      requireLogin = sections(n.require_login, `${where}.require_login`);
      if (requireLogin.length && !hasUsers) fail(`${where}.require_login needs "users": nobody could log in to see those sections`);
    }
    nodes.set(a.key, { name, proxyFor: [], proxiedBy: null, countOwn, publicDetails, publicDiskFigures, publicLogs, requireLogin, ...(ups.length ? { upstreams: ups } : {}) });
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
  const mode = Object.hasOwn(root, 'site_mode') ? siteMode(root.site_mode, 'site_mode') : 'full';
  return { targets, statsUrls, nodes, tokens, tokenFiles, defaults, users: people, login, alerts: alertSettings(root.alerts), siteMode: mode, site: siteSettings(root.site) };
}

// Reads one token file: a small file with the token and, usually, a final newline.
// The file is opened first and checked through the open handle (so it cannot be
// swapped in between), must be a regular file, and at most MAX_TOKEN_FILE_BYTES
// are read. O_NONBLOCK keeps an open of a named pipe from hanging the start.
// A file that other users can read gets a warning (never the token) in warnings.
async function readTokenFile(file, where, warnings, check = tokenValue, noun = 'token') {
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
  return check(text.trim(), `the ${noun} in ${where}`);
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

// The announce queue alert needs a node's stats, so a node without a stats_url never sends it.
export function queueWarnings(alerts, targets, statsUrls) {
  if (!alerts?.events.includes('announce_queue')) return [];
  const missing = targets.map((t) => `${t.host}:${t.port}`).filter((key) => !statsUrls.has(key));
  return missing.length ? [`warning: alerts.events has announce_queue, but ${missing.slice(0, 5).join(', ')}${missing.length > 5 ? ` and ${missing.length - 5} more` : ''} ha${missing.length === 1 ? 's' : 've'} no stats_url, so ${missing.length === 1 ? 'it' : 'they'} will never send that alert`] : [];
}

// Reads and checks the file. The size is checked before reading it. Token files
// are read now, relative to the config file's folder, and merged into tokens;
// the result has no tokenFiles left.
export async function loadConfigFile(file, { storeUsers = false } = {}) {
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
  const config = loadConfig(text, { storeUsers });
  const cache = new Map();
  config.warnings = [];
  for (const [key, p] of config.tokenFiles) {
    const full = path.resolve(path.dirname(file), p);
    if (!cache.has(full)) cache.set(full, await readTokenFile(full, 'stats_token_file', config.warnings));
    config.tokens.set(key, cache.get(full));
  }
  config.tokenFiles = new Map();
  // Alert secrets and mail passwords, read the same way and never kept next to the path.
  for (const [i, c] of (config.alerts?.channels ?? []).entries()) {
    const where = `alerts.channels[${i + 1}]`;
    if (c.secretFile !== undefined) c.secret = await readTokenFile(path.resolve(path.dirname(file), c.secretFile), `${where}.secret_file`, config.warnings, tokenValue, 'secret');
    if (c.passwordFile !== undefined) c.password = await readTokenFile(path.resolve(path.dirname(file), c.passwordFile), `${where}.password_file`, config.warnings, passwordValue, 'password');
    delete c.secretFile;
    delete c.passwordFile;
  }
  if (config.site.logoPath !== null) {
    try {
      config.site.logo = await readLogo(resolveLogoPath(file, config.site.logoPath));
    } catch (err) {
      fail(`site.logo ${err.message}`);
    }
  }
  delete config.site.logoPath;
  config.warnings.push(...tokenWarnings(config.statsUrls, config.tokens));
  for (const [key, info] of config.nodes) if (info.publicLogs) config.warnings.push(`warning: ${key} has public_logs: true, so anyone can read its recent log lines`);
  config.warnings.push(...queueWarnings(config.alerts, config.targets, config.statsUrls));
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
// an error, so it is never unclear which one counts. storeUsers: as for loadConfig.
export async function loadNodes(env, { storeUsers = false } = {}) {
  if (env.CONFIG_FILE) {
    if (env.STATUS_TARGETS || env.STATS_URLS || env.STATS_TOKEN || env.STATS_TOKEN_FILE || env.STATS_TOKEN_FILES || env.PUBLIC_DETAILS || env.PUBLIC_DISK_FIGURES || env.SITE_MODE || env.SITE_URL || env.LOGIN_TRUSTED_PROXIES) {
      throw new Error('CONFIG_FILE replaces STATUS_TARGETS, STATS_URLS, STATS_TOKEN, STATS_TOKEN_FILE, STATS_TOKEN_FILES, PUBLIC_DETAILS, PUBLIC_DISK_FIGURES, SITE_MODE, SITE_URL and LOGIN_TRUSTED_PROXIES: set either the file or the variables, not both (in the file, LOGIN_TRUSTED_PROXIES is login.trusted_proxies)');
    }
    return loadConfigFile(env.CONFIG_FILE, { storeUsers });
  }
  if (env.SITE_MODE === '') throw new Error('SITE_MODE is empty: set it to full or status, or remove it');
  const mode = env.SITE_MODE === undefined ? 'full' : siteMode(env.SITE_MODE, 'SITE_MODE', (m) => { throw new Error(m); });
  if (env.SITE_URL === '') throw new Error('SITE_URL is empty: set it to the https address of the site, like https://example.org, or remove it');
  const url = env.SITE_URL === undefined ? null : siteUrl(env.SITE_URL, 'SITE_URL', (m) => { throw new Error(m); });
  const defaults = { publicDetails: envFlag(env.PUBLIC_DETAILS, 'PUBLIC_DETAILS', true), publicDiskFigures: envFlag(env.PUBLIC_DISK_FIGURES, 'PUBLIC_DISK_FIGURES', false) };
  const proxies = env.LOGIN_TRUSTED_PROXIES === undefined ? [] : parseTrustedProxiesEnv(env.LOGIN_TRUSTED_PROXIES);
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
  if (proxies.length > 0 && !storeUsers) warnings.push('warning: LOGIN_TRUSTED_PROXIES is set, but users.json has no users, so nobody can sign in and it is not used yet');
  // Users in the config file need the config file; with the variables only users.json can have
  // users, and then every section is locked, as with users in a config file.
  return { targets, statsUrls, nodes: new Map(), tokens, tokenFiles: new Map(), warnings, defaults: { ...defaults, publicLogs: false, requireLogin: storeUsers ? [...SECTIONS] : [] }, users: [], login: { ...LOGIN_DEFAULTS, trustedProxies: proxies }, alerts: null, siteMode: mode, site: { ...NO_SITE, links: [], url } };
}
