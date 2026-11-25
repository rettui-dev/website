// Optional per-node stats: fetched from a node's stats.json and cleaned up
// into a fixed shape. Everything a node sends is untrusted.

import net from 'node:net';
import { PEERS_MAX_BYTES, sanitizePeers, tokenAllowedFor, validToken } from './peers.js';
import { INVISIBLE_RE, sanitizeDisk, sanitizePropagation, sanitizePropagationPeerRows, summarizePropagationPeers } from './propagation.js';

export const STATS_TIMEOUT_MS = 5000;
export const STATS_MAX_BYTES = 64 * 1024;
const MAX_VERSION = 32;
// The optional list of a node's interfaces: at most this many rows, names at most this long.
export const MAX_INTERFACE_ROWS = 32;
export const MAX_INTERFACE_NAME = 64;

// Turns "host:port=https://url,..." into a Map of "host:port" to URL. Throws on
// bad input, like parseTargets, and only accepts hosts that are monitored.
export function parseStatsUrls(list, targets) {
  const map = new Map();
  const known = new Set(targets.map((t) => `${t.host}:${t.port}`));
  const items = String(list ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  items.forEach((item, n) => {
    const i = item.indexOf('=');
    const key = i > 0 ? item.slice(0, i).trim().toLowerCase() : '';
    const raw = i > 0 ? item.slice(i + 1).trim() : '';
    // Errors never repeat the entry: the URL could carry a token.
    const label = known.has(key) ? `"${key}"` : `entry ${n + 1}`;
    let url = null;
    try {
      url = new URL(raw);
    } catch {
      // reported below
    }
    if (!url || (url.protocol !== 'http:' && url.protocol !== 'https:') || !url.hostname || url.username || url.password) {
      throw new Error(`STATS_URLS: ${label} is not host:port=http(s)://url (invalid URL)`);
    }
    if (!known.has(key)) throw new Error(`STATS_URLS: ${label} is not one of the monitored hosts`);
    if (url.protocol === 'http:' && !isPrivateHost(url.hostname)) {
      throw new Error(`STATS_URLS: ${label} uses plain http, which is only allowed for loopback and private addresses; use https`);
    }
    if (map.has(key)) throw new Error(`STATS_URLS: ${label} is listed twice`);
    map.set(key, url.href);
  });
  return map;
}

// Plain http is allowed only to private networks. Two lists:
// - for stats (stats_url, and the stats token that goes with it): loopback and RFC 1918;
// - for a node's manage listener (manage_url): the node's own rule for --manage-listen, which adds
//   the shared range 100.64.0.0/10, unique local fc00::/7 (WireGuard over IPv6) and link-local
//   fe80::/10.
// An IPv6 address that holds an IPv4 one (::ffff:a.b.c.d) counts as that IPv4 address.
const STATS_NETS = new net.BlockList();
const MANAGE_NETS = new net.BlockList();
for (const [a, prefix] of [['127.0.0.0', 8], ['10.0.0.0', 8], ['172.16.0.0', 12], ['192.168.0.0', 16]]) {
  STATS_NETS.addSubnet(a, prefix, 'ipv4');
  MANAGE_NETS.addSubnet(a, prefix, 'ipv4');
}
STATS_NETS.addAddress('::1', 'ipv6');
MANAGE_NETS.addSubnet('100.64.0.0', 10, 'ipv4');
for (const [a, prefix] of [['::1', 128], ['fc00::', 7], ['fe80::', 10]]) MANAGE_NETS.addSubnet(a, prefix, 'ipv6');
const MAPPED_V4 = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/;

// Whether a URL's hostname (as new URL gives it: IPv4 in dotted decimal, IPv6 in brackets) is
// localhost or an address in list. Every other name is refused, since it could point anywhere.
function inList(hostname, list) {
  const h = String(hostname).toLowerCase();
  if (h === 'localhost') return true;
  const ip = h.startsWith('[') && h.endsWith(']') ? h.slice(1, -1) : h;
  const family = net.isIP(ip);
  if (family === 4) return list.check(ip, 'ipv4');
  if (family !== 6) return false;
  const m = MAPPED_V4.exec(ip);
  if (m) {
    const [hi, lo] = [parseInt(m[1], 16), parseInt(m[2], 16)];
    return list.check(`${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`, 'ipv4');
  }
  return list.check(ip, 'ipv6');
}

// Loopback and RFC 1918 hosts: the only ones a stats URL (and its token) may use over plain http.
export const isPrivateHost = (hostname) => inList(hostname, STATS_NETS);

// The hosts a manage_url may use over plain http: those the node's manage listener may bind to.
export const isManageHost = (hostname) => inList(hostname, MANAGE_NETS);

class Invalid extends Error {}

// A finite, non-negative whole number no larger than the safe maximum.
function count(v) {
  if (typeof v !== 'number' || !Number.isFinite(v)) throw new Invalid('not a number');
  return Math.min(Math.max(Math.trunc(v), 0), Number.MAX_SAFE_INTEGER);
}

function countOrNull(v) {
  return v === null || v === undefined ? null : count(v);
}

// An optional whole number from 0 to max: anything else is ignored (null), not an error.
function boundedInt(v, max) {
  return typeof v === 'number' && Number.isInteger(v) && v >= 0 && v <= max ? v : null;
}

function text(v, max) {
  if (typeof v !== 'string') return null;
  // Control, bidirectional and zero-width characters out, then cut to length.
  return v.replace(INVISIBLE_RE, '').slice(0, max);
}

// The optional per-interface rows of a node (its interfaces.list): [{name, online, rxBytes, txBytes}],
// or null when the node sent no list (an older rettui, or the operator left it off). Rows that are not
// what the contract describes are dropped one by one, so one bad row never costs the other stats.
// These are not part of what sanitizeStats gives, because that is published; fetchStats hands them
// over on their own, and the monitor only uses them to say whether a declared upstream is online.
export function sanitizeInterfaceList(parsed) {
  const raw = parsed && typeof parsed === 'object' && parsed.interfaces && typeof parsed.interfaces === 'object' ? parsed.interfaces.list : null;
  if (!Array.isArray(raw)) return null;
  const rows = [];
  for (const row of raw.slice(0, MAX_INTERFACE_ROWS)) {
    if (!row || typeof row !== 'object' || Array.isArray(row)) continue;
    const name = text(row.name, MAX_INTERFACE_NAME)?.trim();
    if (!name || typeof row.online !== 'boolean') continue;
    try {
      rows.push({ name, online: row.online, rxBytes: count(row.rx_bytes), txBytes: count(row.tx_bytes) });
    } catch (err) {
      if (!(err instanceof Invalid)) throw err;
    }
  }
  return rows;
}

function object(v) {
  if (!v || typeof v !== 'object' || Array.isArray(v)) throw new Invalid('not an object');
  return v;
}

// Announces waiting to go out: far above what Reticulum keeps (4096 per interface) is nonsense.
export const MAX_QUEUE_COUNT = 1_000_000;

// The optional announce queue: {queued, limit, full, fullest}, or null when the node reports none
// (an older rettui, or no interface with a queue) or sends something that is not whole numbers and
// a true or false. A wrong type is ignored, never an error, so the other stats still count.
// full means one interface is at its own limit; limit is what all the queues together can hold.
export function sanitizeAnnounceQueue(raw, interfaces) {
  const q = raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : null;
  const total = interfaces && typeof interfaces === 'object' ? interfaces.announce_queue : undefined;
  const queued = boundedInt(q?.queued, MAX_QUEUE_COUNT) ?? boundedInt(total, MAX_QUEUE_COUNT);
  if (queued === null || typeof q?.full !== 'boolean') return null;
  return { queued, limit: boundedInt(q.limit, MAX_QUEUE_COUNT), full: q.full, fullest: boundedInt(q.fullest, MAX_QUEUE_COUNT) };
}

// Returns the stats in a fixed shape, with unknown keys dropped. Throws
// Invalid when the payload is not what the contract describes.
export function sanitizeStats(raw) {
  const r = object(raw);
  if (r.version !== 1) throw new Invalid('unknown version');
  const i = object(r.interfaces);
  const p = object(r.peers_heard);
  const out = {
    rettuiVersion: text(r.rettui_version, MAX_VERSION),
    generatedAt: count(r.generated_at),
    uptimeSeconds: count(r.uptime_seconds),
    interfaces: {
      total: count(i.total),
      online: count(i.online),
      clients: countOrNull(i.clients),
      rxBytes: count(i.rx_bytes),
      txBytes: count(i.tx_bytes),
    },
    peersHeard: { total: count(p.total), lxmf: count(p.lxmf), nomad: count(p.nomad), propagation: count(p.propagation) },
    announcesLastMinute: count(r.announces_last_minute),
  };
  // Optional parts, present only when the node sent something usable.
  const propagation = sanitizePropagation(r.propagation);
  if (propagation) out.propagation = propagation;
  const disk = sanitizeDisk(r.disk);
  if (disk) out.disk = disk;
  const announceQueue = sanitizeAnnounceQueue(r.announce_queue, i);
  if (announceQueue) out.announceQueue = announceQueue;
  return out;
}

// Reads a body of at most maxBytes, and stops reading at the limit.
export async function readLimited(res, maxBytes) {
  const length = Number(res.headers.get('content-length'));
  if (Number.isFinite(length) && length > maxBytes) {
    await res.body?.cancel().catch(() => {});
    return null;
  }
  if (!res.body) return '';
  const chunks = [];
  let size = 0;
  const reader = res.body.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > maxBytes) {
      await reader.cancel().catch(() => {});
      return null;
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString('utf8');
}

// Fetches and cleans one stats URL. Always resolves: {ok: true, data, peers?}
// or {ok: false, error} where error is a short code, never text from the node.
// With a token the request carries it as a bearer token and a larger answer is
// accepted; peers is then the cleaned peer list, when the node sent one. The
// token is only sent over https or to a private address, and never appears in
// a result or an error.
export async function fetchStats(url, { fetchFn = fetch, timeoutMs = STATS_TIMEOUT_MS, maxBytes, token } = {}) {
  if (token !== undefined && (!validToken(token) || !tokenAllowedFor(url, isPrivateHost))) return { ok: false, error: 'token not allowed' };
  const limit = maxBytes ?? (token === undefined ? STATS_MAX_BYTES : PEERS_MAX_BYTES);
  const headers = { Accept: 'application/json' };
  if (token !== undefined) headers.Authorization = `Bearer ${token}`;
  let body;
  try {
    const res = await fetchFn(url, { redirect: 'error', signal: AbortSignal.timeout(timeoutMs), headers });
    if (!res.ok) {
      await res.body?.cancel().catch(() => {});
      return { ok: false, error: `http ${res.status}` };
    }
    body = await readLimited(res, limit);
  } catch (err) {
    return { ok: false, error: err?.name === 'TimeoutError' || err?.name === 'AbortError' ? 'timeout' : 'network' };
  }
  if (body === null) return { ok: false, error: 'too large' };
  try {
    const parsed = JSON.parse(body);
    const out = { ok: true, data: sanitizeStats(parsed) };
    const interfaceRows = sanitizeInterfaceList(parsed);
    if (interfaceRows) out.interfaceRows = interfaceRows;
    if (token !== undefined) {
      const peers = sanitizePeers(parsed);
      if (peers) out.peers = peers;
      const propagationPeers = summarizePropagationPeers(parsed);
      if (propagationPeers) out.propagationPeers = propagationPeers;
      const peerRows = sanitizePropagationPeerRows(parsed);
      if (peerRows) out.peerRows = peerRows;
    }
    return out;
  } catch {
    return { ok: false, error: 'invalid' };
  }
}
