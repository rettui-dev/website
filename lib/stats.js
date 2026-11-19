// Optional per-node stats: fetched from a node's stats.json and cleaned up
// into a fixed shape. Everything a node sends is untrusted.

import { PEERS_MAX_BYTES, sanitizePeers, tokenAllowedFor, validToken } from './peers.js';
import { INVISIBLE_RE, sanitizeDisk, sanitizePropagation, summarizePropagationPeers } from './propagation.js';

export const STATS_TIMEOUT_MS = 5000;
export const STATS_MAX_BYTES = 64 * 1024;
const MAX_VERSION = 32;

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

// Loopback and private-range hosts, the only ones allowed over plain http.
export function isPrivateHost(hostname) {
  const h = hostname.toLowerCase();
  if (h === 'localhost' || h === '[::1]') return true;
  const m = /^(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}$/.exec(h);
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}

class Invalid extends Error {}

// A finite, non-negative whole number no larger than the safe maximum.
function count(v) {
  if (typeof v !== 'number' || !Number.isFinite(v)) throw new Invalid('not a number');
  return Math.min(Math.max(Math.trunc(v), 0), Number.MAX_SAFE_INTEGER);
}

function countOrNull(v) {
  return v === null || v === undefined ? null : count(v);
}

function text(v, max) {
  if (typeof v !== 'string') return null;
  // Control, bidirectional and zero-width characters out, then cut to length.
  return v.replace(INVISIBLE_RE, '').slice(0, max);
}

function object(v) {
  if (!v || typeof v !== 'object' || Array.isArray(v)) throw new Invalid('not an object');
  return v;
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
  return out;
}

// Reads a body of at most maxBytes, and stops reading at the limit.
async function readLimited(res, maxBytes) {
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
    if (token !== undefined) {
      const peers = sanitizePeers(parsed);
      if (peers) out.peers = peers;
      const propagationPeers = summarizePropagationPeers(parsed);
      if (propagationPeers) out.propagationPeers = propagationPeers;
    }
    return out;
  } catch {
    return { ok: false, error: 'invalid' };
  }
}
