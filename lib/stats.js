// Optional per-node stats: fetched from a node's stats.json and cleaned up
// into a fixed shape. Everything a node sends is untrusted.

export const STATS_TIMEOUT_MS = 5000;
export const STATS_MAX_BYTES = 64 * 1024;
export const MAX_INTERFACES = 32;
const MAX_NAME = 64;
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
  for (const item of items) {
    const i = item.indexOf('=');
    const key = i > 0 ? item.slice(0, i).trim().toLowerCase() : '';
    const text = i > 0 ? item.slice(i + 1).trim() : '';
    let url = null;
    try {
      url = new URL(text);
    } catch {
      // reported below
    }
    if (!url || (url.protocol !== 'http:' && url.protocol !== 'https:') || !url.hostname || url.username || url.password) {
      throw new Error(`STATS_URLS: "${item}" is not host:port=http(s)://url`);
    }
    if (!known.has(key)) throw new Error(`STATS_URLS: "${key}" is not one of the monitored hosts`);
    if (map.has(key)) throw new Error(`STATS_URLS: "${key}" is listed twice`);
    map.set(key, url.href);
  }
  return map;
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
  // Control characters out, then cut to length.
  return v.replace(/[\u0000-\u001f\u007f-\u009f]/g, '').slice(0, max);
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
  if (!Array.isArray(i.list)) throw new Invalid('no interface list');
  const list = i.list.slice(0, MAX_INTERFACES).map((e) => {
    const x = object(e);
    return {
      name: text(x.name, MAX_NAME) ?? '',
      online: x.online === true,
      clients: countOrNull(x.clients),
      rxBytes: count(x.rx_bytes),
      txBytes: count(x.tx_bytes),
    };
  });
  return {
    rettuiVersion: text(r.rettui_version, MAX_VERSION),
    generatedAt: count(r.generated_at),
    uptimeSeconds: count(r.uptime_seconds),
    interfaces: {
      total: count(i.total),
      online: count(i.online),
      clients: countOrNull(i.clients),
      rxBytes: count(i.rx_bytes),
      txBytes: count(i.tx_bytes),
      list,
    },
    peersHeard: { total: count(p.total), lxmf: count(p.lxmf), nomad: count(p.nomad), propagation: count(p.propagation) },
    announcesLastMinute: count(r.announces_last_minute),
  };
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

// Fetches and cleans one stats URL. Always resolves: {ok: true, data} or
// {ok: false, error} where error is a short code, never text from the node.
export async function fetchStats(url, { fetchFn = fetch, timeoutMs = STATS_TIMEOUT_MS, maxBytes = STATS_MAX_BYTES } = {}) {
  let body;
  try {
    const res = await fetchFn(url, {
      redirect: 'error',
      signal: AbortSignal.timeout(timeoutMs),
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) {
      await res.body?.cancel().catch(() => {});
      return { ok: false, error: `http ${res.status}` };
    }
    body = await readLimited(res, maxBytes);
  } catch (err) {
    return { ok: false, error: err?.name === 'TimeoutError' || err?.name === 'AbortError' ? 'timeout' : 'network' };
  }
  if (body === null) return { ok: false, error: 'too large' };
  try {
    return { ok: true, data: sanitizeStats(JSON.parse(body)) };
  } catch {
    return { ok: false, error: 'invalid' };
  }
}
