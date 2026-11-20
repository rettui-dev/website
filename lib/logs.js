// A node's recent log lines, fetched on demand from its /logs (token only) for the
// Logs tab of the Full details. Everything the node sends is untrusted: the answer
// is cut to a fixed shape here, and the token and the node's own errors never
// leave this module.

import { tokenAllowedFor, validToken } from './peers.js';
import { cleanText } from './propagation.js';
import { STATS_TIMEOUT_MS, isPrivateHost, readLimited } from './stats.js';

export const LOG_LEVELS = ['error', 'warn', 'info', 'debug', 'trace'];
// What may be asked for: the node caps at debug, and trace is refused here already.
export const ASK_LEVELS = LOG_LEVELS.filter((l) => l !== 'trace');
export const DEFAULT_LEVEL = 'info';
export const DEFAULT_LINES = 200;
export const MAX_LINES = 500;
export const MAX_LINE_CHARS = 1000;
const MAX_TIME_CHARS = 40;
export const LOGS_MAX_BYTES = 1024 * 1024;
// An answer is kept this long, and shared by everybody who asks the same question (node, lines and level).
export const LOGS_MIN_INTERVAL_MS = 5000;
// One viewer may start a new question for a node (one that is not kept) this often.
export const LOGS_VIEWER_INTERVAL_MS = LOGS_MIN_INTERVAL_MS;
// Across all viewers, a node is asked this often at most; fetches wait their turn, at most
// LOGS_NODE_QUEUE of them, and a viewer past that is told to wait.
export const LOGS_NODE_INTERVAL_MS = 2000;
export const LOGS_NODE_QUEUE = 4;
// The most answers and viewers remembered at once, so the memory stays bounded.
export const LOGS_MAX_ENTRIES = 200;
export const LOGS_MAX_VIEWERS = 1000;

// The query of /api/logs: {lines, level}, or {error} with words for the visitor.
// Both are optional; anything else (a repeated, empty or out of range value) is refused.
export function parseLogsQuery(params) {
  const one = (name) => {
    const all = params.getAll(name);
    return all.length === 0 ? null : all.length === 1 ? all[0] : false;
  };
  const rawLines = one('lines');
  const rawLevel = one('level');
  let lines = DEFAULT_LINES;
  if (rawLines === false || (rawLines !== null && !/^[0-9]{1,4}$/.test(rawLines))) return { error: `lines must be a number from 1 to ${MAX_LINES}` };
  if (rawLines !== null) {
    lines = Number(rawLines);
    if (lines < 1 || lines > MAX_LINES) return { error: `lines must be a number from 1 to ${MAX_LINES}` };
  }
  if (rawLevel === false || (rawLevel !== null && !ASK_LEVELS.includes(rawLevel))) return { error: `level must be one of ${ASK_LEVELS.join(', ')}` };
  return { lines, level: rawLevel ?? DEFAULT_LEVEL };
}

// The node's answer cleaned up, or null when it is not a log answer. Lines that
// are not text are dropped; at most `lines` are kept (the newest, as the list is
// oldest first) and the answer says when any were left out.
export function sanitizeLogs(raw, { lines = MAX_LINES, level = DEFAULT_LEVEL } = {}) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw) || !Array.isArray(raw.lines)) return null;
  const limit = Math.min(Math.max(1, lines), MAX_LINES);
  const kept = [];
  // Only the tail can be shown, so only the tail is looked at.
  const list = raw.lines.length > limit * 2 ? raw.lines.slice(-limit * 2) : raw.lines;
  for (const e of list) {
    if (!e || typeof e !== 'object' || Array.isArray(e) || typeof e.text !== 'string') continue;
    // A tab or line break would run words together once the control characters go.
    const text = cleanText(e.text.replace(/[\t\r\n]+/g, ' ').slice(0, MAX_LINE_CHARS * 2), MAX_LINE_CHARS);
    if (!text) continue;
    kept.push({
      time: cleanText(e.time, MAX_TIME_CHARS) || null,
      level: typeof e.level === 'string' && LOG_LEVELS.includes(e.level) ? e.level : null,
      text,
    });
  }
  const shown = kept.length > limit ? kept.slice(-limit) : kept;
  return {
    level: typeof raw.level === 'string' && LOG_LEVELS.includes(raw.level) ? raw.level : level,
    truncated: raw.truncated === true || raw.lines.length > limit,
    lines: shown,
  };
}

// Asks the node for its log lines. Always resolves: {ok: true, data} or {ok: false,
// error} with a short code (not-found, rejected, unavailable, invalid, too-large,
// timeout, network, token), never text from the node. The token goes in a header,
// only over https or to a private address, and appears in no result.
export async function fetchLogs(statsUrl, { token, lines = DEFAULT_LINES, level = DEFAULT_LEVEL, fetchFn = fetch, timeoutMs = STATS_TIMEOUT_MS } = {}) {
  if (!validToken(token) || !tokenAllowedFor(statsUrl, isPrivateHost)) return { ok: false, error: 'token' };
  let url;
  try {
    url = new URL('/logs', statsUrl);
  } catch {
    return { ok: false, error: 'unavailable' };
  }
  url.searchParams.set('lines', String(lines));
  url.searchParams.set('level', level);
  let body;
  try {
    const res = await fetchFn(url.href, { redirect: 'error', signal: AbortSignal.timeout(timeoutMs), headers: { Accept: 'application/json', Authorization: `Bearer ${token}` } });
    if (!res.ok) {
      await res.body?.cancel().catch(() => {});
      return { ok: false, error: res.status === 404 ? 'not-found' : res.status === 400 ? 'rejected' : 'unavailable' };
    }
    body = await readLimited(res, LOGS_MAX_BYTES);
  } catch (err) {
    return { ok: false, error: err?.name === 'TimeoutError' || err?.name === 'AbortError' ? 'timeout' : 'network' };
  }
  if (body === null) return { ok: false, error: 'too-large' };
  let parsed;
  try {
    parsed = JSON.parse(body);
  } catch {
    return { ok: false, error: 'invalid' };
  }
  const data = sanitizeLogs(parsed, { lines, level });
  return data ? { ok: true, data } : { ok: false, error: 'invalid' };
}

// Keeps the answers to log questions for LOGS_MIN_INTERVAL_MS, one for each node, lines and level, so
// the same question from any viewer is one fetch (a failure is kept too, so a node that is down is
// not asked again at once). A new question costs an upstream fetch, and is limited twice:
// - for each viewer and node, one new question every LOGS_VIEWER_INTERVAL_MS, so that one viewer
//   asking something different every few seconds cannot use up what the others may have;
// - for each node, one fetch every LOGS_NODE_INTERVAL_MS whoever asks. Fetches that come sooner wait
//   their turn (up to LOGS_NODE_QUEUE); only past that is a viewer told to wait.
// A viewer is a login name, or an address when nobody is logged in. In memory, and bounded.
export class LogsCache {
  constructor({ now = Date.now, intervalMs = LOGS_MIN_INTERVAL_MS, viewerIntervalMs = LOGS_VIEWER_INTERVAL_MS, nodeIntervalMs = LOGS_NODE_INTERVAL_MS, queue = LOGS_NODE_QUEUE, maxEntries = LOGS_MAX_ENTRIES, maxViewers = LOGS_MAX_VIEWERS, sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)) } = {}) {
    Object.assign(this, { now, intervalMs, viewerIntervalMs, nodeIntervalMs, queue, maxEntries, maxViewers, sleep });
    this.entries = new Map();
    // Viewer and node -> when this viewer last started a new question; node -> when its next fetch may start.
    this.viewers = new Map();
    this.nodes = new Map();
  }

  // fetcher() resolves to {ok, data} or {ok: false, error}. Resolves to the same
  // plus fetchedAt (ms), or {ok: false, error: 'rate', retryAfter} (seconds).
  async get(node, { lines, level }, fetcher, viewer = '') {
    const at = this.now();
    const key = `${node}\n${lines}\n${level}`;
    const hit = this.entries.get(key);
    if (hit && at >= hit.made && at < hit.until) return hit.pending;
    const rate = (ms) => ({ ok: false, error: 'rate', retryAfter: Math.max(1, Math.ceil(ms / 1000)) });
    const viewerKey = `${viewer}\n${node}`;
    const last = this.viewers.get(viewerKey);
    if (last !== undefined && at >= last && at - last < this.viewerIntervalMs) return rate(this.viewerIntervalMs - (at - last));
    // The next free turn for this node (only configured nodes get here, so this map is small).
    const turn = this.nodes.get(node);
    // A clock that went backwards since the last fetch starts the node afresh.
    const free = turn !== undefined && at >= turn.seen ? turn.next : at;
    const room = this.queue * this.nodeIntervalMs;
    if (free - at > room) return rate(free - at - room);
    const start = Math.max(free, at);
    this.nodes.set(node, { next: start + this.nodeIntervalMs, seen: at });
    this.remember(this.viewers, viewerKey, at, this.maxViewers, (v) => at - v >= this.viewerIntervalMs || at < v);
    const run = async () => {
      if (start > at) await this.sleep(start - at);
      return fetcher();
    };
    const pending = Promise.resolve()
      .then(run)
      .then((r) => ({ ...r, fetchedAt: start }), () => ({ ok: false, error: 'unavailable', fetchedAt: start }));
    this.remember(this.entries, key, { made: at, until: start + this.intervalMs, pending }, this.maxEntries, (e) => at >= e.until || at < e.made);
    return pending;
  }

  // Sets a map entry as the newest. At the limit the entries that are over go first, then the oldest.
  remember(map, key, value, max, over) {
    map.delete(key);
    if (map.size >= max) {
      for (const [k, v] of map) if (over(v)) map.delete(k);
    }
    while (map.size >= max) map.delete(map.keys().next().value);
    map.set(key, value);
  }
}
