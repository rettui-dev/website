// Probes the monitored hosts and keeps their check history.
import net from 'node:net';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fetchStats } from './stats.js';

// The Reticulum entry points shown on the status page. STATUS_TARGETS
// (comma separated host:port) replaces this list.
export const DEFAULT_TARGETS = [
  'rns.rettui.dev:4242',
  'front.rns.rettui.dev:4242',
  'back.rns.rettui.dev:4242',
  'side.rns.rettui.dev:4242',
];

export const PROBE_TIMEOUT_MS = 5000;
export const PROBE_INTERVAL_MS = 30_000;
// 2880 checks at 30 seconds is the last 24 hours.
export const MAX_HISTORY = 2880;
// Stats older than this many intervals are marked stale.
export const STATS_STALE_INTERVALS = 3;

const HOST_RE = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/i;

// Turns "host:port,host:port" into [{host, port}]. Throws on bad input, so a
// typo in the environment stops the server at start instead of being probed.
export function parseTargets(list) {
  const items = String(list)
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  if (items.length === 0) throw new Error('STATUS_TARGETS has no hosts');
  const seen = new Set();
  const targets = [];
  for (const item of items) {
    const i = item.lastIndexOf(':');
    const host = i > 0 ? item.slice(0, i).toLowerCase() : '';
    const portText = i > 0 ? item.slice(i + 1) : '';
    const port = /^\d{1,5}$/.test(portText) ? Number(portText) : 0;
    if (!HOST_RE.test(host) || port < 1 || port > 65535) {
      throw new Error(`STATUS_TARGETS: "${item}" is not a host:port`);
    }
    const key = `${host}:${port}`;
    if (seen.has(key)) continue;
    seen.add(key);
    targets.push({ host, port });
  }
  return targets;
}

// Tries one TCP connection. Always resolves: {up, ms, error}.
export function probe(host, port, timeoutMs = PROBE_TIMEOUT_MS) {
  return new Promise((resolve) => {
    const started = performance.now();
    let done = false;
    const socket = net.connect({ host, port });
    const finish = (up, error) => {
      if (done) return;
      done = true;
      socket.destroy();
      resolve({ up, ms: Math.round(performance.now() - started), error });
    };
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => finish(true));
    socket.once('timeout', () => finish(false, 'timeout'));
    socket.once('error', (err) => finish(false, err.code ?? 'error'));
  });
}

// A saved check is [time in ms, 1 or 0, connect ms].
function validEntry(e) {
  return (
    Array.isArray(e) &&
    e.length === 3 &&
    Number.isFinite(e[0]) &&
    (e[1] === 0 || e[1] === 1) &&
    Number.isFinite(e[2])
  );
}

export class Monitor {
  constructor({ targets, dataDir, maxHistory = MAX_HISTORY, probeFn = probe, now = Date.now, statsUrls = new Map(), statsFn = fetchStats }) {
    this.targets = targets;
    this.file = path.join(dataDir, 'history.json');
    this.dataDir = dataDir;
    this.maxHistory = maxHistory;
    this.probeFn = probeFn;
    this.now = now;
    this.statsUrls = statsUrls;
    this.statsFn = statsFn;
    // Node stats are kept in memory only and never saved with the history.
    this.stats = new Map();
    this.history = new Map(targets.map((t) => [`${t.host}:${t.port}`, []]));
    this.lastError = new Map();
    this.timer = null;
    this.saving = Promise.resolve();
  }

  // Reads saved history. A missing or damaged file just means starting empty.
  async load() {
    let data;
    try {
      data = JSON.parse(await fs.readFile(this.file, 'utf8'));
    } catch {
      return;
    }
    if (!data || typeof data !== 'object' || typeof data.hosts !== 'object' || data.hosts === null) return;
    for (const key of this.history.keys()) {
      const saved = data.hosts[key];
      if (Array.isArray(saved)) this.history.set(key, saved.filter(validEntry).slice(-this.maxHistory));
    }
  }

  // Writes to a temporary file and renames it, so a crash never leaves half a file.
  save() {
    this.saving = this.saving.then(async () => {
      const hosts = Object.fromEntries(this.history);
      const tmp = `${this.file}.${process.pid}.tmp`;
      try {
        await fs.mkdir(this.dataDir, { recursive: true });
        await fs.writeFile(tmp, JSON.stringify({ version: 1, hosts }), { mode: 0o600 });
        await fs.rename(tmp, this.file);
      } catch (err) {
        console.error(`could not save history: ${err.message}`);
        await fs.rm(tmp, { force: true }).catch(() => {});
      }
    });
    return this.saving;
  }

  // Fetches the stats of every host that has a stats URL. Each failure stays
  // its own: the last good stats are kept, with the error of the latest try.
  async fetchStatsAll() {
    await Promise.all(
      [...this.statsUrls].map(async ([key, url]) => {
        let r;
        try {
          r = await this.statsFn(url);
        } catch {
          r = { ok: false, error: 'network' };
        }
        const prev = this.stats.get(key);
        if (r.ok) this.stats.set(key, { data: r.data, fetchedAt: this.now(), error: null });
        else this.stats.set(key, { data: prev?.data ?? null, fetchedAt: prev?.fetchedAt ?? null, error: r.error ?? 'error' });
      }),
    );
  }

  // Probes every host once, in parallel, and records the results. The stats
  // are fetched at the same time and cannot hold up or fail a probe.
  async checkAll() {
    const [results] = await Promise.all([
      Promise.all(
        this.targets.map(async (t) => {
          try {
            return await this.probeFn(t.host, t.port);
          } catch (err) {
            return { up: false, ms: 0, error: String(err?.code ?? 'error') };
          }
        }),
      ),
      this.fetchStatsAll(),
    ]);
    const time = this.now();
    this.targets.forEach((t, i) => {
      const key = `${t.host}:${t.port}`;
      const r = results[i];
      const list = this.history.get(key);
      list.push([time, r.up ? 1 : 0, r.up ? r.ms : 0]);
      if (list.length > this.maxHistory) list.splice(0, list.length - this.maxHistory);
      this.lastError.set(key, r.up ? null : (r.error ?? 'error'));
    });
    this.lastCheck = time;
    await this.save();
  }

  // Checks now, then again every interval, never two at once.
  start(intervalMs = PROBE_INTERVAL_MS) {
    const tick = async () => {
      try {
        await this.checkAll();
      } catch (err) {
        console.error(`check failed: ${err.message}`);
      }
      if (this.timer !== 'stopped') this.timer = setTimeout(tick, intervalMs);
    };
    this.timer = setTimeout(tick, 0);
  }

  stop() {
    if (this.timer && this.timer !== 'stopped') clearTimeout(this.timer);
    this.timer = 'stopped';
  }

  // The stats of one host: null when it has no stats URL.
  statsFor(key) {
    if (!this.statsUrls.has(key)) return null;
    const s = this.stats.get(key);
    if (!s) return { ok: false, fetchedAt: null, stale: false, error: 'not fetched yet' };
    const stale = s.data !== null && this.now() - s.fetchedAt > STATS_STALE_INTERVALS * PROBE_INTERVAL_MS;
    const out = { ok: s.error === null, fetchedAt: s.fetchedAt === null ? null : new Date(s.fetchedAt).toISOString(), stale };
    if (s.error !== null) out.error = s.error;
    if (s.data !== null) out.data = s.data;
    return out;
  }

  // The JSON the status page shows.
  snapshot(barLength = 90) {
    const hosts = this.targets.map((t) => {
      const key = `${t.host}:${t.port}`;
      const list = this.history.get(key);
      const last = list.at(-1);
      const upCount = list.reduce((n, e) => n + e[1], 0);
      return {
        host: t.host,
        port: t.port,
        status: last ? (last[1] ? 'up' : 'down') : 'unknown',
        latencyMs: last && last[1] ? last[2] : null,
        error: last && !last[1] ? (this.lastError.get(key) ?? null) : null,
        lastChecked: last ? new Date(last[0]).toISOString() : null,
        uptimePercent: list.length ? Math.round((upCount / list.length) * 1000) / 10 : null,
        checks: list.length,
        history: list.slice(-barLength).map((e) => ({ t: e[0], up: e[1] === 1, ms: e[2] })),
        stats: this.statsFor(key),
      };
    });
    const known = hosts.filter((h) => h.status !== 'unknown');
    const down = known.filter((h) => h.status === 'down').length;
    let overall = 'unknown';
    if (known.length) overall = down === 0 ? 'up' : down === known.length ? 'down' : 'degraded';
    return {
      overall,
      checkedAt: this.lastCheck ? new Date(this.lastCheck).toISOString() : null,
      intervalSeconds: PROBE_INTERVAL_MS / 1000,
      hosts,
    };
  }
}
