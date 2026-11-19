// Probes the monitored hosts and keeps their check history.
import net from 'node:net';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fetchStats } from './stats.js';
import { SAMPLE_INTERVAL_MS, MAX_SAMPLES, MAX_VERSIONS, RANGES, buildSeries, cleanSamples, cleanVersions, sampleFrom } from './history.js';

// A saved stats history larger than this is ignored, not read.
// How long a detail answer is reused at most.
const DETAIL_CACHE_MS = 30_000;

const MAX_HISTORY_FILE_BYTES = 8 * 1024 * 1024;

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
  constructor({
    targets,
    dataDir,
    maxHistory = MAX_HISTORY,
    probeFn = probe,
    now = Date.now,
    statsUrls = new Map(),
    statsFn = fetchStats,
    sampleIntervalMs = SAMPLE_INTERVAL_MS,
    maxSamples = MAX_SAMPLES,
  }) {
    this.targets = targets;
    this.file = path.join(dataDir, 'history.json');
    this.statsFile = path.join(dataDir, 'stats-history.json');
    this.sampleIntervalMs = sampleIntervalMs;
    this.maxSamples = maxSamples;
    // Per host with a stats URL: samples every few minutes and the versions
    // seen. Kept in stats-history.json, apart from the check history.
    this.statsHistory = new Map([...statsUrls.keys()].map((key) => [key, { samples: [], versions: [] }]));
    this.statsDirty = false;
    // The answers of detail(), kept until a sample or a fetch changes them.
    this.detailCache = new Map();
    this.savingStats = Promise.resolve();
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
    await this.loadStatsHistory();
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

  // Reads the saved stats history, entry by entry. A missing, oversized or
  // damaged file just means starting empty.
  async loadStatsHistory() {
    let data;
    try {
      if ((await fs.stat(this.statsFile)).size > MAX_HISTORY_FILE_BYTES) return;
      data = JSON.parse(await fs.readFile(this.statsFile, 'utf8'));
    } catch {
      return;
    }
    if (!data || typeof data !== 'object' || !data.hosts || typeof data.hosts !== 'object' || Array.isArray(data.hosts)) return;
    const now = this.now();
    for (const [key, h] of this.statsHistory) {
      const saved = Object.hasOwn(data.hosts, key) ? data.hosts[key] : null;
      if (!saved || typeof saved !== 'object') continue;
      h.samples = cleanSamples(saved.samples, now, this.maxSamples);
      h.versions = cleanVersions(saved.versions, now);
    }
  }

  // Writes to a temporary file and renames it, so a crash never leaves half a file.
  async writeJson(file, value, what) {
    const tmp = `${file}.${process.pid}.tmp`;
    try {
      await fs.mkdir(this.dataDir, { recursive: true });
      // A stale temporary file (or a link planted under that name) is removed first,
      // and 'wx' refuses to open anything that is still there.
      await fs.rm(tmp, { force: true });
      const handle = await fs.open(tmp, 'wx', 0o600);
      try {
        await handle.writeFile(JSON.stringify(value));
        await handle.sync();
      } finally {
        await handle.close();
      }
      await fs.rename(tmp, file);
    } catch (err) {
      console.error(`could not save ${what}: ${err.message}`);
      await fs.rm(tmp, { force: true }).catch(() => {});
    }
  }

  save() {
    this.saving = this.saving.then(() => this.writeJson(this.file, { version: 1, hosts: Object.fromEntries(this.history) }, 'history'));
    return this.saving;
  }

  // Saves the stats history, only when something was added since the last save.
  saveStatsHistory() {
    this.savingStats = this.savingStats.then(async () => {
      if (!this.statsDirty) return;
      this.statsDirty = false;
      const hosts = Object.fromEntries(this.statsHistory);
      await this.writeJson(this.statsFile, { version: 1, hosts }, 'stats history');
    });
    return this.savingStats;
  }

  // Notes the version a node runs and takes a sample when the last one is old
  // enough (a little under the interval, so a slow cycle does not skip one).
  recordStats(key, data, time) {
    const h = this.statsHistory.get(key);
    if (!h) return;
    this.detailCache.clear();
    const version = data.rettuiVersion;
    if (version && h.versions.at(-1)?.[0] !== version) {
      h.versions.push([version, time]);
      if (h.versions.length > MAX_VERSIONS) h.versions.splice(0, h.versions.length - MAX_VERSIONS);
      this.statsDirty = true;
    }
    const last = h.samples.at(-1);
    if (last && (time <= last[0] || time - last[0] < this.sampleIntervalMs - Math.min(PROBE_INTERVAL_MS / 2, this.sampleIntervalMs / 10))) return;
    h.samples.push(sampleFrom(time, data));
    if (h.samples.length > this.maxSamples) h.samples.splice(0, h.samples.length - this.maxSamples);
    this.statsDirty = true;
  }

  // Fetches the stats of every host that has a stats URL. Each failure stays
  // its own: the last good stats are kept, with the error of the latest try.
  async fetchStatsAll() {
    const fetched = [];
    await Promise.all(
      [...this.statsUrls].map(async ([key, url]) => {
        let r;
        try {
          r = await this.statsFn(url);
        } catch {
          r = { ok: false, error: 'network' };
        }
        const prev = this.stats.get(key);
        if (r.ok) {
          const fetchedAt = this.now();
          this.stats.set(key, { data: r.data, fetchedAt, error: null });
          fetched.push([key, r.data, fetchedAt]);
        } else this.stats.set(key, { data: prev?.data ?? null, fetchedAt: prev?.fetchedAt ?? null, error: r.error ?? 'error' });
      }),
    );
    this.detailCache.clear();
    // Only a fetch that worked is sampled.
    for (const [key, data, time] of fetched) this.recordStats(key, data, time);
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
    await Promise.all([this.save(), this.saveStatsHistory()]);
  }

  // Everything the detail view of one host shows, or null when the host has no
  // stats URL. range is a key of RANGES. Never throws: if the saved data turns
  // out to be unusable the graphs are empty.
  buildDetail(key, range) {
    const h = this.statsHistory.get(key);
    const now = this.now();
    const iso = (t) => (Number.isFinite(t) && Math.abs(t) <= 8.64e15 ? new Date(t).toISOString() : null);
    const stats = this.statsFor(key);
    let series;
    try {
      series = buildSeries(h.samples, range, now);
    } catch (err) {
      console.error(`could not build stats series: ${err.message}`);
      series = buildSeries([], range, now);
    }
    return {
      host: key,
      range,
      generatedAt: iso(now),
      sampleIntervalSeconds: Math.round(this.sampleIntervalMs / 1000),
      stats,
      version: {
        current: stats?.data?.rettuiVersion ?? null,
        uptimeSeconds: stats?.data?.uptimeSeconds ?? null,
        history: h.versions.map(([version, firstSeen]) => ({ version, firstSeen: iso(firstSeen) })).filter((v) => v.firstSeen !== null),
      },
      series,
    };
  }

  // The same, kept for up to 30 seconds and until the next fetch or sample.
  cachedDetail(key, range) {
    if (!this.statsHistory.has(key) || !Object.hasOwn(RANGES, range)) return null;
    const id = `${key}|${range}`;
    const now = this.now();
    const hit = this.detailCache.get(id);
    if (hit && now - hit.at >= 0 && now - hit.at < DETAIL_CACHE_MS) return hit;
    const value = this.buildDetail(key, range);
    const entry = { at: now, value, json: JSON.stringify(value) };
    this.detailCache.set(id, entry);
    return entry;
  }

  detail(key, range) {
    return this.cachedDetail(key, range)?.value ?? null;
  }

  detailJson(key, range) {
    return this.cachedDetail(key, range)?.json ?? null;
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
        hasDetail: this.statsUrls.has(key),
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
