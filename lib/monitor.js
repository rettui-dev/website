// Probes the monitored hosts and keeps their check history.
import net from 'node:net';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fetchStats, isPrivateHost } from './stats.js';
import { LogsCache, fetchLogs } from './logs.js';
import { tokenAllowedFor, validToken } from './peers.js';
import { aggregateGroup } from './group.js';
import { unionPeers } from './peers.js';
import { stripGroup, stripSeries, stripStats, union } from './access.js';
import { UptimeLog, SHOWN_DAYS } from './uptime.js';
import { buildLinks } from './links.js';
import { SAMPLE_INTERVAL_MS, MAX_SAMPLES, MAX_VERSIONS, RANGES, buildSeries, combineSeries, cleanSamples, cleanExtras, extraFrom, cleanVersions, sampleFrom } from './history.js';

// A saved stats history larger than this is ignored, not read.
// Fetches that carry a token can bring a large answer (a peer list), so only this
// many run at the same time.
export const MAX_TOKEN_FETCHES = 4;

// Runs async jobs at most `limit` at a time, in the order they were asked for.
export function limiter(limit) {
  let running = 0;
  const waiting = [];
  const next = () => {
    if (running >= limit || waiting.length === 0) return;
    running++;
    const { job, resolve, reject } = waiting.shift();
    job().then(resolve, reject).finally(() => {
      running--;
      next();
    });
  };
  return (job) =>
    new Promise((resolve, reject) => {
      waiting.push({ job, resolve, reject });
      next();
    });
}

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

export const HOST_RE = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/i;

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

// How full a disk is: 'ok', 'high' (75% used or more) or 'full' (90% or more).
export function diskLevel(usedPercent) {
  return usedPercent >= 90 ? 'full' : usedPercent >= 75 ? 'high' : 'ok';
}

// The stats as they are published. The free and total space of the disk can say
// a lot about a machine, so unless the operator allows it (public_disk_figures)
// only a level and the used share rounded to 5 leave, never a byte figure of
// the file system. The data size is already public on the node.
export function publicData(data, figures) {
  if (!data.disk) return data;
  const { dataBytes, fsTotalBytes, fsFreeBytes } = data.disk;
  const used = fsTotalBytes > 0 && fsFreeBytes !== null ? Math.min(Math.max((1 - fsFreeBytes / fsTotalBytes) * 100, 0), 100) : null;
  // The level comes from the published number, so the words and the figure always agree.
  const published = used === null ? null : figures ? Math.round(used) : Math.round(used / 5) * 5;
  const disk = { dataBytes, level: published === null ? null : diskLevel(published), usedPercent: published };
  if (figures) Object.assign(disk, { fsTotalBytes, fsFreeBytes });
  return { ...data, disk };
}

export class Monitor {
  // Stats tokens, by host:port. A private field, so no dump or JSON of the monitor can show them.
  #tokens;
  // The source of detected links (a LinkWatcher), private for the same reason: it knows the hosts the
  // nodes' configs point at. None until attachLinks.
  #linkWatcher = null;

  constructor({
    targets,
    dataDir,
    maxHistory = MAX_HISTORY,
    probeFn = probe,
    now = Date.now,
    statsUrls = new Map(),
    statsFn = fetchStats,
    nodes = new Map(),
    tokens = new Map(),
    publicDetails = true,
    publicDiskFigures = false,
    publicLogs = false,
    requireLogin = [],
    sampleIntervalMs = SAMPLE_INTERVAL_MS,
    maxSamples = MAX_SAMPLES,
    alerts = null,
    logsEnabled = false,
    logsFn = fetchLogs,
  }) {
    this.targets = targets;
    this.file = path.join(dataDir, 'history.json');
    this.statsFile = path.join(dataDir, 'stats-history.json');
    this.uptimeFile = path.join(dataDir, 'uptime.json');
    // Daily uptime and incidents, for 90 days and more (see uptime.js). Only the monitored nodes have any.
    this.uptime = new UptimeLog(targets.map((t) => `${t.host}:${t.port}`), { now });
    this.savingUptime = Promise.resolve();
    // Where alerts go when a node goes down or comes back (see alerts.js); null without a config.
    this.alerts = alerts;
    // Display names and proxy settings from the config file (empty with the environment variables).
    this.nodes = nodes;
    // Defaults for nodes that have no setting of their own (always, with the environment variables).
    this.publicDetails = publicDetails;
    this.publicDiskFigures = publicDiskFigures;
    // The sections a visitor must log in to see (see access.js); empty without users.
    this.publicLogs = publicLogs;
    this.requireLogin = requireLogin;
    this.#tokens = new Map(tokens);
    // Logs are only served to a logged-in viewer, or when the node has public_logs (see logsAllowed).
    this.logsEnabled = logsEnabled;
    this.logsFn = logsFn;
    this.logsCache = new LogsCache({ now });
    // The latest peer list of each node, in memory only (see peers.js): at most 20000 entries of 17 bytes each.
    this.peerLists = new Map();
    this.peerSeq = 0;
    // What the peered propagation nodes a node listed (token only) add up to: counts only, no address or name is kept.
    this.peerSummaries = new Map();
    // The rows of those peered nodes (at most 64 each), in memory only: they go to the node's Details view and nowhere else.
    this.peerRowLists = new Map();
    this.unionCache = new Map();
    this.sampleIntervalMs = sampleIntervalMs;
    this.maxSamples = maxSamples;
    // Per host with a stats URL: samples every few minutes and the versions
    // seen. Kept in stats-history.json, apart from the check history.
    this.statsHistory = new Map([...statsUrls.keys()].map((key) => [key, { samples: [], versions: [], extra: [] }]));
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
    await this.uptime.load(this.uptimeFile);
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
      // Saved by newer versions only; an older file has none.
      h.extra = cleanExtras(saved.extra, now, this.maxSamples);
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

  // Saves the uptime and incidents, only when a check was added since the last save.
  saveUptime() {
    this.savingUptime = this.savingUptime.then(async () => {
      if (!this.uptime.dirty) return;
      this.uptime.dirty = false;
      await this.writeJson(this.uptimeFile, this.uptime, 'uptime');
    });
    return this.savingUptime;
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
    const extra = extraFrom(time, data);
    if (extra) {
      h.extra.push(extra);
      if (h.extra.length > this.maxSamples) h.extra.splice(0, h.extra.length - this.maxSamples);
    }
    this.statsDirty = true;
  }

  // Fetches the stats of every host that has a stats URL. Each failure stays
  // its own: the last good stats are kept, with the error of the latest try.
  async fetchStatsAll() {
    const fetched = [];
    const gate = limiter(MAX_TOKEN_FETCHES);
    await Promise.all(
      [...this.statsUrls].map(async ([key, url]) => {
        let r;
        try {
          const token = this.#tokens.get(key);
          r = token === undefined ? await this.statsFn(url) : await gate(() => this.statsFn(url, { token }));
        } catch {
          r = { ok: false, error: 'network' };
        }
        const prev = this.stats.get(key);
        if (r.ok) {
          const fetchedAt = this.now();
          // The interface rows (names and state only) stay out of the stats that are published.
          const rows = r.interfaceRows ? r.interfaceRows.map((x) => ({ key: x.name.trim().toLowerCase(), online: x.online === true })) : null;
          this.stats.set(key, { data: r.data, rows, fetchedAt, error: null });
          // A fetch without a list drops the old one: it would no longer match the stats.
          if (r.peers && this.#tokens.has(key)) this.peerLists.set(key, { ...r.peers, id: ++this.peerSeq });
          else this.peerLists.delete(key);
          if (r.propagationPeers && this.#tokens.has(key)) {
            const { listed, alive, static: fixed, unhandled, truncated } = r.propagationPeers;
            this.peerSummaries.set(key, { listed, alive, static: fixed, unhandled, truncated });
          } else this.peerSummaries.delete(key);
          if (r.peerRows && this.#tokens.has(key)) this.peerRowLists.set(key, r.peerRows);
          else this.peerRowLists.delete(key);
          fetched.push([key, r.data, fetchedAt]);
          // A node that reports no announce queue (an older rettui) is never watched.
          if (r.data.announceQueue) this.alert((a) => a.observeQueue(key, r.data.announceQueue, fetchedAt));
          else this.alert((a) => a.queueMissed(key));
        } else {
          this.alert((a) => a.queueMissed(key));
          this.stats.set(key, { data: prev?.data ?? null, rows: prev?.rows ?? null, fetchedAt: prev?.fetchedAt ?? null, error: r.error ?? 'error' });
        }
      }),
    );
    this.detailCache.clear();
    // Only a fetch that worked is sampled.
    for (const [key, data, time] of fetched) this.recordStats(key, data, time);
    this.refreshUnions();
  }

  // Works out the exact peer union of every proxy group now, once the lists are in,
  // so that no request has to. checkAll runs it again after the probes, because
  // which members count depends on them.
  refreshUnions() {
    for (const [key, info] of this.nodes) if (info.proxyFor.length) this.groupFor(key, true);
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
      for (const event of this.uptime.record(key, r.up, time)) this.alert((a) => a.notify(event));
    });
    this.alert((a) => a.remind(this.uptime.openIncidents(), time));
    this.lastCheck = time;
    this.refreshUnions();
    await Promise.all([this.save(), this.saveStatsHistory(), this.saveUptime()]);
  }

  // Hands something to the alerts. A problem there never reaches the checks.
  alert(fn) {
    if (!this.alerts) return;
    try {
      fn(this.alerts);
    } catch (err) {
      console.error(`alert failed: ${err?.name ?? 'error'}`);
    }
  }

  // The newest incidents of all nodes, newest first, with the node's name. Up and down is public, so is this.
  incidentList(limit = 100) {
    return this.uptime.allIncidents(limit).map((i) => ({ ...i, name: this.nodeInfo(i.host).name }));
  }

  // Everything the detail view of one host shows, or null when the host has no
  // stats URL. range is a key of RANGES. Never throws: if the saved data turns
  // out to be unusable the graphs are empty.
  // auth: the visitor is logged in, so nothing is hidden from them.
  buildDetail(key, range, auth = false) {
    const h = this.statsHistory.get(key);
    const now = this.now();
    const iso = (t) => (Number.isFinite(t) && Math.abs(t) <= 8.64e15 ? new Date(t).toISOString() : null);
    const hidden = this.hiddenFor(key, auth);
    let stats = stripStats(this.statsFor(key), hidden);
    // The rows are only in a node's own detail answer, and go with the peers section.
    const rows = this.peerRowLists.get(key);
    if (stats && rows && !hidden.has('peers')) stats = { ...stats, peerRows: rows };
    let series;
    try {
      series = buildSeries(h.samples, range, now, undefined, h.extra);
    } catch (err) {
      console.error(`could not build stats series: ${err.message}`);
      series = buildSeries([], range, now);
    }
    // Free space history is a byte figure of the file system: only with public_disk_figures.
    if (!this.nodeInfo(key).publicDiskFigures) series.disk = null;
    const out = {
      host: key,
      range,
      generatedAt: iso(now),
      sampleIntervalSeconds: Math.round(this.sampleIntervalMs / 1000),
      stats,
      version: {
        current: stats?.data?.rettuiVersion ?? null,
        uptimeSeconds: stats?.data?.uptimeSeconds ?? null,
        history: hidden.has('versions') ? [] : h.versions.map(([version, firstSeen]) => ({ version, firstSeen: iso(firstSeen) })).filter((v) => v.firstSeen !== null),
      },
      series: stripSeries(series, hidden),
    };
    // Only said to a viewer who may read them: anyone else must not learn which nodes serve logs.
    if (this.mayReadLogs(key, auth)) out.logs = true;
    // Only with users: what the page should offer a login for.
    if (hidden.size) out.locked = [...hidden];
    return out;
  }

  // The detail of a proxy's group (view "combined"): the members' history added
  // together, with the group's latest numbers and what each member runs. Members
  // without a stats URL have no history and are listed in `excluded`.
  buildCombined(key, range, auth = false) {
    const info = this.nodeInfo(key);
    // A node that keeps its details private, or behind a login the visitor does
    // not have, is not part of the combined graphs either.
    const visible = (k) => this.nodeInfo(k).publicDetails && !this.hiddenFor(k, auth).has('details');
    const keys = (info.countOwn ? [key, ...info.proxyFor] : info.proxyFor).filter(visible);
    const hidden = union([key, ...keys].map((k) => this.hiddenFor(k, auth)));
    const withHistory = keys.filter((k) => this.statsHistory.has(k));
    const now = this.now();
    let series;
    try {
      series = combineSeries(withHistory.map((k) => this.statsHistory.get(k).samples), range, now, this.sampleIntervalMs, undefined, withHistory.map((k) => this.statsHistory.get(k).extra));
    } catch (err) {
      console.error(`could not combine stats series: ${err.message}`);
      series = combineSeries([], range, now, this.sampleIntervalMs);
    }
    if (!keys.every((k) => this.nodeInfo(k).publicDiskFigures)) series.disk = null;
    const out = {
      host: key,
      range,
      view: 'combined',
      generatedAt: new Date(now).toISOString(),
      sampleIntervalSeconds: Math.round(this.sampleIntervalMs / 1000),
      group: stripGroup(this.groupFor(key, false, visible), hidden),
      members: keys.map((k) => {
        const s = this.statsFor(k);
        const version = this.hiddenFor(k, auth).has('versions') ? null : (s?.data?.rettuiVersion ?? null);
        return { host: k, name: this.nodeInfo(k).name, version, uptimeSeconds: s?.data?.uptimeSeconds ?? null, hasHistory: this.statsHistory.has(k), hasLogs: this.mayReadLogs(k, auth) };
      }),
      excluded: keys.filter((k) => !this.statsHistory.has(k)),
      series: stripSeries(series, hidden),
    };
    if (hidden.size) out.locked = [...hidden];
    return out;
  }

  // The same, kept for up to 30 seconds and until the next fetch or sample.
  // A visitor who is logged in and one who is not get separate answers.
  cachedDetail(key, range, view = 'node', auth = false) {
    if (!Object.hasOwn(RANGES, range)) return null;
    if (view === 'combined' ? this.nodeInfo(key).proxyFor.length === 0 : !this.statsHistory.has(key)) return null;
    const id = `${key}|${range}|${view}|${auth ? 'login' : 'public'}`;
    const now = this.now();
    const hit = this.detailCache.get(id);
    if (hit && now - hit.at >= 0 && now - hit.at < DETAIL_CACHE_MS) return hit;
    const value = view === 'combined' ? this.buildCombined(key, range, auth) : this.buildDetail(key, range, auth);
    const entry = { at: now, value, json: JSON.stringify(value) };
    this.detailCache.set(id, entry);
    return entry;
  }

  detail(key, range, view = 'node', auth = false) {
    return this.cachedDetail(key, range, view, auth)?.value ?? null;
  }

  detailJson(key, range, view = 'node', auth = false) {
    return this.cachedDetail(key, range, view, auth)?.json ?? null;
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

  // Waits for the saves that are running, and writes what was added since: for a clean exit.
  async flush() {
    await Promise.all([this.save(), this.saveStatsHistory(), this.saveUptime()]);
  }

  // The stats of one host: null when it has no stats URL.
  statsFor(key) {
    if (!this.statsUrls.has(key)) return null;
    const s = this.stats.get(key);
    if (!s) return { ok: false, fetchedAt: null, stale: false, error: 'not fetched yet' };
    const stale = s.data !== null && this.now() - s.fetchedAt > STATS_STALE_INTERVALS * PROBE_INTERVAL_MS;
    const out = { ok: s.error === null, fetchedAt: s.fetchedAt === null ? null : new Date(s.fetchedAt).toISOString(), stale };
    if (s.error !== null) out.error = s.error;
    if (s.data !== null) out.data = publicData(s.data, this.nodeInfo(key).publicDiskFigures);
    if (this.peerSummaries.has(key)) out.peerSummary = this.peerSummaries.get(key);
    return out;
  }

  // The declared upstreams of a host with what the node itself says about them: online is true or
  // false when the node's own interface list has a row of that name (trimmed, any case), and null with
  // no list, no match or stats that have gone stale. Nothing is probed, and only this one answer
  // leaves: not the rows, the byte counts or the names of any other interface.
  upstreamsFor(key) {
    const ups = this.nodeInfo(key).upstreams;
    if (!ups?.length) return null;
    const s = this.stats.get(key);
    const fresh = s?.rows && s.data !== null && this.now() - s.fetchedAt <= STATS_STALE_INTERVALS * PROBE_INTERVAL_MS;
    return ups.map((u) => {
      const hit = fresh ? s.rows.filter((r) => r.key === u.name.trim().toLowerCase()) : [];
      return { ...u, online: hit.length ? hit.some((r) => r.online) : null };
    });
  }

  // Display name, proxy members and proxy of one host.
  nodeInfo(key) {
    const info = this.nodes.get(key) ?? { name: null, proxyFor: [], proxiedBy: null, countOwn: false };
    return {
      ...info,
      publicDetails: info.publicDetails ?? this.publicDetails,
      publicDiskFigures: info.publicDiskFigures ?? this.publicDiskFigures,
      publicLogs: info.publicLogs ?? this.publicLogs,
      requireLogin: info.requireLogin ?? this.requireLogin,
    };
  }

  // Whether this viewer may read a node's logs: logged in, or the node says public_logs. Never by omission
  // of anything in require_login. The details must be open to them too.
  logsAllowed(key, auth = false) {
    const info = this.nodeInfo(key);
    return info.publicDetails && !this.hiddenFor(key, auth).has('details') && (auth || info.publicLogs === true);
  }

  // Both: the viewer may read them and the node serves them.
  mayReadLogs(key, auth = false) {
    return this.logsAllowed(key, auth) && this.logsAvailable(key);
  }

  // Whether a node can have a Logs tab: logs are on, and it has a stats URL and a token that may be sent there.
  logsAvailable(key) {
    const url = this.statsUrls.get(key);
    const token = this.#tokens.get(key);
    return this.logsEnabled && url !== undefined && validToken(token) && tokenAllowedFor(url, isPrivateHost);
  }

  // A node's log lines for a visitor who may see them: {ok, data, fetchedAt}, or {ok: false, error}
  // with a short code. The token stays in here.
  // viewer says who asks, for the limit on new questions (see LogsCache).
  logsFor(key, { lines, level }, viewer = '') {
    if (!this.logsAvailable(key)) return Promise.resolve({ ok: false, error: 'not-found' });
    const url = this.statsUrls.get(key);
    const token = this.#tokens.get(key);
    return this.logsCache.get(key, { lines, level }, () => this.logsFn(url, { token, lines, level }), viewer);
  }

  // The sections hidden from a visitor: none once logged in.
  hiddenFor(key, auth = false) {
    return auth ? new Set() : new Set(this.nodeInfo(key).requireLogin);
  }

  // What is hidden in a proxy's group line: everything hidden on the proxy or on a node that counts in it.
  groupHidden(key, auth = false) {
    const info = this.nodeInfo(key);
    return union([key, ...info.proxyFor].map((k) => this.hiddenFor(k, auth)));
  }

  // The combined latest stats of a proxy's group: its members, and itself too
  // when count_own is set. Null when the host is not a proxy.
  // include, when given, picks the nodes that count (the combined details view
  // leaves out those whose details are private or need a login).
  groupFor(key, compute = false, include = null) {
    const info = this.nodeInfo(key);
    if (info.proxyFor.length === 0) return null;
    const all = info.countOwn ? [key, ...info.proxyFor] : info.proxyFor;
    const keys = include ? all.filter(include) : all;
    const filtered = keys.length !== all.length;
    const members = keys.map((k) => {
      const last = this.history.get(k)?.at(-1);
      return { key: k, status: last ? (last[1] ? 'up' : 'down') : 'unknown', stats: this.statsFor(k), peers: this.peerLists.get(k) };
    });
    // The union is worked out only when the lists have changed, and only by
    // refreshUnions: a request gets the stored one, or none (the range) for the
    // moment between a change in who reports and the next refresh.
    const union = (lists) => {
      // The stored union covers every member; with some left out there is only the range.
      if (filtered) return null;
      const id = lists.map((l) => l.id).join(',');
      const hit = this.unionCache.get(key);
      if (hit?.id === id) return hit.value;
      if (!compute) return null;
      const value = unionPeers(lists);
      this.unionCache.set(key, { id, value });
      return value;
    };
    return { countOwn: info.countOwn, ...aggregateGroup(members, { union }) };
  }

  // Gives the monitor the source of detected links (a LinkWatcher). It is only ever read here: a page
  // view never asks a node anything.
  attachLinks(watcher) {
    this.#linkWatcher = watcher;
  }

  // The links of every node for this visitor (see links.js): detected and declared, merged. A link
  // is left out when either end keeps its links behind a login (require_login: links), before the
  // cap, and a link found in a node's config is left out for a node whose details are private.
  // Someone who is not signed in gets {to, dir} only: which links were found in a config and which
  // were declared would say which nodes are managed from here, and whether a node's config says the
  // interface is on would say it too (declared links have no such claim).
  linksFor(auth = false) {
    const keys = this.targets.map((t) => `${t.host}:${t.port}`);
    const hidden = new Map(keys.map((k) => [k, this.hiddenFor(k, auth).has('links')]));
    // For a visitor who is not signed in, a link found in a config is only shown when both nodes keep
    // their details public: the one that dials and the one that is dialled.
    const detectedOf = (k) => {
      if (!auth && !this.nodeInfo(k).publicDetails) return null;
      const found = this.#linkWatcher?.detected(k) ?? null;
      return !auth && found ? { ...found, links: found.links.filter((l) => this.nodeInfo(l.to)?.publicDetails !== false) } : found;
    };
    const merged = buildLinks(keys, (k) => this.nodeInfo(k).links ?? [], detectedOf, (from, to) => !hidden.get(from) && !hidden.get(to));
    if (auth) return merged;
    const out = new Map();
    for (const [k, list] of merged) out.set(k, list.map(({ to, dir }) => ({ to, dir })));
    return out;
  }

  // The JSON the status page shows. auth: the visitor is logged in.
  snapshot(barLength = 90, auth = false) {
    const links = this.linksFor(auth);
    const hosts = this.targets.map((t) => {
      const key = `${t.host}:${t.port}`;
      const hidden = this.hiddenFor(key, auth);
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
        uptime90: { percent30: this.uptime.percent(key, 30), percent90: this.uptime.percent(key, SHOWN_DAYS) },
        days: this.uptime.dayList(key, SHOWN_DAYS),
        uptimePercent: list.length ? Math.round((upCount / list.length) * 1000) / 10 : null,
        checks: list.length,
        history: list.slice(-barLength).map((e) => ({ t: e[0], up: e[1] === 1, ms: e[2] })),
        stats: stripStats(this.statsFor(key), hidden),
        // Details exist for a node with stats, and for a proxy with any member that has stats.
        hasDetail: this.nodeInfo(key).publicDetails && (this.statsUrls.has(key) || this.nodeInfo(key).proxyFor.some((k) => this.statsUrls.has(k) && this.nodeInfo(k).publicDetails)),
        name: this.nodeInfo(key).name,
        role: this.nodeInfo(key).proxyFor.length ? 'proxy' : 'node',
        proxy: this.nodeInfo(key).proxyFor.length ? { for: [...this.nodeInfo(key).proxyFor] } : null,
        proxiedBy: this.nodeInfo(key).proxiedBy,
        // Display-only peers the node connects out to (never probed); left out when there are none.
        ...(this.nodeInfo(key).upstreams?.length ? { upstreams: this.upstreamsFor(key) } : {}),
        // Links to other monitored nodes: the other node's key, never an interface or an address; left out when there are none.
        ...(links.get(key).length ? { links: links.get(key) } : {}),
        group: stripGroup(this.groupFor(key), this.groupHidden(key, auth)),
      };
    });
    // Every entry point counts, proxied nodes too. "up" needs all of them checked and up.
    const known = hosts.filter((h) => h.status !== 'unknown');
    const down = known.filter((h) => h.status === 'down').length;
    let overall = 'unknown';
    if (known.length) overall = down === 0 ? (known.length === hosts.length ? 'up' : 'unknown') : down === hosts.length ? 'down' : 'degraded';
    return {
      overall,
      checkedAt: this.lastCheck ? new Date(this.lastCheck).toISOString() : null,
      intervalSeconds: PROBE_INTERVAL_MS / 1000,
      hosts,
    };
  }
}
