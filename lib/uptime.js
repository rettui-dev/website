// Long-term uptime: per node and UTC day, how many checks were up out of how many,
// and a log of incidents (a node going down). Kept in uptime.json, apart from the
// 24 hour check history. Everything read back from the file is untrusted and
// cleaned entry by entry.
import fs from 'node:fs/promises';

// Days kept: a little over the 90 the page shows.
export const KEEP_DAYS = 100;
export const SHOWN_DAYS = 90;
// Incidents kept per node and over all nodes.
export const MAX_INCIDENTS_PER_NODE = 50;
export const MAX_INCIDENTS_TOTAL = 1000;
// Failed checks in a row that open an incident, and good ones that close it, so
// one dropped probe is not an incident.
export const OPEN_AFTER = 2;
export const CLOSE_AFTER = 2;
// A saved file larger than this is ignored, not read.
export const MAX_UPTIME_FILE_BYTES = 2 * 1024 * 1024;
// No day can hold more checks than this (one every 30 seconds is 2880).
const MAX_DAY_CHECKS = 1_000_000;

const DAY_MS = 86_400_000;
const DAY_RE = /^\d{4}-\d{2}-\d{2}$/;
// Saved times must fit a Date.
const MAX_TIME = 8.64e15;

export const dayOf = (time) => new Date(time).toISOString().slice(0, 10);

const validTime = (t) => Number.isSafeInteger(t) && t >= 0 && t <= MAX_TIME;
const validCount = (n) => Number.isSafeInteger(n) && n >= 0 && n <= MAX_DAY_CHECKS;

// The share of checks that were up, in tenths of a percent, rounded down: only a
// day with no failed check reads 100, never a day that merely rounds to it.
export function percentOf(up, total) {
  if (!(total > 0)) return null;
  return Math.floor((up / total) * 1000) / 10;
}

function emptyNode() {
  return { days: new Map(), incidents: [], open: null, fails: null, oks: null };
}

// Saved days, as {"YYYY-MM-DD": [up, total]}: bad entries are dropped.
function cleanDays(raw, now) {
  const days = new Map();
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return days;
  const oldest = dayOf(now - KEEP_DAYS * DAY_MS);
  const newest = dayOf(now + DAY_MS);
  for (const [day, v] of Object.entries(raw)) {
    if (!DAY_RE.test(day) || day < oldest || day > newest || Number.isNaN(Date.parse(day))) continue;
    if (!Array.isArray(v) || v.length !== 2 || !validCount(v[0]) || !validCount(v[1]) || v[0] > v[1]) continue;
    days.set(day, [v[0], v[1]]);
  }
  return days;
}

// Saved incidents, as [[start, end or null], ...]: oldest first, at most one still open (the last).
function cleanIncidents(raw) {
  const out = [];
  if (!Array.isArray(raw)) return out;
  for (const e of raw.slice(-MAX_INCIDENTS_PER_NODE * 2)) {
    if (!Array.isArray(e) || e.length !== 2 || !validTime(e[0])) continue;
    if (e[1] !== null && (!validTime(e[1]) || e[1] < e[0])) continue;
    out.push({ start: e[0], end: e[1] });
  }
  out.sort((a, b) => a.start - b.start);
  // Only the newest can be open; an older one without an end is closed at its own start.
  for (let i = 0; i < out.length - 1; i++) if (out[i].end === null) out[i].end = out[i].start;
  return out.slice(-MAX_INCIDENTS_PER_NODE);
}

export class UptimeLog {
  #nodes;
  #now;

  constructor(keys, { now = Date.now } = {}) {
    this.#now = now;
    this.#nodes = new Map(keys.map((k) => [k, emptyNode()]));
    this.dirty = false;
  }

  // Reads the saved file. A missing, oversized or damaged file means starting empty;
  // nodes that are no longer monitored are not read.
  async load(file) {
    let data;
    try {
      if ((await fs.stat(file)).size > MAX_UPTIME_FILE_BYTES) return;
      data = JSON.parse(await fs.readFile(file, 'utf8'));
    } catch {
      return;
    }
    if (!data || typeof data !== 'object' || data.version !== 1 || !data.hosts || typeof data.hosts !== 'object' || Array.isArray(data.hosts)) return;
    const now = this.#now();
    for (const [key, n] of this.#nodes) {
      const saved = Object.hasOwn(data.hosts, key) ? data.hosts[key] : null;
      if (!saved || typeof saved !== 'object') continue;
      n.days = cleanDays(saved.days, now);
      n.incidents = cleanIncidents(saved.incidents);
      const last = n.incidents.at(-1);
      // The open incident carries on after a restart, so it is not announced again.
      n.open = last && last.end === null ? last : null;
    }
    this.#trimTotal();
  }

  // What is written to the file.
  toJSON() {
    const hosts = {};
    for (const [key, n] of this.#nodes) {
      hosts[key] = { days: Object.fromEntries(n.days), incidents: n.incidents.map((i) => [i.start, i.end]) };
    }
    return { version: 1, hosts };
  }

  // Notes one check of a node. Returns the events it caused: [{type: 'down' | 'recovered', ...}].
  record(key, up, time) {
    const n = this.#nodes.get(key);
    if (!n || !validTime(time)) return [];
    this.dirty = true;
    const day = dayOf(time);
    const d = n.days.get(day) ?? [0, 0];
    d[0] += up ? 1 : 0;
    d[1] += 1;
    n.days.set(day, d);
    if (n.days.size > KEEP_DAYS) {
      for (const k of [...n.days.keys()].sort().slice(0, n.days.size - KEEP_DAYS)) n.days.delete(k);
    }
    const events = [];
    if (up) {
      n.fails = null;
      if (n.open) {
        n.oks ??= { count: 0, first: time };
        n.oks.count += 1;
        if (n.oks.count >= CLOSE_AFTER) {
          n.open.end = n.oks.first;
          events.push({ type: 'recovered', key, start: n.open.start, end: n.open.end, at: time });
          n.open = null;
          n.oks = null;
        }
      }
    } else {
      n.oks = null;
      if (!n.open) {
        n.fails ??= { count: 0, first: time };
        n.fails.count += 1;
        if (n.fails.count >= OPEN_AFTER) {
          n.open = { start: n.fails.first, end: null };
          n.incidents.push(n.open);
          if (n.incidents.length > MAX_INCIDENTS_PER_NODE) n.incidents.splice(0, n.incidents.length - MAX_INCIDENTS_PER_NODE);
          this.#trimTotal();
          events.push({ type: 'down', key, start: n.open.start, end: null, at: time });
          n.fails = null;
        }
      }
    }
    return events;
  }

  // The incidents that are still open, as [key, start].
  openIncidents() {
    return [...this.#nodes].filter(([, n]) => n.open).map(([key, n]) => [key, n.open.start]);
  }

  // Keeps the newest MAX_INCIDENTS_TOTAL incidents over all nodes. An open one is never dropped.
  #trimTotal() {
    let total = 0;
    for (const n of this.#nodes.values()) total += n.incidents.length;
    if (total <= MAX_INCIDENTS_TOTAL) return;
    const all = [];
    for (const n of this.#nodes.values()) for (const i of n.incidents) all.push([i, n]);
    all.sort((a, b) => a[0].start - b[0].start);
    for (const [i, n] of all) {
      if (total <= MAX_INCIDENTS_TOTAL) break;
      if (i.end === null) continue;
      n.incidents.splice(n.incidents.indexOf(i), 1);
      total--;
    }
  }

  // Percent up over the last `count` days including today, or null with no checks in them.
  percent(key, count, now = this.#now()) {
    const n = this.#nodes.get(key);
    if (!n) return null;
    let up = 0;
    let total = 0;
    for (let i = 0; i < count; i++) {
      const d = n.days.get(dayOf(now - i * DAY_MS));
      if (d) {
        up += d[0];
        total += d[1];
      }
    }
    return percentOf(up, total);
  }

  // One entry per day, oldest first and today last: the percent up, or null without checks.
  dayList(key, count = SHOWN_DAYS, now = this.#now()) {
    const n = this.#nodes.get(key);
    const out = [];
    for (let i = count - 1; i >= 0; i--) {
      const d = n?.days.get(dayOf(now - i * DAY_MS));
      out.push(d ? percentOf(d[0], d[1]) : null);
    }
    return out;
  }

  // The newest incidents of a node, newest first, ready to publish.
  incidents(key, limit = MAX_INCIDENTS_PER_NODE, now = this.#now()) {
    const n = this.#nodes.get(key);
    if (!n) return [];
    return n.incidents.slice(-limit).reverse().map((i) => publish(i, now));
  }

  // The newest incidents of all nodes, newest first, each with its host.
  allIncidents(limit, now = this.#now()) {
    const all = [];
    for (const [host, n] of this.#nodes) for (const i of n.incidents) all.push({ host, ...publish(i, now) });
    return all.sort((a, b) => Date.parse(b.start) - Date.parse(a.start) || (a.host < b.host ? -1 : 1)).slice(0, limit);
  }
}

// {start, end, seconds, ongoing} with times as ISO text.
function publish(i, now) {
  const end = i.end ?? now;
  return {
    start: new Date(i.start).toISOString(),
    end: i.end === null ? null : new Date(i.end).toISOString(),
    seconds: Math.max(0, Math.round((end - i.start) / 1000)),
    ongoing: i.end === null,
  };
}
