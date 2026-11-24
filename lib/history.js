// Node stats history: the saved samples, and the pure functions that turn
// them into rates and graph series. Saved data is checked entry by entry.

// One sample every 5 minutes, 2016 of them is 7 days.
export const SAMPLE_INTERVAL_MS = 5 * 60_000;
export const MAX_SAMPLES = 2016;
export const MAX_VERSIONS = 10;
export const MAX_POINTS = 240;
// Two samples further apart than this are not joined into a rate.
export const MAX_GAP_MS = 30 * 60_000;
export const RANGES = { '6h': 6 * 3_600_000, '24h': 24 * 3_600_000, '7d': 7 * 24 * 3_600_000 };
const MAX_VERSION_TEXT = 32;
// No saved time may be later than this: a time that large breaks Date.
export const MAX_TIME = Date.UTC(2100, 0, 1);
// Saved entries dated more than this ahead of the clock are dropped, so a
// tampered file cannot freeze sampling by claiming the future.
export const FUTURE_SLACK_MS = 3_600_000;

// Sample columns.
const [TIME, CLIENTS, RX, TX, PEERS, LXMF, NOMAD, PROP, ANNOUNCES, UPTIME, IFACES] = Array.from({ length: 11 }, (_, i) => i);

const whole = (v) => Number.isSafeInteger(v) && v >= 0;

// A saved sample is [time ms, clients|null, rx, tx, peers, lxmf, nomad, propagation, announces, uptime, interfaces online].
export function validSample(e) {
  return (
    Array.isArray(e) &&
    e.length === 11 &&
    whole(e[TIME]) &&
    e[TIME] > 0 &&
    e[TIME] < MAX_TIME &&
    (e[CLIENTS] === null || whole(e[CLIENTS])) &&
    e.slice(2).every(whole)
  );
}

// Builds a sample from sanitized node stats (see sanitizeStats).
export function sampleFrom(time, d) {
  return [
    time,
    d.interfaces.clients,
    d.interfaces.rxBytes,
    d.interfaces.txBytes,
    d.peersHeard.total,
    d.peersHeard.lxmf,
    d.peersHeard.nomad,
    d.peersHeard.propagation,
    d.announcesLastMinute,
    d.uptimeSeconds,
    d.interfaces.online,
  ];
}

// Keeps the valid samples in strictly rising time order, newest maxSamples,
// none older than the longest range.
export function cleanSamples(list, now, maxSamples = MAX_SAMPLES) {
  if (!Array.isArray(list)) return [];
  const out = [];
  let last = 0;
  for (const e of list) {
    if (!validSample(e) || e[TIME] <= last || e[TIME] < now - RANGES['7d'] || e[TIME] > now + FUTURE_SLACK_MS) continue;
    last = e[TIME];
    out.push(e);
  }
  return out.slice(-maxSamples);
}

// A saved version is [text, first seen ms].
export function validVersion(e) {
  return Array.isArray(e) && e.length === 2 && typeof e[0] === 'string' && e[0].length > 0 && e[0].length <= MAX_VERSION_TEXT && whole(e[1]) && e[1] < MAX_TIME;
}

export function cleanVersions(list, now = Date.now()) {
  if (!Array.isArray(list)) return [];
  return list.filter((e) => validVersion(e) && e[1] <= now + FUTURE_SLACK_MS).slice(-MAX_VERSIONS);
}

// Bytes per second between consecutive samples: [{t, rx, tx}], rx and tx null
// where the interval cannot be measured. A counter or uptime that goes down
// means the node restarted, and a long gap means samples are missing; both
// are skipped rather than guessed at. Never negative, never NaN.
export function rates(samples) {
  const out = [];
  for (let i = 1; i < samples.length; i++) {
    const a = samples[i - 1];
    const b = samples[i];
    const dt = (b[TIME] - a[TIME]) / 1000;
    const restarted = b[RX] < a[RX] || b[TX] < a[TX] || b[UPTIME] < a[UPTIME];
    if (!(dt > 0) || b[TIME] - a[TIME] > MAX_GAP_MS || restarted) {
      out.push({ t: b[TIME], rx: null, tx: null });
      continue;
    }
    const rx = (b[RX] - a[RX]) / dt;
    const tx = (b[TX] - a[TX]) / dt;
    out.push({ t: b[TIME], rx: Number.isFinite(rx) ? rx : null, tx: Number.isFinite(tx) ? tx : null });
  }
  return out;
}

const round2 = (n) => Math.round(n * 100) / 100;

// Shrinks [[t, v|null]] to at most max points by averaging equal-sized groups
// of neighbours. A group with no value stays a gap (null).
export function downsample(points, max = MAX_POINTS) {
  const n = points.length;
  if (max < 1) return [];
  if (n <= max) return points.map((p) => [p[0], p[1] === null ? null : round2(p[1])]);
  const out = [];
  for (let k = 0; k < max; k++) {
    const group = points.slice(Math.floor((k * n) / max), Math.floor(((k + 1) * n) / max));
    if (group.length === 0) continue;
    const values = group.filter((p) => p[1] !== null);
    const mean = values.length ? values.reduce((s, p) => s + p[1], 0) / values.length : null;
    out.push([group.at(-1)[0], mean === null ? null : round2(mean)]);
  }
  return out;
}


// The propagation node and disk numbers are sampled at the same moments as the
// main samples but kept in their own list, so that the main samples keep the
// layout older versions read. An extra sample is
// [time ms, node uptime, stored messages, stored bytes, peers alive, peers total,
// fs free bytes, data bytes, messages sent to peers, messages received from
// peers]; every number after the uptime is null where the node did not send it.
const [X_TIME, X_UP, X_MSG, X_BYTES, X_ALIVE, X_TOTAL, X_FREE, X_DATA, X_SENT, X_RECV] = Array.from({ length: 10 }, (_, i) => i);

export function validExtra(e) {
  return (
    Array.isArray(e) &&
    e.length === 10 &&
    whole(e[X_TIME]) &&
    e[X_TIME] > 0 &&
    e[X_TIME] < MAX_TIME &&
    whole(e[X_UP]) &&
    e.slice(2).every((v) => v === null || whole(v))
  );
}

// Null when the node sent neither propagation nor disk numbers.
export function extraFrom(time, d) {
  const p = d.propagation ?? null;
  const k = d.disk ?? null;
  if (!p && !k) return null;
  const v = (o, key) => (o && o[key] !== undefined ? o[key] : null);
  return [
    time, d.uptimeSeconds, v(p, 'storedMessages'), v(p, 'storedBytes'), v(p, 'peersAlive'), v(p, 'peersTotal'),
    v(k, 'fsFreeBytes'), v(k, 'dataBytes'), v(p, 'messagesSentToPeers'), v(p, 'messagesReceivedFromPeers'),
  ];
}

export function cleanExtras(list, now, maxSamples = MAX_SAMPLES) {
  if (!Array.isArray(list)) return [];
  const out = [];
  let last = 0;
  for (const e of list) {
    if (!validExtra(e) || e[X_TIME] <= last || e[X_TIME] < now - RANGES['7d'] || e[X_TIME] > now + FUTURE_SLACK_MS) continue;
    last = e[X_TIME];
    out.push(e);
  }
  return out.slice(-maxSamples);
}

// Messages per minute between consecutive extra samples, for the two cumulative
// counters, like rates() does for bytes: a counter or uptime that goes down is a
// restart, a long gap is missing data, and both are left as gaps (null).
export function messageRates(extra) {
  const out = [];
  for (let i = 1; i < extra.length; i++) {
    const a = extra[i - 1];
    const b = extra[i];
    const dt = (b[X_TIME] - a[X_TIME]) / 1000;
    const bad = !(dt > 0) || b[X_TIME] - a[X_TIME] > MAX_GAP_MS || b[X_UP] < a[X_UP];
    const rate = (col) => {
      if (bad || a[col] === null || b[col] === null || b[col] < a[col]) return null;
      const r = ((b[col] - a[col]) / dt) * 60;
      return Number.isFinite(r) ? r : null;
    };
    out.push({ t: b[X_TIME], sent: rate(X_SENT), recv: rate(X_RECV) });
  }
  return out;
}

// The graph series of the extra samples within a range. propagation and disk are
// null when the range has no numbers for them.
export function buildExtraSeries(extra, range, now, maxPoints = MAX_POINTS) {
  const from = now - RANGES[range];
  const inRange = extra.filter((e) => e[X_TIME] >= from && e[X_TIME] <= now);
  const col = (i) => downsample(inRange.map((e) => [e[X_TIME], e[i]]), maxPoints);
  const flow = messageRates(extra).filter((r) => r.t >= from && r.t <= now);
  const has = (...cols) => inRange.some((e) => cols.some((c) => e[c] !== null));
  return {
    propagation: has(X_MSG, X_BYTES, X_ALIVE, X_TOTAL, X_SENT, X_RECV)
      ? {
          storedMessages: col(X_MSG),
          storedBytes: col(X_BYTES),
          peersAlive: col(X_ALIVE),
          peersTotal: col(X_TOTAL),
          sentPerMinute: downsample(flow.map((r) => [r.t, r.sent]), maxPoints),
          receivedPerMinute: downsample(flow.map((r) => [r.t, r.recv]), maxPoints),
        }
      : null,
    disk: has(X_FREE, X_DATA) ? { dataBytes: col(X_DATA), fsFreeBytes: col(X_FREE) } : null,
  };
}

// The graph data for one range: every series as [[t, v|null]], at most
// maxPoints each.
export function buildSeries(samples, range, now, maxPoints = MAX_POINTS, extra = []) {
  const span = RANGES[range];
  const from = now - span;
  const inRange = samples.filter((s) => s[TIME] >= from && s[TIME] <= now);
  const col = (i) => downsample(inRange.map((s) => [s[TIME], s[i]]), maxPoints);
  const rate = rates(samples).filter((r) => r.t >= from && r.t <= now);
  return {
    range,
    from,
    to: now,
    sampleCount: inRange.length,
    bytesIn: downsample(rate.map((r) => [r.t, r.rx]), maxPoints),
    bytesOut: downsample(rate.map((r) => [r.t, r.tx]), maxPoints),
    clients: col(CLIENTS),
    peers: { total: col(PEERS), lxmf: col(LXMF), nomad: col(NOMAD), propagation: col(PROP) },
    announces: col(ANNOUNCES),
    interfacesOnline: col(IFACES),
    ...buildExtraSeries(extra, range, now, maxPoints),
  };
}

// Puts items {t, m} (m is the member) into groups of neighbours in time: items
// within half an interval of the first one of a group belong to it, and a member
// is in a group at most once. Returns [{start, last, by: Map member -> item}].
function groupByTime(items, intervalMs) {
  items.sort((a, b) => a.t - b.t);
  const groups = [];
  for (const it of items) {
    const g = groups.at(-1);
    if (g && it.t - g.start <= intervalMs / 2 && !g.by.has(it.m)) {
      g.by.set(it.m, it);
      g.last = it.t;
    } else groups.push({ start: it.t, last: it.t, by: new Map([[it.m, it]]) });
  }
  return groups;
}

// The group's propagation and disk series. Only members that have extra samples
// in the range count (a node without a propagation node is left out), and a
// point is added up only when every one of them is in it, like the main series.
// Free disk space is not added up: the point is the least free space of any node.
function combineExtras(memberExtras, from, now, intervalMs, maxPoints) {
  const items = [];
  let members = 0;
  memberExtras.forEach((extra, m) => {
    const rates = messageRates(extra);
    const inRange = extra.some((e) => e[X_TIME] >= from && e[X_TIME] <= now);
    if (inRange) members++;
    extra.forEach((e, i) => {
      if (e[X_TIME] >= from && e[X_TIME] <= now) items.push({ t: e[X_TIME], m, e, r: i > 0 ? rates[i - 1] : null });
    });
  });
  if (members === 0) return { propagation: null, disk: null };
  const groups = groupByTime(items, intervalMs);
  const cols = { storedMessages: X_MSG, storedBytes: X_BYTES, peersAlive: X_ALIVE, peersTotal: X_TOTAL };
  const out = { sentPerMinute: [], receivedPerMinute: [], dataBytes: [], fsFreeBytes: [] };
  for (const k of Object.keys(cols)) out[k] = [];
  for (const g of groups) {
    const t = g.last;
    const list = g.by.size === members ? [...g.by.values()] : [];
    const total = (f) => (list.length && list.every((it) => f(it) !== null && f(it) !== undefined) ? list.reduce((a, it) => a + f(it), 0) : null);
    for (const [k, c] of Object.entries(cols)) out[k].push([t, total((it) => it.e[c])]);
    out.sentPerMinute.push([t, total((it) => it.r?.sent ?? null)]);
    out.receivedPerMinute.push([t, total((it) => it.r?.recv ?? null)]);
    out.dataBytes.push([t, total((it) => it.e[X_DATA])]);
    out.fsFreeBytes.push([t, list.length && list.every((it) => it.e[X_FREE] !== null) ? Math.min(...list.map((it) => it.e[X_FREE])) : null]);
  }
  const d = (points) => downsample(points, maxPoints);
  const any = (...lists) => lists.some((l) => l.some((p) => p[1] !== null));
  const prop = { storedMessages: d(out.storedMessages), storedBytes: d(out.storedBytes), peersAlive: d(out.peersAlive), peersTotal: d(out.peersTotal), sentPerMinute: d(out.sentPerMinute), receivedPerMinute: d(out.receivedPerMinute) };
  const disk = { dataBytes: d(out.dataBytes), fsFreeBytes: d(out.fsFreeBytes), members };
  return {
    propagation: any(...Object.values(prop)) ? { ...prop, members } : null,
    disk: any(disk.dataBytes, disk.fsFreeBytes) ? disk : null,
  };
}

// The graph data of a proxy's group: the members' samples lined up and added.
//
// Members sample on their own clock, so samples are matched by time: all
// samples that fall within half a sample interval of the first one of a group
// of neighbours belong to one point (a node never has two that close). A point
// is added up only when EVERY member has a sample in it, and, for the byte
// rates, a usable rate (a restart in one member leaves a gap in the sum);
// otherwise the point is a gap (null). Summing what exists would make the line
// dip whenever one node missed a sample. The peers series are the sum (an upper
// bound) in `peers` and the largest single member (a lower bound) in
// `peersLow`, because the same peer can be heard by several nodes.
export function combineSeries(memberSamples, range, now, intervalMs = SAMPLE_INTERVAL_MS, maxPoints = MAX_POINTS, memberExtras = []) {
  const span = RANGES[range];
  const from = now - span;
  const members = memberSamples.length;
  const items = [];
  memberSamples.forEach((samples, m) => {
    const r = rates(samples);
    samples.forEach((smp, i) => {
      if (smp[TIME] >= from && smp[TIME] <= now) items.push({ t: smp[TIME], m, s: smp, r: i > 0 ? r[i - 1] : null });
    });
  });
  const groups = groupByTime(items, intervalMs);
  const kinds = { total: PEERS, lxmf: LXMF, nomad: NOMAD, propagation: PROP };
  const out = { bytesIn: [], bytesOut: [], clients: [], announces: [], interfacesOnline: [], peers: {}, peersLow: {} };
  for (const k of Object.keys(kinds)) {
    out.peers[k] = [];
    out.peersLow[k] = [];
  }
  let full = 0;
  for (const g of groups) {
    const t = g.last;
    const all = members > 0 && g.by.size === members;
    const list = all ? [...g.by.values()] : [];
    if (all) full++;
    const sum = (f) => list.reduce((a, it) => a + f(it), 0);
    const rate = (f) => (list.every((it) => it.r && it.r[f] !== null) ? sum((it) => it.r[f]) : null);
    out.bytesIn.push([t, all ? rate('rx') : null]);
    out.bytesOut.push([t, all ? rate('tx') : null]);
    out.clients.push([t, all && list.every((it) => it.s[CLIENTS] !== null) ? sum((it) => it.s[CLIENTS]) : null]);
    out.announces.push([t, all ? sum((it) => it.s[ANNOUNCES]) : null]);
    out.interfacesOnline.push([t, all ? sum((it) => it.s[IFACES]) : null]);
    for (const [k, col] of Object.entries(kinds)) {
      out.peers[k].push([t, all ? sum((it) => it.s[col]) : null]);
      out.peersLow[k].push([t, all ? Math.max(...list.map((it) => it.s[col])) : null]);
    }
  }
  const d = (points) => downsample(points, maxPoints);
  return {
    range,
    from,
    to: now,
    sampleCount: full,
    members,
    bytesIn: d(out.bytesIn),
    bytesOut: d(out.bytesOut),
    clients: d(out.clients),
    peers: Object.fromEntries(Object.entries(out.peers).map(([k, v]) => [k, d(v)])),
    peersLow: Object.fromEntries(Object.entries(out.peersLow).map(([k, v]) => [k, d(v)])),
    announces: d(out.announces),
    interfacesOnline: d(out.interfacesOnline),
    ...combineExtras(memberExtras, from, now, intervalMs, maxPoints),
  };
}
