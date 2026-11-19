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

// The graph data for one range: every series as [[t, v|null]], at most
// maxPoints each.
export function buildSeries(samples, range, now, maxPoints = MAX_POINTS) {
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
  };
}
