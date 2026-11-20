// The public JSON API: GET /api/public/stats and /api/public/incidents. They are
// built from what an anonymous visitor gets from the status page (the snapshot
// with nothing unlocked, so public_details, public_disk_figures and require_login
// already apply), copying only the fields listed here. Nothing is passed on
// as a whole, so a field added to the snapshot later never leaks by accident.
import crypto from 'node:crypto';

export const API_VERSION = 1;

const KINDS = ['total', 'lxmf', 'nomad', 'propagation'];
const PROPAGATION_KEYS = [
  'storedMessages', 'storedBytes', 'storageLimitBytes', 'peersConnected', 'peersTotal', 'peersAlive', 'peersStatic', 'peersAuto', 'peerLimit',
  'staticPeers', 'autopeerDepth', 'messagesReceived', 'messagesServed', 'messagesSentToPeers', 'messagesReceivedFromPeers',
  'messagesOfferedToPeers', 'unhandledMessages', 'unhandledDistinct',
];

const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : null);
const pick = (obj, keys) => Object.fromEntries(keys.map((k) => [k, num(obj?.[k])]));
const sumOf = (list) => {
  const known = list.filter((v) => v !== null);
  return known.length ? known.reduce((a, b) => a + b, 0) : null;
};

function propagation(p) {
  if (!p) return null;
  const out = pick(p, PROPAGATION_KEYS);
  if (typeof p.nodes === 'number') out.nodes = p.nodes;
  // Counters that were taken out (require_login) are not null but absent.
  for (const k of PROPAGATION_KEYS) if (!Object.hasOwn(p, k)) delete out[k];
  if (typeof p.autopeer === 'boolean') out.autopeer = p.autopeer;
  return out;
}

// The level and share always; the byte figures only when the snapshot has them (public_disk_figures).
function disk(d) {
  if (!d) return null;
  const out = { level: typeof d.level === 'string' ? d.level : null, usedPercent: num(d.usedPercent) };
  if (Object.hasOwn(d, 'fsTotalBytes')) Object.assign(out, { totalBytes: num(d.fsTotalBytes), freeBytes: num(d.fsFreeBytes) });
  return out;
}

function groupDisk(d) {
  if (!d) return null;
  const out = { nodes: num(d.nodes), worstLevel: d.worst?.level ?? null, worstUsedPercent: num(d.worst?.usedPercent) };
  if (d.lowestFree) Object.assign(out, { lowestFreePercent: num(d.lowestFree.percent), lowestFreeBytes: num(d.lowestFree.freeBytes), lowestFreeTotalBytes: num(d.lowestFree.totalBytes) });
  return out;
}

// A proxy's combined view. Peers heard is a range, min to max, which is one
// number (exact: true) when every node supplied its peer list.
function group(g) {
  if (!g) return null;
  const d = g.data;
  const out = { countOwn: g.countOwn === true, nodes: g.nodes, reporting: g.reporting, partial: g.partial, clients: null, interfaces: null, announcesLastMinute: null, peersHeard: null, propagation: null, disk: null };
  if (!d) return out;
  out.clients = num(d.interfaces.clients);
  out.interfaces = pick(d.interfaces, ['total', 'online']);
  out.announcesLastMinute = num(d.announcesLastMinute);
  const p = d.peersHeard;
  out.peersHeard = { exact: p.exact === true };
  for (const k of KINDS) {
    const max = num(p.sum[k]);
    out.peersHeard[k] = { min: p.exact ? num(p.union?.[k]) : num(p.max[k]), max };
  }
  out.propagation = propagation(d.propagation);
  out.disk = groupDisk(d.disk);
  return out;
}

// Announces waiting to go out: the numbers and whether one interface is at its limit.
function announceQueue(q) {
  if (!q || typeof q.full !== 'boolean') return null;
  return { queued: num(q.queued), limit: num(q.limit), full: q.full, fullest: num(q.fullest) };
}

function node(h) {
  const s = h.stats;
  // Numbers of a node that stopped answering are old, so they are not shown.
  const d = s && s.ok && !s.stale && s.data ? s.data : null;
  return {
    name: h.name ?? h.host,
    address: `${h.host}:${h.port}`,
    role: h.role === 'proxy' ? 'proxy' : 'node',
    status: h.status,
    up: h.status === 'up' ? true : h.status === 'down' ? false : null,
    connectMs: num(h.latencyMs),
    lastChecked: h.lastChecked,
    uptime30: num(h.uptime90?.percent30),
    uptime90: num(h.uptime90?.percent90),
    clients: d ? num(d.interfaces.clients) : null,
    interfaces: d ? pick(d.interfaces, ['total', 'online']) : null,
    peersHeard: d ? pick(d.peersHeard, KINDS) : null,
    announcesLastMinute: d ? num(d.announcesLastMinute) : null,
    propagation: d ? propagation(d.propagation) : null,
    disk: d ? disk(d.disk) : null,
    announceQueue: d ? announceQueue(d.announceQueue) : null,
    proxyFor: h.proxy ? [...h.proxy.for] : [],
    proxiedBy: h.proxiedBy ?? null,
    group: group(h.group),
  };
}

// Totals for the whole network. A proxy is the front door, not a node: it is
// counted in `proxies` (and its up and down in `proxiesUp` and `proxiesDown`),
// never in `nodes`, `up`, `down`, `unknown` or `reporting`. Its state still sets
// `overall`, since a down door is an outage. Every node counts once in the sums:
// the nodes behind a proxy count through the proxy's combined view (which leaves
// out the proxy's own numbers unless count_own is set), nodes with no proxy
// through their own. A proxy never adds its own numbers a second time.
function network(snap, nodes) {
  const proxies = nodes.filter((n) => n.role === 'proxy');
  const plain = nodes.filter((n) => n.role !== 'proxy');
  const counted = [];
  for (const n of proxies) if (n.group) counted.push(n.group);
  for (const n of plain) {
    if (n.proxiedBy === null) counted.push({ clients: n.clients, interfaces: n.interfaces, announcesLastMinute: n.announcesLastMinute, peersHeard: n.peersHeard && Object.fromEntries(KINDS.map((k) => [k, { max: n.peersHeard[k] }])) });
  }
  const peersHeardSum = {};
  for (const k of KINDS) peersHeardSum[k] = sumOf(counted.map((c) => num(c.peersHeard?.[k]?.max)));
  const count = (list, status) => list.filter((n) => n.status === status).length;
  return {
    overall: snap.overall,
    checkedAt: snap.checkedAt,
    intervalSeconds: snap.intervalSeconds,
    nodes: plain.length,
    up: count(plain, 'up'),
    down: count(plain, 'down'),
    unknown: count(plain, 'unknown'),
    reporting: plain.filter((n) => n.peersHeard !== null).length,
    proxies: proxies.length,
    proxiesUp: count(proxies, 'up'),
    proxiesDown: count(proxies, 'down'),
    clients: sumOf(counted.map((c) => num(c.clients))),
    interfaces: { total: sumOf(counted.map((c) => num(c.interfaces?.total))), online: sumOf(counted.map((c) => num(c.interfaces?.online))) },
    announcesLastMinute: sumOf(counted.map((c) => num(c.announcesLastMinute))),
    // A peer heard by two nodes counts twice, so this is an upper bound.
    peersHeardSum,
  };
}

// snap: monitor.snapshot(n, false), the anonymous one.
export function publicStats(snap, generated) {
  const nodes = snap.hosts.map(node);
  return { version: API_VERSION, generated, nodes, network: network(snap, nodes) };
}

export function publicIncidents(list, generated) {
  return {
    version: API_VERSION,
    generated,
    incidents: list.map((i) => ({
      address: String(i.host),
      name: i.name ?? String(i.host).replace(/:\d+$/, ''),
      start: i.start,
      end: i.end,
      seconds: num(i.seconds),
      ongoing: i.ongoing === true,
    })),
  };
}

// A JSON answer kept in memory: the body is built at most once per ttlMs, so
// requests (and bursts of them) never touch the monitor. Strong ETag, made from the body without its
// `generated` time, so a rebuild with nothing new keeps the same one and If-None-Match still gets a 304.
export function memoJson(build, ttlMs, clock = Date.now) {
  let at = -Infinity;
  let entry = null;
  return () => {
    const t = clock();
    if (entry === null || t - at >= ttlMs || t < at) {
      const value = build();
      const body = JSON.stringify(value);
      // The time the body was made is not content: with it in the hash, no ETag would survive a rebuild.
      const { generated: _generated, ...content } = value;
      entry = { body, etag: `"${crypto.createHash('sha256').update(JSON.stringify(content)).digest('hex').slice(0, 24)}"` };
      at = t;
    }
    return entry;
  };
}

// Does If-None-Match name this ETag (or "*")? Weak validators compare equal here.
export function etagMatches(header, etag) {
  if (typeof header !== 'string') return false;
  return header.split(',').some((v) => {
    const t = v.trim().replace(/^W\//, '');
    return t === '*' || t === etag;
  });
}
