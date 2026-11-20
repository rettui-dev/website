// The optional propagation node and disk numbers of a node's stats, and the rows
// of the peered nodes. Old nodes send none of it; every part is optional and a
// part that does not fit is left out, never the whole stats. All of it is
// untrusted network data.

export const MAX_PROPAGATION_PEERS = 256;

// A finite number as a whole, non-negative, safe integer; anything else is null.
export function optCount(v) {
  if (typeof v !== 'number' || !Number.isFinite(v)) return null;
  return Math.min(Math.max(Math.trunc(v), 0), Number.MAX_SAFE_INTEGER);
}

const isMap = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

const COUNTERS = {
  stored_messages: 'storedMessages',
  stored_bytes: 'storedBytes',
  storage_limit_bytes: 'storageLimitBytes',
  peers_connected: 'peersConnected',
  peers_total: 'peersTotal',
  peers_alive: 'peersAlive',
  peers_static: 'peersStatic',
  peers_auto: 'peersAuto',
  peer_limit: 'peerLimit',
  static_peers: 'staticPeers',
  autopeer_depth: 'autopeerDepth',
  messages_received: 'messagesReceived',
  messages_served: 'messagesServed',
  messages_sent_to_peers: 'messagesSentToPeers',
  messages_received_from_peers: 'messagesReceivedFromPeers',
  messages_offered_to_peers: 'messagesOfferedToPeers',
  unhandled_messages: 'unhandledMessages',
  // Stored messages some peer still waits for, each once (rettui 2.1.0 and later; null from older nodes).
  unhandled_distinct: 'unhandledDistinct',
};

// The propagation node numbers, or null when there are none: the node must say
// enabled: true. A missing or wrong counter becomes null.
export function sanitizePropagation(raw) {
  if (!isMap(raw) || raw.enabled !== true) return null;
  const out = { enabled: true };
  for (const [key, name] of Object.entries(COUNTERS)) out[name] = optCount(raw[key]);
  out.autopeer = typeof raw.autopeer === 'boolean' ? raw.autopeer : null;
  return out;
}

// The disk numbers, or null when the object is not one or has nothing in it.
export function sanitizeDisk(raw) {
  if (!isMap(raw)) return null;
  const out = { dataBytes: optCount(raw.data_bytes), fsTotalBytes: optCount(raw.fs_total_bytes), fsFreeBytes: optCount(raw.fs_free_bytes) };
  return Object.values(out).every((v) => v === null) ? null : out;
}

// Network text must not carry control, bidirectional or zero-width characters
// (they can reorder or hide what a reader sees). Used for every text we show.
export const INVISIBLE_RE = /[\u0000-\u001f\u007f-\u009f\u00ad\u061c\u180e\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/g;

// Text from the network with those characters out, trimmed and cut to length.
export function cleanText(v, max) {
  if (typeof v !== 'string') return null;
  return v.replace(INVISIBLE_RE, '').trim().slice(0, max);
}

const ADDRESS_RE = /^[0-9a-f]{32}$/;

// What the peered nodes of a token-authorised answer add up to: {listed, alive,
// static, unhandled, truncated, invalid}, or null without a list. The rows
// identify other nodes, so they are only counted here: no address, name or state
// is kept. An entry needs a valid 32 character lower case hex address to count,
// a repeated address counts once (its first entry), and at most
// MAX_PROPAGATION_PEERS entries are looked at.
export function summarizePropagationPeers(raw) {
  if (!isMap(raw) || raw.authorised !== true || !Array.isArray(raw.propagation_peers)) return null;
  const list = raw.propagation_peers;
  const seen = new Set();
  const out = { listed: 0, alive: 0, static: 0, unhandled: 0, truncated: raw.propagation_peers_truncated === true || list.length > MAX_PROPAGATION_PEERS, invalid: 0 };
  const n = Math.min(list.length, MAX_PROPAGATION_PEERS);
  for (let i = 0; i < n; i++) {
    const e = list[i];
    if (!isMap(e) || typeof e.address !== 'string' || !ADDRESS_RE.test(e.address)) {
      out.invalid++;
      continue;
    }
    if (seen.has(e.address)) continue;
    seen.add(e.address);
    out.listed++;
    if (e.alive === true) out.alive++;
    if (e.static === true) out.static++;
    out.unhandled += optCount(e.unhandled) ?? 0;
  }
  return out;
}

// How many rows of peered nodes are kept for the Details view.
export const MAX_PEER_ROWS = 64;
const ROW_NAME_MAX = 64;
const ROW_STATE_RE = /^[a-z][a-z_]{0,31}$/;
// Seconds and counters are cut here: no real value is near it, and it keeps the numbers small.
const ROW_NUMBER_MAX = 1e12;

function rowCount(v) {
  const n = optCount(v);
  return n === null ? null : Math.min(n, ROW_NUMBER_MAX);
}

const rowBool = (v) => (typeof v === 'boolean' ? v : null);

const staticRank = (v) => (v === true ? 0 : v === false ? 1 : 2);

// Static peers first, then the most recently synced (never synced last), then
// by name (a row without one after the named), then by address. Plain code unit
// comparison, so the order does not depend on the server's locale.
export function comparePeerRows(a, b) {
  const ar = staticRank(a.static);
  const br = staticRank(b.static);
  if (ar !== br) return ar - br;
  const as = a.lastSyncSecondsAgo;
  const bs = b.lastSyncSecondsAgo;
  if (as !== bs) return as === null ? 1 : bs === null ? -1 : as - bs;
  const an = a.name === null ? null : a.name.toLowerCase();
  const bn = b.name === null ? null : b.name.toLowerCase();
  if (an !== bn) return an === null ? 1 : bn === null ? -1 : an < bn ? -1 : 1;
  return a.address < b.address ? -1 : a.address > b.address ? 1 : 0;
}

// The peered nodes of a token-authorised answer as a short list for the Details
// view, or null without one. Current state only: it is kept in memory, never
// saved. A row needs a valid 32 character lower case hex address (a repeated
// one counts once); every other field that is missing or of the wrong type
// becomes null. Names lose control, bidirectional and zero-width characters
// and are cut to 64 characters. At most MAX_PROPAGATION_PEERS entries are looked
// at and the first MAX_PEER_ROWS in the order of comparePeerRows are kept.
// hasSync says the node sent the sync fields (rettui 2.1.0 and later).
export function sanitizePropagationPeerRows(raw) {
  if (!isMap(raw) || raw.authorised !== true || !Array.isArray(raw.propagation_peers)) return null;
  const list = raw.propagation_peers;
  const seen = new Set();
  const rows = [];
  const n = Math.min(list.length, MAX_PROPAGATION_PEERS);
  for (let i = 0; i < n; i++) {
    const e = list[i];
    if (!isMap(e) || typeof e.address !== 'string' || !ADDRESS_RE.test(e.address) || seen.has(e.address)) continue;
    seen.add(e.address);
    const state = typeof e.state === 'string' && ROW_STATE_RE.test(e.state) ? e.state : null;
    rows.push({
      address: e.address,
      name: cleanText(e.name, ROW_NAME_MAX) || null,
      alive: rowBool(e.alive),
      static: rowBool(e.static),
      depth: rowCount(e.depth),
      state,
      lastHeardSecondsAgo: rowCount(e.last_heard_seconds_ago),
      lastSyncSecondsAgo: rowCount(e.last_sync_seconds_ago),
      messagesOffered: rowCount(e.messages_offered),
      unhandled: rowCount(e.unhandled),
      peeringCost: rowCount(e.peering_cost),
      syncFailures: rowCount(e.sync_failures),
      lastAttemptSecondsAgo: rowCount(e.last_attempt_seconds_ago),
      nextAttemptInSeconds: rowCount(e.next_attempt_in_seconds),
      lastFailure: typeof e.last_failure === 'string' && ROW_STATE_RE.test(e.last_failure) ? e.last_failure : null,
      hasSync: Object.hasOwn(e, 'last_sync_seconds_ago') || Object.hasOwn(e, 'sync_failures'),
    });
  }
  return rows.sort(comparePeerRows).slice(0, MAX_PEER_ROWS);
}
