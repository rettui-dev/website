// The optional propagation node and disk numbers of a node's stats, and the rows
// of the peered nodes. Old nodes send none of it; every part is optional and a
// part that does not fit is left out, never the whole stats. All of it is
// untrusted network data.

export const MAX_PROPAGATION_PEERS = 256;
const MAX_NAME = 48;

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

// A peer's name is network text: control, bidirectional and zero-width characters
// out, then trimmed and cut to length.
export function cleanName(v) {
  if (typeof v !== 'string') return null;
  const s = v.replace(/[\u0000-\u001f\u007f-\u009f­؜᠎​-‏‪-‮⁠-⁯﻿]/g, '').trim().slice(0, MAX_NAME);
  return s.length ? s : null;
}

const ADDRESS_RE = /^[0-9a-f]{32}$/;
const STATE_RE = /^[a-z][a-z0-9_]{0,23}$/;

// The peered nodes of a token-authorised answer: {rows, truncated, invalid} or
// null without a list. These rows identify other nodes, so they are kept in
// memory only and only counts made from them leave (see summarizePeerRows).
export function sanitizePropagationPeers(raw) {
  if (!isMap(raw) || raw.authorised !== true || !Array.isArray(raw.propagation_peers)) return null;
  const list = raw.propagation_peers;
  const seen = new Map();
  let invalid = 0;
  const n = Math.min(list.length, MAX_PROPAGATION_PEERS);
  for (let i = 0; i < n; i++) {
    const e = list[i];
    if (!isMap(e) || typeof e.address !== 'string' || !ADDRESS_RE.test(e.address)) {
      invalid++;
      continue;
    }
    // A repeated address keeps its first row.
    if (seen.has(e.address)) continue;
    seen.set(e.address, {
      address: e.address,
      name: cleanName(e.name),
      alive: e.alive === true,
      static: e.static === true,
      state: typeof e.state === 'string' && STATE_RE.test(e.state) ? e.state : null,
      depth: optCount(e.depth),
      lastHeardSecondsAgo: optCount(e.last_heard_seconds_ago),
      lastSyncSecondsAgo: optCount(e.last_sync_seconds_ago),
      messagesOffered: optCount(e.messages_offered),
      peeringCost: optCount(e.peering_cost),
      unhandled: optCount(e.unhandled),
    });
  }
  return { rows: [...seen.values()], truncated: raw.propagation_peers_truncated === true || list.length > MAX_PROPAGATION_PEERS, invalid };
}

// The only thing made public from the rows: counts.
export function summarizePeerRows(p) {
  return {
    listed: p.rows.length,
    alive: p.rows.filter((r) => r.alive).length,
    static: p.rows.filter((r) => r.static).length,
    unhandled: p.rows.reduce((a, r) => a + (r.unhandled ?? 0), 0),
    truncated: p.truncated,
  };
}
