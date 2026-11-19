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
