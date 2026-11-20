// What a visitor without a login does not see. With users in the config file,
// sections of the stats can be kept for logged-in users (require_login); these
// functions take them out of the answers before they leave the server.
//
// - details: the Details view (/api/stats) of a node, and its place in a combined view
// - storage: the message store of a propagation node (stored messages and size, message counters)
// - peers: its peered propagation nodes (counts, limits, auto-peering, and the
//   table of them in its Details view), and the messages it exchanges with them
//   (counters and the flow graph)
// - disk: the disk level, share and figures, and the data size; also the size of
//   the message store, which is most of the data size on a propagation node
// - versions: the rettui version a node runs and the versions seen
//
// Logs (a node's recent log lines, see logs.js) are not a section here: they need a login unless the
// node says public_logs: true, whatever require_login lists. They are never public by omission.
//
// Peers heard, clients, traffic, announces, uptime and up or down stay public.
export const SECTIONS = ['details', 'storage', 'peers', 'disk', 'versions'];

const STORAGE_KEYS = [
  'storedMessages', 'storedBytes', 'storageLimitBytes', 'messagesReceived', 'messagesServed', 'messagesSentToPeers',
  'messagesReceivedFromPeers', 'messagesOfferedToPeers', 'unhandledMessages', 'unhandledDistinct',
];
// The messages sent to, received from and offered to peers say how busy the
// peering is, so they go with peers as well as with storage.
const PEER_FLOW_KEYS = ['messagesSentToPeers', 'messagesReceivedFromPeers', 'messagesOfferedToPeers'];
const PEERING_KEYS = ['peersConnected', 'peersTotal', 'peersAlive', 'peersStatic', 'peersAuto', 'peerLimit', 'staticPeers', 'autopeerDepth', 'autopeer', ...PEER_FLOW_KEYS];
const STORAGE_SERIES = ['storedMessages', 'storedBytes', 'sentPerMinute', 'receivedPerMinute'];
const PEERING_SERIES = ['peersAlive', 'peersTotal', 'sentPerMinute', 'receivedPerMinute'];
// The message store size, taken out with the disk: it would give the data size away.
const DISK_KEYS = ['storedBytes'];

const NONE = new Set();

// The propagation numbers without the hidden parts; null when nothing is left.
function stripPropagation(p, hidden, storageKeys, peeringKeys) {
  if (!p) return p;
  if (hidden.has('storage') && hidden.has('peers')) return null;
  const out = { ...p };
  if (hidden.has('storage')) for (const k of storageKeys) delete out[k];
  if (hidden.has('peers')) for (const k of peeringKeys) delete out[k];
  if (hidden.has('disk')) for (const k of DISK_KEYS) delete out[k];
  return out;
}

// One node's stats (what Monitor.statsFor gives) without the hidden sections.
export function stripStats(stats, hidden = NONE) {
  if (!stats || hidden.size === 0) return stats;
  const out = { ...stats };
  if (hidden.has('peers')) {
    delete out.peerSummary;
    delete out.peerRows;
  }
  if (out.data) {
    const data = { ...out.data };
    if (hidden.has('versions')) delete data.rettuiVersion;
    if (hidden.has('disk')) delete data.disk;
    if (Object.hasOwn(data, 'propagation')) {
      const p = stripPropagation(data.propagation, hidden, STORAGE_KEYS, PEERING_KEYS);
      if (p) data.propagation = p;
      else delete data.propagation;
    }
    out.data = data;
  }
  return out;
}

// A group's combined numbers without the hidden sections. hidden is everything
// hidden on any member that counts in it: a sum would give a member's number away.
export function stripGroup(group, hidden = NONE) {
  if (!group || !group.data || hidden.size === 0) return group;
  const data = { ...group.data };
  if (hidden.has('disk')) data.disk = null;
  data.propagation = stripPropagation(data.propagation, hidden, STORAGE_KEYS, PEERING_KEYS);
  return { ...group, data };
}

// The graph series of a detail answer without the hidden sections.
export function stripSeries(series, hidden = NONE) {
  if (!series || hidden.size === 0) return series;
  const out = { ...series };
  if (hidden.has('disk')) out.disk = null;
  if (out.propagation) {
    const p = stripPropagation(out.propagation, hidden, STORAGE_SERIES, PEERING_SERIES);
    // Only the member count would be left.
    out.propagation = p && Object.keys(p).some((k) => k !== 'members') ? p : null;
  }
  return out;
}

// All the sections hidden on any of the given hosts.
export function union(sets) {
  const out = new Set();
  for (const s of sets) for (const x of s) out.add(x);
  return out;
}
