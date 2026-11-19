import { unionPeers } from './peers.js';

// Combines the latest stats of the nodes behind a proxy. Nodes publish counts
// only, so the same peer heard by two nodes cannot be removed: peers are
// reported as a range, from the largest single node (a lower bound) to the sum
// (an upper bound). Everything else is a plain sum.

// Propagation counters that are added up across a group's nodes.
const PROPAGATION_SUMS = [
  'storedMessages', 'storedBytes', 'storageLimitBytes', 'peersConnected', 'peersTotal', 'peersAlive', 'peersStatic', 'peersAuto',
  'messagesReceived', 'messagesServed', 'messagesSentToPeers', 'messagesReceivedFromPeers', 'unhandledMessages',
];

// Adds the propagation and disk numbers of the reporting members. A node without
// a part is left out of it; a number a node did not send is left out of its sum
// (a sum with no known number is null). Free disk space is not added up, since
// each node has its own disk: the node with the least free share is reported.
function addStorage(ok, data) {
  const withProp = ok.filter((m) => m.stats.data.propagation);
  if (withProp.length) {
    const p = { nodes: withProp.length };
    for (const k of PROPAGATION_SUMS) {
      const known = withProp.map((m) => m.stats.data.propagation[k]).filter((v) => v !== null && v !== undefined);
      p[k] = known.length ? known.reduce((a, b) => a + b, 0) : null;
    }
    data.propagation = p;
  }
  const withDisk = ok.filter((m) => m.stats.data.disk);
  if (withDisk.length) {
    const sizes = withDisk.map((m) => m.stats.data.disk.dataBytes).filter((v) => v !== null);
    let lowest = null;
    for (const m of withDisk) {
      const { fsFreeBytes: free, fsTotalBytes: total } = m.stats.data.disk;
      if (free === null || !(total > 0)) continue;
      const percent = Math.round((free / total) * 1000) / 10;
      if (lowest === null || percent < lowest.percent) lowest = { percent, freeBytes: free, totalBytes: total, node: m.key };
    }
    data.disk = { nodes: withDisk.length, dataBytes: sizes.length ? sizes.reduce((a, b) => a + b, 0) : null, lowestFree: lowest };
  }
}

const KINDS = ['total', 'lxmf', 'nomad', 'propagation'];

// A member counts only with fresh stats from a node that is not down: the
// numbers of a node that is down, or that stopped answering, would be stale.
export function reports(member) {
  const s = member.stats;
  return member.status !== 'down' && s !== null && s !== undefined && s.data !== undefined && !s.stale;
}

// members: [{key, status, stats, peers?}] where stats is what Monitor.statsFor
// gives and peers is the member's cleaned peer list, when it supplied one.
// Returns {nodes, reporting, partial, missing, data}; data is null when no
// member reports.
//
// Peers heard is exact (the size of the union of the peer lists) only when every
// member that reports supplied a complete list; with one missing or cut short it
// stays a range, from the largest single node to the sum. `lists` says how many
// of the reporting members had a usable list. The lists themselves never leave
// this function, only counts.
export function aggregateGroup(members, { union = unionPeers } = {}) {
  const ok = members.filter(reports);
  const missing = members.filter((m) => !reports(m)).map((m) => m.key);
  const out = { nodes: members.length, reporting: ok.length, partial: ok.length < members.length, missing, data: null };
  if (ok.length === 0) return out;
  const sum = { total: 0, lxmf: 0, nomad: 0, propagation: 0 };
  const max = { total: 0, lxmf: 0, nomad: 0, propagation: 0 };
  const data = {
    interfaces: { total: 0, online: 0, clients: null, rxBytes: 0, txBytes: 0 },
    announcesLastMinute: 0,
    peersHeard: { sum, max, exact: false, union: null, lists: { have: 0, of: ok.length } },
    propagation: null,
    disk: null,
  };
  for (const m of ok) {
    const d = m.stats.data;
    data.interfaces.total += d.interfaces.total;
    data.interfaces.online += d.interfaces.online;
    data.interfaces.rxBytes += d.interfaces.rxBytes;
    data.interfaces.txBytes += d.interfaces.txBytes;
    if (d.interfaces.clients !== null) data.interfaces.clients = (data.interfaces.clients ?? 0) + d.interfaces.clients;
    data.announcesLastMinute += d.announcesLastMinute;
    for (const k of KINDS) {
      sum[k] += d.peersHeard[k];
      max[k] = Math.max(max[k], d.peersHeard[k]);
    }
  }
  const lists = ok.filter((m) => m.peers && !m.peers.truncated).map((m) => m.peers);
  data.peersHeard.lists.have = lists.length;
  // union may decline (return null), for example when no union has been worked out for these lists.
  const exact = lists.length === ok.length ? union(lists) : null;
  if (exact) {
    data.peersHeard.exact = true;
    data.peersHeard.union = exact;
  }
  addStorage(ok, data);
  out.data = data;
  return out;
}
