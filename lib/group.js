import { unionPeers } from './peers.js';

// Combines the latest stats of the nodes behind a proxy. Nodes publish counts
// only, so the same peer heard by two nodes cannot be removed: peers are
// reported as a range, from the largest single node (a lower bound) to the sum
// (an upper bound). Everything else is a plain sum.

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
  if (lists.length === ok.length) {
    data.peersHeard.exact = true;
    data.peersHeard.union = union(lists);
  }
  out.data = data;
  return out;
}
