// Peer lists for exact de-duplication of a proxy's group, and the token that
// asks a node for them. The lists are private: they are kept in memory only, in
// a compact form, and only their counts ever leave this module.

export const MAX_PEERS = 20000;
// A response with a peer list is larger than the plain stats.
export const PEERS_MAX_BYTES = 4 * 1024 * 1024;

const TYPE_BIT = { lxmf: 1, nomad: 2, propagation: 4 };
const ADDRESS_RE = /^[0-9a-f]{32}$/;
const TOKEN_RE = /^[\x21-\x7e]{16,256}$/;

// The same rule the node applies: 16 to 256 printable ASCII characters, no spaces.
export function validToken(token) {
  return typeof token === 'string' && TOKEN_RE.test(token);
}

// A token may only travel over https, or plain http to a loopback or private
// address (isPrivateHost says which).
export function tokenAllowedFor(url, isPrivateHost) {
  let u;
  try {
    u = new URL(url);
  } catch {
    return false;
  }
  return u.protocol === 'https:' || (u.protocol === 'http:' && isPrivateHost(u.hostname));
}

// Cleans the peer list out of a node's answer. Returns null unless the node says
// the request was authorised and sent a list; otherwise a compact list:
// {addrs: Buffer of 16 bytes each, masks: Uint8Array of type bits, truncated,
// invalid}. Entries that are not a 32 character lower case hex address with a
// known type are dropped and counted, duplicates are merged, names are never
// read, and at most MAX_PEERS entries are looked at.
export function sanitizePeers(raw) {
  if (!raw || typeof raw !== 'object' || raw.authorised !== true || !Array.isArray(raw.peers)) return null;
  const list = raw.peers;
  const seen = new Map();
  let invalid = 0;
  const n = Math.min(list.length, MAX_PEERS);
  for (let i = 0; i < n; i++) {
    const e = list[i];
    const bit = e && typeof e === 'object' && !Array.isArray(e) && typeof e.type === 'string' && Object.hasOwn(TYPE_BIT, e.type) ? TYPE_BIT[e.type] : 0;
    if (!bit || typeof e.address !== 'string' || !ADDRESS_RE.test(e.address)) {
      invalid++;
      continue;
    }
    seen.set(e.address, (seen.get(e.address) ?? 0) | bit);
  }
  const addrs = Buffer.alloc(seen.size * 16);
  const masks = new Uint8Array(seen.size);
  let at = 0;
  for (const [address, mask] of seen) {
    addrs.write(address, at * 16, 16, 'hex');
    masks[at++] = mask;
  }
  // A list that was cut, by the node or here, cannot give an exact union.
  return { addrs, masks, truncated: raw.peers_truncated === true || list.length > MAX_PEERS, invalid };
}

// The size of the union of several lists, per type and overall. An address
// heard as two types counts once in each type and once in the total.
export function unionPeers(lists) {
  const all = new Map();
  for (const l of lists) {
    for (let i = 0; i < l.masks.length; i++) {
      const address = l.addrs.toString('hex', i * 16, i * 16 + 16);
      all.set(address, (all.get(address) ?? 0) | l.masks[i]);
    }
  }
  const out = { total: all.size, lxmf: 0, nomad: 0, propagation: 0 };
  for (const mask of all.values()) {
    if (mask & 1) out.lxmf++;
    if (mask & 2) out.nomad++;
    if (mask & 4) out.propagation++;
  }
  return out;
}
