// Links between the monitored nodes: which node dials which. Two sources, merged:
//  - detected: the website reads each managed node's redacted Reticulum config (the read-only view
//    that the Manage page shows) on its own slow schedule, and a client interface whose target is
//    another monitored node is a link "X dials Y";
//  - declared: the operator's `links` list in the config file, for nodes without management.
// The status page only ever gets the result for the monitored nodes, as {to, dir, enabled, source,
// conflict} (see buildLinks): never an interface name, a target address or a URL. A target that
// matches no monitored node is dropped here and goes nowhere. Page views read the cache only; they
// never cause a signed request to a node.
import { cleanReticulum } from './manage-api.js';
import { limiter } from './monitor.js';

// Whether the website reads the nodes' Reticulum configs for links at all (the `detect_links`
// setting). Off until the operator turns it on: what a node's config says about who it dials is
// private until they choose to publish it. One constant, so the default can be changed in one place.
export const DETECT_LINKS_DEFAULT = false;
// How often each managed node is read, and how long the last good reading is kept when the node
// cannot be reached (three readings). One read of /manage/v1/state per node every 5 minutes is 12 an
// hour, far below what a node accepts, and the Manage page's own reads have separate budgets.
export const LINKS_INTERVAL_MS = 5 * 60_000;
export const LINKS_KEEP_MS = 3 * LINKS_INTERVAL_MS;
// After a failure a node is asked again later, up to this many intervals, so a wrong secret or a
// dead node is not knocked on every 5 minutes.
export const LINKS_MAX_BACKOFF_INTERVALS = 6;
export const LINKS_FIRST_DELAY_MS = 10_000;
// Nodes read at the same time.
export const LINKS_CONCURRENCY = 4;
// The most links one node has in the answer.
export const MAX_LINKS = 8;
// The name the node sees on these reads (they are not a person's).
export const LINKS_ACTOR = 'status-links';

// A host in one spelling, for both the targets of interfaces and the nodes' own hosts: lower case,
// no brackets, no trailing dot, IPv6 compressed the way URLs write it, IPv4 in dotted form (0x7f.1
// and 127.1 are 127.0.0.1). Anything the URL parser refuses stays as it was, in lower case.
export function normHost(h) {
  const plain = String(h).trim().toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  if (plain === '') return plain;
  try {
    return new URL(`http://${plain.includes(':') ? `[${plain}]` : plain}`).hostname.replace(/^\[|\]$/g, '');
  } catch {
    return plain;
  }
}
const PORT_RE = /^\d{1,5}$/;

// The host of an http(s) URL in its normal form, or null.
export function hostOfUrl(url) {
  try {
    return normHost(new URL(url).hostname) || null;
  } catch {
    return null;
  }
}

// The nodes links can point to: [{key, name, host, port, manageHost, statsHost}] from the monitor's
// targets and the config's manage and stats URLs.
export function linkEntries({ targets, nodes = new Map(), manage = new Map(), statsUrls = new Map() }) {
  return targets.map((t, i) => {
    const key = `${t.host}:${t.port}`;
    const m = manage.get(key);
    const s = statsUrls.get(key);
    return { key, name: nodes.get(key)?.name ?? `node ${i + 1}`, host: normHost(t.host), port: t.port, manageHost: m ? hostOfUrl(m.url) : null, statsHost: s ? hostOfUrl(s) : null };
  });
}

// Which monitored node a client interface's target is. In this order: (a) host and port are a
// node's address; (b) the host is the host of a node's manage_url (a WireGuard setup: the port
// differs); (c) the host is the host of a node's stats_url, unless it is also the address host of a monitored node. Gives {key}, {ambiguous: true} when one
// step matches several nodes (never guessed), or null. A match with the node itself is null.
export function matchTarget(entries, selfKey, host, port) {
  const h = normHost(host);
  const exact = entries.filter((e) => e.host === h && e.port === port);
  // A stats host that is also the address host of a monitored node (a name behind a proxy, shared by
  // several nodes) says nothing about which node is meant, so step (c) does not apply to it.
  const statsOk = !entries.some((e) => e.host === h);
  const steps = [exact, entries.filter((e) => e.manageHost === h), statsOk ? entries.filter((e) => e.statsHost === h) : []];
  for (const found of steps) {
    if (found.length === 0) continue;
    if (found.length > 1) return { ambiguous: true };
    return found[0].key === selfKey ? null : { key: found[0].key };
  }
  return null;
}

// How Reticulum reads a switch: true, yes, on and 1 are on; false, no, off and 0 are off (any case);
// anything else is not a switch.
function parseSwitch(value) {
  const v = typeof value === 'string' ? value.trim().toLowerCase() : '';
  if (['true', 'yes', 'on', '1'].includes(v)) return true;
  if (['false', 'no', 'off', '0'].includes(v)) return false;
  return null;
}

// Whether a client interface is switched on, as Reticulum itself decides: it starts a section only
// when `enabled` or `interface_enabled` is true, so with neither key the interface is off, and with
// both it is on when either is. A key the node's redacted view does not show a value for (it shows
// only yes, no, true, false, on and off) could be either: then not known (null).
function enabledOf(keys) {
  const present = keys.filter((k) => k.set && ['enabled', 'interface_enabled'].includes(k.key.toLowerCase()));
  const values = present.map((k) => parseSwitch(k.value));
  if (values.includes(true)) return true;
  if (values.includes(null)) return null;
  return false;
}

// The client interfaces in a cleaned Reticulum view (cleanReticulum): those with a target host and
// a target port, as [{host, port, enabled}]. Section and interface names stay in here.
export function clientTargets(ret) {
  const out = [];
  for (const s of ret?.sections ?? []) {
    if (s.path.length !== 2 || s.path[0] !== 'interfaces') continue;
    const val = (name) => s.keys.find((k) => k.key.toLowerCase() === name && k.set && typeof k.value === 'string')?.value ?? null;
    const host = val('target_host');
    const portText = val('target_port');
    if (host === null || portText === null || !PORT_RE.test(portText.trim())) continue;
    const port = Number(portText);
    if (port < 1 || port > 65535) continue;
    out.push({ host, port, enabled: enabledOf(s.keys) });
  }
  return out;
}

// One link's on or off over several interfaces to the same node: any on wins, then not known.
const rank = { true: 2, null: 1, false: 0 };
const better = (a, b) => (rank[b] > rank[a] ? b : a);

// What a node's cleaned Reticulum view says about links: {links: [{to, enabled}], readable}.
// readable: the view is complete, so that a link missing from it is evidence that there is none.
// ambiguous: how many targets were dropped for matching several nodes.
export function detectLinks(ret, entries, selfKey) {
  const found = new Map();
  let ambiguous = 0;
  const readable = ret !== null && ret.shared_instance !== true && ret.truncated !== true;
  if (ret !== null && ret.shared_instance !== true) {
    for (const t of clientTargets(ret)) {
      const m = matchTarget(entries, selfKey, t.host, t.port);
      if (m === null) continue;
      if (m.ambiguous) {
        ambiguous++;
        continue;
      }
      found.set(m.key, found.has(m.key) ? better(found.get(m.key), t.enabled) : t.enabled);
    }
  }
  return { links: [...found].map(([to, enabled]) => ({ to, enabled })), readable, ambiguous };
}

// Reads the managed nodes on a schedule of its own and keeps the result.
// client: createManageClient's (has, call). entries: linkEntries(...). debug(text) and log(text):
// where the notes for the operator go (the node's name and a short code, never an address).
// Everything it holds is in private fields, so no dump of it can show a host.
export class LinkWatcher {
  #client;
  #entries;
  #now;
  #intervalMs;
  #keepMs;
  #firstDelayMs;
  #debug;
  #log;
  #cache = new Map();
  #failures = new Map();
  #states = new Map();
  #keys;
  #timer = null;

  constructor({ client, entries, now = Date.now, intervalMs = LINKS_INTERVAL_MS, keepMs = LINKS_KEEP_MS, firstDelayMs = LINKS_FIRST_DELAY_MS, debug = () => {}, log = () => {} }) {
    this.#client = client;
    this.#entries = entries;
    this.#now = now;
    this.#intervalMs = intervalMs;
    this.#keepMs = keepMs;
    this.#firstDelayMs = firstDelayMs;
    this.#debug = debug;
    this.#log = log;
    this.#keys = entries.map((e) => e.key).filter((k) => client.has(k));
  }

  // Whether the timer is going.
  get running() {
    return this.#timer !== null && this.#timer !== 'stopped';
  }

  // The last good reading of a node, or null when there is none or it is too old.
  detected(key) {
    const hit = this.#cache.get(key);
    if (!hit) return null;
    const age = this.#now() - hit.at;
    return age >= 0 && age <= this.#keepMs ? hit : null;
  }

  #name(key) {
    return this.#entries.find((e) => e.key === key)?.name ?? 'a node';
  }

  // Says once when what a node lets us read changes: a short code and the node's name.
  #state(key, code) {
    const before = this.#states.get(key);
    if (before === code) return;
    this.#states.set(key, code);
    if (code === 'ok') {
      if (before !== undefined) this.#log(`links: can read ${this.#name(key)} again`);
    } else this.#log(`links: cannot read all of ${this.#name(key)}: ${code}`);
  }

  #fail(key, code) {
    const t = this.#now();
    const count = (this.#failures.get(key)?.count ?? 0) + 1;
    this.#failures.set(key, { count, next: t + this.#intervalMs * Math.min(2 ** (count - 1), LINKS_MAX_BACKOFF_INTERVALS) });
    this.#state(key, code);
  }

  async #read(key) {
    try {
      const r = await this.#client.call(key, 'GET', '/manage/v1/state', LINKS_ACTOR);
      if (!r?.ok || r.status !== 200) {
        this.#fail(key, r?.ok ? `status-${Number.isInteger(r.status) ? r.status : 'unknown'}` : String(r?.error ?? 'error').replace(/[^a-z0-9_-]/gi, '').slice(0, 24) || 'error');
        return;
      }
      const ret = cleanReticulum(r.body?.reticulum);
      const { links, readable, ambiguous } = detectLinks(ret, this.#entries, key);
      this.#failures.delete(key);
      if (ambiguous) this.#debug(`links: ${ambiguous} client interface target(s) of ${this.#name(key)} match several monitored nodes and were dropped`);
      this.#cache.set(key, { at: this.#now(), links, readable });
      this.#state(key, ret === null ? 'no-reticulum-view' : ret.shared_instance ? 'shared-instance' : ret.truncated ? 'view-cut' : 'ok');
    } catch {
      this.#fail(key, 'unreadable');
    }
  }

  // Reads every node that is due, a few at a time. Never throws: a failure is only that node's.
  async refresh() {
    const gate = limiter(LINKS_CONCURRENCY);
    const t = this.#now();
    const due = this.#keys.filter((k) => (this.#failures.get(k)?.next ?? 0) <= t);
    await Promise.all(due.map((k) => gate(() => this.#read(k))));
    for (const [k, v] of this.#cache) if (this.#now() - v.at > this.#keepMs) this.#cache.delete(k);
  }

  // The first reading after a short delay, then every interval, never two at once.
  start() {
    if (this.#keys.length === 0) return;
    const tick = async () => {
      try {
        await this.refresh();
      } catch {
        // A reading must never reach anything else.
      }
      if (this.#timer !== 'stopped') this.#timer = setTimeout(tick, this.#intervalMs).unref();
    };
    this.#timer = setTimeout(tick, this.#firstDelayMs).unref();
  }

  stop() {
    if (this.#timer && this.#timer !== 'stopped') clearTimeout(this.#timer);
    this.#timer = 'stopped';
  }
}

// The links of every node as they are published: Map of key to at most MAX_LINKS of
// {to, dir: 'dials'|'unknown', enabled: true|false|null, source: 'detected'|'declared',
// conflict: null|'direction'|'not_found'}.
// keys: the monitored nodes in order. visible(from, to): whether the viewer may see a link. declaredOf(key): [{to, dir}] from the config. detectedOf(key):
// {links, readable} or null.
// Rules: a node's config is the evidence for the links of that node as the dialler, the declaration
// the fallback. A node's config never changes what is declared on another node.
//  - both say the same direction: detected (a declared "unknown" never disagrees);
//  - detected the other way round: both are kept, one on each node, as if both were declared (the
//    link declared on the one node stays, and the other node's own config adds its link);
//  - on or off: the detected value;
//  - declared only: kept, with conflict 'not_found' when the dialling node's config was complete
//    and shows no such interface (for "unknown": both nodes' configs were).
export function buildLinks(keys, declaredOf, detectedOf, visible = () => true) {
  const index = new Map(keys.map((k, i) => [k, i]));
  const det = new Map();
  const readable = (k) => detectedOf(k)?.readable === true;
  for (const a of keys) {
    for (const l of detectedOf(a)?.links ?? []) {
      if (l.to !== a && index.has(l.to)) det.set(`${a}>${l.to}`, { from: a, to: l.to, dir: 'dials', enabled: l.enabled, source: 'detected', conflict: null });
    }
  }
  const entries = [...det.values()];
  for (const a of keys) {
    for (const l of declaredOf(a) ?? []) {
      const b = l.to;
      if (b === a || !index.has(b)) continue;
      const forward = det.get(`${a}>${b}`);
      const back = det.get(`${b}>${a}`);
      if (l.dir === 'unknown') {
        if (forward || back) continue;
        entries.push({ from: a, to: b, dir: 'unknown', enabled: null, source: 'declared', conflict: readable(a) && readable(b) ? 'not_found' : null });
        continue;
      }
      if (forward) continue;
      // The other node's config says it dials this one: that is its own link and stays, and it does not
      // take away the one declared here for this node. Both are drawn, as if both were declared.
      entries.push({ from: a, to: b, dir: 'dials', enabled: null, source: 'declared', conflict: readable(a) ? 'not_found' : null });
    }
  }
  const out = new Map(keys.map((k) => [k, []]));
  // What the viewer may not see is taken out before the cap, so it cannot crowd out what they may.
  entries.splice(0, entries.length, ...entries.filter((e) => visible(e.from, e.to)));
  entries.sort((x, y) => (x.source === y.source ? 0 : x.source === 'detected' ? -1 : 1) || index.get(x.to) - index.get(y.to));
  for (const e of entries) {
    const list = out.get(e.from);
    if (list.length < MAX_LINKS) list.push({ to: e.to, dir: e.dir, enabled: e.enabled, source: e.source, conflict: e.conflict });
  }
  return out;
}
