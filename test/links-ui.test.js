import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const publicDir = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'public');
const read = (name) => fs.readFileSync(path.join(publicDir, name), 'utf8');

function load(name) {
  const sandbox = { Date, Math, JSON };
  sandbox.globalThis = sandbox;
  vm.runInNewContext(read(name), sandbox);
  return sandbox;
}
const { buildModel, layout, describe, summaryText, listItems } = load('netmap.js').netmapLogic;
const status = load('status.js');

const host = (port, name, over = {}) => ({ host: 'h', port, name, status: 'up', latencyMs: 5, role: 'node', proxy: null, proxiedBy: null, uptime90: { percent90: 99.5 }, stats: { ok: true, stale: false, data: { interfaces: { clients: 1 } } }, ...over });
const K = (p) => `h:${p}`;
const link = (to, over = {}) => ({ to: K(to), dir: 'dials', enabled: true, source: 'detected', conflict: null, ...over });
const plain = (v) => JSON.parse(JSON.stringify(v));

// Front dials Back and Side (turned off), Back dials Side: the example of the design.
const trio = () => [
  host(1, 'Front', { links: [link(2), link(3, { enabled: false })] }),
  host(2, 'Back', { links: [link(3)] }),
  host(3, 'Side'),
];
const door = () => host(9, 'Door', { role: 'proxy', proxy: { for: [K(1), K(2), K(3)] } });

test('model: one edge per pair, with direction, flags and down; bad entries are skipped', () => {
  const m = buildModel(trio());
  assert.equal(m.empty, false, 'links alone are a map');
  const links = m.edges.filter((e) => e.kind === 'link');
  assert.deepEqual(Array.from(links, (e) => `${e.from}>${e.to}:${e.dir}:${e.enabled}:${e.source}`), ['h:1>h:2:dials:true:detected', 'h:1>h:3:dials:false:detected', 'h:2>h:3:dials:true:detected']);
  const bad = buildModel([host(1, 'A', { links: [link(1), link(7), { to: 5 }, null, link(2, { dir: 'sideways' }), link(2, { enabled: 'x', source: 'other', conflict: 'weird' })] }), host(2, 'B')]);
  assert.deepEqual(plain(bad.edges.map((e) => [e.from, e.to, e.enabled, e.source, e.conflict])), [['h:1', 'h:2', null, 'detected', null]]);
  const down = buildModel([host(1, 'A', { links: [link(2)] }), host(2, 'B', { status: 'down' })]);
  assert.equal(down.edges[0].down, true);
  // Garbage in links is survived, and an external peer cannot be a link target.
  assert.equal(buildModel([host(1, 'A', { links: 'x' })]).empty, true);
  assert.equal(buildModel([host(1, 'A', { upstreams: [{ name: 'E' }], links: [{ to: 'ext:e|', dir: 'dials' }] })]).edges.filter((e) => e.kind === 'link').length, 0);
});

test('model: two nodes that dial each other are one edge with the facts of both directions', () => {
  const m = buildModel([host(1, 'A', { links: [link(2)] }), host(2, 'B', { links: [link(1, { enabled: false, source: 'declared' })] })]);
  assert.equal(m.edges.length, 1);
  assert.deepEqual(plain(m.edges[0]), { from: 'h:1', to: 'h:2', kind: 'link', dir: 'dials', mutual: true, enabled: true, source: 'detected', conflict: null, back: { enabled: false, source: 'declared', conflict: null }, down: false });
});

test('model: an unknown direction is one edge, even when both nodes declared it', () => {
  const m = buildModel([host(1, 'A', { links: [link(2, { dir: 'unknown', source: 'declared', enabled: null })] }), host(2, 'B', { links: [link(1, { dir: 'unknown', source: 'declared', enabled: null })] })]);
  assert.equal(m.edges.length, 1);
  assert.equal(m.edges[0].dir, 'unknown');
  assert.equal(m.edges[0].mutual, false);
});

test('empty and summaryText: without node links nothing changes; with them the count is added', () => {
  assert.equal(buildModel([host(1, 'A'), host(2, 'B')]).empty, true);
  assert.equal(buildModel([host(1, 'A', { links: [] }), host(2, 'B')]).empty, true);
  assert.equal(summaryText(buildModel([door(), host(1, 'A'), host(2, 'B')])), '1 proxy, 2 nodes, 2 links');
  assert.equal(summaryText(buildModel([door(), ...trio()])), '1 proxy, 3 nodes, 3 links, 3 links between nodes');
  assert.equal(summaryText(buildModel([host(1, 'A', { links: [link(2)] }), host(2, 'B')])), '2 nodes, 0 links, 1 link between nodes');
});

test('text alternative: the shared wording, qualifiers in parentheses, names only', () => {
  const m = buildModel([door(), ...trio()]);
  const by = Object.fromEntries(m.nodes.map((n) => [n.id, describe(n)]));
  assert.equal(by['h:1'], 'Front: up, 1 client, connect time 5 ms, uptime 99.5% over 90 days. Dials Back, Side (turned off).');
  assert.equal(by['h:2'], 'Back: up, 1 client, connect time 5 ms, uptime 99.5% over 90 days. Dials Side. Dialled by Front.');
  assert.equal(by['h:3'], 'Side: up, 1 client, connect time 5 ms, uptime 99.5% over 90 days. Dialled by Front (turned off), Back.');
  assert.equal(by['h:9'], 'Proxy Door, up, passes visitors to 3 nodes, 1 client, connect time 5 ms, uptime 99.5% over 90 days.', 'a node without links reads as before');
  const items = listItems(m);
  assert.match(items[1], /Dials Back, Side \(turned off\)\.$/);
  assert.match(items[0], /Connects to Front, Back, Side\.$/);
  assert.doesNotMatch(items.join(' '), /h:\d/);
});

test('text alternative: declared, conflicts, unknown direction and mutual links', () => {
  const m = buildModel([
    host(1, 'Front', { links: [link(2, { source: 'declared', enabled: null }), link(3, { source: 'declared', enabled: null, conflict: 'not_found' }), link(4, { dir: 'unknown', source: 'declared', enabled: null })] }),
    host(2, 'Back'),
    host(3, 'Side', { links: [link(2, { conflict: 'direction' })] }),
    host(4, 'Edge'),
  ]);
  const t = (id) => describe(m.nodes.find((n) => n.id === id));
  assert.match(t('h:1'), /Dials Back \(declared\), Side \(declared; not found in the node's config\)\. Linked with Edge, direction not known\.$/);
  assert.match(t('h:2'), /Dialled by Front \(declared\), Side \(the operator declared the other direction\)\.$/);
  assert.match(t('h:4'), /Linked with Front, direction not known\.$/);
  const mutual = buildModel([host(1, 'A', { links: [link(2)] }), host(2, 'B', { links: [link(1)] })]);
  assert.match(describe(mutual.nodes[0]), /A and B dial each other\.$/);
  assert.match(describe(mutual.nodes[1]), /B and A dial each other\.$/);
  const mixed = buildModel([host(1, 'A', { links: [link(2, { enabled: false })] }), host(2, 'B', { links: [link(1)] })]);
  assert.match(describe(mixed.nodes[0]), /A and B dial each other\. A to B: turned off\.$/);
  const same = buildModel([host(1, 'A', { links: [link(2, { source: 'declared' })] }), host(2, 'B', { links: [link(1, { source: 'declared' })] })]);
  assert.match(describe(same.nodes[0]), /A and B dial each other \(declared\)\.$/);
});

const noOverlap = (l, label = '') => {
  for (const a of l.nodes) for (const b of l.nodes) {
    if (a !== b) assert.ok(a.x + a.w <= b.x || b.x + b.w <= a.x || a.y + a.h <= b.y || b.y + b.h <= a.y, `${label} ${a.id} overlaps ${b.id}`);
  }
  for (const n of l.nodes) assert.ok(n.x >= 0 && n.x + n.w <= l.width && n.y >= 0 && n.y + n.h <= l.height, `${label} ${n.id} outside`);
};

test('layout: zero links leaves everything as it was', () => {
  const hosts = [door(), ...trio().map((h) => ({ ...h, links: undefined })), ];
  const withKey = hosts.map((h) => ({ ...h, links: [] }));
  assert.deepEqual(plain(layout(buildModel(withKey), 1000)), plain(layout(buildModel(hosts), 1000)));
  const l = layout(buildModel(hosts), 1000);
  assert.equal(l.linksHidden, false);
  assert.equal(l.edges.some((e) => e.kind === 'link'), false);
});

// The points of a drawn line, and whether a straight leg from p to q passes through the inside of a box.
const through = (p, q, n) => {
  const [x1, y1] = p;
  const [x2, y2] = q;
  if (x1 === x2) return x1 > n.x + 0.5 && x1 < n.x + n.w - 0.5 && Math.max(y1, y2) > n.y + 0.5 && Math.min(y1, y2) < n.y + n.h - 0.5;
  if (y1 === y2) return y1 > n.y + 0.5 && y1 < n.y + n.h - 0.5 && Math.max(x1, x2) > n.x + 0.5 && Math.min(x1, x2) < n.x + n.w - 0.5;
  return false;
};
const legs = (e) => e.pts.slice(1).map((q, i) => [e.pts[i], q]);

test('layout: neighbours get a short arrow in the gap, a link that skips a node an arc above the row in its lane', () => {
  const hosts = [door(), ...trio(), host(8, 'Hub-side', { role: 'node', proxiedBy: K(9) })];
  hosts[0].proxy.for.push(K(8));
  const l = layout(buildModel(hosts), 1200);
  assert.equal(l.mode, 'frame');
  noOverlap({ ...l, nodes: l.nodes.filter((n) => !n.frame) });
  const arcs = l.edges.filter((e) => e.kind === 'link');
  assert.equal(arcs.length, 3);
  const by = Object.fromEntries(l.nodes.map((n) => [n.id, n]));
  const rowY = by[K(1)].y;
  for (const e of arcs) {
    const a = by[e.from];
    const b = by[e.to];
    if (Math.abs(a.x - b.x) < a.w * 2.5 && e.pts.length === 2) {
      // Neighbours: one straight line across the gap, at half the height of the boxes.
      assert.equal(e.pts[0][1], a.y + a.h / 2);
      assert.equal(e.lane, null);
    } else {
      assert.equal(e.pts.length, 4);
      assert.equal(e.pts[0][1], rowY);
      assert.equal(e.pts[3][1], rowY);
      assert.equal(e.pts[1][1], rowY - 22 - 18 * e.lane, 'lane l is 22 + 18 l above the row');
      assert.match(e.d, /^M[\d. ]+ L[\d. ]+ Q/, 'rounded corners');
    }
    for (const n of l.nodes.filter((x) => !x.frame)) for (const [p, q] of legs(e)) assert.ok(!through(p, q, n), `${e.from}>${e.to} through ${n.id}`);
  }
  assert.equal(l.edges.filter((e) => e.kind === 'proxy').length, 0);
});

test('layout: links the row cannot draw are counted, so the page can point to the cards', () => {
  // A link to the proxy itself has no place in the row.
  const hosts = [door(), ...trio(), ];
  hosts[1] = { ...hosts[1], links: [...hosts[1].links, link(9)] };
  const l = layout(buildModel(hosts), 1200);
  assert.equal(l.mode, 'frame');
  assert.equal(l.linksHidden, true);
  assert.equal(l.edges.filter((e) => e.kind === 'link').length, 3);
  // The one-node view shows every link of the node picked, so nothing is hidden there.
  assert.equal(layout(buildModel(hosts), 400).linksHidden, false);
});

test('layout: marks per kind of link, and the slashes of a down node', () => {
  const hosts = [
    host(1, 'A', { links: [link(2), link(3, { source: 'declared', enabled: null }), link(4, { enabled: false }), link(5, { dir: 'unknown', source: 'declared', enabled: null })] }),
    host(2, 'B', { status: 'down' }), host(3, 'C'), host(4, 'D'), host(5, 'E'),
  ];
  const l = layout(buildModel(hosts), 1400);
  assert.equal(l.mode, 'frame');
  const arcs = l.edges.filter((e) => e.kind === 'link');
  const get = (to) => arcs.find((e) => e.to === K(to));
  assert.deepEqual([get(2).start, get(2).end, get(2).off, get(2).declared, get(2).down, get(2).ticks.length], ['dot', 'arrow', false, false, true, 2]);
  assert.deepEqual([get(3).start, get(3).end, get(3).declared], ['dot', 'open', true]);
  assert.deepEqual([get(4).end, get(4).off, get(4).ticks.length], ['bar', true, 0]);
  assert.deepEqual([get(5).start, get(5).end, get(5).dir], ['ring', 'ring', 'unknown']);
  assert.ok(get(2).ticks.every((t) => /^M[\d. -]+ L[\d. -]+$/.test(t)));
  // Without a proxy there is no frame, and the lines are not inside one.
  assert.equal(l.nodes.some((n) => n.frame), false);
  assert.ok(arcs.every((e) => e.inFrame === false));
  assert.ok(layout(buildModel([door(), ...trio()]), 1200).edges.filter((e) => e.kind === 'link').every((e) => e.inFrame === true));
});

test('layout: a mutual link has an arrowhead at both ends and no dot; a mixed one marks each end', () => {
  const l = layout(buildModel([host(1, 'A', { links: [link(2)] }), host(2, 'B', { links: [link(1, { enabled: false })] })]), 800);
  const e = l.edges.find((x) => x.kind === 'link');
  assert.equal(e.mutual, true);
  assert.equal(l.edges.filter((x) => x.kind === 'link').length, 1);
  assert.deepEqual([e.start, e.end].sort(), ['arrow', 'bar']);
  assert.equal(e.off, false);
  const both = layout(buildModel([host(1, 'A', { links: [link(2)] }), host(2, 'B', { links: [link(1)] })]), 800).edges[0];
  assert.deepEqual([both.start, both.end], ['arrow', 'arrow']);
  // The same marks in the one-node view, from either end.
  for (const want of [K(1), K(2)]) {
    const f = layout(buildModel([host(1, 'A', { links: [link(2)] }), host(2, 'B', { links: [link(1, { enabled: false })] })]), 400, want);
    const fe = f.edges.find((x) => x.kind === 'link');
    assert.deepEqual([fe.start, fe.end].sort(), ['arrow', 'bar'], want);
  }
});

test('layout: many links in a row give way to the one-node view', () => {
  const hosts = Array.from({ length: 8 }, (_, i) => host(i + 1, `N${i + 1}`));
  hosts.forEach((h, i) => { h.links = [2, 3, 4].map((k) => link(((i + k) % 8) + 1)); });
  const l = layout(buildModel(hosts), 1400);
  assert.equal(l.mode, 'focus');
  assert.equal(l.reason, 'lanes');
  for (const n of l.nodes) assert.ok(n.x >= 0 && n.x + n.w <= l.width && n.y >= 0 && n.y + n.h <= l.height, n.id);
});

test('the page and styles: the legend, the phone note and the pinned rules of the map', () => {
  const html = read('status.html');
  assert.match(html, /double border and the tag Proxy/);
  assert.match(html, /<span id="netmap-legend-links" hidden> Arrows between nodes: the node at the dot dials the node at the arrowhead; once the link is up, traffic flows both ways\. A solid arrow was found in the node's config\. An outlined arrow was declared by the operator\. A dotted line with a bar is turned off in the dialling node's config\. A line with two slashes has a node that is down\. A line with a hollow circle at each end is linked in a direction we do not know\.<\/span>/);
  assert.match(html, /<p id="netmap-phone-note" class="note" hidden>Links between nodes are listed on each node's card\.<\/p>/);
  assert.match(html, /id="links-legend" hidden> "Dials" lists the nodes this node connects out to; "Dialled by" lists the nodes that connect in; once a link is up, traffic flows both ways\. "Declared" means the operator listed the link\. "Turned off" means the dialling node has that interface switched off\./);
  assert.doesNotMatch(html, /\sstyle=/);
  const css = read('site.css');
  assert.match(css, /\.nm-box-inner \{[^}]*stroke: var\(--accent\)/);
  assert.match(css, /\.nm-node\.down \.nm-box \{ stroke: var\(--red\)/);
  // The numbers the owner approved: the declared line is 6 wide with 3 of panel colour on top, the halo 10, the dotted line 2 4.
  assert.match(css, /\.nm-edge\.link\.outer \{ stroke-width: 6; \}/);
  assert.match(css, /\.nm-edge\.link\.inner \{ stroke: var\(--panel\); stroke-width: 3; \}/);
  assert.match(css, /\.nm-halo\.wide \{ stroke-width: 10; \}/);
  assert.match(css, /\.nm-edge\.link\.off \{ stroke-dasharray: 2 4; stroke-linecap: round; \}/);
  assert.match(css, /\.nm-edge\.link\.down \{ stroke: var\(--control\); \}/);
  assert.match(css, /\.nm-tick \{ stroke: var\(--text\)/);
  assert.match(css, /\.nm-edges\.has-hot \.nm-link\.hot \.nm-edge \{ stroke-width: 3; \}/);
  // Nothing animates: no animation on the links.
  assert.doesNotMatch(css.slice(css.indexOf('Links between nodes on the network map')), /animation/);
  assert.doesNotMatch(read('netmap.js'), /innerHTML|insertAdjacentHTML|\.style\b|setAttribute\('style'/);
  const statusJs = read('status.js');
  const chipCode = statusJs.slice(statusJs.indexOf('// ---- Links between nodes'), statusJs.indexOf('// The collapsed row of a node'));
  assert.ok(chipCode.length > 500);
  assert.doesNotMatch(chipCode, /innerHTML|insertAdjacentHTML|\.style\b|setAttribute\('style'/);
  // Markers and highlight are classes and attributes, in <defs>.
  const js = read('netmap.js');
  assert.match(js, /el\('defs'/);
  assert.match(js, /classList\.add\('hot'\)/);
  assert.doesNotMatch(js, /\blive\b/, 'the live marker is not in this version');
});

// The chips on the cards, built with a small fake document.

class FakeEl {
  constructor(tag) {
    Object.assign(this, { tag, className: '', children: [], attrs: {}, text: '' });
  }
  get textContent() { return this.text + this.children.map((c) => c.textContent).join(''); }
  set textContent(v) { this.text = String(v); this.children = []; }
  get firstChild() { return this.children[0] ?? null; }
  appendChild(c) { this.children.push(c); return c; }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  all() { return [this, ...this.children.flatMap((c) => c.all())]; }
}
status.document = { createElement: (t) => new FakeEl(t) };
const { linkGroups, linkChips, linksSignature } = status.statusLogic;

const chipHosts = () => [
  host(1, 'Front', { links: [link(2), link(3, { enabled: false }), link(4, { dir: 'unknown', source: 'declared', enabled: null })] }),
  host(2, 'Back', { links: [link(1, { source: 'declared', enabled: null, conflict: 'not_found' })] }),
  host(3, 'Side', { status: 'down' }),
  host(4, null),
];

test('chips: Dials, Dialled by and Linked with, with their qualifiers and a mark for a node that is down', () => {
  const hosts = chipHosts();
  const g = plain(linkGroups(hosts[0], hosts));
  assert.deepEqual(g.dials.map((x) => [x.name, x.qualifier, x.down]), [['Back', '', false], ['Side', 'turned off', true]]);
  assert.deepEqual(g.dialledBy.map((x) => [x.name, x.qualifier]), [['Back', "declared; not found in the node's config"]]);
  assert.deepEqual(g.linked.map((x) => x.name), ['h:4'], 'an unnamed node is shown by its address');
  const box = linkChips(hosts[0], hosts);
  assert.equal(box.className, 'nl-lists');
  const lists = box.all().filter((e) => e.tag === 'ul');
  assert.deepEqual(lists.map((u) => u.attrs['aria-label']), ['Dials', 'Dialled by', 'Linked with']);
  const chips = box.all().filter((e) => e.tag === 'a');
  assert.deepEqual(chips.map((a) => a.textContent), ['Back', '\u2715 Side \u00b7 turned off', "Back \u00b7 declared; not found in the node's config", 'h:4']);
  assert.ok(chips.every((a) => a.className === 'badge nl-chip' && /^#host-h-3a-\d$/.test(a.attrs.href)));
  assert.equal(chips[0].attrs.href, '#host-h-3a-2');
  assert.ok(chips.every((a) => a.attrs['data-role'] === 'link' && a.attrs['data-host'] === 'h:1'), 'so the focus can be put back after a rebuild');
});

test('chips: nothing for a node without links; at most 8, then "and N more"; a mutual pair is in both lists', () => {
  const hosts = chipHosts();
  assert.equal(linkChips(hosts[2], hosts.slice(2, 3)), null);
  assert.equal(linkChips(host(5, 'Lone'), hosts), null);
  const many = [host(1, 'Hub', { links: Array.from({ length: 8 }, (_, i) => link(i + 2)) }), ...Array.from({ length: 12 }, (_, i) => host(i + 2, `N${i + 2}`, { links: [link(1)] }))];
  const box = linkChips(many[0], many);
  const [dials, by] = box.all().filter((e) => e.tag === 'ul');
  assert.equal(dials.children.length, 8);
  assert.equal(by.children.length, 9);
  assert.equal(by.children[8].textContent, 'and 4 more');
  const pair = [host(1, 'A', { links: [link(2)] }), host(2, 'B', { links: [link(1)] })];
  const g = plain(linkGroups(pair[0], pair));
  assert.deepEqual([g.dials.length, g.dialledBy.length], [1, 1]);
});

test('chips: names are text, and the signature moves with what a card shows', () => {
  const hosts = [host(1, '<img src=x onerror=alert(1)>', { links: [link(2)] }), host(2, 'B')];
  const box = linkChips(hosts[1], hosts);
  assert.equal(box.all().find((e) => e.tag === 'a').textContent, '<img src=x onerror=alert(1)>');
  const before = linksSignature(hosts[1], hosts);
  assert.notEqual(before, '');
  hosts[0].status = 'down';
  assert.notEqual(linksSignature(hosts[1], hosts), before, 'a neighbour going down changes the card');
  assert.equal(linksSignature(host(7, 'Lone'), hosts), '', 'a card without chips has an empty signature');
  assert.equal(linksSignature(hosts[1], undefined), '');
});

test('signature: a status flip rebuilds only the cards that show that node', () => {
  const hosts = [host(1, 'A', { links: [link(2)] }), host(2, 'B'), host(3, 'C'), host(4, 'D')];
  const sigs = () => hosts.map((h) => linksSignature(h, hosts));
  const before = sigs();
  hosts[3].status = 'down';
  assert.deepEqual(sigs(), before, 'D is not linked with anyone');
  hosts[1].status = 'down';
  const after = sigs();
  assert.notEqual(after[0], before[0]);
  assert.equal(after[1], before[1], 'B shows A, which did not change');
  assert.equal(after[2], before[2]);
  assert.equal(sigs().every((x, i) => x === after[i]), true);
  assert.deepEqual(['', ''], [before[2], before[3]], 'no host links, no signature');
});

test('ids: no two host keys share an id, and an id is only letters, digits and hyphens', () => {
  const { idOf } = status.statusLogic;
  const keys = ['a.b:1', 'a-b:1', 'a_b:1', 'a:b:1', 'h:1', 'H:1', '[::1]:80', '::1:80', 'x y:1', '\u00e9:1', 'a--b:1', 'a-2e-b:1'];
  const ids = keys.map((k) => idOf('host', k));
  assert.equal(new Set(ids).size, keys.length);
  assert.ok(ids.every((i) => /^host-[A-Za-z0-9-]+$/.test(i)), ids.join(' '));
  assert.equal(idOf('host', 'h:1'), 'host-h-3a-1');
});

test('lookups by host key are safe for names that exist on every object', () => {
  const hosts = [host(1, 'A', { links: [{ to: '__proto__:1', dir: 'dials' }, { to: 'constructor:1', dir: 'dials' }, link(2)] }), host(2, 'B')];
  const g = plain(linkGroups(hosts[0], hosts));
  assert.deepEqual(g.dials.map((x) => x.name), ['B']);
  const m = buildModel([{ ...hosts[0], host: '__proto__', port: 1 }, { ...hosts[1], host: 'constructor', port: 2 }]);
  assert.ok(Array.isArray(m.edges));
  assert.doesNotThrow(() => buildModel([host(1, 'A', { links: [{ to: 'toString:1', dir: 'dials' }, { to: 'hasOwnProperty:1', dir: 'unknown' }] })]));
});

test('chips: a card that is in a locked state says links are behind the sign-in', () => {
  const { rowLocks } = status.statusLogic;
  assert.deepEqual(plain(rowLocks({ locked: ['links'] })), ['links'], 'kept even on a row without stats');
  assert.deepEqual(plain(rowLocks({ locked: ['links', 'disk'] })), ['links']);
  assert.deepEqual(plain(rowLocks({ locked: ['links', 'disk'], stats: {} })), ['links', 'disk']);
  assert.match(read('status.js'), /links: 'links between nodes'/);
});

// Every line stays inside the width the layout reports, in both views and at every width.

test('layout: no line or box reaches past the layout width, at every width', () => {
  const sets = {
    single: trio(),
    proxied: [door(), ...trio()],
    busy: Array.from({ length: 9 }, (_, i) => host(i + 1, `N${i + 1}`)).map((h, i) => ({ ...h, links: [1, 2, 3].map((k) => link(((i + k) % 9) + 1)) })),
  };
  const modes = { frame: 0, focus: 0 };
  for (const [name, hosts] of Object.entries(sets)) {
    for (let w = 260; w <= 1400; w += 4) {
      const l = layout(buildModel(hosts), w);
      modes[l.mode]++;
      for (const e of l.edges) {
        for (const [x, y] of e.pts) assert.ok(x >= 0 && x <= l.width && y >= 0 && y <= l.height, `${name} at ${w}: ${e.d}`);
        for (const t of e.ticks || []) for (const v of t.match(/-?\d+(?:\.\d+)?/g).map(Number).filter((_, i) => i % 2 === 0)) assert.ok(v >= 0 && v <= l.width, `${name} tick at ${w}`);
      }
      for (const t of l.texts) assert.ok(t.x >= 0 && t.x <= l.width, `${name} at ${w}: ${t.text}`);
      noOverlap({ ...l, nodes: l.nodes.filter((n) => !n.frame) }, `${name} ${w}`);
    }
  }
  assert.ok(modes.frame > 100 && modes.focus > 100, JSON.stringify(modes));
});

// The real draw(), run against a small fake document.

class SvgEl {
  constructor(tag, doc) {
    Object.assign(this, { tag, doc, children: [], attrs: {}, listeners: {}, classes: new Set(), parent: null, text: '' });
    this.classList = {
      add: (c) => this.classes.add(c),
      remove: (c) => this.classes.delete(c),
      contains: (c) => this.classes.has(c),
    };
  }
  setAttribute(k, v) { this.attrs[k] = String(v); if (k === 'class') this.classes = new Set(String(v).split(/\s+/).filter(Boolean)); }
  getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; }
  appendChild(c) { c.parent = this; this.children.push(c); return c; }
  replaceChildren(...c) { this.children = []; c.forEach((x) => this.appendChild(x)); }
  addEventListener(t, f) { (this.listeners[t] ||= []).push(f); }
  fire(t) { (this.listeners[t] || []).forEach((f) => f()); }
  focus() { this.doc.activeElement = this; }
  contains(o) { for (let n = o; n; n = n.parent) if (n === this) return true; return false; }
  all() { return this.children.flatMap((c) => [c, ...c.all()]); }
  has(sel) { return this.classes.has(sel.slice(1)); }
  querySelectorAll(sel) { return this.all().filter((e) => (sel[0] === '.' ? e.has(sel) : e.tag === sel)); }
  set textContent(v) { this.text = String(v); }
  get textContent() { return this.text; }
}

function mapPage() {
  const doc = { activeElement: null, byId: {} };
  doc.createElementNS = (_ns, t) => new SvgEl(t, doc);
  doc.createElement = (t) => new SvgEl(t, doc);
  for (const id of ['netmap', 'netmap-chart', 'netmap-list', 'netmap-summary', 'netmap-legend-links', 'netmap-phone-note']) doc.byId[id] = new SvgEl('div', doc);
  doc.getElementById = (id) => doc.byId[id] || null;
  const sandbox = { Date, Math, JSON, document: doc, window: { addEventListener() {} } };
  sandbox.globalThis = sandbox;
  vm.runInNewContext(read('netmap.js'), sandbox);
  const chart = doc.byId['netmap-chart'];
  const show = (hosts, width = 1200) => { chart.clientWidth = width; sandbox.netmapView.update(hosts); return chart.children[0]; };
  return { doc, chart, show, section: doc.byId.netmap, legend: doc.byId['netmap-legend-links'], note: doc.byId['netmap-phone-note'] };
}

test('draw: every marker a link refers to exists, and ids stay unique over two draws', () => {
  const p = mapPage();
  const svg = p.show([door(), ...trio(), host(4, 'Off', { links: [link(1, { enabled: false }), link(2, { dir: 'unknown', source: 'declared', enabled: null }), link(3, { source: 'declared', enabled: null })] })]);
  assert.equal(p.section.hidden, false);
  const refs = svg.all().flatMap((e) => ['marker-start', 'marker-end'].map((k) => e.getAttribute(k))).filter(Boolean);
  assert.ok(refs.length >= 6);
  const ids = svg.all().filter((e) => e.tag === 'marker').map((e) => e.getAttribute('id'));
  for (const r of refs) assert.ok(ids.includes(/^url\(#([^)]+)\)$/.exec(r)[1]), `${r} has no marker`);
  assert.equal(new Set(ids).size, ids.length);
  // A second draw (a different width) replaces the svg wholesale; the document holds one set of ids.
  const again = p.show([door(), ...trio()], 900);
  assert.notEqual(again, svg);
  assert.equal(p.chart.children.length, 1);
  const ids2 = p.chart.children[0].all().map((e) => e.getAttribute('id')).filter(Boolean);
  assert.equal(new Set(ids2).size, ids2.length);
  assert.equal(p.legend.hidden, false);
});

test('draw: hover and focus highlight the links of a node, leave and blur clear it, a node without links fades nothing', () => {
  const p = mapPage();
  const svg = p.show([host(1, 'A', { links: [link(2)] }), host(2, 'B'), host(3, 'C'), host(4, 'D', { links: [link(2)] })]);
  const edges = svg.children[0];
  const nodeOf = (id) => svg.children.find((c) => c.getAttribute('data-id') === id);
  const hot = () => edges.all().filter((e) => e.classes.has('hot')).map((e) => e.getAttribute('data-from') + '>' + e.getAttribute('data-to'));
  nodeOf('h:1').fire('mouseenter');
  assert.equal(edges.classes.has('has-hot'), true);
  assert.deepEqual(hot(), ['h:1>h:2']);
  nodeOf('h:1').fire('mouseleave');
  assert.equal(edges.classes.has('has-hot'), false);
  assert.deepEqual(hot(), []);
  nodeOf('h:2').fire('focus');
  assert.deepEqual(hot().sort(), ['h:1>h:2', 'h:4>h:2']);
  nodeOf('h:2').fire('blur');
  assert.deepEqual(hot(), []);
  assert.equal(edges.classes.has('has-hot'), false);
  nodeOf('h:3').fire('mouseenter');
  nodeOf('h:3').fire('focus');
  assert.equal(edges.classes.has('has-hot'), false, 'a node with no links fades nothing');
  assert.deepEqual(hot(), []);
});

test('draw: without node links there are no markers, no legend and no note', () => {
  const p = mapPage();
  const svg = p.show([door(), ...trio().map((h) => ({ ...h, links: undefined }))]);
  assert.equal(svg.all().some((e) => e.tag === 'marker' || e.tag === 'defs'), false);
  assert.equal(p.legend.hidden, true);
  assert.equal(p.note.hidden, true);
});

